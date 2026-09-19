//! Step 3 of the resolution order over a real JOSE implementation: signature, algorithm
//! policy, key resolution and the rest of the verification list.
//!
//! [`RealVerifier`] is the [`crate::FederationVerifier`] the handlers call. It validates a
//! customer IdP token against the trust the connection configures, over `jsonwebtoken`
//! and the key set the issuer published, and returns a [`VerifiedProof`] that reports what
//! it validated and nothing else.
//!
//! # What is verified here
//!
//! The design's own list — `../sources/original-design.md:2516-2524`, under "Resource
//! servers must validate at least" — and `docs/architecture/runtime-decisions.md` §9,
//! item by item:
//!
//! | Item | Where |
//! |---|---|
//! | signature | [`jsonwebtoken::decode`] with [`DecodingKey::from_jwk`], over the `kid` the issuer published |
//! | alg allowlist | [`AllowedAlgorithms`], validated at construction; the connection's configured algorithm must be in it, and the header must name that exact algorithm |
//! | issuer | the `iss` claim against [`FederationConnection::issuer`], plus the discovery document's own `issuer` when the source publishes one |
//! | audience | the `aud` claim — one value or a list — must name [`FederationConnection::client_id`]; a list naming any other party needs an `azp` naming this one, and an `azp` naming another party is refused (OIDC Core 3.1.3.7) |
//! | expiration | `exp`, required, against [`Clock`] rather than the process clock, and bounded ahead: an `exp` at the end of time is a field, not an expiry |
//! | not-before where used | `nbf`, when the token carries one, against the same clock |
//! | token type / typ where applicable | a `typ` header that is present must be `JWT`; a `crit` naming an extension is refused, because this verifier implements none (RFC 7515 4.1.11) |
//! | sender constraint where applicable | a token carrying `cnf` is refused: this verifier terminates no sender-constrained channel, and admitting a constrained token as an unconstrained one loses the constraint |
//! | tenant/resource consistency | the proof is bound to *this* connection's issuer and client; the organization half is the handler's [`crate::authenticate::authenticate_federation`], which resolves the tenant from validated claims alone |
//!
//! `../sources/original-design.md:2527` — "Never select algorithms solely from untrusted
//! token headers" — is why the header is compared to the connection's configured
//! algorithm rather than used to choose one: a header naming anything else is refused
//! before a key is selected, let alone a signature checked.
//!
//! # What stays with `story:federation-linking`
//!
//! Issuer and client binding as *command* conditions. This module refuses a proof whose
//! `iss` or `aud` is not the connection's, and
//! [`crate::authenticate::authenticate_federation`] independently refuses a
//! [`VerifiedProof`] whose issuer or audience is not the connection's
//! (`DenialClause::IssuerMismatch`, `DenialClause::AudienceBinding`). The second check is
//! not redundant: the port admits any implementation, and the command may not assume one.
//!
//! # The network is a port, not a call
//!
//! OIDC discovery and JWKS retrieval are the only part of verification that leaves the
//! process, so they sit behind [`JwksSource`] rather than inside the verifier. The tests
//! drive [`InMemoryJwks`]; [`UreqJwks`] is exercised only against a listener the test
//! itself owns. No case in this crate reaches the network.
//!
//! `../sources/original-design.md:2529-2535` requires the JWKS fetch to be hardened
//! against SSRF, DNS rebinding, unbounded redirects, unexpected schemes, cache poisoning,
//! key-ID abuse and excessive refresh storms. What is implemented, and where:
//!
//! - **SSRF and unexpected schemes**: [`UreqJwks::admits`] parses the `jwks_uri` and
//!   bounds its destination to the issuer's own origin or a host the deployment listed
//!   for that connection ([`RealVerifier::allowing_jwks_hosts`]). A prefix match is not a
//!   bound and is gone.
//! - **Unbounded redirects**: [`UreqJwks::hardened_config`] follows none.
//! - **Key-ID abuse and refresh storms**: [`RealVerifier`] reads the source at most once
//!   per issuer per refetch interval for a `kid` no published set holds
//!   ([`RealVerifier::with_refetch_interval`]).
//! - **DNS rebinding** is *not* addressed: nothing here pins the address a host resolved
//!   to, or refuses a private range after resolution. Recorded as outstanding rather than
//!   claimed.

use core::fmt;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use mandate_types::{
    ClientId, CredentialProof, DenialReason, ExternalSubject, FederationConnectionId, Issuer,
    SigningAlgorithm,
};

use crate::record::FederationConnection;
use crate::verifier::VerifiedProof;
use crate::{DenialClause, Denied, FederationVerifier};

/// How long a fetched key set is served from the cache before it is read again.
///
/// A withdrawn key is refused once the set it was in has aged out, which is the exercised
/// half of the emergency revocation procedure (`../sources/original-design.md:2507`); the
/// other half is the issuer's, and is the act of withdrawing it.
const DEFAULT_KEY_MAX_AGE: u64 = 300;

/// How often a `kid` the cached set does not hold is looked for again.
///
/// The `kid` is resolved before the signature is checked, so an unauthenticated caller
/// decides how often this happens; without an interval, one `kid` nobody published is one
/// upstream read per presentation — the "excessive refresh storm"
/// `../sources/original-design.md:2529-2535` requires the fetch to be hardened against.
const DEFAULT_REFETCH_INTERVAL: u64 = 60;

/// The longest `sub` this verifier admits, in bytes (OIDC Core 2: "never exceeding 255
/// ASCII characters in length").
const SUBJECT_MAX_BYTES: usize = 255;

/// The furthest ahead an admitted proof's `exp` may be, in seconds.
///
/// A day, which is far longer than any ID token's lifetime and far shorter than "the end
/// of time": `exp = u64::MAX` is a token that never expires, and a verifier that reads
/// `exp` without bounding it has validated a field rather than an expiry.
const DEFAULT_MAX_PROOF_LIFETIME: u64 = 24 * 60 * 60;

/// How many refusals the log holds before the oldest is dropped.
const REFUSAL_LOG: usize = 64;

/// OIDC discovery and JWKS retrieval for one issuer, behind a port.
///
/// An implementation answers with the key set the issuer published, as the document it was
/// served and nothing more: key selection, `kid` matching and rollover across a rotation
/// window read that document and belong to the verifier, not to the transport that fetched
/// it.
///
/// `None` is "this source holds no key set for this issuer", which a verifier refuses. It
/// is not "the signature was absent" and not "the signature was valid"; a verifier that
/// collapsed the three would admit an unsigned proof whenever discovery failed.
pub trait JwksSource {
    /// The key set published for `issuer`, if this source holds one.
    fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value>;

    /// The key set published for `issuer`, with the hosts the deployment listed for the
    /// connection being verified.
    ///
    /// This is the method [`RealVerifier`] calls. It is defaulted to [`JwksSource::jwks`]
    /// so that a source which fetches nothing — every in-process one — implements the
    /// required method alone; a source that *does* leave the process overrides it,
    /// because the list is what bounds where it may go. The list is a deployment's, never
    /// a token's and never a discovery document's.
    fn jwks_from(&self, issuer: &Issuer, allowed_hosts: &[String]) -> Option<serde_json::Value> {
        let _ = allowed_hosts;
        self.jwks(issuer)
    }

    /// The OIDC discovery document published for `issuer`, if this source holds one.
    ///
    /// Defaulted to `None`, which is "this source publishes no document" and not "the
    /// document was empty": a source that answers no document asserts nothing about the
    /// issuer, and the verifier falls back on the `iss` claim and the connection alone.
    /// A source that *does* answer one has its `issuer` field checked against the issuer
    /// the key set was asked for, so a document naming another issuer refuses the proof
    /// rather than serving keys for it.
    fn discovery(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        let _ = issuer;
        None
    }
}

/// A [`JwksSource`] over documents a caller published into it.
///
/// A fixture, never a shipped implementation: it fetches nothing. It is `pub` and lives
/// here because every file under `tests/` compiles as its own crate. Publishing takes
/// `&self` and a clone shares one set of documents, so a case can rotate or withdraw a key
/// after the verifier holding it was constructed.
#[derive(Debug, Clone, Default)]
pub struct InMemoryJwks {
    published: Arc<Mutex<BTreeMap<String, Published>>>,
    reads: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, Default)]
struct Published {
    discovery: Option<serde_json::Value>,
    jwks: Option<serde_json::Value>,
}

impl InMemoryJwks {
    /// A source that publishes nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `jwks` as the key set of `issuer`, replacing any set published before.
    ///
    /// Replacing is how a rotation window opens and how an emergency revocation closes
    /// one: the set is what the issuer serves now, not what it has ever served.
    pub fn publish(&self, issuer: &Issuer, jwks: serde_json::Value) {
        self.held()
            .entry(issuer.as_str().to_owned())
            .or_default()
            .jwks = Some(jwks);
    }

    /// Publish `document` as the discovery document of `issuer`.
    pub fn publish_discovery(&self, issuer: &Issuer, document: serde_json::Value) {
        self.held()
            .entry(issuer.as_str().to_owned())
            .or_default()
            .discovery = Some(document);
    }

    /// How many times a key set has been read out of this source.
    ///
    /// A cache that works reads once; a refetch on an unknown `kid` reads twice. Nothing
    /// in the crate reads this — it exists so a case can say which of the two happened.
    #[must_use]
    pub fn fetches(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Published>> {
        self.published
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl JwksSource for InMemoryJwks {
    fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.held().get(issuer.as_str())?.jwks.clone()
    }

    fn discovery(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        self.held().get(issuer.as_str())?.discovery.clone()
    }
}

/// A [`JwksSource`] that reads the discovery document and the key set over HTTP.
///
/// The discovery document is read once per issuer and held, because `jwks_uri` is stable
/// and the *keys* are what rotate; [`UreqJwks::forget`] drops it for a deployment whose
/// document has moved. The key set itself is never cached here — that is
/// [`RealVerifier`]'s, which is where the rotation window and the revocation age live.
pub struct UreqJwks {
    agent: ureq::Agent,
    documents: Mutex<BTreeMap<String, serde_json::Value>>,
}

impl UreqJwks {
    /// A source over an agent that follows no redirect, gives up after five seconds, and
    /// terminates TLS with the host's own provider.
    ///
    /// The provider is named rather than left to `ureq`'s default. The default is
    /// `Rustls`, which this workspace does not compile in (`Cargo.toml`: `ureq` with
    /// `default-features = false`), and `ureq` answers an `https` URI under a provider it
    /// cannot supply by panicking, not by failing the request. Roots come from the
    /// platform store, which is the same choice the workspace made when it took
    /// `native-tls` without a bundled root set.
    #[must_use]
    pub fn new() -> Self {
        Self::over(ureq::Agent::new_with_config(Self::hardened_config()))
    }

    /// The configuration [`UreqJwks::new`] ships.
    ///
    /// Public so that a deployment adding one thing to it — a proxy, a shorter timeout —
    /// starts from the hardened configuration rather than from `ureq`'s default, and so
    /// that a case can read back what was configured rather than infer it from a request
    /// that happened not to be made.
    #[must_use]
    pub fn hardened_config() -> ureq::config::Config {
        ureq::config::Config::builder()
            // A redirect away from the `jwks_uri` is a destination the document never
            // named and the deployment never listed.
            .max_redirects(0)
            // `ureq`'s default proxy is `Proxy::try_from_env()`, so leaving this unset
            // would make the destination depend on `ALL_PROXY`, `HTTPS_PROXY` or
            // `HTTP_PROXY` in the serving process's environment — an egress nobody
            // configured through `allowing_jwks_hosts` and nobody can read off the
            // connection. The shipped source uses no environment proxy at all. An explicit
            // egress proxy is a later deployment option and is absent, not implied.
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(5)))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
    }

    /// A source over an agent the deployment configured.
    #[must_use]
    pub fn over(agent: ureq::Agent) -> Self {
        Self {
            agent,
            documents: Mutex::new(BTreeMap::new()),
        }
    }

    /// Drop every discovery document held, so the next read fetches it again.
    pub fn forget(&self) {
        self.held().clear();
    }

    /// Whether this source would fetch `uri` as the key set of `issuer`, given the hosts
    /// the deployment listed for the connection.
    ///
    /// The document is served by the issuer, so its `jwks_uri` is as trusted as the
    /// issuer — and no further. The URI is parsed, not prefix-matched: a string prefix is
    /// not an origin, and `https://issuer.example@attacker.example/jwks` begins with the
    /// issuer and names the attacker. Admitted when, and only when:
    ///
    /// - it parses as `scheme://host[:port]/…` carrying **no** userinfo;
    /// - its scheme is the issuer's own, so an `https` issuer can never be downgraded;
    /// - and either its (host, port) is the issuer's, or its host is one the deployment
    ///   listed for this connection — some IdPs publish keys on a second host — in which
    ///   case the scheme must be `https`, the port must be the one listed beside the host,
    ///   and the host must be a name, never an address literal and never a spelling of the
    ///   loopback interface, which is the shape an SSRF attempt at a link-local metadata
    ///   service takes.
    ///
    /// Both comparisons normalize the port: RFC 3986 6.2.3 makes the scheme's default port
    /// equivalent to an elided one, so `https://idp.example` and `https://idp.example:443`
    /// are one origin, and a document that spells the default leaves the connection
    /// working. An entry in `allowed_hosts` may carry a port (`keys.idp.example:8443`);
    /// one that does not admits the scheme's default port and no other, because a host is
    /// a host and not every port on it.
    ///
    /// Plaintext survives only for a loopback issuer, which is what a test's own listener
    /// is; no deployment's issuer is one.
    #[must_use]
    pub fn admits(issuer: &Issuer, uri: &str, allowed_hosts: &[String]) -> bool {
        let (Some(target), Some(source)) = (origin(uri), origin(issuer.as_str())) else {
            return false;
        };
        if target.scheme != source.scheme {
            return false;
        }
        if (&target.host, target.port) == (&source.host, source.port) {
            return target.scheme == "https" || loopback(&target.host);
        }
        target.scheme == "https"
            && !literal_address(&target.host)
            && !loopback(&target.host)
            && allowed_hosts.iter().any(|entry| listed(entry, &target))
    }

    fn key_set(&self, issuer: &Issuer, allowed_hosts: &[String]) -> Option<serde_json::Value> {
        let document = self.document(issuer)?;
        let uri = document.get("jwks_uri")?.as_str()?;
        if !Self::admits(issuer, uri, allowed_hosts) {
            return None;
        }
        self.fetch(uri)
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, serde_json::Value>> {
        self.documents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn document(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        if let Some(held) = self.held().get(issuer.as_str()) {
            return Some(held.clone());
        }
        let fetched = self.fetch(&format!(
            "{}/.well-known/openid-configuration",
            issuer.as_str().trim_end_matches('/')
        ))?;
        self.held()
            .insert(issuer.as_str().to_owned(), fetched.clone());
        Some(fetched)
    }

    fn fetch(&self, url: &str) -> Option<serde_json::Value> {
        let mut response = self.agent.get(url).call().ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = response.body_mut().read_to_string().ok()?;
        serde_json::from_str(&body).ok()
    }
}

impl Default for UreqJwks {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UreqJwks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UreqJwks")
    }
}

impl JwksSource for UreqJwks {
    /// The key set, admitting only the issuer's own origin: a caller reaching the port
    /// directly has named no other host for it.
    fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        self.key_set(issuer, &[])
    }

    fn jwks_from(&self, issuer: &Issuer, allowed_hosts: &[String]) -> Option<serde_json::Value> {
        self.key_set(issuer, allowed_hosts)
    }

    fn discovery(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        self.document(issuer)
    }
}

/// The scheme, host and port of an absolute URI, split for comparison.
///
/// The port is never `None`: an elided one is the scheme's default (RFC 3986 6.2.3), so a
/// comparison cannot be defeated by spelling it or by leaving it out.
struct Uri {
    scheme: String,
    host: String,
    port: u16,
}

/// Parse `scheme://[userinfo@]host[:port]…`, refusing any URI that carries userinfo.
///
/// Userinfo is refused rather than ignored: it exists here only to make a URI *look* like
/// it names one host while naming another, and no discovery document has a use for it.
fn origin(uri: &str) -> Option<Uri> {
    let (scheme, rest) = uri.split_once("://")?;
    if scheme.is_empty() || !scheme.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())?;
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.split_once(']') {
        // An IPv6 literal: `[::1]` or `[::1]:8443`.
        Some((bracketed, after)) => (bracketed.strip_prefix('[')?, after.strip_prefix(':')),
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return None;
    }
    // A port that is spelled must parse. Anything else is a host this parser would be
    // guessing about, and guessing is what the whole guard exists not to do.
    let port = match port {
        None | Some("") => default_port(&scheme)?,
        Some(spelled) => spelled.parse::<u16>().ok()?,
    };
    Some(Uri {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// The scheme's default port, for the two schemes a key set is ever fetched over.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

/// Whether an `allowed_hosts` entry names this destination, port included.
///
/// An entry is `host` or `host:port`. Without a port it admits the scheme's default and
/// nothing else: the deployment named a host to fetch a key set from, not every service
/// listening on it.
fn listed(entry: &str, target: &Uri) -> bool {
    let (host, port) = match entry.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => match port.parse::<u16>() {
            Ok(port) => (host, port),
            // An entry whose port does not parse names nothing.
            Err(_) => return false,
        },
        _ => (
            entry,
            match default_port(&target.scheme) {
                Some(port) => port,
                None => return false,
            },
        ),
    };
    host.eq_ignore_ascii_case(&target.host) && port == target.port
}

/// Whether the host is an address literal rather than a name.
fn literal_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Whether the host is the loopback interface, by name class or by literal.
///
/// A name class, not a string: `localhost.` is the absolute form of the same name, and
/// `localhost.localdomain` is in the stock `/etc/hosts` of an ordinary Linux host. Both
/// resolve to `127.0.0.1`, so a guard that compared against `"localhost"` alone would
/// admit the loopback interface under two spellings the deployment could list.
///
/// Every address literal that is loopback is one too. Whether a *name* resolves to the
/// loopback interface at fetch time is a resolution-order question this function cannot
/// answer; the residue is recorded with DNS rebinding in the module documentation.
fn loopback(host: &str) -> bool {
    let name = host.trim_end_matches('.');
    name.eq_ignore_ascii_case("localhost")
        || name.to_ascii_lowercase().ends_with(".localdomain")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The instant a verification is being made at, behind a port.
///
/// `exp` and `nbf` are checked against this and never against the process clock, so a
/// verification is a function of its inputs: the same proof, the same key set and the same
/// instant give the same answer.
pub trait Clock {
    /// The instant, as seconds since the Unix epoch.
    fn unix_seconds(&self) -> u64;
}

/// The host clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// A clock a caller sets and moves.
///
/// A fixture, never a shipped implementation. A clone shares the instant, so a case can
/// move the clock a verifier already holds.
#[derive(Debug, Clone, Default)]
pub struct FixedClock(Arc<AtomicU64>);

impl FixedClock {
    /// A clock reading `seconds` since the Unix epoch.
    #[must_use]
    pub fn at(seconds: u64) -> Self {
        Self(Arc::new(AtomicU64::new(seconds)))
    }

    /// Move the clock to `seconds`.
    pub fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::SeqCst);
    }

    /// Move the clock forward by `seconds`.
    pub fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// One of the two algorithm names the approved allowlist may hold.
///
/// `decision-blocker:algorithm-policy`, approved 2026-09-18: RS256 and ES256,
/// deployment-configured and validated at startup. The type exists so that an admitted
/// algorithm cannot be constructed from a name that was never approved — a
/// [`jsonwebtoken::Algorithm`] can, and its `Default` is `HS256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdmittedAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
    /// ECDSA using P-256 and SHA-256.
    Es256,
}

impl AdmittedAlgorithm {
    /// The JOSE `alg` name, exactly as a header carries it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }

    /// The algorithm the JOSE implementation verifies under.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Es256 => Algorithm::ES256,
        }
    }

    /// The admitted algorithm this name denotes.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmPolicyError::Unsigned`] for `none` and
    /// [`AlgorithmPolicyError::Unadmitted`] for every other name, including a name the
    /// JOSE implementation knows: what the build can compute is not what the policy
    /// admits.
    pub fn named(name: &str) -> Result<Self, AlgorithmPolicyError> {
        match name {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            "none" => Err(AlgorithmPolicyError::Unsigned),
            other => Err(AlgorithmPolicyError::Unadmitted(other.to_owned())),
        }
    }
}

/// Why a configured algorithm list is not an admitted one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgorithmPolicyError {
    /// The deployment configured no algorithm at all. An empty set is refused rather than
    /// defaulted: a defaulted [`jsonwebtoken::Algorithm`] is `HS256`, the shared-secret
    /// family this policy exists to refuse.
    Unconfigured,
    /// The name `none`. A token is refused for carrying it, and a deployment is refused
    /// for configuring it.
    Unsigned,
    /// A name outside the approved allowlist: unknown text, a differently-cased spelling,
    /// or an algorithm the JOSE implementation supports and this policy does not.
    Unadmitted(String),
}

impl fmt::Display for AlgorithmPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unconfigured => formatter.write_str("no algorithm is configured"),
            Self::Unsigned => formatter.write_str("the unsigned algorithm is not admitted"),
            Self::Unadmitted(name) => write!(formatter, "the algorithm {name} is not admitted"),
        }
    }
}

impl std::error::Error for AlgorithmPolicyError {}

/// The deployment's algorithm allowlist, validated when it is built.
///
/// `decision-blocker:algorithm-policy`: a deployment-configured allowlist validated at
/// startup, rejecting unknown names and rejecting an empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedAlgorithms {
    admitted: Vec<AdmittedAlgorithm>,
}

impl AllowedAlgorithms {
    /// The allowlist these configured names denote.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmPolicyError::Unconfigured`] for an empty list, and the error
    /// [`AdmittedAlgorithm::named`] returns for the first name outside the allowlist.
    pub fn configured(names: &[SigningAlgorithm]) -> Result<Self, AlgorithmPolicyError> {
        if names.is_empty() {
            return Err(AlgorithmPolicyError::Unconfigured);
        }
        let mut admitted = Vec::with_capacity(names.len());
        for name in names {
            let one = AdmittedAlgorithm::named(name.as_str())?;
            if !admitted.contains(&one) {
                admitted.push(one);
            }
        }
        Ok(Self { admitted })
    }

    /// Whether this allowlist admits an algorithm.
    #[must_use]
    pub fn admits(&self, algorithm: AdmittedAlgorithm) -> bool {
        self.admitted.contains(&algorithm)
    }

    /// The admitted algorithms, in the order the deployment configured them.
    #[must_use]
    pub fn admitted(&self) -> &[AdmittedAlgorithm] {
        &self.admitted
    }
}

/// Why a proof was refused.
///
/// Log-safe by construction: every variant is a bare name, so a deployment can log the
/// condition that fired without logging any part of the proof, the claims or the key. It
/// is deliberately *not* carried on [`Denied`], which holds the contract's
/// [`DenialReason`] and the declared clause alone — a caller learning which of these
/// fired learns how to make the next attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RefusalReason {
    /// The deployment configured no algorithm for this connection.
    ConnectionAlgorithmUnconfigured,
    /// The presented material is not a compact JWS.
    MalformedToken,
    /// The header names `none`.
    UnsignedAlgorithm,
    /// The header names an algorithm that is not this connection's configured one.
    HeaderAlgorithmNotConfigured,
    /// The header carries a `typ` that is not `JWT`.
    UnexpectedTokenType,
    /// The header names a critical extension this verifier does not implement.
    CriticalHeaderUnread,
    /// The header names no `kid`, so no published key can be selected.
    KeyIdAbsent,
    /// The source holds no key set for this issuer.
    KeySetUnavailable,
    /// The key set is not a JWKS.
    KeySetMalformed,
    /// The discovery document names another issuer than the one it was read for.
    DiscoveryIssuerMismatch,
    /// No published key carries this `kid`, after a refetch.
    KeyIdUnknown,
    /// The published key cannot be read as a verification key.
    KeyMalformed,
    /// The published key names an algorithm other than the connection's configured one.
    KeyAlgorithmMismatch,
    /// The signature does not verify under the published key.
    SignatureInvalid,
    /// The payload is not a JSON object of claims.
    ClaimsMalformed,
    /// The `iss` claim is absent, or is not the connection's configured issuer.
    IssuerMismatch,
    /// No `aud` value is the connection's configured client, or `aud` is not an audience
    /// claim at all.
    AudienceMismatch,
    /// The `aud` names a party beside this client and no `azp` names this one.
    AudienceUntrusted,
    /// The `azp` claim names a party other than the connection's configured client.
    AuthorizedPartyMismatch,
    /// The token carries no `exp`.
    ExpiryAbsent,
    /// The `exp` has passed.
    Expired,
    /// The `exp` is further away than any login proof's lifetime.
    ExpiryTooDistant,
    /// The `nbf` has not arrived.
    NotYetValid,
    /// The token declares a sender constraint no channel binding here can check.
    SenderConstraintUnverifiable,
    /// The `sub` claim is absent or empty.
    SubjectAbsent,
    /// The `sub` claim is longer than OIDC admits.
    SubjectTooLong,
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

/// The key set read for one issuer, when it was read, when a `kid` it does not hold was
/// last looked for, and whether a caller is looking right now.
#[derive(Debug, Clone, Default)]
struct CachedKeys {
    keys: Vec<Jwk>,
    read_at: u64,
    missed_at: Option<u64>,
    /// Claimed under the lock by the one caller performing a refetch for this issuer.
    refreshing: bool,
}

/// What a caller does about a `kid`, decided under the lock in one act.
///
/// The key is boxed because a `Jwk` is two orders of magnitude larger than the other two
/// variants, and this value exists only to carry a decision out of a lock.
enum Plan {
    /// The cached set holds it.
    Serve(Box<Jwk>),
    /// This caller performs the read.
    Read,
    /// No read: the set does not hold it and the source has already been asked, or is
    /// being asked right now.
    Refuse,
}

/// What the deployment configured for one connection.
///
/// The algorithm is an `Option` because the hosts can be listed for a connection whose
/// algorithm has not been configured yet, and a defaulted algorithm is exactly what this
/// module refuses to have: `jsonwebtoken`'s own default is `HS256`.
#[derive(Debug, Clone, Default)]
struct Configured {
    algorithm: Option<AdmittedAlgorithm>,
    jwks_hosts: Vec<String>,
}

/// The real [`FederationVerifier`]: an allowlist, a [`JwksSource`] and a [`Clock`].
///
/// The algorithm a connection's proofs are verified under is the deployment's
/// configuration for that connection, not a field of the proof and not a field of
/// [`FederationConnection`], which declares none. A connection no algorithm was configured
/// for verifies nothing: it is the "unconfigured algorithm name is rejected … at
/// validation" half of `decision-blocker:algorithm-policy`'s evidence, and it fails
/// closed.
#[derive(Debug)]
pub struct RealVerifier<S, C> {
    allowed: AllowedAlgorithms,
    configured: BTreeMap<FederationConnectionId, Configured>,
    source: S,
    clock: C,
    key_max_age: u64,
    refetch_interval: u64,
    max_proof_lifetime: u64,
    cached: Mutex<BTreeMap<String, CachedKeys>>,
    refusals: Mutex<Vec<RefusalReason>>,
}

impl<S: JwksSource, C: Clock> RealVerifier<S, C> {
    /// A verifier over this allowlist, this source of published keys and this clock.
    #[must_use]
    pub fn new(allowed: AllowedAlgorithms, source: S, clock: C) -> Self {
        Self {
            allowed,
            configured: BTreeMap::new(),
            source,
            clock,
            key_max_age: DEFAULT_KEY_MAX_AGE,
            refetch_interval: DEFAULT_REFETCH_INTERVAL,
            max_proof_lifetime: DEFAULT_MAX_PROOF_LIFETIME,
            cached: Mutex::new(BTreeMap::new()),
            refusals: Mutex::new(Vec::new()),
        }
    }

    /// Refuse a proof whose `exp` is more than `seconds` ahead of the clock.
    #[must_use]
    pub fn with_max_proof_lifetime(mut self, seconds: u64) -> Self {
        self.max_proof_lifetime = seconds;
        self
    }

    /// Serve a fetched key set from the cache for at most `seconds`.
    #[must_use]
    pub fn with_key_max_age(mut self, seconds: u64) -> Self {
        self.key_max_age = seconds;
        self
    }

    /// Look for a `kid` the cached set does not hold at most once per `seconds`.
    #[must_use]
    pub fn with_refetch_interval(mut self, seconds: u64) -> Self {
        self.refetch_interval = seconds;
        self
    }

    /// Configure the algorithm this connection's proofs are verified under.
    ///
    /// # Errors
    ///
    /// Returns the error [`AdmittedAlgorithm::named`] returns for a name outside the
    /// approved allowlist, and [`AlgorithmPolicyError::Unadmitted`] for an admitted name
    /// this deployment's own allowlist does not hold.
    pub fn configure_connection(
        mut self,
        connection_id: FederationConnectionId,
        name: &SigningAlgorithm,
    ) -> Result<Self, AlgorithmPolicyError> {
        let algorithm = AdmittedAlgorithm::named(name.as_str())?;
        if !self.allowed.admits(algorithm) {
            return Err(AlgorithmPolicyError::Unadmitted(name.as_str().to_owned()));
        }
        self.configured.entry(connection_id).or_default().algorithm = Some(algorithm);
        Ok(self)
    }

    /// List the hosts this connection's key set may be fetched from, beside its algorithm.
    ///
    /// Empty by default, which admits the issuer's own origin and nothing else. A
    /// deployment lists a host here because the IdP publishes its keys on one — the
    /// discovery document is not allowed to introduce a destination the deployment never
    /// named, and a host listed here still has to arrive as `https` and as a name.
    ///
    /// It is a method of its own rather than a parameter of
    /// [`RealVerifier::configure_connection`] so that configuring an algorithm keeps the
    /// shape every caller already has; the two land in one per-connection record.
    #[must_use]
    pub fn allowing_jwks_hosts(
        mut self,
        connection_id: FederationConnectionId,
        hosts: &[&str],
    ) -> Self {
        self.configured.entry(connection_id).or_default().jwks_hosts =
            hosts.iter().map(|host| host.to_ascii_lowercase()).collect();
        self
    }

    /// Drop this issuer's cached key set at once.
    ///
    /// The emergency revocation path: withdrawing a key from the published set stops it
    /// verifying when the cached set ages out, and an operator who cannot wait that long
    /// calls this. It is `&self` because it is an operational act on a running verifier,
    /// not a step in building one.
    pub fn forget(&self, issuer: &Issuer) {
        self.cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(issuer.as_str());
    }

    /// Every refusal this verifier has made, oldest first, capped at the last 64.
    ///
    /// The material the refusal was about is not here and never was; see
    /// [`RefusalReason`].
    #[must_use]
    pub fn refusals(&self) -> Vec<RefusalReason> {
        self.refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn record(&self, reason: RefusalReason) {
        let mut log = self
            .refusals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if log.len() == REFUSAL_LOG {
            log.remove(0);
        }
        log.push(reason);
    }

    /// The hosts the deployment listed for this connection's key set, if any.
    fn jwks_hosts_of(&self, connection: &FederationConnection) -> &[String] {
        self.configured
            .get(&connection.id)
            .map_or(&[], |held| held.jwks_hosts.as_slice())
    }

    /// The algorithm the deployment configured for this connection, if it admits one.
    fn algorithm_of(
        &self,
        connection: &FederationConnection,
    ) -> Result<AdmittedAlgorithm, RefusalReason> {
        let configured = self
            .configured
            .get(&connection.id)
            .and_then(|held| held.algorithm)
            .ok_or(RefusalReason::ConnectionAlgorithmUnconfigured)?;
        // The allowlist is checked again here rather than trusted from construction: the
        // allowlist is the policy, and a verifier that only enforced it in a builder would
        // enforce it exactly once, at a point no proof passes through.
        if !self.allowed.admits(configured) {
            return Err(RefusalReason::ConnectionAlgorithmUnconfigured);
        }
        Ok(configured)
    }

    /// The published key carrying `kid`, reading the source when the cache cannot answer.
    ///
    /// Three properties, and each is a case:
    ///
    /// - A `kid` the cached set does not hold is looked for once more, which is what a
    ///   rotation window makes necessary.
    /// - That second look happens at most once per issuer per refetch interval, whatever
    ///   the *rate* of presentation, simultaneous arrivals included. The `kid` is resolved
    ///   *before* the signature is checked, so an unauthenticated caller reaches the
    ///   source and decides how many presentations arrive at once; one unknown `kid`
    ///   presented a thousand times, or eight times in one instant, must not be a thousand
    ///   reads or eight (`../sources/original-design.md:2529-2535`, "excessive refresh
    ///   storms"). A check of `missed_at` followed by a store *after* the read bounds a
    ///   sequence and not a rate, because every caller passes the check before any of them
    ///   reaches the store; the bound is a marker claimed under the lock before the read.
    /// - The cache mutex is never held across the port call. A source that blocks — a
    ///   slow IdP is the ordinary case — must not stall verification for every other
    ///   issuer.
    fn key(
        &self,
        issuer: &Issuer,
        kid: &str,
        allowed_hosts: &[String],
    ) -> Result<Jwk, RefusalReason> {
        let now = self.clock.unix_seconds();
        match self.plan(issuer, kid, now) {
            Plan::Serve(jwk) => Ok(*jwk),
            Plan::Refuse => Err(RefusalReason::KeyIdUnknown),
            Plan::Read => {
                // The lock is not held here, and exactly one caller per issuer per
                // interval is.
                let read = self.read(issuer, allowed_hosts);
                self.fold(issuer, kid, now, read)
            }
        }
    }

    /// Decide, under the lock and in one act, whether this caller serves, refuses, or
    /// performs the read — claiming the read before releasing the lock.
    fn plan(&self, issuer: &Issuer, kid: &str, now: u64) -> Plan {
        let mut cached = self.locked();
        let Some(held) = cached.get_mut(issuer.as_str()) else {
            // Nothing is held. Filling an empty cache is not the refetch this bounds, and
            // a caller waiting on another caller's first read would be refused a proof
            // that is about to become verifiable.
            return Plan::Read;
        };
        if now >= held.read_at.saturating_add(self.key_max_age) {
            // Too old to serve. Same reasoning as an empty cache.
            return Plan::Read;
        }
        if let Some(found) = select(&held.keys, kid) {
            return Plan::Serve(Box::new(found));
        }
        if held
            .missed_at
            .is_some_and(|missed| now < missed.saturating_add(self.refetch_interval))
        {
            // A `kid` this set does not hold was already looked for inside this interval.
            // The answer has not changed and the source is not asked again.
            return Plan::Refuse;
        }
        if held.refreshing {
            // Another caller is reading for this issuer right now. Waiting for it would
            // make an unknown `kid` a way to hold verification threads; refusing costs
            // this caller a refusal it was going to get anyway.
            return Plan::Refuse;
        }
        held.refreshing = true;
        Plan::Read
    }

    /// Fold a completed read back into the cache, releasing the marker.
    ///
    /// Re-checked under the lock rather than assumed: another caller may have folded a
    /// newer set while this read was in flight, and may have recorded the miss. The marker
    /// is released on the error path too, or one failed read would suppress every later
    /// refetch for that issuer.
    fn fold(
        &self,
        issuer: &Issuer,
        kid: &str,
        now: u64,
        read: Result<Vec<Jwk>, RefusalReason>,
    ) -> Result<Jwk, RefusalReason> {
        let mut cached = self.locked();
        let held = cached.entry(issuer.as_str().to_owned()).or_default();
        held.refreshing = false;
        let keys = read?;
        if held.read_at <= now {
            held.keys = keys;
            held.read_at = now;
            // The miss recorded against the previous set says nothing about this one.
            held.missed_at = None;
        }
        match select(&held.keys, kid) {
            Some(found) => Ok(found),
            None => {
                if held.missed_at.is_none_or(|missed| missed <= now) {
                    held.missed_at = Some(now);
                }
                Err(RefusalReason::KeyIdUnknown)
            }
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, CachedKeys>> {
        self.cached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Read the issuer's published key set through the port. No lock is held here.
    fn read(&self, issuer: &Issuer, allowed_hosts: &[String]) -> Result<Vec<Jwk>, RefusalReason> {
        if let Some(document) = self.source.discovery(issuer) {
            let named = document
                .get("issuer")
                .and_then(serde_json::Value::as_str)
                .ok_or(RefusalReason::DiscoveryIssuerMismatch)?;
            if named != issuer.as_str() {
                return Err(RefusalReason::DiscoveryIssuerMismatch);
            }
        }
        let published = self
            .source
            .jwks_from(issuer, allowed_hosts)
            .ok_or(RefusalReason::KeySetUnavailable)?;
        let set: JwkSet =
            serde_json::from_value(published).map_err(|_| RefusalReason::KeySetMalformed)?;
        Ok(set.keys)
    }

    /// The whole verification, in the order the refusals are declared in.
    fn validate(
        &self,
        connection: &FederationConnection,
        proof: &CredentialProof,
    ) -> Result<VerifiedProof, RefusalReason> {
        let configured = self.algorithm_of(connection)?;
        let token =
            std::str::from_utf8(proof.expose_bytes()).map_err(|_| RefusalReason::MalformedToken)?;
        let header = jose_header(token)?;
        // The algorithm is the connection's, and the header is only ever compared to it.
        if header.algorithm == "none" {
            return Err(RefusalReason::UnsignedAlgorithm);
        }
        if header.algorithm != configured.name() {
            return Err(RefusalReason::HeaderAlgorithmNotConfigured);
        }
        if let Some(declared) = &header.token_type
            && !declared.eq_ignore_ascii_case("JWT")
        {
            return Err(RefusalReason::UnexpectedTokenType);
        }
        // RFC 7515 4.1.11: a recipient must reject a JWS whose `crit` names a header
        // parameter it does not understand. This verifier reads `alg`, `kid` and `typ`,
        // understands no extension, and so can honour no `crit` at all.
        if header.critical {
            return Err(RefusalReason::CriticalHeaderUnread);
        }
        let kid = header.key_id.ok_or(RefusalReason::KeyIdAbsent)?;
        let jwk = self.key(&connection.issuer, &kid, self.jwks_hosts_of(connection))?;
        if let Some(named) = jwk.common.key_algorithm
            && named.to_string() != configured.name()
        {
            return Err(RefusalReason::KeyAlgorithmMismatch);
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| RefusalReason::KeyMalformed)?;

        let mut validation = Validation::new(configured.algorithm());
        // Every claim this crate requires is required below, against this verifier's own
        // clock; `jsonwebtoken`'s validation reads the process clock, which would make a
        // verification a function of when it ran.
        validation.required_spec_claims = HashSet::new();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        let decoded = decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|_| RefusalReason::SignatureInvalid)?;
        let claims = decoded
            .claims
            .as_object()
            .ok_or(RefusalReason::ClaimsMalformed)?;

        let issuer = text(claims, "iss").ok_or(RefusalReason::IssuerMismatch)?;
        if issuer != connection.issuer.as_str() {
            return Err(RefusalReason::IssuerMismatch);
        }
        let named = audiences(claims).ok_or(RefusalReason::AudienceMismatch)?;
        let audience = named
            .iter()
            .find(|audience| *audience == connection.client_id.as_str())
            .cloned()
            .ok_or(RefusalReason::AudienceMismatch)?;
        // An `azp` in a shape OIDC does not define is still an `azp`, and it does not name
        // this client. Reading it with a helper that answers `None` for a list would make
        // the malformed form the one that changes nothing — the opposite of how `exp`,
        // `sub` and `aud` are read.
        let party = match claims.get("azp") {
            None => None,
            Some(serde_json::Value::String(party)) if party == connection.client_id.as_str() => {
                Some(party.clone())
            }
            Some(_) => return Err(RefusalReason::AuthorizedPartyMismatch),
        };
        // OIDC Core 3.1.3.7 step 3: a token whose `aud` names a party the client does not
        // trust is rejected; step 4 wants `azp` naming this client when there are several.
        // The connection configures exactly one client, so an untrusted party is any
        // audience that is not it — membership, not a count: an `aud` naming this client
        // twice names nobody else.
        if named
            .iter()
            .any(|audience| audience != connection.client_id.as_str())
            && party.is_none()
        {
            return Err(RefusalReason::AudienceUntrusted);
        }
        let now = self.clock.unix_seconds();
        let expiry = seconds(claims, "exp").ok_or(RefusalReason::ExpiryAbsent)?;
        if now >= expiry {
            return Err(RefusalReason::Expired);
        }
        // A proof that expires at the end of time has an `exp` and no expiry. The ceiling
        // is the verifier's, and it is deliberately generous: the per-profile maximum TTL
        // is `story:credential-profiles`' (`combined.md:41`), and this only refuses a
        // lifetime no login proof has.
        if expiry.saturating_sub(now) > self.max_proof_lifetime {
            return Err(RefusalReason::ExpiryTooDistant);
        }
        if let Some(not_before) = seconds(claims, "nbf")
            && now < not_before
        {
            return Err(RefusalReason::NotYetValid);
        }
        if claims.contains_key("cnf") {
            return Err(RefusalReason::SenderConstraintUnverifiable);
        }
        let subject = text(claims, "sub")
            .filter(|subject| !subject.is_empty())
            .ok_or(RefusalReason::SubjectAbsent)?;
        // OIDC Core 2: `sub` is "never exceeding 255 ASCII characters in length". The
        // subject becomes a component of the canonical external key and the generated
        // display name on a persisted event, so an unbounded one is a persisted record of
        // whatever length the caller chose.
        if subject.len() > SUBJECT_MAX_BYTES {
            return Err(RefusalReason::SubjectTooLong);
        }

        let mut verified = VerifiedProof::new(
            Issuer::new(issuer),
            ExternalSubject::new(subject),
            ClientId::new(audience),
        );
        for (name, value) in claims {
            let serde_json::Value::String(carried) = value else {
                continue;
            };
            verified = if issuer_verified(claims, name) {
                verified.with_verified_claim(name, carried)
            } else {
                // Signed is not verified: the signature says the issuer sent the value,
                // and the companion says the issuer did not check it. Tenant resolution
                // reads validated claims alone, so this value can refuse a request and
                // never resolve one.
                verified.with_unverified_hint(name, carried)
            };
        }
        Ok(verified)
    }
}

impl<S: JwksSource, C: Clock> FederationVerifier for RealVerifier<S, C> {
    fn verify(
        &self,
        connection: &FederationConnection,
        proof: &CredentialProof,
    ) -> Result<VerifiedProof, Denied> {
        self.validate(connection, proof).map_err(|reason| {
            self.record(reason);
            refused(reason)
        })
    }
}

/// The contract's denial for a refusal. Fail closed: every reason denies, and the reason
/// itself stays in the log.
///
/// Every variant is named here and there is no wildcard arm, so a reason added to
/// [`RefusalReason`] does not compile until its denial has been decided. A refusal whose
/// contract denial was defaulted rather than chosen is the defect this shape refuses to
/// let through — `DenialClause::ProofInvalid` is the right answer for most of them and is
/// not the right answer for any of them by accident.
fn refused(reason: RefusalReason) -> Denied {
    match reason {
        RefusalReason::ConnectionAlgorithmUnconfigured
        | RefusalReason::UnsignedAlgorithm
        | RefusalReason::HeaderAlgorithmNotConfigured => Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::AlgorithmPolicy,
        ),
        RefusalReason::IssuerMismatch | RefusalReason::DiscoveryIssuerMismatch => Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::IssuerMismatch,
        ),
        RefusalReason::AudienceMismatch
        | RefusalReason::AudienceUntrusted
        | RefusalReason::AuthorizedPartyMismatch => Denied::new(
            DenialReason::AudienceMismatch,
            DenialClause::AudienceBinding,
        ),
        RefusalReason::MalformedToken
        | RefusalReason::UnexpectedTokenType
        | RefusalReason::CriticalHeaderUnread
        | RefusalReason::KeyIdAbsent
        | RefusalReason::KeySetUnavailable
        | RefusalReason::KeySetMalformed
        | RefusalReason::KeyIdUnknown
        | RefusalReason::KeyMalformed
        | RefusalReason::KeyAlgorithmMismatch
        | RefusalReason::SignatureInvalid
        | RefusalReason::ClaimsMalformed
        | RefusalReason::ExpiryAbsent
        | RefusalReason::Expired
        | RefusalReason::ExpiryTooDistant
        | RefusalReason::NotYetValid
        | RefusalReason::SenderConstraintUnverifiable
        | RefusalReason::SubjectAbsent
        | RefusalReason::SubjectTooLong => {
            Denied::new(DenialReason::InvalidCredential, DenialClause::ProofInvalid)
        }
    }
}

/// The published key carrying this `kid`, if the set holds one.
fn select(keys: &[Jwk], kid: &str) -> Option<Jwk> {
    keys.iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
        .cloned()
}

/// Whether the issuer asserted it had verified the claim it signed.
///
/// OIDC defines a verification companion for exactly two claims — `email_verified` for
/// `email`, `phone_number_verified` for `phone_number` (OIDC Core 5.1) — and for those
/// two, an absent companion is not an assertion that the issuer checked anything. Absence
/// is not verification: an address the issuer merely accepted at sign-up must not resolve
/// a tenant, which is the `tenant-unverified` case of `tests/security/cases.json`.
///
/// Every other claim is issuer-asserted as signed. Inventing a `<claim>_verified`
/// convention for claims OIDC does not define one for would make a claim's standing
/// depend on a companion no issuer sends.
///
/// Trust assumption, recorded because it is a real one: the companion is the IdP's to
/// send, so a lax IdP can promote its own claim by sending `true`. That is the customer's
/// IdP policy; this verifier reports what the issuer asserted, and the connection's
/// configured trust is what decides whether that issuer is believed at all.
fn issuer_verified(claims: &serde_json::Map<String, serde_json::Value>, name: &str) -> bool {
    let companion = match name {
        "email" => "email_verified",
        "phone_number" => "phone_number_verified",
        _ => return true,
    };
    claims.get(companion) == Some(&serde_json::Value::Bool(true))
}

fn text(claims: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<String> {
    claims.get(name)?.as_str().map(ToOwned::to_owned)
}

fn seconds(claims: &serde_json::Map<String, serde_json::Value>, name: &str) -> Option<u64> {
    claims.get(name)?.as_u64()
}

/// Every audience the token names, whether it names one or a list of them.
///
/// `None` is "this is not an audience claim": absent, null, an object, or a list holding
/// anything that is not a string. A member that cannot be read is not silently dropped —
/// dropping it would turn a list this verifier does not understand into a shorter list it
/// does, and the count is what decides whether an `azp` is required.
fn audiences(claims: &serde_json::Map<String, serde_json::Value>) -> Option<Vec<String>> {
    match claims.get("aud") {
        Some(serde_json::Value::String(one)) => Some(vec![one.clone()]),
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => None,
    }
}

/// The JOSE header fields this verifier's policy reads.
///
/// The header is parsed here rather than through [`jsonwebtoken::decode_header`] because
/// that function's `alg` is a typed enum: a header naming `none` fails to deserialize, and
/// a refusal that cannot tell `none` from a malformed header cannot report that `none` was
/// refused.
struct JoseHeader {
    algorithm: String,
    key_id: Option<String>,
    token_type: Option<String>,
    critical: bool,
}

fn jose_header(token: &str) -> Result<JoseHeader, RefusalReason> {
    let mut segments = token.split('.');
    let (Some(encoded), Some(payload), Some(_signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(RefusalReason::MalformedToken);
    };
    if payload.is_empty() {
        return Err(RefusalReason::MalformedToken);
    }
    let decoded = base64url(encoded).ok_or(RefusalReason::MalformedToken)?;
    let document: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|_| RefusalReason::MalformedToken)?;
    let algorithm = document
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or(RefusalReason::MalformedToken)?
        .to_owned();
    Ok(JoseHeader {
        algorithm,
        // `jku`, `x5u`, `x5c` and an embedded `jwk` are not read at all: key material a
        // token carries is the token vouching for itself. The key comes from the issuer's
        // published set, by `kid`, and from nowhere else.
        critical: document.get("crit").is_some(),
        key_id: document
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        token_type: document
            .get("typ")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    })
}

/// Decode the unpadded base64url form the compact serialization uses.
fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    Some(decoded)
}
