//! The composition: three cross-crate port adapters, the folds behind them, and the four
//! calls the served road makes.
//!
//! # Why the adapters are here and nowhere else
//!
//! `dependency-boundaries.json` gives `mandate-federation` no `mandate-sts`, and
//! `mandate-sts` neither `mandate-federation` nor `mandate-identity`. Each crate therefore
//! declares the other's read model as a port and names no type of it:
//! `mandate_federation::authorize::TargetRegistry` over `mandate.credential.ResourceServer`,
//! `mandate_sts::code::OAuthClientReads` over `mandate.federation.OAuthClient`, and
//! `mandate_sts::binding::SessionReads` over `mandate.identity.Session`. This package is the
//! one place that sees all three crates, so the adapters land here — `story:product-listener`
//! ruling D1, and `services/sts/src/registry.rs` says the same from the other side.
//!
//! # The `code_id` the token endpoint never receives
//!
//! `RedeemAuthorizationCode.code_id` "is resolved by the trusted adapter from proof; it is
//! not a public OAuth parameter or authority selector" (`credential.yaml`'s header), and
//! `crates/mandate-server/src/decode.rs` refuses a caller-presented one and leaves the field
//! absent. [`resolve_code_id`] is that resolution: the presented `code` is digested in
//! [`CredentialDomain::AuthorizationCodeVerifier`] — the same domain `services/sts/src/code.rs`
//! stores the verifier in — and looked up through
//! [`mandate_sts::store::AuthorizationCodeReads::authorization_code_by_verifier`]. A code
//! that resolves to nothing is the unknown-code denial the redemption already declares for a
//! `code_id` that names no record, reason and all.
//!
//! # What a deployment supplies, and what is a double
//!
//! Four ports: the federation verifier, the clock, the secret source and the identity
//! allocator. [`SystemSecrets`] and [`SystemAllocator`] are this crate's own, over the host
//! CSPRNG; `mandate_federation::verifier_real::RealVerifier` and
//! `mandate_federation::verifier_real::SystemClock` are the shipped other two, wired in
//! `src/main.rs`. Every double the cases use is named in the case that uses it.
//!
//! # Named residue
//!
//! * **The identity fold is seeded with `mandate.identity.SessionOpened`**, which
//!   `identity.yaml` reserves for "the control-plane component that publishes it" — this
//!   one. The federated login's own creating event is
//!   `mandate.federation.FederationAuthenticated`, and
//!   `mandate_identity::IdentityEvent::FederationAuthenticated` carries
//!   `mandate_contract::events::MandateFederationFederationAuthenticated`, a type this
//!   package cannot name: `mandate-contract` is a dev-dependency here. The record the two
//!   events materialize is the same `mandate.identity.Session`, field for field.
//! * **The reading of the declared `date-time` and `duration` forms is copied a fourth
//!   time** ([`instant`]). `services/sts/src/lib.rs` and
//!   `crates/mandate-federation/src/authorize.rs` each hold a private copy and say the same
//!   thing: the shared home is `mandate-types`, which this story may not edit.
//! * **No denial-audit path.** `decision-blocker:audit-routing` holds the vocabulary, and
//!   `mandate-audit` is outside this package's ceiling. A refusal is answered and recorded
//!   nowhere.
//! * **The just-in-time branch seeds no `mandate.identity.Principal`.**
//!   `mandate.federation.ExternalPrincipalProvisioned` is that record's declared writer
//!   (`identity.yaml`'s header) and `mandate_identity::IdentityRead::principal` folds it, but
//!   `IdentityEvent::ExternalPrincipalProvisioned` carries
//!   `mandate_contract::events::MandateFederationExternalPrincipalProvisioned` — a type this
//!   package cannot name, for the same reason the login's own event is named above:
//!   `mandate-contract` is a dev-dependency here. No route this composition serves reads that
//!   record, so nothing served is short of it; a composition that did would need the
//!   dependency, which is `story:domain-runtime`'s to weigh.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use mandate_federation::authorize::{IssueAuthorizationCodeInput, TargetRegistry};
use mandate_federation::publicclient::{OAuthClientStore, registered_public_client};
use mandate_federation::record::{
    FederationEvent, FoldError as FederationFoldError, OAuthClientState,
    Projection as FederationProjection,
};
use mandate_federation::verifier_real::Clock;
use mandate_federation::{
    ConnectionStore, DenialClause as FederationClause, Denied as FederationDenied,
    FederationVerifier, IssuedSession, SessionIssuer,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded, SessionOpened, StreamVersion,
};
use mandate_model::TenantResolutionRule;
use mandate_server::decode;
use mandate_server::metadata::{
    AuthorizationServerMetadata, Jwk, JwkRefusal, Jwks, authorization_server_metadata,
};
use mandate_sts::binding::{EpochStanding, SessionBinding, SessionReads};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, OAuthClientReads,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
};
use mandate_sts::registry::ResourceServerReads;
use mandate_sts::resolve::{IntrospectCredential, IntrospectionParts, introspect_credential};
use mandate_sts::store::{AuthorizationCodeLog, AuthorizationCodeReads, InMemoryCodeLog};
use mandate_sts::{IdentityAllocator, RequestContext as StsRequest, SecretSource};
use mandate_token::CredentialDescriptor;
use mandate_token::projection::{
    CredentialEvent, Denied as CredentialDenied, FoldError as CredentialFoldError,
    Projection as CredentialProjection,
};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, matches, verifier_in};
use mandate_types::{
    Audience, AuthorizationCodeId, ClientId, CorrelationId, CredentialId, CredentialProof,
    CredentialSecret, CredentialVerifier, DenialReason, Duration, EpochSnapshotRef,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OAuthClientId, OrganizationId, PrincipalId, RedirectUri, ResourceServerId, SecurityEpochTarget,
    SessionId, Timestamp, Transient, Uuid, VerifiedContext,
};
use serde::Deserialize;

/// The domain tag a session proof is digested under.
///
/// Its own space, for the reason [`CredentialDomain`] has three: one deployment holds
/// verifiers for material of several kinds, and a value of one kind resolving to a record of
/// another is the failure the separation exists to prevent. A session proof is not one of
/// `CredentialDomain`'s three — that enum is `mandate-token`'s and is
/// `#[non_exhaustive]` — so the tag is stated here and prefixed the same way
/// [`mandate_token::verifier::verifier_in`] prefixes those: the tag, a `0x00` separator no
/// tag contains, then the material.
pub const SESSION_PROOF_DOMAIN: &str = "mandate.control-plane.session-proof";

// ---------------------------------------------------------------------------------------
// The three cross-crate adapters
// ---------------------------------------------------------------------------------------

/// `mandate_federation::authorize::TargetRegistry` over
/// `mandate_sts::registry::ResourceServerReads`.
///
/// `mandate.credential.ResourceServer` is the credential domain's record and
/// `crates/mandate-federation/src/authorize.rs` reads it through a port because that crate
/// folds none of it. The fold behind this adapter *is* the registered set, so
/// [`TargetRegistry::can_answer`] is `true`: a target it holds no registration for is one it
/// has decided is unregistered, not one it cannot see.
#[derive(Debug, Clone, Copy)]
pub struct TargetRegistryOver<'a, R: ResourceServerReads>(&'a R);

impl<'a, R: ResourceServerReads> TargetRegistryOver<'a, R> {
    /// The port, over this registration read model.
    #[must_use]
    pub const fn over(registrations: &'a R) -> Self {
        Self(registrations)
    }
}

impl<R: ResourceServerReads> TargetRegistry for TargetRegistryOver<'_, R> {
    /// The organization the registration binds, whatever its lifecycle state.
    ///
    /// A *disabled* registration is still registered, and the two refusals are different:
    /// `mandate_sts::code::CodeIssuance::issue` raises `TargetDisabled` for the second, so
    /// reporting it here as unregistered would answer the wrong clause.
    fn target_organization(&self, id: &ResourceServerId) -> Option<OrganizationId> {
        self.0.organization_of(id)
    }

    fn can_answer(&self, id: &ResourceServerId) -> bool {
        let _ = id;
        true
    }
}

/// `mandate_sts::code::OAuthClientReads` over a `mandate.federation.OAuthClient` read model.
///
/// Wired over `mandate_federation::record::Projection`, which answers
/// [`OAuthClientStore`] from the federation log. All four answers are read off the one
/// record, so "not registered" (`None`) is never confused with "registered and disabled" or
/// "registered and confidential" (`Some(false)`), which is the distinction
/// `mandate_sts::code::admitted_client` fails closed on.
#[derive(Debug, Clone, Copy)]
pub struct OAuthClientReadsOver<'a, C: OAuthClientStore>(&'a C);

impl<'a, C: OAuthClientStore> OAuthClientReadsOver<'a, C> {
    /// The port, over this client read model.
    #[must_use]
    pub const fn over(clients: &'a C) -> Self {
        Self(clients)
    }
}

impl<C: OAuthClientStore> OAuthClientReads for OAuthClientReadsOver<'_, C> {
    fn client_organization(&self, id: &OAuthClientId) -> Option<OrganizationId> {
        self.0.client(id).map(|client| client.organization_id)
    }

    fn is_enabled(&self, id: &OAuthClientId) -> Option<bool> {
        self.0
            .client(id)
            .map(|client| client.state == OAuthClientState::Recorded)
    }

    fn is_public(&self, id: &OAuthClientId) -> Option<bool> {
        self.0.client(id).map(|client| client.public)
    }

    /// Byte for byte, and nothing is normalized — not a trailing slash, not the case of a
    /// host, not a percent-encoding, not a dot segment. Every normalization admits a URI the
    /// registrant did not register.
    fn redirect_registered(&self, id: &OAuthClientId, redirect_uri: &RedirectUri) -> Option<bool> {
        self.0.client(id).map(|client| {
            client.redirect_uris.iter().any(|registered| {
                registered.as_str().as_bytes() == redirect_uri.as_str().as_bytes()
            })
        })
    }
}

/// `mandate_sts::binding::SessionReads` over `mandate_identity::IdentityRead`.
///
/// The narrowed mirror `services/sts/src/binding.rs` declares, answered from the identity
/// fold. The epoch verdict is recomputed from the snapshot's own recorded generations
/// against the authoritative ones — the same comparison
/// `mandate_identity::SecurityEpochSnapshot::eligibility` makes, written out here so that
/// the dimension that moved is carried as the `SecurityEpochTarget` the port names rather
/// than reconstructed from a verdict that has already dropped it.
#[derive(Debug, Clone, Copy)]
pub struct SessionReadsOver<'a, I: IdentityRead>(&'a I);

impl<'a, I: IdentityRead> SessionReadsOver<'a, I> {
    /// The port, over this identity read model.
    #[must_use]
    pub const fn over(identity: &'a I) -> Self {
        Self(identity)
    }
}

impl<I: IdentityRead> SessionReads for SessionReadsOver<'_, I> {
    fn resolve(&self, id: &SessionId) -> Option<SessionBinding> {
        self.0.resolve(id).map(|session| SessionBinding {
            id: *session.id(),
            subject: *session.principal(),
            organization: *session.organization(),
            // `mandate.identity.Session` always names a snapshot; the port admits a session
            // that names none, and this fold's records are not those.
            epochs: Some(*session.epochs()),
            expires_at: session.expires_at().clone(),
            revoked: !session.is_active(),
        })
    }

    /// `None` when the fold records no such snapshot, which every caller fails closed on:
    /// a snapshot that cannot be resolved has not been shown to be current.
    fn epoch_standing(&self, snapshot: &EpochSnapshotRef) -> Option<EpochStanding> {
        let recorded = self.0.snapshot(snapshot)?;
        for target in recorded.targets() {
            let Some(issued_against) = recorded.recorded(&target) else {
                continue;
            };
            if self.0.current(&target).generation() != issued_against {
                return Some(EpochStanding::Stale(target));
            }
        }
        Some(EpochStanding::Current)
    }
}

// ---------------------------------------------------------------------------------------
// The session proof, and the `code` → `code_id` resolution
// ---------------------------------------------------------------------------------------

/// The verifier a session proof derives, in [`SESSION_PROOF_DOMAIN`].
#[must_use]
pub fn session_proof_verifier<T: Transient + ?Sized>(
    digest: &impl CredentialDigest,
    material: &T,
) -> CredentialVerifier {
    let material = material.expose_material();
    let tag = SESSION_PROOF_DOMAIN.as_bytes();
    let mut tagged = Vec::with_capacity(tag.len() + 1 + material.len());
    tagged.extend_from_slice(tag);
    tagged.push(0);
    tagged.extend_from_slice(material);
    digest.digest(&tagged)
}

/// The session a presented proof names, by verifier.
///
/// `AuthorizePublicClient` declares a `session_proof` and *not* a session: "resolving one to
/// a session is the trusted adapter's work" (`crates/mandate-federation/src/authorize.rs`),
/// and this is that adapter's half of it. Nothing here records the proof — what is kept is
/// the non-reversible verifier of it, the way every other credential on this road is kept —
/// and the comparison does not stop at the first differing byte.
#[derive(Debug, Clone, Default)]
pub struct SessionProofs {
    recorded: Vec<(CredentialVerifier, SessionId)>,
}

impl SessionProofs {
    /// An index that holds no proof.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            recorded: Vec::new(),
        }
    }

    /// Record the verifier of a proof minted for a session. The proof itself is not kept.
    pub fn record<T: Transient + ?Sized>(
        &mut self,
        digest: &impl CredentialDigest,
        proof: &T,
        session: SessionId,
    ) {
        self.recorded
            .push((session_proof_verifier(digest, proof), session));
    }

    /// The session a presented proof resolves to, or `None` when it resolves to nothing.
    ///
    /// The whole index is read: an early return would take a time that depends on *where*
    /// the matching entry sits, which is a position a caller can move by opening sessions.
    #[must_use]
    pub fn resolve<T: Transient + ?Sized>(
        &self,
        digest: &impl CredentialDigest,
        presented: &T,
    ) -> Option<SessionId> {
        let presented = session_proof_verifier(digest, presented);
        let mut found = None;
        for (recorded, session) in &self.recorded {
            if matches(recorded, &presented) && found.is_none() {
                found = Some(*session);
            }
        }
        found
    }
}

/// The `code_id` a presented authorization code resolves to.
///
/// The one read the wire form cannot carry; see the module documentation.
#[must_use]
pub fn resolve_code_id(
    codes: &(impl AuthorizationCodeReads + ?Sized),
    digest: &impl CredentialDigest,
    code: &CredentialProof,
) -> Option<AuthorizationCodeId> {
    codes
        .authorization_code_by_verifier(&verifier_in(
            digest,
            CredentialDomain::AuthorizationCodeVerifier,
            code,
        ))
        .map(|record| record.id)
}

// ---------------------------------------------------------------------------------------
// What a refusal carries to the listener
// ---------------------------------------------------------------------------------------

/// A refusal, as the two values a listener renders it from.
///
/// `mandate_proto::oauth::code_for_denial` reads a clause **name** and a
/// `mandate.core.DenialReason`, because the two deciding crates carry two different
/// `DenialClause` types and `mandate-proto` can see neither. The name is the variant's own
/// (`{:?}`) and carries nothing a caller sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The refusing clause's own variant name.
    pub clause: String,
    /// The declared `mandate.core.DenialReason`.
    pub reason: DenialReason,
}

impl From<&FederationDenied> for Refusal {
    fn from(denied: &FederationDenied) -> Self {
        Self {
            clause: format!("{:?}", denied.clause),
            reason: denied.reason,
        }
    }
}

impl From<&CredentialDenied> for Refusal {
    fn from(denied: &CredentialDenied) -> Self {
        Self {
            clause: format!("{:?}", denied.clause),
            reason: denied.reason,
        }
    }
}

/// Why an authorization request produced no code, and whether it may be redirected.
///
/// RFC 6749 section 4.1.2.1 returns an error by redirecting to a validated redirect URI, and
/// a listener "cannot redirect to a redirect URI it has not validated"
/// (`docs/architecture/adapter-contract.md`). Every refusal raised before
/// `registered_public_client` has returned — the client is unknown, disabled or
/// confidential, or the presented redirect is not one it registered — is therefore rendered
/// as a response (`story:product-listener`, the last ruling). Everything after it carries
/// the validated redirect and the exact state received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRefusal {
    /// Rendered as a response: there is no validated redirect to send it to.
    InPlace(Refusal),
    /// RFC 6749 section 4.1.2.1's redirect, to the validated redirect URI.
    AtRedirect {
        /// The refusal.
        refusal: Refusal,
        /// The redirect URI the client registered and this request presented, exactly.
        redirect_uri: RedirectUri,
        /// The exact state received from the client.
        state: String,
    },
}

// ---------------------------------------------------------------------------------------
// What each served route answers with
// ---------------------------------------------------------------------------------------

/// The accepted outcome of `mandate.federation.AuthenticateFederation`, and the proof.
///
/// The five declared response fields, plus the session proof the composition minted. The
/// proof is **not** a declared response field: `AuthorizePublicClient` declares a
/// `session_proof` input and nothing in the contract says how a client comes to hold one, so
/// the adapter that opens the session is the thing that can hand it over. A cookie-borne
/// session adapter is `story:protocol-adapters`' named residue
/// (`docs/architecture/adapter-contract.md`); this is the bearer form of the same thing.
#[derive(Debug, Clone)]
pub struct Login {
    /// The declared `session_id` response.
    pub session_id: SessionId,
    /// The declared `principal_id` response.
    pub principal_id: PrincipalId,
    /// The declared `organization_id` response.
    pub organization_id: OrganizationId,
    /// The declared `epochs` response.
    pub epochs: EpochSnapshotRef,
    /// The declared `expires_at` response.
    pub expires_at: Timestamp,
    /// The proof the client presents at the authorization endpoint. Returned once.
    pub session_proof: CredentialSecret,
}

/// The accepted outcome of `mandate.federation.AuthorizePublicClient`.
#[derive(Debug, Clone)]
pub struct Authorization {
    /// The declared `code_id` response.
    pub code_id: AuthorizationCodeId,
    /// The declared `code` response: the transient code, returned once.
    pub code: CredentialSecret,
    /// The validated redirect the code authorized.
    pub redirect_uri: RedirectUri,
    /// The exact state received from the client.
    pub state: String,
}

/// The accepted outcome of `mandate.credential.RedeemAuthorizationCode`.
#[derive(Debug, Clone)]
pub struct Token {
    /// The declared `credential` response: the material, returned once.
    pub credential: CredentialSecret,
    /// The declared `credential_id` response.
    pub credential_id: CredentialId,
    /// The descriptor the credential was issued under.
    pub descriptor: CredentialDescriptor,
    /// The instant the request was served at, which `expires_in` is measured from.
    pub issued_at: Timestamp,
}

/// The accepted outcome of `mandate.credential.IntrospectCredential`.
#[derive(Debug, Clone)]
pub struct Introspection {
    /// The declared `active` response.
    pub active: bool,
    /// The declared `descriptor` response, carried by an active answer alone.
    pub descriptor: Option<CredentialDescriptor>,
    /// The declared `credential_id` response, carried by an active answer alone.
    pub credential_id: Option<CredentialId>,
}

// ---------------------------------------------------------------------------------------
// The deployment
// ---------------------------------------------------------------------------------------

/// What a deployment states that neither the contract nor a request carries.
///
/// Every value here is decided before a deployment is built ([`Configuration::checked`]):
/// a lifetime that names no span and an issuer that is not an issuer identifier are refusals
/// at startup, not silent zeroes and not a document published under a name no client can
/// validate against.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// The issuer identifier RFC 8414's metadata document is published under.
    ///
    /// Held **normalised**: `Configuration::checked` trims one trailing `/`, and both readers
    /// — the metadata document and the federation audience — take it from here.
    pub issuer: String,
    /// The longest lifetime this deployment issues an authorization code for.
    pub code_lifetime: CodeLifetime,
    /// The longest lifetime a session opened by a federated login is usable for.
    pub session_lifetime: Duration,
    /// The public keys the JWK Set document publishes.
    pub keys: Vec<Jwk>,
}

impl Configuration {
    /// This configuration with its issuer normalised, or why no deployment serves it.
    ///
    /// The two lifetimes are bounded **at both ends**, and the same sentence decides both:
    /// a lifetime this deployment cannot honour is refused here rather than answered as a
    /// denial to every client.
    ///
    /// * *Below* — the span [`instant::span_of`] reads must be positive. A code lifetime of
    ///   zero puts a code's `expires_at` at the instant it is issued, which
    ///   `services/sts/src/code.rs` refuses as `ExpiryUnbounded` on every authorization
    ///   request.
    /// * *Above* — the expiry the span produces must be one this deployment can render and a
    ///   reader on this road can read back ([`instant::renders_readably`]). `instant::at`
    ///   renders the year with `{year:04}`, a minimum width and not a maximum, and the STS's
    ///   reader (`services/sts/src/lib.rs:312-320`) requires a `-` at offset 4 — so a span
    ///   past the year 9999 renders a timestamp this deployment itself cannot read, and the
    ///   handler answers the same `ExpiryUnbounded` the lower bound exists for. The bound is
    ///   decided from [`instant::LATEST_CHECKED_REQUEST_INSTANT`], because this function has
    ///   no clock.
    ///
    /// **A session lifetime shorter than the code lifetime is admitted**, and is not a
    /// mistake: a code is redeemable only while the session it was issued under is fresh
    /// (`services/sts/src/binding.rs` refuses a redemption whose bound session is not
    /// strictly before its `expires_at` with `SessionUnusable`), so the short session simply
    /// shortens the code's usable life to its own. The two are configured independently
    /// because they bound different things — how long a login lasts, and how long the client
    /// has to exchange a code within it — and neither is derived from the other.
    ///
    /// The issuer must be the identifier RFC 8414 section 2 declares — "a URL that uses the
    /// `https` scheme and has no query or fragment components" — with `http` on the loopback
    /// admitted for a deployment running on a developer's own machine. Exactly one trailing
    /// `/` is trimmed, because RFC 8414 section 3.1 inserts the well-known path *into* the
    /// identifier and `https://host/` and `https://host` publish the same document; a second
    /// trailing `/` is refused rather than guessed at.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationRefused`] naming the value that is not servable.
    pub fn checked(self) -> Result<Self, ConfigurationRefused> {
        // A `kid` naming two keys is a set no reader resolves a signature against, and
        // `Jwks::new` is the one place that says so. Decided here rather than at the JWK Set
        // request: a deployment that serves and answers 500 to every reader of its own key
        // set has published nothing, and the operator learns it from a client.
        Jwks::new(self.keys.clone()).map_err(ConfigurationRefused::Keys)?;
        if servable_lifetime(self.code_lifetime.as_duration()).is_none() {
            return Err(ConfigurationRefused::CodeLifetimeUnbounded);
        }
        if servable_lifetime(&self.session_lifetime).is_none() {
            return Err(ConfigurationRefused::SessionLifetimeUnbounded);
        }
        let issuer = normalised_issuer(&self.issuer).map_err(ConfigurationRefused::Issuer)?;
        Ok(Self { issuer, ..self })
    }
}

/// The positive span a configured lifetime names, or `None` when it names none.
fn span_of_lifetime(lifetime: &Duration) -> Option<i64> {
    instant::span_of(lifetime).filter(|span| *span > 0)
}

/// The span a configured lifetime names when this deployment can serve it, both ends.
///
/// One function for both bounds, so a lifetime admitted at startup and a lifetime the
/// handlers can honour are the same set by construction.
fn servable_lifetime(lifetime: &Duration) -> Option<i64> {
    span_of_lifetime(lifetime).filter(|span| {
        instant::renders_readably(instant::LATEST_CHECKED_REQUEST_INSTANT.saturating_add(*span))
    })
}

/// The issuer identifier this deployment publishes, or why the configured text is none.
fn normalised_issuer(configured: &str) -> Result<String, IssuerRefused> {
    // RFC 3986 section 3.1: the scheme is case-insensitive; the rest is not lowercased.
    let lowered = configured.to_ascii_lowercase();
    let authority = if lowered.starts_with("https://") {
        &configured["https://".len()..]
    } else if lowered.starts_with("http://") {
        let authority = &configured["http://".len()..];
        if !is_loopback(authority.split(['/', '?', '#']).next().unwrap_or("")) {
            return Err(IssuerRefused::SchemeUnadmitted);
        }
        authority
    } else {
        return Err(IssuerRefused::SchemeUnadmitted);
    };
    if configured.contains('?') {
        return Err(IssuerRefused::QueryComponent);
    }
    if configured.contains('#') {
        return Err(IssuerRefused::FragmentComponent);
    }
    if authority.split('/').next().unwrap_or("").is_empty() {
        return Err(IssuerRefused::HostMissing);
    }
    let trimmed = configured.strip_suffix('/').unwrap_or(configured);
    if trimmed.ends_with('/') {
        return Err(IssuerRefused::RepeatedTrailingSlash);
    }
    Ok(trimmed.to_owned())
}

/// Whether an authority names this host: RFC 6761's `localhost`, the IPv4 loopback block, or
/// the IPv6 loopback address.
fn is_loopback(authority: &str) -> bool {
    let host = match authority.rsplit_once(':') {
        // An IPv6 literal carries colons of its own and is bracketed.
        Some((host, _)) if !authority.ends_with(']') => host,
        _ => authority,
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "[::1]"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Why a deployment could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigurationRefused {
    /// The published key set names one `kid` twice, or carries an unadmitted member.
    Keys(JwkRefusal),
    /// The configured code lifetime names no positive span, so every code it bounded would
    /// expire at the instant it was issued.
    CodeLifetimeUnbounded,
    /// The configured session lifetime names no positive span.
    SessionLifetimeUnbounded,
    /// The configured issuer is not an issuer identifier this deployment can publish.
    Issuer(IssuerRefused),
}

/// Why a configured issuer is not an issuer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IssuerRefused {
    /// Not `https://`, and not `http://` on the loopback.
    SchemeUnadmitted,
    /// RFC 8414 section 2: an issuer identifier has no query component.
    QueryComponent,
    /// RFC 8414 section 2: an issuer identifier has no fragment component.
    FragmentComponent,
    /// The URL names no authority.
    HostMissing,
    /// More than one trailing `/`: which identifier the deployment publishes is not decidable.
    RepeatedTrailingSlash,
}

impl core::fmt::Display for IssuerRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::SchemeUnadmitted => {
                "the issuer identifier is not an https URL, or an http URL on the loopback"
            }
            Self::QueryComponent => "the issuer identifier carries a query component",
            Self::FragmentComponent => "the issuer identifier carries a fragment component",
            Self::HostMissing => "the issuer identifier names no host",
            Self::RepeatedTrailingSlash => "the issuer identifier ends in more than one slash",
        })
    }
}

impl core::fmt::Display for ConfigurationRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Keys(refusal) => write!(formatter, "{refusal}"),
            Self::CodeLifetimeUnbounded => {
                formatter.write_str("the code lifetime names no positive span")
            }
            Self::SessionLifetimeUnbounded => {
                formatter.write_str("the session lifetime names no positive span")
            }
            Self::Issuer(refusal) => write!(formatter, "{refusal}"),
        }
    }
}

impl std::error::Error for ConfigurationRefused {}

// ---------------------------------------------------------------------------------------
// The two documents a served deployment is configured from
// ---------------------------------------------------------------------------------------

/// The inputs one `--connection` document carries.
///
/// **The document carries a command's inputs; the binary constructs the event.**
/// [`FederationEvent`] is `Serialize`-only and `#[serde(untagged)]`
/// (`crates/mandate-federation/src/record.rs:145-154`), so reading one back needs a tagged
/// envelope that belongs to the persistence story. This is the shape an operator writes, and
/// [`ConnectionSeed::events`] is the construction.
///
/// # Why a link is part of it
///
/// A connection alone selects: `mandate.federation.AuthenticateFederation` resolves its
/// principal through an explicit link and refuses `DenialClause::LinkAbsent` when there is
/// none (`crates/mandate-federation/src/authenticate.rs:118-121`). The just-in-time branch
/// that would create one is behind `decision-blocker:jit-provisioning` and no route reaches
/// it, so a seeded connection carrying no link is a connection every login is denied
/// against — the flag would configure a road that still cannot be walked. `link` is
/// optional because a deployment may legitimately seed the connection and link later
/// through the persistence story's log.
///
/// `jit_provisioning` is stated rather than defaulted: it decides whether a first login may
/// create a principal, and a security-relevant value nobody wrote is not a value an operator
/// chose.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSeed {
    /// The connection identity, when the operator states one. Absent, one is allocated and
    /// printed.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub connection_id: Option<FederationConnectionId>,
    /// The organization the connection is bound to.
    ///
    /// The fold reads it from the registering caller's verified context
    /// (`crates/mandate-federation/src/record.rs:491-493`), so it is carried there.
    pub organization: OrganizationId,
    /// The configured issuer a proof's `iss` must be.
    pub issuer: Issuer,
    /// The configured client a proof's `aud` must name.
    pub client_id: ClientId,
    /// How the organization is resolved from validated claims.
    pub tenant_resolution: TenantResolutionRule,
    /// Whether this connection admits just-in-time provisioning.
    pub jit_provisioning: bool,
    /// The external principal this connection's logins resolve to, when one is seeded.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub link: Option<PrincipalLinkSeed>,
}

/// The inputs the optional `link` member of a `--connection` document carries.
///
/// `link_method` is not among them and is not configurable: the other four
/// [`ExternalLinkMethod`] values each name an act — an administrator's, an authenticated
/// user's confirmation, a migration, a support decision — that a configuration file did not
/// perform. A seeded link is `ConfiguredFederation`, which is what it is.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalLinkSeed {
    /// The Mandate principal the external subject resolves to.
    pub principal_id: PrincipalId,
    /// The link identity, when the operator states one. Absent, one is allocated.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub external_principal_id: Option<ExternalPrincipalId>,
    /// The external subject, as the IdP's `sub` presents it.
    pub subject: ExternalSubject,
    /// The instant the link was made.
    pub linked_at: Timestamp,
}

/// The connection one document seeds, and the events that seed it.
#[derive(Debug, Clone)]
pub struct SeededConnection {
    /// The connection identity, stated by the document or allocated for it.
    ///
    /// Handed back because an operator who cannot learn it cannot call the login route:
    /// `mandate.federation.AuthenticateFederation` selects on it.
    pub connection_id: FederationConnectionId,
    /// The events, in the order the fold reads them: the connection before its link.
    pub events: Vec<FederationEvent>,
}

impl ConnectionSeed {
    /// The events this document seeds, allocating the identities it states none for.
    ///
    /// `allocate` is the identity source, so the binary mints from the host CSPRNG and a
    /// case mints what it can assert against. Order matters: the fold refuses a link naming
    /// a connection no event created ([`FederationFoldError::UnknownConnection`]).
    pub fn events(&self, allocate: &mut impl FnMut() -> Uuid) -> SeededConnection {
        let connection_id = self
            .connection_id
            .unwrap_or_else(|| FederationConnectionId::new(allocate()));
        let mut events = vec![FederationEvent::FederationConnectionCreated {
            context: self.context(),
            connection_id,
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            tenant_resolution: self.tenant_resolution.clone(),
            jit_provisioning: self.jit_provisioning,
        }];
        if let Some(link) = &self.link {
            events.push(FederationEvent::ExternalPrincipalLinked {
                context: self.context(),
                connection_id,
                principal_id: link.principal_id,
                external_principal_id: link
                    .external_principal_id
                    .unwrap_or_else(|| ExternalPrincipalId::new(allocate())),
                subject: link.subject.clone(),
                link_method: ExternalLinkMethod::ConfiguredFederation,
                linked_at: link.linked_at.clone(),
            });
        }
        SeededConnection {
            connection_id,
            events,
        }
    }

    /// The context a seeded event is recorded under.
    ///
    /// The organization is the document's, because the fold binds the connection to it. The
    /// subject and the credential name none, spelled the way [`Deployment::authenticate`]
    /// spells it for the same reason: the declared types are not `Optional`, and this
    /// seeding authenticated no caller — it is the operator's own configuration, not a
    /// command a credential was validated for.
    fn context(&self) -> VerifiedContext {
        VerifiedContext {
            subject: PrincipalId::new(Uuid::from_bytes([0; 16])),
            actor: None,
            organization: self.organization,
            audience: Audience::new(SEEDED_CONFIGURATION_AUDIENCE),
            credential: CredentialId::new(Uuid::from_bytes([0; 16])),
            delegation: None,
            execution: None,
            correlation: CorrelationId::new(SEEDED_CONFIGURATION_AUDIENCE),
        }
    }
}

/// The audience and correlation a seeded event is recorded under.
///
/// Its own name, and not the deployment's issuer: a record that says it came from the
/// process's own configuration is not one that says a client presented a credential for it.
const SEEDED_CONFIGURATION_AUDIENCE: &str = "mandate.control-plane.configuration";

/// The declared members of a JWK document, and everything else it carries.
///
/// `#[serde(flatten)]` into a map of text, so a parameter whose value is not text is a
/// refusal of the document rather than a member silently dropped from a published key. The
/// map is ordered, so the published document does not depend on the order the file was
/// written in.
#[derive(Debug, Clone, Deserialize)]
struct KeySeed {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    key_use: String,
    alg: String,
    #[serde(flatten)]
    parameters: BTreeMap<String, String>,
}

/// Why a document named by `--connection` or `--key` configures no deployment.
///
/// Every variant carries the path, because an operator running a process with several of
/// each learns nothing from a refusal that does not say which file it read.
#[derive(Debug)]
#[non_exhaustive]
pub enum SeedRefused {
    /// The path did not open.
    Unreadable {
        /// The file that was read.
        path: PathBuf,
        /// The host's own error.
        error: std::io::Error,
    },
    /// The body is not the JSON object this flag declares.
    Malformed {
        /// The file that was read.
        path: PathBuf,
        /// The reader's own error.
        error: serde_json::Error,
    },
    /// The body is a JSON object, and not a key this deployment publishes.
    Key {
        /// The file that was read.
        path: PathBuf,
        /// Which member `Jwk::new` refused.
        refusal: JwkRefusal,
    },
    /// The events the document seeds are not a history the fold reads.
    Unseedable {
        /// The file that was read.
        path: PathBuf,
        /// The fold's own refusal.
        error: FederationFoldError,
    },
}

impl SeedRefused {
    /// The file this refusal was read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Unreadable { path, .. }
            | Self::Malformed { path, .. }
            | Self::Key { path, .. }
            | Self::Unseedable { path, .. } => path,
        }
    }
}

impl core::fmt::Display for SeedRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let path = self.path().display();
        match self {
            Self::Unreadable { error, .. } => write!(formatter, "{path}: {error}"),
            Self::Malformed { error, .. } => write!(formatter, "{path}: {error}"),
            Self::Key { refusal, .. } => write!(formatter, "{path}: {refusal}"),
            Self::Unseedable { error, .. } => write!(formatter, "{path}: {error:?}"),
        }
    }
}

impl std::error::Error for SeedRefused {}

/// The connection document at this path.
///
/// # Errors
///
/// Returns [`SeedRefused`] naming the file when it does not open, or is not the object
/// [`ConnectionSeed`] declares.
pub fn read_connection_seed(path: &Path) -> Result<ConnectionSeed, SeedRefused> {
    serde_json::from_str(&read_document(path)?).map_err(|error| SeedRefused::Malformed {
        path: path.to_path_buf(),
        error,
    })
}

/// The public JWK at this path.
///
/// # Errors
///
/// Returns [`SeedRefused`] naming the file when it does not open, is not a JSON object of
/// text, or carries a member [`Jwk::new`] refuses — RFC 7517 section 9.2's private members
/// among them.
pub fn read_key(path: &Path) -> Result<Jwk, SeedRefused> {
    let seed: KeySeed =
        serde_json::from_str(&read_document(path)?).map_err(|error| SeedRefused::Malformed {
            path: path.to_path_buf(),
            error,
        })?;
    let parameters: Vec<(&str, &str)> = seed
        .parameters
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    Jwk::new(&seed.kty, &seed.kid, &seed.key_use, &seed.alg, &parameters).map_err(|refusal| {
        SeedRefused::Key {
            path: path.to_path_buf(),
            refusal,
        }
    })
}

fn read_document(path: &Path) -> Result<String, SeedRefused> {
    std::fs::read_to_string(path).map_err(|error| SeedRefused::Unreadable {
        path: path.to_path_buf(),
        error,
    })
}

/// The composed deployment: the folds, the ports, and the four calls the road makes.
///
/// **In-memory folds, for the first served vertical** (`story:product-listener`, ruling D4).
/// `eventlog-sqlite` is the next milestone, together with the runtime its async API forces.
pub struct Deployment<V, C, X, A> {
    configuration: Configuration,
    /// The span the configured code lifetime names, in seconds, read once at construction.
    code_lifetime: i64,
    /// The span the configured session lifetime names, in seconds, read once at construction.
    session_lifetime: i64,
    verifier: V,
    clock: C,
    secrets: X,
    allocator: A,
    digest: Sha256Digest,
    issuance: CodeIssuance,
    federation: FederationProjection,
    identity: IdentityLog,
    credentials: CredentialProjection,
    codes: InMemoryCodeLog,
    proofs: SessionProofs,
}

impl<V, C, X, A> Deployment<V, C, X, A>
where
    V: FederationVerifier,
    C: Clock,
    X: SecretSource,
    A: IdentityAllocator,
{
    /// A deployment over these ports, holding nothing.
    ///
    /// The configuration is decided first ([`Configuration::checked`]): a deployment is built
    /// from values it can honour, or it is not built. Every read of a configured value below
    /// is therefore a read of a validated one, and neither lifetime needs a default for a
    /// span that was never named.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationRefused`] when a lifetime names no positive span or the issuer
    /// is not an issuer identifier this deployment can publish.
    pub fn new(
        configuration: Configuration,
        verifier: V,
        clock: C,
        secrets: X,
        allocator: A,
    ) -> Result<Self, ConfigurationRefused> {
        let configuration = configuration.checked()?;
        // Read once, from the checked configuration, and held as the spans the handlers add.
        // Neither read below can fall back to a zero the operator never asked for.
        let code_lifetime = span_of_lifetime(configuration.code_lifetime.as_duration())
            .ok_or(ConfigurationRefused::CodeLifetimeUnbounded)?;
        let session_lifetime = span_of_lifetime(&configuration.session_lifetime)
            .ok_or(ConfigurationRefused::SessionLifetimeUnbounded)?;
        let issuance = CodeIssuance::new(configuration.code_lifetime.clone());
        Ok(Self {
            configuration,
            code_lifetime,
            session_lifetime,
            verifier,
            clock,
            secrets,
            allocator,
            digest: Sha256Digest,
            issuance,
            federation: FederationProjection::default(),
            identity: IdentityLog::new(),
            credentials: CredentialProjection::default(),
            codes: InMemoryCodeLog::new(),
            proofs: SessionProofs::new(),
        })
    }

    /// The issuer identifier this deployment publishes, normalised.
    ///
    /// **One value, two readers.** The metadata document ([`Deployment::metadata`]) and the
    /// federation audience ([`Deployment::audience`]) both read it here, so the identifier a
    /// client validates against and the audience a proof is bound to cannot drift apart over
    /// a trailing slash — which is what they did while one reader trimmed and the other did
    /// not.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.configuration.issuer
    }

    /// The audience this deployment names itself by, which is [`Deployment::issuer`].
    #[must_use]
    pub fn audience(&self) -> Audience {
        Audience::new(self.issuer())
    }

    /// Seed one `mandate.federation` event into the fold behind the client and connection
    /// read models.
    ///
    /// The seeding path a deployment has until the event-log adapter lands (ruling D4); it
    /// is never a command path, and every guard is the handlers'.
    ///
    /// # Errors
    ///
    /// Returns [`FederationFoldError`] when the event is not a history that fold can read.
    pub fn record_federation(
        &mut self,
        event: &FederationEvent,
    ) -> Result<(), FederationFoldError> {
        self.federation.apply(event)
    }

    /// The `mandate.federation` read model this deployment folds.
    ///
    /// The read half of [`Deployment::record_federation`], and public for the same reason:
    /// the fold is the record. A login that creates a principal and a link creates them
    /// *here* and nowhere a status code can be read off, so a caller deciding whether
    /// anything was created — a case, or the operator tooling `story:directory-provenance`
    /// will want — reads it here rather than inferring it from a response.
    #[must_use]
    pub fn federation(&self) -> &FederationProjection {
        &self.federation
    }

    /// Seed one `mandate.identity` event into the session and epoch fold.
    pub fn record_identity(&mut self, event: IdentityEvent) {
        self.identity.record(event);
    }

    /// Seed one `mandate.credential` event into the registration and credential fold.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialFoldError`] when the event is not a history that fold can read.
    pub fn record_credential(
        &mut self,
        event: &CredentialEvent,
    ) -> Result<(), CredentialFoldError> {
        self.credentials.apply(event)
    }

    /// The RFC 8414 metadata document, with every endpoint read from the route table.
    #[must_use]
    pub fn metadata(&self) -> AuthorizationServerMetadata {
        authorization_server_metadata(self.issuer())
    }

    /// The JWK Set document this deployment publishes.
    ///
    /// # Errors
    ///
    /// Returns [`JwkRefusal::RepeatedKeyId`] when the configured set names one `kid` twice.
    pub fn jwks(&self) -> Result<Jwks, JwkRefusal> {
        Jwks::new(self.configuration.keys.clone())
    }

    /// The instant this request is being served at.
    ///
    /// One clock read per request, so that two handlers serving one request decide the same
    /// instant (`mandate_sts::RequestContext::at` says so for its own half).
    #[must_use]
    pub fn now(&self) -> Timestamp {
        instant::at(self.seconds())
    }

    fn seconds(&self) -> i64 {
        i64::try_from(self.clock.unix_seconds()).unwrap_or(i64::MAX)
    }

    /// An identity minted from the deployment's secret source; see [`identity_from`], which
    /// says why the deployment mints these at all and why the minting is a free function.
    fn next_identity(&mut self) -> Uuid {
        identity_from(&mut self.secrets, &self.digest)
    }

    /// Realize `mandate.federation.AuthenticateFederation`, open the session it responds
    /// with, and create the principal a first login has none of.
    ///
    /// # The three-step sequence, and why it is here
    ///
    /// `authenticate_federation` resolves its principal through an explicit link and refuses
    /// `LinkAbsent` when there is none, and that is the whole of what it decides: one command
    /// decides one command, emits one event, and reads `jit_provisioning` nowhere
    /// (`crates/mandate-federation/src/authenticate.rs`'s header says so in as many words).
    /// A first-time user of a customer's platform therefore has no path through that command
    /// alone. `decision-blocker:jit-provisioning`'s alternative 2, which the operator chose,
    /// is a **composition**: `AuthenticateFederation`; on an absent-link refusal from a
    /// connection that admits provisioning, `ProvisionExternalPrincipal`; then
    /// `AuthenticateFederation` once more. This is the adapter that owns composition, so this
    /// is where the sequence lives.
    ///
    /// **Once, and not in a loop.** Whatever the second attempt answers is the login's
    /// answer, a second `LinkAbsent` included. The retry is taken on the *first* attempt's
    /// refusal and on nothing else, so there is no state in which this drives a third command.
    ///
    /// **`jit_provisioning` false leaves the refusal exactly as it stands.** `federation.yaml`
    /// gives the flag one meaning — a connection that does not admit provisioning "denies the
    /// first login and creates nothing" — so a connection with it off answers what it answered
    /// before this sequence existed, byte for byte.
    ///
    /// **A refused provisioning is not the login's refusal either.** The caller called one
    /// command; a clause from a command it never made — `ProvisioningNotAdmitted`,
    /// `ExternalKeyExists` — is not an answer to the one it did. The declared `LinkAbsent` of
    /// the login stands instead, and the attempt creates nothing.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the connection is unresolved or disabled, the proof
    /// is refused, its issuer or audience is not the connection's, tenant resolution has zero
    /// or multiple matches, or the link is absent or the principal disabled.
    pub fn authenticate(
        &mut self,
        input: &decode::AuthenticateFederation,
    ) -> Result<Login, Refusal> {
        let denied = match self.authenticate_once(input) {
            Ok(login) => return Ok(login),
            Err(denied) => denied,
        };
        // The absent link is the only refusal provisioning answers, and the flag on the
        // connection the request selected is the only thing that admits it. Every other
        // refusal — a disabled connection, a refused proof, an unresolved tenant, a disabled
        // principal — is a condition creating a principal would not change.
        if denied.clause != FederationClause::LinkAbsent
            || !self
                .federation
                .connection(&input.connection_id)
                .is_some_and(|connection| connection.jit_provisioning)
        {
            return Err(Refusal::from(&denied));
        }
        if !self.provisioned(input) {
            return Err(Refusal::from(&denied));
        }
        self.authenticate_once(input)
            .map_err(|refused| Refusal::from(&refused))
    }

    /// Drive `mandate.federation.ProvisionExternalPrincipal` for this login and fold the
    /// event its accepted outcome emits.
    ///
    /// Answers whether the record the retry resolves through was created: a refused command
    /// and a fold that cannot read the event it emitted are the same thing to the caller,
    /// which is a login that still has no linked principal.
    fn provisioned(&mut self, input: &decode::AuthenticateFederation) -> bool {
        let request = mandate_federation::RequestContext {
            audience: self.audience(),
            // Minted here, from the deployment's own identity source, for the reason the
            // login's own correlation is minted rather than read: nothing a caller sent may
            // become the correlation of a persisted record.
            correlation: CorrelationId::new(self.next_identity().to_string()),
            // As at `Deployment::authenticate_once`: this route authenticates no caller
            // credential, and the nil UUID is what "names none" spells.
            credential: CredentialId::new(Uuid::from_bytes([0; 16])),
            at: self.now(),
        };
        let mut allocator = MintedIdentities {
            secrets: &mut self.secrets,
            digest: &self.digest,
        };
        let Ok(provisioned) = mandate_federation::authenticate::provision_external_principal(
            &mandate_federation::authenticate::ProvisionExternalPrincipal {
                connection_id: input.connection_id,
                proof: input.proof.clone(),
            },
            &request,
            &self.verifier,
            &self.federation,
            &self.federation,
            &mut allocator,
        ) else {
            return false;
        };
        // The event is the record. It is also the creation record of the
        // `mandate.identity.Principal` (`identity.yaml`'s header), which this composition
        // does not seed: see the module header.
        self.federation.apply(&provisioned.event).is_ok()
    }

    /// One `mandate.federation.AuthenticateFederation`, with its own session identity.
    ///
    /// Separated from [`Deployment::authenticate`] so that the sequence above reads the
    /// refusing clause rather than the rendered [`Refusal`], which carries the clause as text
    /// for a listener and is not a value to decide on.
    fn authenticate_once(
        &mut self,
        input: &decode::AuthenticateFederation,
    ) -> Result<Login, FederationDenied> {
        let at = self.now();
        let session_id = SessionId::new(self.next_identity());
        let epochs = EpochSnapshotRef::new(self.next_identity());
        let expires_at = instant::at(self.seconds().saturating_add(self.session_lifetime));
        let request = mandate_federation::RequestContext {
            audience: self.audience(),
            correlation: CorrelationId::new(session_id.to_string()),
            // This route authenticates no caller credential — `AuthenticateFederation`
            // declares none and `crates/mandate-server/src/decode.rs` refuses a presented
            // one — so the field names none. The declared type is not `Optional`, and the
            // nil UUID is what "names none" spells in it.
            credential: CredentialId::new(Uuid::from_bytes([0; 16])),
            at: at.clone(),
        };
        let mut issuer = OpeningSessionIssuer {
            identity: &mut self.identity,
            session_id,
            epochs,
            expires_at,
        };
        let authenticated = mandate_federation::authenticate::authenticate_federation(
            &mandate_federation::authenticate::AuthenticateFederation {
                connection_id: input.connection_id,
                proof: input.proof.clone(),
            },
            &request,
            &self.verifier,
            &self.federation,
            &self.federation,
            &mut issuer,
        )?;
        // The event is the record: the federation fold reads the authentication too.
        let _ = self.federation.apply(&authenticated.event);

        let session_proof = self.secrets.next_secret();
        self.proofs
            .record(&self.digest, &session_proof, authenticated.session_id);
        Ok(Login {
            session_id: authenticated.session_id,
            principal_id: authenticated.principal_id,
            organization_id: authenticated.organization_id,
            epochs: authenticated.epochs,
            expires_at: authenticated.expires_at,
            session_proof,
        })
    }

    /// Realize `mandate.federation.AuthorizePublicClient` up to the STS call its accepted
    /// outcome makes, and make it.
    ///
    /// The order is the one `crates/mandate-federation/src/authorize.rs` states for its own
    /// validation: the session proof and the session it names, the registered public client
    /// and its exact redirect, the registered target inside that tenant, and then
    /// `mandate.credential.IssueAuthorizationCode`.
    ///
    /// **`mandate_federation::authorize::validate_authorization_code` is not the call made
    /// here, and cannot be.** That function validates a *presented* code against a
    /// *presented* PKCE verifier (`verify_pkce` refuses `VerifierMissing` when none is
    /// given), and an authorization request carries neither: the code does not exist yet and
    /// the verifier stays with the client until the redemption. What this reaches for in that
    /// module is [`IssueAuthorizationCodeInput`] — the value its accepted outcome stops at —
    /// and [`TargetRegistry`], the port it reads the target through. Recorded rather than
    /// smoothed over.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRefusal`], which says whether the refusal may be redirected.
    pub fn authorize(
        &mut self,
        input: &decode::AuthorizePublicClient,
    ) -> Result<Authorization, AuthorizationRefusal> {
        use mandate_federation::DenialClause as FederationClause;

        let at = self.now();
        let in_place = |clause: FederationClause, reason: DenialReason| {
            AuthorizationRefusal::InPlace(Refusal {
                clause: format!("{clause:?}"),
                reason,
            })
        };

        // The session proof is evidence, and the session identity it resolves to is not a
        // parameter (`docs/architecture/adapter-contract.md`).
        let session_id = self
            .proofs
            .resolve(&self.digest, &input.session_proof)
            .ok_or_else(|| {
                in_place(
                    FederationClause::SessionUnknown,
                    DenialReason::InvalidCredential,
                )
            })?;
        let session = self.identity.resolve(&session_id).ok_or_else(|| {
            in_place(
                FederationClause::SessionUnknown,
                DenialReason::InvalidCredential,
            )
        })?;
        if !session.is_active() {
            return Err(in_place(
                FederationClause::SessionRevoked,
                DenialReason::InvalidCredential,
            ));
        }
        match session.eligibility(&self.identity) {
            Ok(mandate_identity::Eligibility::Current) => {}
            Ok(mandate_identity::Eligibility::Stale(_)) => {
                return Err(in_place(
                    FederationClause::SessionStale,
                    DenialReason::StaleEpoch,
                ));
            }
            Err(denial) => {
                return Err(in_place(
                    FederationClause::SessionEpochUnresolved,
                    denial.reason(),
                ));
            }
        }
        if session.is_expired_at(&at) {
            return Err(in_place(
                FederationClause::SessionExpired,
                DenialReason::InvalidCredential,
            ));
        }

        // The organization is the authenticated session's, never a caller-supplied selector.
        // Every refusal to here is rendered rather than redirected: the client and its
        // registered redirect have not been validated, so there is nowhere to send one.
        let client = registered_public_client(
            &self.federation,
            &input.client_id,
            &input.redirect_uri,
            session.organization(),
        )
        .map_err(|denied| AuthorizationRefusal::InPlace(Refusal::from(&denied)))?;

        // From here the redirect is the one the client registered, byte for byte, so a
        // refusal is RFC 6749 section 4.1.2.1's redirect.
        let redirected =
            |clause: FederationClause, reason: DenialReason| AuthorizationRefusal::AtRedirect {
                refusal: Refusal {
                    clause: format!("{clause:?}"),
                    reason,
                },
                redirect_uri: input.redirect_uri.clone(),
                state: input.state.clone(),
            };
        let targets = TargetRegistryOver::over(&self.credentials);
        if !targets.can_answer(&input.target) {
            return Err(redirected(
                FederationClause::TargetUnanswerable,
                DenialReason::Unavailable,
            ));
        }
        match targets.target_organization(&input.target) {
            None => {
                return Err(redirected(
                    FederationClause::TargetUnknown,
                    DenialReason::Denied,
                ));
            }
            Some(registered) if registered != client.organization_id => {
                return Err(redirected(
                    FederationClause::TargetOutsideTenant,
                    DenialReason::TenantMismatch,
                ));
            }
            Some(_) => {}
        }

        let expires_at = instant::at(self.seconds().saturating_add(self.code_lifetime));
        // The value `AuthorizePublicClient`'s accepted outcome stops at, assembled from
        // validated facts and handed to the STS by value.
        let assembled = IssueAuthorizationCodeInput {
            context: mandate_types::VerifiedContext {
                subject: *session.principal(),
                actor: None,
                organization: client.organization_id,
                // The audience is the registered target's own, read off the registration
                // and never from a caller-supplied selector.
                audience: self
                    .credentials
                    .resource_server(&input.target)
                    .map_or_else(|| self.audience(), |server| server.audience),
                credential: CredentialId::new(Uuid::from_bytes([0; 16])),
                delegation: None,
                execution: None,
                correlation: CorrelationId::new(session_id.to_string()),
            },
            client_id: client.id,
            session_id,
            target: input.target,
            requested_scope: input.requested_scope.clone(),
            challenge: input.challenge.clone(),
            method: input.method,
            redirect_uri: input.redirect_uri.clone(),
            expires_at,
        };

        let request = StsRequest {
            correlation: CorrelationId::new(session_id.to_string()),
            at,
            epochs: Some(*session.epochs()),
        };
        let clients = OAuthClientReadsOver::over(&self.federation);
        let issued = self
            .issuance
            .issue(
                &into_sts_issuance(assembled),
                &request,
                &self.credentials,
                &clients,
                AuthorizationCodeParts {
                    digest: &self.digest,
                    secrets: &mut self.secrets,
                    allocator: &mut self.allocator,
                },
            )
            .map_err(|denied| AuthorizationRefusal::AtRedirect {
                refusal: Refusal::from(&denied),
                redirect_uri: input.redirect_uri.clone(),
                state: input.state.clone(),
            })?;
        // One append group on the code's own stream, at the version it was read at.
        let expected = AuthorizationCodeLog::version(&self.codes, &issued.code_id);
        self.codes
            .append(
                &issued.code_id,
                expected,
                std::slice::from_ref(&issued.event),
            )
            .map_err(|_| AuthorizationRefusal::AtRedirect {
                refusal: Refusal {
                    clause: "IssuanceNotCommitted".to_owned(),
                    reason: DenialReason::Unavailable,
                },
                redirect_uri: input.redirect_uri.clone(),
                state: input.state.clone(),
            })?;
        Ok(Authorization {
            code_id: issued.code_id,
            code: issued.code,
            redirect_uri: input.redirect_uri.clone(),
            state: input.state.clone(),
        })
    }

    /// Realize `mandate.credential.RedeemAuthorizationCode` through the one-winner
    /// transaction, resolving the `code_id` from the presented proof first.
    ///
    /// # Errors
    ///
    /// Returns [`RedemptionRefused`] with whatever the redemption refused, and with an
    /// append that did not commit. A code that resolves to nothing is refused exactly as a
    /// `code_id` that names no record is: [`mandate_token::projection::DenialClause::CodeUnknown`],
    /// `InvalidCredential`, so a caller cannot tell the two apart.
    pub fn redeem(
        &mut self,
        input: &decode::RedeemAuthorizationCode,
    ) -> Result<Token, RedemptionRefused> {
        use mandate_token::projection::DenialClause as CredentialClause;

        let at = self.now();
        let code_id = resolve_code_id(self.codes.projection(), &self.digest, &input.code)
            .ok_or_else(|| {
                RedemptionRefused::Denied(CredentialDenied::new(
                    DenialReason::InvalidCredential,
                    CredentialClause::CodeUnknown,
                ))
            })?;
        let request = StsRequest {
            correlation: CorrelationId::new(code_id.to_string()),
            at: at.clone(),
            epochs: None,
        };
        let clients = OAuthClientReadsOver::over(&self.federation);
        let sessions = SessionReadsOver::over(&self.identity);
        let redeemed = redeem_and_consume(
            &RedeemAuthorizationCode {
                code_id,
                client_id: input.client_id,
                code: input.code.clone(),
                pkce_verifier: input.pkce_verifier.clone(),
                redirect_uri: input.redirect_uri.clone(),
            },
            &request,
            &mut self.codes,
            BoundReads {
                servers: &self.credentials,
                clients: &clients,
                sessions: &sessions,
            },
            RedemptionParts {
                digest: &self.digest,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        )?;
        // The same event seeds the `mandate.credential.AccessCredential` the outcome issues;
        // nothing in `mandate-sts` holds that log, so the composition routes it.
        if let Some(event) = redeemed.event.credential_event() {
            let _ = self.credentials.apply(&event);
        }
        Ok(Token {
            credential: redeemed.credential,
            credential_id: redeemed.credential_id,
            descriptor: redeemed.descriptor,
            issued_at: at,
        })
    }

    /// Realize `mandate.credential.IntrospectCredential`.
    ///
    /// The emitted `mandate.credential.CredentialIntrospected` "creates, moves and updates
    /// nothing" and "folds into no record" (`credential.yaml`), so nothing is applied.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the caller's own proof is malformed, resolves to
    /// nothing, is revoked or has expired, when the caller speaks for no enabled
    /// registration, when the presented proof is malformed, when the presented credential
    /// names another audience or organization, and when the resolution cannot be reached.
    pub fn introspect(
        &self,
        input: &decode::IntrospectCredential,
    ) -> Result<Introspection, CredentialDenied> {
        let request = StsRequest {
            correlation: CorrelationId::new("introspect"),
            at: self.now(),
            epochs: None,
        };
        let introspected = introspect_credential(
            &IntrospectCredential {
                caller_proof: input.caller_proof.clone(),
                credential_proof: input.credential_proof.clone(),
            },
            &request,
            &self.credentials,
            IntrospectionParts {
                digest: &self.digest,
                resolution: &self.credentials,
            },
        )?;
        Ok(Introspection {
            active: introspected.active,
            descriptor: introspected.descriptor,
            credential_id: introspected.credential_id,
        })
    }
}

/// The value `mandate.federation.AuthorizePublicClient` stops at, as
/// `mandate.credential.IssueAuthorizationCode`'s declared input.
///
/// Field for field: the two crates declare the same nine values and neither may name the
/// other's type (`dependency-boundaries.json`), so the composition is what carries one to
/// the other — which is what `services/sts/src/code.rs` says it is for.
fn into_sts_issuance(input: IssueAuthorizationCodeInput) -> IssueAuthorizationCode {
    IssueAuthorizationCode {
        context: input.context,
        client_id: input.client_id,
        session_id: input.session_id,
        target: input.target,
        requested_scope: input.requested_scope,
        challenge: input.challenge,
        method: input.method,
        redirect_uri: input.redirect_uri,
        expires_at: input.expires_at,
    }
}

/// The value a hexadecimal digit carries; anything else reads as zero.
const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

/// An identity minted from a secret source, through the digest.
///
/// No allocator port in this package's ceiling mints a `SessionId` or an `EpochSnapshotRef`:
/// `mandate_sts::IdentityAllocator` mints the credential domain's four and
/// `mandate_federation::IdentityAllocator` that domain's four, and neither declares these.
/// What the deployment does hold is a CSPRNG behind [`SecretSource`], so a fresh secret is
/// minted and the identity is the first sixteen bytes of its digest — one-way, so the
/// identity says nothing about the secret, and unguessable exactly when the source is.
///
/// A free function over the two fields rather than a method, because
/// [`MintedIdentities`] mints from the same source while the deployment's read models are
/// borrowed by the handler it is minting for.
fn identity_from(secrets: &mut impl SecretSource, digest: &Sha256Digest) -> Uuid {
    let material = secrets.next_secret();
    let digested = digest.digest(material.expose_material());
    let mut bytes = [0_u8; 16];
    let hex = digested.as_str().as_bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex.get(index * 2).copied().unwrap_or(b'0');
        let low = hex.get(index * 2 + 1).copied().unwrap_or(b'0');
        *byte = (nibble(high) << 4) | nibble(low);
    }
    Uuid::from_bytes(bytes)
}

/// The `mandate_federation::IdentityAllocator` the composition mints this domain's
/// identities from.
///
/// The deployment's own `A` is `mandate_sts::IdentityAllocator` — the credential domain's
/// four, and neither a `PrincipalId` nor an `ExternalPrincipalId` among them — so
/// `ProvisionExternalPrincipal` needs the other port, over the same CSPRNG every other
/// identity this deployment mints comes from. Both traits are spelled `IdentityAllocator`,
/// which is why this one is named by its full path below.
struct MintedIdentities<'a, X> {
    secrets: &'a mut X,
    digest: &'a Sha256Digest,
}

impl<X: SecretSource> MintedIdentities<'_, X> {
    fn next(&mut self) -> Uuid {
        identity_from(self.secrets, self.digest)
    }
}

impl<X: SecretSource> mandate_federation::IdentityAllocator for MintedIdentities<'_, X> {
    fn next_connection_id(&mut self) -> FederationConnectionId {
        FederationConnectionId::new(self.next())
    }

    fn next_principal_id(&mut self) -> PrincipalId {
        PrincipalId::new(self.next())
    }

    fn next_external_principal_id(&mut self) -> ExternalPrincipalId {
        ExternalPrincipalId::new(self.next())
    }

    fn next_o_auth_client_id(&mut self) -> OAuthClientId {
        OAuthClientId::new(self.next())
    }
}

/// The `SessionIssuer` the composition answers step 9 of the resolution order with.
///
/// It opens the session in the identity fold, under an epoch snapshot recorded immediately
/// before it: `mandate_identity::Session::eligibility` refuses a session whose snapshot
/// resolves to nothing, and `mandate_sts::binding::fresh_session` fails closed on the same.
/// The snapshot binds the generations the authority held at the position it was recorded at,
/// which is what `IdentityLog` reads off its own log.
struct OpeningSessionIssuer<'a> {
    identity: &'a mut IdentityLog,
    session_id: SessionId,
    epochs: EpochSnapshotRef,
    expires_at: Timestamp,
}

impl SessionIssuer for OpeningSessionIssuer<'_> {
    fn issue(
        &mut self,
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        connection_id: mandate_types::FederationConnectionId,
    ) -> Result<IssuedSession, FederationDenied> {
        // A snapshot binds every dimension it names to a stated generation, and the fold
        // refuses one naming a dimension no generation has been stated for. A dimension no
        // increment has touched states its first generation here, at zero. Every recording
        // is checked: a refused append would leave a login answered and no session behind
        // it, so the refusal is the login's.
        let unavailable =
            || FederationDenied::new(DenialReason::Unavailable, FederationClause::SessionUnknown);
        for target in [
            SecurityEpochTarget::Principal(principal_id),
            SecurityEpochTarget::Organization(organization_id),
            SecurityEpochTarget::Federation(connection_id),
        ] {
            if self.identity.current(&target).version() == StreamVersion::INITIAL {
                self.identity
                    .try_record(IdentityEvent::SecurityEpochRecorded(
                        SecurityEpochRecorded {
                            target,
                            generation: Generation::ZERO,
                        },
                    ))
                    .map_err(|_| unavailable())?;
            }
        }
        self.identity
            .try_record(IdentityEvent::EpochSnapshotRecorded(
                EpochSnapshotRecorded {
                    id: self.epochs,
                    principal_id,
                    organization_id,
                    connection_id: Some(connection_id),
                },
            ))
            .map_err(|_| unavailable())?;
        self.identity
            .try_record(IdentityEvent::SessionOpened(SessionOpened {
                id: self.session_id,
                principal_id,
                organization_id,
                connection_id: Some(connection_id),
                epochs: self.epochs,
                expires_at: self.expires_at.clone(),
            }))
            .map_err(|_| unavailable())?;
        Ok(IssuedSession {
            session_id: self.session_id,
            // A login mints no credential; see `Deployment::authenticate`.
            credential_id: CredentialId::new(Uuid::from_bytes([0; 16])),
            epochs: self.epochs,
            expires_at: self.expires_at.clone(),
        })
    }
}

// ---------------------------------------------------------------------------------------
// The host's CSPRNG, behind the two ports that need one
// ---------------------------------------------------------------------------------------

/// The number of bytes a minted secret carries.
pub const SECRET_BYTES: usize = 32;

/// A [`SecretSource`] over the host CSPRNG.
///
/// `rand` is a dev-dependency of this package and `getrandom` is not in its ceiling at all
/// (`dependency-boundaries.json`), so the source is the kernel's own, opened once and read
/// per secret. A secret minted from anything a caller could reproduce is not a secret, which
/// is why `mandate_sts::CountingSecrets` is a double and never this.
#[derive(Debug)]
pub struct SystemSecrets {
    source: File,
}

impl SystemSecrets {
    /// Open the host CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns the host's error when `/dev/urandom` cannot be opened. A deployment that
    /// cannot mint a secret must not start.
    pub fn open() -> std::io::Result<Self> {
        Ok(Self {
            source: File::open("/dev/urandom")?,
        })
    }
}

impl SecretSource for SystemSecrets {
    /// # Panics
    ///
    /// Panics when the opened CSPRNG cannot be read. There is no weaker secret to fall back
    /// to and no error this port can return, so the process stops rather than minting one a
    /// caller could reproduce — which is what `rand`'s own `OsRng` does for the same reason.
    fn next_secret(&mut self) -> CredentialSecret {
        let mut bytes = [0_u8; SECRET_BYTES];
        self.source
            .read_exact(&mut bytes)
            .expect("the host CSPRNG is readable");
        CredentialSecret::from_bytes(mandate_types::value::encode_base64(&bytes).into_bytes())
    }
}

/// An [`IdentityAllocator`] over the host CSPRNG.
///
/// Every identity the credential domain's responses bind is minted here, from 16 random
/// bytes. `mandate_sts::SequentialAllocator` is the double; this is the shipped one.
#[derive(Debug)]
pub struct SystemAllocator {
    source: File,
}

impl SystemAllocator {
    /// Open the host CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns the host's error when `/dev/urandom` cannot be opened.
    pub fn open() -> std::io::Result<Self> {
        Ok(Self {
            source: File::open("/dev/urandom")?,
        })
    }

    /// An identity from the host CSPRNG.
    ///
    /// Public because a seeded [`ConnectionSeed`] needs a `FederationConnectionId` and an
    /// `ExternalPrincipalId`, and [`IdentityAllocator`] declares neither: it mints the
    /// credential domain's four and nothing else. The source is the same one every other
    /// identity this deployment mints comes from.
    ///
    /// # Panics
    ///
    /// Panics when the opened CSPRNG cannot be read; see [`SystemSecrets::next_secret`].
    pub fn next_uuid(&mut self) -> Uuid {
        let mut bytes = [0_u8; 16];
        self.source
            .read_exact(&mut bytes)
            .expect("the host CSPRNG is readable");
        Uuid::from_bytes(bytes)
    }
}

impl IdentityAllocator for SystemAllocator {
    fn next_resource_server_id(&mut self) -> ResourceServerId {
        ResourceServerId::new(self.next_uuid())
    }

    fn next_credential_id(&mut self) -> CredentialId {
        CredentialId::new(self.next_uuid())
    }

    fn next_signing_key_id(&mut self) -> mandate_types::SigningKeyId {
        mandate_types::SigningKeyId::new(self.next_uuid())
    }

    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId {
        AuthorizationCodeId::new(self.next_uuid())
    }
}

/// Reading the declared `date-time` and `duration` forms as spans on a timeline.
///
/// The fourth copy of one rule, and the third that is private to its crate:
/// `services/sts/src/lib.rs` and `crates/mandate-federation/src/authorize.rs` hold the other
/// two and both say why — the shared home is `mandate-types`, which this story may not edit.
/// Named as residue rather than left to be found.
pub mod instant {
    use mandate_types::{Duration, Timestamp};

    /// The span a declared duration names, in seconds, or `None` when it names none.
    ///
    /// `P[nD]T[nH][nM][nS]` with integer components. The calendar designators are refused
    /// rather than approximated: a month is not a number of seconds.
    #[must_use]
    pub fn span_of(value: &Duration) -> Option<i64> {
        let text = value.as_str().as_bytes();
        let [b'P', rest @ ..] = text else {
            return None;
        };
        let mut seconds: i64 = 0;
        let mut digits: Option<i64> = None;
        let mut in_time = false;
        let mut components = 0_u32;
        for byte in rest {
            match byte {
                b'0'..=b'9' => {
                    let value = digits.unwrap_or(0).checked_mul(10)?;
                    digits = Some(value.checked_add(i64::from(byte - b'0'))?);
                }
                b'T' => {
                    if in_time || digits.is_some() {
                        return None;
                    }
                    in_time = true;
                }
                b'D' | b'H' | b'M' | b'S' => {
                    let value = digits.take()?;
                    let unit = match (in_time, byte) {
                        (false, b'D') => 86_400,
                        (true, b'H') => 3_600,
                        (true, b'M') => 60,
                        (true, b'S') => 1,
                        _ => return None,
                    };
                    seconds = seconds.checked_add(value.checked_mul(unit)?)?;
                    components += 1;
                }
                _ => return None,
            }
        }
        if digits.is_some() || components == 0 {
            return None;
        }
        Some(seconds)
    }

    /// The last request instant an admitted lifetime is checked from: `3000-01-01T00:00:00Z`.
    ///
    /// [`crate::adapters::Configuration::checked`] has no clock — `src/main.rs` calls it
    /// before the host clock is read, and a caller may hold none — so the upper bound on a
    /// lifetime is decided from a stated instant rather than from "now". A span admitted
    /// against this one renders a readable expiry for every request instant from the epoch
    /// until the year 3000, which is 974 years past this deployment's release; a deployment
    /// still running then has a reader problem this constant is the smallest part of.
    pub const LATEST_CHECKED_REQUEST_INSTANT: i64 = 32_503_680_000;
    /// Whether the instant this deployment renders for `seconds` is one the readers on this
    /// road read back.
    ///
    /// [`at`] renders the year with `{year:04}`, which is a minimum width and not a maximum,
    /// so an instant past `9999-12-31T23:59:59Z` renders a five-digit year and every RFC 3339
    /// reader on this road refuses it — `services/sts/src/lib.rs:312-320` reads offset 4 for
    /// the `-` and answers `None`, which `services/sts/src/code.rs` turns into
    /// `ExpiryUnbounded`. The layout this checks is exactly the one that reader checks, and
    /// it is checked against what [`at`] actually rendered rather than against arithmetic on
    /// the seconds.
    #[must_use]
    pub fn renders_readably(seconds: i64) -> bool {
        let rendered = at(seconds);
        let text = rendered.as_str().as_bytes();
        text.len() >= 20
            && text[4] == b'-'
            && text[7] == b'-'
            && text[10] == b'T'
            && text[13] == b':'
            && text[16] == b':'
    }

    /// The declared `date-time` form of an instant, in UTC.
    #[must_use]
    pub fn at(seconds: i64) -> Timestamp {
        let days = seconds.div_euclid(86_400);
        let rest = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Timestamp::new(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rest / 3600,
            (rest % 3600) / 60,
            rest % 60
        ))
    }

    /// The civil date a day count from `1970-01-01` names, by the era arithmetic that needs
    /// no table.
    const fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let shifted = days + 719_468;
        let era = if shifted >= 0 {
            shifted
        } else {
            shifted - 146_096
        } / 146_097;
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        } as u32;
        (if month <= 2 { year + 1 } else { year }, month, day)
    }
}
