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
//! # One proof, validated more than once, answering the same
//!
//! [`Deployment::authenticate`] puts a proof past the verifier up to four times for one
//! login. That is sound and is stated as such: "the proof is validated twice; both
//! validations are pure functions of the same proof inside its validity window, so the second
//! cannot admit what the first refused" (`docs/architecture/federated-login.md`, *Why two
//! commands at the adapter, not one*). Nothing here may be built on a verifier that answers
//! two calls differently, and nothing here is.
//!
//! **`RotatingSubjects` in `tests/serve.rs` breaks that rule on purpose**, validating a
//! different subject on every call. It is a test construction and not a description of the
//! contract: it exists because with a conforming verifier the retry always resolves the link
//! the provisioning just created, so it is the only way to reach the second `LinkAbsent` and
//! show that the sequence returns it instead of running again. A reader must not take that
//! double for what an issuer is allowed to do.
//!
//! # Named residue
//!
//! * **The identity fold is seeded with `mandate.identity.SessionOpened`**, which
//!   `identity.yaml` reserves for "the control-plane component that publishes it" — this
//!   one. The federated login's own creating event is
//!   `mandate.federation.FederationAuthenticated`, which
//!   `mandate_identity::IdentityEvent::FederationAuthenticated` carries in its generated
//!   shape. Since `story:jit-principal-record` promoted `mandate-contract` to a dependency
//!   this package can name that shape; moving the opening onto it is not that story's. The
//!   record the two events materialize is the same `mandate.identity.Session`, field for
//!   field.
//! * **The reading of the declared `date-time` and `duration` forms is copied a fourth
//!   time** ([`instant`]). `services/sts/src/lib.rs` and
//!   `crates/mandate-federation/src/authorize.rs` each hold a private copy and say the same
//!   thing: the shared home is `mandate-types`, which this story may not edit.
//! * **No denial-audit path.** `decision-blocker:audit-routing` holds the vocabulary, and
//!   `mandate-audit` is outside this package's ceiling. A refusal is answered and recorded
//!   nowhere.
//! * **Only the just-in-time branch seeds a `mandate.identity.Principal`.**
//!   `mandate.federation.ExternalPrincipalProvisioned` is that record's declared writer
//!   (`identity.yaml`'s header), and [`Deployment::authenticate`] folds it into both the
//!   federation and the identity read models (`identity_event_of`). A link seeded from a
//!   `--connection` document has no creating event for its principal, so that principal has
//!   no record here: see [`PrincipalLinkSeed::principal_id`].

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::authority::{
    AUTHORITY_DENIED, Admission, Admitting, ISSUANCE_RELATION, ISSUE_AUTHORIZATION_CODE,
    RESOURCE_SERVER,
};
use mandate_federation::authorize::{IssueAuthorizationCodeInput, TargetRegistry};
use mandate_federation::idp_token::{
    ClientSecret, CodeRedemption, IdpEndpoints, IdpTokenEndpoint, TokenRefusal,
    authorization_request, base64url, endpoints, nonce_matches,
};
use mandate_federation::publicclient::{OAuthClientStore, registered_public_client};
use mandate_federation::record::{
    FederationEvent, FoldError as FederationFoldError, OAuthClientState,
    Projection as FederationProjection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::verifier_real::{AlgorithmPolicyError, Clock, JwksSource, RealVerifier};
use mandate_federation::{
    ConnectionStore, DenialClause as FederationClause, Denied as FederationDenied,
    FederationVerifier, IdentityAllocator as FederationIdentityAllocator, IssuedSession,
    PrincipalStore, SessionIssuer,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded, SessionOpened, StreamVersion,
};
use mandate_model::TenantResolutionRule;
use mandate_proto::oauth;
use mandate_server::decode;
use mandate_server::metadata::{
    AuthorizationServerMetadata, Jwk, JwkRefusal, Jwks, authorization_server_metadata,
};
use mandate_sts::binding::{EpochStanding, SessionBinding, SessionReads};
use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, OAuthClientReads,
    s256_challenge,
};
use mandate_sts::exchange::{
    ExchangeParts, ExchangeRequest, ExchangeTarget, exchange_request, seconds_between,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::redemption::{
    BoundReads, RedeemAuthorizationCode, RedemptionParts, RedemptionRefused, redeem_and_consume,
};
use mandate_sts::registry::{
    RegisterResourceServer, ResourceServerReads, register_resource_server,
};
use mandate_sts::resolve::{IntrospectCredential, IntrospectionParts, introspect_credential};
use mandate_sts::store::{AuthorizationCodeLog, AuthorizationCodeReads, InMemoryCodeLog};
use mandate_sts::{IdentityAllocator, RequestContext as StsRequest, SecretSource};
use mandate_token::projection::{
    CredentialEvent, DenialClause as CredentialClause, Denied as CredentialDenied,
    FoldError as CredentialFoldError, Projection as CredentialProjection,
};
use mandate_token::verifier::{CredentialDigest, CredentialDomain, matches, verifier_in};
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::{
    Action, Audience, AuthorizationCodeId, ClientId, CorrelationId, CredentialId, CredentialProof,
    CredentialSecret, CredentialVerifier, DenialReason, Duration, EpochSnapshotRef,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OAuthClientId, OrganizationId, PkceMethod, PrincipalId, RedirectUri, ResourceId, ResourceRef,
    ResourceServerId, ResourceType, SecurityEpochTarget, SessionId, SigningAlgorithm, SigningKeyId,
    Timestamp, Transient, Uuid, VerifiedContext,
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

/// How many exchange decisions of **each kind** [`Deployment::exchanges`] holds: 1024 admitted
/// and 1024 refused.
///
/// The token endpoint authenticates no client, so an unbounded record is memory any caller
/// can grow by being refused in a loop (correction round 1, F2). Past this many of a kind the
/// oldest of that kind is evicted, and only of that kind: refusals, which any caller can
/// produce, never evict the record of an admitted exchange (final correction, F6). The number is a bound, not a retention policy: the record is the
/// in-memory stand-in for durable delivery, which is `decision-blocker:audit-routing`'s, and
/// at the size of one `TokenExchangeDenied` it holds well under a megabyte.
pub const EXCHANGE_RECORD_CAPACITY: usize = 1024;

/// A refused `mandate.credential.ExchangeCredential`: the declared refusal, and the cause the
/// operator is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeDenied {
    /// The refusing clause, which decides the wire answer.
    pub clause: CredentialClause,
    /// The declared `mandate.core.DenialReason`.
    pub reason: DenialReason,
    /// Why the subject token was unusable, when that is what refused. The operator's line
    /// carries it and the wire never does (final correction, F7).
    pub cause: Option<mandate_sts::exchange::SubjectTokenCause>,
}

/// The accepted outcome of `mandate.credential.ExchangeCredential`, as RFC 8693 section
/// 2.2.1 renders it.
#[derive(Debug, Clone)]
pub struct Exchanged {
    /// The declared `credential` response: the material, returned once.
    pub credential: CredentialSecret,
    /// The declared `credential_id` response.
    pub credential_id: CredentialId,
    /// The declared `descriptor` response.
    pub descriptor: CredentialDescriptor,
    /// Seconds from the instant the request was served at to the descriptor's `expires_at`:
    /// RFC 8693's `expires_in`.
    pub expires_in: i64,
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
///
/// It asks the question `mandate-federation`'s destination guard asks of the same kind of
/// authority (`origin` and `loopback` in `crates/mandate-federation/src/verifier_real.rs`),
/// and answers it the same way for every spelling but one, decided: the federation guard
/// also counts names ending in `.localdomain` as the loopback, and this one does not, because a
/// plaintext issuer is admitted here only where it cannot widen who may speak in the clear:
///
/// * An authority carrying `@` is refused outright. Userinfo exists here only to make an
///   authority look like it names one host while naming another — `localhost:80@evil.example`
///   names `evil.example`.
/// * A port that is spelled must parse. Anything else is a host this guard would be guessing
///   about.
/// * Each of RFC 3986 section 3.2.2's host forms is read by the parser for that form and no
///   other: a bracketed host is an `IP-literal` and must parse as `Ipv6Addr`; an unbracketed
///   host is an `IPv4address` or a `reg-name`, neither of which carries a `:`, so one that
///   does is refused rather than read as an address.
/// * One trailing dot is folded on an unbracketed name, because it is the absolute form of
///   the same name. A second is a name with an empty label, which is no spelling of anything,
///   and an address has no absolute form: `127.0.0.1.` is not an address, and the resolver
///   cannot look it up.
fn is_loopback(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }
    let (host, port) = match authority.split_once(']') {
        // An IPv6 literal carries colons of its own and is bracketed.
        // Anything after it but a port is not an authority.
        Some((bracketed, after)) => match (bracketed.strip_prefix('['), after) {
            (Some(host), "") => (Host::Literal(host), None),
            (Some(host), _) => match after.strip_prefix(':') {
                Some(port) => (Host::Literal(host), Some(port)),
                None => return false,
            },
            (None, _) => return false,
        },
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (Host::Unbracketed(host), Some(port)),
            None => (Host::Unbracketed(authority), None),
        },
    };
    if let Some(spelled) = port.filter(|port| !port.is_empty())
        // RFC 3986 section 3.2.3: `port = *DIGIT`. `u16::from_str` also takes a leading `+`,
        // so it bounds the range and does not decide the spelling.
        && (!spelled.bytes().all(|byte| byte.is_ascii_digit()) || spelled.parse::<u16>().is_err())
    {
        return false;
    }
    match host {
        Host::Literal(host) => host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address.is_loopback()),
        Host::Unbracketed(host) if host.contains(':') => false,
        Host::Unbracketed(host) => {
            let name = match host.strip_suffix('.') {
                Some(name) if !name.is_empty() => name,
                _ => host,
            };
            name.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok_and(|address| address.is_loopback())
        }
    }
}

/// Which of RFC 3986 section 3.2.2's host forms an authority's host was spelled in.
enum Host<'a> {
    /// Between `[` and `]`: an `IP-literal`.
    Literal(&'a str),
    /// Anything else: an `IPv4address` or a `reg-name`.
    Unbracketed(&'a str),
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
/// that creates one is driven by `Deployment::authenticate` since `story:federated-jit-login`
/// (`decision-blocker:jit-provisioning`, cleared 2026-09-21), so a connection carrying no link
/// is walkable when it admits provisioning and denied when it does not. `link` is
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
    /// The algorithm this connection's proofs are verified under, when one is configured.
    ///
    /// **Not a field of the connection record, and not defaulted.**
    /// `mandate.federation.FederationConnection` declares no algorithm; the algorithm is the
    /// *deployment's* configuration for a connection, held by
    /// `mandate_federation::verifier_real::RealVerifier` and installed through
    /// `RealVerifier::configure_connection`. That module refuses to have a default at all,
    /// in as many words — `jsonwebtoken`'s own is `HS256` — and a connection no algorithm
    /// was configured for verifies nothing and fails closed
    /// (`RefusalReason::ConnectionAlgorithmUnconfigured`).
    ///
    /// So absence here is not a gap this reader fills: it is the operator declining to
    /// configure verification for this connection, and the served process refuses every
    /// login through it. It is optional rather than required only because the in-process
    /// cases seed a verifier double for which the value decides nothing.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub algorithm: Option<SigningAlgorithm>,
    /// The hosts this connection's key set may be fetched from, beside the issuer's own
    /// origin.
    ///
    /// **Not a field of the connection record either**, and the same kind of value
    /// `algorithm` is: what the *deployment* holds about a connection, installed through
    /// `RealVerifier::allowing_jwks_hosts` and read by `UreqJwks::admits`.
    ///
    /// Absent — or empty, which is the same list — admits the issuer's own origin and
    /// nothing else, which is what every document written before this member existed
    /// configured and still configures. An operator lists a host here because the IdP
    /// publishes its keys on one: Google's discovery document is served by
    /// `accounts.google.com` and names a key set on `www.googleapis.com`, and Okta and
    /// Entra do the same. Without one, that connection's every login is refused — the
    /// discovery document is served by the issuer and is not allowed to introduce a
    /// destination the deployment never named.
    ///
    /// An entry is `host` or `host:port`; `admits` decides what each one admits and this
    /// reader decides nothing about them. In particular an entry naming a host that
    /// verifier would never fetch from — an address literal, a spelling of the loopback
    /// interface — is **not** refused here: the rules are one implementation's, in one
    /// place, and a copy of them in this reader would be a second answer to the same
    /// question that could disagree with the first.
    #[serde(default)]
    pub jwks_hosts: Vec<String>,
    /// How the organization is resolved from validated claims.
    pub tenant_resolution: TenantResolutionRule,
    /// Whether this connection admits just-in-time provisioning.
    pub jit_provisioning: bool,
    /// The external principal this connection's logins resolve to, when one is seeded.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub link: Option<PrincipalLinkSeed>,
    /// The relying-party half of this connection, when this deployment signs a browser in
    /// through the IdP's authorization-code flow (`story:relying-party-code-flow`).
    ///
    /// **Not a field of the connection record**, and the same kind of value `algorithm` and
    /// `jwks_hosts` are: what this *deployment* holds about a connection. A redirect URI is
    /// where this deployment's callback is served, and a client secret is a credential that
    /// never enters a persistent domain record; the reference names a
    /// `--client-secret-file`, and the secret is read from that file alone.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub relying_party: Option<RelyingPartySeed>,
}

/// The inputs the optional `relying_party` member of a `--connection` document carries.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelyingPartySeed {
    /// The redirect URI the IdP registered for this client, exactly: this deployment's
    /// `/v1/federation/callback` as the browser reaches it.
    pub redirect_uri: String,
    /// The name a `--client-secret-file NAME=PATH` flag gives the file the IdP's client
    /// secret is read from. A reference, never the secret.
    pub client_secret: String,
    /// Where the callback sends the browser once a session is open: the embedding
    /// application's own page, which receives a single-use `handoff` code and exchanges it
    /// server-to-server at `POST /v1/federation/handoff`.
    ///
    /// Absent, the callback answers the handoff code as a JSON body instead. Either way the
    /// session proof never reaches the browser's navigation.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub return_uri: Option<String>,
    /// The hosts beside the issuer's own origin the IdP's authorization and token endpoints
    /// may be on.
    ///
    /// Separate from `jwks_hosts` on purpose: the token endpoint receives the client secret,
    /// and a host the deployment listed for fetching keys is not thereby a host it trusts with
    /// a credential.
    #[serde(default)]
    pub endpoint_hosts: Vec<String>,
}

/// What the relying party holds for one connection.
#[derive(Debug, Clone)]
pub struct RelyingPartyConnection {
    /// The redirect URI the authorization request names and the redemption repeats.
    pub redirect_uri: String,
    /// The client secret the token endpoint is authenticated to with HTTP Basic.
    pub client_secret: ClientSecret,
    /// The hosts beside the issuer's origin an endpoint may be on: the document's
    /// `relying_party.endpoint_hosts`, and never its `jwks_hosts`.
    pub allowed_hosts: Vec<String>,
    /// Where the callback sends the browser with its handoff code, when one is configured.
    pub return_uri: Option<String>,
}

/// The relying-party configuration one `--connection` document states, with its secret
/// read from the file its reference names.
///
/// `secrets` is every `--client-secret-file` the process was given, by name.
///
/// # Errors
///
/// [`SeedRefused::ClientSecretUnresolved`] naming the connection document when no flag
/// gives its reference a file, [`SeedRefused::ReturnUriUnusable`] when the `return_uri`
/// could not carry a handoff code in a `Location` header, and [`SeedRefused::Unreadable`]
/// naming the secret file when it cannot be read or is empty. None carries a byte of the
/// secret.
pub fn relying_party_connection(
    path: &Path,
    seed: &ConnectionSeed,
    secrets: &BTreeMap<String, PathBuf>,
) -> Result<Option<RelyingPartyConnection>, SeedRefused> {
    let Some(relying_party) = &seed.relying_party else {
        return Ok(None);
    };
    if let Some(return_uri) = &relying_party.return_uri
        && !return_uri_is_usable(return_uri)
    {
        return Err(SeedRefused::ReturnUriUnusable {
            path: path.to_path_buf(),
        });
    }
    let secret_path = secrets.get(&relying_party.client_secret).ok_or_else(|| {
        SeedRefused::ClientSecretUnresolved {
            path: path.to_path_buf(),
            reference: relying_party.client_secret.clone(),
        }
    })?;
    let client_secret =
        ClientSecret::read(secret_path).map_err(|error| SeedRefused::Unreadable {
            path: secret_path.clone(),
            error,
        })?;
    Ok(Some(RelyingPartyConnection {
        redirect_uri: relying_party.redirect_uri.clone(),
        client_secret,
        allowed_hosts: relying_party.endpoint_hosts.clone(),
        return_uri: relying_party.return_uri.clone(),
    }))
}

/// The parameters the callback adds to a `return_uri`, and the ones a relying party's
/// redirects carry anywhere on its way. A `return_uri` whose query already names one of
/// these — in any spelling, decoded — is refused: a second value is a parameter two readers
/// may resolve differently, and the application's own reader is one of them.
pub const RETURN_RESERVED_PARAMETERS: &[&str] =
    &["state", "code", "error", "iss", "handoff", "app_state"];

/// Whether a `return_uri` can carry a handoff: the one check the seed and the callback both
/// run, because [`return_redirect`] is the whole of it.
fn return_uri_is_usable(uri: &str) -> bool {
    return_redirect(uri, &[("handoff", "x"), ("app_state", "x")]).is_ok()
}

/// Why a `return_uri` cannot carry a handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReturnUriRefused {
    /// A control or whitespace byte, which would be a header of its own in `Location`.
    NotAHeaderValue,
    /// Neither `https`, nor `http` on the loopback interface — decided on the parsed host.
    SchemeUnadmitted,
    /// The authority carries userinfo, or no host at all.
    AuthorityMalformed,
    /// A fragment: every parameter appended after it would be inside the fragment.
    Fragment,
    /// The query is not an `application/x-www-form-urlencoded` form.
    QueryNotAForm,
    /// The query already names one of [`RETURN_RESERVED_PARAMETERS`].
    QueryNamesReservedParameter,
}

/// The `Location` a completed callback sends the browser to: `return_uri` with
/// `parameters` added to its query, or why it cannot carry them.
///
/// **The seed runs this same function** ([`relying_party_connection`]), so a `return_uri`
/// the process starts with is one every callback can compose onto, and the two cannot
/// disagree about one.
///
/// # Errors
///
/// [`ReturnUriRefused`], naming the first rule the URI breaks.
pub fn return_redirect(
    return_uri: &str,
    parameters: &[(&str, &str)],
) -> Result<String, ReturnUriRefused> {
    if return_uri
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ReturnUriRefused::NotAHeaderValue);
    }
    if return_uri.contains('#') {
        return Err(ReturnUriRefused::Fragment);
    }
    let lowered = return_uri.to_ascii_lowercase();
    let (plaintext, rest) = if lowered.starts_with("https://") {
        (false, &return_uri["https://".len()..])
    } else if lowered.starts_with("http://") {
        (true, &return_uri["http://".len()..])
    } else {
        return Err(ReturnUriRefused::SchemeUnadmitted);
    };
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(ReturnUriRefused::AuthorityMalformed);
    }
    // The host, parsed, and asked the question the issuer's own plaintext rule asks of it:
    // a string prefix is not a host, and `localhost.attacker.example` begins with one.
    if plaintext && !is_loopback(authority) {
        return Err(ReturnUriRefused::SchemeUnadmitted);
    }
    let registered_query = return_uri.split_once('?').map(|(_, query)| query);
    if let Some(query) = registered_query {
        let form = oauth::decode_form(query).map_err(|_| ReturnUriRefused::QueryNotAForm)?;
        if form.keys().any(|name| {
            RETURN_RESERVED_PARAMETERS
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
        }) {
            return Err(ReturnUriRefused::QueryNamesReservedParameter);
        }
    }
    let mut location = return_uri.to_owned();
    let mut separator = match registered_query {
        Some("") => None,
        Some(_) => Some('&'),
        None => Some('?'),
    };
    for (name, value) in parameters {
        if let Some(separator) = separator {
            location.push(separator);
        }
        location.push_str(name);
        location.push('=');
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                location.push(char::from(byte));
            } else {
                location.push_str(&format!("%{byte:02X}"));
            }
        }
        separator = Some('&');
    }
    Ok(location)
}

/// How long a pending sign-in waits for its callback, in seconds.
pub const PENDING_LIFETIME: u64 = 600;

/// How many sign-ins may wait for a callback at once.
pub const PENDING_CAPACITY: usize = 4096;

/// How long a handoff code waits to be exchanged, in seconds.
///
/// Short, because the embedding application exchanges it as soon as the browser arrives,
/// and a bearer code that outlives that is exposure for nothing.
pub const HANDOFF_LIFETIME: u64 = 60;

/// How many handoff codes may wait to be exchanged at once: the pending store's bound.
pub const HANDOFF_CAPACITY: usize = PENDING_CAPACITY;

/// A bounded, in-memory store of values each taken at most once.
///
/// Every value carries the instant it was put in. It is answered by [`OnceStore::take`] at
/// most once, and never once `lifetime` seconds have passed. When `capacity` values are
/// already held, putting one more **evicts the oldest** rather than refusing the new one:
/// a store that refuses when full is one an anonymous caller fills and every other caller
/// is then refused by, and a store that evicts costs the flooder's victims only the sign-ins
/// the flood outran. Pressure that remains — a flood fast enough to evict a real browser's
/// sign-in before its callback returns — is the ingress's to shed with a rate limit; this
/// store's part is that memory stays bounded and nobody is locked out.
#[derive(Debug)]
pub struct OnceStore<T> {
    held: BTreeMap<String, (u64, T)>,
    order: VecDeque<String>,
    lifetime: u64,
    capacity: usize,
}

impl<T> OnceStore<T> {
    /// An empty store over this lifetime and capacity. A capacity of zero holds one.
    #[must_use]
    pub fn new(lifetime: u64, capacity: usize) -> Self {
        Self {
            held: BTreeMap::new(),
            order: VecDeque::new(),
            lifetime,
            capacity: capacity.max(1),
        }
    }

    /// How many values are held, expired ones not yet dropped included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Put `value` in under `key` at `now`, dropping what has expired and evicting the
    /// oldest while the store is full.
    pub fn insert(&mut self, key: String, value: T, now: u64) {
        while let Some(oldest) = self.order.front() {
            match self.held.get(oldest) {
                // Taken already: the order entry is stale.
                None => {}
                Some((at, _)) if !self.expired(*at, now) && self.held.len() < self.capacity => {
                    break;
                }
                Some(_) => {
                    self.held.remove(oldest);
                }
            }
            self.order.pop_front();
        }
        // Order entries for values taken out of the middle are compacted before they can
        // outgrow the store they index.
        if self.order.len() > self.capacity.saturating_mul(2) {
            let held = &self.held;
            self.order.retain(|key| held.contains_key(key));
        }
        self.held.insert(key.clone(), (now, value));
        self.order.push_back(key);
    }

    /// Take the value under `key` out, answering it only while it has not expired. The
    /// value is gone afterwards either way.
    pub fn take(&mut self, key: &str, now: u64) -> Option<T> {
        let (at, value) = self.held.remove(key)?;
        (!self.expired(at, now)).then_some(value)
    }

    fn expired(&self, at: u64, now: u64) -> bool {
        now.saturating_sub(at) >= self.lifetime
    }
}

/// One sign-in sent to an IdP and not yet returned: held in memory, taken once.
struct PendingLogin {
    connection_id: FederationConnectionId,
    nonce: String,
    verifier: CredentialProof,
    /// The random value the `__Host-` cookie set on the authorize response carries, which
    /// binds this sign-in to the browser that started it.
    binding: String,
    /// The embedding application's `app_state`, bound to the handoff this sign-in ends in.
    app_state: Option<String>,
}

/// What a completed callback hands the browser: where to go, and the code to go with.
#[derive(Debug, Clone)]
pub struct Handoff {
    /// The connection's `return_uri`, when one is configured.
    pub return_uri: Option<String>,
    /// The single-use code `POST /v1/federation/handoff` exchanges for the session.
    pub code: String,
    /// The `app_state` the sign-in was started with, returned beside the code.
    ///
    /// **The embedding application must check it against its own session** before it
    /// exchanges the code, exactly as an OAuth client checks `state`: it is what tells the
    /// application that this browser's sign-in is the one it started, and not an attacker's
    /// completed sign-in delivered to it. The exchange presents it again and is refused —
    /// and the code used up — when it differs.
    pub app_state: Option<String>,
}

/// What a callback answers: its outcome, and what becomes of the browser's binding cookie.
#[derive(Debug)]
pub struct CallbackAnswer {
    /// The bindings the cookie is to carry afterwards, when this callback used up the
    /// sign-in one of the presented bindings bound; empty clears the cookie. `None` leaves
    /// the cookie alone: a callback naming a state nobody issued, or another sign-in's,
    /// changes nothing the browser holds.
    pub bindings_left: Option<Vec<String>>,
    /// The handoff, or the refusal.
    pub outcome: Result<Handoff, Refusal>,
}

/// What an accepted authorize step answers: the IdP URL and the browser binding.
#[derive(Debug, Clone)]
pub struct Started {
    /// The IdP authorization URL the browser is sent to.
    pub location: String,
    /// The bindings the browser-binding cookie is set to: the ones the browser presented,
    /// newest last and at most [`MAX_HELD_BINDINGS`], and this sign-in's.
    pub bindings: Vec<String>,
}

/// How many sign-ins one browser's binding cookie holds at once. A tab past this many has
/// its binding dropped, oldest first, and its callback is refused.
pub const MAX_HELD_BINDINGS: usize = 4;

/// The relying party toward external OIDC IdPs: the token-endpoint port, what each
/// connection holds, the sign-ins waiting for a callback, and the sessions waiting for
/// their handoff.
///
/// **Neither store is durable, and that is deliberate.** A pending sign-in is a `state`, a
/// `nonce`, a PKCE verifier and a browser binding for one round trip; a handoff is a session
/// waiting for the embedding application to collect it. Both are [`OnceStore`]s — bounded,
/// taken at most once, oldest evicted first — and neither is recorded: a verifier and a
/// session proof are secrets, and an event log is the one place they must not reach. A
/// process that restarts forgets them, and the browser starts again.
pub struct RelyingParty {
    endpoint: Box<dyn IdpTokenEndpoint + Send>,
    connections: BTreeMap<FederationConnectionId, RelyingPartyConnection>,
    pending: OnceStore<PendingLogin>,
    handoffs: OnceStore<(Login, Option<String>)>,
}

impl RelyingParty {
    /// A relying party over this port, holding no connection.
    #[must_use]
    pub fn new(endpoint: Box<dyn IdpTokenEndpoint + Send>) -> Self {
        Self {
            endpoint,
            connections: BTreeMap::new(),
            pending: OnceStore::new(PENDING_LIFETIME, PENDING_CAPACITY),
            handoffs: OnceStore::new(HANDOFF_LIFETIME, HANDOFF_CAPACITY),
        }
    }

    /// Sign browsers in through this connection's IdP.
    #[must_use]
    pub fn with_connection(
        mut self,
        connection_id: FederationConnectionId,
        connection: RelyingPartyConnection,
    ) -> Self {
        self.connections.insert(connection_id, connection);
        self
    }

    /// Whether this connection signs browsers in through its IdP — and so admits no proof
    /// presented directly at `/v1/federation/login`.
    #[must_use]
    pub fn relies_on(&self, connection_id: &FederationConnectionId) -> bool {
        self.connections.contains_key(connection_id)
    }

    /// How many sign-ins are waiting for a callback.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// How many sessions are waiting for their handoff.
    #[must_use]
    pub fn handoffs(&self) -> usize {
        self.handoffs.len()
    }
}

/// The connection's IdP endpoints, from its discovery document.
fn endpoints_of(
    endpoint: &(dyn IdpTokenEndpoint + Send),
    issuer: &Issuer,
    connection: &RelyingPartyConnection,
) -> Result<IdpEndpoints, TokenRefusal> {
    let document = endpoint
        .discovery(issuer)
        .ok_or(TokenRefusal::DiscoveryUnavailable)?;
    endpoints(issuer, &document, &connection.allowed_hosts)
}

/// Whether two texts are equal, without stopping at the first byte that differs.
fn same_text(one: &str, other: &str) -> bool {
    one.len() == other.len()
        && one
            .bytes()
            .zip(other.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// The refusal a relying-party step answers with.
fn relying_refusal(reason: DenialReason, clause: FederationClause) -> Refusal {
    Refusal::from(&FederationDenied::new(reason, clause))
}

/// A token-endpoint or discovery refusal: its log-safe name to the operator's stream, and
/// the declared denial to the caller.
fn token_refused(refusal: TokenRefusal) -> Refusal {
    eprintln!("mandate-control-plane: relying party refused {refusal}");
    match refusal {
        TokenRefusal::DiscoveryUnavailable | TokenRefusal::Unreachable => {
            relying_refusal(DenialReason::Unavailable, FederationClause::ProofInvalid)
        }
        TokenRefusal::DiscoveryIssuerMismatch => relying_refusal(
            DenialReason::InvalidCredential,
            FederationClause::IssuerMismatch,
        ),
        _ => relying_refusal(
            DenialReason::InvalidCredential,
            FederationClause::ProofInvalid,
        ),
    }
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
    ///
    /// **Trusted, and this is the limit of what is checked.**
    /// `mandate.federation.LinkExternalPrincipal` refuses a principal the records place in
    /// another organization — `links.organization_of(&principal_id) != connection.organization_id`
    /// is `PrincipalMismatch`, and an unanswered principal is refused too because "this path
    /// fails closed" (`crates/mandate-federation/src/link.rs:71-79`). That guard cannot be
    /// run here: this composition writes a `mandate.identity` principal only for a
    /// just-in-time login, never for a seeded link, so `organization_of` answers `None` for
    /// **every** first link and
    /// the command would refuse every document — and `link_external_principal` refuses
    /// `ExternalLinkMethod::ConfiguredFederation` outright (`LinkingAuthority`), which is
    /// the method a configured link is.
    ///
    /// So a single document's `principal_id` is taken as written: nothing in this process
    /// can contradict it. What is decided is the part that does not need an identity record
    /// — two documents placing one principal in two organizations, which
    /// [`ConnectionSeeding::admit`] refuses
    /// ([`SeedRefused::PrincipalAcrossOrganizations`]). Making the single-document case
    /// checkable needs a principal record in this process, which arrives with the folds
    /// seeded from an event log (ruling D4, `story:declared-writers`); until then an
    /// operator writing this field is asserting the principal exists and is that
    /// organization's.
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

/// The `--connection` documents one process was given, decided **together and in order**.
///
/// # Why a document is not read on its own
///
/// Every guard `mandate.federation.RegisterFederationConnection` states is a guard about the
/// connections already held, so a reader that turns one document into an event on its own
/// enforces none of them. Three ways that went wrong, each measured against the flag before
/// this type existed:
///
/// * two documents on one issuer in two organizations were both seeded, and the first
///   connection's login — which succeeded with only its own document present — was then
///   denied `TenantAmbiguous`. `register_federation_connection` refuses that second document
///   with `TenantResolutionUnadmitted` and says why in as many words: no command
///   un-registers a connection, so the incumbent could not undo it.
/// * a document whose `tenant_resolution` named an organization its connection was not bound
///   to was seeded, and every login through it was denied `OrganizationMismatch`. The same
///   command refuses it.
/// * two documents stating one `connection_id` were both seeded and both printed, and only
///   the first was the record the login route read.
///
/// So the documents are admitted one at a time against a fold of the ones before, through
/// the command itself. The fold here is a **mirror** of the deployment's: the same events in
/// the same order, built before the deployment exists because the per-connection verifier
/// algorithm is installed from the allocated `connection_id` and must be known first.
pub struct ConnectionSeeding {
    projection: FederationProjection,
    admitted: Vec<(PathBuf, FederationConnectionId)>,
    linked: Vec<(PathBuf, PrincipalId, OrganizationId)>,
}

impl Default for ConnectionSeeding {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionSeeding {
    /// A seeding holding no connection.
    #[must_use]
    pub fn new() -> Self {
        Self {
            projection: FederationProjection::default(),
            admitted: Vec::new(),
            linked: Vec::new(),
        }
    }

    /// Admit one document against the ones already admitted, and answer the events it seeds.
    ///
    /// `allocate` is the identity source, so the binary mints from the host CSPRNG and a
    /// case mints what it can assert against. Order matters twice: the fold refuses a link
    /// naming a connection no event created
    /// ([`FederationFoldError::UnknownConnection`]), and the command reads the connections
    /// admitted before this one.
    ///
    /// # Errors
    ///
    /// Returns [`SeedRefused`] naming the file — and the incumbent file, where two documents
    /// contradict each other.
    pub fn admit(
        &mut self,
        path: &Path,
        seed: &ConnectionSeed,
        allocate: &mut impl FnMut() -> Uuid,
    ) -> Result<SeededConnection, SeedRefused> {
        if let Some(stated) = seed.connection_id
            && self.projection.connection(&stated).is_some()
        {
            return Err(SeedRefused::RepeatedConnectionId {
                path: path.to_path_buf(),
                incumbent: self.incumbent_of(stated),
                connection_id: stated,
            });
        }
        // The command decides the inputs; this reader decides nothing about them. A stated
        // `connection_id` is handed to it as the identity it allocates, so the operator's
        // own id and an allocated one take exactly the same path through the guards.
        let registered = register_federation_connection(
            &RegisterFederationConnection {
                context: seeded_context(seed.organization),
                issuer: seed.issuer.clone(),
                client_id: seed.client_id.clone(),
                tenant_resolution: seed.tenant_resolution.clone(),
                jit_provisioning: seed.jit_provisioning,
            },
            &self.projection,
            &mut StatedIdentities {
                connection_id: seed.connection_id,
                allocate,
            },
        )
        .map_err(|denied| SeedRefused::Unregistrable {
            path: path.to_path_buf(),
            denied,
        })?;
        let connection_id = registered.connection_id;
        let mut events = vec![registered.event];

        if let Some(link) = &seed.link {
            // The read `link_external_principal` makes, where this composition can answer
            // it: `PrincipalStore::organization_of` reports the organization the records
            // place a principal in, and for this fold those records are the links seeded
            // before this one. A principal that two documents place in two organizations is
            // refused; a principal no document has placed yet is admitted, which is the
            // limitation [`PrincipalLinkSeed::principal_id`] states.
            if let Some(held) = self.projection.organization_of(&link.principal_id)
                && held != seed.organization
            {
                return Err(SeedRefused::PrincipalAcrossOrganizations {
                    path: path.to_path_buf(),
                    incumbent: self.incumbent_link_of(link.principal_id),
                    principal_id: link.principal_id,
                    organization: seed.organization,
                    held,
                });
            }
            events.push(FederationEvent::ExternalPrincipalLinked {
                context: seeded_context(seed.organization),
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

        // Every event decides before any is kept: they are applied to a copy, and the copy
        // replaces the fold only once the last is accepted — the copy-then-swap
        // `Deployment::provisioned` uses. A link the fold refuses would otherwise leave its
        // connection applied behind a refused document, and the corrected document stating
        // the same `connection_id` would be refused as a repeat of a connection no admitted
        // document seeded (`story:control-plane-multi-fold-writes`).
        let mut projection = self.projection.clone();
        for event in &events {
            projection
                .apply(event)
                .map_err(|error| SeedRefused::Unseedable {
                    path: path.to_path_buf(),
                    error,
                })?;
        }
        self.projection = projection;
        self.admitted.push((path.to_path_buf(), connection_id));
        if let Some(link) = &seed.link {
            self.linked
                .push((path.to_path_buf(), link.principal_id, seed.organization));
        }
        Ok(SeededConnection {
            connection_id,
            events,
        })
    }

    /// The file that seeded this connection, for a refusal that has to name both.
    fn incumbent_of(&self, connection_id: FederationConnectionId) -> PathBuf {
        self.admitted
            .iter()
            .find(|(_, held)| *held == connection_id)
            .map_or_else(PathBuf::new, |(path, _)| path.clone())
    }

    /// The file that linked this principal first, for a refusal that has to name both.
    fn incumbent_link_of(&self, principal_id: PrincipalId) -> PathBuf {
        self.linked
            .iter()
            .find(|(_, held, _)| *held == principal_id)
            .map_or_else(PathBuf::new, |(path, _, _)| path.clone())
    }
}

/// The identity source [`register_federation_connection`] allocates through.
///
/// The command mints the `connection_id` it responds with, so a document stating one states
/// what the command mints. The other three are never reached by that command and are minted
/// from the same source rather than left to panic: an allocator that answers some of its
/// trait and not the rest is a trap for the next caller.
struct StatedIdentities<'a, F: FnMut() -> Uuid> {
    connection_id: Option<FederationConnectionId>,
    allocate: &'a mut F,
}

impl<F: FnMut() -> Uuid> FederationIdentityAllocator for StatedIdentities<'_, F> {
    fn next_connection_id(&mut self) -> FederationConnectionId {
        self.connection_id
            .unwrap_or_else(|| FederationConnectionId::new((self.allocate)()))
    }

    fn next_principal_id(&mut self) -> PrincipalId {
        PrincipalId::new((self.allocate)())
    }

    fn next_external_principal_id(&mut self) -> ExternalPrincipalId {
        ExternalPrincipalId::new((self.allocate)())
    }

    fn next_o_auth_client_id(&mut self) -> OAuthClientId {
        OAuthClientId::new((self.allocate)())
    }
}

/// The `--client` documents, decided against the ones before them.
///
/// # Why this exists, and why it is not the command
///
/// `src/main.rs`'s header states the rule for all four flags — "the documents are decided
/// together, by the commands they are the inputs of … a set this process cannot serve is
/// refused before the socket — not seeded, printed as seeded, and then denied at every
/// login". `--connection` and `--key` were routed through
/// [`ConnectionSeeding::admit`] and [`key_set`]; `--client` was added afterwards and went
/// through neither, so two documents naming one `client_id` were both seeded and both
/// printed. The federation fold answers `Ok(())` for an `OAuthClientRegistered` whose id it
/// already holds (`crates/mandate-federation/src/record.rs:638`), so the second document's
/// redirect URIs were registered nowhere and every authorization naming one was denied.
///
/// **It does not run `register_o_auth_client`, and that is deliberate.** That command's
/// three guards are all questions about a *caller* —
/// `ClientRegistrationAdmission::admits_client_administration`, `admits_organization` and
/// `admits_redirect_uri` — behind a port whose only implementation in this workspace is
/// `mandate_federation::register_client::ConfiguredAdmission`, which its own documentation
/// calls "a fixture, never a shipped implementation". Seeding authenticates no caller
/// ([`seeded_context`] says so for every document), so running it here would mean this
/// composition inventing a registration policy in order to satisfy a guard about a caller
/// that does not exist. What *is* decidable from the documents alone is the contradiction
/// between two of them, and that is what is refused. A `--client` document whose redirect
/// set a deployment policy would reject is admitted here, exactly as a seeded link's
/// `principal_id` is trusted and for the same reason.
pub struct ClientSeeding {
    projection: FederationProjection,
    admitted: Vec<(PathBuf, OAuthClientId)>,
}

impl Default for ClientSeeding {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientSeeding {
    /// A seeding holding no client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            projection: FederationProjection::default(),
            admitted: Vec::new(),
        }
    }

    /// Admit one document against the ones already admitted, and answer the events it
    /// seeds.
    ///
    /// The fold here is a **mirror** of the deployment's, for [`ConnectionSeeding`]'s
    /// reason: the whole set is decided before a deployment is built, so a refusal reaches
    /// the operator instead of the socket.
    ///
    /// # Errors
    ///
    /// Returns [`SeedRefused::RepeatedClientId`] naming both files when two documents state
    /// one identity, and [`SeedRefused::Unseedable`] when the events are not a history the
    /// fold reads.
    pub fn admit(
        &mut self,
        path: &Path,
        seed: &ClientSeed,
        allocate: &mut impl FnMut() -> Uuid,
    ) -> Result<SeededClient, SeedRefused> {
        if let Some(stated) = seed.client_id
            && self.projection.client(&stated).is_some()
        {
            return Err(SeedRefused::RepeatedClientId {
                path: path.to_path_buf(),
                incumbent: self.incumbent_of(stated),
                client_id: stated,
            });
        }
        let client = seed.events(allocate);
        // One event today, applied to a copy anyway: the loop admits more, and a document
        // the fold refuses part of must leave nothing behind, as at
        // `ConnectionSeeding::admit`.
        let mut projection = self.projection.clone();
        for event in &client.events {
            projection
                .apply(event)
                .map_err(|error| SeedRefused::Unseedable {
                    path: path.to_path_buf(),
                    error,
                })?;
        }
        self.projection = projection;
        self.admitted.push((path.to_path_buf(), client.client_id));
        Ok(client)
    }

    /// The file that seeded this client, for a refusal that has to name both.
    fn incumbent_of(&self, client_id: OAuthClientId) -> PathBuf {
        self.admitted
            .iter()
            .find(|(_, held)| *held == client_id)
            .map_or_else(PathBuf::new, |(path, _)| path.clone())
    }
}

/// The `--resource-server` documents, through the command they are the inputs of.
///
/// # Why this one *is* the command
///
/// Every guard `mandate.credential.RegisterResourceServer` states is a question about the
/// registrations already held or about the document's own profile, and **not one of them is
/// about a caller**: "audience registration is ambiguous"
/// ([`CredentialProjection::admits_audience`]), a profile whose semantics are unadmitted,
/// and an exchange source that is unresolved, disabled or in another organization. So the
/// documents go through `register_resource_server` itself and this reader decides nothing
/// about them — the shape [`ConnectionSeeding::admit`] already establishes. Whether a caller
/// holds resource-server administration authority is the one question that command does not
/// ask, and `services/sts/src/registry.rs` says why: "the adapter has decided it before the
/// handler is reached". For a document the operator wrote, the adapter is the operator.
///
/// Before the correction this reader built the event by hand ([`ResourceServerSeed::events`])
/// and asked nothing, so two documents holding one `(organization, audience)` key were both
/// seeded and both printed as seeded.
pub struct TargetSeeding {
    projection: CredentialProjection,
    admitted: Vec<(PathBuf, ResourceServerId)>,
}

impl Default for TargetSeeding {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetSeeding {
    /// A seeding holding no registration.
    #[must_use]
    pub fn new() -> Self {
        Self::over(CredentialProjection::default())
    }

    /// A seeding over a fold that already holds registrations.
    ///
    /// The in-memory folds are seeded from documents today and from an event log at the
    /// next milestone (ruling D4), and a replayed log can hold what no document could: two
    /// writers that each read a free `(organization, audience)` key both append, and
    /// `admits_audience` — a read-then-write guard — refused neither. [`Self::settled`] is
    /// what answers for that, and this constructor is what lets it be asked.
    #[must_use]
    pub fn over(projection: CredentialProjection) -> Self {
        Self {
            projection,
            admitted: Vec::new(),
        }
    }

    /// Admit one document against the ones already admitted, and answer the events it
    /// seeds.
    ///
    /// # Errors
    ///
    /// Returns [`SeedRefused::RepeatedResourceServerId`] naming both files when two
    /// documents state one identity, [`SeedRefused::UnregistrableTarget`] with the command's
    /// own denial, and [`SeedRefused::UnseedableCredential`] when the event is not a history
    /// the credential fold reads.
    pub fn admit(
        &mut self,
        path: &Path,
        seed: &ResourceServerSeed,
        allocate: &mut impl FnMut() -> Uuid,
    ) -> Result<SeededResourceServer, SeedRefused> {
        if let Some(stated) = seed.resource_server_id
            && self.projection.resource_server(&stated).is_some()
        {
            return Err(SeedRefused::RepeatedResourceServerId {
                path: path.to_path_buf(),
                incumbent: self.incumbent_of(stated),
                resource_server_id: stated,
            });
        }
        // The command decides the inputs; this reader decides nothing about them. A stated
        // `resource_server_id` is handed to it as the identity it allocates, so the
        // operator's own id and an allocated one take exactly the same path through the
        // guards — [`StatedIdentities`]'s rule, one crate over.
        let registered = register_resource_server(
            &RegisterResourceServer {
                context: seeded_context(seed.organization),
                audience: seed.audience.clone(),
                profile: seed.profile.clone(),
                allowed_exchange_sources: seed.allowed_exchange_sources.clone(),
            },
            &self.projection,
            &mut StatedResourceServerIdentity {
                resource_server_id: seed.resource_server_id,
                allocate,
            },
        )
        .map_err(|denied| self.refusal(path, seed, denied))?;
        let resource_server_id = registered.resource_server_id;
        self.projection.apply(&registered.event).map_err(|error| {
            SeedRefused::UnseedableCredential {
                path: path.to_path_buf(),
                error,
            }
        })?;
        self.admitted.push((path.to_path_buf(), resource_server_id));
        Ok(SeededResourceServer {
            resource_server_id,
            events: vec![registered.event],
        })
    }

    /// Every registration the seeded fold holds records an audience it holds.
    ///
    /// The post-condition over the whole fold, asked once after every document is admitted.
    /// [`CredentialProjection::admits_audience`] is a read-then-write guard and can refuse
    /// only a document being admitted now; this reads
    /// [`CredentialProjection::audience_conflicts`], the view over the records themselves,
    /// and so also answers for a fold that arrived already holding a pair. Until now that
    /// view had no caller outside a test, and its own documentation said as much: "A read
    /// for the adapter, not for a command: no handler consults it."
    ///
    /// # Errors
    ///
    /// Returns [`SeedRefused::AudienceConflicted`] naming the registration that does not
    /// hold its audience and the one that does, with the files that seeded them where
    /// files did.
    pub fn settled(&self) -> Result<(), SeedRefused> {
        // The first, not all of them: a refusal an operator acts on names one correction,
        // and the next run reports the next. Deciding the order by the fold's own order
        // rather than by identifier keeps the report stable across a rebuild.
        let Some(conflict) = self.projection.audience_conflicts().into_iter().next() else {
            return Ok(());
        };
        let held_by = self
            .projection
            .registered(&conflict.organization_id, &conflict.audience)
            .map(|holder| holder.id);
        Err(SeedRefused::AudienceConflicted {
            path: self.incumbent_of(conflict.id),
            incumbent: held_by.map_or_else(PathBuf::new, |id| self.incumbent_of(id)),
            organization: conflict.organization_id,
            audience: conflict.audience,
            resource_server_id: conflict.id,
        })
    }

    /// The command's denial, as the refusal an operator reads.
    ///
    /// One clause of `register_resource_server` compares this document with another
    /// **document** — `AudienceAmbiguous` — and [`SeedRefused::incumbent`] requires every
    /// such variant to carry both files. The command does not know the files, so the
    /// translation is here: the incumbent is the registration that holds the key, and the
    /// file that seeded it. Every other clause is about this document alone and is carried
    /// verbatim.
    fn refusal(
        &self,
        path: &Path,
        seed: &ResourceServerSeed,
        denied: CredentialDenied,
    ) -> SeedRefused {
        if denied.clause != CredentialClause::AudienceAmbiguous {
            return SeedRefused::UnregistrableTarget {
                path: path.to_path_buf(),
                denied,
            };
        }
        let incumbent = self
            .projection
            .registered(&seed.organization, &seed.audience)
            .map_or_else(PathBuf::new, |holder| self.incumbent_of(holder.id));
        SeedRefused::RepeatedAudience {
            path: path.to_path_buf(),
            incumbent,
            organization: seed.organization,
            audience: seed.audience.clone(),
        }
    }

    /// The file that seeded this registration, for a refusal that has to name both. Empty
    /// for a registration the fold carried before any document was read.
    fn incumbent_of(&self, resource_server_id: ResourceServerId) -> PathBuf {
        self.admitted
            .iter()
            .find(|(_, held)| *held == resource_server_id)
            .map_or_else(PathBuf::new, |(path, _)| path.clone())
    }
}

/// The identity source [`register_resource_server`] allocates through.
///
/// [`StatedIdentities`]'s rule for the credential side: the command mints the
/// `resource_server_id` it responds with, so a document stating one states what the command
/// mints, and the other three are minted from the same source rather than left to panic.
struct StatedResourceServerIdentity<'a, F: FnMut() -> Uuid> {
    resource_server_id: Option<ResourceServerId>,
    allocate: &'a mut F,
}

impl<F: FnMut() -> Uuid> IdentityAllocator for StatedResourceServerIdentity<'_, F> {
    fn next_resource_server_id(&mut self) -> ResourceServerId {
        self.resource_server_id
            .unwrap_or_else(|| ResourceServerId::new((self.allocate)()))
    }

    fn next_credential_id(&mut self) -> CredentialId {
        CredentialId::new((self.allocate)())
    }

    fn next_signing_key_id(&mut self) -> SigningKeyId {
        SigningKeyId::new((self.allocate)())
    }

    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId {
        AuthorizationCodeId::new((self.allocate)())
    }

    /// Minted from the same source, for the reason the other three are: registration
    /// reserves no credential identity, so this is reached by no handler it is handed to,
    /// and a source of fresh identities holds a reservation by never answering it again.
    fn reserve_credential_id(&mut self) -> CredentialId {
        CredentialId::new((self.allocate)())
    }

    fn commit_credential_id(&mut self, _reserved: CredentialId) {}

    fn release_credential_id(&mut self, _reserved: CredentialId) {}
}

/// Install one document's **deployment** configuration on the verifier: the algorithm this
/// connection's proofs are verified under, and the hosts its key set may be fetched from.
///
/// Neither is a field of `mandate.federation.FederationConnection` and neither is an input
/// of `mandate.federation.RegisterFederationConnection` — so neither goes through
/// [`ConnectionSeeding::admit`], which is where every input of that command goes and the
/// only place a `--connection` document is admitted. These two are what the *deployment*
/// holds about a connection, under an identity that is known only once that command has
/// allocated it, which is why this runs after it and before the listener binds.
///
/// A document naming no algorithm is left unconfigured deliberately: `RealVerifier` has no
/// default at all and refuses every proof through that connection
/// (`RefusalReason::ConnectionAlgorithmUnconfigured`), which is the closed answer. A
/// document listing no host is left listing none, which admits the issuer's own origin and
/// nothing else.
///
/// **It is here and not in `src/main.rs` because nothing reaches a binary's `main`.**
/// `--connection` is the only configuration surface this deployment has, and the step that
/// carries a document's value onto the verifier is the whole of what that surface does; in
/// `main` it is checkable only through a login, and a login says nothing at all about
/// [`RealVerifier::allowing_jwks_hosts`] unless the key set is on a host `UreqJwks::admits`
/// would fetch from — `https`, and never the loopback a case's own listener is.
///
/// # Errors
///
/// Returns [`SeedRefused::Algorithm`] naming the file whose algorithm the verifier refused.
pub fn configure_verifier<S: JwksSource, C: Clock>(
    verifier: RealVerifier<S, C>,
    path: &Path,
    seed: &ConnectionSeed,
    connection_id: FederationConnectionId,
) -> Result<RealVerifier<S, C>, SeedRefused> {
    let listed: Vec<&str> = seed.jwks_hosts.iter().map(String::as_str).collect();
    let verifier = if listed.is_empty() {
        verifier
    } else {
        verifier.allowing_jwks_hosts(connection_id, &listed)
    };
    let Some(algorithm) = &seed.algorithm else {
        return Ok(verifier);
    };
    verifier
        .configure_connection(connection_id, algorithm)
        .map_err(|error| SeedRefused::Algorithm {
            path: path.to_path_buf(),
            error,
        })
}

/// The key set these `--key` documents publish, or why they publish none.
///
/// [`Jwks::new`] refuses a repeated `kid` and is the rule; it is decided here because only
/// the flags know which **file** each key was read from, and
/// `two keys of the set carry the same kid` with neither file named is a refusal an operator
/// cannot act on. [`Configuration::checked`] still runs the same check on whatever it is
/// given, for a caller that is not this binary.
///
/// # Errors
///
/// Returns [`SeedRefused::RepeatedKeyId`] naming both files.
pub fn key_set(documents: Vec<(PathBuf, Jwk)>) -> Result<Vec<Jwk>, SeedRefused> {
    let mut held: Vec<(PathBuf, Jwk)> = Vec::with_capacity(documents.len());
    for (path, key) in documents {
        if let Some((incumbent, _)) = held.iter().find(|(_, carried)| carried.kid == key.kid) {
            return Err(SeedRefused::RepeatedKeyId {
                path,
                incumbent: incumbent.clone(),
                kid: key.kid,
            });
        }
        held.push((path, key));
    }
    Ok(held.into_iter().map(|(_, key)| key).collect())
}

/// The `--client` document: a registered `mandate.federation.OAuthClient`.
///
/// The authorization endpoint reads this record after the session — the client must be
/// registered, enabled, **public**, in the session's own organization, and have registered
/// the exact redirection URI the request presents
/// (`crates/mandate-federation/src/publicclient.rs`). A process configured from
/// `--connection` and `--key` alone holds no such record and refuses every
/// `GET /oauth/authorize`, which is what this flag closes.
///
/// `public` is stated rather than defaulted, for the reason `jit_provisioning` is: a
/// confidential client authenticates at the token endpoint and a public one does not, and a
/// security-relevant value nobody wrote is not a value an operator chose.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSeed {
    /// The client identity, when the operator states one. Absent, one is allocated and
    /// printed.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub client_id: Option<OAuthClientId>,
    /// The organization the client is bound to.
    ///
    /// The fold reads it from the event (`crates/mandate-federation/src/record.rs`), and the
    /// authorization endpoint refuses a client whose organization is not the authenticated
    /// session's — so this is the same organization the `--connection` document resolves to.
    pub organization: OrganizationId,
    /// Whether this client is a public client.
    pub public: bool,
    /// The redirection endpoint URIs this client registers.
    ///
    /// Compared byte for byte and normalized in no way at all
    /// ([`OAuthClientReadsOver::redirect_registered`]), so a URI written here with a trailing
    /// slash the client does not send is a URI the client has not registered.
    pub redirect_uris: Vec<RedirectUri>,
    /// The PKCE method this client's authorization requests must use.
    pub pkce_method: PkceMethod,
}

/// The client one document seeds, and the events that seed it.
#[derive(Debug, Clone)]
pub struct SeededClient {
    /// The client identity, stated by the document or allocated for it.
    ///
    /// Handed back for the reason [`SeededConnection::connection_id`] is: the authorization
    /// endpoint selects on it, so an operator who cannot learn it cannot call that route.
    pub client_id: OAuthClientId,
    /// The events, in the order the fold reads them.
    pub events: Vec<FederationEvent>,
}

impl ClientSeed {
    /// The events this document seeds, allocating the identity it states none for.
    pub fn events(&self, allocate: &mut impl FnMut() -> Uuid) -> SeededClient {
        let client_id = self
            .client_id
            .unwrap_or_else(|| OAuthClientId::new(allocate()));
        SeededClient {
            client_id,
            events: vec![FederationEvent::OAuthClientRegistered {
                context: seeded_context(self.organization),
                id: client_id,
                organization_id: self.organization,
                public: self.public,
                redirect_uris: self.redirect_uris.clone(),
                pkce_method: self.pkce_method,
            }],
        }
    }
}

/// The `--resource-server` document: a registered `mandate.credential.ResourceServer`.
///
/// The authorization endpoint reads this record as the request's `target` — it must resolve,
/// be enabled, and belong to the client's organization — and the issued code carries the
/// registration's own `audience` and credential profile. A process holding no registration
/// refuses every authorization with `TargetUnknown`, which is what this flag closes.
///
/// **The organization is carried in the context, not in the payload.** The event declares no
/// organization of its own: `mandate_token::projection::Projection` binds the registration to
/// the *registering caller's verified* organization, read off the context, and
/// `mandate_sts::registry::register_resource_server` refuses any other. This document
/// therefore states the organization once and it lands where the fold reads it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceServerSeed {
    /// The registration identity, when the operator states one. Absent, one is allocated and
    /// printed.
    #[serde(default, deserialize_with = "mandate_types::value::present")]
    pub resource_server_id: Option<ResourceServerId>,
    /// The organization the registration is bound to.
    pub organization: OrganizationId,
    /// The audience the registration holds, which a credential issued for this target is
    /// bound to.
    pub audience: Audience,
    /// The credential profile the registration issues under.
    pub profile: CredentialProfile,
    /// The registrations admitted as exchange sources into this one.
    ///
    /// Stated rather than defaulted, and empty is the ordinary value: this is a declared
    /// input of `mandate.credential.RegisterResourceServer`, every member of it widens what
    /// may be exchanged into this target, and a list nobody wrote is not a list an operator
    /// chose.
    pub allowed_exchange_sources: Vec<ResourceServerId>,
}

/// The registration one document seeds, and the events that seed it.
#[derive(Debug, Clone)]
pub struct SeededResourceServer {
    /// The registration identity, stated by the document or allocated for it.
    ///
    /// Handed back because the authorization request names the target by it: an operator who
    /// cannot learn it cannot ask for a credential for this server.
    pub resource_server_id: ResourceServerId,
    /// The events, in the order the fold reads them.
    pub events: Vec<CredentialEvent>,
}

impl ResourceServerSeed {
    /// The events this document seeds, allocating the identity it states none for.
    pub fn events(&self, allocate: &mut impl FnMut() -> Uuid) -> SeededResourceServer {
        let resource_server_id = self
            .resource_server_id
            .unwrap_or_else(|| ResourceServerId::new(allocate()));
        SeededResourceServer {
            resource_server_id,
            events: vec![CredentialEvent::ResourceServerRegistered {
                context: seeded_context(self.organization),
                id: resource_server_id,
                audience: self.audience.clone(),
                credential_profile: self.profile.clone(),
                allowed_exchange_sources: self.allowed_exchange_sources.clone(),
            }],
        }
    }
}

/// The context every seeded event is recorded under, whichever document seeded it.
///
/// One function rather than one per seed type: a record that says it came from the process's
/// own configuration says so the same way for all three, and the reasoning below holds for
/// each of them.
///
/// The organization is the document's, because the folds bind the seeded record to it. The
/// subject and the credential name none, spelled the way [`Deployment::authenticate`] spells
/// it for the same reason: the declared types are not `Optional`, and this seeding
/// authenticated no caller — it is the operator's own configuration, not a command a
/// credential was validated for.
fn seeded_context(organization: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(Uuid::from_bytes([0; 16])),
        actor: None,
        organization,
        audience: Audience::new(SEEDED_CONFIGURATION_AUDIENCE),
        credential: CredentialId::new(Uuid::from_bytes([0; 16])),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new(SEEDED_CONFIGURATION_AUDIENCE),
    }
}

/// The audience and correlation a seeded event is recorded under.
///
/// Its own name, and not the deployment's issuer: a record that says it came from the
/// process's own configuration is not one that says a client presented a credential for it.
const SEEDED_CONFIGURATION_AUDIENCE: &str = "mandate.control-plane.configuration";

/// The declared members of a JWK document, and everything else it carries.
///
/// # Why this is not `#[serde(flatten)]` into a map
///
/// It was, into a `BTreeMap<String, String>`, and a map holds one value per name: a document
/// stating `"crv":"P-256","crv":"P-521"` was read as `P-521` and **published** as `P-521`,
/// with the first value dropped in silence — a key that states a curve the document's own
/// first line did not. `serde_json` parses the repeat happily; the map is where it is lost.
///
/// So the members are collected **in document order, repeats and all**, and handed to
/// [`Jwk::new`] as they were written. That constructor already refuses a repeat
/// ([`JwkRefusal::DuplicateParameter`]) and a parameter colliding with a declared member
/// ([`JwkRefusal::DeclaredMemberCollision`]); this reader's job is to stop deciding on the
/// document's behalf which of two values it meant. A declared member stated twice reaches
/// the constructor the same way — the first occurrence fills the field and the second is
/// carried on as a parameter, where it collides with the member it repeats.
#[derive(Debug, Clone)]
struct KeySeed {
    kty: String,
    kid: String,
    key_use: String,
    alg: String,
    /// Every member that is not the first occurrence of one of the declared four, in the
    /// order the document wrote them, repeats preserved.
    parameters: Vec<(String, String)>,
}

impl<'de> Deserialize<'de> for KeySeed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Members;

        impl<'de> serde::de::Visitor<'de> for Members {
            type Value = Vec<(String, String)>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a JWK object whose members are all text")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Self::Value, M::Error> {
                let mut members = Vec::new();
                while let Some((name, value)) = map.next_entry::<String, String>()? {
                    members.push((name, value));
                }
                Ok(members)
            }
        }

        let members = deserializer.deserialize_map(Members)?;
        let mut declared: BTreeMap<&'static str, String> = BTreeMap::new();
        let mut parameters = Vec::new();
        for (name, value) in members {
            match Jwk::DECLARED_MEMBERS.iter().find(|held| **held == name) {
                // The *first* occurrence fills the declared field; a second is carried on
                // rather than dropped, and `Jwk::new` refuses it as a collision.
                Some(held) if !declared.contains_key(held) => {
                    declared.insert(held, value);
                }
                _ => parameters.push((name, value)),
            }
        }
        let kty = declared
            .remove("kty")
            .ok_or_else(|| serde::de::Error::missing_field("kty"))?;
        let kid = declared
            .remove("kid")
            .ok_or_else(|| serde::de::Error::missing_field("kid"))?;
        let key_use = declared
            .remove("use")
            .ok_or_else(|| serde::de::Error::missing_field("use"))?;
        let alg = declared
            .remove("alg")
            .ok_or_else(|| serde::de::Error::missing_field("alg"))?;
        Ok(Self {
            kty,
            kid,
            key_use,
            alg,
            parameters,
        })
    }
}

/// Why a document named by `--connection`, `--key`, `--client` or `--resource-server`
/// configures no deployment.
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
    /// The events the document seeds are not a history the credential fold reads.
    ///
    /// Separate from [`SeedRefused::Unseedable`] because the two folds raise different
    /// errors and neither can be rendered as the other; a refusal that named the wrong fold
    /// would tell the operator to look at the wrong document.
    UnseedableCredential {
        /// The file that was read.
        path: PathBuf,
        /// The fold's own refusal.
        error: CredentialFoldError,
    },
    /// The document names an algorithm this deployment's allowlist does not admit.
    ///
    /// A `--connection` refusal, and a configuration one: the algorithm is installed on the
    /// verifier before the listener binds, so an unadmitted name is the operator's to
    /// correct rather than a denial every login learns about.
    Algorithm {
        /// The file that was read.
        path: PathBuf,
        /// The policy's own refusal.
        error: AlgorithmPolicyError,
    },
    /// The command this document's inputs realize refuses them.
    ///
    /// **The guards are the domain's, not this reader's.** A `--connection` document is the
    /// inputs of `mandate.federation.RegisterFederationConnection`, and
    /// [`register_federation_connection`] is what decides them: a `tenant_resolution`
    /// resolving to an organization the connection is not bound to is `OrganizationMismatch`,
    /// and a rule another organization's connection on the same issuer could match for the
    /// same proof is `TenantResolutionUnadmitted`. Both were seeded happily while this
    /// reader built the event by hand, and both turn every login through the connection into
    /// a denial — which is exactly what that command's own comment says not to do: "no
    /// command un-registers a connection, so the incumbent could not undo it. Refuse the
    /// configuration rather than the logins."
    Unregistrable {
        /// The file that was read.
        path: PathBuf,
        /// The command's own denial.
        denied: FederationDenied,
    },
    /// Two `--key` documents publish one `kid`.
    ///
    /// A `kid` names at most one key in a set, so a reader resolving a signature's `kid`
    /// against the published document resolves it to one key or to none ([`Jwks::new`]).
    /// Decided here rather than there because only the flags know which **files** the two
    /// keys were read from, and a refusal an operator cannot act on is not a refusal.
    RepeatedKeyId {
        /// The file that was read.
        path: PathBuf,
        /// The file the incumbent key was read from.
        incumbent: PathBuf,
        /// The `kid` both state.
        kid: String,
    },
    /// Two `--connection` documents state one `connection_id`.
    ///
    /// For [`SeedRefused::RepeatedKeyId`]'s reason, one level up: the login route selects a
    /// connection by this id, so the fold answers with the first document's record and the
    /// second document's issuer, client and link are configured into a connection nothing
    /// can reach. Both ids are printed as seeded, so nothing anywhere says which one won.
    RepeatedConnectionId {
        /// The file that was read.
        path: PathBuf,
        /// The file the incumbent connection was read from.
        incumbent: PathBuf,
        /// The identity both state.
        connection_id: FederationConnectionId,
    },
    /// Two `--connection` documents link one principal under different organizations.
    ///
    /// `link_external_principal` refuses a principal the records place in another
    /// organization (`crates/mandate-federation/src/link.rs:71-79`) and fails closed. This
    /// composition records no `mandate.identity` principal for a seeded link, so that guard
    /// cannot be satisfied by any document here — see [`PrincipalLinkSeed::principal_id`] for what is
    /// therefore trusted. What **is** decidable is the contradiction between two documents,
    /// and it is refused: a principal that logs into two tenants is the cross-tenant hole
    /// the guard exists to close.
    PrincipalAcrossOrganizations {
        /// The file that was read.
        path: PathBuf,
        /// The file that linked the principal first.
        incumbent: PathBuf,
        /// The principal both link.
        principal_id: PrincipalId,
        /// The organization this document places it in.
        organization: OrganizationId,
        /// The organization the incumbent document placed it in.
        held: OrganizationId,
    },
    /// `mandate.credential.RegisterResourceServer` refuses a `--resource-server` document.
    ///
    /// The credential half of [`SeedRefused::Unregistrable`], and separate for that
    /// variant's reason: the two commands raise different denials and neither renders as
    /// the other. Every guard that command states is a guard about the registrations
    /// already held or about the document's own profile — an unadmitted profile, an
    /// unresolved, disabled or cross-tenant exchange source — and **none of them is about a
    /// caller**, which is why a `--resource-server` document goes through the command itself
    /// and a `--client` document does not.
    ///
    /// The one clause that compares two *documents* is carried by
    /// [`SeedRefused::RepeatedAudience`] instead, so that it can name both files.
    UnregistrableTarget {
        /// The file that was read.
        path: PathBuf,
        /// The command's own denial.
        denied: CredentialDenied,
    },
    /// Two `--resource-server` documents hold one `(organization, audience)` key.
    ///
    /// `register_resource_server`'s own `AudienceAmbiguous`, rendered as the two-document
    /// refusal it is. The command decides it — nothing here re-implements
    /// `admits_audience` — and this variant is chosen from the clause the command returned,
    /// because [`SeedRefused::incumbent`] states the rule this would otherwise break:
    /// "Every variant that compares documents carries both", and a refusal naming one of
    /// two contradicting files tells an operator half of what to correct.
    ///
    /// Measured before this was decided: both documents were seeded and both printed as
    /// seeded, and which registration *held* the audience was
    /// `Projection::registered`'s `min_by_key(|server| server.id)` — sixteen bytes of UUID,
    /// a value no document states.
    RepeatedAudience {
        /// The file that was read.
        path: PathBuf,
        /// The file the incumbent registration was read from.
        incumbent: PathBuf,
        /// The organization the key is in.
        organization: OrganizationId,
        /// The audience both documents register.
        audience: Audience,
    },
    /// Two `--resource-server` documents state one `resource_server_id`.
    ///
    /// [`SeedRefused::RepeatedConnectionId`]'s defect in the credential fold: `apply`
    /// answers `Ok(())` for a `ResourceServerRegistered` whose id it already holds
    /// (`crates/mandate-token/src/projection.rs:763-765`), so the second document's
    /// audience, profile and exchange sources are registered nowhere while both ids are
    /// printed as seeded.
    RepeatedResourceServerId {
        /// The file that was read.
        path: PathBuf,
        /// The file the incumbent registration was read from.
        incumbent: PathBuf,
        /// The identity both state.
        resource_server_id: ResourceServerId,
    },
    /// Two `--client` documents state one `client_id`.
    ///
    /// The same defect one fold over: `Projection::apply` returns `Ok(())` for an
    /// `OAuthClientRegistered` whose id it already holds
    /// (`crates/mandate-federation/src/record.rs:638`), so the redirect URIs the second
    /// document registers are registered nowhere and every authorization naming them is
    /// denied `RedirectUnregistered` — while both ids are printed as seeded.
    RepeatedClientId {
        /// The file that was read.
        path: PathBuf,
        /// The file the incumbent client was read from.
        incumbent: PathBuf,
        /// The identity both state.
        client_id: OAuthClientId,
    },
    /// The seeded credential fold holds a registration that does not hold its audience.
    ///
    /// [`TargetSeeding::settled`]'s refusal, and the one this set of flags cannot produce
    /// on its own: `admits_audience` is a read-then-write guard, so it refuses a document
    /// being admitted now and can say nothing about a pair a fold already carried. A fold
    /// seeded from an event log (ruling D4) can carry one, because two writers that each
    /// read a free key both append
    /// (`crates/mandate-token/src/projection.rs:45-56`). Which registration then *holds*
    /// the key is `Projection::registered`'s `min_by_key(|server| server.id)` — sixteen
    /// bytes of UUID, a value no document states and no operator chose — and
    /// `services/sts/src/resolve.rs` reads introspection authority through it. So the set
    /// is refused before the socket rather than served under a registration nothing named.
    AudienceConflicted {
        /// The file that seeded the registration that does not hold the key, where a file
        /// seeded it; empty for a registration the fold already carried.
        path: PathBuf,
        /// The file that seeded the registration that does hold it, on the same terms.
        incumbent: PathBuf,
        /// The organization the key is in.
        organization: OrganizationId,
        /// The audience two registrations record.
        audience: Audience,
        /// The registration that does not hold it.
        resource_server_id: ResourceServerId,
    },
    /// A `--connection` document's `relying_party.client_secret` names a reference no
    /// `--client-secret-file` gives a file.
    ClientSecretUnresolved {
        /// The connection document that was read.
        path: PathBuf,
        /// The reference it names. A name, never the secret.
        reference: String,
    },
    /// A `--connection` document's `relying_party.return_uri` cannot carry a handoff code:
    /// not absolute `https` (or loopback `http`), a fragment, a control or whitespace byte,
    /// or a query already naming `handoff`.
    ReturnUriUnusable {
        /// The connection document that was read.
        path: PathBuf,
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
            | Self::Unseedable { path, .. }
            | Self::UnseedableCredential { path, .. }
            | Self::Algorithm { path, .. }
            | Self::Unregistrable { path, .. }
            | Self::RepeatedKeyId { path, .. }
            | Self::RepeatedConnectionId { path, .. }
            | Self::PrincipalAcrossOrganizations { path, .. }
            | Self::UnregistrableTarget { path, .. }
            | Self::RepeatedAudience { path, .. }
            | Self::RepeatedResourceServerId { path, .. }
            | Self::RepeatedClientId { path, .. }
            | Self::AudienceConflicted { path, .. }
            | Self::ClientSecretUnresolved { path, .. }
            | Self::ReturnUriUnusable { path } => path,
        }
    }

    /// The other file this refusal is about, when it is about two.
    ///
    /// A refusal that names one of two contradicting documents tells an operator half of
    /// what to correct. Every variant that compares documents carries both, and this is the
    /// reader for the second — `None` for the variants that read one file.
    #[must_use]
    pub fn incumbent(&self) -> Option<&Path> {
        match self {
            Self::RepeatedKeyId { incumbent, .. }
            | Self::RepeatedConnectionId { incumbent, .. }
            | Self::PrincipalAcrossOrganizations { incumbent, .. }
            | Self::RepeatedAudience { incumbent, .. }
            | Self::RepeatedResourceServerId { incumbent, .. }
            | Self::RepeatedClientId { incumbent, .. }
            | Self::AudienceConflicted { incumbent, .. } => Some(incumbent),
            _ => None,
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
            Self::UnseedableCredential { error, .. } => write!(formatter, "{path}: {error:?}"),
            Self::Algorithm { error, .. } => write!(formatter, "{path}: {error}"),
            Self::Unregistrable { denied, .. } => write!(
                formatter,
                "{path}: mandate.federation.RegisterFederationConnection refuses these inputs \
                 ({:?}, {:?})",
                denied.clause, denied.reason
            ),
            Self::RepeatedKeyId { incumbent, kid, .. } => write!(
                formatter,
                "{path}: the kid `{kid}` is already published from {}",
                incumbent.display()
            ),
            Self::RepeatedConnectionId {
                incumbent,
                connection_id,
                ..
            } => write!(
                formatter,
                "{path}: the connection_id {connection_id} is already seeded from {}",
                incumbent.display()
            ),
            Self::PrincipalAcrossOrganizations {
                incumbent,
                principal_id,
                organization,
                held,
                ..
            } => write!(
                formatter,
                "{path}: the principal {principal_id} is linked in organization {organization} \
                 here and in {held} from {}",
                incumbent.display()
            ),
            Self::UnregistrableTarget { denied, .. } => write!(
                formatter,
                "{path}: mandate.credential.RegisterResourceServer refuses these inputs \
                 ({:?}, {:?})",
                denied.clause, denied.reason
            ),
            Self::RepeatedAudience {
                incumbent,
                organization,
                audience,
                ..
            } => write!(
                formatter,
                "{path}: the audience {audience} is already registered in organization \
                 {organization} from {}",
                incumbent.display()
            ),
            Self::RepeatedResourceServerId {
                incumbent,
                resource_server_id,
                ..
            } => write!(
                formatter,
                "{path}: the resource_server_id {resource_server_id} is already seeded from {}",
                incumbent.display()
            ),
            Self::RepeatedClientId {
                incumbent,
                client_id,
                ..
            } => write!(
                formatter,
                "{path}: the client_id {client_id} is already seeded from {}",
                incumbent.display()
            ),
            Self::AudienceConflicted {
                incumbent,
                organization,
                audience,
                resource_server_id,
                ..
            } => write!(
                formatter,
                "{path}: the registration {resource_server_id} records the audience \
                 {audience} in organization {organization} and does not hold it; {} holds \
                 it, and which of the two a request resolves to is decided by identifier \
                 order and by no document",
                incumbent.display()
            ),
            Self::ClientSecretUnresolved { reference, .. } => write!(
                formatter,
                "{path}: the client secret `{reference}` is named by no --client-secret-file"
            ),
            Self::ReturnUriUnusable { .. } => write!(
                formatter,
                "{path}: relying_party.return_uri cannot carry a handoff code in a redirect"
            ),
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

/// The client document at this path.
///
/// # Errors
///
/// Returns [`SeedRefused`] naming the file when it does not open, or is not the object
/// [`ClientSeed`] declares.
pub fn read_client_seed(path: &Path) -> Result<ClientSeed, SeedRefused> {
    serde_json::from_str(&read_document(path)?).map_err(|error| SeedRefused::Malformed {
        path: path.to_path_buf(),
        error,
    })
}

/// The resource-server document at this path.
///
/// # Errors
///
/// Returns [`SeedRefused`] naming the file when it does not open, or is not the object
/// [`ResourceServerSeed`] declares.
pub fn read_resource_server_seed(path: &Path) -> Result<ResourceServerSeed, SeedRefused> {
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
    /// The last [`EXCHANGE_RECORD_CAPACITY`] `TokenExchangeAllowed` and, bounded apart, the last as many `TokenExchangeDenied`
    /// this deployment recorded, oldest first: the in-memory record of each exchange
    /// decision. Durable delivery is `decision-blocker:audit-routing`'s.
    exchanges: Vec<CredentialEvent>,
    /// The authority decision taken before a handler is dispatched, when the deployment is
    /// configured with one.
    ///
    /// `Option`, and `None` in `src/main.rs`, for the reason `crate::authority`'s header
    /// gives: the two ports `mandate_authz::check` reads have one implementor each outside
    /// a test file and both are doubles, so a shipped binary has nothing real to configure
    /// here. A deployment that is given one asks before it dispatches; a deployment that is
    /// not is exactly the deployment that shipped before this story, which decided no
    /// authority at all.
    ///
    /// `Send` because [`crate::serve::Listener::serve`] takes a deployment onto a thread.
    authority: Option<Box<dyn Admitting + Send>>,
    /// The relying party toward external OIDC IdPs, when the deployment signs browsers in
    /// through one. `None` answers both relying-party routes with a refusal.
    relying_party: Option<RelyingParty>,
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
            exchanges: Vec::new(),
            authority: None,
            relying_party: None,
        })
    }

    /// The same deployment, signing browsers in through `relying_party`'s IdPs.
    #[must_use]
    pub fn with_relying_party(mut self, relying_party: RelyingParty) -> Self {
        self.relying_party = Some(relying_party);
        self
    }

    /// The relying party, when the deployment has one.
    #[must_use]
    pub fn relying_party(&self) -> Option<&RelyingParty> {
        self.relying_party.as_ref()
    }

    /// The same deployment, deciding `mandate.authorization.Check` through `point` before
    /// it dispatches a handler.
    ///
    /// A builder rather than a parameter of [`Deployment::new`]: the decision point is not
    /// part of the configuration a deployment is validated against, and a deployment
    /// without one is the deployment that shipped before this story. See
    /// [`crate::authority`] for why nothing real can be passed here yet.
    #[must_use]
    pub fn with_authority(mut self, point: Box<dyn Admitting + Send>) -> Self {
        self.authority = Some(point);
        self
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

    /// The `mandate.identity` read model this deployment folds.
    ///
    /// The read half of [`Deployment::record_identity`], public for the reason
    /// [`Deployment::federation`] is: a just-in-time login creates its principal here and
    /// nowhere a status code can be read off.
    #[must_use]
    pub fn identity(&self) -> &IdentityLog {
        &self.identity
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

    /// The `mandate.credential` read model this deployment folds.
    ///
    /// The read half of [`Deployment::record_credential`], public for the reason
    /// [`Deployment::federation`] is: an exchange creates its credential here and nowhere a
    /// status code can be read off.
    #[must_use]
    pub fn credentials(&self) -> &CredentialProjection {
        &self.credentials
    }

    /// The exchange decisions this deployment still holds, oldest first: the last
    /// [`EXCHANGE_RECORD_CAPACITY`] `mandate.credential.TokenExchangeAllowed`, one per admitted
    /// exchange, and, bounded separately, the last as many `TokenExchangeDenied`, one per
    /// refused one.
    #[must_use]
    pub fn exchanges(&self) -> &[CredentialEvent] {
        &self.exchanges
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
    /// the login stands instead, and the attempt **records** nothing: no event is emitted, no
    /// principal exists that did not before, and the fold is the one the login read.
    ///
    /// It is not free of every effect, and saying "creates nothing" would be the file lying
    /// about itself. [`Deployment::provisioned`] builds the whole `RequestContext` before it
    /// calls the command, and minting the correlation of the record the command *would*
    /// write is part of building it — so one identity is drawn from this deployment's own
    /// source per attempt, refused attempts included. **The draw precedes the decision; the
    /// decision never consults it.** `provision_external_principal` reads
    /// `request.correlation` in one place, inside the accepted outcome it emits, and no
    /// refusal path in that command reads the request at all. Moving the draw after the
    /// command admits would therefore change no outcome, and is a shape this call site does
    /// not have: the context is one value, built eagerly, and the correlation is one of its
    /// fields. Nothing observable to a caller rests on the draw either — the source is a
    /// CSPRNG — and `ExternalKeyExists` is now reachable here on every revoked key, which is
    /// what makes the refused attempts routine rather than exceptional.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the connection is unresolved or disabled, the proof
    /// is refused, its issuer or audience is not the connection's, tenant resolution has zero
    /// or multiple matches, or the link is absent or the principal disabled — and, on this
    /// route alone, when the connection signs browsers in through its IdP's code flow.
    ///
    /// **A relying-party connection admits no proof presented here.** Its ID tokens are
    /// nonce-bound to a sign-in this deployment started, and this route has no nonce to bind
    /// them to: an ID token lifted from one browser's flow would open a session here with
    /// no check that anybody started one. So the callback
    /// ([`Deployment::complete_federation`]) is that connection's only way in, and it reaches
    /// the command without this refusal.
    pub fn authenticate(
        &mut self,
        input: &decode::AuthenticateFederation,
    ) -> Result<Login, Refusal> {
        if self
            .relying_party
            .as_ref()
            .is_some_and(|relying_party| relying_party.relies_on(&input.connection_id))
        {
            return Err(relying_refusal(
                DenialReason::InvalidCredential,
                FederationClause::NonceMismatch,
            ));
        }
        self.authenticate_admitted(input)
    }

    /// [`Deployment::authenticate`] without the relying-party refusal: the three-step
    /// sequence itself, for the login route and the callback both.
    fn authenticate_admitted(
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
        let Some(connection) = self.federation.connection(&input.connection_id) else {
            return Err(Refusal::from(&denied));
        };
        if denied.clause != FederationClause::LinkAbsent || !connection.jit_provisioning {
            return Err(Refusal::from(&denied));
        }
        // And the clause is not enough by itself: it is two conditions under one name —
        // never linked, and linked and then revoked — and only one of them may be
        // provisioned into. **The command decides that, not this adapter.**
        // `ProvisionExternalPrincipal` refuses `ExternalKeyExists` for a key any record
        // holds in any lifecycle state (`crates/mandate-federation/src/authenticate.rs`),
        // including the terminal `Unlinked` one `mandate.federation.UnlinkExternalPrincipal`
        // moves a link to, so a revoked key creates nothing here: `provisioned` answers
        // false and the login's own `LinkAbsent` stands.
        //
        // This adapter carried a `key_holds_no_record` pre-check of its own until
        // `story:link-absent-discriminates` moved the condition into the library, where
        // every composition inherits it rather than one. Deciding it in two places is what
        // lets them disagree.
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
    ///
    /// **One identity is drawn per attempt, refused attempts included**, because the whole
    /// `RequestContext` below is built before the command is called and the correlation is
    /// one of its fields. The command does not decide against it: `provision_external_principal`
    /// reads `request.correlation` only inside the accepted outcome it emits, and no refusal
    /// path there reads the request at all — see [`Deployment::authenticate`], which says
    /// what a refused attempt does and does not leave behind. Since
    /// `story:link-absent-discriminates` the command refuses `ExternalKeyExists` for every
    /// key a revoked record holds, so this is the ordinary path for a revoked subject's every
    /// login attempt, not an exceptional one.
    fn provisioned(&mut self, input: &decode::AuthenticateFederation) -> bool {
        let request = mandate_federation::RequestContext {
            audience: self.audience(),
            // Minted here, from the deployment's own identity source, for the reason the
            // login's own correlation is minted rather than read: nothing a caller sent may
            // become the correlation of a persisted record. Drawn before the command decides
            // — not because the decision needs it, which it does not, but because this
            // context is built in one go — so a refusal has consumed one: see this
            // function's header.
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
        // `mandate.identity.Principal` (`identity.yaml`'s header), so both folds read it.
        // The identity fold reads it in its generated shape, and the encoding is the one
        // `crates/mandate-federation/tests/contract_agreement.rs` proves round-trips through
        // that shape; one it cannot read is decided before either fold is touched.
        //
        // Both folds decide before either is written: the federation fold is folded into a
        // copy, the identity fold appends only what it accepts, and the copy replaces the
        // federation fold only once the identity fold has accepted. A refusal by either
        // leaves both as they were, which is what `false` promises the caller.
        let Some(principal) = identity_event_of(&provisioned.event) else {
            return false;
        };
        let mut federation = self.federation.clone();
        if federation.apply(&provisioned.event).is_err() {
            return false;
        }
        if self.identity.try_record(principal).is_err() {
            return false;
        }
        self.federation = federation;
        true
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
        //
        // **Unreachable refusal, which is why it is discarded rather than surfaced after the
        // session above has been opened.** The fold's one refusal of a
        // `FederationAuthenticated` is `FoldError::UnknownConnection`
        // (`crates/mandate-federation/src/record.rs`), and the event's `connection_id` is
        // `resolved.connection.id`: the record `authenticate_federation` found in this same
        // fold, through `ConnectionStore::connection`, while this `&mut self` held it. Nothing
        // between that read and this apply writes the fold, and no event removes a
        // connection from it. The arm mutates nothing either, so a refusal would lose no
        // record. A change that gives this arm a second refusal must decide it before the
        // issuer opens the session (`story:control-plane-multi-fold-writes`).
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

        // The authority decision, **before** the handler is dispatched. Nothing below this
        // point runs for a caller the decision point refuses: the code is not minted, the
        // append is not made, and the refusal is the declared `mandate.authorization.Denied`
        // reason rather than a clause of a command that was never called.
        //
        // The question is asked about the command that is about to be dispatched
        // (`ISSUE_AUTHORIZATION_CODE`) on the registered target, under the context the
        // dispatch would run in. `crate::authority`'s header records why the relation is a
        // constant, why `scope` is `None`, and why a deployment that was given no decision
        // point asks nothing at all.
        if let Some(authority) = self.authority.as_mut() {
            let action = Action::new(ISSUE_AUTHORIZATION_CODE);
            let resource = ResourceRef {
                resource_type: ResourceType::new(RESOURCE_SERVER),
                resource_id: ResourceId::new(*input.target.as_uuid()),
            };
            // The expectation is the context's own audience, and `context::bind`'s
            // `AudienceMismatch` arm is therefore **unreachable from here**: both values
            // are the registered target's, read from the credential fold a few lines
            // above, and this endpoint runs before any credential exists for a second
            // source to disagree with. Said plainly rather than left for a reader to
            // discover, and said in `crate::authority`'s header too, with what it would
            // take to make the arm reachable honestly.
            if let Err(denied) = authority.admit(&Admission {
                context: &assembled.context,
                action: &action,
                resource: &resource,
                expected_audience: &assembled.context.audience,
                relation: ISSUANCE_RELATION,
                scope: None,
            }) {
                return Err(AuthorizationRefusal::AtRedirect {
                    refusal: Refusal {
                        clause: AUTHORITY_DENIED.to_owned(),
                        reason: denied.reason,
                    },
                    redirect_uri: input.redirect_uri.clone(),
                    state: input.state.clone(),
                });
            }
        }

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
        //
        // **Unreachable refusal, which is why it is discarded rather than surfaced after the
        // code has been consumed.** The fold's one refusal of an `AuthorizationCodeRedeemed`
        // is `FoldError::UnknownIssuingTarget` (`crates/mandate-token/src/projection.rs`,
        // `record_credential`), for a `target` no event registered. The event's `target` is
        // the code's own, and `redeem_and_consume` decided it through `target_in_tenant`
        // against this same fold (`bound.servers` above), refusing `TargetUnregistered` before
        // the consume; nothing between that read and this apply writes the fold, and no event
        // removes a registration. A repeated `credential_id` is insert-if-absent, not a
        // refusal. A change that gives this arm a second refusal must decide it before the
        // consume (`story:control-plane-multi-fold-writes`).
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

    /// Start a sign-in through the connection's IdP: mint a `state`, a `nonce`, a PKCE
    /// verifier and a browser binding, hold them with the application's `app_state`, and
    /// answer the IdP authorization URL the browser is sent to with the bindings its cookie
    /// carries.
    ///
    /// Each value is one draw of this deployment's secret source — the 44-character base64
    /// text of 32 random bytes — re-rendered in unpadded base64url, so each is 59 characters
    /// and the verifier is inside RFC 7636's 43 to 128 of its unreserved set. Its S256
    /// challenge is sent in its place.
    ///
    /// The browser keeps the bindings of the sign-ins it already holds, newest last and at
    /// most [`MAX_HELD_BINDINGS`] with this one, so two tabs signing in at once each complete.
    ///
    /// A full pending store evicts its oldest sign-in rather than refusing this one
    /// ([`OnceStore`]); the flood that exploits that is `story:authorize-flood-eviction`'s,
    /// and the ingress rate limit is the defence until it lands.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the deployment has no relying party, the
    /// connection is unknown, disabled or not configured for one, or its IdP's endpoints
    /// cannot be read, are not admitted, or are not a URI.
    pub fn begin_federation(
        &mut self,
        input: &decode::BeginFederation,
    ) -> Result<Started, Refusal> {
        let now = self.clock.unix_seconds();
        let connection = self
            .federation
            .connection(&input.connection_id)
            .ok_or_else(|| {
                relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
            })?;
        if connection.state != mandate_federation::record::ConnectionState::Enabled {
            return Err(relying_refusal(
                DenialReason::Denied,
                FederationClause::ConnectionDisabled,
            ));
        }
        let state = base64url(self.secrets.next_secret().expose_bytes());
        let nonce = base64url(self.secrets.next_secret().expose_bytes());
        let verifier = base64url(self.secrets.next_secret().expose_bytes());
        let binding = base64url(self.secrets.next_secret().expose_bytes());
        let relying_party = self.relying_party.as_mut().ok_or_else(|| {
            relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
        })?;
        let configured = relying_party
            .connections
            .get(&input.connection_id)
            .ok_or_else(|| {
                relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
            })?;
        let found = endpoints_of(
            relying_party.endpoint.as_ref(),
            &connection.issuer,
            configured,
        )
        .map_err(token_refused)?;
        let challenge = s256_challenge(&CredentialProof::from_bytes(verifier.as_bytes().to_vec()));
        let location = authorization_request(
            &found.authorization_endpoint,
            &connection.client_id,
            &configured.redirect_uri,
            &state,
            &nonce,
            challenge.as_str(),
        );
        relying_party.pending.insert(
            state,
            PendingLogin {
                connection_id: input.connection_id,
                nonce,
                verifier: CredentialProof::from_bytes(verifier.into_bytes()),
                binding: binding.clone(),
                app_state: input.app_state.clone(),
            },
            now,
        );
        let kept = input.bindings.len().saturating_sub(MAX_HELD_BINDINGS - 1);
        let mut bindings: Vec<String> = input.bindings[kept..].to_vec();
        bindings.push(binding);
        Ok(Started { location, bindings })
    }

    /// Finish a sign-in: take the pending `state` once, require a browser binding the
    /// authorize step set, redeem the code at the IdP's token endpoint with HTTP Basic client
    /// authentication and the PKCE verifier, verify the returned ID token with the
    /// deployment's verifier, check its `nonce`, realize
    /// `mandate.federation.AuthenticateFederation` over it — just-in-time branch included —
    /// and hold the session for a single-use handoff.
    ///
    /// **The state is taken before anything is decided.** A callback naming it is its only
    /// use, whatever that callback answers — a missing or wrong binding, an IdP error
    /// response, a refused code — so a replayed or a second callback finds nothing and
    /// reaches no IdP.
    ///
    /// **The browser's binding cookie changes only when this callback used up the sign-in
    /// one of its bindings binds** ([`CallbackAnswer::bindings_left`]). A callback naming a
    /// state nobody issued, or another browser's or another tab's sign-in, leaves every
    /// binding the browser holds where it is: a cross-site navigation to this route cannot end
    /// the sign-in the browser is in the middle of.
    ///
    /// **The session proof is not answered here.** The callback is a browser navigation, and
    /// a bearer credential in its response is one in the browser's history and every
    /// extension that reads it. A single-use code is answered instead, beside the
    /// application's `app_state`, and the embedding application exchanges it server-to-server
    /// ([`Deployment::redeem_handoff`]).
    ///
    /// The outcome is a refusal when the state is unknown, used or expired, no presented
    /// binding binds it, the IdP answered an error, the callback's `iss` is not the
    /// connection's issuer or is absent where the IdP advertises it, the code is not
    /// redeemed, the ID token is refused, its nonce is not the one sent, or the login itself
    /// is refused.
    pub fn complete_federation(&mut self, input: &decode::CompleteFederation) -> CallbackAnswer {
        let now = self.clock.unix_seconds();
        let refused = |clause| CallbackAnswer {
            bindings_left: None,
            outcome: Err(relying_refusal(DenialReason::InvalidCredential, clause)),
        };
        let Some(relying_party) = self.relying_party.as_mut() else {
            return refused(FederationClause::ConnectionUnknown);
        };
        let Some(pending) = relying_party.pending.take(&input.state, now) else {
            return refused(FederationClause::StateMismatch);
        };
        // Login CSRF: a callback URL completed by any client but the browser that started
        // the sign-in opens nothing. Every presented binding is compared, so the answer does
        // not depend on where in the cookie the matching one sits.
        let bound = input.bindings.iter().fold(false, |found, presented| {
            found | same_text(presented, &pending.binding)
        });
        if !bound {
            return refused(FederationClause::StateMismatch);
        }
        let bindings_left = input
            .bindings
            .iter()
            .filter(|presented| !same_text(presented, &pending.binding))
            .cloned()
            .collect();
        CallbackAnswer {
            bindings_left: Some(bindings_left),
            outcome: self.finish_federation(input, pending, now),
        }
    }

    /// The rest of the callback, once the pending sign-in is taken and its binding matched.
    fn finish_federation(
        &mut self,
        input: &decode::CompleteFederation,
        pending: PendingLogin,
        now: u64,
    ) -> Result<Handoff, Refusal> {
        let relying_party = self.relying_party.as_mut().ok_or_else(|| {
            relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
        })?;
        // OIDC Core 3.1.2.6: the IdP refused. Its text is not read and never echoed.
        let Some(code) = input.code.as_ref().filter(|_| !input.error) else {
            eprintln!("mandate-control-plane: relying party refused IdpError");
            return Err(relying_refusal(
                DenialReason::Denied,
                FederationClause::ProofInvalid,
            ));
        };
        let connection = self
            .federation
            .connection(&pending.connection_id)
            .ok_or_else(|| {
                relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
            })?;
        // RFC 9207: an `iss` that is present names the issuer that answered. One that is not
        // this connection's is a response from somewhere else, whatever it carries.
        if let Some(named) = &input.issuer
            && named != connection.issuer.as_str()
        {
            return Err(relying_refusal(
                DenialReason::InvalidCredential,
                FederationClause::IssuerMismatch,
            ));
        }
        let configured = relying_party
            .connections
            .get(&pending.connection_id)
            .ok_or_else(|| {
                relying_refusal(DenialReason::Denied, FederationClause::ConnectionUnknown)
            })?;
        let found = endpoints_of(
            relying_party.endpoint.as_ref(),
            &connection.issuer,
            configured,
        )
        .map_err(token_refused)?;
        // RFC 9207 section 2.4: an IdP whose metadata advertises `iss` in the authorization
        // response obliges the client to reject a response without it.
        if found.issuer_in_response && input.issuer.is_none() {
            return Err(relying_refusal(
                DenialReason::InvalidCredential,
                FederationClause::IssuerMismatch,
            ));
        }
        let return_uri = configured.return_uri.clone();
        let proof = relying_party
            .endpoint
            .redeem(&CodeRedemption {
                issuer: &connection.issuer,
                token_endpoint: &found.token_endpoint,
                allowed_hosts: &configured.allowed_hosts,
                client_id: &connection.client_id,
                client_secret: &configured.client_secret,
                code,
                redirect_uri: &configured.redirect_uri,
                code_verifier: &pending.verifier,
            })
            .map_err(token_refused)?;
        let verified = self
            .verifier
            .verify(&connection, &proof)
            .map_err(|denied| Refusal::from(&denied))?;
        if !nonce_matches(&verified, &pending.nonce) {
            return Err(relying_refusal(
                DenialReason::InvalidCredential,
                FederationClause::NonceMismatch,
            ));
        }
        let login = self.authenticate_admitted(&decode::AuthenticateFederation {
            connection_id: pending.connection_id,
            proof,
        })?;
        let code = base64url(self.secrets.next_secret().expose_bytes());
        if let Some(relying_party) = self.relying_party.as_mut() {
            relying_party
                .handoffs
                .insert(code.clone(), (login, pending.app_state.clone()), now);
        }
        Ok(Handoff {
            return_uri,
            code,
            app_state: pending.app_state,
        })
    }

    /// Exchange a handoff code for the session a callback opened: once, only within
    /// [`HANDOFF_LIFETIME`], and only for the application that started the sign-in — the one
    /// presenting the same `app_state`, or none where it was started with none.
    ///
    /// **A mismatched `app_state` uses the code up.** The code is taken before the comparison,
    /// so an attacker's completed sign-in delivered to a victim's application, which presents
    /// its own `app_state`, is refused there and cannot then be redeemed by anyone.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the deployment has no relying party, the code is
    /// unknown, already exchanged or expired (`SessionUnknown`), or the `app_state` is not the
    /// one the sign-in was started with (`StateMismatch`).
    pub fn redeem_handoff(&mut self, input: &decode::RedeemHandoff) -> Result<Login, Refusal> {
        let now = self.clock.unix_seconds();
        let (login, bound) = self
            .relying_party
            .as_mut()
            .and_then(|relying_party| relying_party.handoffs.take(&input.handoff, now))
            .ok_or_else(|| {
                relying_refusal(
                    DenialReason::InvalidCredential,
                    FederationClause::SessionUnknown,
                )
            })?;
        let same = match (&bound, &input.app_state) {
            (None, None) => true,
            (Some(bound), Some(presented)) => same_text(bound, presented),
            _ => false,
        };
        if !same {
            return Err(relying_refusal(
                DenialReason::InvalidCredential,
                FederationClause::StateMismatch,
            ));
        }
        Ok(login)
    }
}

impl<V, C, X, A> Deployment<V, C, X, A>
where
    V: FederationVerifier,
    C: Clock,
    X: SecretSource,
    A: IdentityAllocator,
{
    /// Realize `mandate.credential.ExchangeCredential`, subject-only, and record the decision.
    ///
    /// The subject proof is resolved against the credential fold, authoritatively; the source
    /// is the registration the subject credential was issued for, and the target's
    /// registration must list it (`mandate_sts::exchange`). An admitted exchange folds the
    /// credential it issued and records `TokenExchangeAllowed`; a refused one records
    /// `TokenExchangeDenied`, folds nothing and draws nothing from this deployment's secret
    /// source or allocator.
    ///
    /// No authority decision is asked here, and that is a gap rather than a ruling: the
    /// decision point ([`Deployment::with_authority`]) is asked about a context the adapter
    /// already holds, and an exchange's context is the one the STS validates the subject
    /// proof to. `None` is what the shipped binary configures (`crate::authority`).
    ///
    /// # Errors
    ///
    /// Returns the declared refusal the exchange was refused with; see
    /// [`mandate_sts::exchange::exchange_credential`].
    pub fn exchange(
        &mut self,
        input: &decode::ExchangeCredential,
    ) -> Result<Exchanged, ExchangeDenied> {
        let at = self.now();
        let request = StsRequest {
            correlation: CorrelationId::new("exchange"),
            at: at.clone(),
            epochs: None,
        };
        let outcome = exchange_request(
            &ExchangeRequest {
                subject_proof: input.subject_proof.clone(),
                actor_proof: input.actor_proof.clone(),
                target: match &input.target {
                    decode::ExchangeTarget::Registration(id) => ExchangeTarget::Registration(*id),
                    decode::ExchangeTarget::Audience(audience) => {
                        ExchangeTarget::Audience(audience.clone())
                    }
                },
                requested_scope: input.requested_scope.clone(),
                delegation_id: input.delegation_id,
            },
            &request,
            &self.credentials,
            ExchangeParts {
                digest: &self.digest,
                resolution: &self.credentials,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        );
        match outcome {
            Err(refused) => {
                self.record_exchange(refused.event);
                Err(ExchangeDenied {
                    clause: refused.denied.clause,
                    reason: refused.denied.reason,
                    cause: refused.cause,
                })
            }
            Ok(issued) => {
                // **Unreachable refusal, discarded for the reason `redeem` gives for its own.**
                // The fold's one refusal of a creating event is `UnknownIssuingTarget`, and
                // the exchange decided its target through `admitted_target` against this same
                // fold a moment ago; nothing between that read and this apply writes it.
                let _ = self.credentials.apply(&issued.event);
                self.record_exchange(issued.event);
                let expires_in =
                    seconds_between(&at, &issued.descriptor.expires_at).unwrap_or_default();
                Ok(Exchanged {
                    credential: issued.credential,
                    credential_id: issued.credential_id,
                    descriptor: issued.descriptor,
                    expires_in,
                })
            }
        }
    }
}

impl<V, C, X, A> Deployment<V, C, X, A> {
    /// Record one exchange decision, evicting the oldest past [`EXCHANGE_RECORD_CAPACITY`].
    ///
    /// One ordered record, so [`Deployment::exchanges`] reads the decisions as they were
    /// taken, and two bounds over it: the oldest record **of the arriving kind** is what is
    /// evicted, so a flood of refusals leaves every admitted record where it was.
    fn record_exchange(&mut self, event: CredentialEvent) {
        let allowed = |record: &CredentialEvent| {
            matches!(record, CredentialEvent::TokenExchangeAllowed { .. })
        };
        let arriving = allowed(&event);
        let same_kind = self
            .exchanges
            .iter()
            .filter(|record| allowed(record) == arriving)
            .count();
        if same_kind >= EXCHANGE_RECORD_CAPACITY
            && let Some(oldest) = self
                .exchanges
                .iter()
                .position(|record| allowed(record) == arriving)
        {
            self.exchanges.remove(oldest);
        }
        self.exchanges.push(event);
    }
}

/// `mandate.federation.ExternalPrincipalProvisioned`, as the identity fold reads it.
///
/// `mandate-identity` reads the event in its generated shape because the dependency runs
/// `mandate-federation → mandate-identity` and never back (`crates/mandate-identity/src/port.rs`,
/// `IdentityEvent::ExternalPrincipalProvisioned`). The federation crate's encoding of the event
/// *is* that shape — `crates/mandate-federation/tests/contract_agreement.rs` round-trips every
/// event through its generated type and requires the identity — so it is carried across by
/// that encoding rather than by a field-for-field copy that could drift from it. Answers `None`
/// for any other event, and for an encoding the generated shape refuses.
fn identity_event_of(event: &FederationEvent) -> Option<IdentityEvent> {
    let FederationEvent::ExternalPrincipalProvisioned { .. } = event else {
        return None;
    };
    let encoded = serde_json::to_value(event).ok()?;
    serde_json::from_value(encoded)
        .ok()
        .map(IdentityEvent::ExternalPrincipalProvisioned)
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
        //
        // Every recording decides before any is kept: they are recorded into a copy, and the
        // copy replaces the fold only once the session has been accepted — the copy-then-swap
        // `Deployment::provisioned` uses. Each recording must go to the copy rather than be
        // pre-checked against the fold, because each is decided against the ones before it:
        // the snapshot needs its dimensions stated and the session needs its snapshot. A
        // refusal at any step leaves the fold as the login found it, rather than holding
        // generations stated for a session that was never opened.
        let unavailable =
            || FederationDenied::new(DenialReason::Unavailable, FederationClause::SessionUnknown);
        let mut identity = self.identity.clone();
        for target in [
            SecurityEpochTarget::Principal(principal_id),
            SecurityEpochTarget::Organization(organization_id),
            SecurityEpochTarget::Federation(connection_id),
        ] {
            if identity.current(&target).version() == StreamVersion::INITIAL {
                identity
                    .try_record(IdentityEvent::SecurityEpochRecorded(
                        SecurityEpochRecorded {
                            target,
                            generation: Generation::ZERO,
                        },
                    ))
                    .map_err(|_| unavailable())?;
            }
        }
        identity
            .try_record(IdentityEvent::EpochSnapshotRecorded(
                EpochSnapshotRecorded {
                    id: self.epochs,
                    principal_id,
                    organization_id,
                    connection_id: Some(connection_id),
                },
            ))
            .map_err(|_| unavailable())?;
        identity
            .try_record(IdentityEvent::SessionOpened(SessionOpened {
                id: self.session_id,
                principal_id,
                organization_id,
                connection_id: Some(connection_id),
                epochs: self.epochs,
                expires_at: self.expires_at.clone(),
            }))
            .map_err(|_| unavailable())?;
        *self.identity = identity;
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

    /// 16 fresh bytes from the host CSPRNG. This allocator keeps no state, so a reservation
    /// is held by the source never answering those bytes again, and a released one leaves
    /// nothing behind: an identity never handed on is indistinguishable from one never read.
    ///
    /// # Panics
    ///
    /// Panics when the opened CSPRNG cannot be read; see [`SystemSecrets::next_secret`].
    fn reserve_credential_id(&mut self) -> CredentialId {
        CredentialId::new(self.next_uuid())
    }

    fn commit_credential_id(&mut self, _reserved: CredentialId) {}

    fn release_credential_id(&mut self, _reserved: CredentialId) {}
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
