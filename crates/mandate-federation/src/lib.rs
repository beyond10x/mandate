//! Verified federation and explicit linking.
//!
//! The commands this crate realizes are declared in
//! `systems/mandate/domains/federation.yaml`. The canonical external key is
//! `(organization, connection.issuer, external subject)`, and the issuer is read from
//! the validated connection rather than from the caller (`federation.yaml:1`).
//!
//! # What is here, and what is behind a port
//!
//! Steps 1, 2 and 5-9 of the mandated resolution order
//! (`docs/architecture/federated-login.md`) are pure domain logic and live here.
//! Signature verification is step 3; no dependency in this crate's ceiling can perform
//! it, so it sits behind [`FederationVerifier`] with the double
//! [`verifier::ConstructedVerifier`], which admits or refuses by construction.
//! `story:signing-and-verification` attaches a real implementation at that trait.
//!
//! # Why the doubles are `pub`
//!
//! Every file under `tests/` compiles as its own crate, so a double declared in one of
//! them is unreachable from the others. The three ports this crate declares are doubled
//! here instead: [`verifier::ConstructedVerifier`], [`SequentialAllocator`] and
//! [`RecordingSessionIssuer`].
//!
//! # Records are folds
//!
//! `docs/adr/0009-event-sourced-persistence.md`: commands produce events, the events are
//! the record, reads are folds. A command handler here is a pure function of the read
//! model and its input; it returns the event it would emit and mutates nothing. The
//! caller appends, and [`record::Projection::fold`] rebuilds the read model.

pub mod authenticate;
pub mod authorize;
pub mod link;
pub mod pkce;
pub mod publicclient;
pub mod record;
pub mod verifier;

use core::fmt;

use mandate_types::{
    Audience, CorrelationId, CredentialId, CredentialProof, DenialReason, ExternalPrincipalId,
    FederationConnectionId, Issuer, OrganizationId, PrincipalId, SessionId, Timestamp, value::Uuid,
};

use record::{ExternalKey, ExternalPrincipal, FederationConnection, Projection};
use verifier::VerifiedProof;

/// `mandate.federation.Denied`: fail closed; no credential, authority or lifecycle
/// mutation on refusal (`federation.yaml:388-393`).
///
/// The contract's error payload is [`DenialReason`] alone. [`Denied::clause`] is a
/// crate-local discriminator that names *which* declared denial condition fired; it is
/// not a contract field and no wire form carries it. It exists because two conditions
/// the adapter sequence must tell apart — an absent link and a conflicting one — both
/// surface as `DenialReason::Denied`, which `story:federation-linking` records as a
/// contract change for `story:domain-runtime` to weigh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The declared `mandate.core.DenialReason`.
    pub reason: DenialReason,
    /// Which declared denial condition fired. Crate-local; see the type documentation.
    pub clause: DenialClause,
}

impl Denied {
    /// Refuse, naming the declared reason and the condition that fired.
    #[must_use]
    pub const fn new(reason: DenialReason, clause: DenialClause) -> Self {
        Self { reason, clause }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "denied: {:?} ({:?})", self.reason, self.clause)
    }
}

impl std::error::Error for Denied {}

/// A condition named by a declared denial clause in `federation.yaml`.
///
/// Every variant is one phrase of the denial text of `LinkExternalPrincipal`,
/// `AuthenticateFederation`, `ProvisionExternalPrincipal` or
/// `RegisterFederationConnection`, verbatim from `docs/architecture/command-obligations.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DenialClause {
    /// The connection named by the command does not resolve.
    ConnectionUnknown,
    /// "Connection is disabled/untrusted".
    ConnectionDisabled,
    /// "proof signature/issuer/audience/expiry is invalid", refused at the verifier.
    ProofInvalid,
    /// "proof signature/issuer/audience/expiry is invalid": the validated proof's issuer
    /// is not the connection's configured issuer.
    IssuerMismatch,
    /// "proof signature/issuer/audience/expiry is invalid": the validated audience is not
    /// the connection's configured client.
    AudienceBinding,
    /// "tenant resolution has zero or multiple matches": zero.
    TenantZero,
    /// "tenant resolution has zero or multiple matches": multiple. No tenant is guessed.
    TenantAmbiguous,
    /// "any email-domain/unverified-input fallback would be required": a rule would have
    /// matched on an unverified value, so the request is refused rather than resolved.
    UnverifiedFallback,
    /// "organization or target principal mismatches", and the consistent
    /// organization/connection binding of `federation.yaml:2`.
    OrganizationMismatch,
    /// "Caller/method lacks linking authority".
    LinkingAuthority,
    /// "principal linking is absent/conflicting": absent.
    LinkAbsent,
    /// "composite (organization, configured issuer, subject) key conflicts".
    LinkConflict,
    /// "connection does not admit provisioning".
    ProvisioningNotAdmitted,
    /// "the composite (organization, configured issuer, subject) key already exists".
    ExternalKeyExists,
    /// "organization or target principal mismatches": the target principal is recorded
    /// outside the connection's organization, or is not recorded at all.
    PrincipalMismatch,
    /// A key component that is empty is not a key component: the canonical key would
    /// collapse across identities.
    EmptySubject,
    /// A subject that is not its own trim is not the subject the issuer issued.
    SubjectNotTrimmed,
    /// The target or linked principal is in the terminal `Disabled` state.
    PrincipalDisabled,
    /// `RegisterFederationConnection`: "tenant-resolution ... configuration is
    /// unadmitted". Two organizations cannot share an issuer when either resolves it
    /// unconditionally; see [`record::register_federation_connection`].
    TenantResolutionUnadmitted,
    /// `AuthorizePublicClient`: "S256 challenge is absent/invalid": the recorded
    /// challenge is not in the declared S256 form.
    ChallengeMalformed,
    /// "S256 challenge is absent/invalid": no code verifier was presented.
    VerifierMissing,
    /// "S256 challenge is absent/invalid": the presented verifier is not in the form
    /// RFC 7636 section 4.1 declares.
    VerifierMalformed,
    /// "S256 challenge is absent/invalid": the presented verifier does not digest to the
    /// recorded challenge.
    VerifierMismatch,
    /// `AuthorizePublicClient`: "client is not a registered public client": the read
    /// model answers no client with that identity.
    ClientUnknown,
    /// "client is not a registered public client": the client is not a public client.
    ClientNotPublic,
    /// "the client is disabled": the client is in the terminal `Disabled` state.
    ClientDisabled,
    /// "exact redirect URI ... binding fails": the presented redirect URI is not
    /// byte-identical to a registered one, or to the one the code record bound.
    RedirectMismatch,
    /// "Session proof is invalid/stale": the code names a session the read model does
    /// not resolve.
    SessionUnknown,
    /// "Session proof is invalid/stale": the session is in the terminal `Revoked` state.
    SessionRevoked,
    /// "Session proof is invalid/stale": the session's epoch snapshot does not resolve,
    /// or is bound to another subject.
    SessionEpochUnresolved,
    /// "source/session epoch is stale" (`credential.yaml:223`): an applicable generation
    /// no longer matches the authoritative one.
    SessionStale,
    /// "Session proof is invalid/stale": the session's own expiry has passed.
    SessionExpired,
    /// "code is consumed/expired" (`credential.yaml:223`): the code record is in the
    /// declared terminal `Consumed` state. The concurrent second redemption is the STS
    /// transaction's to refuse, not this one's.
    CodePreviouslyRedeemed,
    /// "code is consumed/expired": the code record's expiry has passed, or names no
    /// instant. The request instant naming none is this clause with the reason
    /// `Unavailable` — the reader cannot be dated, which is not the record expiring.
    CodeExpired,
    /// "target is unregistered/outside tenant": the registry answers no organization for
    /// the target the code names.
    TargetUnknown,
    /// "target is unregistered/outside tenant": the target is registered to another
    /// organization than the verified one.
    TargetOutsideTenant,
    /// The registry cannot answer for the target at all, which is not a decision that it
    /// is unregistered. The reason is `Unavailable`, as for a request that names no
    /// instant.
    TargetUnanswerable,
    /// "state/applicable nonce binding fails": the presented state is not the one the
    /// authorization request recorded.
    StateMismatch,
    /// "state/applicable nonce binding fails": the applicable nonce is absent, unbound or
    /// not the one the authorization request recorded.
    NonceMismatch,
    /// The verifier's configured algorithm allowlist is not an admitted one.
    /// `decision-blocker:algorithm-policy`: an empty set is rejected. The admitted names
    /// themselves are withheld, so none is named here.
    AlgorithmPolicy,
}

/// What the adapter carries that neither a command input nor the read model supplies.
///
/// `federation.yaml` declares the `context` of `FederationAuthenticated` and
/// `ExternalPrincipalProvisioned` as `generated: true`, and `mandate.core.VerifiedContext`
/// requires an audience, a credential and a correlation. The subject, the organization
/// and — for an authentication — the credential are resolved here. These are the fields
/// that are left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// The audience the control plane establishes the context for.
    pub audience: Audience,
    /// The correlation carried through the request.
    pub correlation: CorrelationId,
    /// The credential the trusted federation endpoint was reached with.
    ///
    /// `ProvisionExternalPrincipal` mints no session and no credential — "No session is
    /// minted here; the adapter calls AuthenticateFederation again" — and its event
    /// nevertheless carries a `VerifiedContext`, whose `credential` is required. The
    /// contract names no source for it. An authentication does not read this field: it
    /// names the credential [`SessionIssuer`] minted.
    pub credential: CredentialId,
    /// The moment the request is being served. A clock is an adapter concern.
    pub at: Timestamp,
}

/// Step 3 of the resolution order, behind a port.
///
/// An implementation validates the proof's signature against the connection's configured
/// trust and returns what it validated. It never reports the caller's own claims as
/// validated ones.
pub trait FederationVerifier {
    /// Validate `proof` against `connection`.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] when the proof is not admitted.
    fn verify(
        &self,
        connection: &FederationConnection,
        proof: &CredentialProof,
    ) -> Result<VerifiedProof, Denied>;
}

/// What issuing a session produced.
///
/// `mandate.identity.Session` is the session; the credential the session was validated
/// from is named by identifier alone, never by material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedSession {
    /// The session `AuthenticateFederation` responds with.
    pub session_id: SessionId,
    /// The credential identifier the generated `VerifiedContext` names.
    pub credential_id: CredentialId,
}

/// Step 9 of the resolution order, behind a port.
///
/// `decision-blocker:epoch`: `Session.epochs` is an `EpochSnapshotRef`, an immutable
/// handle. Nothing here compares generations.
pub trait SessionIssuer {
    /// Mint a session for a resolved principal in a resolved organization.
    ///
    /// # Errors
    ///
    /// Returns [`Denied`] when the session cannot be issued.
    fn issue(
        &mut self,
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        connection_id: FederationConnectionId,
    ) -> Result<IssuedSession, Denied>;
}

/// The identities a command's *response* binds, behind a port.
///
/// `federation.yaml` binds `connection_id`, `principal_id` and `external_principal_id`
/// from the response rather than from the caller, so the handler mints them. No crate in
/// this crate's dependency ceiling generates a UUID, which is why this is a port and not
/// a function.
pub trait IdentityAllocator {
    /// The identity `RegisterFederationConnection` responds with.
    fn next_connection_id(&mut self) -> FederationConnectionId;
    /// The identity `ProvisionExternalPrincipal` responds with for the created principal.
    fn next_principal_id(&mut self) -> PrincipalId;
    /// The identity a linking command responds with.
    fn next_external_principal_id(&mut self) -> ExternalPrincipalId;
}

/// The connection read model. A fold over the event log; see
/// [`record::Projection`].
pub trait ConnectionStore {
    /// The connection with this identity, whatever its lifecycle state.
    fn connection(&self, id: &FederationConnectionId) -> Option<FederationConnection>;
    /// Every `Enabled` connection configured for this issuer.
    ///
    /// Tenant resolution runs over this set rather than over the selected connection
    /// alone: a single connection carries one `TenantResolutionRule` and so could only
    /// ever yield zero or one match, while `federation.yaml:210` declares a denial for
    /// "zero or multiple matches".
    fn enabled_for_issuer(&self, issuer: &Issuer) -> Vec<FederationConnection>;
}

/// The external-principal read model, keyed by the canonical composite key.
pub trait LinkStore {
    /// The link recorded for this exact key, if there is one.
    ///
    /// An implementation may return a row in any lifecycle state. Every command that
    /// reads this port honours [`record::ExternalPrincipal::state`] itself rather than
    /// relying on an implementation to filter, because a port cannot make that a
    /// property of the command.
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal>;
}

/// The principal read model, for the half of "organization or target principal
/// mismatches" that is about the target principal.
///
/// `mandate.identity.Principal` is another domain's record. An adapter answers this port
/// from that domain's read model; [`record::Projection`] answers it only for the
/// principals this crate's own events created, which is why an unanswered principal is
/// refused rather than admitted.
pub trait PrincipalStore {
    /// The organization the principal is recorded in, if it is recorded at all.
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId>;

    /// The principal's lifecycle state, if it is recorded at all.
    ///
    /// Defaulted to [`PrincipalState::Active`] for any principal this store answers an
    /// organization for, so that a store which cannot see the identity domain's
    /// disablement events says what it knows rather than guessing. An implementation
    /// that can see them overrides this.
    fn state_of(&self, principal_id: &PrincipalId) -> Option<PrincipalState> {
        self.organization_of(principal_id)
            .map(|_| PrincipalState::Active)
    }
}

/// `mandate.identity.Principal.State`, as this crate reads it through
/// [`PrincipalStore`].
///
/// The states are the ones `systems/mandate/domains/identity.yaml` declares. The
/// transition between them is `mandate.identity`'s event, not this domain's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalState {
    /// The declared initial state.
    Active,
    /// The declared terminal state.
    Disabled,
}

/// An [`IdentityAllocator`] that mints distinct identities in order.
///
/// A fixture, never a shipped implementation: a real allocator does not mint from a
/// counter. It is `pub` and lives here because every file under `tests/` compiles as its
/// own crate; the move to `crates/mandate-testkit` is a later story the coordinator
/// files. Each kind of identity is minted from its own prefix, so a principal and an
/// external principal never share a wire form.
#[derive(Debug, Clone, Default)]
pub struct SequentialAllocator {
    connections: u8,
    principals: u8,
    external_principals: u8,
}

impl SequentialAllocator {
    /// A double that has minted nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

const fn minted(prefix: u8, ordinal: u8) -> Uuid {
    Uuid::from_bytes([
        prefix, ordinal, 0x28, 0xba, 0x2f, 0xa1, 0x4d, 0x8e, 0xb1, 0xb0, 0x8c, 0x1d, 0x4e, 0x5f,
        0x6a, 0x7b,
    ])
}

impl IdentityAllocator for SequentialAllocator {
    fn next_connection_id(&mut self) -> FederationConnectionId {
        self.connections += 1;
        FederationConnectionId::new(minted(0xc0, self.connections))
    }

    fn next_principal_id(&mut self) -> PrincipalId {
        self.principals += 1;
        PrincipalId::new(minted(0xa0, self.principals))
    }

    fn next_external_principal_id(&mut self) -> ExternalPrincipalId {
        self.external_principals += 1;
        ExternalPrincipalId::new(minted(0xe0, self.external_principals))
    }
}

/// A [`LinkStore`] over a folded projection paired with a [`PrincipalStore`] over a
/// recorded table.
///
/// A fixture, never a shipped implementation: the principals it answers for are the ones
/// a test recorded. `LinkExternalPrincipal` reads both ports, and a principal that exists
/// in `mandate.identity` and has no federation link yet — the ordinary case for an
/// administrative link — is exactly what [`record::Projection`] alone cannot answer.
#[derive(Debug, Clone, Default)]
pub struct RecordedPrincipals {
    links: Projection,
    organizations: Vec<(PrincipalId, OrganizationId, PrincipalState)>,
}

impl RecordedPrincipals {
    /// A store whose links are the ones this projection records.
    #[must_use]
    pub fn over(links: Projection) -> Self {
        Self {
            links,
            organizations: Vec::new(),
        }
    }

    /// Record a principal as belonging to an organization, in a lifecycle state.
    #[must_use]
    pub fn with_principal(
        mut self,
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        state: PrincipalState,
    ) -> Self {
        self.organizations
            .push((principal_id, organization_id, state));
        self
    }
}

impl ConnectionStore for RecordedPrincipals {
    fn connection(&self, id: &FederationConnectionId) -> Option<FederationConnection> {
        self.links.connection(id)
    }

    fn enabled_for_issuer(&self, issuer: &Issuer) -> Vec<FederationConnection> {
        self.links.enabled_for_issuer(issuer)
    }
}

impl LinkStore for RecordedPrincipals {
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal> {
        self.links.link(key)
    }
}

impl PrincipalStore for RecordedPrincipals {
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
        self.organizations
            .iter()
            .find(|(recorded, _, _)| recorded == principal_id)
            .map(|(_, organization_id, _)| *organization_id)
            .or_else(|| self.links.organization_of(principal_id))
    }

    fn state_of(&self, principal_id: &PrincipalId) -> Option<PrincipalState> {
        self.organizations
            .iter()
            .find(|(recorded, _, _)| recorded == principal_id)
            .map(|(_, _, state)| *state)
            .or_else(|| self.links.state_of(principal_id))
    }
}

/// A [`SessionIssuer`] that records what it was asked to issue.
///
/// A fixture, never a shipped implementation: it mints no session and validates nothing.
/// It exists so that a denial can be shown to have issued nothing.
#[derive(Debug, Clone, Default)]
pub struct RecordingSessionIssuer {
    issued: Vec<(PrincipalId, OrganizationId, FederationConnectionId)>,
}

impl RecordingSessionIssuer {
    /// A double that has issued nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every session this double was asked to issue, in order.
    #[must_use]
    pub fn issued(&self) -> &[(PrincipalId, OrganizationId, FederationConnectionId)] {
        &self.issued
    }
}

impl SessionIssuer for RecordingSessionIssuer {
    fn issue(
        &mut self,
        principal_id: PrincipalId,
        organization_id: OrganizationId,
        connection_id: FederationConnectionId,
    ) -> Result<IssuedSession, Denied> {
        self.issued
            .push((principal_id, organization_id, connection_id));
        let ordinal = u8::try_from(self.issued.len())
            .map_err(|_| Denied::new(DenialReason::Unavailable, DenialClause::ConnectionUnknown))?;
        Ok(IssuedSession {
            session_id: SessionId::new(minted(0x5e, ordinal)),
            credential_id: CredentialId::new(minted(0xcd, ordinal)),
        })
    }
}
