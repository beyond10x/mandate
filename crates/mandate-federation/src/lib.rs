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
pub mod disable;
pub mod link;
pub mod pkce;
pub mod publicclient;
pub mod record;
pub mod register_client;
pub mod verifier;
pub mod verifier_real;

// Every `mandate.federation` element this crate realizes, against the item that realizes
// it. Each entry is expanded into a `use` of the named symbol, so a registry line whose
// symbol was renamed, moved or deleted does not compile
// (`crates/mandate-types/src/macros.rs`).
//
// `crates/mandate-federation/tests/contract_agreement.rs` decides the other half: every
// name on the left is read back out of `generated/ir/system.json`, so a name this crate
// invented — or a domain element the contract renamed — is a failing case rather than a
// coverage report that overstates itself.
//
// What this crate does *not* realize is [`ESS_UNREALIZED`], named element by element with
// the reason: a registry that lists what is covered and waves at the rest overstates
// itself in the one direction that matters, and
// `crates/mandate-federation/tests/contract_agreement.rs` decides both directions against
// the contract's own index.
mandate_types::realizes! {
    "mandate.federation.RegisterFederationConnection" => crate::record::register_federation_connection,
    "mandate.federation.LinkExternalPrincipal" => crate::link::link_external_principal,
    "mandate.federation.AuthenticateFederation" => crate::authenticate::authenticate_federation,
    "mandate.federation.ProvisionExternalPrincipal" => crate::authenticate::provision_external_principal,
    "mandate.federation.AuthorizePublicClient" => crate::authorize::validate_authorization_code,
    "mandate.federation.DisableFederationConnection" => crate::disable::disable_federation_connection,
    "mandate.federation.UnlinkExternalPrincipal" => crate::disable::unlink_external_principal,
    "mandate.federation.DisableOAuthClient" => crate::disable::disable_oauth_client,
    "mandate.federation.RegisterOAuthClient" => crate::register_client::register_o_auth_client,
    "mandate.federation.FederationConnectionCreated" => crate::record::FederationEvent,
    "mandate.federation.FederationConnectionDisabled" => crate::record::FederationEvent,
    "mandate.federation.ExternalPrincipalLinked" => crate::record::FederationEvent,
    "mandate.federation.ExternalPrincipalUnlinked" => crate::record::FederationEvent,
    "mandate.federation.ExternalPrincipalProvisioned" => crate::record::FederationEvent,
    "mandate.federation.FederationAuthenticated" => crate::record::FederationEvent,
    "mandate.federation.OAuthClientRegistered" => crate::record::FederationEvent,
    "mandate.federation.OAuthClientDisabled" => crate::record::FederationEvent,
    "mandate.federation.FederationConnection" => crate::record::FederationConnection,
    "mandate.federation.ExternalPrincipal" => crate::record::ExternalPrincipal,
    "mandate.federation.OAuthClient" => crate::record::OAuthClient,
    "mandate.federation.Denied" => crate::Denied,
    "mandate.federation.FederationConnection.State" => crate::record::ConnectionState,
    "mandate.federation.ExternalPrincipal.State" => crate::record::LinkState,
    "mandate.federation.OAuthClient.State" => crate::record::OAuthClientState,
    // This registry names elements of `mandate.federation` and of no other domain.
    //
    // Two lifecycle enums of other domains' records live in this crate, and **neither** is
    // realized here: one declared element has one realizer, and for both of these it is the
    // crate that folds the record.
    //
    // * [`PrincipalState`] — `mandate.identity.Principal.State`. Realized by
    //   `mandate_identity::PrincipalState`, beside the `mandate.identity.Principal` record
    //   that crate's own fold materializes, since the realization round of
    //   `story:declared-writers`.
    // * [`authorize::AuthorizationCodeState`] — `mandate.credential.AuthorizationCode.State`.
    //   Realized by `mandate_sts::store::AuthorizationCodeState`, beside the
    //   `mandate.credential.AuthorizationCode` record `services/sts/src/store.rs` folds,
    //   since `story:oauth-transaction`. "STS alone owns authorization-code verifier storage
    //   and consumption" (`credential.yaml`), and what this crate holds is the **port view**
    //   of that record: `authorize::AuthorizationCode` is a caller-supplied read-only input
    //   that `AuthorizePublicClient` validates non-consumingly, and it deliberately mirrors
    //   neither the declared `verifier` nor the store behind it.
    //
    // Both enums are still decided against their generated shapes, in
    // `crates/mandate-federation/tests/contract_agreement.rs`: an unrealized type that
    // disagrees with the contract is still a type that disagrees with the contract.
}

/// Every declared `mandate.federation` element this crate does **not** realize, with the
/// reason.
///
/// A coverage registry that names what it covers and says nothing about the rest is read
/// as a claim about the whole domain. This is the other half of [`ESS_REALIZATIONS`], and
/// `crates/mandate-federation/tests/contract_agreement.rs` decides the pair against
/// `generated/ir/system.json` in both directions: an element this list names and the
/// registry also realizes is a contradiction, and an element neither one names is an
/// element nobody accounted for. `mandate-identity` carries the same pair for its domain.
///
/// There is one, and it is not an oversight. `mandate.federation.AuthorizePublicClient` is
/// realized here up to the STS call its accepted outcome makes;
/// [`authorize::validate_authorization_code`] is non-consuming and returns a validation
/// candidate carrying no event. The event that outcome declares is **not**
/// `mandate.credential.AuthorizationCodeIssued`, which `mandate_sts::code` emits since
/// `story:oauth-transaction`; it is this domain's own event, which the adapter that carries
/// the validation candidate into the STS call emits. A variant for it on
/// [`record::FederationEvent`] would be a payload nothing in this crate can fill.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[(
    "mandate.federation.AuthorizationCodeIssued",
    "emitted by the adapter that carries this crate's validation candidate into the STS \
     call, not by this crate; owner story:oauth-integration",
)];

use core::fmt;

use mandate_types::{
    Audience, CorrelationId, CredentialId, CredentialProof, DenialReason, EpochSnapshotRef,
    ExternalPrincipalId, FederationConnectionId, Issuer, OAuthClientId, OrganizationId,
    PrincipalId, SessionId, Timestamp, value::Uuid,
};

use record::{ExternalKey, ExternalPrincipal, FederationConnection, LinkState, Projection};
use verifier::VerifiedProof;

/// Which declared refusing outcome a [`Denied`] is.
///
/// A command that moves an entity along its lifecycle declares **two** error outcomes,
/// not one: the external `denied` and the `wrong-state` taken "when the subject is in a
/// state none of that command's declared moves start from", which "reports the same
/// `Denied` error and renders as HTTP 409 in the OpenAPI projection rather than the 502
/// an external denial renders as" (`docs/architecture/command-obligations.md`).
///
/// The distinction cannot live in [`DenialReason`]: that enum is the contract's, it is
/// closed, and it declares no wrong-state reason. It cannot live in [`DenialClause`]
/// either — a clause names *which condition* fired, and several conditions map to each
/// outcome. So it is its own value, and [`RefusedOutcome::ir_name`] is the name the
/// outcome carries in `generated/ir/system.json`, which is what
/// `crates/mandate-federation/tests/emitted_events.rs` looks the refusal up by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusedOutcome {
    /// The declared `denied` outcome: an externally caused refusal.
    Denied,
    /// The declared `wrong-state` outcome: the named record is in a state none of the
    /// command's declared moves start from.
    WrongState,
}

impl RefusedOutcome {
    /// The name this outcome carries in the compiled contract.
    #[must_use]
    pub const fn ir_name(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::WrongState => "wrong-state",
        }
    }
}

/// `mandate.federation.Denied`: fail closed; no credential, authority or lifecycle
/// mutation on refusal (`federation.yaml:388-393`).
///
/// The contract's error payload is [`DenialReason`] alone. [`Denied::clause`] is a
/// crate-local discriminator that names *which* declared denial condition fired; it is
/// not a contract field and no wire form carries it. It exists because two conditions
/// the adapter sequence must tell apart — an absent link and a conflicting one — both
/// surface as `DenialReason::Denied`, which `story:federation-linking` records as a
/// contract change for `story:domain-runtime` to weigh.
///
/// [`Denied::outcome`] is the declared outcome the refusal *is*, which the caller needs
/// to render the refusal the contract's way; see [`RefusedOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The declared `mandate.core.DenialReason`.
    pub reason: DenialReason,
    /// Which declared denial condition fired. Crate-local; see the type documentation.
    pub clause: DenialClause,
    /// Which declared refusing outcome this is.
    pub outcome: RefusedOutcome,
}

impl Denied {
    /// Refuse through the declared `denied` outcome, naming the reason and the condition
    /// that fired.
    #[must_use]
    pub const fn new(reason: DenialReason, clause: DenialClause) -> Self {
        Self {
            reason,
            clause,
            outcome: RefusedOutcome::Denied,
        }
    }

    /// Refuse through the declared `wrong-state` outcome: the named record is in a state
    /// none of the command's declared moves start from.
    #[must_use]
    pub const fn wrong_state(reason: DenialReason, clause: DenialClause) -> Self {
        Self {
            reason,
            clause,
            outcome: RefusedOutcome::WrongState,
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {:?} ({:?})",
            self.outcome.ir_name(),
            self.reason,
            self.clause
        )
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
    /// `RegisterOAuthClient`: "Caller lacks client-administration authority". An
    /// authorization decision, admitted through
    /// [`register_client::ClientRegistrationAdmission`].
    ClientAdministrationAuthority,
    /// `RegisterOAuthClient`: "a redirect URI is unadmitted". A deployment's redirect
    /// policy, admitted through the same port; compare [`DenialClause::RedirectMismatch`],
    /// which is the *presented* redirect failing the registered set at authorization.
    RedirectUriUnadmitted,
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
/// `federation.yaml` no longer declares a `context` on `FederationAuthenticated` or
/// `ExternalPrincipalProvisioned`. Both are reached without a verified caller — an
/// authentication is what *establishes* a context, and `ProvisionExternalPrincipal` mints
/// no session and no credential ("No session is minted here; the adapter calls
/// AuthenticateFederation again") — so a `mandate.core.VerifiedContext`, whose `credential`
/// is required, had no source on either. The contract declares the fields the records
/// actually need instead: `session_id`, `principal_id`, `audience`, `correlation` and
/// `connection_id` on the authentication, and `organization_id` plus `correlation` on the
/// provisioning. Of those, the audience and the correlation are the adapter's; the rest
/// are resolved from the proof, the connection or the issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// The audience the control plane establishes the context for.
    ///
    /// Carried onto `mandate.federation.FederationAuthenticated`.
    pub audience: Audience,
    /// The correlation carried through the request.
    ///
    /// Carried onto both context-free events.
    pub correlation: CorrelationId,
    /// The credential the trusted federation endpoint was reached with.
    ///
    /// No event of this domain carries it: the two that once demanded one through a
    /// `VerifiedContext` no longer declare a context at all, and the credential an
    /// authentication mints is [`SessionIssuer`]'s, named by `mandate.identity` against
    /// the `session_id` the authentication declares. It is kept because the adapter that
    /// reached the endpoint holds it and the audit path is `mandate.audit`'s, not this
    /// crate's to drop on its behalf.
    pub credential: CredentialId,
    /// The moment the request is being served. A clock is an adapter concern.
    ///
    /// Carried onto both link events as `linked_at`.
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
///
/// The epoch snapshot handle and the expiry are the issuer's and are carried back because
/// `AuthenticateFederation` responds with them and `mandate.federation.FederationAuthenticated`
/// declares them (`federation.yaml`). The identity fold materializes the whole Session from
/// that payload, so a value the issuer minted and did not return would be a Session field
/// no replay could recover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedSession {
    /// The session `AuthenticateFederation` responds with.
    pub session_id: SessionId,
    /// The credential identifier the generated `VerifiedContext` names.
    pub credential_id: CredentialId,
    /// The epoch snapshot handle the session is bound to.
    ///
    /// `decision-blocker:epoch`: an `EpochSnapshotRef` is an immutable record handle and
    /// never a generation. The snapshot's own contents are recorded by the adapter through
    /// `mandate.identity.EpochSnapshotRecorded`.
    pub epochs: EpochSnapshotRef,
    /// When the session stops being refreshable.
    pub expires_at: Timestamp,
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
    /// The identity `RegisterOAuthClient` responds with.
    fn next_o_auth_client_id(&mut self) -> OAuthClientId;
}

/// The connection read model. A fold over the event log; see
/// [`record::Projection`].
pub trait ConnectionStore {
    /// The connection with this identity, whatever its lifecycle state.
    fn connection(&self, id: &FederationConnectionId) -> Option<FederationConnection>;
    /// The connections configured for this issuer. An implementation may answer them in
    /// any lifecycle state.
    ///
    /// Tenant resolution runs over this set rather than over the selected connection
    /// alone: a single connection carries one `TenantResolutionRule` and so could only
    /// ever yield zero or one match, while `federation.yaml:210` declares a denial for
    /// "zero or multiple matches".
    ///
    /// **The filter is the command's, not the implementor's.** A command reads
    /// [`record::FederationConnection::state`] and `issuer` itself on what it is handed,
    /// through this crate's own `enabled_on_issuer`, so a store that answers a `Disabled`
    /// connection, or one on another issuer, changes no decision: which connections take
    /// part in a tenant resolution is part of the admission rule, and a port cannot make
    /// that a property of the command. [`record::Projection`] answers `Enabled` connections only, which is one
    /// admissible answer.
    fn enabled_for_issuer(&self, issuer: &Issuer) -> Vec<FederationConnection>;
}

/// The external-principal read model, keyed by the record's own identity.
///
/// Separate from [`LinkStore`] rather than a method on it: the question [`LinkStore`]
/// answers is "what holds this composite key", which is what every proof-driven command
/// asks, and the question here is "what is this record", which is what a lifecycle
/// command asks. An implementation of one is not an implementation of the other — a store
/// indexed by key cannot answer by identity — and folding them into one trait would ask
/// every existing implementor to answer a read it has no index for.
pub trait ExternalPrincipalStore {
    /// The external principal with this identity, whatever its lifecycle state.
    ///
    /// An implementation may return a row in any state. The command reads
    /// [`record::ExternalPrincipal::state`] itself rather than relying on an
    /// implementation to filter, because a port cannot make that a property of the
    /// command.
    fn external_principal(&self, id: &ExternalPrincipalId) -> Option<ExternalPrincipal>;
}

/// The external-principal read model, keyed by the canonical composite key.
///
/// **An implementor answers one question, and this crate derives every answer a command
/// needs from it.** The three commands that read this port ask three different things of
/// one key — is it held at all, which record holds it, is that record explicitly linked —
/// and each of those is a decision the commands must own. A port with one method per
/// question is a port whose implementations can disagree with each other, and a command
/// whose correctness is then a property of the implementation it happened to be handed
/// rather than of the port. So [`LinkStore::records_on_key`] is the only method this trait
/// has, and every decision a command makes about a key is taken in [`LinkResolution`].
///
/// [`LinkResolution`] is a separate trait with a blanket implementation over every
/// `LinkStore`, and that is the whole of what makes the sentence above true rather than
/// merely intended: a defaulted method on *this* trait would be one an implementor is free
/// to write — this crate's own [`PrincipalStore::state_of`] is defaulted and overridden
/// twice — so the derivation would be a suggestion. A blanket implementation is not
/// overridable: writing `impl LinkResolution for MyStore` collides with it and does not
/// compile.
pub trait LinkStore {
    /// Every record on this exact key, in every lifecycle state, in any order.
    ///
    /// **Every record**: the terminal `Unlinked` state of
    /// `mandate.federation.UnlinkExternalPrincipal` empties a key, it does not erase it,
    /// and an implementation that omits a revoked record here reports a revoked key as
    /// free. `LinkAbsent` names two conditions — never linked, and revoked — and a
    /// composition that admits just-in-time provisioning on that clause would then answer
    /// this domain's one federated revocation by minting a **new** `PrincipalId` for the
    /// same external subject. That is why the read is here and not in one implementation
    /// of it: [`authenticate::provision_external_principal`] refuses `ExternalKeyExists`
    /// for a key this answers anything at all for, so every implementor has to say what
    /// the key holds and none of them can leave a revoked record out of the answer by
    /// saying nothing.
    ///
    /// An empty vector is the only way to say the key is free.
    fn records_on_key(&self, key: &ExternalKey) -> Vec<ExternalPrincipal>;
}

/// What a command decides about a key, derived from [`LinkStore::records_on_key`].
///
/// **No implementation of this trait can exist but the one below.** It is implemented once,
/// blanket, for every [`LinkStore`], so a store cannot supply its own answer to either
/// question: `impl LinkResolution for MyStore` is a conflicting implementation and is
/// refused by the compiler. That is the difference between a derivation and a default, and
/// it is the reason this is a trait of its own rather than two more methods on
/// [`LinkStore`] — a defaulted method is one an implementor may write, and an implementor
/// that writes this one decides a command's outcome.
pub trait LinkResolution {
    /// The record that holds this key: the smallest `external_principal_id` among the
    /// `Linked` records on it, and — when no record on the key is `Linked` — the smallest
    /// among the records that remain.
    ///
    /// [`authenticate::authenticate_federation`] and [`link::link_external_principal`]
    /// depend on it: both ask whether the key resolves to an **explicitly linked**
    /// principal, and both read [`record::ExternalPrincipal::state`] on what they are
    /// handed. An implementation free to answer the smallest `Unlinked` record while the
    /// key still has a `Linked` one would deny `LinkAbsent` to a validly linked caller and
    /// stop `LinkConflict` firing over a key that is taken — which is the same class of
    /// defect as hiding the revoked record, one command further along.
    ///
    /// `ExternalPrincipalId` orders on the sixteen bytes of its UUID, which is the order
    /// of its canonical lexical form, so "smallest" is a property of the identity the
    /// event carried and of nothing else. An unlink of the holder promotes the next
    /// smallest `Linked` record; see [`record::Projection`].
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal>;

    /// Whether any record holds this key, in any lifecycle state — which is the question
    /// [`authenticate::provision_external_principal`] asks, and the negation of "free to
    /// create a record on".
    fn key_is_held(&self, key: &ExternalKey) -> bool;
}

impl<T: LinkStore + ?Sized> LinkResolution for T {
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal> {
        let records = on_key(self, key);
        records
            .iter()
            .filter(|record| record.state == LinkState::Linked)
            .min_by_key(|record| record.id)
            .or_else(|| records.iter().min_by_key(|record| record.id))
            .cloned()
    }

    fn key_is_held(&self, key: &ExternalKey) -> bool {
        !on_key(self, key).is_empty()
    }
}

/// The records a store answered that are on the key it was asked about.
///
/// [`LinkStore::records_on_key`] promises "every record on this **exact** key", and a
/// promise a derivation rests on is one the derivation checks where it can. Two of the
/// key's three components are carried on the record — the organization the fold reads off
/// the connection, and the subject — so a record naming another organization or another
/// subject is not on this key whatever a store answered, and is dropped here rather than
/// resolved into a session for its principal. The third component, the issuer, is the
/// connection's and is not carried on an [`ExternalPrincipal`]; it cannot be checked from
/// the value alone and is not.
///
/// This narrows, never widens: a store that answers only records on the key it was asked
/// about — every implementation in this repository, [`record::Projection`] included, which
/// filters on its own [`record::Projection::key_of`] — is unaffected.
fn on_key<T: LinkStore + ?Sized>(store: &T, key: &ExternalKey) -> Vec<ExternalPrincipal> {
    store
        .records_on_key(key)
        .into_iter()
        .filter(|record| {
            record.organization_id == key.organization_id && record.subject == key.subject
        })
        .collect()
}

/// The connections a command resolves a tenant over: those a store answered for this
/// issuer that are `Enabled` and configured for this exact issuer.
///
/// A free function private to this crate rather than a method on [`ConnectionStore`],
/// for the reason [`LinkResolution`] is blanket: a defaulted method is one an implementor
/// may write, and an implementor that writes this one decides a command's outcome.
///
/// The enumeration contributes **identities**, and a record only where the store cannot
/// answer one by identity (below). Each identity is read once, through
/// [`ConnectionStore::connection`] — the one answer the selected connection is also
/// decided on in step 1 — and its state and issuer are taken from that answer, so a stale
/// or duplicated copy in the enumeration decides nothing: an identity the store answers
/// `Disabled` by identity takes no part however the enumeration presents it, and an
/// identity answered twice counts once.
///
/// **An identity the store lists but cannot answer by identity fails closed.** It is
/// read as the enumeration listed it, state and issuer included, rather than dropped:
/// every candidate here can only add a match, so dropping one can only turn a refusal
/// (`TenantAmbiguous`, `TenantResolutionUnadmitted`) into an admission, and a read the
/// store cannot complete is not evidence that the connection is absent.
///
/// This narrows, never widens: a store that answers only `Enabled` connections on the
/// issuer it was asked about, once each and as it answers them by identity —
/// [`record::Projection`] included — is unaffected.
fn enabled_on_issuer<T: ConnectionStore + ?Sized>(
    store: &T,
    issuer: &Issuer,
) -> Vec<FederationConnection> {
    let mut listed: Vec<FederationConnection> = Vec::new();
    for answered in store.enabled_for_issuer(issuer) {
        if !listed.iter().any(|held| held.id == answered.id) {
            listed.push(answered);
        }
    }
    listed
        .into_iter()
        .map(|as_listed| store.connection(&as_listed.id).unwrap_or(as_listed))
        .filter(|connection| {
            connection.state == record::ConnectionState::Enabled && connection.issuer == *issuer
        })
        .collect()
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

/// `mandate.identity.Principal.State`, as this crate reads it through [`PrincipalStore`].
///
/// The states are the ones `systems/mandate/domains/identity.yaml` declares. The
/// transition between them is `mandate.identity`'s event, not this domain's.
///
/// **The port's view of another domain's lifecycle, not a realization of that element.**
/// One declared element has one realizer, and `mandate.identity.Principal.State`'s is
/// `mandate_identity::PrincipalState`, which sits beside the record that crate's own fold
/// materializes. This type exists because [`PrincipalStore`] must be answerable by an
/// adapter that composes both domains' read models, and a port cannot make a lifecycle
/// check a property of the command that reads it. It is absent from [`ESS_REALIZATIONS`]
/// for that reason and is still decided against the generated shape in
/// `crates/mandate-federation/tests/contract_agreement.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
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
    o_auth_clients: u8,
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

    fn next_o_auth_client_id(&mut self) -> OAuthClientId {
        self.o_auth_clients += 1;
        OAuthClientId::new(minted(0x0c, self.o_auth_clients))
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
    fn records_on_key(&self, key: &ExternalKey) -> Vec<ExternalPrincipal> {
        self.links.records_on_key(key)
    }
}

impl ExternalPrincipalStore for RecordedPrincipals {
    fn external_principal(&self, id: &ExternalPrincipalId) -> Option<ExternalPrincipal> {
        self.links.external_principal(id)
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
            epochs: EpochSnapshotRef::new(minted(0x3e, ordinal)),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        })
    }
}
