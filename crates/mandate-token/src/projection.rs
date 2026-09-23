//! The `mandate.credential` projections and the fold that materializes them.
//!
//! # Why the records are here and not in `mandate-model`
//!
//! `ResourceServer.credential_profile` is [`crate::CredentialProfile`] and
//! `AccessCredential.descriptor` is [`crate::CredentialDescriptor`], both declared in this
//! crate; a projection that named them from `mandate-model` would invert the dependency
//! direction `dependency-boundaries.json` fixes. `SigningKey` follows by cohesion — it is
//! the third record of one domain and one fold. `docs/architecture/ownership.md:15` assigns
//! "registry/credential/code records" to `mandate-model`, which cannot compile; under
//! `docs/adr/0009-event-sourced-persistence.md` a state record is a projection of the
//! folding crate in any case.
//!
//! `mandate.credential.AuthorizationCode` is **not** projected here: `services/sts` owns
//! the code record and its verifier storage (`credential.yaml:4`) and folds it in
//! `services/sts/src/store.rs`.
//!
//! `mandate.credential.AuthorizationCodeRedeemed` is folded here all the same, because it
//! writes two records. `credential.yaml`'s header declares that the event "also seeds a
//! `mandate.credential.AccessCredential`" — the redemption's one outcome subject is the code
//! it consumes, and an ESS outcome declares one `creates`/`moves`/`updates` — and that it
//! "carries the whole AccessCredential record ... so a fold materializes the credential from
//! the event and the issuing registration the log already holds, reading no command input or
//! response". The code half of that event is `services/sts`'s; this is the credential half.
//!
//! # Decide, apply, fold
//!
//! [`Projection::apply`] is the **write** half: it writes what it is handed and re-checks
//! no guard. Every guard belongs to a handler in `services/sts`, which reads this
//! projection before the event exists and returns [`Denied`] instead of the event. A fold
//! that re-decided a guard would not be a rebuild of an accepted history.
//!
//! What the fold does refuse is a log it cannot *read*, which is a statement about the log
//! and not about the command that wrote it: an event naming an instance no event created,
//! because a dropped event is a lost record.
//!
//! It refuses nothing else. In particular the two uniqueness guards of
//! `mandate.credential.SigningKey` — one `key_reference`, one `thumbprint` — are **views**
//! and not fold refusals, for the reason the audience index is one: `Projection::fold` is
//! all-or-nothing, so refusing a log for a duplicated key reference would make every
//! `ResourceServer` and every `AccessCredential` that log carries unreadable, and under
//! `docs/adr/0009-event-sourced-persistence.md` there is nowhere else to read them from.
//! See [`Projection::signing_key_conflicts`].
//!
//! # A uniqueness index is a projection view, not a fold refusal
//!
//! `decision-blocker:identity-uniqueness` places the unique index on the projection
//! (`docs/adr/0009-event-sourced-persistence.md`). Two writers that each read a free
//! `(organization_id, audience)` append to two `ResourceServer` aggregates, so the kit's
//! compare-and-set on the appending stream does not see the other: the log is the record of
//! both registrations. Which record *holds* the key is a total order over the records
//! themselves — the smallest [`ResourceServerId`] among the `Enabled` ones
//! ([`Projection::registered`]) — so a rebuild that interleaves the two streams differently
//! resolves the key the same way, and the rest are [`Projection::audience_conflicts`]. The
//! write path refuses through [`Projection::admits_audience`], which returns the declared
//! `mandate.credential.Denied`.
//!
//! `mandate.credential.SigningKey`'s two indexes are resolved the same way
//! ([`Projection::key_reference_holder`], [`Projection::thumbprint_holder`]) and reported the
//! same way ([`Projection::signing_key_conflicts`]). The difference is what an index means
//! there: a key that does not hold one is admitted for neither issuance nor verification, so
//! material a deployment revoked cannot come back under a second identity even though the
//! second record exists.

use core::fmt;

use serde::Serialize;

use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CredentialId, CredentialVerifier, DenialReason,
    EpochSnapshotRef, KeyReference, OrganizationId, PersistedValue, ResourceServerId,
    SigningAlgorithm, SigningKeyId, Timestamp, VerifiedContext,
};

use crate::{CredentialDescriptor, CredentialProfile};

/// `mandate.credential.ResourceServer.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ResourceServerState {
    /// The declared initial state.
    Enabled,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.credential.AccessCredential.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AccessCredentialState {
    /// The declared initial state.
    Active,
    /// The declared terminal state.
    Revoked,
}

/// `mandate.credential.SigningKey.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SigningKeyState {
    /// The declared initial state.
    Recorded,
    /// The declared terminal state a rotation reaches.
    Retired,
    /// The declared terminal state the emergency path reaches.
    Revoked,
}

/// `mandate.credential.ResourceServer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceServer {
    /// The registration identity.
    pub id: ResourceServerId,
    /// The organization the registration is bound to.
    pub organization_id: OrganizationId,
    /// The audience credentials for this server name.
    pub audience: Audience,
    /// The profile the server's credentials are issued under.
    pub credential_profile: CredentialProfile,
    /// The servers whose credentials may be exchanged for this one's.
    pub allowed_exchange_sources: Vec<ResourceServerId>,
    /// The lifecycle state.
    pub state: ResourceServerState,
}

/// `mandate.credential.AccessCredential`.
///
/// `reference_verifier` is the non-reversible verifier and never the material: the raw
/// secret is returned once, at issuance, and no record here can carry it —
/// `mandate.core.CredentialSecret` is not a [`PersistedValue`], which the check at the foot
/// of this module makes the compiler's business.
///
/// # Two fields the declared record does not have
///
/// [`AccessCredential::target`] and [`AccessCredential::issuing_profile`] carry
/// `#[serde(skip)]` and are **not** part of `mandate.credential.AccessCredential`:
/// `credential.yaml` declares that entity as `descriptor`, `reference_verifier`, `epochs`
/// and `issued_at`, and the registration a credential was issued under is nowhere on it.
/// Both issuance events do carry the `target` (`CredentialReferenceIssued`,
/// `CredentialSelfContainedIssued`), so a fold can materialize both — and it must, because
/// **a credential's revocation guarantee is the one its issuing registration published, not
/// the one whatever registration holds that audience today publishes**. An audience changes
/// hands (`crate::projection::Projection::registered` releases it on disablement), and a
/// credential issued under `ImmediateOnline` does not become a `BoundedOffline` credential
/// when it does.
///
/// The residue is stated rather than hidden: the declared subset round-trips through the
/// generated entity shape and these two do not appear in it, which
/// `crates/mandate-token/tests/contract_agreement.rs` pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessCredential {
    /// The credential identity.
    pub id: CredentialId,
    /// What the credential asserts.
    pub descriptor: CredentialDescriptor,
    /// The non-reversible verifier a presented proof is resolved against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_verifier: Option<CredentialVerifier>,
    /// The epoch snapshot the credential is bound to, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epochs: Option<EpochSnapshotRef>,
    /// When the credential was issued.
    pub issued_at: Timestamp,
    /// The lifecycle state.
    pub state: AccessCredentialState,
    /// The registration this credential was issued for. Not a declared field; see the type
    /// documentation.
    #[serde(skip)]
    pub target: ResourceServerId,
    /// The profile that registration published when this credential was issued. Not a
    /// declared field; see the type documentation.
    #[serde(skip)]
    pub issuing_profile: CredentialProfile,
}

/// `mandate.credential.SigningKey`.
///
/// No key material is here. `key_reference` is the handle the deployment resolves and
/// `thumbprint` is the RFC 7638 JWK thumbprint of the public key that reference resolved
/// to, "so a revocation record naming a kid and a thumbprint is rebuilt from this log
/// without resolving the material of a key that was revoked as compromised"
/// (`credential.yaml`, `RegisterSigningKey`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningKey {
    /// The key identity, which is the `kid` a credential names.
    pub id: SigningKeyId,
    /// The handle the deployment resolves to the material.
    pub key_reference: KeyReference,
    /// The thumbprint of the public key the reference resolved to.
    pub thumbprint: String,
    /// The declared algorithm name.
    pub algorithm: SigningAlgorithm,
    /// When the key starts being usable.
    pub not_before: Timestamp,
    /// When the key stops being usable.
    pub expires_at: Timestamp,
    /// The lifecycle state.
    pub state: SigningKeyState,
}

/// An event of `mandate.credential`, in the form this crate folds.
///
/// Each variant is one compiled payload under `generated/schema/events`, field for field.
/// `#[serde(untagged)]` is what makes that true on the wire — a variant serializes as the
/// bare payload object, with no discriminant wrapping it — and
/// `crates/mandate-token/tests/contract_agreement.rs` decides it against the generated shape
/// of the element [`CredentialEvent::ess_name`] answers.
///
/// **`Serialize` only, deliberately: this enum does not round-trip and no code should
/// assume it does.** Under `#[serde(untagged)]` a reader cannot tell
/// `ResourceServerDisabled`, `AccessCredentialRevoked`, `SigningKeyRetired` and
/// `SigningKeyRevoked` apart — all four serialize exactly `{context, id}` with a uuid
/// string for the `id`. Reading an event back needs a tagged envelope carrying the ESS name
/// beside the payload, which belongs to the persistence story.
///
/// One declared event of this domain has no variant here, and it is not an oversight:
/// `AuthorizationCodeIssued` writes the code record alone and is folded where that record
/// lives (`services/sts/src/store.rs`).
///
/// [`CredentialEvent::AuthorizationCodeRedeemed`] is the one payload of this domain **two**
/// folds read, because it writes two records; see the module documentation.
/// `services/sts/src/store.rs` declares the same payload for the code half and
/// `services/sts/tests/store.rs` decides that the two encode identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CredentialEvent {
    /// `mandate.credential.ResourceServerRegistered`.
    ResourceServerRegistered {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the command's response identity.
        id: ResourceServerId,
        /// The declared `audience`.
        audience: Audience,
        /// The declared `credential_profile`.
        credential_profile: CredentialProfile,
        /// The declared `allowed_exchange_sources`.
        allowed_exchange_sources: Vec<ResourceServerId>,
    },
    /// `mandate.credential.ResourceServerDisabled`.
    ResourceServerDisabled {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the instance the declared `moves` names.
        id: ResourceServerId,
    },
    /// `mandate.credential.CredentialReferenceIssued`.
    CredentialReferenceIssued {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `credential_id`: the command's response identity.
        credential_id: CredentialId,
        /// The declared `reference_verifier`: non-reversible, never the secret.
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_verifier: Option<CredentialVerifier>,
        /// The declared `epochs`.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<EpochSnapshotRef>,
        /// The declared `issued_at`.
        issued_at: Timestamp,
        /// The declared `descriptor`.
        descriptor: CredentialDescriptor,
        /// The declared `target`.
        target: ResourceServerId,
        /// The declared `requested_scope`.
        requested_scope: AuthorityScope,
    },
    /// `mandate.credential.CredentialSelfContainedIssued`.
    CredentialSelfContainedIssued {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `credential_id`: the command's response identity.
        credential_id: CredentialId,
        /// The declared `reference_verifier`: non-reversible, never the token.
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_verifier: Option<CredentialVerifier>,
        /// The declared `epochs`.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<EpochSnapshotRef>,
        /// The declared `issued_at`.
        issued_at: Timestamp,
        /// The declared `descriptor`.
        descriptor: CredentialDescriptor,
        /// The declared `target`.
        target: ResourceServerId,
        /// The declared `requested_scope`.
        requested_scope: AuthorityScope,
    },
    /// `mandate.credential.AccessCredentialRevoked`.
    AccessCredentialRevoked {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the instance the declared `moves` names.
        id: CredentialId,
    },
    /// `mandate.credential.CredentialIntrospected`.
    ///
    /// The one event of this domain that "creates, moves and updates nothing" and "folds
    /// into no record" (`credential.yaml`, `IntrospectCredential`). Its `credential_id`
    /// names an instance only when one exists in this log, and [`Projection::apply`] does
    /// not take the name for the existence of a record: the presented credential may have
    /// been issued by a deployment this log never saw.
    CredentialIntrospected {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `descriptor`, carried by an active answer alone.
        #[serde(skip_serializing_if = "Option::is_none")]
        descriptor: Option<CredentialDescriptor>,
        /// The declared `active`.
        active: bool,
        /// The declared `credential_id`, carried by an active answer alone.
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_id: Option<CredentialId>,
    },
    /// `mandate.credential.SigningKeyRegistered`.
    SigningKeyRegistered {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the command's response identity, and the `kid`.
        id: SigningKeyId,
        /// The declared `key_reference`.
        key_reference: KeyReference,
        /// The declared `thumbprint`: the command's response value.
        thumbprint: String,
        /// The declared `algorithm`.
        algorithm: SigningAlgorithm,
        /// The declared `not_before`.
        not_before: Timestamp,
        /// The declared `expires_at`.
        expires_at: Timestamp,
    },
    /// `mandate.credential.SigningKeyRetired`.
    SigningKeyRetired {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the instance the declared `moves` names.
        id: SigningKeyId,
    },
    /// `mandate.credential.SigningKeyRevoked`.
    SigningKeyRevoked {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the instance the declared `moves` names.
        id: SigningKeyId,
    },
    /// `mandate.credential.AuthorizationCodeRedeemed`.
    ///
    /// The credential half. The declared `moves` of the outcome that emits it names the
    /// authorization code, which `services/sts` folds; the record *this* fold materializes
    /// is the `AccessCredential` the domain header declares the event seeds.
    AuthorizationCodeRedeemed {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `code_id`: the code the emitting outcome consumes. Not a name this
        /// fold resolves — the code record lives in `services/sts` — and carried because the
        /// payload is one declaration read by two folds.
        code_id: AuthorizationCodeId,
        /// The declared `credential_id`: the command's response identity.
        credential_id: CredentialId,
        /// The declared `reference_verifier`: non-reversible, never the credential.
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_verifier: Option<CredentialVerifier>,
        /// The declared `epochs`.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<EpochSnapshotRef>,
        /// The declared `issued_at`.
        issued_at: Timestamp,
        /// The declared `descriptor`.
        descriptor: CredentialDescriptor,
        /// The declared `target`: the registration whose published guarantee the credential
        /// carries.
        target: ResourceServerId,
    },
    /// `mandate.credential.TokenExchangeAllowed`.
    ///
    /// The fourth creator of an `AccessCredential`, carrying the same record fields the two
    /// issuance events carry: `ExchangeCredential`'s accepted outcome `creates` the credential
    /// it issues for the exchange target (`credential.yaml`).
    TokenExchangeAllowed {
        /// The declared `context`: the one the subject credential validated to.
        context: VerifiedContext,
        /// The declared `credential_id`: the command's response identity.
        credential_id: CredentialId,
        /// The declared `reference_verifier`: non-reversible, never the credential.
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_verifier: Option<CredentialVerifier>,
        /// The declared `epochs`.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<EpochSnapshotRef>,
        /// The declared `issued_at`.
        issued_at: Timestamp,
        /// The declared `descriptor`.
        descriptor: CredentialDescriptor,
        /// The declared `target`: the registration the credential is issued for.
        target: ResourceServerId,
        /// The declared `requested_scope`.
        requested_scope: AuthorityScope,
    },
    /// `mandate.credential.TokenExchangeDenied`.
    ///
    /// Folds into no record, like [`CredentialEvent::CredentialIntrospected`]: a refused
    /// exchange creates, moves and updates nothing, and this is the record that it was
    /// refused. `context` is absent when the subject proof resolved to nothing, because no
    /// context was validated to carry.
    TokenExchangeDenied {
        /// The declared `context`, when the subject proof resolved to one.
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<VerifiedContext>,
        /// The declared `requested_target`.
        requested_target: ResourceServerId,
        /// The declared `requested_scope`.
        requested_scope: AuthorityScope,
    },
}

impl CredentialEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub const fn ess_name(&self) -> &'static str {
        match self {
            Self::ResourceServerRegistered { .. } => "mandate.credential.ResourceServerRegistered",
            Self::ResourceServerDisabled { .. } => "mandate.credential.ResourceServerDisabled",
            Self::CredentialReferenceIssued { .. } => {
                "mandate.credential.CredentialReferenceIssued"
            }
            Self::CredentialSelfContainedIssued { .. } => {
                "mandate.credential.CredentialSelfContainedIssued"
            }
            Self::AccessCredentialRevoked { .. } => "mandate.credential.AccessCredentialRevoked",
            Self::CredentialIntrospected { .. } => "mandate.credential.CredentialIntrospected",
            Self::SigningKeyRegistered { .. } => "mandate.credential.SigningKeyRegistered",
            Self::SigningKeyRetired { .. } => "mandate.credential.SigningKeyRetired",
            Self::SigningKeyRevoked { .. } => "mandate.credential.SigningKeyRevoked",
            Self::AuthorizationCodeRedeemed { .. } => {
                "mandate.credential.AuthorizationCodeRedeemed"
            }
            Self::TokenExchangeAllowed { .. } => "mandate.credential.TokenExchangeAllowed",
            Self::TokenExchangeDenied { .. } => "mandate.credential.TokenExchangeDenied",
        }
    }
}

/// A recorded registration that does not hold its `(organization_id, audience)` key,
/// because another `Enabled` registration on that key holds it.
///
/// **A view over the records, not a place records are kept.** Recomputed on each call from
/// the records and their lifecycle states, so a disablement of the holder promotes the next
/// registration and takes it off this list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceConflict {
    /// The organization the key is in.
    pub organization_id: OrganizationId,
    /// The audience that was already taken.
    pub audience: Audience,
    /// The registration that does not hold it.
    pub id: ResourceServerId,
}

/// Which index of a recorded key another key holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningKeyIndex {
    /// The handle the deployment resolves to the material.
    KeyReference,
    /// The thumbprint of the public key that handle resolved to.
    Thumbprint,
}

/// A recorded key that does not hold an index it records, because another key holds it.
///
/// **A view over the records, not a place records are kept**; see
/// [`Projection::signing_key_conflicts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningKeyConflict {
    /// The key that does not hold it.
    pub id: SigningKeyId,
    /// Which index.
    pub index: SigningKeyIndex,
    /// The key that does.
    pub held_by: SigningKeyId,
}

/// A log that is not a history this fold can read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FoldError {
    /// A lifecycle event names a registration no event created.
    UnknownResourceServer {
        /// The registration the event named.
        id: ResourceServerId,
    },
    /// A lifecycle event names a credential no event created.
    UnknownAccessCredential {
        /// The credential the event named.
        id: CredentialId,
    },
    /// A lifecycle event names a signing key no event created.
    UnknownSigningKey {
        /// The key the event named.
        id: SigningKeyId,
    },
    /// An issuance names a registration no event created, so the guarantee the credential
    /// was issued under cannot be recovered.
    UnknownIssuingTarget {
        /// The credential the event created.
        id: CredentialId,
        /// The registration it named.
        target: ResourceServerId,
    },
}

impl fmt::Display for FoldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownResourceServer { id } => {
                write!(formatter, "no event created the resource server {id}")
            }
            Self::UnknownAccessCredential { id } => {
                write!(formatter, "no event created the access credential {id}")
            }
            Self::UnknownSigningKey { id } => {
                write!(formatter, "no event created the signing key {id}")
            }
            Self::UnknownIssuingTarget { id, target } => write!(
                formatter,
                "the access credential {id} was issued for the resource server {target}, which no event registered"
            ),
        }
    }
}

impl std::error::Error for FoldError {}

/// Which declared refusing outcome a [`Denied`] is.
///
/// A command that moves an entity along its lifecycle declares **two** error outcomes, not
/// one: the external `denied` and the `wrong-state` taken "when the subject is in a state
/// none of that command's declared moves start from", which "reports the same `Denied`
/// error and renders as HTTP 409 in the OpenAPI projection rather than the 502 an external
/// denial renders as" (`docs/architecture/command-obligations.md`).
///
/// The distinction cannot live in [`DenialReason`]: that enum is the contract's, it is
/// closed, and it declares no wrong-state reason. [`RefusedOutcome::ir_name`] is the name
/// the outcome carries in `generated/ir/system.json`, which is what
/// `services/sts/tests/emitted_events.rs` looks the refusal up by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefusedOutcome {
    /// The declared `denied` outcome: an externally caused refusal.
    Denied,
    /// The declared `wrong-state` outcome.
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

/// A condition named by a declared denial clause of `mandate.credential`.
///
/// Every variant is one phrase of a denial text in `systems/mandate/domains/credential.yaml`,
/// verbatim from `docs/architecture/command-obligations.md`. It is a crate-local
/// discriminator and not a contract field: no wire form carries it, and the contract's own
/// error payload is [`DenialReason`] alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DenialClause {
    /// `RegisterResourceServer`: "audience registration is ambiguous".
    AudienceAmbiguous,
    /// "profile semantics are unadmitted": the profile the command supplies, or the
    /// registered profile the command was reached through, does not admit what was asked.
    ProfileUnadmitted,
    /// "an allowed source server is unresolved/disabled/outside the verified organization":
    /// unresolved.
    SourceUnresolved,
    /// The same clause: the named source is in the terminal `Disabled` state.
    SourceDisabled,
    /// The same clause: the named source is registered to another organization.
    SourceOutsideOrganization,
    /// "target/profile is unregistered/disabled/outside tenant": the registry answers no
    /// registration for the target.
    TargetUnregistered,
    /// The same clause: the registration is in the terminal `Disabled` state.
    TargetDisabled,
    /// "server is outside the verified organization", and every other clause that names a
    /// record bound to another organization than the caller's verified one.
    OrganizationMismatch,
    /// "expiry cannot be bounded": the profile's TTL or the request instant does not name a
    /// span this deployment can add.
    ExpiryUnbounded,
    /// The signer refused the credential this issuance would have returned.
    SigningRefused,
    /// `IntrospectCredential`: "the presented credential proof is malformed".
    ProofMalformed,
    /// "Caller proof ... is itself invalid, revoked or expired".
    CallerProofInvalid,
    /// "Caller proof lacks introspection authority for the registered server/tenant": the
    /// caller's own context resolves to no enabled registration.
    IntrospectionAuthority,
    /// "audience mismatches": the presented credential names another audience than the
    /// caller's registered server.
    AudienceMismatch,
    /// "authoritative online resolution is unavailable".
    ResolutionUnavailable,
    /// `RevokeAccessCredential`: the credential does not resolve.
    CredentialUnknown,
    /// The `wrong-state` branch: the credential is already in the terminal `Revoked` state.
    CredentialRevoked,
    /// The `wrong-state` branch: the registration is already in the terminal `Disabled`
    /// state.
    ServerDisabled,
    /// `RegisterSigningKey`: "the algorithm is outside the deployment's admitted set".
    AlgorithmUnadmitted,
    /// "the key reference is unresolvable".
    KeyReferenceUnresolvable,
    /// "the key reference or the key material is already recorded": the reference.
    KeyReferenceRecorded,
    /// The same clause: the material, caught by its thumbprint.
    KeyMaterialRecorded,
    /// The entity invariant `not_before < expires_at`, checked by the deciding handler.
    KeyWindowNotOrdered,
    /// `RetireSigningKey` / `RevokeSigningKey`: "the key is unresolved".
    KeyUnknown,
    /// `RetireSigningKey`: "no overlapping replacement key is published for continued
    /// verification".
    NoReplacementKey,
    /// The `wrong-state` branch: the key is in a state no declared move starts from.
    KeyNotRecorded,
    /// `IssueAuthorizationCode`: "S256 policy" — the challenge offered is not in the
    /// declared S256 form, so it is the challenge of no verifier that exists.
    /// `RedeemAuthorizationCode`: "S256 verifier mismatches", for a recorded challenge in
    /// that same shape.
    ChallengeMalformed,
    /// `RedeemAuthorizationCode`: "S256 verifier mismatches" — the presented verifier is not
    /// in the form RFC 7636 declares.
    VerifierMalformed,
    /// The same clause: the presented verifier does not redeem the recorded challenge.
    VerifierMismatch,
    /// "Code proof does not match the server-resolved code_id": the proof presented is not
    /// the one the record's verifier was derived from.
    CodeProofMismatch,
    /// The same clause: the `code_id` resolves to no record, so there is no server-resolved
    /// code for a proof to match.
    ///
    /// It carries the same [`DenialReason`] as [`DenialClause::CodeProofMismatch`] —
    /// `InvalidCredential` — deliberately. The reason is the contract's only wire field on
    /// this error, and a caller that could tell "this code_id exists and your proof is
    /// wrong" from "no such code_id" would hold an oracle over the code space.
    CodeUnknown,
    /// "code is expired".
    CodeExpired,
    /// The `wrong-state` branch: the code is already in the terminal `Consumed` state. The
    /// contract declares this outcome by the transition's `from:` set and gives it no prose,
    /// which is why no phrase is quoted here.
    CodeConsumed,
    /// "client ... mismatches": the presented client is not the one the code is bound to.
    ClientMismatch,
    /// `IssueAuthorizationCode`: "registered public client" — the client the code would be
    /// bound to is registered nowhere this deployment can read.
    /// `RedeemAuthorizationCode`: the same fact, under "client ... mismatches".
    ClientUnregistered,
    /// `IssueAuthorizationCode`: "registered public client" — the registry does not answer
    /// that this client is a public one, or cannot answer at all. The authorization-code
    /// road with PKCE is the public-client road, and the STS is the second line behind the
    /// adapter that has already decided it.
    ClientNotPublic,
    /// "the client the code would be bound to is disabled" / "the bound client is disabled".
    ClientDisabled,
    /// The tenant half: the client is registered to another organization. "tenant/target
    /// agreement" at issuance, "client ... mismatches" at redemption.
    ClientOutsideOrganization,
    /// `IssueAuthorizationCode`: "exact redirect URI" — the redirect a code would be bound
    /// to is not one the client's registration carries, byte for byte.
    RedirectUnregistered,
    /// `RedeemAuthorizationCode`: "redirect URI ... mismatches" — the presented redirect is
    /// not the one the code authorized, byte for byte.
    RedirectMismatch,
    /// "source/session epoch is stale": the epoch snapshot the session names has moved, or
    /// cannot be resolved — and a snapshot that cannot be resolved has not been shown to be
    /// current. [`Denied::reason`] tells the two apart: `StaleEpoch` for a generation that
    /// moved, `Unavailable` for a reader that could not answer.
    SessionEpochStale,
    /// "source/session epoch is stale": the session the code names resolves to no record,
    /// has been revoked, or has expired.
    ///
    /// The nearest declared phrase and not an exact one, which is the whole of why this is a
    /// separate clause from [`DenialClause::SessionEpochStale`] rather than the same one:
    /// `RedeemAuthorizationCode`'s denial names a stale session *epoch* and **no phrase at
    /// all** for an unresolved, revoked or expired session, while its accepted summary reads
    /// the session through the STS's session port
    /// (`systems/mandate/domains/credential.yaml:245`). The gap is a contract observation,
    /// routed to the contract and recorded here and on this clause's row in
    /// `services/sts/tests/declared_denials.rs`, rather than papered over with a clause that
    /// quotes nothing.
    SessionUnusable,
    /// `ExchangeCredential`: "registered target/source ... binding fails" — the target's
    /// registration does not list, among its `allowed_exchange_sources`, the registration the
    /// subject credential was issued for. An empty list admits none.
    SourceUnadmitted,
    /// `ExchangeCredential`: "scope ... binding fails" — the requested scope is not inside the
    /// subject credential's own, so the exchange would widen authority rather than narrow it.
    ScopeNotNarrowed,
    /// `ExchangeCredential`: "actor ... or delegation ... binding fails" — an actor proof or a
    /// delegation was presented to an exchange this deployment realizes subject-only
    /// (`story:federated-token-exchange`; the actor and delegation exchange is
    /// `story:constrained-exchange`'s).
    ExchangeNotSubjectOnly,
    /// `ExchangeCredential`: "independently validated proof is invalid/revoked/expired/stale"
    /// — the subject token resolves to no credential, or to one that is revoked, expired, or
    /// issued by a registration that is disabled. One clause for all of them, so a caller
    /// holding a well-formed token learns only that it is unusable.
    ///
    /// Its own clause, not [`DenialClause::CallerProofInvalid`]: that one is the introspection
    /// caller's failed authentication and answers `invalid_client`, and the subject token of
    /// an exchange is the grant presented, not a client credential (correction round 2).
    SubjectTokenInvalid,
}

/// `mandate.credential.Denied`: fail closed; no credential, authority or lifecycle mutation
/// on refusal.
///
/// Declared here rather than in `services/sts` because the guard this crate's projection
/// owns — the `(organization_id, audience)` index of
/// `decision-blocker:identity-uniqueness` — returns one, and a domain that refused in two
/// vocabularies would be two rules. `services/sts/src/lib.rs` registers this type as the
/// realization of `mandate.credential.Denied`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The declared `mandate.core.DenialReason`.
    pub reason: DenialReason,
    /// Which declared denial condition fired. Crate-local; see [`DenialClause`].
    pub clause: DenialClause,
    /// Which declared refusing outcome this is.
    pub outcome: RefusedOutcome,
}

impl Denied {
    /// Refuse through the declared `denied` outcome.
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

/// The read model of `mandate.credential`: a fold over the event log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    resource_servers: Vec<ResourceServer>,
    credentials: Vec<AccessCredential>,
    keys: Vec<SigningKey>,
}

impl Projection {
    /// Materialize the read model from a log.
    ///
    /// # Errors
    ///
    /// Returns [`FoldError`] when the log is not a history this fold can read.
    pub fn fold(events: &[CredentialEvent]) -> Result<Self, FoldError> {
        let mut projection = Self::default();
        for event in events {
            projection.apply(event)?;
        }
        Ok(projection)
    }

    /// Apply one event.
    ///
    /// Writing a record is insert-if-absent at the record's own identity, and moving one
    /// honours the declared `from:` set of the transition the event is
    /// ([`Projection::move_key`] states why). Both are the same rule: the kit's
    /// at-least-once delivery admits a redelivered or late event, and applying one must
    /// write nothing rather than return a record to a state the contract does not admit it
    /// moving back to. Every lifecycle arm here names its own declared source set.
    ///
    /// # Errors
    ///
    /// Returns [`FoldError`] when the event names an instance no event created — including
    /// the registration an issuance was made under — or records key material another
    /// recorded key already holds.
    pub fn apply(&mut self, event: &CredentialEvent) -> Result<(), FoldError> {
        match event {
            CredentialEvent::ResourceServerRegistered {
                context,
                id,
                audience,
                credential_profile,
                allowed_exchange_sources,
            } => {
                if self.resource_server(id).is_some() {
                    return Ok(());
                }
                self.resource_servers.push(ResourceServer {
                    id: *id,
                    // The payload declares no organization: the registering caller's
                    // verified organization is the binding, and `register_resource_server`
                    // refuses any other.
                    organization_id: context.organization,
                    audience: audience.clone(),
                    credential_profile: credential_profile.clone(),
                    allowed_exchange_sources: allowed_exchange_sources.clone(),
                    state: ResourceServerState::Enabled,
                });
            }
            CredentialEvent::ResourceServerDisabled { context: _, id } => {
                let server = self
                    .resource_servers
                    .iter_mut()
                    .find(|server| server.id == *id)
                    .ok_or(FoldError::UnknownResourceServer { id: *id })?;
                // `disable` starts `from: [Enabled]`.
                if server.state == ResourceServerState::Enabled {
                    server.state = ResourceServerState::Disabled;
                }
            }
            CredentialEvent::CredentialReferenceIssued {
                context: _,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope: _,
            }
            | CredentialEvent::CredentialSelfContainedIssued {
                context: _,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope: _,
            }
            // The fourth creator: an admitted exchange issues its credential for the target
            // the event names, from the same record fields.
            | CredentialEvent::TokenExchangeAllowed {
                context: _,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope: _,
            } => {
                self.record_credential(
                    credential_id,
                    reference_verifier,
                    epochs,
                    issued_at,
                    descriptor,
                    target,
                )?;
            }
            // The third creator of an `AccessCredential`, and the same record from the same
            // two sources: this event and the issuing registration the log already holds.
            // `code_id` names the code record, which `services/sts` folds and this one does
            // not.
            CredentialEvent::AuthorizationCodeRedeemed {
                context: _,
                code_id: _,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
            } => {
                self.record_credential(
                    credential_id,
                    reference_verifier,
                    epochs,
                    issued_at,
                    descriptor,
                    target,
                )?;
            }
            CredentialEvent::AccessCredentialRevoked { context: _, id } => {
                let credential = self
                    .credentials
                    .iter_mut()
                    .find(|credential| credential.id == *id)
                    .ok_or(FoldError::UnknownAccessCredential { id: *id })?;
                // `revoke` starts `from: [Active]`.
                if credential.state == AccessCredentialState::Active {
                    credential.state = AccessCredentialState::Revoked;
                }
            }
            // Creates, moves and updates nothing. The `credential_id` it carries is not a
            // name this fold resolves: the presented credential may have been issued by a
            // deployment this log never saw, which is why the field is optional rather than
            // the event's subject.
            CredentialEvent::CredentialIntrospected { .. } => {}
            // A refused exchange creates, moves and updates nothing; the record is that it
            // was refused.
            CredentialEvent::TokenExchangeDenied { .. } => {}
            CredentialEvent::SigningKeyRegistered {
                context: _,
                id,
                key_reference,
                thumbprint,
                algorithm,
                not_before,
                expires_at,
            } => {
                if self.signing_key(id).is_some() {
                    return Ok(());
                }
                // A `key_reference` or a `thumbprint` a recorded key already holds is not a
                // log this fold cannot read; it is the same race the audience index has, and
                // it is resolved the same way — every registration is recorded, one of them
                // holds each index ([`Projection::signing_key_conflicts`]), and the write
                // path refuses what it can see.
                self.keys.push(SigningKey {
                    id: *id,
                    key_reference: key_reference.clone(),
                    thumbprint: thumbprint.clone(),
                    algorithm: algorithm.clone(),
                    not_before: not_before.clone(),
                    expires_at: expires_at.clone(),
                    state: SigningKeyState::Recorded,
                });
            }
            // `retire` starts `from: [Recorded]`.
            CredentialEvent::SigningKeyRetired { context: _, id } => {
                self.move_key(id, &[SigningKeyState::Recorded], SigningKeyState::Retired)?;
            }
            // `revoke` starts `from: [Recorded, Retired]`.
            CredentialEvent::SigningKeyRevoked { context: _, id } => {
                self.move_key(
                    id,
                    &[SigningKeyState::Recorded, SigningKeyState::Retired],
                    SigningKeyState::Revoked,
                )?;
            }
        }
        Ok(())
    }

    /// Write one `AccessCredential` record, from the event that creates it and the
    /// registration the log already holds.
    ///
    /// Three declared events create this record — `CredentialReferenceIssued`,
    /// `CredentialSelfContainedIssued` and `AuthorizationCodeRedeemed` — and each carries
    /// the same record fields, so each creates it the same way. Writing it in one place is
    /// what makes that true rather than what asserts it: a fourth creator added to the
    /// contract gets this body or does not compile.
    ///
    /// Insert-if-absent at the record's own identity, for the reason every creation arm
    /// here is: the kit's at-least-once delivery admits a redelivered event, and applying
    /// one must write nothing.
    ///
    /// # Errors
    ///
    /// Returns [`FoldError::UnknownIssuingTarget`] when no event registered the target the
    /// event names: the guarantee a credential carries is the one published by the
    /// registration it was issued under — the registration holding that audience later may
    /// publish another (see [`AccessCredential`]) — so a log that cannot answer it is a log
    /// this fold cannot read, for the same reason a lifecycle event naming no record is.
    fn record_credential(
        &mut self,
        credential_id: &CredentialId,
        reference_verifier: &Option<CredentialVerifier>,
        epochs: &Option<EpochSnapshotRef>,
        issued_at: &Timestamp,
        descriptor: &CredentialDescriptor,
        target: &ResourceServerId,
    ) -> Result<(), FoldError> {
        if self.access_credential(credential_id).is_some() {
            return Ok(());
        }
        let issuing = self
            .resource_server(target)
            .ok_or(FoldError::UnknownIssuingTarget {
                id: *credential_id,
                target: *target,
            })?;
        self.credentials.push(AccessCredential {
            id: *credential_id,
            descriptor: descriptor.clone(),
            reference_verifier: reference_verifier.clone(),
            epochs: *epochs,
            issued_at: issued_at.clone(),
            state: AccessCredentialState::Active,
            target: *target,
            issuing_profile: issuing.credential_profile,
        });
        Ok(())
    }

    /// Move one recorded key along a declared transition.
    ///
    /// `from` is that transition's declared source set, and a record in any other state is
    /// left where it is. `mandate.credential.SigningKey` is the one record of this domain
    /// with **two** terminal states, so writing the state an event names without asking
    /// which state the record is in is not idempotent here the way it is for the other two:
    /// a `SigningKeyRetired` the kit redelivers after the revocation that followed it, or
    /// delivers late, would return a revoked key to `Retired` — and a key the fold rebuilds
    /// as `Retired` is a key the restarted signer does not know was compromised
    /// (`RealSigner::new_with_revocations` is rehydrated from the `Revoked` records).
    ///
    /// Left where it is, rather than refused: a redelivery is a normal event under the
    /// kit's at-least-once delivery and is not a log this fold cannot read. The write path
    /// refuses the *command* through the declared `wrong-state` outcome
    /// (`services/sts/src/keys.rs`); this is the fold's half of the same rule, and the
    /// other three lifecycle arms state their own `from:` set beside them.
    fn move_key(
        &mut self,
        id: &SigningKeyId,
        from: &[SigningKeyState],
        state: SigningKeyState,
    ) -> Result<(), FoldError> {
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.id == *id)
            .ok_or(FoldError::UnknownSigningKey { id: *id })?;
        if from.contains(&key.state) {
            key.state = state;
        }
        Ok(())
    }

    /// Every registration, in the order it was created.
    #[must_use]
    pub fn resource_servers(&self) -> &[ResourceServer] {
        &self.resource_servers
    }

    /// Every credential, in the order it was issued.
    #[must_use]
    pub fn credentials(&self) -> &[AccessCredential] {
        &self.credentials
    }

    /// Every signing key, in the order it was registered.
    #[must_use]
    pub fn signing_keys(&self) -> &[SigningKey] {
        &self.keys
    }

    /// The registration with this identity, whatever its lifecycle state.
    ///
    /// A lifecycle command needs to tell "no such record" from "already disabled": the two
    /// are different declared outcomes, so this never filters by state.
    #[must_use]
    pub fn resource_server(&self, id: &ResourceServerId) -> Option<ResourceServer> {
        self.resource_servers
            .iter()
            .find(|server| server.id == *id)
            .cloned()
    }

    /// The credential with this identity, whatever its lifecycle state.
    #[must_use]
    pub fn access_credential(&self, id: &CredentialId) -> Option<AccessCredential> {
        self.credentials
            .iter()
            .find(|credential| credential.id == *id)
            .cloned()
    }

    /// The signing key with this identity, whatever its lifecycle state.
    #[must_use]
    pub fn signing_key(&self, id: &SigningKeyId) -> Option<SigningKey> {
        self.keys.iter().find(|key| key.id == *id).cloned()
    }

    /// The registration that holds an `(organization_id, audience)` key.
    ///
    /// The smallest [`ResourceServerId`] among the `Enabled` records on the key, which
    /// orders on the sixteen bytes of its UUID. A disabled registration holds no audience:
    /// no command un-registers one, so a retired registration would otherwise take an
    /// audience out of use for good.
    #[must_use]
    pub fn registered(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Option<ResourceServer> {
        self.resource_servers
            .iter()
            .filter(|server| {
                server.state == ResourceServerState::Enabled
                    && server.organization_id == *organization_id
                    && server.audience == *audience
            })
            .min_by_key(|server| server.id)
            .cloned()
    }

    /// Every recorded registration that does not hold its key, derived from the records.
    ///
    /// A read for the adapter, not for a command: no handler consults it. Each entry is a
    /// registration that was written and does not hold its audience, and its record is
    /// still in [`Projection::resource_servers`].
    #[must_use]
    pub fn audience_conflicts(&self) -> Vec<AudienceConflict> {
        self.resource_servers
            .iter()
            .filter(|server| server.state == ResourceServerState::Enabled)
            .filter(|server| {
                self.registered(&server.organization_id, &server.audience)
                    .is_some_and(|holder| holder.id != server.id)
            })
            .map(|server| AudienceConflict {
                organization_id: server.organization_id,
                audience: server.audience.clone(),
                id: server.id,
            })
            .collect()
    }

    /// The key that holds a `key_reference`: the smallest identity among the keys recording
    /// it, in whatever lifecycle state.
    ///
    /// "In whatever state" is the contract's own rule — a reference is held "in every state
    /// that key can be in, including Retired and Revoked, so material the deployment revoked
    /// never returns under a second identity" (`credential.yaml`, `RegisterSigningKey`) — and
    /// it is why this filters by nothing where [`Projection::registered`] filters by
    /// `Enabled`.
    #[must_use]
    pub fn key_reference_holder(&self, key_reference: &KeyReference) -> Option<SigningKey> {
        self.keys
            .iter()
            .filter(|key| key.key_reference == *key_reference)
            .min_by_key(|key| key.id)
            .cloned()
    }

    /// The key that holds a `thumbprint`, by the same rule: the same material re-filed under
    /// a second identity does not take the index from the identity that already had it.
    #[must_use]
    pub fn thumbprint_holder(&self, thumbprint: &str) -> Option<SigningKey> {
        self.keys
            .iter()
            .filter(|key| key.thumbprint == thumbprint)
            .min_by_key(|key| key.id)
            .cloned()
    }

    /// Whether a recorded key holds both indexes it records.
    ///
    /// The question every admission asks: a key that does not hold its `key_reference` or
    /// its `thumbprint` is a second record of material another key already has, and it is
    /// admitted for neither issuance nor verification
    /// (`services/sts/src/keys.rs`). A key no event recorded holds nothing.
    #[must_use]
    pub fn holds_its_key_material(&self, id: &SigningKeyId) -> bool {
        self.signing_key(id).is_some_and(|key| {
            self.key_reference_holder(&key.key_reference)
                .is_some_and(|holder| holder.id == key.id)
                && self
                    .thumbprint_holder(&key.thumbprint)
                    .is_some_and(|holder| holder.id == key.id)
        })
    }

    /// Every recorded key that does not hold an index it records, derived from the records.
    ///
    /// The `SigningKey` half of what [`Projection::audience_conflicts`] is for the audience
    /// index, and for the same reason. Two `RegisterSigningKey` writers that each read a free
    /// `key_reference` append to two `SigningKey` aggregates, so the kit's compare-and-set on
    /// the appending stream does not see the other and the log is the record of both. A fold
    /// that refused such a log would refuse **the whole log** — every `ResourceServer` and
    /// every `AccessCredential` in it — and under
    /// `docs/adr/0009-event-sourced-persistence.md` there is nowhere else to read those from.
    ///
    /// So the record is kept, one key holds each index ([`Projection::key_reference_holder`],
    /// [`Projection::thumbprint_holder`]), and the loser is named here. A key can appear
    /// twice, once per index it lost.
    ///
    /// Recomputed on each call: which key holds an index is a function of the records alone,
    /// so a rebuild that interleaves two streams differently resolves it the same way.
    #[must_use]
    pub fn signing_key_conflicts(&self) -> Vec<SigningKeyConflict> {
        let mut conflicts = Vec::new();
        for key in &self.keys {
            if let Some(holder) = self.key_reference_holder(&key.key_reference)
                && holder.id != key.id
            {
                conflicts.push(SigningKeyConflict {
                    id: key.id,
                    index: SigningKeyIndex::KeyReference,
                    held_by: holder.id,
                });
            }
            if let Some(holder) = self.thumbprint_holder(&key.thumbprint)
                && holder.id != key.id
            {
                conflicts.push(SigningKeyConflict {
                    id: key.id,
                    index: SigningKeyIndex::Thumbprint,
                    held_by: holder.id,
                });
            }
        }
        conflicts
    }

    /// Whether an `(organization_id, audience)` key is free to register.
    ///
    /// `decision-blocker:identity-uniqueness` as the write path sees it: audiences are
    /// unique within an organization, and the same audience in another organization is a
    /// different key. This is a read-then-write guard; storage enforces the same index
    /// atomically (`docs/adr/0009-event-sourced-persistence.md`).
    ///
    /// # Errors
    ///
    /// Returns the declared `mandate.credential.Denied` — "audience registration is
    /// ambiguous" — when an enabled registration in that organization already holds it.
    pub fn admits_audience(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Result<(), Denied> {
        if self.registered(organization_id, audience).is_some() {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::AudienceAmbiguous,
            ));
        }
        Ok(())
    }
}

const _: () = {
    // Raw credentials never enter a persistent domain record or an audit record
    // (`AGENTS.md`). This is the check rather than a list: the match is exhaustive and no
    // pattern uses `..`, so a variant or a field added to `CredentialEvent` whose type is
    // not a `PersistedValue` does not compile. Neither `CredentialSecret` nor
    // `CredentialProof` is one, and no crate can add that impl for them.
    fn persistable<T: PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_payload_is_persistable(event: &CredentialEvent) {
        match event {
            CredentialEvent::ResourceServerRegistered {
                context,
                id,
                audience,
                credential_profile,
                allowed_exchange_sources,
            } => {
                persistable(context);
                persistable(id);
                persistable(audience);
                persistable(credential_profile);
                persistable(allowed_exchange_sources);
            }
            CredentialEvent::ResourceServerDisabled { context, id } => {
                persistable(context);
                persistable(id);
            }
            CredentialEvent::CredentialReferenceIssued {
                context,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope,
            }
            | CredentialEvent::CredentialSelfContainedIssued {
                context,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope,
            }
            | CredentialEvent::TokenExchangeAllowed {
                context,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
                requested_scope,
            } => {
                persistable(context);
                persistable(credential_id);
                persistable(reference_verifier);
                persistable(epochs);
                persistable(issued_at);
                persistable(descriptor);
                persistable(target);
                persistable(requested_scope);
            }
            CredentialEvent::AccessCredentialRevoked { context, id } => {
                persistable(context);
                persistable(id);
            }
            CredentialEvent::CredentialIntrospected {
                context,
                descriptor,
                active,
                credential_id,
            } => {
                persistable(context);
                persistable(descriptor);
                persistable(active);
                persistable(credential_id);
            }
            CredentialEvent::SigningKeyRegistered {
                context,
                id,
                key_reference,
                thumbprint,
                algorithm,
                not_before,
                expires_at,
            } => {
                persistable(context);
                persistable(id);
                persistable(key_reference);
                persistable(thumbprint);
                persistable(algorithm);
                persistable(not_before);
                persistable(expires_at);
            }
            CredentialEvent::SigningKeyRetired { context, id }
            | CredentialEvent::SigningKeyRevoked { context, id } => {
                persistable(context);
                persistable(id);
            }
            CredentialEvent::AuthorizationCodeRedeemed {
                context,
                code_id,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
            } => {
                persistable(context);
                persistable(code_id);
                persistable(credential_id);
                persistable(reference_verifier);
                persistable(epochs);
                persistable(issued_at);
                persistable(descriptor);
                persistable(target);
            }
            CredentialEvent::TokenExchangeDenied {
                context,
                requested_target,
                requested_scope,
            } => {
                persistable(context);
                persistable(requested_target);
                persistable(requested_scope);
            }
        }
    }
};
