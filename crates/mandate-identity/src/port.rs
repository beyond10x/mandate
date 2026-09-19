//! The ports: reading identity state, and the compare-and-set that advances a
//! generation.
//!
//! Under `docs/adr/0009-event-sourced-persistence.md` every durable state here is
//! event-sourced: commands produce events, the events are the record and every read is a
//! fold. The write port is therefore the log's own aggregate append — a compare-and-set
//! on the expected stream version — and not a setter. [`IdentityLog`] is that fold over a
//! `Vec` of events, which is what the tests run against until the event-log kit is
//! admitted to the workspace.
//!
//! Reading and writing are two traits, not one. A holder of a read port cannot advance a
//! generation through the type it holds, which is what keeps a non-consuming reader of
//! this crate non-consuming.

use mandate_contract::events::{
    MandateFederationExternalPrincipalProvisioned, MandateFederationFederationAuthenticated,
};
use mandate_contract::types::{MandateCoreExternalLinkMethod, MandateCorePrincipalKind};
use mandate_types::{
    DenialReason, EpochSnapshotRef, ExternalPrincipalId, FederationConnectionId, OrganizationId,
    PrincipalId, PrincipalKind, SecurityEpochTarget, SessionId, Timestamp, VerifiedContext,
};
use serde::{Serialize, Serializer};

use crate::{Denial, Generation, SecurityEpochSnapshot, Session, SessionOpened, SessionRevoked};

/// The expected version of one target's event stream.
///
/// The kit's aggregate append is a compare-and-set on this value
/// (`decision-blocker:epoch-atomicity`); the signature is revisited when the kit lands.
///
/// A version is a compare-and-set key, so advancing one must always produce a strictly
/// greater value: a version that wrapped to [`StreamVersion::INITIAL`] would be the key
/// the compare-and-set accepts for an untouched stream. The counter is therefore wider
/// than any version the public constructor can name — `new` takes a `u64`, the value is
/// held as a `u128` — so [`StreamVersion::advance`] of a constructible version is total
/// and strictly increasing. Saturation needs 2^128 appends and is unreachable; the
/// compare-and-set refuses a stream whose version does not advance in any case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StreamVersion(u128);

impl StreamVersion {
    /// The version of a stream that holds no event.
    pub const INITIAL: Self = Self(0);

    /// The version for a declared value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value as u128)
    }

    /// The declared value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }

    /// The version one appended event later, which is always greater than this one for
    /// every version `new` can produce.
    #[must_use]
    pub const fn advance(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// One dimension's authoritative generation together with the version it was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochState {
    generation: Generation,
    version: StreamVersion,
}

impl EpochState {
    /// The state for a declared generation and version.
    #[must_use]
    pub const fn new(generation: Generation, version: StreamVersion) -> Self {
        Self {
            generation,
            version,
        }
    }

    /// The authoritative generation.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// The version this generation was read at, which a write compares against.
    #[must_use]
    pub const fn version(self) -> StreamVersion {
        self.version
    }
}

/// `mandate.identity.Principal.State`.
///
/// The two states `systems/mandate/domains/identity.yaml` declares. The fold reaches
/// `Active` alone today: this crate realizes no command that moves a principal, and
/// `mandate.identity.PrincipalDisabled` — the event `DisablePrincipal`'s accepted outcome
/// emits — is not folded here. A reader that needs the disablement composes this port over
/// the store that carries that event; see [`crate::ESS_UNREALIZED`].
///
/// `mandate-federation` holds its own enum over the same declared lifecycle, for the port
/// it reads this record through. Two readers of one declared lifecycle, both decided
/// against the same generated shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PrincipalState {
    /// The declared initial state.
    Active,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.identity.Principal`, as this crate folds it.
///
/// The declared record is an identity, a `kind` and a `display_name`
/// (`systems/mandate/domains/identity.yaml`). No command in this contract declares its
/// creation: the writer is declared in that file's header, and it is
/// `mandate.federation.ExternalPrincipalProvisioned`, which "carries principal_id, kind
/// and display_name — the whole Principal record — and the identity fold materializes the
/// principal from that event alone".
///
/// The field names on the wire are the declared ones, which
/// `crates/mandate-identity/tests/contract_agreement.rs` decides against the generated
/// entity shape; the Rust names are the crate's own and each accessor is named for what it
/// answers. Like [`Session`], this is a projection of the fold and not a canonical
/// `mandate.core.*` type; see the crate documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Principal {
    id: PrincipalId,
    kind: PrincipalKind,
    display_name: String,
    state: PrincipalState,
}

impl Principal {
    /// The record a seeding event puts into existence, in the declared initial state.
    #[must_use]
    pub const fn new(id: PrincipalId, kind: PrincipalKind, display_name: String) -> Self {
        Self {
            id,
            kind,
            display_name,
            state: PrincipalState::Active,
        }
    }

    /// The declared `id`.
    #[must_use]
    pub const fn id(&self) -> &PrincipalId {
        &self.id
    }

    /// The declared `kind`.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// The declared `display_name`.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The lifecycle state.
    #[must_use]
    pub const fn state(&self) -> PrincipalState {
        self.state
    }
}

/// The read port. Every method takes `&self`; none of them mutates anything.
pub trait IdentityRead {
    /// The session with this identity, when the fold records one.
    fn resolve(&self, id: &SessionId) -> Option<Session>;

    /// The principal with this identity, when the fold records one.
    ///
    /// A principal the log has no creation record for answers `None` rather than a
    /// defaulted record: `identity.yaml` states that "a principal named by
    /// LinkExternalPrincipal rather than provisioned is seeded by no event today and has
    /// no record until a command creates one". An opening that names such a principal is
    /// still folded — [`IdentityLog`] refuses no opening for it — so `None` here is the
    /// answer for a principal that exists outside this log, not a refusal of the session.
    fn principal(&self, id: &PrincipalId) -> Option<Principal>;

    /// The authoritative generation for a target, and the version it was read at.
    ///
    /// A target no increment has been recorded for is at [`Generation::ZERO`].
    fn current(&self, target: &SecurityEpochTarget) -> EpochState;

    /// The snapshot a session's handle refers to, when the fold records one.
    fn snapshot(&self, id: &EpochSnapshotRef) -> Option<SecurityEpochSnapshot>;

    /// The instant this read is evaluated at, when the host has supplied one.
    ///
    /// A reader that has none cannot decide whether a record has expired, and
    /// [`crate::refresh_session`] fails closed rather than certifying a session it
    /// cannot date. The default is no instant.
    fn as_of(&self) -> Option<Timestamp> {
        None
    }
}

/// The write port: the one operation that advances a generation.
///
/// Separate from [`IdentityRead`] so that holding a reader is not holding a mutator.
pub trait SecurityEpochWrite {
    /// Advance one target's generation, if the stream is still at `expected`.
    ///
    /// The verified context is the command's own: `mandate.identity.SecurityEpochIncremented`
    /// declares `context: input.context`, and this is the operation that appends that
    /// event, so it is handed the context rather than inventing one.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the stream has moved since it was read, and
    /// when the generation is already at [`Generation::MAX`] — which fails closed rather
    /// than wrapping or reusing a generation.
    fn increment(
        &mut self,
        context: &VerifiedContext,
        target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial>;
}

/// `mandate.identity.EpochSnapshotRecorded`: the seeding event of one epoch snapshot.
///
/// The declared payload, field for field. It carries **no generation**, because the
/// declared record carries none — "EpochSnapshotRef is only an immutable record handle,
/// never an epoch number" (`identity.yaml`, `UNMAPPED-EPOCH`). The per-dimension
/// generations the addendum requires are the ones the authority held when this event was
/// recorded, and the fold reads them off the log at that point; see
/// [`IdentityRead::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EpochSnapshotRecorded {
    /// The declared `id`: the handle a session refers to the snapshot by.
    pub id: EpochSnapshotRef,
    /// The declared `principal_id`.
    pub principal_id: PrincipalId,
    /// The declared `organization_id`.
    pub organization_id: OrganizationId,
    /// The declared `connection_id`, when the snapshot covers a federation connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<FederationConnectionId>,
}

/// `mandate.identity.SecurityEpochRecorded`: one target's generation, as recorded.
///
/// **Not a reset**: the authoritative generation never moves backwards. A value below the
/// one already folded for that target is refused by [`IdentityLog::try_record`] and
/// ignored by the fold.
///
/// At [`Generation::MAX`] the increment denies for that target from then on, and the
/// out-of-band recovery the architecture names is not a rewind: it is the revocation of
/// every session whose snapshot names that target. A generation is never reused, so a
/// snapshot that was once stale is stale forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityEpochRecorded {
    /// The declared `target`: what the generation applies to.
    pub target: SecurityEpochTarget,
    /// The declared `generation`, an ESS `Integer` constrained non-negative.
    #[serde(serialize_with = "declared_integer")]
    pub generation: Generation,
}

/// The contract declares `generation` as an ESS `Integer`, so it is written as a JSON
/// number and not as the opaque value [`Generation`] is in Rust.
fn declared_integer<S: Serializer>(
    generation: &Generation,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_i64(generation.get())
}

/// The recorded events this crate folds.
///
/// Each variant carries one declared payload, field for field: the payload's fields are
/// the compiled event's `properties`, with the same names and the same types, which
/// `crates/mandate-identity/tests/contract_agreement.rs` decides against the generated
/// shape of the element [`IdentityEvent::ess_name`] answers. `#[serde(untagged)]` is what
/// makes that true on the wire — a variant serializes as the bare payload object, with no
/// discriminant wrapping it.
///
/// **`Serialize` only, deliberately: this enum does not round-trip and no code should
/// assume it does.** Under `#[serde(untagged)]` a reader cannot tell one `{context, id}`
/// payload from another, and reading an event back needs a tagged envelope carrying the
/// ESS name beside the payload, which belongs to the persistence story.
///
/// What this module ships, exactly: the two port traits, and [`IdentityLog`] as an
/// in-memory double of the event-log adapter that a later story supplies. Its seeding is
/// a fixture path — for this crate's own tests, and for a host that has no adapter yet —
/// and never a command path: a generation is advanced for real through
/// [`SecurityEpochWrite::increment`], which is the compare-and-set
/// `decision-blocker:epoch-atomicity` requires. A caller holding this type can seed a
/// target at any generation, including [`Generation::MAX`], which is how the overflow
/// cases are written; what it cannot do is move one backwards, reopen a session identity
/// any event already names or rewrite a snapshot, because every append goes through the
/// same guards.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum IdentityEvent {
    /// A session came into existence without a federation connection.
    ///
    /// `mandate.identity.SessionOpened`. No command in this contract declares such an
    /// open and no outcome emits it; it is reserved for the control-plane component that
    /// publishes it (`identity.yaml`). One identity is opened once: a second
    /// `SessionOpened` for a session any recorded event already names is refused by
    /// [`IdentityLog::try_record`] and ignored by the fold, because `Revoked` is declared
    /// terminal and no transition leaves it.
    SessionOpened(SessionOpened),
    /// A session came into existence through a federated login.
    ///
    /// `mandate.federation.FederationAuthenticated`, whose accepted outcome **creates**
    /// `mandate.identity.Session` with `session_id` as its instance (`federation.yaml`).
    /// The payload "carries the whole Session record ... so the identity fold materializes
    /// the session from this event alone and reads no command input or response".
    ///
    /// It is the *generated* shape and not a hand-written copy: the dependency direction
    /// is `mandate-federation → mandate-identity` and never the reverse, so this crate
    /// cannot see `mandate_federation::record::FederationEvent`. `mandate-contract`
    /// re-exports generated structure and reaches no Mandate domain crate.
    ///
    /// The same identity rule applies as to [`IdentityEvent::SessionOpened`], and across
    /// both: whichever of the two arrives first opens the session, and the second is
    /// refused.
    FederationAuthenticated(MandateFederationFederationAuthenticated),
    /// A principal came into existence through a just-in-time first login.
    ///
    /// `mandate.federation.ExternalPrincipalProvisioned`. No command in this contract
    /// declares the Principal's creation — `ProvisionExternalPrincipal`'s accepted outcome
    /// spends its one subject on `mandate.federation.ExternalPrincipal`, and an ESS
    /// outcome declares one `creates`/`moves`/`updates` — so the writer is declared in
    /// `identity.yaml`'s header instead: this event "carries principal_id, kind and
    /// display_name — the whole Principal record — and the identity fold materializes the
    /// principal from that event alone".
    ///
    /// It is the *generated* shape and not a hand-written copy, for the same reason
    /// [`IdentityEvent::FederationAuthenticated`] is.
    ///
    /// One identity is created once: a second provisioning of a principal a recorded
    /// provisioning already names is refused by [`IdentityLog::try_record`] and ignored by
    /// the fold, because a second creation would return a record the log already holds to
    /// its initial state.
    ExternalPrincipalProvisioned(MandateFederationExternalPrincipalProvisioned),
    /// `mandate.identity.SessionRevoked`.
    SessionRevoked(SessionRevoked),
    /// An epoch snapshot was recorded for a session to refer to.
    ///
    /// `mandate.identity.EpochSnapshotRecorded`. `EpochSnapshotRef` is an immutable
    /// record handle and `SecurityEpochSnapshot`'s only lifecycle state is `Recorded`, so
    /// a second recording of a handle the fold already holds is refused and ignored.
    EpochSnapshotRecorded(EpochSnapshotRecorded),
    /// A target's first generation. `mandate.identity.SecurityEpochRecorded`.
    SecurityEpochRecorded(SecurityEpochRecorded),
    /// `mandate.identity.SecurityEpochIncremented`: one target advanced by exactly one.
    SecurityEpochIncremented(crate::SecurityEpochIncremented),
}

impl IdentityEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub fn ess_name(&self) -> &'static str {
        match self {
            Self::SessionOpened(_) => "mandate.identity.SessionOpened",
            Self::FederationAuthenticated(_) => "mandate.federation.FederationAuthenticated",
            Self::ExternalPrincipalProvisioned(_) => {
                "mandate.federation.ExternalPrincipalProvisioned"
            }
            Self::SessionRevoked(_) => "mandate.identity.SessionRevoked",
            Self::EpochSnapshotRecorded(_) => "mandate.identity.EpochSnapshotRecorded",
            Self::SecurityEpochRecorded(_) => "mandate.identity.SecurityEpochRecorded",
            Self::SecurityEpochIncremented(_) => "mandate.identity.SecurityEpochIncremented",
        }
    }

    /// The session identity this event names, when it names one.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added that names
    /// a session — and would therefore have to be refused as a second open — does not
    /// compile until this answers for it.
    fn names_session(&self) -> Option<SessionId> {
        match self {
            Self::SessionOpened(opened) => Some(opened.id),
            Self::SessionRevoked(revoked) => Some(revoked.id),
            Self::FederationAuthenticated(login) => declared_session_id(login),
            Self::ExternalPrincipalProvisioned(_)
            | Self::EpochSnapshotRecorded(_)
            | Self::SecurityEpochRecorded(_)
            | Self::SecurityEpochIncremented(_) => None,
        }
    }

    /// The principal identity this event *creates*, when it creates one.
    ///
    /// Only the seeding event does. The two opening events and the revocation name a
    /// principal without creating it — an opening is not a creation record for the
    /// principal it names — so a session for a principal no provisioning created is
    /// neither refused here nor answered for by [`IdentityRead::principal`]; that is the
    /// explicit-link path, and `identity.yaml` states it has no record until a command
    /// creates one. The match is exhaustive and carries no wildcard arm, so a variant
    /// added that creates a principal does not compile until this answers for it.
    fn creates_principal(&self) -> Option<PrincipalId> {
        match self {
            Self::ExternalPrincipalProvisioned(provisioned) => {
                principal_of(provisioned).map(|record| *record.id())
            }
            Self::SessionOpened(_)
            | Self::FederationAuthenticated(_)
            | Self::SessionRevoked(_)
            | Self::EpochSnapshotRecorded(_)
            | Self::SecurityEpochRecorded(_)
            | Self::SecurityEpochIncremented(_) => None,
        }
    }
}

/// The session identity a federated login names, when its declared lexical form is one
/// the contract admits.
fn declared_session_id(login: &MandateFederationFederationAuthenticated) -> Option<SessionId> {
    SessionId::parse(&login.session_id.0).ok()
}

/// The `mandate.identity.Session` a federated login materializes, when every identifier
/// it carries is in the lexical form the contract declares.
///
/// `mandate-contract` states structure and not lexical form — "a Rust type that claimed
/// them here would be claiming validation it does not do"
/// (`crates/mandate-contract/src/lib.rs`) — so the form is decided here, once, for **every**
/// declared field and not only the identifiers: the expiry is an RFC 3339 `date-time` and
/// is read the same way. A payload that fails any of them is refused by
/// [`IdentityLog::try_record`] rather than folded into a session the entity's own schema
/// would refuse.
fn session_of(login: &MandateFederationFederationAuthenticated) -> Option<Session> {
    let expires_at = Timestamp::new(login.expires_at.clone());
    // `expires_at` is a declared `date-time` and is decided exactly as the identifiers
    // are: the schema refuses a value that names no instant, and a session whose expiry
    // cannot be read could never be shown unexpired.
    if !crate::session::names_an_instant(&expires_at) {
        return None;
    }
    Some(
        Session::new(
            declared_session_id(login)?,
            PrincipalId::parse(&login.principal_id.0).ok()?,
            OrganizationId::parse(&login.organization_id.0).ok()?,
            EpochSnapshotRef::parse(&login.epochs.0).ok()?,
            expires_at,
        )
        .with_connection(FederationConnectionId::parse(&login.connection_id.0).ok()?),
    )
}

/// The `mandate.identity.Principal` a provisioning materializes, when every value it
/// carries is one the contract admits.
///
/// The same seam as [`session_of`], for the other record a `mandate.federation` payload
/// creates in this domain, and — like that one — it decides **every declared field of the
/// payload and not only the ones the record keeps**. Three of the four identifiers and the
/// timestamp are parsed and dropped: the record carries none of them, and the reason to
/// read them is the rule [`IdentityLog`] states for the opening arm beside this one, *a
/// payload the closed schema refuses is never appended*. A fold that materialized a record
/// out of an event no conforming producer could have written would be inventing the
/// record, not rebuilding it.
///
/// Four things, and the oracle for the first three is
/// `generated/schema/events/mandate.federation.ExternalPrincipalProvisioned.schema.json`:
///
/// * **The declared lexical form of every identifier.** `organization_id`,
///   `connection_id`, `external_principal_id` and `principal_id` each carry the uuid
///   pattern; `mandate-contract` states structure and not lexical form, so the form is
///   decided here.
/// * **The declared `date-time`.** `linked_at` is read exactly as the opening event's
///   `expires_at` is, with [`crate::session::names_an_instant`].
/// * **Both literals the contract pins.** `federation.yaml` pins `kind: User` and
///   `link_method: ConfiguredFederation`, and
///   `mandate_federation::record::Projection::apply` refuses each separately
///   (`FoldError::ProvisionedKind`, `FoldError::ProvisionedLinkMethod`). `identity.yaml`
///   says what the first means — "the seeding event binds kind to the literal User, so
///   this contract declares a writer for User principals alone".
/// * **The subject the sibling fold reads as a corrupt log.** This one is *not* a schema
///   rule — `mandate.core.ExternalSubject` is an unconstrained string — it is
///   `mandate_federation::record::Projection`'s: "an empty key component is not a key
///   component ... a log written before the commands refused one is read as corrupt rather
///   than collapsed" (`FoldError::EmptySubject`, `FoldError::SubjectNotTrimmed`). Both
///   folds read one log, and a payload one of them calls unreadable is not a payload the
///   other may materialize a record out of.
///
/// `correlation` and `display_name` are the two declared fields with nothing to decide:
/// each is an unconstrained `type: string` in the generated schema and neither fold
/// constrains it further.
///
/// Both matches are exhaustive and carry no wildcard, so a variant added to
/// `mandate.core.PrincipalKind` or `mandate.core.ExternalLinkMethod` does not compile
/// until this answers for it.
fn principal_of(provisioned: &MandateFederationExternalPrincipalProvisioned) -> Option<Principal> {
    let kind = match provisioned.kind {
        MandateCorePrincipalKind::User => PrincipalKind::User,
        MandateCorePrincipalKind::Service
        | MandateCorePrincipalKind::Agent
        | MandateCorePrincipalKind::ServiceAccount => return None,
    };
    match provisioned.link_method {
        MandateCoreExternalLinkMethod::ConfiguredFederation => {}
        MandateCoreExternalLinkMethod::Administrator
        | MandateCoreExternalLinkMethod::AuthenticatedConfirmation
        | MandateCoreExternalLinkMethod::VerifiedMigration
        | MandateCoreExternalLinkMethod::SecuritySupport => return None,
    }
    let id = PrincipalId::parse(&provisioned.principal_id.0).ok()?;
    // Parsed for their form and then dropped: the declared record has no field for any of
    // them, and a payload the closed schema refuses is never appended.
    let _organization = OrganizationId::parse(&provisioned.organization_id.0).ok()?;
    let _connection = FederationConnectionId::parse(&provisioned.connection_id.0).ok()?;
    let _link = ExternalPrincipalId::parse(&provisioned.external_principal_id.0).ok()?;
    if !crate::session::names_an_instant(&Timestamp::new(provisioned.linked_at.clone())) {
        return None;
    }
    let subject = provisioned.subject.0.as_str();
    if subject.trim().is_empty() || subject != subject.trim() {
        return None;
    }
    Some(Principal::new(id, kind, provisioned.display_name.clone()))
}

/// An event log held in memory, and the fold over it.
///
/// The SQLite backend the ADR names is `:memory:`-capable for the same reason: what is
/// proved over this fold is proved over the deployment's.
///
/// # What the host owes this log, in order
///
/// A session's `epochs` handle must already be recorded when the session is opened:
/// append `mandate.identity.EpochSnapshotRecorded` for the snapshot **before** the
/// `SessionOpened` or `mandate.federation.FederationAuthenticated` that names it. An
/// opening that arrives first is refused ([`IdentityLog::try_record`]) rather than
/// admitted, because the snapshot carries no generation of its own and the fold reads each
/// dimension off the log at the recording's position — so the two orders do not describe
/// the same session.
///
/// A target's generation is stated the same way and is enforced the same way: every
/// dimension a snapshot names — the principal, the organization and the connection when it
/// carries one — must already have a `SecurityEpochRecorded` (or an increment) in the log,
/// **including when its generation is zero**, or the recording is refused. A generation
/// that arrives after a snapshot bound it at zero is indistinguishable from the authority
/// advancing, and it makes every session on that snapshot permanently stale.
///
/// Every append is guarded, because there is no other way to reach the events. The
/// vector is not exposed for writing:
///
/// ```compile_fail
/// use mandate_identity::{IdentityEvent, IdentityLog, SessionRevoked};
/// use mandate_types::{SessionId, Uuid};
///
/// let mut log = IdentityLog::new();
/// log.events().push(IdentityEvent::SessionRevoked(SessionRevoked {
///     context: todo!(),
///     id: SessionId::new(Uuid::from_bytes([20; 16])),
/// }));
/// ```
///
/// and the type cannot be assembled around it either:
///
/// ```compile_fail
/// use mandate_identity::IdentityLog;
///
/// let log = IdentityLog {
///     events: Vec::new(),
///     as_of: None,
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IdentityLog {
    events: Vec<IdentityEvent>,
    as_of: Option<Timestamp>,
}

impl IdentityLog {
    /// An empty log, with no evaluation instant.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same log, evaluated as of a declared instant.
    ///
    /// A log that has not been told what time it is cannot certify that a session has
    /// not expired, and [`crate::refresh_session`] fails closed on it.
    #[must_use]
    pub fn with_as_of(self, as_of: Timestamp) -> Self {
        Self {
            as_of: Some(as_of),
            ..self
        }
    }

    /// Seed one event, or refuse it.
    ///
    /// The same append as [`IdentityLog::try_record`], with the refusal discarded rather
    /// than returned. There is no third, unguarded path: both go through
    /// [`IdentityLog::refusal`], and the only other append in this crate is the
    /// compare-and-set in [`SecurityEpochWrite::increment`].
    pub fn record(&mut self, event: IdentityEvent) {
        let _ = self.try_record(event);
    }

    /// Seed one event.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the event would move a target's generation
    /// backwards or leave it where it is, open a session identity the log already
    /// records — whether it currently projects to one or has only been revoked — or
    /// record a snapshot handle the log already holds. The log is unchanged in each
    /// case.
    pub fn try_record(&mut self, event: IdentityEvent) -> Result<(), Denial> {
        if let Some(denial) = self.refusal(&event) {
            return Err(denial);
        }
        self.append(event);
        Ok(())
    }

    /// The one place an event is added to the log.
    fn append(&mut self, event: IdentityEvent) {
        self.events.push(event);
    }

    /// Why an event cannot be appended, if it cannot.
    ///
    /// Each guard reads the recorded history rather than a projection of it: a
    /// projection is a fold of the events that happen to have arrived, so a guard keyed
    /// on one is a guard on the order they arrived in.
    fn refusal(&self, event: &IdentityEvent) -> Option<Denial> {
        let refused = match event {
            IdentityEvent::SecurityEpochRecorded(recorded) => {
                let state = self.current(&recorded.target);
                // A first recording seeds the target. Afterwards a recording must move
                // the generation: one that does not is not an event, and appending it
                // would consume a stream version and invalidate every concurrent
                // writer's compare-and-set token for nothing.
                state.version() > StreamVersion::INITIAL
                    && recorded.generation <= state.generation()
            }
            // Two rules, both on the two opening events.
            //
            // `Revoked` is terminal for the identity, not for one projection of it: an
            // identity any recorded event names has been opened once already. The two
            // opening events are one rule here, not two: a session opened by a federated
            // login is not opened again by a `SessionOpened`, or the other way round.
            //
            // And the snapshot the `epochs` handle names must already be recorded. The
            // handle is what every eligibility decision resolves through, and
            // `mandate.identity.EpochSnapshotRecorded` carries no generation: the fold
            // binds each dimension to what the authority held **at the position the
            // recording appears at**. A recording that lands after the session it is
            // named by would therefore bind a generation the session was never issued
            // against — an increment between the two would be invisible — so an opening
            // whose handle the log does not yet record is refused rather than folded into
            // a session whose epochs are decided by an ordering nobody stated. The
            // ordering obligation this puts on the host is stated on [`IdentityLog`].
            // That the contract carries no generation on the snapshot at all stays filed
            // under `decision-blocker:epoch`.
            IdentityEvent::SessionOpened(opened) => {
                // Every declared form this payload carries, decided exactly as the login
                // arm decides the same fields. The identifiers are parsed types here —
                // `SessionId`, `PrincipalId`, `OrganizationId`, `EpochSnapshotRef` cannot
                // hold a form the contract refuses — and `expires_at` is a `Timestamp`,
                // which carries a lexical form verbatim, so it is the one field a host can
                // get wrong. A payload the closed schema refuses is never appended.
                !crate::session::names_an_instant(&opened.expires_at)
                    || self.records_session(&opened.id)
                    || !self.records_snapshot(&opened.epochs)
            }
            IdentityEvent::FederationAuthenticated(login) => {
                // A payload whose declared forms are not the ones the contract admits
                // materializes no session, and appending it would record a login the fold
                // could never resolve. Fail closed.
                match session_of(login) {
                    None => true,
                    Some(session) => {
                        self.records_session(session.id())
                            || !self.records_snapshot(session.epochs())
                    }
                }
            }
            // The seeding event of `mandate.identity.Principal`, decided the same way the
            // login arm is decided: a payload whose declared forms and pinned literals are
            // not the ones the contract admits materializes no principal, and appending it
            // would record a creation the fold could never resolve. Fail closed.
            //
            // The identity rule is the opening events' rule, for this record: a principal
            // a recorded provisioning already created has been created once, and a second
            // creation would return the record the log holds to its initial state. It is
            // decided over the recorded history and not over a projection of it, because a
            // guard keyed on a projection is a guard on the order events arrived in.
            IdentityEvent::ExternalPrincipalProvisioned(provisioned) => {
                match principal_of(provisioned) {
                    None => true,
                    Some(record) => self.records_principal(record.id()),
                }
            }
            IdentityEvent::EpochSnapshotRecorded(snapshot) => {
                self.records_snapshot(&snapshot.id) || !self.records_every_dimension(snapshot)
            }
            IdentityEvent::SessionRevoked(_) | IdentityEvent::SecurityEpochIncremented(_) => false,
        };
        refused.then(|| Denial::new(DenialReason::Denied))
    }

    /// Whether any recorded event names this session identity.
    fn records_session(&self, id: &SessionId) -> bool {
        self.events
            .iter()
            .any(|event| event.names_session().as_ref() == Some(id))
    }

    /// Whether any recorded event created this principal identity.
    ///
    /// "Created", not "named": an opening names a principal and creates no record for it,
    /// so a session on the explicit-link path never makes a later provisioning of that
    /// principal unrecordable — and never makes one recordable twice either.
    fn records_principal(&self, id: &PrincipalId) -> bool {
        self.events
            .iter()
            .any(|event| event.creates_principal().as_ref() == Some(id))
    }

    /// Whether the log states a generation for every dimension a snapshot names.
    ///
    /// The second half of the ordering obligation [`IdentityLog`] documents. The snapshot
    /// carries no generation of its own, so the fold binds each dimension to what the log
    /// says was in force at the recording's position: a dimension the log has said nothing
    /// about yet binds [`Generation::ZERO`], and a `SecurityEpochRecorded` for it landing
    /// afterwards is indistinguishable from the authority advancing — it makes every
    /// session on that snapshot permanently stale, which is a failure no caller can act on.
    /// So the generation is stated first, explicitly, including when it is zero.
    ///
    /// "States a generation" is the stream having moved at all, which an increment does as
    /// well as a recording: both are the authority speaking about that target.
    fn records_every_dimension(&self, snapshot: &EpochSnapshotRecorded) -> bool {
        let mut dimensions = vec![
            SecurityEpochTarget::Principal(snapshot.principal_id),
            SecurityEpochTarget::Organization(snapshot.organization_id),
        ];
        if let Some(connection) = snapshot.connection_id {
            dimensions.push(SecurityEpochTarget::Federation(connection));
        }
        dimensions
            .iter()
            .all(|target| self.current(target).version() > StreamVersion::INITIAL)
    }

    /// Whether any recorded event names this snapshot handle.
    fn records_snapshot(&self, id: &EpochSnapshotRef) -> bool {
        self.events.iter().any(|event| match event {
            IdentityEvent::EpochSnapshotRecorded(snapshot) => snapshot.id == *id,
            _ => false,
        })
    }

    /// Every recorded event, in order.
    #[must_use]
    pub fn events(&self) -> &[IdentityEvent] {
        &self.events
    }
}

impl IdentityRead for IdentityLog {
    /// The session an event opened and every later event moved.
    ///
    /// Two events open one: `mandate.identity.SessionOpened` for a session opened without
    /// a federation connection, and `mandate.federation.FederationAuthenticated` for the
    /// federated login, whose accepted outcome creates the record. Both carry the whole
    /// declared record, so the fold materializes it from the event alone and consults no
    /// command input, no response and no request context.
    fn resolve(&self, id: &SessionId) -> Option<Session> {
        let mut resolved: Option<Session> = None;
        for event in &self.events {
            match event {
                IdentityEvent::SessionOpened(opened) if opened.id == *id && resolved.is_none() => {
                    // `Revoked` is declared terminal and no transition leaves it, so a
                    // replayed open of a session the fold already holds changes nothing.
                    resolved = Some(opened.session());
                }
                IdentityEvent::FederationAuthenticated(login) if resolved.is_none() => {
                    if let Some(session) = session_of(login).filter(|s| s.id() == id) {
                        resolved = Some(session);
                    }
                }
                IdentityEvent::SessionRevoked(revoked) if revoked.id == *id => {
                    resolved = resolved.map(Session::revoke);
                }
                _ => {}
            }
        }
        resolved
    }

    /// The principal its seeding event created.
    ///
    /// One event creates it — `mandate.federation.ExternalPrincipalProvisioned`, declared
    /// as this record's writer in `identity.yaml` — and it carries the whole declared
    /// record, so the fold materializes it from that event alone and consults no command
    /// input, no response and no request context. The first creation of an identity is the
    /// record: a second is refused by [`IdentityLog::try_record`], and one that reached the
    /// log another way does not rewrite the first.
    ///
    /// A principal this log holds no creation for answers `None`. That is the
    /// explicit-link path, where `LinkExternalPrincipal` names a principal no event of this
    /// contract creates.
    fn principal(&self, id: &PrincipalId) -> Option<Principal> {
        self.events.iter().find_map(|event| match event {
            IdentityEvent::ExternalPrincipalProvisioned(provisioned) => {
                principal_of(provisioned).filter(|record| record.id() == id)
            }
            _ => None,
        })
    }

    fn current(&self, target: &SecurityEpochTarget) -> EpochState {
        generations_at(&self.events, target)
    }

    fn as_of(&self) -> Option<Timestamp> {
        self.as_of.clone()
    }

    /// The snapshot a handle refers to, with the generations the authority held when it
    /// was recorded.
    ///
    /// `mandate.identity.EpochSnapshotRecorded` declares the record's own fields and no
    /// generation, because the declared record carries none. The per-dimension values the
    /// addendum requires are therefore read off the log: a snapshot binds what each of its
    /// dimensions was at the position the recording appears at, which is what "the
    /// generations a session was issued against" means for a log. Nothing invents them,
    /// and a replay of the same log binds the same values.
    fn snapshot(&self, id: &EpochSnapshotRef) -> Option<SecurityEpochSnapshot> {
        for (position, event) in self.events.iter().enumerate() {
            // An `EpochSnapshotRef` is an immutable record handle: the first recording
            // of it is the record, and a later one does not rewrite it.
            let IdentityEvent::EpochSnapshotRecorded(recorded) = event else {
                continue;
            };
            if recorded.id != *id {
                continue;
            }
            let held = &self.events[..position];
            let snapshot = SecurityEpochSnapshot::new(
                recorded.id,
                recorded.principal_id,
                generations_at(held, &SecurityEpochTarget::Principal(recorded.principal_id))
                    .generation(),
                recorded.organization_id,
                generations_at(
                    held,
                    &SecurityEpochTarget::Organization(recorded.organization_id),
                )
                .generation(),
            );
            return Some(match recorded.connection_id {
                Some(connection) => snapshot.with_federation(
                    connection,
                    generations_at(held, &SecurityEpochTarget::Federation(connection)).generation(),
                ),
                None => snapshot,
            });
        }
        None
    }
}

/// One target's authoritative generation over a run of events, and the version it is at.
///
/// The whole log answers [`IdentityRead::current`]; a prefix of it answers what a snapshot
/// recorded at that point was issued against.
fn generations_at(events: &[IdentityEvent], target: &SecurityEpochTarget) -> EpochState {
    let mut generation = Generation::ZERO;
    let mut version = StreamVersion::INITIAL;
    for event in events {
        match event {
            IdentityEvent::SecurityEpochRecorded(recorded) if recorded.target == *target => {
                // The authoritative generation never moves backwards, whoever built the
                // log: a recorded value below the folded one is not applied.
                if recorded.generation > generation {
                    generation = recorded.generation;
                }
                version = version.advance();
            }
            IdentityEvent::SecurityEpochIncremented(incremented)
                if incremented.target() == target =>
            {
                // The write port refuses to advance past the maximum, so no log it
                // produced holds this event at the maximum; a hand-recorded one that
                // does holds there rather than wrapping.
                generation = generation.advance().unwrap_or(generation);
                version = version.advance();
            }
            _ => {}
        }
    }
    EpochState::new(generation, version)
}

impl SecurityEpochWrite for IdentityLog {
    fn increment(
        &mut self,
        context: &VerifiedContext,
        target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial> {
        let state = self.current(target);
        if state.version() != expected {
            return Err(Denial::new(DenialReason::Unavailable));
        }
        let Some(generation) = state.generation().advance() else {
            return Err(Denial::new(DenialReason::Denied));
        };
        let version = state.version().advance();
        if version <= state.version() {
            return Err(Denial::new(DenialReason::Unavailable));
        }
        self.append(IdentityEvent::SecurityEpochIncremented(
            crate::SecurityEpochIncremented::new(context.clone(), target.clone()),
        ));
        Ok(EpochState::new(generation, version))
    }
}
