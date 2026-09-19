//! Principal, linking and session lifecycle.
//!
//! What this crate realizes is the exact session security generation: a session records
//! the principal, organization and federation generations it was issued against, and a
//! refresh is refused when any applicable one of them no longer matches the authoritative
//! value. An increment on one subject leaves every other subject's sessions untouched.
//!
//! # The generation
//!
//! The contract declares `generation` as an ESS `Integer` constrained `generation >= 0`
//! on `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch` and `FederationSecurityEpoch`
//! (`systems/mandate/domains/identity.yaml`). ESS 0.25.0 has no unsigned primitive, so
//! `Integer` is the recorded stand-in for the addendum's `u64`. [`Generation`] holds the
//! non-negative constraint by construction and refuses to advance past its maximum, so a
//! generation is never wrapped and never reused.
//!
//! The authoritative generation also never moves backwards: the fold refuses a recorded
//! value below the one it already holds, so a generation that has been issued against
//! cannot be handed out again and a snapshot once refused as stale stays refused. At
//! [`Generation::MAX`] the increment denies for that target from then on; the recovery
//! is not a rewind but the revocation of every session whose snapshot names that target.
//!
//! # What a refresh decides
//!
//! The revocation state, the snapshot binding, the applicable generations, and the
//! declared expiry — `RefreshSession` denies a record that is "expired/revoked". The
//! instant is supplied by the reader ([`IdentityRead::as_of`]); a reader that supplies
//! none cannot certify that a session has not expired, and [`refresh_session`] fails
//! closed on it.
//!
//! # Why `Session` and `SecurityEpochSnapshot` live here
//!
//! Both are projections of this crate's fold, not canonical `mandate.core.*` types.
//! `mandate_types::canonical_record!` mints `mandate.core.<Name>` by construction, so a
//! `mandate.identity.*` record cannot go through it; `mandate-model` realizes exactly the
//! four records the accepted account assigns it, and `mandate-types` accepts exactly the
//! compiled `mandate.core.*` projection. Under
//! `docs/adr/0009-event-sourced-persistence.md` a state record is a projection in any
//! case. The vocabulary both records need is public in `mandate-types`.
//!
//! # A snapshot behind the authority is refused
//!
//! ```
//! use mandate_identity::{
//!     EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
//!     IncrementSecurityEpoch, SecurityEpochRecorded, SessionOpened, refresh_session,
//! };
//! use mandate_types::{
//!     Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, OrganizationId,
//!     PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
//! };
//!
//! let principal = PrincipalId::new(Uuid::from_bytes([1; 16]));
//! let organization = OrganizationId::new(Uuid::from_bytes([2; 16]));
//! let handle = EpochSnapshotRef::new(Uuid::from_bytes([3; 16]));
//! let session = SessionId::new(Uuid::from_bytes([4; 16]));
//! let target = SecurityEpochTarget::Principal(principal);
//!
//! let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));
//! log.record(IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded {
//!     target: target.clone(),
//!     generation: Generation::new(41).unwrap(),
//! }));
//! log.record(IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded {
//!     target: SecurityEpochTarget::Organization(organization),
//!     generation: Generation::ZERO,
//! }));
//! // The snapshot carries no generation: it is bound to what each dimension held at the
//! // position it was recorded at, which is 41 for the principal and 0 for the
//! // organization. Both dimensions have stated a generation by now, which is what the log
//! // requires of a recording.
//! log.record(IdentityEvent::EpochSnapshotRecorded(EpochSnapshotRecorded {
//!     id: handle,
//!     principal_id: principal,
//!     organization_id: organization,
//!     connection_id: None,
//! }));
//! log.record(IdentityEvent::SessionOpened(SessionOpened {
//!     id: session,
//!     principal_id: principal,
//!     organization_id: organization,
//!     connection_id: None,
//!     epochs: handle,
//!     expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
//! }));
//!
//! assert!(refresh_session(&log, &session).is_ok());
//!
//! let context = VerifiedContext {
//!     subject: principal,
//!     actor: None,
//!     organization,
//!     audience: Audience::new("mandate"),
//!     credential: CredentialId::new(Uuid::from_bytes([5; 16])),
//!     delegation: None,
//!     execution: None,
//!     correlation: CorrelationId::new("correlation"),
//! };
//! let expected = log.current(&target).version();
//! IncrementSecurityEpoch::new(context, target.clone())
//!     .execute(&mut log, expected)
//!     .unwrap();
//!
//! assert_eq!(log.current(&target).generation(), Generation::new(42).unwrap());
//! assert_eq!(
//!     refresh_session(&log, &session).unwrap_err().reason(),
//!     DenialReason::StaleEpoch,
//! );
//! ```
//!
//! # A holder of the read port cannot advance a generation
//!
//! ```compile_fail
//! use mandate_identity::{IdentityRead, StreamVersion};
//! use mandate_types::{SecurityEpochTarget, VerifiedContext};
//!
//! fn advance(
//!     epochs: &dyn IdentityRead,
//!     context: &VerifiedContext,
//!     target: &SecurityEpochTarget,
//! ) {
//!     epochs
//!         .increment(context, target, StreamVersion::INITIAL)
//!         .unwrap();
//! }
//! ```

use core::fmt;

use mandate_types::DenialReason;

mod generation;
mod increment;
mod port;
mod session;
mod snapshot;

pub use generation::Generation;
pub use increment::{IncrementSecurityEpoch, SecurityEpochIncremented};
pub use port::{
    EpochSnapshotRecorded, EpochState, IdentityEvent, IdentityLog, IdentityRead, Principal,
    PrincipalState, SecurityEpochRecorded, SecurityEpochWrite, StreamVersion,
};
pub use session::{
    Session, SessionOpened, SessionRefreshed, SessionRevoked, SessionState, refresh_session,
    revoke_session,
};
pub use snapshot::{Eligibility, EpochDimension, SecurityEpochSnapshot};

// Every `mandate.identity` element this crate realizes, against the item that realizes
// it. Each entry is expanded into a `use` of the named symbol, so a registry line whose
// symbol was renamed, moved or deleted does not compile
// (`crates/mandate-types/src/macros.rs`), and
// `crates/mandate-identity/tests/contract_agreement.rs` reads every name on the left back
// out of `generated/ir/system.json`.
//
// What this crate does *not* realize is [`ESS_UNREALIZED`], named element by element with
// the reason: a registry that lists what is covered and waves at the rest overstates
// itself in the one direction that matters, and
// `crates/mandate-identity/tests/contract_agreement.rs` decides both directions against
// the contract's own index.
mandate_types::realizes! {
    "mandate.identity.RevokeSession" => crate::session::revoke_session,
    "mandate.identity.RefreshSession" => crate::session::refresh_session,
    "mandate.identity.IncrementSecurityEpoch" => crate::increment::IncrementSecurityEpoch,
    "mandate.identity.SessionOpened" => crate::session::SessionOpened,
    "mandate.identity.SessionRevoked" => crate::session::SessionRevoked,
    "mandate.identity.SessionRefreshed" => crate::session::SessionRefreshed,
    "mandate.identity.EpochSnapshotRecorded" => crate::port::EpochSnapshotRecorded,
    "mandate.identity.SecurityEpochRecorded" => crate::port::SecurityEpochRecorded,
    "mandate.identity.SecurityEpochIncremented" => crate::increment::SecurityEpochIncremented,
    "mandate.identity.Session" => crate::session::Session,
    // The record no command in this contract creates. `identity.yaml`'s header declares
    // its writer instead — `mandate.federation.ExternalPrincipalProvisioned`, which
    // carries the whole record — and the fold materializes it from that event alone
    // ([`IdentityRead::principal`]).
    "mandate.identity.Principal" => crate::port::Principal,
    "mandate.identity.Principal.State" => crate::port::PrincipalState,
    "mandate.identity.SecurityEpochSnapshot" => crate::snapshot::SecurityEpochSnapshot,
    // One projection realizes all three generation records: the fold *is* the record
    // (`docs/adr/0009-event-sourced-persistence.md`), each is declared as one
    // non-negative `generation` keyed by its owning identity, and
    // [`IdentityRead::current`] answers that generation for a `SecurityEpochTarget`
    // together with the stream version a compare-and-set is made against.
    // `crates/mandate-identity/tests/replay.rs` rebuilds all three from their events.
    "mandate.identity.PrincipalSecurityEpoch" => crate::port::EpochState,
    "mandate.identity.OrganizationSecurityEpoch" => crate::port::EpochState,
    "mandate.identity.FederationSecurityEpoch" => crate::port::EpochState,
    "mandate.identity.Denied" => crate::Denial,
    "mandate.identity.Session.State" => crate::session::SessionState,
}

/// Every declared `mandate.identity` element this crate does **not** realize, with the
/// reason.
///
/// A coverage registry that names what it covers and says nothing about the rest is read as
/// a claim about the whole domain. This is the other half of [`ESS_REALIZATIONS`], and
/// `crates/mandate-identity/tests/contract_agreement.rs` decides the pair against
/// `generated/ir/system.json` in both directions: an element this list names and the
/// registry also realizes is a contradiction, and an element neither one names is an
/// element nobody accounted for.
///
/// Three groups, and none is an oversight:
///
/// * The `RefreshCredential` record, its lifecycle move and the commands that make them.
///   This crate folds sessions, principals and generations; that record is not projected
///   here.
/// * The principal's *disablement*. The record itself is realized — the fold materializes
///   it from the seeding event `identity.yaml` declares — but no handler here decides
///   `DisablePrincipal`, and `mandate.identity.PrincipalDisabled` is not folded, so
///   [`IdentityRead::principal`] answers the declared initial state for every principal a
///   seeding event created. A reader that needs the disablement composes this port over
///   the store that carries that event, which is the seam
///   `mandate_federation::PrincipalStore::state_of` documents from the other side.
/// * The single-state lifecycles. `SecurityEpochSnapshot` and the three generation records
///   each declare exactly one state, `Recorded`, which no value in this crate names: there
///   is no transition to fold and an enum of one variant would decide nothing. The records
///   themselves are realized.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[
    (
        "mandate.identity.DisablePrincipal",
        "no handler here decides it; the fold materializes the created record and folds no \
         disablement",
    ),
    (
        "mandate.identity.PrincipalDisabled",
        "declared and not folded here: no handler in this crate emits it, so the record's \
         state is the declared initial one",
    ),
    (
        "mandate.identity.RefreshCredential",
        "not projected here; no handler in this crate writes one",
    ),
    (
        "mandate.identity.RefreshCredentialRevoked",
        "the RefreshCredential record is not projected here",
    ),
    (
        "mandate.identity.RefreshCredential.State",
        "the RefreshCredential record is not projected here",
    ),
    (
        "mandate.identity.RevokeRefreshCredential",
        "the RefreshCredential record is not projected here",
    ),
    (
        "mandate.identity.SecurityEpochSnapshot.State",
        "a single-state lifecycle: no transition to fold",
    ),
    (
        "mandate.identity.PrincipalSecurityEpoch.State",
        "a single-state lifecycle: no transition to fold",
    ),
    (
        "mandate.identity.OrganizationSecurityEpoch.State",
        "a single-state lifecycle: no transition to fold",
    ),
    (
        "mandate.identity.FederationSecurityEpoch.State",
        "a single-state lifecycle: no transition to fold",
    ),
];

/// Which declared refusing outcome a [`Denial`] is.
///
/// A command that moves an entity along its lifecycle declares **two** error outcomes,
/// not one: the external `denied` and the `wrong-state` taken "when the subject is in a
/// state none of that command's declared moves start from", which "reports the same
/// `Denied` error and renders as HTTP 409 in the OpenAPI projection rather than the 502
/// an external denial renders as" (`docs/architecture/command-obligations.md`).
/// `RevokeSession`, `DisablePrincipal` and `RevokeRefreshCredential` each declare one.
///
/// The distinction cannot live in [`DenialReason`]: that enum is the contract's, it is
/// closed, and it declares no wrong-state reason. [`RefusedOutcome::ir_name`] is the name
/// the outcome carries in `generated/ir/system.json`, which is what
/// `crates/mandate-identity/tests/emitted_events.rs` looks the refusal up by.
///
/// `mandate-federation` declares the same enum for the same reason. The shared home for
/// both is `mandate-types`, which neither this story nor its wave may edit; until one
/// does, the duplication is two declarations of one contract rule rather than two rules.
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

/// `mandate.identity.Denied`: fail closed; no credential, authority or lifecycle
/// mutation on refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    reason: DenialReason,
    outcome: RefusedOutcome,
}

impl Denial {
    /// The refusal carrying a declared reason, through the declared `denied` outcome.
    #[must_use]
    pub const fn new(reason: DenialReason) -> Self {
        Self {
            reason,
            outcome: RefusedOutcome::Denied,
        }
    }

    /// The refusal through the declared `wrong-state` outcome: the named record is in a
    /// state none of the command's declared moves start from.
    #[must_use]
    pub const fn wrong_state(reason: DenialReason) -> Self {
        Self {
            reason,
            outcome: RefusedOutcome::WrongState,
        }
    }

    /// The declared reason.
    #[must_use]
    pub const fn reason(&self) -> DenialReason {
        self.reason
    }

    /// Which declared refusing outcome this is.
    #[must_use]
    pub const fn outcome(&self) -> RefusedOutcome {
        self.outcome
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {:?}", self.outcome.ir_name(), self.reason)
    }
}

impl std::error::Error for Denial {}
