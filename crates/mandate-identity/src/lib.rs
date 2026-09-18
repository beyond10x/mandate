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
//!     Generation, IdentityEvent, IdentityLog, IdentityRead, IncrementSecurityEpoch,
//!     SecurityEpochSnapshot, Session, refresh_session,
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
//! log.record(IdentityEvent::SecurityEpochRecorded {
//!     target: target.clone(),
//!     generation: Generation::new(41).unwrap(),
//! });
//! log.record(IdentityEvent::EpochSnapshotRecorded(SecurityEpochSnapshot::new(
//!     handle,
//!     principal,
//!     Generation::new(41).unwrap(),
//!     organization,
//!     Generation::ZERO,
//! )));
//! log.record(IdentityEvent::SessionOpened(Session::new(
//!     session,
//!     principal,
//!     organization,
//!     handle,
//!     Timestamp::new("2026-12-31T00:00:00Z"),
//! )));
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
//! use mandate_types::SecurityEpochTarget;
//!
//! fn advance(epochs: &dyn IdentityRead, target: &SecurityEpochTarget) {
//!     epochs.increment(target, StreamVersion::INITIAL).unwrap();
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
    EpochState, IdentityEvent, IdentityLog, IdentityRead, SecurityEpochWrite, StreamVersion,
};
pub use session::{Session, SessionRefreshed, SessionState, refresh_session};
pub use snapshot::{Eligibility, EpochDimension, SecurityEpochSnapshot};

/// `mandate.identity.Denied`: fail closed; no credential, authority or lifecycle
/// mutation on refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    reason: DenialReason,
}

impl Denial {
    /// The refusal carrying a declared reason.
    #[must_use]
    pub const fn new(reason: DenialReason) -> Self {
        Self { reason }
    }

    /// The declared reason.
    #[must_use]
    pub const fn reason(&self) -> DenialReason {
        self.reason
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "denied: {:?}", self.reason)
    }
}

impl std::error::Error for Denial {}
