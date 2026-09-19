//! Adversary: an expired session refreshes.
//!
//! `systems/mandate/domains/identity.yaml:273-275` declares `RefreshSession`'s `denied`
//! outcome for, among others, "record is expired/revoked". `mandate.identity.Session`
//! carries `expires_at: Timestamp` (`identity.yaml:43-44`), and this crate's projection
//! carries it too and documents it as "When the session stops being refreshable"
//! (`crates/mandate-identity/src/session.rs:123-127`).
//!
//! `Session::refresh` (`src/session.rs:173-186`) reads the revocation state and the epoch
//! snapshot and never reads `expires_at`, so a session whose expiry has passed is
//! accepted. Its signature takes no instant, so the declared denial cannot be reached
//! through it at all.
//!
//! `Timestamp` derives `Ord` and exposes `as_str` (`crates/mandate-types/src/value.rs:214-249`),
//! so comparing two `Z`-form instants lexically is available without arithmetic; the
//! missing piece is the instant to compare against, not the comparison.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, SecurityEpochRecorded,
    SessionOpened, refresh_session,
};
use mandate_types::{
    EpochSnapshotRef, OrganizationId, PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn handle() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(10))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

/// Every generation matches the authority; the only thing wrong with this session is that
/// it expired six years before the world it is refreshed in.
fn expired_world() -> IdentityLog {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Principal(principal()),
            generation: generation(3),
        },
    ));
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: SecurityEpochTarget::Organization(organization()),
            generation: generation(7),
        },
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle(),
            principal_id: principal(),
            organization_id: organization(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_id(),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: handle(),
        expires_at: Timestamp::new("2020-01-01T00:00:00Z"),
    }));
    log
}

#[test]
fn a_session_past_its_declared_expiry_does_not_refresh() {
    let log = expired_world();

    assert!(
        refresh_session(&log, &session_id()).is_err(),
        "`RefreshSession` denies an expired record (identity.yaml:274) and \
         `Session::expires_at` is 'when the session stops being refreshable'"
    );
}

#[test]
fn the_declared_expiry_is_comparable_without_arithmetic() {
    // The reason recorded for leaving expiry unevaluated is that `Timestamp` is a lexical
    // string. It is, and it is also `Ord`: the two instants this crate's own fixtures use
    // order correctly. What `Session::refresh` lacks is a parameter for "now".
    assert!(Timestamp::new("2020-01-01T00:00:00Z") < Timestamp::new("2026-09-18T00:00:00Z"));
}
