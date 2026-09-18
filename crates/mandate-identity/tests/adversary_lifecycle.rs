//! Adversary: `Revoked` is a terminal state and the fold leaves it.
//!
//! `systems/mandate/domains/identity.yaml` declares `mandate.identity.Session` with
//! `terminal: [Revoked]` and exactly one transition, `revoke: Active -> Revoked`. A
//! terminal state is one no transition leaves. `IdentityLog::resolve`
//! (`crates/mandate-identity/src/port.rs:164-178`) rebuilds the projection from whichever
//! `SessionOpened` it saw last, so a second `SessionOpened` for an identity that was
//! already revoked puts the session back into `Active` and it refreshes again.
//!
//! The log is append-only (`docs/adr/0009-event-sourced-persistence.md`) and this crate
//! emits no `SessionOpened` itself, so the duplicate comes from the host: an at-least-once
//! append, or a retry after a partial write.

use mandate_identity::{
    Generation, IdentityEvent, IdentityLog, IdentityRead, SecurityEpochSnapshot, Session,
    SessionState, refresh_session,
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

fn opened() -> IdentityEvent {
    IdentityEvent::SessionOpened(Session::new(
        session_id(),
        principal(),
        organization(),
        handle(),
        Timestamp::new("2026-09-18T00:00:00Z"),
    ))
}

/// One principal, one organization, one snapshot that matches the authority exactly, and
/// one session against it.
fn world() -> IdentityLog {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Principal(principal()),
        generation: generation(3),
    });
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Organization(organization()),
        generation: generation(7),
    });
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            handle(),
            principal(),
            generation(3),
            organization(),
            generation(7),
        ),
    ));
    log.record(opened());
    log
}

#[test]
fn a_replayed_session_opened_does_not_leave_the_terminal_revoked_state() {
    let mut log = world();
    log.record(IdentityEvent::SessionRevoked(session_id()));
    assert_eq!(
        log.resolve(&session_id())
            .expect("the fold records the session")
            .state(),
        SessionState::Revoked,
        "the revocation is folded"
    );

    // The host appends the same `SessionOpened` a second time: an at-least-once delivery,
    // or a retry after a partial write. Nothing in the contract lets it leave `Revoked`.
    log.record(opened());

    assert_eq!(
        log.resolve(&session_id())
            .expect("the fold records the session")
            .state(),
        SessionState::Revoked,
        "`Revoked` is declared terminal; a replayed `SessionOpened` must not reopen it"
    );
}

#[test]
fn a_replayed_session_opened_does_not_make_a_revoked_session_refreshable_again() {
    let mut log = world();
    log.record(IdentityEvent::SessionRevoked(session_id()));
    assert!(
        refresh_session(&log, &session_id()).is_err(),
        "a revoked session does not refresh"
    );

    log.record(opened());

    assert!(
        refresh_session(&log, &session_id()).is_err(),
        "a revoked session does not refresh, however many times it was opened"
    );
}
