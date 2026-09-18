//! The substrate the epoch cases run on: the read port as a fold over recorded events,
//! and the write port as a compare-and-set on the expected stream version
//! (`docs/adr/0009-event-sourced-persistence.md`, `decision-blocker:epoch-atomicity`).

use mandate_identity::{
    EpochState, Generation, IdentityEvent, IdentityLog, IdentityRead, SecurityEpochSnapshot,
    SecurityEpochWrite, Session, SessionState, StreamVersion,
};
use mandate_types::{
    DenialReason, EpochSnapshotRef, OrganizationId, PrincipalId, SecurityEpochTarget, SessionId,
    Timestamp, Uuid,
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

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

fn session() -> Session {
    Session::new(
        SessionId::new(uuid(20)),
        principal(),
        organization(),
        EpochSnapshotRef::new(uuid(10)),
        Timestamp::new("2026-09-18T00:00:00Z"),
    )
}

fn snapshot() -> SecurityEpochSnapshot {
    SecurityEpochSnapshot::new(
        EpochSnapshotRef::new(uuid(10)),
        principal(),
        generation(3),
        organization(),
        generation(7),
    )
}

#[test]
fn the_read_port_folds_a_recorded_session_out_of_the_event_vec() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionOpened(session()));

    let resolved = log
        .resolve(&SessionId::new(uuid(20)))
        .expect("the session was recorded");
    assert_eq!(resolved, session());
    assert_eq!(resolved.state(), SessionState::Active);
    assert_eq!(log.events().len(), 1);
}

#[test]
fn the_read_port_folds_a_revocation_into_the_resolved_session() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionOpened(session()));
    log.record(IdentityEvent::SessionRevoked(SessionId::new(uuid(20))));

    let resolved = log
        .resolve(&SessionId::new(uuid(20)))
        .expect("nothing is deleted; the state is folded");
    assert_eq!(resolved.state(), SessionState::Revoked);
}

#[test]
fn a_session_that_was_never_recorded_does_not_resolve() {
    let log = IdentityLog::new();

    assert!(log.resolve(&SessionId::new(uuid(20))).is_none());
    assert!(log.snapshot(&EpochSnapshotRef::new(uuid(10))).is_none());
}

#[test]
fn the_read_port_resolves_a_snapshot_by_its_handle() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::EpochSnapshotRecorded(snapshot()));

    assert_eq!(
        log.snapshot(&EpochSnapshotRef::new(uuid(10))),
        Some(snapshot())
    );
    assert!(log.snapshot(&EpochSnapshotRef::new(uuid(11))).is_none());
}

#[test]
fn a_target_with_no_recorded_epoch_reads_as_generation_zero_at_the_initial_version() {
    let log = IdentityLog::new();
    let state = log.current(&SecurityEpochTarget::Principal(principal()));

    assert_eq!(state.generation(), Generation::ZERO);
    assert_eq!(state.version(), StreamVersion::INITIAL);
    assert_eq!(
        state,
        EpochState::new(Generation::ZERO, StreamVersion::new(0))
    );
}

#[test]
fn an_advance_through_the_write_port_is_visible_through_the_read_port() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(41),
    });

    let before = log.current(&target);
    assert_eq!(before.generation(), generation(41));
    assert_eq!(before.version(), StreamVersion::new(1));

    let after = log
        .increment(&target, before.version())
        .expect("the stream is at the expected version");

    assert_eq!(after.generation(), generation(42));
    assert_eq!(after.version(), StreamVersion::new(2));
    assert_eq!(log.current(&target), after);
}

#[test]
fn the_write_port_refuses_an_expected_version_the_stream_has_moved_past() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(41),
    });
    let stale_version = log.current(&target).version();
    log.increment(&target, stale_version)
        .expect("the first writer commits");

    let refused = log
        .increment(&target, stale_version)
        .expect_err("the second writer read before the first committed");

    assert_eq!(refused.reason(), DenialReason::Unavailable);
    assert_eq!(log.current(&target).generation(), generation(42));
}

#[test]
fn each_target_keeps_its_own_stream_version() {
    let principal_target = SecurityEpochTarget::Principal(principal());
    let organization_target = SecurityEpochTarget::Organization(organization());
    let mut log = IdentityLog::new();

    log.increment(&principal_target, StreamVersion::INITIAL)
        .expect("an unrecorded target starts at the initial version");

    assert_eq!(
        log.current(&principal_target).version(),
        StreamVersion::new(1)
    );
    assert_eq!(
        log.current(&organization_target).version(),
        StreamVersion::INITIAL
    );
    assert_eq!(
        log.current(&organization_target).generation(),
        Generation::ZERO
    );
}

#[test]
fn the_read_port_is_usable_behind_a_shared_reference() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionOpened(session()));
    let port: &dyn IdentityRead = &log;

    assert!(port.resolve(&SessionId::new(uuid(20))).is_some());
    assert_eq!(
        port.current(&SecurityEpochTarget::Principal(principal()))
            .generation(),
        Generation::ZERO
    );
}

#[test]
fn the_fold_refuses_a_recorded_generation_below_the_one_it_already_holds() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(42),
    });

    let refused = log
        .try_record(IdentityEvent::SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(41),
        })
        .expect_err("the authoritative generation never moves backwards");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(log.current(&target).generation(), generation(42));
    assert_eq!(log.events().len(), 1, "the refused event is not appended");

    // The infallible form refuses the same event and discards the refusal.
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: Generation::ZERO,
    });
    assert_eq!(log.current(&target).generation(), generation(42));
    assert_eq!(log.events().len(), 1);
}

#[test]
fn the_fold_refuses_a_second_opening_of_a_session_it_already_records() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionOpened(session()));
    log.record(IdentityEvent::SessionRevoked(SessionId::new(uuid(20))));

    let refused = log
        .try_record(IdentityEvent::SessionOpened(session()))
        .expect_err("`Revoked` is terminal; a session is opened once");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.resolve(&SessionId::new(uuid(20)))
            .expect("the fold records the session")
            .state(),
        SessionState::Revoked
    );
}

#[test]
fn the_fold_refuses_a_second_recording_of_a_snapshot_handle() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::EpochSnapshotRecorded(snapshot()));

    let rewritten = SecurityEpochSnapshot::new(
        EpochSnapshotRef::new(uuid(10)),
        principal(),
        generation(9),
        organization(),
        generation(9),
    );
    let refused = log
        .try_record(IdentityEvent::EpochSnapshotRecorded(rewritten))
        .expect_err("an `EpochSnapshotRef` is an immutable record handle");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.snapshot(&EpochSnapshotRef::new(uuid(10))),
        Some(snapshot())
    );
}

#[test]
fn a_reader_supplies_an_instant_only_when_it_was_told_one() {
    let undated = IdentityLog::new();
    let dated = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));

    assert_eq!(undated.as_of(), None);
    assert_eq!(dated.as_of(), Some(Timestamp::new("2026-09-18T00:00:00Z")));
}

#[test]
fn advancing_any_version_the_public_constructor_can_name_yields_a_greater_one() {
    assert_eq!(StreamVersion::INITIAL.advance(), StreamVersion::new(1));
    assert!(StreamVersion::new(u64::MAX).advance() > StreamVersion::new(u64::MAX));
    assert_eq!(
        StreamVersion::new(u64::MAX).advance().get(),
        u128::from(u64::MAX) + 1
    );
}

#[test]
fn re_recording_the_generation_a_target_already_holds_is_refused_and_costs_no_version() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(5),
    });
    let before = log.current(&target);

    let refused = log
        .try_record(IdentityEvent::SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(5),
        })
        .expect_err("a recording that moves nothing is not an event");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.current(&target),
        before,
        "a refused recording consumes no version, so no writer's token is invalidated"
    );
    assert_eq!(log.events().len(), 1);

    // The token a writer read before the attempt still commits.
    log.increment(&target, before.version())
        .expect("the stream is still at the version the writer read");
}

#[test]
fn an_opening_that_arrives_after_a_recorded_revocation_is_refused() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionRevoked(SessionId::new(uuid(20))));

    let refused = log
        .try_record(IdentityEvent::SessionOpened(session()))
        .expect_err("`Revoked` is terminal for the identity, not for one projection of it");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.resolve(&SessionId::new(uuid(20))).map(|s| s.state()),
        None,
        "the revocation of a session the fold never opened projects to nothing"
    );
}

#[test]
fn every_seeding_path_refuses_exactly_what_the_fallible_one_refuses() {
    let target = SecurityEpochTarget::Principal(principal());
    let refusals = [
        IdentityEvent::SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::ZERO,
        },
        IdentityEvent::SessionOpened(session()),
        IdentityEvent::EpochSnapshotRecorded(snapshot()),
    ];

    let mut seeded = IdentityLog::new();
    seeded.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(5),
    });
    seeded.record(IdentityEvent::SessionOpened(session()));
    seeded.record(IdentityEvent::EpochSnapshotRecorded(snapshot()));
    let expected = seeded.clone();

    for event in refusals {
        let mut fallible = seeded.clone();
        assert!(
            fallible.try_record(event.clone()).is_err(),
            "{event:?} is refused"
        );
        assert_eq!(fallible, expected, "a refused event is not appended");

        let mut infallible = seeded.clone();
        infallible.record(event);
        assert_eq!(
            infallible, expected,
            "the infallible seeding path refuses what the fallible one refuses"
        );
    }
}
