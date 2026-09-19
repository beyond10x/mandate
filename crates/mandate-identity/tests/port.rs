//! The substrate the epoch cases run on: the read port as a fold over recorded events,
//! and the write port as a compare-and-set on the expected stream version
//! (`docs/adr/0009-event-sourced-persistence.md`, `decision-blocker:epoch-atomicity`).

use mandate_identity::{
    EpochSnapshotRecorded, EpochState, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded, SecurityEpochSnapshot, SecurityEpochWrite, Session, SessionOpened,
    SessionRevoked, SessionState, StreamVersion,
};
use mandate_testkit::contract::check_event_conforms;
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, FederationConnectionId,
    OrganizationId, PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
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

/// The same session as the declared payload that opens it.
fn opened() -> SessionOpened {
    SessionOpened {
        id: SessionId::new(uuid(20)),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
        epochs: EpochSnapshotRef::new(uuid(10)),
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
    }
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

/// The same snapshot as the declared payload that records it.
///
/// The payload carries the record's own fields and no generation: the contract declares
/// none on `mandate.identity.SecurityEpochSnapshot`, so the fold binds each dimension to
/// what the authority held at the position the recording appears at. `world()` seeds those
/// generations first, so the record this event rebuilds is `snapshot()`.
fn recorded_snapshot() -> EpochSnapshotRecorded {
    EpochSnapshotRecorded {
        id: EpochSnapshotRef::new(uuid(10)),
        principal_id: principal(),
        organization_id: organization(),
        connection_id: None,
    }
}

/// The verified context `RevokeSession` is evaluated in. `mandate.identity.SessionRevoked`
/// declares one (`context: input.context`), so every recorded revocation carries it.
fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// A log whose snapshot recording precedes the session that names it, which is the order
/// `IdentityLog` requires of a host: an opening whose `epochs` handle the log does not yet
/// record is refused, because the snapshot carries no generation and the fold binds each
/// dimension at the recording's position.
fn opened_log() -> IdentityLog {
    let mut log = seeded();
    log.record(IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()));
    log.record(IdentityEvent::SessionOpened(opened()));
    log
}

/// How many events `opened_log` seeds before the case's own: the two generations the
/// snapshot's dimensions hold, the snapshot, and the opening. Both are ordering
/// obligations `IdentityLog` documents and `try_record` enforces.
const SEEDED: usize = 4;

#[test]
fn the_read_port_folds_a_recorded_session_out_of_the_event_vec() {
    let log = opened_log();

    let resolved = log
        .resolve(&SessionId::new(uuid(20)))
        .expect("the session was recorded");
    assert_eq!(resolved, session());
    assert_eq!(resolved.state(), SessionState::Active);
    assert_eq!(log.events().len(), SEEDED);
}

#[test]
fn the_read_port_folds_a_revocation_into_the_resolved_session() {
    let mut log = opened_log();
    log.record(IdentityEvent::SessionRevoked(SessionRevoked {
        context: context(),
        id: SessionId::new(uuid(20)),
    }));

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

/// The authority `snapshot()` was issued against, seeded before the recording.
///
/// `mandate.identity.EpochSnapshotRecorded` carries no generation, so the fold binds each
/// dimension to what the authority held at the position the recording appears at. Seeding
/// these two is what makes the folded record `snapshot()` rather than a record at
/// `Generation::ZERO`.
fn seeded() -> IdentityLog {
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
    log
}

#[test]
fn the_read_port_resolves_a_snapshot_by_its_handle() {
    let mut log = seeded();
    log.record(IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()));

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
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(41),
        },
    ));

    let before = log.current(&target);
    assert_eq!(before.generation(), generation(41));
    assert_eq!(before.version(), StreamVersion::new(1));

    let after = log
        .increment(&context(), &target, before.version())
        .expect("the stream is at the expected version");

    assert_eq!(after.generation(), generation(42));
    assert_eq!(after.version(), StreamVersion::new(2));
    assert_eq!(log.current(&target), after);
}

#[test]
fn the_write_port_refuses_an_expected_version_the_stream_has_moved_past() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(41),
        },
    ));
    let stale_version = log.current(&target).version();
    log.increment(&context(), &target, stale_version)
        .expect("the first writer commits");

    let refused = log
        .increment(&context(), &target, stale_version)
        .expect_err("the second writer read before the first committed");

    assert_eq!(refused.reason(), DenialReason::Unavailable);
    assert_eq!(log.current(&target).generation(), generation(42));
}

#[test]
fn each_target_keeps_its_own_stream_version() {
    let principal_target = SecurityEpochTarget::Principal(principal());
    let organization_target = SecurityEpochTarget::Organization(organization());
    let mut log = IdentityLog::new();

    log.increment(&context(), &principal_target, StreamVersion::INITIAL)
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
    let log = opened_log();
    let port: &dyn IdentityRead = &log;

    assert!(port.resolve(&SessionId::new(uuid(20))).is_some());
    assert_eq!(
        port.current(&SecurityEpochTarget::Principal(principal()))
            .generation(),
        generation(3),
        "the generation the log states for the dimension the session's snapshot names"
    );
}

#[test]
fn the_fold_refuses_a_recorded_generation_below_the_one_it_already_holds() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(42),
        },
    ));

    let refused = log
        .try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: target.clone(),
                generation: generation(41),
            },
        ))
        .expect_err("the authoritative generation never moves backwards");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(log.current(&target).generation(), generation(42));
    assert_eq!(log.events().len(), 1, "the refused event is not appended");

    // The infallible form refuses the same event and discards the refusal.
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::ZERO,
        },
    ));
    assert_eq!(log.current(&target).generation(), generation(42));
    assert_eq!(log.events().len(), 1);
}

#[test]
fn the_fold_refuses_a_second_opening_of_a_session_it_already_records() {
    let mut log = opened_log();
    log.record(IdentityEvent::SessionRevoked(SessionRevoked {
        context: context(),
        id: SessionId::new(uuid(20)),
    }));

    let refused = log
        .try_record(IdentityEvent::SessionOpened(opened()))
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
    let mut log = seeded();
    log.record(IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()));

    // The same handle naming another subject: the one rewrite the declared payload can
    // express, now that the generations are read off the log rather than carried.
    let rewritten = EpochSnapshotRecorded {
        id: EpochSnapshotRef::new(uuid(10)),
        principal_id: PrincipalId::new(uuid(9)),
        organization_id: OrganizationId::new(uuid(9)),
        connection_id: None,
    };
    let refused = log
        .try_record(IdentityEvent::EpochSnapshotRecorded(rewritten))
        .expect_err("an `EpochSnapshotRef` is an immutable record handle");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.snapshot(&EpochSnapshotRef::new(uuid(10))),
        Some(snapshot())
    );
}

/// The append guard decides every declared form on an opening, the expiry included, with
/// the generated schema as the oracle.
///
/// `mandate.identity.SessionOpened` declares `expires_at` as an RFC 3339 `date-time`
/// (`generated/schema/events/mandate.identity.SessionOpened.schema.json`), and the guard
/// reads it through the same `instant` parser the refresh decision uses. A payload the
/// closed schema refuses is never appended, so the fold cannot materialize a session whose
/// expiry names no instant — a session that could never be shown unexpired and would fail
/// closed forever. The sibling login payload is decided the same way.
#[test]
fn the_log_refuses_an_opening_whose_expiry_is_not_the_declared_date_time() {
    for malformed in ["2026-09-19", "never", "", "2026-13-01T00:00:00Z"] {
        let mut log = seeded();
        log.record(IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()));
        let held = log.clone();
        let opening = SessionOpened {
            expires_at: Timestamp::new(malformed),
            ..opened()
        };

        // The oracle: the contract's own schema, not this file's opinion.
        let payload = serde_json::to_value(&opening).expect("the declared payload serializes");
        check_event_conforms("mandate.identity.SessionOpened", &payload)
            .expect_err("the closed schema declares `expires_at` as a `date-time`");

        let refused = log
            .try_record(IdentityEvent::SessionOpened(opening))
            .expect_err("a payload the contract refuses is not appended");

        assert_eq!(refused.reason(), DenialReason::Denied);
        assert_eq!(log, held, "a refused event is not appended");
        assert!(
            log.resolve(&SessionId::new(uuid(20))).is_none(),
            "the fold materializes no session from an event it never recorded"
        );
    }
}

/// A snapshot recording whose dimensions the log has said nothing about is refused.
///
/// `mandate.identity.EpochSnapshotRecorded` carries no generation, so the fold binds each
/// dimension to what the log states was in force at the recording's position. A dimension
/// the log has not spoken about yet binds `Generation::ZERO`, and a `SecurityEpochRecorded`
/// for it landing afterwards is indistinguishable from the authority advancing: every
/// session on that snapshot would be permanently stale. The generation is therefore stated
/// first, explicitly, including when it is zero — the second ordering obligation
/// `IdentityLog` documents, enforced like the first.
#[test]
fn the_log_refuses_a_snapshot_whose_dimensions_state_no_generation() {
    let connection = FederationConnectionId::new(uuid(4));
    let federated = EpochSnapshotRecorded {
        connection_id: Some(connection),
        ..recorded_snapshot()
    };

    // Nothing stated at all.
    let mut empty = IdentityLog::new();
    assert!(
        empty
            .try_record(IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()))
            .is_err(),
        "neither dimension has stated a generation"
    );
    assert!(empty.events().is_empty(), "a refused event is not appended");

    // The principal and the organization have; the connection the snapshot also names has
    // not, so the recording is still refused.
    let mut partial = seeded();
    let held = partial.clone();
    assert!(
        partial
            .try_record(IdentityEvent::EpochSnapshotRecorded(federated.clone()))
            .is_err(),
        "the federation dimension has stated no generation"
    );
    assert_eq!(partial, held, "a refused event is not appended");
    assert!(partial.snapshot(&EpochSnapshotRef::new(uuid(10))).is_none());

    // With every dimension stated — zero counts, and so does an increment — it is admitted
    // and binds what each dimension holds.
    let mut complete = seeded();
    complete
        .increment(
            &context(),
            &SecurityEpochTarget::Federation(connection),
            StreamVersion::INITIAL,
        )
        .expect("an unstated target starts at the initial version");
    complete
        .try_record(IdentityEvent::EpochSnapshotRecorded(federated))
        .expect("every dimension has stated a generation");
    let snapshot = complete
        .snapshot(&EpochSnapshotRef::new(uuid(10)))
        .expect("the recording");
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Federation(connection)),
        Generation::new(1),
        "the dimension binds what the log says it holds"
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
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(5),
        },
    ));
    let before = log.current(&target);

    let refused = log
        .try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: target.clone(),
                generation: generation(5),
            },
        ))
        .expect_err("a recording that moves nothing is not an event");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(
        log.current(&target),
        before,
        "a refused recording consumes no version, so no writer's token is invalidated"
    );
    assert_eq!(log.events().len(), 1);

    // The token a writer read before the attempt still commits.
    log.increment(&context(), &target, before.version())
        .expect("the stream is still at the version the writer read");
}

#[test]
fn an_opening_that_arrives_after_a_recorded_revocation_is_refused() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionRevoked(SessionRevoked {
        context: context(),
        id: SessionId::new(uuid(20)),
    }));

    let refused = log
        .try_record(IdentityEvent::SessionOpened(opened()))
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
        IdentityEvent::SecurityEpochRecorded(SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::ZERO,
        }),
        IdentityEvent::SessionOpened(opened()),
        IdentityEvent::EpochSnapshotRecorded(recorded_snapshot()),
    ];

    let mut seeded = opened_log();
    seeded.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: generation(5),
        },
    ));
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
