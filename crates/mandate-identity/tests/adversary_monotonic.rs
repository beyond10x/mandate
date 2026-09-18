//! Adversary: the authoritative generation is not monotonic, and a generation is reused.
//!
//! `systems/mandate/domains/identity.yaml:1` records the requirement as "exact u64
//! monotonic semantics"; `tests/security/cases.json` `epoch-overflow` expects "fail
//! closed; no wrap **or reuse**"; `crates/mandate-identity/src/lib.rs:13-14` states that
//! "a generation is never wrapped and never reused".
//!
//! `IdentityEvent::SecurityEpochRecorded` (`src/port.rs:120-127`) is documented as the
//! out-of-band set that answers a generation at its maximum, and
//! `IdentityLog::current` (`src/port.rs:180-205`) applies whatever value it carries —
//! including one below the generation already folded. Nothing in `IdentityLog::record`
//! (`src/port.rs:152`) or in the fold refuses it, so the authority moves backwards, the
//! generation it lands on is one that has already been issued against, and a session that
//! was denied `StaleEpoch` refreshes again.

use mandate_identity::{
    Generation, IdentityEvent, IdentityLog, IdentityRead, SecurityEpochSnapshot, Session,
    refresh_session,
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

fn handle() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(10))
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn subject() -> SecurityEpochTarget {
    SecurityEpochTarget::Principal(principal())
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

/// A session snapshotted at principal generation 41 against an authority at 42: the
/// `epoch-principal` case, already denied.
fn denied_world() -> IdentityLog {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: subject(),
        generation: generation(42),
    });
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Organization(organization()),
        generation: generation(7),
    });
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            handle(),
            principal(),
            generation(41),
            organization(),
            generation(7),
        ),
    ));
    log.record(IdentityEvent::SessionOpened(Session::new(
        session_id(),
        principal(),
        organization(),
        handle(),
        Timestamp::new("2026-09-18T00:00:00Z"),
    )));
    log
}

#[test]
fn an_out_of_band_record_never_moves_the_authoritative_generation_backwards() {
    let mut log = denied_world();
    let before = log.current(&subject()).generation();
    assert_eq!(before, generation(42), "the authority is at 42");

    log.record(IdentityEvent::SecurityEpochRecorded {
        target: subject(),
        generation: generation(41),
    });

    let after = log.current(&subject()).generation();
    assert!(
        after >= before,
        "the generation is declared monotonic; it went from {before} to {after}"
    );
}

#[test]
fn a_session_denied_as_stale_is_not_made_current_again_by_reusing_its_generation() {
    let mut log = denied_world();
    assert_eq!(
        refresh_session(&log, &session_id())
            .expect_err("the snapshot is behind the authority")
            .reason(),
        DenialReason::StaleEpoch
    );

    log.record(IdentityEvent::SecurityEpochRecorded {
        target: subject(),
        generation: generation(41),
    });

    assert_eq!(
        refresh_session(&log, &session_id())
            .expect_err("generation 41 was already issued against and is not reusable")
            .reason(),
        DenialReason::StaleEpoch
    );
}

#[test]
fn a_generation_reset_to_zero_does_not_resurrect_every_snapshot_that_recorded_zero() {
    // The contract's answer at `Generation::MAX` is an out-of-band reset
    // (`src/port.rs:120-123`). A reset that lands on a value already issued against
    // re-validates every snapshot holding it, which is the reuse `epoch-overflow` forbids.
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: subject(),
        generation: Generation::MAX,
    });
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: SecurityEpochTarget::Organization(organization()),
        generation: Generation::ZERO,
    });
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            handle(),
            principal(),
            Generation::ZERO,
            organization(),
            Generation::ZERO,
        ),
    ));
    log.record(IdentityEvent::SessionOpened(Session::new(
        session_id(),
        principal(),
        organization(),
        handle(),
        Timestamp::new("2026-09-18T00:00:00Z"),
    )));
    assert!(
        refresh_session(&log, &session_id()).is_err(),
        "a snapshot at generation 0 against an authority at the maximum is stale"
    );

    log.record(IdentityEvent::SecurityEpochRecorded {
        target: subject(),
        generation: Generation::ZERO,
    });

    assert!(
        refresh_session(&log, &session_id()).is_err(),
        "the reset reused generation 0 and made the stale session current again"
    );
}
