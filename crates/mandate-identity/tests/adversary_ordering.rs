//! Adversary: did the terminal-state fix hold, or did it move?
//!
//! Pass 1 showed that a replayed `SessionOpened` left the declared terminal state
//! `Revoked`. Correction round 1 closed that instance two ways: `IdentityLog::resolve`
//! keeps the first `SessionOpened` it sees (`src/port.rs:256-274`), and
//! `IdentityLog::try_record` refuses a second one for a session the fold already resolves
//! (`src/port.rs:234-236`). The sentence written to record the guarantee is
//! `src/port.rs:142-145`: "One identity is opened once: a second `SessionOpened` for a
//! session the fold already records is refused by [`IdentityLog::try_record`] and ignored
//! by the fold, because `Revoked` is declared terminal and no transition leaves it."
//!
//! Both halves of that fix are keyed on `resolve(id).is_some()`, and `resolve` returns
//! `None` for a session whose only recorded event is its revocation — the fold has
//! nothing to apply `Session::revoke` to (`src/port.rs:267-269` maps over `resolved`,
//! which is still `None`). So the guard is not "this identity was revoked" but "this
//! identity currently projects to a session", and the two differ by the order the events
//! arrive in. Neither `try_record` arm refuses a `SessionRevoked` for an identity the fold
//! does not record, and neither refuses the `SessionOpened` that follows it.
//!
//! The ordering this case builds is one I built: the log is append-only and this crate
//! emits neither event, so there is no producer in this repository that emits a revocation
//! before an open. It is filed as the class the fix left open, not as a state anybody was
//! shown to reach.

use mandate_identity::{IdentityEvent, IdentityLog, IdentityRead, Session, SessionState};
use mandate_types::{EpochSnapshotRef, OrganizationId, PrincipalId, SessionId, Timestamp, Uuid};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn session_id() -> SessionId {
    SessionId::new(uuid(20))
}

fn session() -> Session {
    Session::new(
        session_id(),
        PrincipalId::new(uuid(1)),
        OrganizationId::new(uuid(2)),
        EpochSnapshotRef::new(uuid(10)),
        Timestamp::new("2026-12-31T00:00:00Z"),
    )
}

#[test]
fn a_recorded_revocation_is_not_undone_by_an_opening_that_arrives_after_it() {
    let mut log = IdentityLog::new();
    log.record(IdentityEvent::SessionRevoked(session_id()));
    assert_eq!(log.events().len(), 1, "the revocation is on the log");

    let refused = log.try_record(IdentityEvent::SessionOpened(session()));
    let state = log.resolve(&session_id()).map(|session| session.state());

    assert!(
        refused.is_err() || state == Some(SessionState::Revoked),
        "`Revoked` is declared terminal (`identity.yaml`, `terminal: [Revoked]`) and \
         `src/port.rs:142-145` rests that on `try_record` refusing the second open; the \
         log holds this identity's revocation, accepted the open anyway, and the session \
         resolves {state:?}"
    );
}
