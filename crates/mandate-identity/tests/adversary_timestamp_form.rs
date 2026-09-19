//! Adversary: the expiry decision is a byte comparison of two strings, and the form the
//! contract declares for those strings does not order chronologically.
//!
//! `mandate.identity.Session.expires_at` is declared `Timestamp`
//! (`systems/mandate/domains/identity.yaml`), which the projection renders as
//! `"format": "date-time"` with no pattern (`generated/schema/...`), i.e. an RFC 3339
//! `date-time`. `mandate_types::Timestamp` carries that string verbatim and derives `Ord`
//! over it, and its own documentation says so:
//! "The lexical form is carried verbatim; validating it, and any arithmetic over it, are
//! runtime obligations this milestone does not discharge"
//! (`crates/mandate-types/src/value.rs:214-247`).
//!
//! `Session::is_expired_at` (`crates/mandate-identity/src/session.rs:169-171`) is
//! `self.expires_at <= *as_of` — that byte comparison — and the sentence written above it
//! claims it is sound: "`Timestamp` carries the declared lexical form and orders on it, so
//! two `Z`-form instants compare without any arithmetic over them" (`src/session.rs:165-167`).
//! The hedge is "two `Z`-form instants", and nothing requires that form: `Timestamp::new`
//! accepts any string, `Session::new` accepts any `Timestamp`, `IdentityLog::with_as_of`
//! accepts any `Timestamp`, and RFC 3339 `date-time` admits `+hh:mm` / `-hh:mm` offsets and
//! a fractional-seconds part.
//!
//! Every instant in this file is a valid RFC 3339 `date-time`. In three of these four
//! cases a session that has expired refreshes; in the fourth a session that has not
//! expired is refused.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    SecurityEpochRecorded, Session, SessionOpened, refresh_session,
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

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

/// A world in which every applicable generation matches the authority and the session is
/// active, so the only thing `RefreshSession` still has to decide is the expiry.
fn world(expires_at: &str, as_of: &str) -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(Timestamp::new(as_of));
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
        expires_at: Timestamp::new(expires_at),
    }));
    log
}

/// The same session, resolved out of that fold.
fn session(expires_at: &str) -> Session {
    world(expires_at, "2026-09-18T00:00:00Z")
        .resolve(&session_id())
        .expect("the fold records the session")
}

#[test]
fn an_expired_session_does_not_refresh_because_the_readers_instant_carries_an_offset() {
    // The session expired at 2026-09-18T12:00:00Z. The reader's instant is
    // 2026-09-18T11:30:00-01:00, which is 2026-09-18T12:30:00Z — half an hour later.
    let log = world("2026-09-18T12:00:00Z", "2026-09-18T11:30:00-01:00");

    assert_eq!(
        refresh_session(&log, &session_id())
            .expect_err(
                "the session expired half an hour before the instant this read is evaluated at"
            )
            .reason(),
        DenialReason::InvalidCredential
    );
}

#[test]
fn the_expiry_boundary_holds_for_the_same_instant_written_in_the_other_declared_utc_form() {
    // `tests/refresh.rs:334-353` pins the boundary: at the instant the session expires at,
    // it is expired. RFC 3339 spells UTC two ways, and this is the same instant.
    let session = session("2026-09-18T12:00:00Z");

    assert!(
        session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00+00:00")),
        "2026-09-18T12:00:00+00:00 is the instant the session expires at, and the pinned \
         boundary (`expires_at <= as_of`) makes that instant expired"
    );
}

#[test]
fn a_session_is_expired_at_an_instant_that_names_a_fraction_of_a_second_after_its_expiry() {
    // A host whose clock has sub-second resolution renders one; RFC 3339 `time-secfrac` is
    // part of the declared form, and this instant is half a second past the expiry.
    let session = session("2026-09-18T12:00:00Z");

    assert!(
        session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00.500Z")),
        "2026-09-18T12:00:00.500Z is after 2026-09-18T12:00:00Z, so the session has expired"
    );
}

#[test]
fn a_session_that_has_not_expired_is_not_refused_because_its_expiry_carries_an_offset() {
    // The other direction: this session expires at 2026-09-18T20:00:00-05:00, which is
    // 2026-09-19T01:00:00Z — an hour after the instant it is being refreshed at.
    let session = session("2026-09-18T20:00:00-05:00");

    assert!(
        !session.is_expired_at(&Timestamp::new("2026-09-19T00:00:00Z")),
        "the session is refreshable for another hour; `expires_at` is 2026-09-19T01:00:00Z \
         written with a -05:00 offset"
    );
}
