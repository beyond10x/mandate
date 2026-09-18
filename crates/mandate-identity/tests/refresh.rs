//! The refresh half of `epoch-principal`, `epoch-org`, `epoch-federation` and
//! `epoch-isolation` (`tests/security/cases.json`): `mandate.identity.RefreshSession`
//! evaluated over the read port, with `mandate.identity.RevokeSession`'s state as an
//! input.

use mandate_identity::{
    Generation, IdentityEvent, IdentityLog, IdentityRead, SecurityEpochSnapshot,
    SecurityEpochWrite, Session, SessionState, refresh_session,
};
use mandate_types::{
    DenialReason, EpochSnapshotRef, FederationConnectionId, OrganizationId, PrincipalId,
    SecurityEpochTarget, SessionId, Timestamp, Uuid,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(1))
}

fn organization_a() -> OrganizationId {
    OrganizationId::new(uuid(2))
}

fn organization_b() -> OrganizationId {
    OrganizationId::new(uuid(3))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(4))
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

fn expires_at() -> Timestamp {
    Timestamp::new("2026-12-31T00:00:00Z")
}

/// The fixed instant every case in this file is evaluated at.
fn as_of() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn session_in_a() -> SessionId {
    SessionId::new(uuid(20))
}

fn session_in_b() -> SessionId {
    SessionId::new(uuid(21))
}

fn federated_session() -> SessionId {
    SessionId::new(uuid(22))
}

/// One principal with a session in organization A, a session in the unrelated
/// organization B, and a federated session in A.
fn world() -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(as_of());
    for (target, value) in [
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 7),
        (SecurityEpochTarget::Organization(organization_b()), 5),
        (SecurityEpochTarget::Federation(connection()), 1),
    ] {
        log.record(IdentityEvent::SecurityEpochRecorded {
            target,
            generation: generation(value),
        });
    }

    let in_a = EpochSnapshotRef::new(uuid(10));
    let in_b = EpochSnapshotRef::new(uuid(11));
    let federated = EpochSnapshotRef::new(uuid(12));

    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            in_a,
            principal(),
            generation(3),
            organization_a(),
            generation(7),
        ),
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            in_b,
            principal(),
            generation(3),
            organization_b(),
            generation(5),
        ),
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            federated,
            principal(),
            generation(3),
            organization_a(),
            generation(7),
        )
        .with_federation(connection(), generation(1)),
    ));

    log.record(IdentityEvent::SessionOpened(Session::new(
        session_in_a(),
        principal(),
        organization_a(),
        in_a,
        expires_at(),
    )));
    log.record(IdentityEvent::SessionOpened(Session::new(
        session_in_b(),
        principal(),
        organization_b(),
        in_b,
        expires_at(),
    )));
    log.record(IdentityEvent::SessionOpened(
        Session::new(
            federated_session(),
            principal(),
            organization_a(),
            federated,
            expires_at(),
        )
        .with_connection(connection()),
    ));

    log
}

/// The same events, folded by a reader that was never told what time it is.
fn replayed_without_an_instant(log: &IdentityLog) -> IdentityLog {
    let mut replayed = IdentityLog::new();
    for event in log.events() {
        replayed.record(event.clone());
    }
    replayed
}

fn advance(log: &mut IdentityLog, target: &SecurityEpochTarget) {
    let expected = log.current(target).version();
    log.increment(target, expected)
        .expect("the authority advances the generation");
}

#[test]
fn epoch_principal_a_refresh_after_the_principal_generation_advanced_denies_stale_epoch() {
    let mut log = world();
    assert!(refresh_session(&log, &session_in_a()).is_ok());

    advance(&mut log, &SecurityEpochTarget::Principal(principal()));

    assert_eq!(
        refresh_session(&log, &session_in_a())
            .expect_err("the snapshot is behind the authority")
            .reason(),
        DenialReason::StaleEpoch
    );
}

#[test]
fn epoch_org_a_refresh_after_the_organization_generation_advanced_denies_stale_epoch() {
    let mut log = world();

    advance(
        &mut log,
        &SecurityEpochTarget::Organization(organization_a()),
    );

    assert_eq!(
        refresh_session(&log, &session_in_a())
            .expect_err("the organization was reset")
            .reason(),
        DenialReason::StaleEpoch
    );
}

#[test]
fn epoch_federation_a_refresh_after_the_connection_generation_advanced_denies_stale_epoch() {
    let mut log = world();
    assert!(refresh_session(&log, &federated_session()).is_ok());

    advance(&mut log, &SecurityEpochTarget::Federation(connection()));

    assert_eq!(
        refresh_session(&log, &federated_session())
            .expect_err("federation trust was reset")
            .reason(),
        DenialReason::StaleEpoch
    );
    assert!(
        refresh_session(&log, &session_in_a()).is_ok(),
        "a session that came from no connection is not compared on that dimension"
    );
}

#[test]
fn epoch_isolation_only_organization_a_is_reset_so_the_b_session_stays_eligible() {
    let mut log = world();

    advance(
        &mut log,
        &SecurityEpochTarget::Organization(organization_a()),
    );

    assert_eq!(
        refresh_session(&log, &session_in_a())
            .expect_err("the reset organization's session is stale")
            .reason(),
        DenialReason::StaleEpoch
    );
    assert_eq!(
        refresh_session(&log, &session_in_b())
            .expect("the unrelated organization's session is untouched")
            .session_id(),
        &session_in_b()
    );
}

#[test]
fn a_revoked_session_is_refused_even_though_every_generation_still_matches() {
    let mut log = world();
    log.record(IdentityEvent::SessionRevoked(session_in_a()));

    let session = log
        .resolve(&session_in_a())
        .expect("the fold still records the session");
    assert_eq!(session.state(), SessionState::Revoked);
    assert!(!session.is_active());
    assert_eq!(
        session
            .refresh(&log, &as_of())
            .expect_err("a revoked session does not refresh")
            .reason(),
        DenialReason::InvalidCredential
    );
    assert!(
        refresh_session(&log, &session_in_b()).is_ok(),
        "revoking one session leaves the others alone"
    );
}

#[test]
fn a_session_the_fold_does_not_record_is_refused() {
    let log = world();

    assert_eq!(
        refresh_session(&log, &SessionId::new(uuid(99)))
            .expect_err("no such session")
            .reason(),
        DenialReason::InvalidCredential
    );
}

#[test]
fn a_session_whose_snapshot_is_bound_to_another_organization_is_refused() {
    let mut log = world();
    let borrowed = EpochSnapshotRef::new(uuid(13));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            borrowed,
            principal(),
            generation(3),
            organization_b(),
            generation(5),
        ),
    ));
    log.record(IdentityEvent::SessionOpened(Session::new(
        SessionId::new(uuid(23)),
        principal(),
        organization_a(),
        borrowed,
        expires_at(),
    )));

    assert_eq!(
        refresh_session(&log, &SessionId::new(uuid(23)))
            .expect_err("the snapshot does not belong to this session")
            .reason(),
        DenialReason::TenantMismatch
    );
}

#[test]
fn a_session_whose_snapshot_handle_resolves_to_nothing_is_refused() {
    let mut log = world();
    log.record(IdentityEvent::SessionOpened(Session::new(
        SessionId::new(uuid(24)),
        principal(),
        organization_a(),
        EpochSnapshotRef::new(uuid(98)),
        expires_at(),
    )));

    assert_eq!(
        refresh_session(&log, &SessionId::new(uuid(24)))
            .expect_err("the handle resolves to no snapshot")
            .reason(),
        DenialReason::Denied
    );
}

#[test]
fn epoch_principal_a_principal_increment_denies_that_principal_s_session_in_every_organization() {
    // `epoch-isolation` is an organization-scoped exemption: the organization that was
    // not reset keeps its sessions. A principal reset is deliberately global — one
    // principal's sessions go everywhere the principal has them — so the same world that
    // exempts B from an organization reset must not exempt it from a principal one.
    let mut log = world();

    advance(&mut log, &SecurityEpochTarget::Principal(principal()));

    assert_eq!(
        refresh_session(&log, &session_in_a())
            .expect_err("the principal was reset")
            .reason(),
        DenialReason::StaleEpoch
    );
    assert_eq!(
        refresh_session(&log, &session_in_b())
            .expect_err("a principal reset reaches the principal's sessions in every organization")
            .reason(),
        DenialReason::StaleEpoch
    );
}

#[test]
fn a_session_is_refreshable_strictly_before_the_instant_it_expires_at() {
    let log = world();
    let session = log
        .resolve(&session_in_a())
        .expect("the fold records the session");

    assert!(!session.is_expired_at(&as_of()));
    assert!(session.refresh(&log, &as_of()).is_ok());

    assert!(
        session.is_expired_at(&expires_at()),
        "at the instant itself"
    );
    assert_eq!(
        session
            .refresh(&log, &expires_at())
            .expect_err("a session does not refresh at or after its expiry")
            .reason(),
        DenialReason::InvalidCredential
    );
    assert_eq!(
        session
            .refresh(&log, &Timestamp::new("2027-01-01T00:00:00Z"))
            .expect_err("nor after it")
            .reason(),
        DenialReason::InvalidCredential
    );
}

#[test]
fn a_reader_that_supplies_no_instant_cannot_certify_a_session_and_fails_closed() {
    let mut log = world();
    let undated = replayed_without_an_instant(&log);

    assert!(undated.as_of().is_none());
    assert_eq!(
        refresh_session(&undated, &session_in_a())
            .expect_err("a reader that does not know the time cannot date a session")
            .reason(),
        DenialReason::Unavailable
    );

    // What does not depend on the instant is still decided, and first.
    advance(
        &mut log,
        &SecurityEpochTarget::Organization(organization_a()),
    );
    let undated = replayed_without_an_instant(&log);
    assert_eq!(
        refresh_session(&undated, &session_in_a())
            .expect_err("staleness is decided without an instant")
            .reason(),
        DenialReason::StaleEpoch
    );
}

/// A session whose only interesting property is the lexical form of its expiry.
fn expiring_at(text: &str) -> Session {
    Session::new(
        session_in_a(),
        principal(),
        organization_a(),
        EpochSnapshotRef::new(uuid(10)),
        Timestamp::new(text),
    )
}

#[test]
fn an_expiry_is_compared_as_an_instant_and_not_as_bytes() {
    // 2026-09-18T20:00:00-05:00 is 2026-09-19T01:00:00Z: later than an instant whose text
    // sorts after it, earlier than one whose text sorts before it.
    let session = expiring_at("2026-09-18T20:00:00-05:00");

    assert!(!session.is_expired_at(&Timestamp::new("2026-09-19T00:59:59Z")));
    assert!(session.is_expired_at(&Timestamp::new("2026-09-19T01:00:00Z")));
    assert!(session.is_expired_at(&Timestamp::new("2026-09-18T21:00:00-05:00")));
}

#[test]
fn a_minus_zero_offset_names_the_same_instant_as_the_zulu_form() {
    let session = expiring_at("2026-09-18T12:00:00-00:00");

    assert!(session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00Z")));
    assert!(session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00+00:00")));
    assert!(!session.is_expired_at(&Timestamp::new("2026-09-18T11:59:59Z")));
}

#[test]
fn a_fractional_second_of_one_to_nine_digits_orders_inside_its_second() {
    let session = expiring_at("2026-09-18T12:00:00.500Z");

    assert!(!session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00.499Z")));
    assert!(session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00.500Z")));
    assert!(session.is_expired_at(&Timestamp::new("2026-09-18T12:00:00.5Z")));

    let whole = expiring_at("2026-09-18T12:00:00Z");
    for digits in 1..=9 {
        let mut fraction = String::from("2026-09-18T12:00:00.");
        for _ in 1..digits {
            fraction.push('0');
        }
        fraction.push_str("1Z");
        assert!(
            whole.is_expired_at(&Timestamp::new(fraction.clone())),
            "{fraction} is after the whole second it starts in"
        );
    }
}

#[test]
fn the_last_day_of_a_leap_february_parses_and_a_day_that_does_not_exist_fails_closed() {
    let leap_day = expiring_at("2024-02-29T00:00:00Z");
    assert!(!leap_day.is_expired_at(&Timestamp::new("2024-02-28T23:59:59Z")));
    assert!(leap_day.is_expired_at(&Timestamp::new("2024-02-29T00:00:00Z")));

    let century = expiring_at("2000-02-29T00:00:00Z");
    assert!(!century.is_expired_at(&Timestamp::new("2000-02-28T23:59:59Z")));

    for impossible in [
        "2023-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-09-31T00:00:00Z",
    ] {
        assert!(
            expiring_at(impossible).is_expired_at(&Timestamp::new("1970-01-01T00:00:00Z")),
            "{impossible} names no instant, so no session carrying it can be shown unexpired"
        );
    }
}

#[test]
fn an_hour_of_twenty_four_names_no_instant_and_the_last_second_of_a_day_does() {
    assert!(
        expiring_at("2026-09-18T24:00:00Z").is_expired_at(&Timestamp::new("1970-01-01T00:00:00Z")),
        "24:00 is not an hour RFC 3339 admits"
    );

    let last_second = expiring_at("2026-09-18T23:59:59Z");
    assert!(!last_second.is_expired_at(&Timestamp::new("2026-09-18T23:59:58Z")));
    assert!(last_second.is_expired_at(&Timestamp::new("2026-09-19T00:00:00Z")));
}

#[test]
fn an_expiry_that_names_no_instant_denies_the_refresh_as_an_invalid_record() {
    let mut log = world();
    log.record(IdentityEvent::SessionOpened(Session::new(
        SessionId::new(uuid(25)),
        principal(),
        organization_a(),
        EpochSnapshotRef::new(uuid(10)),
        Timestamp::new("the thirty-first of Octember"),
    )));

    assert_eq!(
        refresh_session(&log, &SessionId::new(uuid(25)))
            .expect_err("a session whose expiry names no instant cannot be shown unexpired")
            .reason(),
        DenialReason::InvalidCredential
    );
}

#[test]
fn a_readers_instant_that_names_no_instant_cannot_date_a_session() {
    let dated = world();
    let undatable = IdentityLog::new().with_as_of(Timestamp::new("later"));
    let undatable = dated.events().iter().fold(undatable, |mut log, event| {
        log.record(event.clone());
        log
    });

    assert_eq!(
        refresh_session(&undatable, &session_in_a())
            .expect_err("a reader whose instant names no instant knows no time at all")
            .reason(),
        DenialReason::Unavailable
    );
}
