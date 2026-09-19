//! `epoch-overflow` and the increment half of `epoch-isolation`
//! (`tests/security/cases.json`): `mandate.identity.IncrementSecurityEpoch` over the
//! write port, and the concurrent disable/refresh race.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, SecurityEpochRecorded, SessionOpened, StreamVersion, refresh_session,
};
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

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization_a(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(5)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn recorded(entries: &[(SecurityEpochTarget, i64)]) -> IdentityLog {
    let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));
    for (target, value) in entries {
        log.record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: target.clone(),
                generation: generation(*value),
            },
        ));
    }
    log
}

#[test]
fn epoch_overflow_an_increment_at_the_maximum_is_denied_and_the_generation_does_not_move() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = recorded(&[]);
    log.record(IdentityEvent::SecurityEpochRecorded(
        SecurityEpochRecorded {
            target: target.clone(),
            generation: Generation::MAX,
        },
    ));
    let before = log.current(&target);

    let refused = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, before.version())
        .expect_err("the generation is at its maximum");

    assert_eq!(refused.reason(), DenialReason::Denied);
    assert_eq!(log.current(&target), before);
    assert_eq!(log.current(&target).generation(), Generation::MAX);
}

#[test]
fn epoch_overflow_the_generation_below_the_maximum_advances_to_it_and_then_refuses() {
    let target = SecurityEpochTarget::Organization(organization_a());
    let mut log = recorded(&[(target.clone(), i64::MAX - 1)]);
    let command = IncrementSecurityEpoch::new(context(), target.clone());

    let expected = log.current(&target).version();
    command
        .execute(&mut log, expected)
        .expect("one advance remains");
    assert_eq!(log.current(&target).generation(), Generation::MAX);

    let expected = log.current(&target).version();
    assert_eq!(
        command
            .execute(&mut log, expected)
            .expect_err("there is no generation after the maximum")
            .reason(),
        DenialReason::Denied
    );
    assert_eq!(log.current(&target).generation(), Generation::MAX);
}

#[test]
fn epoch_isolation_incrementing_organization_a_leaves_organization_b_where_it_was() {
    let in_a = SecurityEpochTarget::Organization(organization_a());
    let in_b = SecurityEpochTarget::Organization(organization_b());
    let mut log = recorded(&[(in_a.clone(), 7), (in_b.clone(), 5)]);

    let expected = log.current(&in_a).version();
    IncrementSecurityEpoch::new(context(), in_a.clone())
        .execute(&mut log, expected)
        .expect("organization A is reset");

    assert_eq!(log.current(&in_a).generation(), generation(8));
    assert_eq!(log.current(&in_b).generation(), generation(5));
    assert_eq!(log.current(&in_b).version(), StreamVersion::new(1));
}

#[test]
fn epoch_isolation_incrementing_a_principal_moves_no_other_dimension() {
    let subject = SecurityEpochTarget::Principal(principal());
    let organization = SecurityEpochTarget::Organization(organization_a());
    let federation = SecurityEpochTarget::Federation(connection());
    let mut log = recorded(&[
        (subject.clone(), 3),
        (organization.clone(), 7),
        (federation.clone(), 1),
    ]);

    let expected = log.current(&subject).version();
    IncrementSecurityEpoch::new(context(), subject.clone())
        .execute(&mut log, expected)
        .expect("the principal is reset");

    assert_eq!(log.current(&subject).generation(), generation(4));
    assert_eq!(log.current(&organization).generation(), generation(7));
    assert_eq!(log.current(&federation).generation(), generation(1));
}

#[test]
fn the_accepted_outcome_carries_the_verified_context_and_the_selected_target() {
    let target = SecurityEpochTarget::Federation(connection());
    let mut log = recorded(&[(target.clone(), 1)]);
    let command = IncrementSecurityEpoch::new(context(), target.clone());

    assert_eq!(command.context(), &context());
    assert_eq!(command.target(), &target);

    let expected = log.current(&target).version();
    let event = command
        .execute(&mut log, expected)
        .expect("federation trust is reset");

    assert_eq!(event.context(), &context());
    assert_eq!(event.target(), &target);
    assert_eq!(log.current(&target).generation(), generation(2));
}

#[test]
fn epoch_isolation_two_writers_at_one_expected_version_advance_the_generation_exactly_once() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = recorded(&[(target.clone(), 3)]);
    let command = IncrementSecurityEpoch::new(context(), target.clone());

    let both_read = log.current(&target).version();
    command
        .execute(&mut log, both_read)
        .expect("the first writer commits");
    let refused = command
        .execute(&mut log, both_read)
        .expect_err("the second writer's expected version is no longer current");

    assert_eq!(refused.reason(), DenialReason::Unavailable);
    assert_eq!(log.current(&target).generation(), generation(4));
    assert_eq!(log.current(&target).version(), StreamVersion::new(2));
}

#[test]
fn a_refresh_racing_a_committed_disable_driven_increment_is_denied_and_the_other_tenant_is_not() {
    let target = SecurityEpochTarget::Principal(principal());
    let in_a = EpochSnapshotRef::new(uuid(10));
    let in_b = EpochSnapshotRef::new(uuid(11));
    let session_in_a = SessionId::new(uuid(20));
    let session_in_b = SessionId::new(uuid(21));
    let expires_at = Timestamp::new("2026-12-31T00:00:00Z");

    // Every dimension the two snapshots name states its generation first, zero included:
    // `IdentityLog` refuses a recording whose dimensions the log has said nothing about.
    let mut log = recorded(&[
        (target.clone(), 3),
        (SecurityEpochTarget::Organization(organization_a()), 7),
        (SecurityEpochTarget::Organization(organization_b()), 5),
        (SecurityEpochTarget::Principal(PrincipalId::new(uuid(6))), 0),
    ]);
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: in_a,
            principal_id: principal(),
            organization_id: organization_a(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: in_b,
            principal_id: PrincipalId::new(uuid(6)),
            organization_id: organization_b(),
            connection_id: None,
        },
    ));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_in_a,
        principal_id: principal(),
        organization_id: organization_a(),
        connection_id: None,
        epochs: in_a,
        expires_at: expires_at.clone(),
    }));
    log.record(IdentityEvent::SessionOpened(SessionOpened {
        id: session_in_b,
        principal_id: PrincipalId::new(uuid(6)),
        organization_id: organization_b(),
        connection_id: None,
        epochs: in_b,
        expires_at,
    }));

    assert!(refresh_session(&log, &session_in_a).is_ok());

    let expected = log.current(&target).version();
    IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, expected)
        .expect("disablement increments the principal's generation");

    assert_eq!(
        refresh_session(&log, &session_in_a)
            .expect_err("the refresh reads the snapshot before the increment committed")
            .reason(),
        DenialReason::StaleEpoch
    );
    assert!(
        refresh_session(&log, &session_in_b).is_ok(),
        "another principal in another organization is untouched"
    );
}
