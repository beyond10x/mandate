//! `epoch-overflow` and the increment half of `epoch-isolation`
//! (`tests/security/cases.json`): `mandate.identity.IncrementSecurityEpoch` over the
//! write port, and the concurrent disable/refresh race.

use mandate_contract::events::{
    MandateFederationExternalPrincipalProvisioned, MandateFederationFederationAuthenticated,
};
use mandate_contract::types::{
    MandateCoreAudience, MandateCoreCorrelationId, MandateCoreEpochSnapshotRef,
    MandateCoreExternalLinkMethod, MandateCoreExternalPrincipalId, MandateCoreExternalSubject,
    MandateCoreFederationConnectionId, MandateCoreOrganizationId, MandateCorePrincipalId,
    MandateCorePrincipalKind, MandateCoreSessionId,
};
use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, RefusedOutcome, SecurityEpochRecorded, SessionOpened, StreamVersion,
    refresh_session,
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

// ==================================================================================
// "tenant containment fails" (`identity.yaml`, `IncrementSecurityEpoch`, `denied`)
// ==================================================================================

/// The declared uuid form, as the generated shapes carry it.
fn declared(tag: u8) -> String {
    uuid(tag).to_string()
}

/// A log in which `principal()` and `connection()` are recorded under `organization`, through
/// one snapshot, with every dimension it names stated first.
fn recorded_under(organization: OrganizationId) -> IdentityLog {
    let mut log = recorded(&[
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 7),
        (SecurityEpochTarget::Organization(organization_b()), 5),
        (SecurityEpochTarget::Federation(connection()), 1),
    ]);
    log.try_record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: EpochSnapshotRef::new(uuid(10)),
            principal_id: principal(),
            organization_id: organization,
            connection_id: Some(connection()),
        },
    ))
    .expect("every dimension the snapshot names is stated");
    log
}

/// Refused through `denied` with `TenantMismatch`, and the log is exactly as it was.
fn refused_for_tenancy(log: &mut IdentityLog, target: &SecurityEpochTarget) {
    let before = log.clone();
    let expected = log.current(target).version();
    let refused = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(log, expected)
        .expect_err("the target is recorded outside the caller's organization");
    assert_eq!(refused.reason(), DenialReason::TenantMismatch);
    assert_eq!(refused.outcome(), RefusedOutcome::Denied);
    assert_eq!(*log, before, "the refused increment appended an event");
}

#[test]
fn tenant_containment_an_organization_target_is_compared_by_identity() {
    let mut log = recorded(&[(SecurityEpochTarget::Organization(organization_b()), 5)]);
    refused_for_tenancy(
        &mut log,
        &SecurityEpochTarget::Organization(organization_b()),
    );
}

#[test]
fn tenant_containment_a_principal_a_snapshot_places_in_another_organization_is_refused() {
    let mut log = recorded_under(organization_b());
    refused_for_tenancy(&mut log, &SecurityEpochTarget::Principal(principal()));
}

#[test]
fn tenant_containment_a_connection_a_snapshot_places_in_another_organization_is_refused() {
    let mut log = recorded_under(organization_b());
    refused_for_tenancy(&mut log, &SecurityEpochTarget::Federation(connection()));
}

#[test]
fn tenant_containment_a_principal_and_connection_in_the_callers_organization_advance() {
    for target in [
        SecurityEpochTarget::Principal(principal()),
        SecurityEpochTarget::Federation(connection()),
    ] {
        let mut log = recorded_under(organization_a());
        let before = log.current(&target).generation();
        let expected = log.current(&target).version();
        IncrementSecurityEpoch::new(context(), target.clone())
            .execute(&mut log, expected)
            .expect("the target is recorded in the caller's organization alone");
        assert_eq!(
            log.current(&target).generation(),
            before.advance().expect("below the maximum")
        );
    }
}

/// A principal's generation gates every session it holds, in every organization: a caller in
/// one of them advancing it would invalidate the other's sessions, so a record in any other
/// organization refuses the increment.
#[test]
fn tenant_containment_a_principal_recorded_in_two_organizations_is_refused() {
    let mut log = recorded_under(organization_a());
    log.try_record(IdentityEvent::SessionOpened(SessionOpened {
        id: SessionId::new(uuid(21)),
        principal_id: principal(),
        organization_id: organization_b(),
        connection_id: None,
        epochs: EpochSnapshotRef::new(uuid(10)),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }))
    .expect("the snapshot the opening names is recorded");
    refused_for_tenancy(&mut log, &SecurityEpochTarget::Principal(principal()));
}

#[test]
fn tenant_containment_a_federated_login_in_another_organization_places_its_principal_and_connection()
 {
    for target in [
        SecurityEpochTarget::Principal(principal()),
        SecurityEpochTarget::Federation(connection()),
    ] {
        let mut log = recorded_under(organization_a());
        log.try_record(IdentityEvent::FederationAuthenticated(
            MandateFederationFederationAuthenticated {
                session_id: MandateCoreSessionId(declared(22)),
                principal_id: MandateCorePrincipalId(principal().to_string()),
                audience: MandateCoreAudience("mandate".to_owned()),
                correlation: MandateCoreCorrelationId("correlation".to_owned()),
                connection_id: MandateCoreFederationConnectionId(connection().to_string()),
                organization_id: MandateCoreOrganizationId(organization_b().to_string()),
                epochs: MandateCoreEpochSnapshotRef(declared(10)),
                expires_at: "2026-12-31T00:00:00Z".to_owned(),
            },
        ))
        .expect("a well-formed login on a recorded snapshot");
        refused_for_tenancy(&mut log, &target);
    }
}

#[test]
fn tenant_containment_a_provisioning_in_another_organization_places_its_principal_and_connection() {
    for target in [
        SecurityEpochTarget::Principal(principal()),
        SecurityEpochTarget::Federation(connection()),
    ] {
        let mut log = recorded_under(organization_a());
        log.try_record(IdentityEvent::ExternalPrincipalProvisioned(
            MandateFederationExternalPrincipalProvisioned {
                organization_id: MandateCoreOrganizationId(organization_b().to_string()),
                correlation: MandateCoreCorrelationId("correlation".to_owned()),
                connection_id: MandateCoreFederationConnectionId(connection().to_string()),
                principal_id: MandateCorePrincipalId(principal().to_string()),
                kind: MandateCorePrincipalKind::User,
                display_name: "Display Name".to_owned(),
                external_principal_id: MandateCoreExternalPrincipalId(declared(0x71)),
                subject: MandateCoreExternalSubject("subject-one".to_owned()),
                link_method: MandateCoreExternalLinkMethod::ConfiguredFederation,
                linked_at: "2026-09-19T00:00:00Z".to_owned(),
            },
        ))
        .expect("a well-formed provisioning");
        refused_for_tenancy(&mut log, &target);
    }
}

/// The refusal is decided before the write port is reached: a cross-organization increment at a
/// stale version is refused for its tenancy, not reported as a moved stream.
#[test]
fn tenant_containment_is_decided_before_the_compare_and_set() {
    let target = SecurityEpochTarget::Organization(organization_b());
    let mut log = recorded(&[(target.clone(), 5)]);
    let before = log.clone();
    let refused = IncrementSecurityEpoch::new(context(), target)
        .execute(&mut log, StreamVersion::INITIAL)
        .expect_err("another organization's target at a stale version");
    assert_eq!(refused.reason(), DenialReason::TenantMismatch);
    assert_eq!(log, before);
}
