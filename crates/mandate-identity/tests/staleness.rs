//! `epoch-principal`, `epoch-org`, `epoch-federation` and `epoch-isolation`
//! (`tests/security/cases.json`): the per-dimension comparison a snapshot makes against
//! the authoritative generations, and the verdict it produces.

use mandate_identity::{
    Eligibility, EpochDimension, Generation, IdentityEvent, IdentityLog, SecurityEpochRecorded,
    SecurityEpochSnapshot,
};
use mandate_types::{
    DenialReason, EpochSnapshotRef, FederationConnectionId, OrganizationId, PrincipalId,
    SecurityEpochTarget, Uuid,
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

fn handle(tag: u8) -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(tag))
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

fn authority(entries: &[(SecurityEpochTarget, i64)]) -> IdentityLog {
    let mut log = IdentityLog::new();
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
fn epoch_principal_a_snapshot_at_41_against_an_authoritative_42_is_stale() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 42),
        (SecurityEpochTarget::Organization(organization_a()), 7),
    ]);
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(41),
        organization_a(),
        generation(7),
    );

    assert_eq!(
        snapshot.eligibility(&log),
        Eligibility::Stale(EpochDimension::Principal)
    );
}

#[test]
fn epoch_principal_a_stale_verdict_carries_the_declared_stale_epoch_refusal() {
    let verdict = Eligibility::Stale(EpochDimension::Principal);

    assert!(!verdict.is_current());
    assert_eq!(verdict.stale_dimension(), Some(EpochDimension::Principal));
    assert_eq!(
        verdict.denial().expect("a stale verdict denies").reason(),
        DenialReason::StaleEpoch
    );
    assert!(Eligibility::Current.denial().is_none());
    assert!(Eligibility::Current.is_current());
}

#[test]
fn epoch_principal_a_snapshot_at_the_authoritative_generation_is_current() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 42),
        (SecurityEpochTarget::Organization(organization_a()), 7),
    ]);
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(42),
        organization_a(),
        generation(7),
    );

    assert_eq!(snapshot.eligibility(&log), Eligibility::Current);
}

#[test]
fn epoch_org_an_advanced_organization_generation_is_stale_on_the_organization_dimension() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 8),
    ]);
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(3),
        organization_a(),
        generation(7),
    );

    assert_eq!(
        snapshot.eligibility(&log),
        Eligibility::Stale(EpochDimension::Organization)
    );
}

#[test]
fn epoch_federation_an_advanced_connection_generation_is_stale_on_the_federation_dimension() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 7),
        (SecurityEpochTarget::Federation(connection()), 2),
    ]);
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(3),
        organization_a(),
        generation(7),
    )
    .with_federation(connection(), generation(1));

    assert_eq!(
        snapshot.eligibility(&log),
        Eligibility::Stale(EpochDimension::Federation)
    );
}

#[test]
fn epoch_federation_a_snapshot_with_no_connection_is_not_compared_on_that_dimension() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 7),
        (SecurityEpochTarget::Federation(connection()), 9),
    ]);
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(3),
        organization_a(),
        generation(7),
    );

    assert!(snapshot.connection().is_none());
    assert_eq!(snapshot.eligibility(&log), Eligibility::Current);
}

#[test]
fn epoch_isolation_only_organization_a_is_reset_so_the_b_snapshot_stays_current() {
    let log = authority(&[
        (SecurityEpochTarget::Principal(principal()), 3),
        (SecurityEpochTarget::Organization(organization_a()), 8),
        (SecurityEpochTarget::Organization(organization_b()), 5),
    ]);
    let in_a = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(3),
        organization_a(),
        generation(7),
    );
    let in_b = SecurityEpochSnapshot::new(
        handle(11),
        principal(),
        generation(3),
        organization_b(),
        generation(5),
    );

    assert_eq!(
        in_a.eligibility(&log),
        Eligibility::Stale(EpochDimension::Organization)
    );
    assert_eq!(in_b.eligibility(&log), Eligibility::Current);
}

#[test]
fn epoch_isolation_a_target_naming_another_subject_is_not_recorded_in_this_snapshot() {
    let snapshot = SecurityEpochSnapshot::new(
        handle(11),
        principal(),
        generation(3),
        organization_b(),
        generation(5),
    );

    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Organization(organization_b())),
        Some(generation(5))
    );
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Organization(organization_a())),
        None
    );
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Principal(principal())),
        Some(generation(3))
    );
    assert_eq!(
        snapshot.recorded(&SecurityEpochTarget::Federation(connection())),
        None
    );
}

#[test]
fn epoch_isolation_a_snapshot_is_compared_only_against_the_targets_it_applies_to() {
    let snapshot = SecurityEpochSnapshot::new(
        handle(10),
        principal(),
        generation(3),
        organization_a(),
        generation(7),
    )
    .with_federation(connection(), generation(1));

    assert_eq!(
        snapshot.targets(),
        vec![
            SecurityEpochTarget::Principal(principal()),
            SecurityEpochTarget::Organization(organization_a()),
            SecurityEpochTarget::Federation(connection()),
        ]
    );
    assert_eq!(snapshot.id(), &handle(10));
    assert_eq!(snapshot.principal(), &principal());
    assert_eq!(snapshot.organization(), &organization_a());
    assert_eq!(snapshot.connection(), Some(&connection()));
}
