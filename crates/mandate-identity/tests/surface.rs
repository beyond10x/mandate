//! The crate's public surface: what the modules wire together, what the root re-exports,
//! and the shape of the two ports.

use mandate_identity::{
    Denial, Eligibility, EpochDimension, EpochState, Generation, IdentityEvent, IdentityLog,
    IdentityRead, IncrementSecurityEpoch, SecurityEpochIncremented, SecurityEpochSnapshot,
    SecurityEpochWrite, Session, SessionRefreshed, SessionState, StreamVersion, refresh_session,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, FederationConnectionId,
    OrganizationId, PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn generation(value: i64) -> Generation {
    Generation::new(value).expect("a non-negative generation")
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(1)),
        actor: None,
        organization: OrganizationId::new(uuid(2)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(5)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// The read port is used through a shared reference and mutates nothing; the write port
/// is a second trait, so a value held as a reader cannot advance a generation. That half
/// is proved by the `compile_fail` example on the crate root.
fn reads(_: &dyn IdentityRead) {}

fn writes(_: &mut dyn SecurityEpochWrite) {}

#[test]
fn the_crate_root_re_exports_every_module_type() {
    let _: Generation = Generation::ZERO;
    let _: EpochDimension = EpochDimension::Federation;
    let _: Eligibility = Eligibility::Current;
    let _: Denial = Denial::new(DenialReason::StaleEpoch);
    let _: StreamVersion = StreamVersion::INITIAL;
    let _: EpochState = EpochState::new(Generation::ZERO, StreamVersion::INITIAL);
    let _: SessionState = SessionState::Active;
    let _: IdentityEvent = IdentityEvent::SessionRevoked(SessionId::new(uuid(20)));
    let _: IdentityLog = IdentityLog::new();
    let _: IncrementSecurityEpoch = IncrementSecurityEpoch::new(
        context(),
        SecurityEpochTarget::Principal(PrincipalId::new(uuid(1))),
    );
}

#[test]
fn both_ports_are_implemented_by_the_event_fold_and_only_one_of_them_mutates() {
    let mut log = IdentityLog::new();

    reads(&log);
    writes(&mut log);
}

#[test]
fn the_session_record_carries_every_field_the_contract_declares() {
    let id = SessionId::new(uuid(20));
    let principal = PrincipalId::new(uuid(1));
    let organization = OrganizationId::new(uuid(2));
    let connection = FederationConnectionId::new(uuid(4));
    let epochs = EpochSnapshotRef::new(uuid(10));
    let expires_at = Timestamp::new("2026-09-18T00:00:00Z");

    let session = Session::new(id, principal, organization, epochs, expires_at.clone())
        .with_connection(connection);

    assert_eq!(session.id(), &id);
    assert_eq!(session.principal(), &principal);
    assert_eq!(session.organization(), &organization);
    assert_eq!(session.connection(), Some(&connection));
    assert_eq!(session.epochs(), &epochs);
    assert_eq!(session.expires_at(), &expires_at);
    assert_eq!(session.state(), SessionState::Active);
    assert_eq!(session.revoke().state(), SessionState::Revoked);
}

#[test]
fn the_snapshot_record_is_keyed_by_the_handle_and_holds_a_generation_per_dimension() {
    let handle = EpochSnapshotRef::new(uuid(10));
    let snapshot = SecurityEpochSnapshot::new(
        handle,
        PrincipalId::new(uuid(1)),
        generation(3),
        OrganizationId::new(uuid(2)),
        generation(7),
    )
    .with_federation(FederationConnectionId::new(uuid(4)), generation(1));

    assert_eq!(snapshot.id(), &handle);
    assert_eq!(snapshot.targets().len(), 3);
    for target in snapshot.targets() {
        assert!(snapshot.recorded(&target).is_some());
    }
}

#[test]
fn a_stale_verdict_is_the_declared_denial_and_a_current_one_is_no_denial() {
    assert_eq!(
        Eligibility::Stale(EpochDimension::Organization)
            .denial()
            .map(|denial| denial.reason()),
        Some(DenialReason::StaleEpoch)
    );
    assert_eq!(Eligibility::Current.denial(), None);
    assert_eq!(
        Denial::new(DenialReason::Unavailable).reason(),
        DenialReason::Unavailable
    );
}

#[test]
fn the_accepted_outcomes_are_the_shapes_the_contract_declares() {
    let target = SecurityEpochTarget::Organization(OrganizationId::new(uuid(2)));
    let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));
    log.record(IdentityEvent::SecurityEpochRecorded {
        target: target.clone(),
        generation: generation(7),
    });
    let expected = log.current(&target).version();

    let emitted: SecurityEpochIncremented = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut log, expected)
        .expect("the stream is at the expected version");
    assert_eq!(emitted.target(), &target);
    assert_eq!(emitted.context(), &context());

    let session_id = SessionId::new(uuid(20));
    let handle = EpochSnapshotRef::new(uuid(10));
    log.record(IdentityEvent::EpochSnapshotRecorded(
        SecurityEpochSnapshot::new(
            handle,
            PrincipalId::new(uuid(1)),
            Generation::ZERO,
            OrganizationId::new(uuid(2)),
            generation(8),
        ),
    ));
    log.record(IdentityEvent::SessionOpened(Session::new(
        session_id,
        PrincipalId::new(uuid(1)),
        OrganizationId::new(uuid(2)),
        handle,
        Timestamp::new("2026-12-31T00:00:00Z"),
    )));

    let refreshed: SessionRefreshed =
        refresh_session(&log, &session_id).expect("every generation matches");
    assert_eq!(refreshed.session_id(), &session_id);
}
