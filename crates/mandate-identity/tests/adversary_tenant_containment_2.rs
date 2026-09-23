//! Adversarial pass 2 on `story:identity-tenant-containment`.
//!
//! `IncrementSecurityEpoch::execute` refuses a principal target when any recorded event places
//! it in another organization, and states why (`src/increment.rs`, `contained`): "its
//! generation gates its sessions in each of them, so one record elsewhere is enough to
//! refuse". `TargetTenancy::organizations_of` (`src/port.rs`) never forgets a placement: a
//! session the other organization has since revoked still places the principal there, although
//! its generation then gates no session of that organization at all.
//!
//! The consequence is on the revocation lever itself: the caller's own organization can no
//! longer advance the generation its own live session is bound to, so that session keeps
//! refreshing.

use mandate_identity::{
    EpochSnapshotRecorded, Generation, IdentityEvent, IdentityLog, IdentityRead,
    IncrementSecurityEpoch, SecurityEpochRecorded, SessionOpened, refresh_session, revoke_session,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, OrganizationId,
    PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x21))
}

fn organization_a() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn organization_b() -> OrganizationId {
    OrganizationId::new(uuid(0x0b))
}

fn context_in(organization: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x01)),
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0x05)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn open(log: &mut IdentityLog, snapshot: u8, session: u8, organization: OrganizationId) {
    log.try_record(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: EpochSnapshotRef::new(uuid(snapshot)),
            principal_id: principal(),
            organization_id: organization,
            connection_id: None,
        },
    ))
    .expect("every dimension the snapshot names is stated");
    log.try_record(IdentityEvent::SessionOpened(SessionOpened {
        id: SessionId::new(uuid(session)),
        principal_id: principal(),
        organization_id: organization,
        connection_id: None,
        epochs: EpochSnapshotRef::new(uuid(snapshot)),
        expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
    }))
    .expect("the snapshot the opening names is recorded");
}

/// The principal's one session in organization B was revoked by B. Its only live session is in
/// organization A, and A's caller advances the principal's generation to end it.
#[test]
fn a_principal_whose_only_other_organization_session_is_revoked_can_be_advanced_by_its_own_organization()
 {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));
    for stated in [
        target.clone(),
        SecurityEpochTarget::Organization(organization_a()),
        SecurityEpochTarget::Organization(organization_b()),
    ] {
        log.try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: stated,
                generation: Generation::ZERO,
            },
        ))
        .expect("a first generation");
    }
    open(&mut log, 0x51, 0x61, organization_b());
    revoke_session(
        &mut log,
        &context_in(organization_b()),
        SessionId::new(uuid(0x61)),
    )
    .expect("organization B revokes its own session");
    open(&mut log, 0x52, 0x62, organization_a());

    let in_a = SessionId::new(uuid(0x62));
    assert!(
        refresh_session(&log, &in_a).is_ok(),
        "precondition: the session in A is live"
    );
    assert!(
        refresh_session(&log, &SessionId::new(uuid(0x61))).is_err(),
        "precondition: no session of B is live"
    );

    let expected = log.current(&target).version();
    let decided = IncrementSecurityEpoch::new(context_in(organization_a()), target.clone())
        .execute(&mut log, expected)
        .map_err(|denial| denial.reason());

    assert_eq!(
        decided.as_ref().map(|_| ()),
        Ok(()),
        "organization A was refused the increment of a principal whose generation gates no live \
         session outside A: a revoked session in B still places the principal there \
         (TargetTenancy::organizations_of never forgets a placement)"
    );
    assert_eq!(
        refresh_session(&log, &in_a)
            .map_err(|denial| denial.reason())
            .err(),
        Some(DenialReason::StaleEpoch),
        "A's own session outlives the increment A asked for"
    );
}
