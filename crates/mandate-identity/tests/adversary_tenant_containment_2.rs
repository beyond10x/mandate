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
//!
//! Ruled by the coordinator (correction round 2): the fail-closed rule stands, and `contained`
//! now states it as a rule rather than as a claim about the other organization's sessions. The
//! case below pins that rule.

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
/// organization A, and A's caller asks to advance the principal's generation.
///
/// **A decided rule, pinned by the coordinator (correction round 2):** containment fails closed
/// on any recorded placement outside the caller's organization, live or not. Forgetting a
/// placement would need a session-liveness read the port does not have, and a wrong "not live"
/// answer would hand one organization another's lever. So A is refused `TenantMismatch`, the
/// generation does not move, and A's session keeps refreshing. Changing this is a deliberate
/// decision, not a fix.
#[test]
fn a_principal_with_a_revoked_session_in_another_organization_is_refused_to_its_own_organization() {
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
    let before = log.current(&target);
    let decided = IncrementSecurityEpoch::new(context_in(organization_a()), target.clone())
        .execute(&mut log, expected)
        .map_err(|denial| denial.reason());

    assert_eq!(
        decided.as_ref().map(|_| ()),
        Err(&DenialReason::TenantMismatch),
        "organization A advanced a principal the log still places in B through a revoked \
         session; the decided rule fails closed on any recorded placement, and changing it is a \
         deliberate decision, not a fix"
    );
    assert_eq!(
        log.current(&target),
        before,
        "the refused increment moved the generation"
    );
    assert!(
        refresh_session(&log, &in_a).is_ok(),
        "A's session stopped refreshing although the increment was refused"
    );
}
