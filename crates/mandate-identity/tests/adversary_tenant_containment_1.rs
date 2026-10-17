//! Adversarial pass 1 on `story:identity-tenant-containment`.
//!
//! `IncrementSecurityEpoch::execute` decides tenancy with one read
//! (`TargetTenancy::organizations_of`) and then advances the generation with a second call
//! (`SecurityEpochWrite::increment`) whose compare-and-set token is the target's stream
//! version. Recording a snapshot or opening a session places a target in an organization
//! without moving that version, so the containment decision is not covered by the token: a
//! placement that commits between the two calls is invisible to both.
//!
//! `identity.yaml` (`IncrementSecurityEpoch`, accepted summary) requires the adapter to
//! "atomically increment the one selected generation ... and preserve isolation of unrelated
//! organizations/connections". The port below is the in-memory log with one concurrent
//! writer interleaved between the two calls — the ordering any adapter that is not held
//! under one `&mut` admits.

use mandate_identity::{
    Denial, EpochSnapshotRecorded, EpochState, Generation, IdentityEvent, IdentityLog,
    IdentityRead, IncrementSecurityEpoch, SecurityEpochRecorded, SecurityEpochWrite, SessionOpened,
    StreamVersion, TargetTenancy,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef, OrganizationId,
    PrincipalId, SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn caller_organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0b))
}

/// A principal whose generation is stated and that no record yet places anywhere.
fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x41))
}

fn snapshot_ref() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x51))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x01)),
        actor: None,
        organization: caller_organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0x05)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// The in-memory log, with another organization's login committing between the tenancy
/// read and the compare-and-set.
struct Interleaved {
    log: IdentityLog,
    landing: Vec<IdentityEvent>,
}

impl TargetTenancy for Interleaved {
    fn organizations_of(&self, target: &SecurityEpochTarget) -> Vec<OrganizationId> {
        self.log.organizations_of(target)
    }
}

impl SecurityEpochWrite for Interleaved {
    fn increment(
        &mut self,
        context: &VerifiedContext,
        target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial> {
        for event in std::mem::take(&mut self.landing) {
            self.log
                .try_record(event)
                .expect("the concurrent login is well-formed and ordered");
        }
        self.log.increment(context, target, expected)
    }
}

/// The tenancy read and the compare-and-set are still two port calls with no shared token
/// (`decision-blocker:epoch-atomicity`), but a target no record places anywhere is not contained
/// in the caller's organization: containment fails closed on an empty placement list. So the
/// interleaved login cannot be advanced past: the read sees no placement, the increment refuses
/// with `TenantMismatch` before the write, and the generation stays at 0.
#[test]
fn a_placement_committing_between_the_tenancy_read_and_the_compare_and_set_is_not_advanced_past() {
    let target = SecurityEpochTarget::Principal(principal());
    let mut log = IdentityLog::new().with_as_of(Timestamp::new("2026-09-18T00:00:00Z"));
    for stated in [
        target.clone(),
        SecurityEpochTarget::Organization(other_organization()),
    ] {
        log.try_record(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target: stated,
                generation: Generation::ZERO,
            },
        ))
        .expect("a first generation");
    }
    assert!(
        log.organizations_of(&target).is_empty(),
        "precondition: no record places the principal yet"
    );
    let expected = log.current(&target).version();

    // The other organization's login: snapshot, then the session bound to it.
    let landing = vec![
        IdentityEvent::EpochSnapshotRecorded(EpochSnapshotRecorded {
            id: snapshot_ref(),
            principal_id: principal(),
            organization_id: other_organization(),
            connection_id: None,
        }),
        IdentityEvent::SessionOpened(SessionOpened {
            id: SessionId::new(uuid(0x61)),
            principal_id: principal(),
            organization_id: other_organization(),
            connection_id: None,
            epochs: snapshot_ref(),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
            authenticated_at: None,
            external_principal_id: None,
        }),
    ];
    let mut port = Interleaved { log, landing };

    let decided = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut port, expected)
        .map_err(|denial| denial.reason());

    assert_eq!(
        decided.map(|_| ()),
        Err(DenialReason::TenantMismatch),
        "a target no record places anywhere is not contained in the caller's organization"
    );
    assert_eq!(
        port.landing.len(),
        2,
        "the refusal comes from the tenancy read, before the compare-and-set is reached"
    );
    assert_eq!(
        port.log.current(&target).generation(),
        Generation::ZERO,
        "the refused increment leaves the generation unmoved"
    );

    // The other organization's login then commits; its fresh session is bound to the generation
    // the refused increment left in place.
    for event in std::mem::take(&mut port.landing) {
        port.log
            .try_record(event)
            .expect("the concurrent login is well-formed and ordered");
    }
    let bound = port
        .log
        .snapshot(&snapshot_ref())
        .expect("the snapshot is recorded")
        .recorded(&target)
        .expect("the snapshot names the principal");
    assert_eq!(bound, port.log.current(&target).generation());
}
