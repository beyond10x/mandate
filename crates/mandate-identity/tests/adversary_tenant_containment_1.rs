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
    Audience, CorrelationId, CredentialId, EpochSnapshotRef, OrganizationId, PrincipalId,
    SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
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

/// Pinned by the coordinator (correction round 1, F1) to the shipped behaviour: the tenancy read
/// and the compare-and-set are two port calls with no shared token, so the interleaved increment
/// is accepted and the generation moves 0 → 1. Making the check atomic with the write is the
/// transactional behaviour `decision-blocker:epoch-atomicity` owns; this case flips to a
/// `TenantMismatch` refusal with an unmoved generation when that blocker is answered.
#[test]
fn a_placement_committing_between_the_tenancy_read_and_the_compare_and_set_is_advanced_past_until_epoch_atomicity()
 {
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
        }),
    ];
    let mut port = Interleaved { log, landing };

    let decided = IncrementSecurityEpoch::new(context(), target.clone())
        .execute(&mut port, expected)
        .map_err(|denial| denial.reason());

    assert_eq!(
        port.log.organizations_of(&target),
        vec![other_organization()],
        "the concurrent login placed the principal in the other organization"
    );
    let bound = port
        .log
        .snapshot(&snapshot_ref())
        .expect("the snapshot is recorded")
        .recorded(&target)
        .expect("the snapshot names the principal");
    assert_eq!(
        bound,
        Generation::ZERO,
        "the fresh session is bound to generation 0"
    );
    assert!(
        decided.is_ok(),
        "the interleaved increment was refused ({decided:?}); the tenancy read is now covered \
         by the write's token, so decision-blocker:epoch-atomicity has been answered and this \
         pin must flip to a TenantMismatch refusal with an unmoved generation"
    );
    assert_eq!(
        port.log.current(&target).generation(),
        Generation::new(1).expect("a non-negative generation"),
        "the interleaved increment advanced the generation 0 -> 1 past the other organization's \
         fresh session; this is the unatomic check decision-blocker:epoch-atomicity owns, and the \
         assertion flips when that blocker is answered"
    );
}
