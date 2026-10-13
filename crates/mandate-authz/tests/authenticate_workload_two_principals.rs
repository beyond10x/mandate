//! `mandate.workload.AuthenticateWorkload`, read against the wave's stated invariant: the
//! agent is never derived from the workload proof, a retired agent or a disabled principal
//! refuses, and the runtime and the agent stay two principals in the event.
//!
//! `systems/mandate/domains/workload.yaml`, `AuthenticateWorkload.accepted`: "Two identities,
//! each authenticated on its own." The world is the one `workload_authentication.rs` builds:
//! one organization, a workload identity whose runtime principal is installed as an agent of
//! that organization too (as `the_agent_is_never_derived_from_the_workload_proof` arranges
//! it), and a trust domain that verifies one proof as that identity's binding.

use mandate_authz::agent::{AgentRecords, PrincipalStanding};
use mandate_authz::delegation::{Agent, AgentState};
use mandate_authz::workload::{
    AuthenticateWorkload, ConfiguredTrustDomains, VerifiedWorkload, decide_authenticate_workload,
};
use mandate_model::workload::{WorkloadIdentities, WorkloadIdentity, WorkloadIdentityState};
use mandate_types::{
    CredentialProof, ExternalSubject, OrganizationId, PrincipalId, Timestamp, TrustDomain, Uuid,
    WorkloadIdentityId,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

/// The application agent the caller names in the control case.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

/// The runtime principal the workload identity binds.
fn runtime() -> PrincipalId {
    PrincipalId::new(uuid(7))
}

fn now() -> Timestamp {
    Timestamp::new("2026-06-01T12:00:00Z")
}

fn proof() -> CredentialProof {
    CredentialProof::from_bytes(b"workload-proof".to_vec())
}

fn verifier() -> ConfiguredTrustDomains {
    ConfiguredTrustDomains::new().with_proof(
        proof(),
        VerifiedWorkload {
            trust_domain: TrustDomain::new("spiffe://cluster.example"),
            external_subject: ExternalSubject::new("spiffe://cluster.example/ns/jobs/sa/runner"),
            expires_at: Timestamp::new("2026-06-01T13:00:00Z"),
        },
    )
}

fn workloads() -> WorkloadIdentities {
    WorkloadIdentities::holding([WorkloadIdentity {
        id: WorkloadIdentityId::new(uuid(0x20)),
        organization_id: organization(),
        principal_id: runtime(),
        trust_domain: TrustDomain::new("spiffe://cluster.example"),
        external_subject: ExternalSubject::new("spiffe://cluster.example/ns/jobs/sa/runner"),
        state: WorkloadIdentityState::Recorded,
    }])
}

fn installed(principal: PrincipalId) -> Agent {
    Agent {
        id: principal,
        organization_id: organization(),
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
    }
}

/// Both principals active, and both installed as agents of the organization.
fn records() -> AgentRecords {
    AgentRecords {
        standings: vec![
            (agent(), PrincipalStanding::Active),
            (runtime(), PrincipalStanding::Active),
        ],
        agents: vec![installed(agent()), installed(runtime())],
        ..AgentRecords::new()
    }
}

fn request(agent: PrincipalId) -> AuthenticateWorkload {
    AuthenticateWorkload {
        workload_proof: proof(),
        agent,
        execution: None,
    }
}

/// The runtime and the agent stay two principals: a caller naming the workload's own
/// runtime principal as the application agent does not get one principal authenticated as
/// both identities.
#[test]
fn invariant_3_the_runtime_is_never_authenticated_as_its_own_agent() {
    // The control: the pair of two distinct principals is admitted in this world.
    decide_authenticate_workload(
        &verifier(),
        &workloads(),
        &records(),
        &request(agent()),
        &now(),
    )
    .expect("the control: a distinct agent is admitted");

    let decided = decide_authenticate_workload(
        &verifier(),
        &workloads(),
        &records(),
        &request(runtime()),
        &now(),
    );
    assert!(
        decided.is_err(),
        "the runtime principal was authenticated as the application agent it runs: {:?}",
        decided.map(|authenticated| authenticated.event)
    );
}

/// A disabled principal refuses: the runtime principal the proof resolves to, disabled,
/// is not authenticated as a workload runtime.
#[test]
fn invariant_3_a_disabled_runtime_principal_is_refused() {
    let mut records = records();
    records
        .standings
        .push((runtime(), PrincipalStanding::Disabled));
    let decided = decide_authenticate_workload(
        &verifier(),
        &workloads(),
        &records,
        &request(agent()),
        &now(),
    );
    assert!(
        decided.is_err(),
        "a disabled runtime principal was authenticated: {:?}",
        decided.map(|authenticated| authenticated.event)
    );
}
