//! `story:agent-security`, `mandate.workload.AuthenticateWorkload`: a workload runtime and the
//! application agent it runs, each authenticated on its own.
//!
//! Every rule asserted here is read off `systems/mandate/domains/workload.yaml`. The workload
//! proof is verified by the trust domain that issued it ([`TrustDomainVerifier`], answered here
//! by [`ConfiguredTrustDomains`]) and resolves to one recorded workload identity, which names
//! the runtime principal. The agent is a recorded, unretired agent of that identity's
//! organization whose principal is not disabled, read through [`AgentAuthorityRead`]; it is
//! named by the caller and never derived from the proof. A named execution is recorded, not
//! completed, unexpired, of that organization and of that agent. Accepted, the decision
//! returns `mandate.workload.WorkloadAuthenticated` and creates or moves nothing; refused, it
//! is one `mandate.workload.Denied` with one reason, whichever condition refused it.
//!
//! The world: one organization with an agent installed in it, a workload identity whose
//! runtime principal is a different principal from that agent, a trust domain that verifies
//! one proof as that identity's binding, and an open execution of the agent. Each refusal
//! below changes the one record or input it names.

use mandate_authz::agent::{AgentAuthorityRead, AgentRecords, PrincipalStanding};
use mandate_authz::delegation::{Agent, AgentState, Execution, ExecutionState};
use mandate_authz::workload::{
    AuthenticateWorkload, AuthenticationClause, ConfiguredTrustDomains, Denied, ProofRefused,
    TrustDomainVerifier, VerifiedWorkload, decide_authenticate_workload,
};
use mandate_model::workload::{
    WorkloadEvent, WorkloadIdentities, WorkloadIdentity, WorkloadIdentityState,
};
use mandate_types::{
    CredentialProof, DenialReason, ExecutionId, ExternalSubject, OrganizationId, PolicyVersion,
    PrincipalId, Timestamp, TrustDomain, Uuid, WorkloadIdentityId,
};

// ---------------------------------------------------------------------------------------------
// The world.
// ---------------------------------------------------------------------------------------------

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

/// The application agent the caller names.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

/// Another agent of the same organization.
fn other_agent() -> PrincipalId {
    PrincipalId::new(uuid(6))
}

/// The runtime principal the workload identity binds: never the agent.
fn runtime() -> PrincipalId {
    PrincipalId::new(uuid(7))
}

fn workload() -> WorkloadIdentityId {
    WorkloadIdentityId::new(uuid(0x20))
}

fn execution() -> ExecutionId {
    ExecutionId::new(uuid(0x30))
}

fn trust_domain() -> TrustDomain {
    TrustDomain::new("spiffe://cluster.example")
}

fn subject() -> ExternalSubject {
    ExternalSubject::new("spiffe://cluster.example/ns/jobs/sa/runner")
}

/// The decision instant.
fn now() -> Timestamp {
    Timestamp::new("2026-06-01T12:00:00Z")
}

/// The proof the trust domain verifies.
fn proof() -> CredentialProof {
    CredentialProof::from_bytes(b"workload-proof".to_vec())
}

/// What the trust domain answers for [`proof`]: the binding, valid for an hour.
fn verified() -> VerifiedWorkload {
    VerifiedWorkload {
        trust_domain: trust_domain(),
        external_subject: subject(),
        expires_at: Timestamp::new("2026-06-01T13:00:00Z"),
    }
}

fn verifier() -> ConfiguredTrustDomains {
    ConfiguredTrustDomains::new().with_proof(proof(), verified())
}

fn identity(
    id: WorkloadIdentityId,
    organization: OrganizationId,
    state: WorkloadIdentityState,
) -> WorkloadIdentity {
    WorkloadIdentity {
        id,
        organization_id: organization,
        principal_id: runtime(),
        trust_domain: trust_domain(),
        external_subject: subject(),
        state,
    }
}

fn workloads() -> WorkloadIdentities {
    WorkloadIdentities::holding([identity(
        workload(),
        organization(),
        WorkloadIdentityState::Recorded,
    )])
}

fn installed(principal: PrincipalId, organization: OrganizationId) -> Agent {
    Agent {
        id: principal,
        organization_id: organization,
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
    }
}

fn open_execution() -> Execution {
    Execution {
        id: execution(),
        organization_id: organization(),
        agent_id: agent(),
        subject: None,
        delegation_id: None,
        initiating_session: None,
        created_at: Timestamp::new("2026-06-01T11:00:00Z"),
        expires_at: Timestamp::new("2026-06-01T14:00:00Z"),
        policy_version: PolicyVersion::new("1"),
        state: ExecutionState::Recorded,
    }
}

fn records() -> AgentRecords {
    AgentRecords {
        standings: vec![
            (agent(), PrincipalStanding::Active),
            (runtime(), PrincipalStanding::Active),
        ],
        agents: vec![
            installed(agent(), organization()),
            installed(other_agent(), organization()),
        ],
        executions: vec![open_execution()],
        ..AgentRecords::new()
    }
}

fn request(execution: Option<ExecutionId>) -> AuthenticateWorkload {
    AuthenticateWorkload {
        workload_proof: proof(),
        agent: agent(),
        execution,
    }
}

/// Decide over the given world at [`now`].
fn decide(
    verifier: &dyn TrustDomainVerifier,
    workloads: &WorkloadIdentities,
    records: &AgentRecords,
    request: &AuthenticateWorkload,
) -> Result<mandate_authz::workload::Authenticated, Denied> {
    decide_authenticate_workload(verifier, workloads, records, request, &now())
}

/// The refusal, and that the clause it names is `clause`.
fn refused(
    verifier: &dyn TrustDomainVerifier,
    workloads: &WorkloadIdentities,
    records: &AgentRecords,
    request: &AuthenticateWorkload,
    clause: AuthenticationClause,
) -> Denied {
    let denied = decide(verifier, workloads, records, request).expect_err("the request is refused");
    assert_eq!(denied.clause, clause, "refused on {:?}", denied.clause);
    assert_eq!(denied.reason, DenialReason::Denied);
    denied
}

// ---------------------------------------------------------------------------------------------
// Accepted.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_workload_and_its_agent_are_authenticated_each_on_its_own() {
    let authenticated = decide(&verifier(), &workloads(), &records(), &request(None))
        .expect("the pair is admitted");

    assert_eq!(authenticated.workload, workload());
    assert_eq!(authenticated.runtime, runtime());
    assert_eq!(authenticated.organization, organization());
    assert_eq!(
        authenticated.event,
        WorkloadEvent::Authenticated {
            workload: workload(),
            runtime: runtime(),
            agent: agent(),
            organization: organization(),
            execution: None,
            authenticated_at: now(),
        }
    );
    assert_eq!(
        authenticated.event.ess_name(),
        "mandate.workload.WorkloadAuthenticated"
    );
    // Two identities: the runtime the proof names and the agent the caller names.
    let WorkloadEvent::Authenticated { runtime, agent, .. } = &authenticated.event else {
        panic!("the authentication event");
    };
    assert_ne!(runtime, agent, "the agent is not the workload's runtime");
}

#[test]
fn a_named_execution_of_the_agent_is_authenticated_with_the_pair() {
    let authenticated = decide(
        &verifier(),
        &workloads(),
        &records(),
        &request(Some(execution())),
    )
    .expect("the pair and its execution are admitted");

    assert_eq!(
        authenticated.event,
        WorkloadEvent::Authenticated {
            workload: workload(),
            runtime: runtime(),
            agent: agent(),
            organization: organization(),
            execution: Some(execution()),
            authenticated_at: now(),
        }
    );
}

#[test]
fn a_revoked_binding_beside_a_recorded_one_resolves_to_the_recorded_one() {
    let replacement = WorkloadIdentityId::new(uuid(0x21));
    let workloads = WorkloadIdentities::holding([
        identity(workload(), organization(), WorkloadIdentityState::Revoked),
        identity(replacement, organization(), WorkloadIdentityState::Recorded),
    ]);
    let authenticated = decide(&verifier(), &workloads, &records(), &request(None))
        .expect("the recorded binding is the one admitted");
    assert_eq!(authenticated.workload, replacement);
}

#[test]
fn an_accepted_authentication_creates_and_moves_nothing() {
    let workloads = workloads();
    let records = records();
    let authenticated = decide(
        &verifier(),
        &workloads,
        &records,
        &request(Some(execution())),
    )
    .expect("the pair is admitted");

    // The event folds into no record.
    let mut folded = workloads.clone();
    folded.apply(&authenticated.event);
    assert_eq!(folded, workloads, "the event folds into no workload record");
    assert_eq!(records, self::records(), "no agent record was touched");
}

// ---------------------------------------------------------------------------------------------
// The workload proof.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_malformed_proof_is_refused() {
    let malformed = AuthenticateWorkload {
        workload_proof: CredentialProof::from_bytes(Vec::new()),
        ..request(None)
    };
    refused(
        &verifier(),
        &workloads(),
        &records(),
        &malformed,
        AuthenticationClause::ProofMalformed,
    );
}

#[test]
fn a_proof_its_trust_domain_does_not_verify_is_refused() {
    let forged = AuthenticateWorkload {
        workload_proof: CredentialProof::from_bytes(b"another-proof".to_vec()),
        ..request(None)
    };
    refused(
        &verifier(),
        &workloads(),
        &records(),
        &forged,
        AuthenticationClause::ProofUnverified,
    );
}

#[test]
fn an_expired_proof_is_refused() {
    // Expiring exactly at the decision instant is expired.
    let verifier = ConfiguredTrustDomains::new().with_proof(
        proof(),
        VerifiedWorkload {
            expires_at: now(),
            ..verified()
        },
    );
    refused(
        &verifier,
        &workloads(),
        &records(),
        &request(None),
        AuthenticationClause::ProofExpired,
    );

    // Compared as instants, not bytes: an offset that names an earlier instant is expired.
    let verifier = ConfiguredTrustDomains::new().with_proof(
        proof(),
        VerifiedWorkload {
            expires_at: Timestamp::new("2026-06-01T13:30:00+02:00"),
            ..verified()
        },
    );
    refused(
        &verifier,
        &workloads(),
        &records(),
        &request(None),
        AuthenticationClause::ProofExpired,
    );
}

#[test]
fn a_verifier_that_cannot_answer_refuses_as_unavailable() {
    struct Unreachable;
    impl TrustDomainVerifier for Unreachable {
        fn verify(
            &self,
            _proof: &CredentialProof,
            _at: &Timestamp,
        ) -> Result<VerifiedWorkload, ProofRefused> {
            Err(ProofRefused::Unavailable)
        }
    }
    let denied = decide(&Unreachable, &workloads(), &records(), &request(None))
        .expect_err("an outage refuses");
    assert_eq!(denied.reason, DenialReason::Unavailable);
    assert_eq!(denied.clause, AuthenticationClause::Unavailable);
}

// ---------------------------------------------------------------------------------------------
// Resolution.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_proof_that_resolves_to_no_workload_identity_is_refused() {
    refused(
        &verifier(),
        &WorkloadIdentities::default(),
        &records(),
        &request(None),
        AuthenticationClause::WorkloadUnresolved,
    );
}

#[test]
fn a_revoked_workload_identity_refuses() {
    let revoked = WorkloadIdentities::holding([identity(
        workload(),
        organization(),
        WorkloadIdentityState::Revoked,
    )]);
    refused(
        &verifier(),
        &revoked,
        &records(),
        &request(None),
        AuthenticationClause::WorkloadRevoked,
    );

    // Revoked through the command's own fold, not only arranged.
    let mut folded = workloads();
    folded.apply(&WorkloadEvent::IdentityRevoked {
        context: mandate_types::VerifiedContext {
            subject: other_agent(),
            actor: None,
            organization: organization(),
            audience: mandate_types::Audience::new("mandate"),
            credential: mandate_types::CredentialId::new(uuid(0x40)),
            delegation: None,
            execution: None,
            correlation: mandate_types::CorrelationId::new("correlation"),
        },
        id: workload(),
    });
    refused(
        &verifier(),
        &folded,
        &records(),
        &request(None),
        AuthenticationClause::WorkloadRevoked,
    );
}

/// `workload.yaml`, `RevokeWorkloadIdentity` denied: "revocation cannot durably stop the
/// exchange of workload credentials presented under the binding". The revocation the command
/// accepts is the one the exchange reads: the binding authenticates before it, and the same
/// proof is refused on the revoked clause once `decide_revoke_workload_identity`'s event is
/// applied to the records `AuthenticateWorkload` reads.
#[test]
fn revoked_binding_refuses_authentication() {
    let mut workloads = workloads();
    decide(&verifier(), &workloads, &records(), &request(None))
        .expect("the binding authenticates before it is revoked");

    let administrator = mandate_types::VerifiedContext {
        subject: other_agent(),
        actor: None,
        organization: organization(),
        audience: mandate_types::Audience::new("mandate"),
        credential: mandate_types::CredentialId::new(uuid(0x41)),
        delegation: None,
        execution: None,
        correlation: mandate_types::CorrelationId::new("revocation"),
    };
    let revoked = mandate_model::workload::decide_revoke_workload_identity(
        &workloads,
        &administrator,
        workload(),
    )
    .expect("the caller's own recorded binding is revoked");
    workloads.apply(&revoked);

    refused(
        &verifier(),
        &workloads,
        &records(),
        &request(None),
        AuthenticationClause::WorkloadRevoked,
    );
    refused(
        &verifier(),
        &workloads,
        &records(),
        &request(Some(execution())),
        AuthenticationClause::WorkloadRevoked,
    );
}

#[test]
fn a_binding_two_recorded_identities_carry_is_refused_as_ambiguous() {
    let ambiguous = WorkloadIdentities::holding([
        identity(workload(), organization(), WorkloadIdentityState::Recorded),
        identity(
            WorkloadIdentityId::new(uuid(0x21)),
            other_organization(),
            WorkloadIdentityState::Recorded,
        ),
    ]);
    refused(
        &verifier(),
        &ambiguous,
        &records(),
        &request(None),
        AuthenticationClause::WorkloadAmbiguous,
    );
}

#[test]
fn a_workload_identity_of_another_organization_than_the_agent_is_refused() {
    let foreign = WorkloadIdentities::holding([identity(
        workload(),
        other_organization(),
        WorkloadIdentityState::Recorded,
    )]);
    refused(
        &verifier(),
        &foreign,
        &records(),
        &request(None),
        AuthenticationClause::OrganizationMismatch,
    );
}

// ---------------------------------------------------------------------------------------------
// The agent.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unrecorded_agent_is_refused() {
    let unrecorded = AuthenticateWorkload {
        agent: PrincipalId::new(uuid(0x50)),
        ..request(None)
    };
    refused(
        &verifier(),
        &workloads(),
        &records(),
        &unrecorded,
        AuthenticationClause::AgentUnrecorded,
    );
}

#[test]
fn an_agent_of_another_organization_refuses_like_an_unrecorded_one() {
    let mut foreign = records();
    foreign.agents = vec![installed(agent(), other_organization())];
    let mut unrecorded = records();
    unrecorded.agents = Vec::new();

    let foreign = decide(&verifier(), &workloads(), &foreign, &request(None))
        .expect_err("an agent of another organization is refused");
    let unrecorded = decide(&verifier(), &workloads(), &unrecorded, &request(None))
        .expect_err("an unrecorded agent is refused");

    assert_eq!(foreign.reason, unrecorded.reason);
    assert_eq!(foreign.contract(), unrecorded.contract());
}

#[test]
fn the_agent_is_never_derived_from_the_workload_proof() {
    // The runtime the proof resolves to is itself an installed agent; the caller names a
    // principal that is not one. The decision does not fall back to the runtime.
    let mut records = records();
    records.agents.push(installed(runtime(), organization()));
    let not_an_agent = AuthenticateWorkload {
        agent: PrincipalId::new(uuid(0x51)),
        ..request(None)
    };
    refused(
        &verifier(),
        &workloads(),
        &records,
        &not_an_agent,
        AuthenticationClause::AgentUnrecorded,
    );
}

#[test]
fn a_retired_agent_is_refused() {
    let mut records = records();
    records.agents = vec![Agent {
        state: AgentState::Retired,
        ..installed(agent(), organization())
    }];
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(None),
        AuthenticationClause::AgentRetired,
    );
}

#[test]
fn an_agent_whose_principal_is_disabled_is_refused() {
    let mut records = records();
    records
        .standings
        .push((agent(), PrincipalStanding::Disabled));
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(None),
        AuthenticationClause::AgentPrincipalDisabled,
    );
}

// ---------------------------------------------------------------------------------------------
// The execution.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unrecorded_execution_is_refused() {
    refused(
        &verifier(),
        &workloads(),
        &records(),
        &request(Some(ExecutionId::new(uuid(0x31)))),
        AuthenticationClause::ExecutionUnrecorded,
    );
}

#[test]
fn a_completed_execution_is_refused() {
    let mut records = records();
    records.executions = vec![Execution {
        state: ExecutionState::Completed,
        ..open_execution()
    }];
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(Some(execution())),
        AuthenticationClause::ExecutionCompleted,
    );
}

#[test]
fn an_expired_execution_is_refused() {
    let mut records = records();
    records.executions = vec![Execution {
        expires_at: now(),
        ..open_execution()
    }];
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(Some(execution())),
        AuthenticationClause::ExecutionExpired,
    );
}

#[test]
fn an_execution_of_another_agent_is_refused() {
    let mut records = records();
    records.executions = vec![Execution {
        agent_id: other_agent(),
        ..open_execution()
    }];
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(Some(execution())),
        AuthenticationClause::ExecutionBoundElsewhere,
    );
}

#[test]
fn an_execution_of_another_organization_is_refused() {
    let mut records = records();
    records.executions = vec![Execution {
        organization_id: other_organization(),
        ..open_execution()
    }];
    refused(
        &verifier(),
        &workloads(),
        &records,
        &request(Some(execution())),
        AuthenticationClause::ExecutionBoundElsewhere,
    );
}

// ---------------------------------------------------------------------------------------------
// Every refusal.
// ---------------------------------------------------------------------------------------------

/// Every refusing world above, by the clause it refuses on.
fn every_refusal() -> Vec<Denied> {
    let other_proof = AuthenticateWorkload {
        workload_proof: CredentialProof::from_bytes(b"another-proof".to_vec()),
        ..request(None)
    };
    let empty_proof = AuthenticateWorkload {
        workload_proof: CredentialProof::from_bytes(Vec::new()),
        ..request(None)
    };
    let expired = ConfiguredTrustDomains::new().with_proof(
        proof(),
        VerifiedWorkload {
            expires_at: now(),
            ..verified()
        },
    );
    let revoked = WorkloadIdentities::holding([identity(
        workload(),
        organization(),
        WorkloadIdentityState::Revoked,
    )]);
    let foreign = WorkloadIdentities::holding([identity(
        workload(),
        other_organization(),
        WorkloadIdentityState::Recorded,
    )]);
    let mut retired = records();
    retired.agents = vec![Agent {
        state: AgentState::Retired,
        ..installed(agent(), organization())
    }];
    let mut disabled = records();
    disabled
        .standings
        .push((agent(), PrincipalStanding::Disabled));
    let mut completed = records();
    completed.executions = vec![Execution {
        state: ExecutionState::Completed,
        ..open_execution()
    }];
    let unrecorded_agent = AuthenticateWorkload {
        agent: PrincipalId::new(uuid(0x50)),
        ..request(None)
    };

    [
        decide(&verifier(), &workloads(), &records(), &empty_proof),
        decide(&verifier(), &workloads(), &records(), &other_proof),
        decide(&expired, &workloads(), &records(), &request(None)),
        decide(
            &verifier(),
            &WorkloadIdentities::default(),
            &records(),
            &request(None),
        ),
        decide(&verifier(), &revoked, &records(), &request(None)),
        decide(&verifier(), &foreign, &records(), &request(None)),
        decide(&verifier(), &workloads(), &records(), &unrecorded_agent),
        decide(&verifier(), &workloads(), &retired, &request(None)),
        decide(&verifier(), &workloads(), &disabled, &request(None)),
        decide(
            &verifier(),
            &workloads(),
            &records(),
            &request(Some(ExecutionId::new(uuid(0x31)))),
        ),
        decide(
            &verifier(),
            &workloads(),
            &completed,
            &request(Some(execution())),
        ),
    ]
    .into_iter()
    .map(|decided| decided.expect_err("every world here refuses"))
    .collect()
}

#[test]
fn every_refusal_is_one_denied_with_one_reason() {
    let refusals = every_refusal();
    let clauses: std::collections::BTreeSet<AuthenticationClause> =
        refusals.iter().map(|denied| denied.clause).collect();
    assert_eq!(
        clauses.len(),
        refusals.len(),
        "each world refuses on its own clause"
    );
    for denied in &refusals {
        assert_eq!(
            denied.contract(),
            mandate_model::workload::Denied {
                reason: DenialReason::Denied
            },
            "{:?} answers the caller something other than the one refusal",
            denied.clause
        );
    }
}

#[test]
fn a_refusal_writes_nothing() {
    let workloads = workloads();
    let records = records();
    let mut retired = records.clone();
    retired.agents = vec![Agent {
        state: AgentState::Retired,
        ..installed(agent(), organization())
    }];

    decide(
        &verifier(),
        &workloads,
        &retired,
        &request(Some(execution())),
    )
    .expect_err("a retired agent is refused");

    assert_eq!(workloads, self::workloads(), "no workload record moved");
    assert_eq!(
        retired.agent(&agent()).expect("readable"),
        Some(Agent {
            state: AgentState::Retired,
            ..installed(agent(), organization())
        }),
        "no agent record moved"
    );
    assert_eq!(
        retired.execution(&execution()).expect("readable"),
        Some(open_execution()),
        "no execution moved"
    );
}
