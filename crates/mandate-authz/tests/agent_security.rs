//! `story:agent-security`: the policy enforcement point decides a delegated request through the
//! record checks the token exchange already applies, never through a second implementation of
//! them and never by refusing it wholesale.
//!
//! The story's acceptance: given an administrator delegates an action outside an agent
//! installation ceiling, when the agent invokes that privileged tool, then the PEP denies the
//! action under the preserved subject and actor identities. Every case drives
//! [`mandate_authz::check`] — the decision a PEP asks for — with the agent, its ceilings, the
//! delegation and the execution arranged as records behind [`AgentAuthorityRead`], the port a
//! fold of the `mandate.delegation` events answers. `SupersedeAgentCapabilityCeiling` cannot
//! yet create a ceiling (`docs/plans/2026-10-13-wave-7-execution.md`), so the ceilings are
//! fixtures of that port and nothing else.
//!
//! The world is built so a refusal is attributable: the graph holds a grant for the subject
//! alone, so an allowed delegated request shows the subject's authority was read and not the
//! actor's, and each refusal below has a control that differs from it in the one record the
//! case names.

use mandate_authz::agent::{
    AgentAuthorityRead, AgentRecords, AuthorityClause, AuthorityDecision, AuthorityRequest,
    PrincipalStanding, ValidatedProof, evaluate_agent_authority,
};
use mandate_authz::decision::{Denied, FixedChallenge, SequentialDecisionIds};
use mandate_authz::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, CeilingState, Delegation, DelegationState,
    Execution, ExecutionState,
};
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::double::GraphDouble;
use mandate_graph::record::Grant;
use mandate_graph::topology::ResourceRegistry;
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{AttributeSet, ChallengeRequirement};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, Audience, AuthorityScope, AuthoritySubject,
    AuthorizationModelId, AuthzRevision, CorrelationId, CredentialId, DecisionReason, DelegationId,
    DenialReason, Duration, ExecutionId, GrantId, OrganizationId, OrganizationMembershipId,
    PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, Timestamp, Uuid,
    VerifiedContext,
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

/// The administrator who delegates: the subject of every delegated request.
fn user() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

/// The agent installation the delegation is to: the actor of every delegated request.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

/// A second agent, the subject of the case where the delegator is itself an agent.
fn second_agent() -> PrincipalId {
    PrincipalId::new(uuid(4))
}

fn delegation_id() -> DelegationId {
    DelegationId::new(uuid(20))
}

fn execution_id() -> ExecutionId {
    ExecutionId::new(uuid(21))
}

fn audience() -> Audience {
    Audience::new("mandate")
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("deployment"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

/// The tool inside every ceiling.
fn read_tool() -> Action {
    Action::new("tool.read")
}

/// The privileged tool: delegated, granted and allowed by policy, and outside the
/// installation ceiling.
fn privileged_tool() -> Action {
    Action::new("tool.delete")
}

fn both_tools() -> AuthorityScope {
    AuthorityScope {
        actions: vec![read_tool(), privileged_tool()],
        resources: vec![resource()],
        space: None,
    }
}

/// The decision instant.
fn at() -> Timestamp {
    Timestamp::new("2026-01-05T09:00:00Z")
}

fn plain_context(subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization: organization(),
        audience: audience(),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("agent-security"),
    }
}

/// The context a delegated tool call is checked under: the subject preserved, the agent as
/// the actor, the delegation it acts under, and the execution when one is named.
fn delegated_context(
    subject: PrincipalId,
    delegation: DelegationId,
    execution: Option<ExecutionId>,
) -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        delegation: Some(delegation),
        execution,
        ..plain_context(subject)
    }
}

/// Every principal of the world is a member of the organization.
fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&plain_context(user()), organization(), "acme")
        .expect("the organization is recorded");
    for (index, principal) in [user(), agent(), second_agent()].into_iter().enumerate() {
        let membership =
            OrganizationMembershipId::new(uuid(50 + u8::try_from(index).expect("three")));
        tenancy
            .add_organization_membership(
                &plain_context(user()),
                MembershipAuthority::VerifiedOrganization,
                membership,
                organization(),
                principal,
            )
            .expect("a member");
    }
    tenancy
}

/// The graph: the resource registered, and an `operator` grant over both tools for each
/// principal in `holders`, and for nobody else.
fn graph(holders: &[PrincipalId]) -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    let mut revision = AuthzRevision::new("0");
    graph
        .register_resource(&plain_context(user()), &resource(), None)
        .expect("the resource is registered");
    for (index, principal) in holders.iter().enumerate() {
        let subject = AuthoritySubject::Principal(*principal);
        graph.admit_subject(organization(), subject.clone());
        revision = graph.record_grant(Grant::recorded(
            GrantId::new(uuid(30 + u8::try_from(index).expect("few"))),
            organization(),
            subject,
            both_tools(),
            "operator",
        ));
    }
    (graph, revision)
}

/// Policy allows every principal both tools, and `operator` carries both.
fn policy() -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_policy(Policy::recorded(
        PolicyId::new(uuid(40)),
        organization(),
        PolicyVersion::new("v1"),
        "source",
    ));
    policy.record_model(AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(41)),
        organization(),
        PolicyVersion::new("v1"),
        "schema",
    ));
    policy.record_role(
        organization(),
        "operator",
        vec![read_tool(), privileged_tool()],
    );
    for principal in [user(), agent(), second_agent()] {
        for action in [read_tool(), privileged_tool()] {
            policy.allow(
                organization(),
                AuthoritySubject::Principal(principal),
                action,
                resource(),
            );
        }
    }
    policy
}

fn agent_record(principal: PrincipalId) -> Agent {
    Agent {
        id: principal,
        organization_id: organization(),
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
    }
}

fn ceiling(
    byte: u8,
    agent_id: PrincipalId,
    organization_id: Option<OrganizationId>,
    allowed: &[&str],
    denied: &[&str],
) -> AgentCapabilityCeiling {
    AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(uuid(byte)),
        agent_id,
        organization_id,
        allowed_actions: allowed
            .iter()
            .map(|name| ActionPattern::new(*name))
            .collect(),
        denied_actions: denied
            .iter()
            .map(|name| ActionPattern::new(*name))
            .collect(),
        scope: both_tools(),
        max_delegation_ttl: Duration::new("PT1H"),
        state: CeilingState::Recorded,
    }
}

/// The platform ceiling: admits every tool.
fn platform_ceiling(agent_id: PrincipalId) -> AgentCapabilityCeiling {
    ceiling(60, agent_id, None, &["tool.*"], &[])
}

/// The installation ceiling: recorded for the organization, refusing the privileged tool.
fn installation_ceiling(agent_id: PrincipalId) -> AgentCapabilityCeiling {
    ceiling(
        61,
        agent_id,
        Some(organization()),
        &["tool.*"],
        &["tool.delete"],
    )
}

/// The administrator's delegation of both tools to the agent.
fn delegation(delegator: PrincipalId) -> Delegation {
    Delegation {
        id: delegation_id(),
        organization_id: organization(),
        delegator,
        delegate: agent(),
        scope: both_tools(),
        audience: audience(),
        not_before: None,
        expires_at: Timestamp::new("2026-01-05T20:00:00Z"),
        execution_binding: None,
        transitive: false,
        created_at: Timestamp::new("2026-01-05T08:00:00Z"),
        state: DelegationState::Active,
    }
}

/// The agent's execution for the administrator, under the delegation.
fn execution(expires_at: &str, state: ExecutionState) -> Execution {
    Execution {
        id: execution_id(),
        organization_id: organization(),
        agent_id: agent(),
        subject: Some(user()),
        delegation_id: Some(delegation_id()),
        initiating_session: None,
        created_at: Timestamp::new("2026-01-05T08:30:00Z"),
        expires_at: Timestamp::new(expires_at),
        policy_version: PolicyVersion::new("v1"),
        state,
    }
}

/// The records of a delegation from `delegator` to the agent, whose ceilings are `ceilings`.
fn delegated_records(
    delegator: PrincipalId,
    ceilings: Vec<AgentCapabilityCeiling>,
) -> AgentRecords {
    AgentRecords {
        standings: [user(), agent(), second_agent()]
            .into_iter()
            .map(|principal| (principal, PrincipalStanding::Active))
            .collect(),
        agents: vec![agent_record(agent())],
        ceilings,
        delegations: vec![delegation(delegator)],
        ..AgentRecords::new()
    }
}

/// One `mandate.authorization.Check` of `action` under `context`, against `records`, with a
/// grant held by each of `holders`.
fn check_with<R: AgentAuthorityRead>(
    records: &R,
    holders: &[PrincipalId],
    policy: &PolicyDouble,
    context: &VerifiedContext,
    action: &Action,
) -> Result<Decision, Denied> {
    let (graph, minimum) = graph(holders);
    let tenancy = tenancy();
    let topology = Topology::new();
    let issuer = FixedChallenge {
        expires_at: Timestamp::new("2026-01-05T10:00:00Z"),
        approver_policy: Some(PolicyId::new(uuid(40))),
    };
    let pdp = Pdp {
        graph: &graph,
        policy,
        catalog: policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
        agents: records,
    };
    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context,
            action,
            resource: &resource(),
            expected_audience: &audience(),
            relation: "operator",
            minimum: &minimum,
            attributes: &AttributeSet::new(),
            scope: None,
            at: &at(),
        },
    )
}

/// A check of a delegated request from the administrator, where only the administrator holds
/// a grant.
fn check_delegated<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
    action: &Action,
) -> Result<Decision, Denied> {
    check_with(records, &[user()], &policy(), context, action)
}

fn proof(principal: PrincipalId, expires_at: &str) -> ValidatedProof {
    ValidatedProof {
        principal,
        organization: organization(),
        authority: both_tools(),
        expires_at: Timestamp::new(expires_at),
        actor: None,
        delegation: None,
    }
}

/// The token exchange's question about the same delegated request: the other caller of the
/// shared record checks.
fn exchange<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
    requested: &AuthorityScope,
) -> AuthorityDecision {
    evaluate_agent_authority(
        records,
        &policy(),
        &AuthorityRequest {
            context,
            subject: &proof(context.subject, "2026-01-05T20:00:00Z"),
            actor: &proof(agent(), "2026-01-05T20:00:00Z"),
            delegation: context.delegation.as_ref(),
            audience: &audience(),
            requested,
            attributes: &AttributeSet::new(),
            at: &at(),
        },
    )
}

fn only(action: Action) -> AuthorityScope {
    AuthorityScope {
        actions: vec![action],
        resources: vec![resource()],
        space: None,
    }
}

fn assert_denied(refusal: &Denied, why: &str) {
    assert!(!refusal.decision.allowed, "{why}");
    assert_eq!(refusal.reason, DenialReason::Denied, "{why}");
    assert_eq!(refusal.decision.reason, DecisionReason::Denied, "{why}");
    assert_eq!(refusal.decision.challenge, None, "{why}");
}

// ---------------------------------------------------------------------------------------------
// The cases.
// ---------------------------------------------------------------------------------------------

/// The story's acceptance, at the PEP.
///
/// The administrator delegated both tools, holds a grant for both, and policy allows both.
/// The agent's platform ceiling admits both; its installation ceiling refuses the privileged
/// one. The control is the read tool under the same records, which is allowed — so the
/// subject's own authority was read (only the administrator holds a grant) — and the
/// privileged tool under the platform ceiling alone, which is allowed too, so the refusal is
/// the installation ceiling's and nothing else's. The exchange, asked the same question,
/// refuses it under the same subject and actor.
#[test]
fn a_delegated_action_outside_the_installation_ceiling_is_denied_at_the_pep_under_the_preserved_subject_and_actor()
 {
    let context = delegated_context(user(), delegation_id(), None);
    let installed = delegated_records(
        user(),
        vec![platform_ceiling(agent()), installation_ceiling(agent())],
    );
    let platform_only = delegated_records(user(), vec![platform_ceiling(agent())]);

    let inside = check_delegated(&installed, &context, &read_tool())
        .expect("a tool inside every ceiling is allowed for the agent acting for the subject");
    assert!(inside.allowed);
    assert_eq!(inside.reason, DecisionReason::Allowed);
    assert!(
        inside.revision.is_some(),
        "the subject's authority was read from the graph"
    );

    let unbounded = check_delegated(&platform_only, &context, &privileged_tool())
        .expect("without the installation ceiling the privileged tool is allowed");
    assert!(unbounded.allowed);

    let refusal = check_delegated(&installed, &context, &privileged_tool())
        .expect_err("the installation ceiling does not admit the privileged tool");
    assert_denied(
        &refusal,
        "the installation ceiling refuses the privileged tool",
    );
    assert_eq!(
        refusal.decision.revision, None,
        "a request the record checks refuse reads no authority"
    );

    let exchanged = exchange(&installed, &context, &only(privileged_tool()));
    assert!(!exchanged.allowed);
    assert_eq!(exchanged.clause, Some(AuthorityClause::NothingPermitted));
    assert_eq!(exchanged.subject, user(), "the subject is preserved");
    assert_eq!(exchanged.actor, agent(), "the actor is preserved");
}

/// An execution that completed admits no further tool call under it (`CompleteExecution`'s
/// summary), at the PEP and at the exchange alike.
#[test]
fn a_completed_execution_denies() {
    let context = delegated_context(user(), delegation_id(), Some(execution_id()));
    let ceilings = vec![platform_ceiling(agent())];
    let running = AgentRecords {
        executions: vec![execution("2026-01-05T12:00:00Z", ExecutionState::Recorded)],
        ..delegated_records(user(), ceilings.clone())
    };
    let completed = AgentRecords {
        executions: vec![execution("2026-01-05T12:00:00Z", ExecutionState::Completed)],
        ..delegated_records(user(), ceilings)
    };

    let allowed = check_delegated(&running, &context, &read_tool())
        .expect("a tool call under a recorded execution is allowed");
    assert!(allowed.allowed);

    let refusal = check_delegated(&completed, &context, &read_tool())
        .expect_err("a completed execution admits no tool call");
    assert_denied(&refusal, "a completed execution");

    let exchanged = exchange(&completed, &context, &only(read_tool()));
    assert!(!exchanged.allowed);
    assert_eq!(exchanged.reason, DecisionReason::Denied);
}

/// An execution past its `expires_at` is ineligible with no recorded move
/// (`delegation.yaml:3`).
#[test]
fn an_expired_execution_denies() {
    let context = delegated_context(user(), delegation_id(), Some(execution_id()));
    let ceilings = vec![platform_ceiling(agent())];
    let expired = AgentRecords {
        // Recorded, never completed, and expired at the decision instant exactly.
        executions: vec![execution("2026-01-05T09:00:00Z", ExecutionState::Recorded)],
        ..delegated_records(user(), ceilings.clone())
    };
    let unrecorded = delegated_records(user(), ceilings);

    let refusal = check_delegated(&expired, &context, &read_tool())
        .expect_err("an execution expired at the decision instant admits nothing");
    assert_denied(&refusal, "an expired execution");

    let refusal = check_delegated(&unrecorded, &context, &read_tool())
        .expect_err("an execution nobody recorded admits nothing");
    assert_denied(&refusal, "an unrecorded execution");

    let exchanged = exchange(&expired, &context, &only(read_tool()));
    assert!(!exchanged.allowed);
}

/// The execution's `expires_at` is one more input to the earliest expiry: an exchange under
/// an execution that ends before the proofs and the delegation expires when it ends.
#[test]
fn the_permitted_expiry_never_outlives_the_execution() {
    let context = delegated_context(user(), delegation_id(), Some(execution_id()));
    let records = AgentRecords {
        // An offset form, so the comparison is between instants and not between strings:
        // 11:30+01:00 is 10:30Z, earlier than the proofs' and the delegation's 20:00Z.
        executions: vec![execution(
            "2026-01-05T11:30:00+01:00",
            ExecutionState::Recorded,
        )],
        ..delegated_records(user(), vec![platform_ceiling(agent())])
    };

    let decision = exchange(&records, &context, &only(read_tool()));

    assert!(decision.allowed, "{decision:?}");
    assert_eq!(
        decision.expires_at,
        Some(Timestamp::new("2026-01-05T11:30:00+01:00")),
        "the permitted set never outlives the execution it was asked under"
    );
}

/// When the subject of a delegated request is itself an agent, its own applicable ceilings
/// bound the request too, and a subject agent with no ceiling is refused.
#[test]
fn an_agent_subject_is_bounded_by_its_own_ceilings() {
    let context = delegated_context(second_agent(), delegation_id(), None);
    let base = |subject_ceilings: Vec<AgentCapabilityCeiling>| {
        let mut ceilings = vec![platform_ceiling(agent())];
        ceilings.extend(subject_ceilings);
        AgentRecords {
            agents: vec![agent_record(agent()), agent_record(second_agent())],
            ..delegated_records(second_agent(), ceilings)
        }
    };
    let holders = [second_agent()];

    let bounded = base(vec![ceiling(
        62,
        second_agent(),
        Some(organization()),
        &["tool.read"],
        &[],
    )]);
    let allowed = check_with(&bounded, &holders, &policy(), &context, &read_tool())
        .expect("a tool inside both agents' ceilings is allowed");
    assert!(allowed.allowed);

    let refusal = check_with(&bounded, &holders, &policy(), &context, &privileged_tool())
        .expect_err("the subject agent's own ceiling does not admit the privileged tool");
    assert_denied(&refusal, "the subject agent's ceiling refuses");

    let unceilinged = base(Vec::new());
    let refusal = check_with(&unceilinged, &holders, &policy(), &context, &read_tool())
        .expect_err("a subject agent with no ceiling is bounded by nothing, and refused");
    assert_denied(&refusal, "the subject agent has no ceiling");

    let exchanged = exchange(&unceilinged, &context, &only(read_tool()));
    assert_eq!(exchanged.clause, Some(AuthorityClause::CeilingAbsent));
}

/// A delegated `Check` is decided: allowed when every record check and every port allows, and
/// refused by the record check that fails — not refused because it is delegated.
#[test]
fn a_delegated_check_is_decided_by_the_evaluator_and_never_refused_wholesale() {
    let context = delegated_context(user(), delegation_id(), None);
    let records = delegated_records(user(), vec![platform_ceiling(agent())]);

    let allowed = check_delegated(&records, &context, &read_tool())
        .expect("a delegated request every bound admits is allowed");
    assert!(allowed.allowed);
    assert_eq!(allowed.reason, DecisionReason::Allowed);
    assert_eq!(allowed.policy_version, Some(PolicyVersion::new("v1")));

    // The same request where the delegation names another audience: the evaluator's
    // `DelegationMismatch`, a decision about the request.
    let elsewhere = AgentRecords {
        delegations: vec![Delegation {
            audience: Audience::new("another-api"),
            ..delegation(user())
        }],
        ..records.clone()
    };
    let refusal = check_delegated(&elsewhere, &context, &read_tool())
        .expect_err("a delegation for another audience does not bind");
    assert_denied(&refusal, "the delegation is for another audience");

    // With no record at all, as the external callers' empty read answers today, a delegated
    // request is refused, and a direct one of a principal that is no agent is decided as
    // before.
    let refusal = check_delegated(&AgentRecords::new(), &context, &read_tool())
        .expect_err("nothing records the agent or the delegation");
    assert_denied(&refusal, "no record");
    let direct = check_delegated(&AgentRecords::new(), &plain_context(user()), &read_tool())
        .expect("a direct request of a principal that is no agent reads no agent record");
    assert!(direct.allowed);
}

/// Retirement takes effect at the next check: no exchange admits a retired agent
/// (`RetireAgent`'s summary), and no PEP does.
#[test]
fn a_retired_agent_is_denied_at_the_next_check() {
    let context = delegated_context(user(), delegation_id(), None);
    let records = delegated_records(user(), vec![platform_ceiling(agent())]);
    check_delegated(&records, &context, &read_tool()).expect("the agent is installed");

    let mut retired = records;
    retired.agents.push(Agent {
        state: AgentState::Retired,
        ..agent_record(agent())
    });
    let refusal = check_delegated(&retired, &context, &read_tool())
        .expect_err("a retired agent is admitted by no check");
    assert_denied(&refusal, "the agent is retired");

    // Acting for itself makes no difference: a retired agent is refused as a subject too.
    let autonomous = check_with(
        &retired,
        &[agent()],
        &policy(),
        &plain_context(agent()),
        &read_tool(),
    )
    .expect_err("a retired agent acting for itself is refused");
    assert_denied(&autonomous, "the autonomous agent is retired");
}

/// Revocation takes effect at the next check.
#[test]
fn a_revoked_delegation_is_denied_at_the_next_check() {
    let context = delegated_context(user(), delegation_id(), None);
    let records = delegated_records(user(), vec![platform_ceiling(agent())]);
    check_delegated(&records, &context, &read_tool()).expect("the delegation is active");

    let mut revoked = records;
    revoked.delegations.push(Delegation {
        state: DelegationState::Revoked,
        ..delegation(user())
    });
    let refusal = check_delegated(&revoked, &context, &read_tool())
        .expect_err("a revoked delegation admits nothing");
    assert_denied(&refusal, "the delegation is revoked");
}

/// An approval requirement on a delegated request is answered as on a direct one:
/// `allowed = false`, `ApprovalRequired`, and the challenge that would clear it. The record
/// checks pass first, so the requirement is policy's and not a refusal of the delegation.
#[test]
fn approval_required_stays_allowed_false_with_a_challenge() {
    let context = delegated_context(user(), delegation_id(), None);
    let records = delegated_records(user(), vec![platform_ceiling(agent())]);
    let mut policy = policy();
    policy.require_approval(
        organization(),
        AuthoritySubject::Principal(user()),
        read_tool(),
        resource(),
        ChallengeRequirement::Approval,
    );

    let refusal = check_with(&records, &[user()], &policy, &context, &read_tool())
        .expect_err("an approval requirement is not an allow");

    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.reason, DenialReason::ApprovalRequired);
    assert_eq!(refusal.decision.reason, DecisionReason::ApprovalRequired);
    let challenge = refusal
        .decision
        .challenge
        .expect("the challenge to answer is carried");
    assert_eq!(challenge.action, read_tool());
    assert_eq!(challenge.resource, resource());
}
