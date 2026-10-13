//! Integrity conformance checks of `story:agent-security`'s invariants at the PEP
//! (`mandate_authz::check`) and at the token exchange (`evaluate_agent_authority`), the two
//! callers of the shared record checks.
//!
//! Each case builds the records behind `AgentAuthorityRead` and asks both callers the same
//! question where the invariant is about agreement between them.

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
use mandate_policy::port::AttributeSet;
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, Audience, AuthorityScope, AuthoritySubject,
    AuthorizationModelId, AuthzRevision, CorrelationId, CredentialId, DelegationId, DenialReason,
    Duration, ExecutionId, GrantId, OrganizationId, OrganizationMembershipId, PolicyId,
    PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, Timestamp, Uuid,
    VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn user() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn agent() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

fn second_agent() -> PrincipalId {
    PrincipalId::new(uuid(4))
}

fn delegation_id() -> DelegationId {
    DelegationId::new(uuid(20))
}

fn other_delegation_id() -> DelegationId {
    DelegationId::new(uuid(22))
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

fn read_tool() -> Action {
    Action::new("tool.read")
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: vec![read_tool()],
        resources: vec![resource()],
        space: None,
    }
}

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
        correlation: CorrelationId::new("adversary-agent-security"),
    }
}

fn delegated_context(execution: Option<ExecutionId>) -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        delegation: Some(delegation_id()),
        execution,
        ..plain_context(user())
    }
}

fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&plain_context(user()), organization(), "org")
        .expect("the organization is recorded");
    for (index, principal) in [user(), agent(), second_agent()].into_iter().enumerate() {
        tenancy
            .add_organization_membership(
                &plain_context(user()),
                MembershipAuthority::VerifiedOrganization,
                OrganizationMembershipId::new(uuid(50 + u8::try_from(index).expect("few"))),
                organization(),
                principal,
            )
            .expect("a member");
    }
    tenancy
}

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
            scope(),
            "operator",
        ));
    }
    (graph, revision)
}

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
    policy.record_role(organization(), "operator", vec![read_tool()]);
    for principal in [user(), agent(), second_agent()] {
        policy.allow(
            organization(),
            AuthoritySubject::Principal(principal),
            read_tool(),
            resource(),
        );
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
) -> AgentCapabilityCeiling {
    AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(uuid(byte)),
        agent_id,
        organization_id,
        allowed_actions: vec![ActionPattern::new("tool.*")],
        denied_actions: Vec::new(),
        scope: scope(),
        max_delegation_ttl: Duration::new("PT1H"),
        state: CeilingState::Recorded,
    }
}

fn delegation() -> Delegation {
    Delegation {
        id: delegation_id(),
        organization_id: organization(),
        delegator: user(),
        delegate: agent(),
        scope: scope(),
        audience: audience(),
        not_before: None,
        expires_at: Timestamp::new("2026-01-05T20:00:00Z"),
        execution_binding: None,
        transitive: false,
        created_at: Timestamp::new("2026-01-05T08:00:00Z"),
        state: DelegationState::Active,
    }
}

fn execution() -> Execution {
    Execution {
        id: execution_id(),
        organization_id: organization(),
        agent_id: agent(),
        subject: Some(user()),
        delegation_id: Some(delegation_id()),
        initiating_session: None,
        created_at: Timestamp::new("2026-01-05T08:30:00Z"),
        expires_at: Timestamp::new("2026-01-05T19:00:00Z"),
        policy_version: PolicyVersion::new("v1"),
        state: ExecutionState::Recorded,
    }
}

fn records() -> AgentRecords {
    AgentRecords {
        standings: [user(), agent(), second_agent()]
            .into_iter()
            .map(|principal| (principal, PrincipalStanding::Active))
            .collect(),
        agents: vec![agent_record(agent())],
        ceilings: vec![ceiling(60, agent(), None)],
        delegations: vec![delegation()],
        executions: vec![execution()],
        ..AgentRecords::new()
    }
}

fn check_at<R: AgentAuthorityRead>(
    records: &R,
    holders: &[PrincipalId],
    context: &VerifiedContext,
    when: &Timestamp,
) -> Result<Decision, Denied> {
    let (graph, minimum) = graph(holders);
    let tenancy = tenancy();
    let topology = Topology::new();
    let policy = policy();
    let issuer = FixedChallenge {
        expires_at: Timestamp::new("2026-01-05T10:00:00Z"),
        approver_policy: Some(PolicyId::new(uuid(40))),
    };
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
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
            action: &read_tool(),
            resource: &resource(),
            expected_audience: &audience(),
            relation: "operator",
            minimum: &minimum,
            attributes: &AttributeSet::new(),
            scope: None,
            at: when,
        },
    )
}

fn check_delegated<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
) -> Result<Decision, Denied> {
    check_at(records, &[user()], context, &at())
}

fn proof(principal: PrincipalId, expires_at: &str) -> ValidatedProof {
    ValidatedProof {
        principal,
        organization: organization(),
        authority: scope(),
        expires_at: Timestamp::new(expires_at),
        actor: None,
        delegation: None,
    }
}

fn exchange_at<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
    proofs_expire: &str,
    when: &Timestamp,
) -> AuthorityDecision {
    evaluate_agent_authority(
        records,
        &policy(),
        &AuthorityRequest {
            context,
            subject: &proof(context.subject, proofs_expire),
            actor: &proof(context.actor.unwrap_or(context.subject), proofs_expire),
            delegation: context.delegation.as_ref(),
            audience: &audience(),
            requested: &scope(),
            attributes: &AttributeSet::new(),
            at: when,
        },
    )
}

fn exchange<R: AgentAuthorityRead>(records: &R, context: &VerifiedContext) -> AuthorityDecision {
    exchange_at(records, context, "2026-01-05T20:00:00Z", &at())
}

// ---------------------------------------------------------------------------------------------
// Invariant 4: a refusal discloses nothing about a record of another organization.
// ---------------------------------------------------------------------------------------------

/// A delegation recorded in another organization must refuse at the PEP exactly as one nobody
/// recorded (wave 7 decision 1: an unknown id refuses like a record the caller may not see).
#[test]
fn a_delegation_of_another_organization_refuses_like_an_unrecorded_one_at_check() {
    let context = delegated_context(None);
    let mut elsewhere = records();
    elsewhere.delegations = vec![Delegation {
        organization_id: other_organization(),
        ..delegation()
    }];
    let mut unrecorded = records();
    unrecorded.delegations.clear();

    let elsewhere = check_delegated(&elsewhere, &context).expect_err("another tenant's delegation");
    let unrecorded = check_delegated(&unrecorded, &context).expect_err("no delegation");
    assert_eq!(
        (elsewhere.reason, elsewhere.decision.reason),
        (unrecorded.reason, unrecorded.decision.reason),
        "the PEP's answer tells a delegation of another organization from an unrecorded one"
    );
}

/// The actor's agent record recorded in another organization must refuse at the PEP exactly
/// as a principal no agent record names.
#[test]
fn an_agent_record_of_another_organization_refuses_like_no_agent_record_at_check() {
    let context = delegated_context(None);
    let mut elsewhere = records();
    elsewhere.agents = vec![Agent {
        organization_id: other_organization(),
        ..agent_record(agent())
    }];
    let mut unrecorded = records();
    unrecorded.agents.clear();

    let elsewhere = check_delegated(&elsewhere, &context).expect_err("another tenant's agent");
    let unrecorded = check_delegated(&unrecorded, &context).expect_err("no agent record");
    assert_eq!(
        (elsewhere.reason, elsewhere.decision.reason),
        (unrecorded.reason, unrecorded.decision.reason),
        "the PEP's answer tells an agent of another organization from a principal that is no agent"
    );
}

/// The execution half of invariant 4, at both callers (a guard; green when written).
#[test]
fn an_execution_of_another_organization_refuses_like_an_unrecorded_one() {
    let context = delegated_context(Some(execution_id()));
    let mut elsewhere = records();
    elsewhere.executions = vec![Execution {
        organization_id: other_organization(),
        ..execution()
    }];
    let mut unrecorded = records();
    unrecorded.executions.clear();

    let a = check_delegated(&elsewhere, &context).expect_err("another tenant's execution");
    let b = check_delegated(&unrecorded, &context).expect_err("no execution");
    assert_eq!((a.reason, a.decision.reason), (b.reason, b.decision.reason));
    assert_eq!(a.reason, DenialReason::Denied);
    assert_eq!(
        exchange(&elsewhere, &context).clause,
        exchange(&unrecorded, &context).clause
    );
}

// ---------------------------------------------------------------------------------------------
// Invariant 2: Check admits nothing the exchange refuses for the same records.
// ---------------------------------------------------------------------------------------------

/// A disabled agent principal whose `Agent` record is still `Recorded`: the exchange refuses
/// (`ActorDisabled`); the PEP must not admit the same delegated request.
#[test]
fn a_disabled_agent_principal_is_refused_at_check_as_at_the_exchange() {
    let context = delegated_context(None);
    let mut disabled = records();
    disabled
        .standings
        .push((agent(), PrincipalStanding::Disabled));

    assert_eq!(
        exchange(&disabled, &context).clause,
        Some(AuthorityClause::ActorDisabled),
        "the exchange refuses a disabled actor"
    );
    let decided = check_delegated(&disabled, &context);
    assert!(
        decided.is_err(),
        "Check admits a delegated request the exchange refuses for the same records: {decided:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Invariant 3: execution binding (guards; green when written).
// ---------------------------------------------------------------------------------------------

#[test]
fn an_execution_that_names_no_subject_does_not_admit_a_delegated_request() {
    let context = delegated_context(Some(execution_id()));
    let mut absent = records();
    absent.executions = vec![Execution {
        subject: None,
        ..execution()
    }];
    check_delegated(&records(), &context).expect("the control: the execution holds");
    check_delegated(&absent, &context)
        .expect_err("subject absent means the agent, never the delegator");
    assert_eq!(
        exchange(&absent, &context).clause,
        Some(AuthorityClause::ExecutionUnbound)
    );
}

#[test]
fn an_execution_of_another_agent_delegation_or_subject_refuses() {
    let context = delegated_context(Some(execution_id()));
    for (why, wrong) in [
        (
            "another agent",
            Execution {
                agent_id: second_agent(),
                ..execution()
            },
        ),
        (
            "another delegation",
            Execution {
                delegation_id: Some(other_delegation_id()),
                ..execution()
            },
        ),
        (
            "no delegation",
            Execution {
                delegation_id: None,
                ..execution()
            },
        ),
        (
            "another subject",
            Execution {
                subject: Some(second_agent()),
                ..execution()
            },
        ),
    ] {
        let mut records = records();
        records.executions = vec![wrong];
        check_delegated(&records, &context).expect_err(why);
        assert_eq!(
            exchange(&records, &context).clause,
            Some(AuthorityClause::ExecutionUnbound),
            "{why}"
        );
    }
}

/// An agent acting for itself names its own execution; an execution recorded for a subject
/// cannot be reused directly to drop the delegation.
#[test]
fn a_direct_request_cannot_use_an_execution_recorded_for_a_subject() {
    let context = VerifiedContext {
        execution: Some(execution_id()),
        ..plain_context(agent())
    };
    let mut records = records();
    records.executions = vec![Execution {
        delegation_id: None,
        ..execution()
    }];
    check_at(&records, &[agent()], &context, &at())
        .expect_err("an execution for the user is not the agent's own");
}

// ---------------------------------------------------------------------------------------------
// Invariant 1: expiries compared as instants across offsets (guards; green when written).
// ---------------------------------------------------------------------------------------------

/// `2026-01-05T10:30:00+02:00` is 08:30Z, before the decision at 09:00Z, though it sorts
/// after it byte by byte.
#[test]
fn an_execution_expired_by_instant_but_not_by_bytes_refuses() {
    let context = delegated_context(Some(execution_id()));
    let mut records = records();
    records.executions = vec![Execution {
        expires_at: Timestamp::new("2026-01-05T10:30:00+02:00"),
        ..execution()
    }];
    check_delegated(&records, &context).expect_err("the execution ended at 08:30Z");
    assert_eq!(
        exchange(&records, &context).clause,
        Some(AuthorityClause::ExecutionUnbound)
    );
}

/// The exchange's expiry is the earliest instant: the execution's `11:30+02:00` (09:30Z),
/// before proofs expiring at `10:00Z`, which sort before it byte by byte.
#[test]
fn the_exchange_expiry_is_the_execution_instant_across_offsets() {
    let context = delegated_context(Some(execution_id()));
    let mut records = records();
    records.executions = vec![Execution {
        expires_at: Timestamp::new("2026-01-05T11:30:00+02:00"),
        ..execution()
    }];
    let decided = exchange_at(&records, &context, "2026-01-05T10:00:00Z", &at());
    assert!(decided.allowed, "{decided:?}");
    assert_eq!(
        decided.expires_at,
        Some(Timestamp::new("2026-01-05T11:30:00+02:00"))
    );
}

// ---------------------------------------------------------------------------------------------
// Invariants 5 and 6: ceilings (guards; green when written).
// ---------------------------------------------------------------------------------------------

#[test]
fn two_current_platform_ceilings_on_one_key_deny_with_the_declared_clause() {
    let context = delegated_context(None);
    let mut records = records();
    records.ceilings.push(ceiling(62, agent(), None));
    check_delegated(&records, &context).expect_err("two current ceilings share one key");
    assert_eq!(
        exchange(&records, &context).clause,
        Some(AuthorityClause::CeilingConflict)
    );
}

#[test]
fn a_ceiling_of_another_organization_does_not_apply_and_leaves_the_agent_unbounded_refused() {
    let context = delegated_context(None);
    let mut records = records();
    records.ceilings = vec![
        ceiling(63, agent(), Some(other_organization())),
        ceiling(64, agent(), Some(other_organization())),
    ];
    check_delegated(&records, &context).expect_err("no applicable ceiling");
    assert_eq!(
        exchange(&records, &context).clause,
        Some(AuthorityClause::CeilingAbsent),
        "another organization's conflict is not this one's, and nothing applies here"
    );
}

#[test]
fn an_agent_subject_without_a_ceiling_is_refused() {
    let context = VerifiedContext {
        subject: second_agent(),
        ..delegated_context(None)
    };
    let mut records = records();
    records.agents.push(agent_record(second_agent()));
    records.delegations = vec![Delegation {
        delegator: second_agent(),
        ..delegation()
    }];
    check_at(&records, &[second_agent()], &context, &at())
        .expect_err("the subject agent has no ceiling");
    assert_eq!(
        exchange(&records, &context).clause,
        Some(AuthorityClause::CeilingAbsent)
    );
    // The control: with its own ceiling, the same request is allowed.
    records.ceilings.push(ceiling(65, second_agent(), None));
    check_at(&records, &[second_agent()], &context, &at()).expect("bounded by its own ceiling");
}
