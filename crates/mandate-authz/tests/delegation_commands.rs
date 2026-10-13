//! `story:agent-security`, the delegation commands: `CreateDelegation`, `RevokeDelegation`,
//! `RetireAgent`, `CompleteExecution` and `ConsumeApproval`, their events, and the fold that
//! [`mandate_authz::check`] and the token exchange read what the commands wrote through.
//!
//! Every command is decided by a function of [`mandate_authz::command`] over the
//! [`AgentAuthorityRead`] port and, where a declared clause is a judgement no record answers,
//! the [`DelegationAdmission`] port. An accepted decision returns the declared event and
//! writes nothing; [`DelegationProjection::apply`] writes it. A refusal returns
//! [`Denied`], emits nothing and moves no record, and every case that refuses asserts the fold
//! it decided against is the fold it started from.
//!
//! The world is the one `tests/agent_security.rs` decides `check` in: an administrator, an
//! agent installed in the organization with a platform and a tenant ceiling, a resource with a
//! grant for the administrator only, and policy that allows both tools. Each refusal below has
//! a control that differs from it in the one input or record the case names.

use mandate_authz::agent::{AgentAuthorityRead, AgentRecords, PrincipalStanding};
use mandate_authz::command::{
    ConfiguredDelegationAdmission, CreateDelegation, DelegationAdmission, DelegationClause, Denied,
    RefusedAs, SequentialDelegationIds, decide_complete_execution, decide_consume_approval,
    decide_create_delegation, decide_retire_agent, decide_revoke_delegation,
};
use mandate_authz::decision::{FixedChallenge, SequentialDecisionIds};
use mandate_authz::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, Approval, ApprovalState, CeilingState,
    DelegationState, Execution, ExecutionState,
};
use mandate_authz::event::{DelegationCreated, DelegationEvent, DelegationProjection};
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
    Action, ActionPattern, AgentCapabilityCeilingId, ApprovalId, Audience, AuthorityScope,
    AuthoritySubject, AuthorizationModelId, CorrelationId, CredentialId, DelegationId,
    DenialReason, Duration, ExecutionId, GrantId, OrganizationId, OrganizationMembershipId,
    PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId,
    Timestamp, Uuid, VerifiedContext,
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

/// The administrator who delegates.
fn user() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

/// The agent installation the delegation is to.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

/// A principal of the organization that is no agent.
fn colleague() -> PrincipalId {
    PrincipalId::new(uuid(4))
}

/// An agent installed in another organization.
fn foreign_agent() -> PrincipalId {
    PrincipalId::new(uuid(5))
}

/// A principal no record names.
fn stranger() -> PrincipalId {
    PrincipalId::new(uuid(6))
}

fn execution_id() -> ExecutionId {
    ExecutionId::new(uuid(21))
}

fn approval_id() -> ApprovalId {
    ApprovalId::new(uuid(22))
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

fn privileged_tool() -> Action {
    Action::new("tool.delete")
}

fn scope_of(actions: Vec<Action>, space: Option<SpaceId>) -> AuthorityScope {
    AuthorityScope {
        actions,
        resources: vec![resource()],
        space,
    }
}

fn both_tools() -> AuthorityScope {
    scope_of(vec![read_tool(), privileged_tool()], None)
}

fn read_only() -> AuthorityScope {
    scope_of(vec![read_tool()], None)
}

/// The instant every command is decided at, and every delegation is created at.
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
        correlation: CorrelationId::new("delegation-commands"),
    }
}

/// The context the agent's tool call is checked under, acting for the administrator under
/// `delegation`.
fn delegated_context(delegation: DelegationId, execution: Option<ExecutionId>) -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        delegation: Some(delegation),
        execution,
        ..plain_context(user())
    }
}

fn agent_record(principal: PrincipalId, organization_id: OrganizationId) -> Agent {
    Agent {
        id: principal,
        organization_id,
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
    }
}

fn ceiling(
    byte: u8,
    agent_id: PrincipalId,
    organization_id: Option<OrganizationId>,
    denied: &[&str],
    scope: AuthorityScope,
    ttl: &str,
) -> AgentCapabilityCeiling {
    AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(uuid(byte)),
        agent_id,
        organization_id,
        allowed_actions: vec![ActionPattern::new("tool.*")],
        denied_actions: denied
            .iter()
            .map(|name| ActionPattern::new(*name))
            .collect(),
        scope,
        max_delegation_ttl: Duration::new(ttl),
        state: CeilingState::Recorded,
    }
}

/// The agent's platform ceiling, two hours, and its tenant ceiling, one hour: the smallest
/// applicable `max_delegation_ttl` is the tenant's.
fn ceilings() -> Vec<AgentCapabilityCeiling> {
    vec![
        ceiling(60, agent(), None, &[], both_tools(), "PT2H"),
        ceiling(61, agent(), Some(organization()), &[], both_tools(), "PT1H"),
    ]
}

fn execution(agent_id: PrincipalId, organization_id: OrganizationId) -> Execution {
    Execution {
        id: execution_id(),
        organization_id,
        agent_id,
        subject: Some(user()),
        delegation_id: None,
        initiating_session: None,
        created_at: Timestamp::new("2026-01-05T08:30:00Z"),
        expires_at: Timestamp::new("2026-01-05T12:00:00Z"),
        policy_version: PolicyVersion::new("v1"),
        state: ExecutionState::Recorded,
    }
}

fn approval(organization_id: OrganizationId, expires_at: &str) -> Approval {
    Approval {
        id: approval_id(),
        organization_id,
        subject: user(),
        actor: Some(agent()),
        action: privileged_tool(),
        resource: resource(),
        expires_at: Timestamp::new(expires_at),
        approver: colleague(),
        state: ApprovalState::Recorded,
    }
}

/// The records no command of this contract creates: standings, agents, ceilings, an
/// execution and an approval. Delegations are written by `CreateDelegation` alone.
fn starting_records() -> AgentRecords {
    AgentRecords {
        standings: [user(), agent(), colleague(), foreign_agent()]
            .into_iter()
            .map(|principal| (principal, PrincipalStanding::Active))
            .collect(),
        agents: vec![
            agent_record(agent(), organization()),
            agent_record(foreign_agent(), other_organization()),
        ],
        ceilings: ceilings(),
        executions: vec![execution(agent(), organization())],
        approvals: vec![approval(organization(), "2026-01-05T10:00:00Z")],
        ..AgentRecords::new()
    }
}

fn projection() -> DelegationProjection {
    DelegationProjection::holding(starting_records())
}

/// Every delegation authority, revocation authority, agent administration and audience the
/// cases below are decided under: the administrator holds all of them, and nobody else.
fn admission() -> ConfiguredDelegationAdmission {
    ConfiguredDelegationAdmission::new()
        .with_delegator(user())
        .with_revoker(user())
        .with_agent_administrator(user())
        .with_audience(organization(), audience())
}

/// Policy allows every principal both tools.
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
    for principal in [user(), agent()] {
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

/// The request to delegate `scope` to `delegate` until `expires_at`, by `context`.
fn create(
    context: VerifiedContext,
    delegate: PrincipalId,
    scope: AuthorityScope,
    expires_at: &str,
) -> CreateDelegation {
    CreateDelegation {
        context,
        delegate,
        scope,
        audience: audience(),
        expires_at: Timestamp::new(expires_at),
        not_before: None,
        execution_binding: None,
    }
}

/// The administrator's delegation of both tools to the agent for 45 minutes.
fn within_ceilings() -> CreateDelegation {
    create(
        plain_context(user()),
        agent(),
        both_tools(),
        "2026-01-05T09:45:00Z",
    )
}

/// Decide `input` against `fold` under [`admission`] and [`policy`].
fn decide_create(
    fold: &DelegationProjection,
    admission: &impl DelegationAdmission,
    ids: &mut SequentialDelegationIds,
    input: &CreateDelegation,
) -> Result<mandate_authz::command::Created, Denied> {
    decide_create_delegation(fold, &policy(), admission, ids, input, &at())
}

/// Create the administrator's delegation through the command and the fold, and return its id.
fn created(fold: &mut DelegationProjection) -> DelegationId {
    let mut ids = SequentialDelegationIds::new();
    let created = decide_create(fold, &admission(), &mut ids, &within_ceilings())
        .expect("a delegation within the ceilings is created");
    fold.apply(&created.event);
    created.delegation_id
}

/// The refusal is the one `clause` names, under the one declared reason, through `outcome`.
fn assert_refused(refused: &Denied, clause: DelegationClause, outcome: RefusedAs) {
    assert_eq!(refused.clause, clause, "the clause refused on: {refused:?}");
    assert_eq!(
        refused.outcome, outcome,
        "the branch refused through: {refused:?}"
    );
    assert_eq!(
        refused.reason,
        DenialReason::Denied,
        "the reason: {refused:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// `mandate.authorization.Check`, reading the fold.
// ---------------------------------------------------------------------------------------------

fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&plain_context(user()), organization(), "acme")
        .expect("the organization is recorded");
    for (index, principal) in [user(), agent()].into_iter().enumerate() {
        tenancy
            .add_organization_membership(
                &plain_context(user()),
                MembershipAuthority::VerifiedOrganization,
                OrganizationMembershipId::new(uuid(50 + u8::try_from(index).expect("two"))),
                organization(),
                principal,
            )
            .expect("a member");
    }
    tenancy
}

/// One check of `action` under `context` against `records`; the administrator alone holds a
/// grant.
fn check_through<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
    action: &Action,
) -> Result<Decision, mandate_authz::decision::Denied> {
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&plain_context(user()), &resource(), None)
        .expect("the resource is registered");
    let subject = AuthoritySubject::Principal(user());
    graph.admit_subject(organization(), subject.clone());
    let minimum = graph.record_grant(Grant::recorded(
        GrantId::new(uuid(30)),
        organization(),
        subject,
        both_tools(),
        "operator",
    ));
    let policy = policy();
    let tenancy = tenancy();
    let topology = Topology::new();
    let issuer = FixedChallenge {
        expires_at: Timestamp::new("2026-01-05T10:00:00Z"),
        approver_policy: Some(PolicyId::new(uuid(40))),
    };
    check(
        &Pdp {
            graph: &graph,
            policy: &policy,
            catalog: &policy,
            issuer: &issuer,
            tenancy: &tenancy,
            topology: &topology,
            agents: records,
        },
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

// ---------------------------------------------------------------------------------------------
// `mandate.delegation.CreateDelegation`.
// ---------------------------------------------------------------------------------------------

/// Accepted: the delegator is the verified subject, the record is `Active`, non-transitive,
/// in the verified organization, and `check` admits the agent's tool call under it.
#[test]
fn a_delegation_within_the_delegates_ceilings_is_created_by_the_verified_subject() {
    let mut fold = projection();
    let mut ids = SequentialDelegationIds::new();
    let input = within_ceilings();
    let created =
        decide_create(&fold, &admission(), &mut ids, &input).expect("the delegation is created");
    assert_eq!(
        created.delegator,
        user(),
        "the delegator is the verified subject"
    );
    let DelegationEvent::Created(payload) = &created.event else {
        panic!(
            "CreateDelegation emits DelegationCreated: {:?}",
            created.event
        );
    };
    let DelegationCreated {
        context,
        id,
        delegator,
        delegate,
        scope,
        audience: delegated_audience,
        not_before,
        expires_at,
        execution_binding,
        created_at,
    } = payload.as_ref();
    assert_eq!(context, &input.context);
    assert_eq!(
        *id, created.delegation_id,
        "the response names the event's identity"
    );
    assert_eq!(*delegator, user());
    assert_eq!(*delegate, agent());
    assert_eq!(scope, &both_tools());
    assert_eq!(delegated_audience, &audience());
    assert_eq!(*not_before, None);
    assert_eq!(expires_at, &input.expires_at);
    assert_eq!(*execution_binding, None);
    assert_eq!(
        created_at,
        &at(),
        "the creation instant is the decision instant"
    );
    assert_eq!(
        created.event.ess_name(),
        "mandate.delegation.DelegationCreated"
    );

    fold.apply(&created.event);
    let record = fold
        .delegation(&created.delegation_id)
        .expect("the read answers")
        .expect("the fold holds the delegation");
    assert_eq!(record.organization_id, organization());
    assert_eq!(record.state, DelegationState::Active);
    assert!(
        !record.transitive,
        "CreateDelegation fixes transitive=false"
    );

    let context = delegated_context(created.delegation_id, None);
    check_through(&fold, &context, &read_tool())
        .expect("check admits the agent's tool call under the created delegation");
}

/// "Caller lacks delegation authority": the admission does not hold the caller as a
/// delegator. Nothing is emitted, no identity is allocated and the fold does not move.
#[test]
fn a_caller_the_admission_does_not_hold_as_a_delegator_is_refused_and_nothing_is_written() {
    let fold = projection();
    let before = fold.clone();
    let mut ids = SequentialDelegationIds::new();
    let refused = decide_create(
        &fold,
        &ConfiguredDelegationAdmission::new().with_audience(organization(), audience()),
        &mut ids,
        &within_ceilings(),
    )
    .expect_err("a caller without delegation authority is refused");
    assert_refused(
        &refused,
        DelegationClause::CallerUnauthorized,
        RefusedAs::Denied,
    );
    assert_eq!(
        ids.issued(),
        0,
        "a refusal allocates no delegation identity"
    );
    assert_eq!(fold, before, "a refusal moves no record");
}

/// A refusal on a record — the delegate is no agent — allocates no identity, emits nothing
/// and leaves the fold exactly as it was.
#[test]
fn a_refused_creation_allocates_nothing_and_moves_no_record() {
    let fold = projection();
    let before = fold.clone();
    let mut ids = SequentialDelegationIds::new();
    let mut input = within_ceilings();
    input.delegate = colleague();
    decide_create(&fold, &admission(), &mut ids, &input)
        .expect_err("a delegate that is no agent is refused");
    assert_eq!(
        ids.issued(),
        0,
        "a refusal allocates no delegation identity"
    );
    assert_eq!(fold, before, "a refusal moves no record");
    assert!(fold.log().is_empty(), "a refusal logs no event");
}

/// "subject": a delegator whose principal is disabled delegates nothing.
#[test]
fn a_disabled_delegator_is_refused() {
    let mut records = starting_records();
    records
        .standings
        .push((user(), PrincipalStanding::Disabled));
    let fold = DelegationProjection::holding(records);
    let refused = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &within_ceilings(),
    )
    .expect_err("a disabled delegator is refused");
    assert_refused(
        &refused,
        DelegationClause::SubjectInvalid,
        RefusedAs::Denied,
    );
}

/// "delegate": a principal of the organization that is no agent is bounded by no ceiling,
/// and a delegation to it would be bounded by nothing.
#[test]
fn a_delegate_that_is_no_agent_is_refused() {
    let refused = decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &create(
            plain_context(user()),
            colleague(),
            read_only(),
            "2026-01-05T09:45:00Z",
        ),
    )
    .expect_err("a delegate that is no agent is refused");
    assert_refused(
        &refused,
        DelegationClause::DelegateInvalid,
        RefusedAs::Denied,
    );
}

/// "tenant": an agent installed in another organization refuses exactly as a principal no
/// record names, so the refusal discloses nothing about the other tenant.
#[test]
fn a_delegate_agent_of_another_organization_refuses_like_an_unknown_one() {
    let refuse = |delegate| {
        decide_create(
            &projection(),
            &admission(),
            &mut SequentialDelegationIds::new(),
            &create(
                plain_context(user()),
                delegate,
                read_only(),
                "2026-01-05T09:45:00Z",
            ),
        )
        .expect_err("refused")
    };
    let foreign = refuse(foreign_agent());
    let unknown = refuse(stranger());
    assert_refused(
        &foreign,
        DelegationClause::DelegateInvalid,
        RefusedAs::Denied,
    );
    assert_eq!(
        foreign, unknown,
        "a foreign agent refuses like an unknown one"
    );
}

/// "space": a scope confined to one space, under ceilings confined to another, permits
/// nothing; the intersection is the evaluator's own.
#[test]
fn a_scope_whose_space_conflicts_with_the_ceilings_is_refused() {
    let mut records = starting_records();
    records.ceilings = vec![ceiling(
        62,
        agent(),
        Some(organization()),
        &[],
        scope_of(
            vec![read_tool(), privileged_tool()],
            Some(SpaceId::new(uuid(70))),
        ),
        "PT1H",
    )];
    let fold = DelegationProjection::holding(records);
    let mut input = within_ceilings();
    input.scope = scope_of(vec![read_tool()], Some(SpaceId::new(uuid(71))));
    let refused = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("a scope in another space than the ceilings is refused");
    assert_refused(&refused, DelegationClause::SpaceConflict, RefusedAs::Denied);

    input.scope = scope_of(vec![read_tool()], Some(SpaceId::new(uuid(70))));
    decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect("the control: the ceilings' own space is admitted");
}

/// "registered audience": an audience the admission does not register for the organization.
#[test]
fn an_audience_the_admission_does_not_register_is_refused() {
    let refused = decide_create(
        &projection(),
        &ConfiguredDelegationAdmission::new()
            .with_delegator(user())
            .with_audience(other_organization(), audience()),
        &mut SequentialDelegationIds::new(),
        &within_ceilings(),
    )
    .expect_err("an unregistered audience is refused");
    assert_refused(
        &refused,
        DelegationClause::AudienceUnregistered,
        RefusedAs::Denied,
    );
}

/// "execution binding fails": a delegation bound to an execution another agent holds, or one
/// no record names, is refused; bound to the delegate's own execution it is created.
#[test]
fn an_execution_binding_to_another_agents_execution_is_refused() {
    let mut records = starting_records();
    records.executions = vec![execution(foreign_agent(), organization())];
    let mut input = within_ceilings();
    input.execution_binding = Some(execution_id());
    let refused = decide_create(
        &DelegationProjection::holding(records),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("an execution another agent holds is refused");
    assert_refused(
        &refused,
        DelegationClause::ExecutionBindingFails,
        RefusedAs::Denied,
    );

    input.execution_binding = Some(ExecutionId::new(uuid(99)));
    let unknown = decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("an execution no record names is refused");
    assert_eq!(
        unknown, refused,
        "an unknown execution refuses like a foreign one"
    );

    input.execution_binding = Some(execution_id());
    decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect("the control: the delegate's own execution binds");
}

/// "agent ceilings": a scope naming an action the installation ceiling refuses is refused,
/// rather than narrowed into a delegation the delegator did not ask for.
#[test]
fn a_scope_outside_the_delegates_ceilings_is_refused() {
    let mut records = starting_records();
    records.ceilings = vec![ceiling(
        63,
        agent(),
        Some(organization()),
        &["tool.delete"],
        both_tools(),
        "PT1H",
    )];
    let fold = DelegationProjection::holding(records);
    let refused = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &within_ceilings(),
    )
    .expect_err("the privileged tool is outside the ceiling");
    assert_refused(
        &refused,
        DelegationClause::ExceedsCeilings,
        RefusedAs::Denied,
    );

    let mut input = within_ceilings();
    input.scope = read_only();
    decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect("the control: the tool the ceiling admits is delegated");
}

/// `expires_at - created_at` is bounded by the smallest `max_delegation_ttl` over the
/// delegate's applicable ceilings: one hour (tenant), not two (platform).
#[test]
fn a_delegation_whose_expiry_exceeds_the_delegates_smallest_max_delegation_ttl_is_refused() {
    let mut input = within_ceilings();
    input.expires_at = Timestamp::new("2026-01-05T10:30:00Z");
    let refused = decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("ninety minutes exceeds the tenant ceiling's hour");
    assert_refused(
        &refused,
        DelegationClause::ExceedsCeilings,
        RefusedAs::Denied,
    );

    input.expires_at = Timestamp::new("2026-01-05T10:00:00Z");
    decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect("the control: exactly the smallest ttl is admitted");

    input.expires_at = Timestamp::new("2026-01-05T10:00:00.5Z");
    decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("half a second past the smallest ttl is refused");

    input.expires_at = at();
    decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("a window that ends when it is created delegates nothing");
}

/// "a transitive" grant: a delegation created under a context that is itself delegated
/// would hand on authority that was delegated once.
#[test]
fn a_delegation_created_under_a_delegated_context_is_refused_as_transitive() {
    let mut fold = projection();
    let held = created(&mut fold);
    let mut input = within_ceilings();
    input.context = delegated_context(held, None);
    let refused = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("a delegated context creates no delegation");
    assert_refused(&refused, DelegationClause::Transitive, RefusedAs::Denied);
}

/// "approval-required grant would be created": policy requires an approval for the
/// delegator's use of the privileged tool, so delegating it would create a grant that skips
/// the approval.
#[test]
fn a_scope_policy_requires_approval_for_is_refused() {
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
    policy.allow(
        organization(),
        AuthoritySubject::Principal(user()),
        read_tool(),
        resource(),
    );
    policy.require_approval(
        organization(),
        AuthoritySubject::Principal(user()),
        privileged_tool(),
        resource(),
        ChallengeRequirement::Approval,
    );
    let refused = decide_create_delegation(
        &projection(),
        &policy,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &within_ceilings(),
        &at(),
    )
    .expect_err("an approval-required action is not delegated");
    assert_refused(
        &refused,
        DelegationClause::ApprovalRequired,
        RefusedAs::Denied,
    );

    let mut input = within_ceilings();
    input.scope = read_only();
    decide_create_delegation(
        &projection(),
        &policy,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
        &at(),
    )
    .expect("the control: the tool policy allows outright is delegated");
}

// ---------------------------------------------------------------------------------------------
// `mandate.delegation.RevokeDelegation`.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_active_delegation_is_revoked_and_the_record_is_kept_in_revoked() {
    let mut fold = projection();
    let id = created(&mut fold);
    let context = plain_context(user());
    let event = decide_revoke_delegation(&fold, &admission(), &context, id)
        .expect("an active delegation is revoked");
    assert_eq!(
        event,
        DelegationEvent::Revoked {
            context: context.clone(),
            id,
        }
    );
    assert_eq!(event.ess_name(), "mandate.delegation.DelegationRevoked");
    fold.apply(&event);
    let record = fold
        .delegation(&id)
        .expect("the read answers")
        .expect("the record is kept");
    assert_eq!(record.state, DelegationState::Revoked);
}

/// The story's own requirement: once revoked through the command and the fold, the agent's
/// tool call under the delegation is refused at the PEP, and before it was allowed.
#[test]
fn a_revoked_delegation_is_refused_at_check_through_the_fold() {
    let mut fold = projection();
    let id = created(&mut fold);
    let context = delegated_context(id, None);
    check_through(&fold, &context, &read_tool()).expect("allowed before the revocation");

    let event =
        decide_revoke_delegation(&fold, &admission(), &plain_context(user()), id).expect("revoked");
    fold.apply(&event);
    let refused = check_through(&fold, &context, &read_tool())
        .expect_err("a revoked delegation admits nothing at Check");
    assert!(!refused.decision.allowed);
    assert_eq!(refused.reason, DenialReason::Denied);
}

/// "delegation is outside the verified organization": a delegation recorded in another
/// organization refuses exactly as an identity no record carries.
#[test]
fn a_delegation_of_another_organization_refuses_like_an_unknown_one() {
    let mut fold = projection();
    let id = created(&mut fold);
    let outsider = VerifiedContext {
        organization: other_organization(),
        ..plain_context(user())
    };
    let before = fold.clone();
    let foreign = decide_revoke_delegation(&fold, &admission(), &outsider, id)
        .expect_err("another organization's delegation is refused");
    let unknown =
        decide_revoke_delegation(&fold, &admission(), &outsider, DelegationId::new(uuid(98)))
            .expect_err("an unknown delegation is refused");
    assert_refused(&foreign, DelegationClause::RecordOutside, RefusedAs::Denied);
    assert_eq!(foreign, unknown, "foreign and unknown refuse alike");
    assert_eq!(fold, before, "a refusal moves no record");
}

/// A revoked delegation is terminal: the second revocation is the declared `wrong-state`,
/// emits nothing and moves nothing.
#[test]
fn a_second_revocation_answers_wrong_state_and_emits_nothing() {
    let mut fold = projection();
    let id = created(&mut fold);
    let context = plain_context(user());
    let event = decide_revoke_delegation(&fold, &admission(), &context, id).expect("revoked");
    fold.apply(&event);
    let before = fold.clone();
    let refused = decide_revoke_delegation(&fold, &admission(), &context, id)
        .expect_err("a revoked delegation is not revoked again");
    assert_refused(
        &refused,
        DelegationClause::WrongState,
        RefusedAs::WrongState,
    );
    assert_eq!(fold, before, "a refusal moves no record");
}

/// "Caller lacks delegation-revocation authority".
#[test]
fn a_caller_the_admission_does_not_hold_as_a_revoker_is_refused() {
    let mut fold = projection();
    let id = created(&mut fold);
    let refused = decide_revoke_delegation(
        &fold,
        &ConfiguredDelegationAdmission::new(),
        &plain_context(user()),
        id,
    )
    .expect_err("a caller without revocation authority is refused");
    assert_refused(
        &refused,
        DelegationClause::CallerUnauthorized,
        RefusedAs::Denied,
    );
}

// ---------------------------------------------------------------------------------------------
// `mandate.delegation.RetireAgent`.
// ---------------------------------------------------------------------------------------------

/// Accepted, and "retirement cannot stop new executions and exchanges under its ceiling":
/// once retired through the fold, the agent acting for itself is refused at Check, where
/// before it was allowed.
#[test]
fn a_recorded_agent_is_retired_and_check_refuses_it_through_the_fold() {
    let mut fold = projection();
    let own = plain_context(agent());
    // The agent acting for itself needs a grant of its own; the administrator's delegation
    // stands in for it, so the agent acts under the administrator instead.
    let delegation = created(&mut fold);
    let acting = delegated_context(delegation, None);
    check_through(&fold, &acting, &read_tool()).expect("allowed before the retirement");

    let context = plain_context(user());
    let event =
        decide_retire_agent(&fold, &admission(), &context, agent()).expect("the agent retires");
    assert_eq!(
        event,
        DelegationEvent::AgentRetired {
            context: context.clone(),
            id: agent(),
        }
    );
    assert_eq!(event.ess_name(), "mandate.delegation.AgentRetired");
    fold.apply(&event);
    let record = fold
        .agent(&agent())
        .expect("the read answers")
        .expect("the record is kept");
    assert_eq!(record.state, AgentState::Retired);
    check_through(&fold, &acting, &read_tool())
        .expect_err("a retired agent is admitted by no check");
    check_through(&fold, &own, &read_tool()).expect_err("nor acting for itself");
}

#[test]
fn an_agent_of_another_organization_refuses_like_an_unknown_one() {
    let fold = projection();
    let before = fold.clone();
    let foreign = decide_retire_agent(&fold, &admission(), &plain_context(user()), foreign_agent())
        .expect_err("another organization's agent is refused");
    let unknown = decide_retire_agent(&fold, &admission(), &plain_context(user()), stranger())
        .expect_err("an unknown agent is refused");
    assert_refused(&foreign, DelegationClause::RecordOutside, RefusedAs::Denied);
    assert_eq!(foreign, unknown, "foreign and unknown refuse alike");
    assert_eq!(fold, before, "a refusal moves no record");
}

#[test]
fn a_second_retirement_answers_wrong_state_and_emits_nothing() {
    let mut fold = projection();
    let context = plain_context(user());
    let event = decide_retire_agent(&fold, &admission(), &context, agent()).expect("retired");
    fold.apply(&event);
    let before = fold.clone();
    let refused = decide_retire_agent(&fold, &admission(), &context, agent())
        .expect_err("a retired agent is not retired again");
    assert_refused(
        &refused,
        DelegationClause::WrongState,
        RefusedAs::WrongState,
    );
    assert_eq!(fold, before, "a refusal moves no record");
}

/// "Caller lacks agent-administration authority".
#[test]
fn a_caller_the_admission_does_not_hold_as_an_agent_administrator_is_refused() {
    let refused = decide_retire_agent(
        &projection(),
        &ConfiguredDelegationAdmission::new().with_delegator(user()),
        &plain_context(user()),
        agent(),
    )
    .expect_err("a caller without agent administration is refused");
    assert_refused(
        &refused,
        DelegationClause::CallerUnauthorized,
        RefusedAs::Denied,
    );
}

// ---------------------------------------------------------------------------------------------
// `mandate.delegation.CompleteExecution`.
// ---------------------------------------------------------------------------------------------

/// Accepted: the agent that holds the execution completes it, and Check then refuses a tool
/// call made in it.
#[test]
fn a_recorded_execution_is_completed_by_its_agent_and_check_refuses_it_through_the_fold() {
    let mut records = starting_records();
    records.executions = Vec::new();
    let mut fold = DelegationProjection::holding(records.clone());
    let delegation = created(&mut fold);
    // The execution runs under the delegation, for the administrator.
    let mut held = execution(agent(), organization());
    held.delegation_id = Some(delegation);
    records.executions = vec![held];
    let mut fold = DelegationProjection::fold(records, fold.log());
    let acting = delegated_context(delegation, Some(execution_id()));
    check_through(&fold, &acting, &read_tool()).expect("allowed in the open execution");

    let event = decide_complete_execution(&fold, &acting, execution_id())
        .expect("the agent completes its execution");
    assert_eq!(
        event,
        DelegationEvent::ExecutionCompleted {
            context: acting.clone(),
            id: execution_id(),
        }
    );
    assert_eq!(event.ess_name(), "mandate.delegation.ExecutionCompleted");
    fold.apply(&event);
    let record = fold
        .execution(&execution_id())
        .expect("the read answers")
        .expect("the record is kept");
    assert_eq!(record.state, ExecutionState::Completed);
    check_through(&fold, &acting, &read_tool())
        .expect_err("no tool call is admitted in a completed execution");
}

/// "Caller is not the agent runtime that holds this execution".
#[test]
fn an_execution_completed_by_another_principal_is_refused() {
    let fold = projection();
    let before = fold.clone();
    let refused = decide_complete_execution(&fold, &plain_context(user()), execution_id())
        .expect_err("the administrator does not hold the agent's execution");
    assert_refused(&refused, DelegationClause::NotTheRuntime, RefusedAs::Denied);
    assert_eq!(fold, before, "a refusal moves no record");
    decide_complete_execution(&fold, &plain_context(agent()), execution_id())
        .expect("the control: the agent itself completes it");
}

#[test]
fn an_execution_of_another_organization_refuses_like_an_unknown_one() {
    let mut records = starting_records();
    records.executions = vec![execution(agent(), other_organization())];
    let fold = DelegationProjection::holding(records);
    let foreign = decide_complete_execution(&fold, &plain_context(agent()), execution_id())
        .expect_err("another organization's execution is refused");
    let unknown =
        decide_complete_execution(&fold, &plain_context(agent()), ExecutionId::new(uuid(97)))
            .expect_err("an unknown execution is refused");
    assert_refused(&foreign, DelegationClause::RecordOutside, RefusedAs::Denied);
    assert_eq!(foreign, unknown, "foreign and unknown refuse alike");
}

#[test]
fn a_second_completion_answers_wrong_state_and_emits_nothing() {
    let mut fold = projection();
    let context = plain_context(agent());
    let event = decide_complete_execution(&fold, &context, execution_id()).expect("completed");
    fold.apply(&event);
    let before = fold.clone();
    let refused = decide_complete_execution(&fold, &context, execution_id())
        .expect_err("a completed execution is not completed again");
    assert_refused(
        &refused,
        DelegationClause::WrongState,
        RefusedAs::WrongState,
    );
    assert_eq!(fold, before, "a refusal moves no record");
}

// ---------------------------------------------------------------------------------------------
// `mandate.delegation.ConsumeApproval`.
// ---------------------------------------------------------------------------------------------

fn approval_context() -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        ..plain_context(user())
    }
}

#[test]
fn a_recorded_approval_is_consumed_once_by_the_context_it_answers() {
    let mut fold = projection();
    let context = approval_context();
    let event = decide_consume_approval(&fold, &context, approval_id(), &at())
        .expect("the approval is consumed");
    assert_eq!(
        event,
        DelegationEvent::ApprovalConsumed {
            context: context.clone(),
            id: approval_id(),
        }
    );
    assert_eq!(event.ess_name(), "mandate.delegation.ApprovalConsumed");
    fold.apply(&event);
    let record = fold
        .approval(&approval_id())
        .expect("the read answers")
        .expect("the record is kept");
    assert_eq!(record.state, ApprovalState::Consumed);
}

/// "Caller does not hold the decision context the approval answers": another subject, or
/// the same subject without the actor the approval names.
#[test]
fn an_approval_consumed_under_another_subject_or_actor_is_refused() {
    let fold = projection();
    let other_subject = VerifiedContext {
        actor: Some(agent()),
        ..plain_context(colleague())
    };
    let refused = decide_consume_approval(&fold, &other_subject, approval_id(), &at())
        .expect_err("another subject does not hold the decision context");
    assert_refused(
        &refused,
        DelegationClause::NotTheDecisionContext,
        RefusedAs::Denied,
    );
    let without_actor =
        decide_consume_approval(&fold, &plain_context(user()), approval_id(), &at())
            .expect_err("the subject acting as itself is not the decision the approval answers");
    assert_refused(
        &without_actor,
        DelegationClause::NotTheDecisionContext,
        RefusedAs::Denied,
    );
}

#[test]
fn an_approval_of_another_organization_refuses_like_an_unknown_one() {
    let mut records = starting_records();
    records.approvals = vec![approval(other_organization(), "2026-01-05T10:00:00Z")];
    let fold = DelegationProjection::holding(records);
    let foreign = decide_consume_approval(&fold, &approval_context(), approval_id(), &at())
        .expect_err("another organization's approval is refused");
    let unknown =
        decide_consume_approval(&fold, &approval_context(), ApprovalId::new(uuid(96)), &at())
            .expect_err("an unknown approval is refused");
    assert_refused(&foreign, DelegationClause::RecordOutside, RefusedAs::Denied);
    assert_eq!(foreign, unknown, "foreign and unknown refuse alike");
}

/// "expiry does not match the check being satisfied": an approval past its `expires_at`
/// satisfies nothing, with no recorded move.
#[test]
fn an_expired_approval_is_refused() {
    let mut records = starting_records();
    records.approvals = vec![approval(organization(), "2026-01-05T09:00:00Z")];
    let fold = DelegationProjection::holding(records);
    let refused = decide_consume_approval(&fold, &approval_context(), approval_id(), &at())
        .expect_err("an approval expiring at the decision instant is spent");
    assert_refused(
        &refused,
        DelegationClause::ApprovalExpired,
        RefusedAs::Denied,
    );
}

#[test]
fn a_second_consumption_answers_wrong_state_and_emits_nothing() {
    let mut fold = projection();
    let context = approval_context();
    let event = decide_consume_approval(&fold, &context, approval_id(), &at()).expect("consumed");
    fold.apply(&event);
    let before = fold.clone();
    let refused = decide_consume_approval(&fold, &context, approval_id(), &at())
        .expect_err("an approval is one-use");
    assert_refused(
        &refused,
        DelegationClause::WrongState,
        RefusedAs::WrongState,
    );
    assert_eq!(fold, before, "a refusal moves no record");
}

// ---------------------------------------------------------------------------------------------
// The fold.
// ---------------------------------------------------------------------------------------------

/// The fold is a function of its starting records and its log: replaying the log from the
/// same records rebuilds the same projection.
#[test]
fn the_projection_is_rebuilt_by_folding_its_log() {
    let mut fold = projection();
    let id = created(&mut fold);
    for event in [
        decide_revoke_delegation(&fold, &admission(), &plain_context(user()), id).expect("revoked"),
        decide_complete_execution(&fold, &plain_context(agent()), execution_id())
            .expect("completed"),
        decide_consume_approval(&fold, &approval_context(), approval_id(), &at())
            .expect("consumed"),
        decide_retire_agent(&fold, &admission(), &plain_context(user()), agent()).expect("retired"),
    ] {
        fold.apply(&event);
    }
    assert_eq!(fold.log().len(), 5, "every applied event is logged");
    let rebuilt = DelegationProjection::fold(starting_records(), fold.log());
    assert_eq!(rebuilt, fold, "the projection is its log folded");
}
