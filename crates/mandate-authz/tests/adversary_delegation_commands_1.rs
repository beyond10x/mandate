//! Security review of `story:agent-security`, the delegation commands (wave 7, U2): integrity
//! conformance checks of the deciders in `mandate_authz::command`, the fold in
//! `mandate_authz::event` and `mandate_types::Duration::seconds`. The world is
//! `tests/delegation_commands.rs`'s, copied because every file under `tests/` is its own crate.

#![allow(dead_code, unused_imports)]

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

fn approval_context() -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        ..plain_context(user())
    }
}

// ---------------------------------------------------------------------------------------------
// Security review of the delegation commands (wave 7, U2). Every case below is an integrity
// conformance check of the unit's own contract: the five deciders, the fold and the duration
// reading they bound a delegation with.
// ---------------------------------------------------------------------------------------------

use mandate_authz::agent::{
    AuthorityClause, AuthorityRequest, ValidatedProof, evaluate_agent_authority,
};

fn proof(principal: PrincipalId) -> ValidatedProof {
    ValidatedProof {
        principal,
        organization: organization(),
        authority: both_tools(),
        expires_at: Timestamp::new("2026-01-05T12:00:00Z"),
        actor: None,
        delegation: None,
    }
}

/// The token exchange's evaluation of `requested` under `context`, against `records`.
fn exchange<R: AgentAuthorityRead>(
    records: &R,
    context: &VerifiedContext,
) -> mandate_authz::agent::AuthorityDecision {
    let subject = proof(context.subject);
    let actor = proof(context.actor.unwrap_or(context.subject));
    evaluate_agent_authority(
        records,
        &policy(),
        &AuthorityRequest {
            context,
            subject: &subject,
            actor: &actor,
            delegation: context.delegation.as_ref(),
            audience: &audience(),
            requested: &read_only(),
            attributes: &AttributeSet::new(),
            at: &at(),
        },
    )
}

/// The `DelegationCreated` event the administrator's delegation is recorded by.
fn created_event(fold: &DelegationProjection) -> DelegationEvent {
    decide_create(
        fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &within_ceilings(),
    )
    .expect("a delegation within the ceilings is created")
    .event
}

fn created_id(event: &DelegationEvent) -> DelegationId {
    match event {
        DelegationEvent::Created(created) => created.id,
        other => panic!("not a creation: {other:?}"),
    }
}

/// Invariant 3: a `DelegationCreated` delivered a second time after the delegation was revoked
/// does not put the delegation back in force. The fold must leave the record `Revoked`, and
/// neither `check` nor the exchange may admit a tool call under it.
#[test]
fn a_replayed_creation_does_not_resurrect_a_revoked_delegation() {
    let start = projection();
    let creation = created_event(&start);
    let id = created_id(&creation);
    let revocation = DelegationEvent::Revoked {
        context: plain_context(user()),
        id,
    };
    let fold = DelegationProjection::fold(
        starting_records(),
        &[creation.clone(), revocation, creation],
    );
    let context = delegated_context(id, None);

    let record = fold
        .delegation(&id)
        .expect("readable")
        .expect("the delegation is recorded");
    assert_eq!(
        record.state,
        DelegationState::Revoked,
        "a replayed creation must not move a revoked delegation back to Active"
    );
    assert!(
        check_through(&fold, &context, &read_tool()).is_err(),
        "check must refuse a tool call under a revoked delegation, whatever was replayed"
    );
    assert!(
        !exchange(&fold, &context).allowed,
        "the exchange must refuse a revoked delegation, whatever was replayed"
    );
}

/// Invariant 3, event order: a log in which the revocation precedes the creation it names
/// never leaves that delegation in force.
#[test]
fn a_revocation_ordered_before_its_creation_never_leaves_the_delegation_in_force() {
    let start = projection();
    let creation = created_event(&start);
    let id = created_id(&creation);
    let revocation = DelegationEvent::Revoked {
        context: plain_context(user()),
        id,
    };
    let fold = DelegationProjection::fold(starting_records(), &[revocation, creation]);
    assert!(
        check_through(&fold, &delegated_context(id, None), &read_tool()).is_err(),
        "a delegation whose revocation is in the log admits nothing at check"
    );
}

/// Invariant 3: no order or repetition of the log reinstates a retired agent, at check and at
/// the exchange (the control: the same log without the retirement admits).
#[test]
fn no_order_or_repetition_of_the_log_reinstates_a_retired_agent() {
    let start = projection();
    let creation = created_event(&start);
    let id = created_id(&creation);
    let retirement = DelegationEvent::AgentRetired {
        context: plain_context(user()),
        id: agent(),
    };
    let context = delegated_context(id, None);

    let control = DelegationProjection::fold(starting_records(), std::slice::from_ref(&creation));
    check_through(&control, &context, &read_tool()).expect("the control admits");
    assert!(exchange(&control, &context).allowed, "the control admits");

    for log in [
        vec![creation.clone(), retirement.clone()],
        vec![retirement.clone(), creation.clone()],
        vec![retirement.clone(), creation.clone(), retirement.clone()],
        vec![creation.clone(), retirement.clone(), creation.clone()],
    ] {
        let fold = DelegationProjection::fold(starting_records(), &log);
        assert!(
            check_through(&fold, &context, &read_tool()).is_err(),
            "a retired agent is admitted at check after {log:?}"
        );
        let decided = exchange(&fold, &context);
        assert!(
            !decided.allowed,
            "a retired agent is admitted at the exchange"
        );
        assert_eq!(decided.clause, Some(AuthorityClause::AgentRetired));
    }
}

/// Invariant 3: a delegation recorded in another organization's log admits nothing in this
/// one, though it names this organization's administrator, agent and audience.
#[test]
fn a_creation_logged_under_another_organization_admits_nothing_here() {
    let start = projection();
    let DelegationEvent::Created(mut foreign) = created_event(&start) else {
        panic!("a creation");
    };
    foreign.context.organization = other_organization();
    let id = foreign.id;
    let fold = DelegationProjection::fold(starting_records(), &[DelegationEvent::Created(foreign)]);
    let context = delegated_context(id, None);
    assert!(check_through(&fold, &context, &read_tool()).is_err());
    let decided = exchange(&fold, &context);
    assert!(!decided.allowed);
    assert_eq!(decided.clause, Some(AuthorityClause::DelegationAbsent));
}

/// Invariant 3: once revoked or completed through the commands, the exchange refuses too,
/// not only `check` (the existing cases cover `check`).
#[test]
fn the_exchange_refuses_what_a_revocation_or_a_completion_withdrew() {
    let mut fold = projection();
    let id = created(&mut fold);
    let context = delegated_context(id, None);
    assert!(exchange(&fold, &context).allowed, "the control admits");
    let event =
        decide_revoke_delegation(&fold, &admission(), &plain_context(user()), id).expect("revoked");
    fold.apply(&event);
    let decided = exchange(&fold, &context);
    assert!(!decided.allowed);
    assert_eq!(decided.clause, Some(AuthorityClause::DelegationRevoked));

    // The agent acting for itself inside its own execution.
    let mut records = starting_records();
    records.executions[0].subject = None;
    let mut fold = DelegationProjection::holding(records);
    let own = VerifiedContext {
        execution: Some(execution_id()),
        ..plain_context(agent())
    };
    assert!(exchange(&fold, &own).allowed, "the control admits");
    let event =
        decide_complete_execution(&fold, &plain_context(agent()), execution_id()).expect("done");
    fold.apply(&event);
    let decided = exchange(&fold, &own);
    assert!(!decided.allowed);
    assert_eq!(decided.clause, Some(AuthorityClause::ExecutionNotTheActors));
}

/// Invariant 2: a record of another organization that is in its terminal state refuses with
/// exactly the value an identity no record carries refuses with, in each command; it is
/// never told as `wrong-state`, which would disclose that it exists.
#[test]
fn a_terminal_record_of_another_organization_refuses_like_an_unknown_one() {
    let start = projection();
    let DelegationEvent::Created(mut foreign) = created_event(&start) else {
        panic!("a creation");
    };
    foreign.context.organization = other_organization();
    let delegation = foreign.id;
    let mut records = starting_records();
    records.agents.push(Agent {
        state: AgentState::Retired,
        ..agent_record(foreign_agent(), other_organization())
    });
    records.executions[0].organization_id = other_organization();
    records.executions[0].state = ExecutionState::Completed;
    records.approvals[0].organization_id = other_organization();
    records.approvals[0].state = ApprovalState::Consumed;
    let fold = DelegationProjection::fold(
        records,
        &[
            DelegationEvent::Created(foreign),
            DelegationEvent::Revoked {
                context: VerifiedContext {
                    organization: other_organization(),
                    ..plain_context(user())
                },
                id: delegation,
            },
        ],
    );
    let unknown = DelegationId::new(uuid(98));

    let foreign_revoke =
        decide_revoke_delegation(&fold, &admission(), &plain_context(user()), delegation)
            .expect_err("refused");
    let unknown_revoke =
        decide_revoke_delegation(&fold, &admission(), &plain_context(user()), unknown)
            .expect_err("refused");
    assert_eq!(foreign_revoke, unknown_revoke, "RevokeDelegation");

    let foreign_retire =
        decide_retire_agent(&fold, &admission(), &plain_context(user()), foreign_agent())
            .expect_err("refused");
    let unknown_retire =
        decide_retire_agent(&fold, &admission(), &plain_context(user()), stranger())
            .expect_err("refused");
    assert_eq!(foreign_retire, unknown_retire, "RetireAgent");

    let foreign_complete =
        decide_complete_execution(&fold, &plain_context(agent()), execution_id())
            .expect_err("refused");
    let unknown_complete =
        decide_complete_execution(&fold, &plain_context(agent()), ExecutionId::new(uuid(97)))
            .expect_err("refused");
    assert_eq!(foreign_complete, unknown_complete, "CompleteExecution");

    let foreign_consume = decide_consume_approval(&fold, &approval_context(), approval_id(), &at())
        .expect_err("refused");
    let unknown_consume =
        decide_consume_approval(&fold, &approval_context(), ApprovalId::new(uuid(96)), &at())
            .expect_err("refused");
    assert_eq!(foreign_consume, unknown_consume, "ConsumeApproval");

    for refused in [
        foreign_revoke,
        foreign_retire,
        foreign_complete,
        foreign_consume,
    ] {
        assert_eq!(refused.outcome, RefusedAs::Denied, "{refused:?}");
        assert_eq!(
            refused.clause,
            DelegationClause::RecordOutside,
            "{refused:?}"
        );
    }

    let mut input = within_ceilings();
    input.delegate = foreign_agent();
    let foreign_create = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("refused");
    input.delegate = stranger();
    let unknown_create = decide_create(
        &fold,
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("refused");
    assert_eq!(foreign_create, unknown_create, "CreateDelegation");
}

/// Invariant 1: the tenant ceiling's `max_delegation_ttl` in any form that names no span, or
/// a smaller one, never lets a 45-minute delegation through; the platform ceiling's two hours
/// stay beside it. The control: a tenant ttl of one hour admits it.
#[test]
fn a_malformed_or_reordered_ttl_never_widens_the_window() {
    let with_tenant_ttl = |ttl: &str| {
        let mut records = starting_records();
        records.ceilings = vec![
            ceiling(60, agent(), None, &[], both_tools(), "PT2H"),
            ceiling(61, agent(), Some(organization()), &[], both_tools(), ttl),
        ];
        decide_create(
            &DelegationProjection::holding(records),
            &admission(),
            &mut SequentialDelegationIds::new(),
            &within_ceilings(),
        )
    };
    with_tenant_ttl("PT1H").expect("the control: one hour admits 45 minutes");
    with_tenant_ttl("PT45M").expect("the control: the boundary is inclusive");
    for ttl in [
        "PT44M59S",
        "PT0030M",
        "PT29M60S",
        "P0D",
        "PT0S",
        "PT1M1H",
        "PT1S1M",
        "PT1H1H",
        "-PT1H",
        "PT-1H",
        " PT1H",
        "PT1H ",
        "P1W",
        "P1M",
        "P1Y",
        "PT1.5H",
        "PT9223372036854775808S",
        "P106751991167301D",
        "PT",
        "P",
        "",
        "pt1h",
        "PT1h",
        "P1DT",
        "PT1D",
        "P1H",
        "PT\u{0661}H",
    ] {
        let decided = with_tenant_ttl(ttl);
        let refused = decided.expect_err(&format!("a tenant ttl of {ttl:?} admits 45 minutes"));
        assert_eq!(refused.clause, DelegationClause::ExceedsCeilings, "{ttl:?}");
    }
}

/// Invariant 4, read directly: the shared parser never reads a value larger than it names.
#[test]
fn the_duration_reading_never_names_more_than_its_designators_say() {
    for (text, seconds) in [
        ("PT1H", Some(3_600)),
        ("PT0H60M", Some(3_600)),
        ("P1DT24H", Some(172_800)),
        ("PT9223372036854775807S", Some(i64::MAX)),
        ("PT9223372036854775808S", None),
        ("P106751991167300DT15H", Some(9_223_372_036_854_774_000)),
        ("P106751991167300DT16H", None),
        ("PT2562047788015215H", Some(2_562_047_788_015_215 * 3_600)),
        ("PT2562047788015216H", None),
        ("PT1M1H", None),
        ("P1DT1H1M1S1", None),
        ("PPT1H", None),
        ("PTT1H", None),
        ("P+1D", None),
    ] {
        assert_eq!(Duration::new(text).seconds(), seconds, "{text:?}");
    }
}

/// Invariant 1: the window is compared as instants. An expiry written with an offset that is
/// 90 minutes after creation is refused against the one-hour ttl, one that is before creation
/// is refused, and the same 45 minutes written with an offset is admitted.
#[test]
fn an_expiry_written_with_an_offset_is_bounded_as_an_instant() {
    let decide = |expires_at: &str| {
        let mut input = within_ceilings();
        input.expires_at = Timestamp::new(expires_at);
        decide_create(
            &projection(),
            &admission(),
            &mut SequentialDelegationIds::new(),
            &input,
        )
    };
    decide("2026-01-05T10:45:00+01:00").expect("the control: 45 minutes, written at +01:00");
    for expires_at in [
        "2026-01-05T11:30:00+01:00",
        "2026-01-05T08:59:00-00:00",
        "2026-01-05T10:59:00+02:00",
        "2026-01-05T09:00:00Z",
        "2026-01-05T10:00:00.000000001Z",
        "2026-01-05T09:45:00",
        "2026-01-05 09:45:00Z",
    ] {
        let refused = decide(expires_at).expect_err(expires_at);
        assert_eq!(
            refused.clause,
            DelegationClause::ExceedsCeilings,
            "{expires_at}"
        );
    }
}

/// Invariant 1: the delegator is the verified subject — a context whose actor is another
/// principal, or that already carries an execution, is refused as transitive, and an
/// accepted creation records the context's subject whatever the scope names.
#[test]
fn a_context_that_is_not_the_subject_acting_for_itself_creates_nothing() {
    for context in [
        VerifiedContext {
            actor: Some(agent()),
            ..plain_context(user())
        },
        VerifiedContext {
            execution: Some(execution_id()),
            ..plain_context(user())
        },
    ] {
        let mut input = within_ceilings();
        input.context = context;
        let mut ids = SequentialDelegationIds::new();
        let refused = decide_create(&projection(), &admission(), &mut ids, &input)
            .expect_err("a delegated context creates nothing");
        assert_eq!(refused.clause, DelegationClause::Transitive);
        assert_eq!(ids.issued(), 0, "nothing was allocated");
    }
}

/// Invariant 1: a scope that names a resource the ceilings do not name, beside one they do,
/// is refused rather than recorded whole.
#[test]
fn a_resource_outside_the_ceilings_beside_one_inside_is_refused() {
    let mut input = within_ceilings();
    input.scope.resources.push(ResourceRef {
        resource_type: ResourceType::new("deployment"),
        resource_id: ResourceId::new(uuid(11)),
    });
    let refused = decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect_err("a resource no ceiling names is refused");
    assert_eq!(refused.clause, DelegationClause::ExceedsCeilings);
}

// ---------------------------------------------------------------------------------------------
// The execution-bound delegation (`delegation.yaml`'s header): the execution is recorded
// first and may name no delegation yet, the delegation names it in `execution_binding`, and
// `check` decides the bound call instead of refusing it.
// ---------------------------------------------------------------------------------------------

/// Another execution the agent holds for the administrator, recorded and running.
fn second_execution_id() -> ExecutionId {
    ExecutionId::new(uuid(23))
}

/// Create the administrator's delegation bound to [`execution_id`] through the command, over
/// the starting records, and return its event.
fn bound_creation() -> mandate_authz::command::Created {
    let mut input = within_ceilings();
    input.execution_binding = Some(execution_id());
    decide_create(
        &projection(),
        &admission(),
        &mut SequentialDelegationIds::new(),
        &input,
    )
    .expect("the delegate's own open execution binds")
}

/// A fold holding `records` and the bound delegation [`bound_creation`] decided.
fn bound_fold(records: AgentRecords) -> (DelegationProjection, DelegationId) {
    let created = bound_creation();
    let mut fold = DelegationProjection::holding(records);
    fold.apply(&created.event);
    (fold, created.delegation_id)
}

/// The refusal a bound call naming an execution no record carries gets: every refusal of the
/// binding is this one, so the caller learns nothing about which condition failed.
fn unrecorded_execution_refusal() -> mandate_authz::decision::Denied {
    let mut records = starting_records();
    records.executions.clear();
    let (fold, id) = bound_fold(records);
    check_through(
        &fold,
        &delegated_context(id, Some(execution_id())),
        &read_tool(),
    )
    .expect_err("an execution no record carries refuses the bound call")
}

/// The bound call is decided: the execution created before the delegation, naming no
/// delegation yet, admits the agent's call for the administrator under it. So does the same
/// execution naming no subject, and one naming this delegation.
#[test]
fn a_delegation_bound_to_an_execution_admits_the_bound_call_at_check() {
    let mut fold = projection();
    let created = bound_creation();
    fold.apply(&created.event);
    let context = delegated_context(created.delegation_id, Some(execution_id()));
    let decision = check_through(&fold, &context, &read_tool()).expect("the bound call");
    assert!(decision.allowed);
    // The same record checks, read through the exchange, which reports who it decided for.
    let exchanged = exchange(&fold, &context);
    assert!(exchanged.allowed, "{exchanged:?}");
    assert_eq!(exchanged.subject, user(), "the subject is preserved");
    assert_eq!(exchanged.actor, agent(), "the actor is preserved");

    // The execution's `expires_at` still bounds the permitted expiry.
    let mut records = starting_records();
    records.executions[0].expires_at = Timestamp::new("2026-01-05T09:30:00Z");
    let (early, _) = bound_fold(records);
    assert_eq!(
        exchange(&early, &context).expires_at,
        Some(Timestamp::new("2026-01-05T09:30:00Z")),
        "the execution ends before the delegation"
    );

    for (why, change) in [
        (
            "an execution naming no subject",
            (|execution: &mut Execution, _: DelegationId| execution.subject = None)
                as fn(&mut Execution, DelegationId),
        ),
        ("an execution naming this delegation", |execution, id| {
            execution.delegation_id = Some(id);
        }),
    ] {
        let mut records = starting_records();
        change(&mut records.executions[0], created.delegation_id);
        let (fold, id) = bound_fold(records);
        assert_eq!(
            id, created.delegation_id,
            "one allocator, one first identity"
        );
        check_through(&fold, &context, &read_tool()).expect(why);
    }
}

/// One change to the bound execution.
type ExecutionChange = fn(&mut Execution);

/// Every condition of the binding refuses the bound call, each with exactly the refusal an
/// unrecorded execution gets.
#[test]
fn an_execution_that_does_not_hold_refuses_the_bound_call_like_an_unrecorded_one() {
    let unrecorded = unrecorded_execution_refusal();
    let cases: [(&str, ExecutionChange); 6] = [
        ("completed", |execution| {
            execution.state = ExecutionState::Completed;
        }),
        ("expired", |execution| {
            execution.expires_at = Timestamp::new("2026-01-05T09:00:00Z");
        }),
        ("of another organization", |execution| {
            execution.organization_id = other_organization();
        }),
        ("held by another agent", |execution| {
            execution.agent_id = colleague();
        }),
        ("for another subject", |execution| {
            execution.subject = Some(colleague());
        }),
        ("naming another delegation", |execution| {
            execution.delegation_id = Some(DelegationId::new(uuid(98)));
        }),
    ];
    for (why, change) in cases {
        let mut records = starting_records();
        change(&mut records.executions[0]);
        let (fold, id) = bound_fold(records);
        let refused = check_through(
            &fold,
            &delegated_context(id, Some(execution_id())),
            &read_tool(),
        )
        .expect_err(why);
        assert_eq!(refused, unrecorded, "an execution {why}");
    }
}

/// A completion recorded through `CompleteExecution` refuses the bound call from then on.
#[test]
fn a_completion_through_the_command_refuses_the_bound_call() {
    let (mut fold, id) = bound_fold(starting_records());
    let context = delegated_context(id, Some(execution_id()));
    check_through(&fold, &context, &read_tool()).expect("the control: the bound call holds");
    let completed = decide_complete_execution(&fold, &plain_context(agent()), execution_id())
        .expect("the agent completes its own execution");
    fold.apply(&completed);
    let refused = check_through(&fold, &context, &read_tool()).expect_err("completed");
    assert_eq!(refused, unrecorded_execution_refusal());
}

/// A delegation bound to an execution admits no request made outside it: one naming no
/// execution, and one naming another execution that is itself recorded and running.
#[test]
fn a_bound_delegation_refuses_a_call_outside_its_execution() {
    let unrecorded = unrecorded_execution_refusal();
    let mut records = starting_records();
    let mut second = execution(agent(), organization());
    second.id = second_execution_id();
    records.executions.push(second);
    let (fold, id) = bound_fold(records);

    let none = check_through(&fold, &delegated_context(id, None), &read_tool())
        .expect_err("a bound delegation used with no execution");
    assert_eq!(none, unrecorded, "no execution");
    let other = check_through(
        &fold,
        &delegated_context(id, Some(second_execution_id())),
        &read_tool(),
    )
    .expect_err("a bound delegation used with another execution");
    assert_eq!(other, unrecorded, "another execution");
}

/// `CreateDelegation` admits the binding the bound call is decided by: an execution naming no
/// subject, and one naming no delegation.
#[test]
fn create_delegation_binds_an_execution_naming_no_subject_or_no_delegation() {
    let mut input = within_ceilings();
    input.execution_binding = Some(execution_id());
    for (why, subject) in [
        ("an execution naming no subject", None),
        ("an execution naming the delegator", Some(user())),
    ] {
        let mut records = starting_records();
        records.executions[0].subject = subject;
        assert_eq!(
            records.executions[0].delegation_id, None,
            "names no delegation"
        );
        let created = decide_create(
            &DelegationProjection::holding(records),
            &admission(),
            &mut SequentialDelegationIds::new(),
            &input,
        )
        .expect(why);
        let DelegationEvent::Created(event) = &created.event else {
            panic!("a creation records DelegationCreated: {:?}", created.event);
        };
        assert_eq!(event.execution_binding, Some(execution_id()), "{why}");
    }
}
