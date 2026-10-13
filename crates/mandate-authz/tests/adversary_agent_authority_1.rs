//! Adversary cases against the shared agent authority evaluator (`story:agent-authority-kernel`).
//!
//! Each case asserts the story's acceptance, the cleared ceiling decision or the declared
//! `ExchangeCredential` denial on an input the unit's own suite does not exercise: instants at
//! and across day, month, year, leap-day and leap-second boundaries; a proof expiring at the
//! evaluation instant; a delegation starting at it; a space bound carried only by a ceiling;
//! a policy refusal on one pair only; a tenant ceiling's own denied patterns; a port that fails
//! on one read only; the authored `exchange-ceiling-conflict` scenario's records; and the
//! declared reason a policy refusal carries.

use std::cell::Cell;
use std::collections::BTreeSet;

use mandate_authz::agent::{
    AgentAuthorityRead, AuthorityClause, AuthorityDecision, AuthorityRequest, PrincipalStanding,
    Unavailable, ValidatedProof, evaluate_agent_authority,
};
use mandate_authz::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, CeilingState, Delegation, DelegationState,
    current_ceilings,
};
use mandate_policy::port::{
    AttributeSet, Evaluation, PolicyEffect, PolicyError, PolicyEvaluator, PolicyRequest,
};
use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, Audience, AuthorityScope, CorrelationId,
    CredentialId, DecisionReason, DelegationId, DenialReason, Duration, ExecutionId,
    OrganizationId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId,
    Timestamp, Uuid, VerifiedContext,
};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn user() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn agent_principal() -> PrincipalId {
    PrincipalId::new(uuid(3))
}

fn other_agent() -> PrincipalId {
    PrincipalId::new(uuid(8))
}

fn delegation_id() -> DelegationId {
    DelegationId::new(uuid(20))
}

fn audience() -> Audience {
    Audience::new("api-a")
}

fn at() -> Timestamp {
    Timestamp::new("2026-01-05T09:00:00Z")
}

fn resource(byte: u8) -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(byte)),
    }
}

fn actions(names: &[&str]) -> Vec<Action> {
    names.iter().map(|name| Action::new(*name)).collect()
}

fn patterns(names: &[&str]) -> Vec<ActionPattern> {
    names.iter().map(|name| ActionPattern::new(*name)).collect()
}

const UNIVERSE: [&str; 4] = [
    "document.read",
    "document.write",
    "document.share",
    "admin.delete",
];

fn scope(action_names: &[&str], resources: &[u8]) -> AuthorityScope {
    AuthorityScope {
        actions: actions(action_names),
        resources: resources.iter().map(|byte| resource(*byte)).collect(),
        space: None,
    }
}

fn wide_scope() -> AuthorityScope {
    scope(&UNIVERSE, &[10, 11, 12])
}

fn proof(principal: PrincipalId, expires_at: &str) -> ValidatedProof {
    ValidatedProof {
        principal,
        organization: organization(),
        authority: wide_scope(),
        expires_at: Timestamp::new(expires_at),
        actor: None,
        delegation: None,
    }
}

fn context(
    subject: PrincipalId,
    actor: Option<PrincipalId>,
    delegation: Option<DelegationId>,
) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor,
        organization: organization(),
        audience: audience(),
        credential: CredentialId::new(uuid(7)),
        delegation,
        execution: None,
        correlation: CorrelationId::new("adversary"),
    }
}

fn ceiling(
    byte: u8,
    organization_id: Option<OrganizationId>,
    allowed: &[&str],
    denied: &[&str],
) -> AgentCapabilityCeiling {
    AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(uuid(byte)),
        agent_id: agent_principal(),
        organization_id,
        allowed_actions: patterns(allowed),
        denied_actions: patterns(denied),
        scope: wide_scope(),
        max_delegation_ttl: Duration::new("PT1H"),
        state: CeilingState::Recorded,
    }
}

fn delegation_record(scope: AuthorityScope) -> Delegation {
    Delegation {
        id: delegation_id(),
        organization_id: organization(),
        delegator: user(),
        delegate: agent_principal(),
        scope,
        audience: audience(),
        not_before: None,
        expires_at: Timestamp::new("2030-01-01T00:00:00Z"),
        execution_binding: None,
        transitive: false,
        created_at: Timestamp::new("2026-01-05T08:00:00Z"),
        state: DelegationState::Active,
    }
}

/// Which single read the port fails on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fails {
    Nothing,
    Standing,
    Agent,
    Ceilings,
    Delegation,
}

/// A port over lists. `ceilings` answers every record it holds, for any agent, so that a
/// filter the evaluator relies on is the evaluator's and not this port's.
#[derive(Debug, Clone)]
struct Records {
    standings: Vec<(PrincipalId, PrincipalStanding)>,
    agents: Vec<Agent>,
    ceilings: Vec<AgentCapabilityCeiling>,
    delegations: Vec<Delegation>,
    fails: Fails,
}

impl Records {
    fn new(ceilings: Vec<AgentCapabilityCeiling>) -> Self {
        Self {
            standings: vec![
                (user(), PrincipalStanding::Active),
                (agent_principal(), PrincipalStanding::Active),
            ],
            agents: vec![Agent {
                id: agent_principal(),
                organization_id: organization(),
                agent_type: "assistant".to_owned(),
                state: AgentState::Recorded,
            }],
            ceilings,
            delegations: vec![delegation_record(wide_scope())],
            fails: Fails::Nothing,
        }
    }

    fn platform() -> Self {
        Self::new(vec![ceiling(30, None, &["*"], &[])])
    }
}

impl AgentAuthorityRead for Records {
    fn standing(&self, principal: &PrincipalId) -> Result<Option<PrincipalStanding>, Unavailable> {
        if self.fails == Fails::Standing {
            return Err(Unavailable);
        }
        Ok(self
            .standings
            .iter()
            .find(|(recorded, _)| recorded == principal)
            .map(|(_, standing)| *standing))
    }

    fn agent(&self, principal: &PrincipalId) -> Result<Option<Agent>, Unavailable> {
        if self.fails == Fails::Agent {
            return Err(Unavailable);
        }
        Ok(self
            .agents
            .iter()
            .find(|agent| agent.id == *principal)
            .cloned())
    }

    fn ceilings(&self, _agent: &PrincipalId) -> Result<Vec<AgentCapabilityCeiling>, Unavailable> {
        if self.fails == Fails::Ceilings {
            return Err(Unavailable);
        }
        Ok(self.ceilings.clone())
    }

    fn delegation(&self, id: &DelegationId) -> Result<Option<Delegation>, Unavailable> {
        if self.fails == Fails::Delegation {
            return Err(Unavailable);
        }
        Ok(self
            .delegations
            .iter()
            .find(|delegation| delegation.id == *id)
            .cloned())
    }
}

/// A policy that allows every pair except the ones it names, which it answers with `answer`.
struct Except {
    refused: Vec<(Action, ResourceId)>,
    answer: Result<PolicyEffect, PolicyError>,
    asked: Cell<usize>,
}

impl Except {
    fn allow() -> Self {
        Self {
            refused: Vec::new(),
            answer: Ok(PolicyEffect::Allow),
            asked: Cell::new(0),
        }
    }
}

impl PolicyEvaluator for Except {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.asked.set(self.asked.get() + 1);
        let hit = self.refused.iter().any(|(action, resource)| {
            action == request.action && *resource == request.resource.resource_id
        });
        let effect = if hit {
            self.answer.clone()?
        } else {
            PolicyEffect::Allow
        };
        Ok(Evaluation {
            effect,
            version: PolicyVersion::new("v1"),
            challenge: None,
        })
    }
}

#[derive(Debug, Clone)]
struct Ask {
    context: VerifiedContext,
    subject: ValidatedProof,
    actor: ValidatedProof,
    delegation: Option<DelegationId>,
    audience: Audience,
    requested: AuthorityScope,
    attributes: AttributeSet,
    at: Timestamp,
}

impl Ask {
    fn autonomous(requested: AuthorityScope) -> Self {
        let own = proof(agent_principal(), "2030-01-01T00:00:00Z");
        Self {
            context: context(agent_principal(), None, None),
            subject: own.clone(),
            actor: own,
            delegation: None,
            audience: audience(),
            requested,
            attributes: AttributeSet::new(),
            at: at(),
        }
    }

    fn delegated(requested: AuthorityScope) -> Self {
        Self {
            context: context(user(), Some(agent_principal()), Some(delegation_id())),
            subject: proof(user(), "2030-01-01T00:00:00Z"),
            actor: proof(agent_principal(), "2030-01-01T00:00:00Z"),
            delegation: Some(delegation_id()),
            audience: audience(),
            requested,
            attributes: AttributeSet::new(),
            at: at(),
        }
    }

    fn evaluate<P: PolicyEvaluator>(&self, records: &Records, policy: &P) -> AuthorityDecision {
        evaluate_agent_authority(
            records,
            policy,
            &AuthorityRequest {
                context: &self.context,
                subject: &self.subject,
                actor: &self.actor,
                delegation: self.delegation.as_ref(),
                audience: &self.audience,
                requested: &self.requested,
                attributes: &self.attributes,
                at: &self.at,
            },
        )
    }
}

fn action_set(scope: &AuthorityScope) -> BTreeSet<String> {
    scope
        .actions
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect()
}

#[track_caller]
fn assert_refused(decision: &AuthorityDecision, clause: AuthorityClause) {
    assert!(!decision.allowed, "refused on {clause:?}, got {decision:?}");
    assert_eq!(decision.clause, Some(clause), "{decision:?}");
    assert!(
        decision.permitted.actions.is_empty() && decision.permitted.resources.is_empty(),
        "{decision:?}"
    );
    assert_eq!(decision.expires_at, None, "{decision:?}");
}

// ---------------------------------------------------------------------------------------------
// 1. Expiry: never later than any input, at and across every calendar boundary
// ---------------------------------------------------------------------------------------------

/// A proof that ends at the evaluation instant is expired, as a delegation that ends there
/// is (`an_expired_delegation_denies` decides only the delegation's equality and a proof one
/// second early).
#[test]
fn adv_a_proof_ending_exactly_at_the_evaluation_instant_is_expired() {
    for which in ["subject", "actor"] {
        let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
        // The same instant in another notation, so byte equality cannot be what decides.
        let same = Timestamp::new("2026-01-05T10:00:00+01:00");
        match which {
            "subject" => ask.subject.expires_at = same,
            _ => ask.actor.expires_at = same,
        }
        assert_refused(
            &ask.evaluate(&Records::platform(), &Except::allow()),
            AuthorityClause::ProofExpired,
        );
    }
}

/// A delegation whose `not_before` is the evaluation instant is in force at it.
#[test]
fn adv_a_delegation_starting_exactly_at_the_evaluation_instant_is_in_force() {
    let mut records = Records::platform();
    records.delegations[0].not_before = Some(Timestamp::new("2026-01-05T09:00:00.000Z"));
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
}

/// The earliest of subject, actor and delegation expiry, where the inputs differ in day,
/// month, year, offset, fraction, leap day or leap second. The suite's own expiry cases all
/// fall on one day, so a reading that ignored the date would pass them and return a later
/// instant than an input names.
#[test]
fn adv_the_permitted_expiry_is_the_earliest_instant_across_calendar_boundaries() {
    // (subject, actor, delegation, expected earliest)
    let cases = [
        // Across a day.
        (
            "2026-01-06T01:00:00Z",
            "2026-01-05T23:00:00Z",
            "2030-01-01T00:00:00Z",
            "2026-01-05T23:00:00Z",
        ),
        // Across a month.
        (
            "2026-02-01T00:00:00Z",
            "2026-01-31T23:59:59Z",
            "2030-01-01T00:00:00Z",
            "2026-01-31T23:59:59Z",
        ),
        // Across a year, with nanoseconds.
        (
            "2027-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            "2026-12-31T23:59:59.999999999Z",
            "2026-12-31T23:59:59.999999999Z",
        ),
        // An offset that moves the wall clock across a day: 23:30-01:00 is 00:30Z next day.
        (
            "2026-01-05T23:30:00-01:00",
            "2026-01-06T00:00:00Z",
            "2030-01-01T00:00:00Z",
            "2026-01-06T00:00:00Z",
        ),
        // An offset the other way: 00:30+01:00 on the 6th is 23:30Z on the 5th.
        (
            "2026-01-05T23:45:00Z",
            "2026-01-06T00:30:00+01:00",
            "2030-01-01T00:00:00Z",
            "2026-01-06T00:30:00+01:00",
        ),
        // Leap day, and the day after it.
        (
            "2028-03-01T00:00:00Z",
            "2028-02-29T23:59:59Z",
            "2030-01-01T00:00:00Z",
            "2028-02-29T23:59:59Z",
        ),
        // A leap second is before half a second into the next year.
        (
            "2027-01-01T00:00:00.5Z",
            "2026-12-31T23:59:60Z",
            "2030-01-01T00:00:00Z",
            "2026-12-31T23:59:60Z",
        ),
        // Across centuries: 2100 is not a leap year, 2000 was.
        (
            "2100-03-01T00:00:00Z",
            "2100-02-28T23:00:00Z",
            "2101-01-01T00:00:00Z",
            "2100-02-28T23:00:00Z",
        ),
    ];
    for (subject, actor, delegation, earliest) in cases {
        let mut records = Records::platform();
        records.delegations[0].expires_at = Timestamp::new(delegation);
        let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
        ask.subject.expires_at = Timestamp::new(subject);
        ask.actor.expires_at = Timestamp::new(actor);

        let decision = ask.evaluate(&records, &Except::allow());

        assert!(
            decision.allowed,
            "{subject} {actor} {delegation}: {decision:?}"
        );
        assert_eq!(
            decision.expires_at,
            Some(Timestamp::new(earliest)),
            "{subject} {actor} {delegation}"
        );
    }
}

/// Dates that name no instant are refused, never read as some other day.
#[test]
fn adv_a_date_that_names_no_instant_is_refused() {
    for unreadable in [
        "2026-02-29T12:00:00Z",
        "2100-02-29T12:00:00Z",
        "2026-04-31T12:00:00Z",
        "2026-01-05T24:00:00Z",
        "2026-01-05T12:00:00",
        "2026-01-05T12:00:00+24:00",
        "2026-01-05T12:00:00.Z",
    ] {
        let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
        ask.actor.expires_at = Timestamp::new(unreadable);
        assert_refused(
            &ask.evaluate(&Records::platform(), &Except::allow()),
            AuthorityClause::ProofUnreadable,
        );
    }
    // A leap day that exists is read.
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.actor.expires_at = Timestamp::new("2028-02-29T12:00:00Z");
    assert!(ask.evaluate(&Records::platform(), &Except::allow()).allowed);

    // An evaluation instant that names no instant is refused too.
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.at = Timestamp::new("2026-13-01T00:00:00Z");
    assert_refused(
        &ask.evaluate(&Records::platform(), &Except::allow()),
        AuthorityClause::ProofUnreadable,
    );
}

// ---------------------------------------------------------------------------------------------
// 2. Ceilings
// ---------------------------------------------------------------------------------------------

/// A space named only by a ceiling's scope is a bound like any other: it narrows the
/// permitted set to it, and conflicts with a request confined to another space.
#[test]
fn adv_a_space_named_only_by_a_ceiling_bounds_the_permitted_set() {
    let mut tenant = ceiling(31, Some(organization()), &["document.*"], &[]);
    tenant.scope.space = Some(SpaceId::new(uuid(70)));
    let records = Records::new(vec![ceiling(30, None, &["*"], &[]), tenant]);

    let decision =
        Ask::autonomous(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.permitted.space, Some(SpaceId::new(uuid(70))));

    let mut ask = Ask::autonomous(scope(&["document.read"], &[10]));
    ask.requested.space = Some(SpaceId::new(uuid(71)));
    assert_refused(
        &ask.evaluate(&records, &Except::allow()),
        AuthorityClause::SpaceConflict,
    );
}

/// The tenant ceiling's own denied patterns narrow, wildcard ones included (the sampled
/// property only ever gives the platform ceiling denied patterns, and only literal ones).
#[test]
fn adv_a_tenant_ceilings_denied_patterns_narrow_including_wildcards() {
    let records = Records::new(vec![
        ceiling(30, None, &["*"], &[]),
        ceiling(
            31,
            Some(organization()),
            &["*"],
            &["admin.*", "document.write"],
        ),
    ]);
    let decision = Ask::autonomous(scope(&UNIVERSE, &[10])).evaluate(&records, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(
        action_set(&decision.permitted),
        ["document.read", "document.share"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    );
}

/// With no tenant ceiling the platform ceiling alone bounds; with no platform ceiling the
/// tenant ceiling alone bounds. Neither absence widens past the ceiling that is present.
#[test]
fn adv_one_absent_ceiling_level_leaves_the_other_as_the_bound() {
    let platform_only = Records::new(vec![ceiling(30, None, &["document.read"], &[])]);
    let decision =
        Ask::autonomous(scope(&UNIVERSE, &[10])).evaluate(&platform_only, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.permitted.actions, actions(&["document.read"]));

    let tenant_only = Records::new(vec![ceiling(
        31,
        Some(organization()),
        &["document.share"],
        &[],
    )]);
    let decision =
        Ask::autonomous(scope(&UNIVERSE, &[10])).evaluate(&tenant_only, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.permitted.actions, actions(&["document.share"]));
}

/// A ceiling of another agent, recorded for this organization or the platform, applies to
/// nothing and conflicts with nothing, even when the port hands it over.
#[test]
fn adv_a_ceiling_of_another_agent_does_not_apply_or_conflict() {
    let mut foreign_tenant = ceiling(40, Some(organization()), &["*"], &[]);
    foreign_tenant.agent_id = other_agent();
    let mut foreign_platform = ceiling(41, None, &["*"], &[]);
    foreign_platform.agent_id = other_agent();

    // Alone, they leave the agent with no ceiling.
    let records = Records::new(vec![foreign_tenant.clone(), foreign_platform.clone()]);
    assert_refused(
        &Ask::autonomous(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow()),
        AuthorityClause::CeilingAbsent,
    );

    // Beside the agent's own ceilings on the same keys, they are no second current ceiling.
    let records = Records::new(vec![
        ceiling(30, None, &["document.read"], &[]),
        ceiling(31, Some(organization()), &["document.read"], &[]),
        foreign_tenant,
        foreign_platform,
    ]);
    let decision = Ask::autonomous(scope(&UNIVERSE, &[10])).evaluate(&records, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.permitted.actions, actions(&["document.read"]));
}

/// Two current ceilings on another organization's key are not this request's conflict.
#[test]
fn adv_a_conflict_on_another_organizations_key_is_not_this_requests() {
    let other = OrganizationId::new(uuid(9));
    let records = Records::new(vec![
        ceiling(30, None, &["document.*"], &[]),
        ceiling(42, Some(other), &["*"], &[]),
        ceiling(43, Some(other), &["*"], &[]),
    ]);
    let decision =
        Ask::autonomous(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow());
    assert!(decision.allowed, "{decision:?}");
    let read = current_ceilings(&records.ceilings, &agent_principal(), &organization());
    assert!(read.conflicts.is_empty(), "{read:?}");
}

/// A platform-key conflict denies even when the tenant key holds exactly one ceiling.
#[test]
fn adv_a_platform_key_conflict_denies_beside_a_unique_tenant_ceiling() {
    let records = Records::new(vec![
        ceiling(31, Some(organization()), &["document.read"], &[]),
        ceiling(42, None, &["*"], &[]),
        ceiling(43, None, &["document.read"], &[]),
    ]);
    assert_refused(
        &Ask::autonomous(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow()),
        AuthorityClause::CeilingConflict,
    );
}

/// The authored scenario `exchange-ceiling-conflict` (`systems/mandate/scenarios`), whose
/// expected outcome is `unsupported` and which therefore runs nowhere: its arranged records,
/// as the evaluator reads them, must deny on the clause the scenario's summary names.
#[test]
fn adv_the_authored_ceiling_conflict_scenario_denies_on_its_named_clause() {
    let id = |text: &str| Uuid::parse(text).expect("scenario identity");
    let organization = OrganizationId::new(id("00000000-0000-4000-8000-0000000000a1"));
    let agent = PrincipalId::new(id("00000000-0000-4000-8000-000000000003"));
    let subject = PrincipalId::new(id("00000000-0000-4000-8000-000000000001"));
    let delegation = DelegationId::new(id("00000000-0000-4000-8000-0000000000d1"));
    let document = ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(id("00000000-0000-4000-8000-000000000072")),
    };
    let bound = AuthorityScope {
        actions: actions(&["document.read"]),
        resources: vec![document],
        space: None,
    };
    let scenario_ceiling = |identity: &str, allowed: &[&str]| AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(id(identity)),
        agent_id: agent,
        organization_id: Some(organization),
        allowed_actions: patterns(allowed),
        denied_actions: Vec::new(),
        scope: bound.clone(),
        max_delegation_ttl: Duration::new("PT1H"),
        state: CeilingState::Recorded,
    };
    let records = Records {
        standings: vec![
            (subject, PrincipalStanding::Active),
            (agent, PrincipalStanding::Active),
        ],
        agents: vec![Agent {
            id: agent,
            organization_id: organization,
            agent_type: "assistant".to_owned(),
            state: AgentState::Recorded,
        }],
        ceilings: vec![
            scenario_ceiling("00000000-0000-4000-8000-0000000000e1", &["document.*"]),
            scenario_ceiling("00000000-0000-4000-8000-0000000000e2", &["document.read"]),
        ],
        delegations: vec![Delegation {
            id: delegation,
            organization_id: organization,
            delegator: subject,
            delegate: agent,
            scope: bound.clone(),
            audience: Audience::new("api-a"),
            not_before: None,
            expires_at: Timestamp::new("2026-01-05T23:00:00Z"),
            execution_binding: None,
            transitive: false,
            created_at: Timestamp::new("2026-01-05T08:00:00Z"),
            state: DelegationState::Active,
        }],
        fails: Fails::Nothing,
    };
    let proof_for = |principal| ValidatedProof {
        principal,
        organization,
        authority: bound.clone(),
        expires_at: Timestamp::new("2026-01-05T12:00:00Z"),
        actor: None,
        delegation: None,
    };
    let mut ask = Ask::delegated(bound.clone());
    ask.context = VerifiedContext {
        organization,
        ..context(subject, Some(agent), Some(delegation))
    };
    ask.subject = proof_for(subject);
    ask.actor = proof_for(agent);
    ask.delegation = Some(delegation);
    ask.at = Timestamp::new("2026-01-05T09:00:00Z");

    let decision = ask.evaluate(&records, &Except::allow());
    assert_refused(&decision, AuthorityClause::CeilingConflict);
    assert_eq!(decision.reason, DecisionReason::Denied);
}

// ---------------------------------------------------------------------------------------------
// 3. Delegation and identity
// ---------------------------------------------------------------------------------------------

/// An agent acting for itself that names a delegation is refused, even one recorded from
/// itself to itself, whose scope would otherwise only narrow.
#[test]
fn adv_an_autonomous_request_naming_a_self_delegation_is_refused() {
    let mut records = Records::platform();
    records.delegations[0].delegator = agent_principal();
    records.delegations[0].delegate = agent_principal();
    let mut ask = Ask::autonomous(scope(&["document.read"], &[10]));
    ask.delegation = Some(delegation_id());
    ask.context.delegation = Some(delegation_id());
    assert_refused(
        &ask.evaluate(&records, &Except::allow()),
        AuthorityClause::DelegationMismatch,
    );
}

/// An actor proof itself issued under a delegation is a chain (the suite covers a subject
/// proof carrying a delegation and an actor proof carrying an actor, not this).
#[test]
fn adv_an_actor_proof_issued_under_a_delegation_is_a_chain() {
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.actor.delegation = Some(DelegationId::new(uuid(21)));
    assert_refused(
        &ask.evaluate(&Records::platform(), &Except::allow()),
        AuthorityClause::TransitiveChain,
    );
}

/// A delegation bound to an execution admits the request made in that execution, and no
/// other one.
#[test]
fn adv_an_execution_bound_delegation_admits_only_its_execution() {
    let mut records = Records::platform();
    records.delegations[0].execution_binding = Some(ExecutionId::new(uuid(6)));

    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.context.execution = Some(ExecutionId::new(uuid(6)));
    assert!(ask.evaluate(&records, &Except::allow()).allowed);

    ask.context.execution = Some(ExecutionId::new(uuid(66)));
    assert_refused(
        &ask.evaluate(&records, &Except::allow()),
        AuthorityClause::DelegationMismatch,
    );
}

/// A context naming the agent as its own actor is the autonomous request it says it is, and
/// widens nothing: the subject stays the agent, and the bound is the same.
#[test]
fn adv_a_context_naming_the_agent_as_its_own_actor_widens_nothing() {
    let records = Records::new(vec![ceiling(30, None, &["document.read"], &[])]);
    let plain = Ask::autonomous(scope(&UNIVERSE, &[10]));
    let mut named = plain.clone();
    named.context.actor = Some(agent_principal());
    let a = plain.evaluate(&records, &Except::allow());
    let b = named.evaluate(&records, &Except::allow());
    assert!(a.allowed && b.allowed, "{a:?} {b:?}");
    assert_eq!(a.permitted, b.permitted);
    assert_eq!((b.subject, b.actor), (agent_principal(), agent_principal()));
}

// ---------------------------------------------------------------------------------------------
// 5. Fail closed, and the declared reason
// ---------------------------------------------------------------------------------------------

/// Each read failing on its own denies as `Unavailable` (the suite fails every read at once,
/// so only the first read's error handling is decided).
#[test]
fn adv_each_port_read_failing_alone_denies_as_unavailable() {
    for fails in [
        Fails::Standing,
        Fails::Agent,
        Fails::Ceilings,
        Fails::Delegation,
    ] {
        let mut records = Records::platform();
        records.fails = fails;
        let decision =
            Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Except::allow());
        assert!(!decision.allowed, "{fails:?}: {decision:?}");
        assert_eq!(
            decision.clause,
            Some(AuthorityClause::Unavailable),
            "{fails:?}"
        );
        assert_eq!(decision.reason, DecisionReason::Unavailable, "{fails:?}");
    }
}

/// A policy refusal on one pair that is not the first refuses the request: policy is asked
/// about every permitted action on every permitted resource.
#[test]
fn adv_a_policy_refusal_on_one_later_pair_refuses_the_request() {
    let policy = Except {
        refused: vec![(Action::new("document.write"), ResourceId::new(uuid(11)))],
        answer: Ok(PolicyEffect::Deny),
        asked: Cell::new(0),
    };
    let decision = Ask::autonomous(scope(&["document.read", "document.write"], &[10, 11]))
        .evaluate(&Records::platform(), &policy);
    assert_refused(&decision, AuthorityClause::PolicyDenied);
}

/// A policy refusal carries its declared reason through, as `check` does
/// (`crates/mandate-authz/src/decision.rs:194-197`): the policy port's only implementation
/// refuses a policy of another organization as `TenantMismatch`
/// (`crates/mandate-policy/src/double.rs:252`), and the exchange's error declares `reason`.
#[test]
fn adv_a_policy_refusal_keeps_its_declared_reason() {
    let policy = Except {
        refused: vec![(Action::new("document.read"), ResourceId::new(uuid(10)))],
        answer: Err(PolicyError::Denied(DenialReason::TenantMismatch)),
        asked: Cell::new(0),
    };
    let decision =
        Ask::autonomous(scope(&["document.read"], &[10])).evaluate(&Records::platform(), &policy);
    assert!(!decision.allowed, "{decision:?}");
    assert_eq!(
        decision.reason,
        DecisionReason::TenantMismatch,
        "policy's declared reason is dropped: {decision:?}"
    );
}
