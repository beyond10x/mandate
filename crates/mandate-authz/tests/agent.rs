//! The shared agent authority evaluator, decided case by case and by property.
//!
//! `story:agent-authority-kernel`: given a subject, an independently authenticated actor,
//! applicable ceilings, a delegation and a requested capability, the permitted set is exactly
//! the applicable intersection and never exceeds any input bound. Each required observation
//! of the story is one case below, named for what it observes; the two properties enumerate
//! their inputs deterministically, with no dependency, because the workspace carries no
//! property-testing crate and `dependency-boundaries.json` gives this package none.
//!
//! `decision-blocker:identity-uniqueness-ceiling` asks for three of these: two current
//! ceilings on one key deny with the declared clause, the permitted set is within both the
//! platform and the tenant ceiling, and a ceiling recorded for another organization does not
//! apply.

use std::cell::Cell;
use std::collections::BTreeSet;

use mandate_authz::agent::{
    AgentAuthorityRead, AuthorityClause, AuthorityDecision, AuthorityRequest, PrincipalStanding,
    Unavailable, ValidatedProof, evaluate_agent_authority,
};
use mandate_authz::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, Approval, CeilingKey, CeilingState, Delegation,
    DelegationState, Execution, current_ceilings,
};
use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, Evaluation, PolicyEffect, PolicyError,
    PolicyEvaluator, PolicyRequest, Unanswered,
};
use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, ApprovalId, Audience, AuthorityScope,
    CorrelationId, CredentialId, DecisionReason, DelegationId, DenialReason, Duration, ExecutionId,
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

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn user() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn agent_principal() -> PrincipalId {
    PrincipalId::new(uuid(3))
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

/// The four actions every case draws from.
const UNIVERSE: [&str; 4] = [
    "document.read",
    "document.write",
    "document.share",
    "admin.delete",
];

fn wide_scope() -> AuthorityScope {
    AuthorityScope {
        actions: actions(&UNIVERSE),
        resources: vec![resource(10), resource(11), resource(12)],
        space: None,
    }
}

fn scope(action_names: &[&str], resources: &[u8]) -> AuthorityScope {
    AuthorityScope {
        actions: actions(action_names),
        resources: resources.iter().map(|byte| resource(*byte)).collect(),
        space: None,
    }
}

fn proof(principal: PrincipalId, authority: AuthorityScope, expires_at: &str) -> ValidatedProof {
    ValidatedProof {
        principal,
        organization: organization(),
        authority,
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
        correlation: CorrelationId::new("agent-authority"),
    }
}

fn agent_record() -> Agent {
    Agent {
        id: agent_principal(),
        organization_id: organization(),
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
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

fn platform_ceiling(allowed: &[&str]) -> AgentCapabilityCeiling {
    ceiling(30, None, allowed, &[])
}

fn tenant_ceiling(allowed: &[&str]) -> AgentCapabilityCeiling {
    ceiling(31, Some(organization()), allowed, &[])
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
        expires_at: Timestamp::new("2026-01-05T20:00:00Z"),
        execution_binding: None,
        transitive: false,
        created_at: Timestamp::new("2026-01-05T08:00:00Z"),
        state: DelegationState::Active,
    }
}

/// The records the port answers with. Every field is the whole answer for its read.
#[derive(Debug, Clone)]
struct Records {
    standings: Vec<(PrincipalId, PrincipalStanding)>,
    agents: Vec<Agent>,
    ceilings: Vec<AgentCapabilityCeiling>,
    delegations: Vec<Delegation>,
    unavailable: bool,
}

impl Records {
    fn autonomous(ceilings: Vec<AgentCapabilityCeiling>) -> Self {
        Self {
            standings: vec![
                (user(), PrincipalStanding::Active),
                (agent_principal(), PrincipalStanding::Active),
            ],
            agents: vec![agent_record()],
            ceilings,
            delegations: Vec::new(),
            unavailable: false,
        }
    }

    fn delegated(ceilings: Vec<AgentCapabilityCeiling>, delegation: Delegation) -> Self {
        Self {
            delegations: vec![delegation],
            ..Self::autonomous(ceilings)
        }
    }
}

impl AgentAuthorityRead for Records {
    fn standing(&self, principal: &PrincipalId) -> Result<Option<PrincipalStanding>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .standings
            .iter()
            .find(|(recorded, _)| recorded == principal)
            .map(|(_, standing)| *standing))
    }

    fn agent(&self, principal: &PrincipalId) -> Result<Option<Agent>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .agents
            .iter()
            .find(|agent| agent.id == *principal)
            .cloned())
    }

    fn ceilings(&self, agent: &PrincipalId) -> Result<Vec<AgentCapabilityCeiling>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .ceilings
            .iter()
            .filter(|ceiling| ceiling.agent_id == *agent)
            .cloned()
            .collect())
    }

    fn delegation(&self, id: &DelegationId) -> Result<Option<Delegation>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(self
            .delegations
            .iter()
            .find(|delegation| delegation.id == *id)
            .cloned())
    }

    // No case here names an execution or an approval record; `tests/agent_security.rs` does.
    fn execution(&self, _id: &ExecutionId) -> Result<Option<Execution>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(None)
    }

    fn approval(&self, _id: &ApprovalId) -> Result<Option<Approval>, Unavailable> {
        if self.unavailable {
            return Err(Unavailable);
        }
        Ok(None)
    }
}

/// A policy that answers every pair with one effect, and counts what it is asked.
struct Answers {
    effect: PolicyEffect,
    asked: Cell<usize>,
}

impl Answers {
    fn allow() -> Self {
        Self {
            effect: PolicyEffect::Allow,
            asked: Cell::new(0),
        }
    }

    fn with(effect: PolicyEffect) -> Self {
        Self {
            effect,
            asked: Cell::new(0),
        }
    }
}

impl PolicyEvaluator for Answers {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.asked.set(self.asked.get() + 1);
        Ok(Evaluation {
            effect: self.effect,
            version: PolicyVersion::new("v1"),
            challenge: (self.effect == PolicyEffect::ApprovalRequired).then(|| Challenge {
                requirement: ChallengeRequirement::Approval,
                correlation: request.context.correlation.clone(),
            }),
        })
    }
}

/// A policy that cannot answer.
struct Unreachable;

impl PolicyEvaluator for Unreachable {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        Err(PolicyError::CouldNotAnswer(Unanswered::Unreachable))
    }
}

/// One request, owned, so a case can change one input and leave the rest.
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
    /// An agent acting for itself: one principal is both subject and actor.
    fn autonomous(requested: AuthorityScope) -> Self {
        let own = proof(agent_principal(), wide_scope(), "2026-01-05T18:00:00Z");
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

    /// An agent acting for a user under an explicit delegation.
    fn delegated(requested: AuthorityScope) -> Self {
        Self {
            context: context(user(), Some(agent_principal()), Some(delegation_id())),
            subject: proof(user(), wide_scope(), "2026-01-05T18:00:00Z"),
            actor: proof(agent_principal(), wide_scope(), "2026-01-05T17:00:00Z"),
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
        .map(|action| action.as_str().to_owned())
        .collect()
}

fn resource_set(scope: &AuthorityScope) -> BTreeSet<ResourceId> {
    scope
        .resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect()
}

#[track_caller]
fn assert_refused(decision: &AuthorityDecision, clause: AuthorityClause) {
    assert!(!decision.allowed, "refused on {clause:?}, got {decision:?}");
    assert_eq!(decision.clause, Some(clause), "{decision:?}");
    assert_ne!(decision.reason, DecisionReason::Allowed, "{decision:?}");
    assert!(
        decision.permitted.actions.is_empty() && decision.permitted.resources.is_empty(),
        "a refusal permits nothing: {decision:?}"
    );
    assert_eq!(
        decision.expires_at, None,
        "a refusal states no expiry: {decision:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Autonomous and delegated agents
// ---------------------------------------------------------------------------------------------

#[test]
fn an_autonomous_agent_is_permitted_the_intersection_of_its_own_authority_its_ceilings_and_the_request()
 {
    let records = Records::autonomous(vec![
        platform_ceiling(&["document.*"]),
        tenant_ceiling(&["document.read", "document.write", "admin.delete"]),
    ]);
    let mut ask = Ask::autonomous(scope(
        &[
            "document.read",
            "document.write",
            "document.share",
            "admin.delete",
        ],
        &[10, 11],
    ));
    ask.subject.authority = scope(
        &["document.read", "document.write", "admin.delete"],
        &[10, 11, 12],
    );
    ask.actor = ask.subject.clone();

    let decision = ask.evaluate(&records, &Answers::allow());

    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.reason, DecisionReason::Allowed);
    assert_eq!(decision.clause, None);
    assert_eq!(
        decision.permitted,
        scope(&["document.read", "document.write"], &[10, 11])
    );
    assert_eq!(decision.subject, agent_principal());
    assert_eq!(decision.actor, agent_principal());
}

#[test]
fn a_delegated_agent_is_permitted_the_intersection_of_subject_authority_delegation_ceilings_and_the_request()
 {
    let records = Records::delegated(
        vec![
            platform_ceiling(&["document.*", "admin.delete"]),
            tenant_ceiling(&["document.read", "document.share", "admin.delete"]),
        ],
        delegation_record(scope(
            &["document.read", "document.share", "document.write"],
            &[10, 11, 12],
        )),
    );
    let mut ask = Ask::delegated(scope(&UNIVERSE, &[10, 11, 12]));
    ask.subject.authority = scope(
        &["document.read", "document.share", "admin.delete"],
        &[10, 11],
    );

    let decision = ask.evaluate(&records, &Answers::allow());

    assert!(decision.allowed, "{decision:?}");
    assert_eq!(
        decision.permitted,
        scope(&["document.read", "document.share"], &[10, 11])
    );
    assert_eq!(
        decision.subject,
        user(),
        "the subject stays the user, never the agent"
    );
    assert_eq!(decision.actor, agent_principal());
}

// ---------------------------------------------------------------------------------------------
// Platform and tenant ceilings
// ---------------------------------------------------------------------------------------------

/// Every subset of [`UNIVERSE`], as a list in universe order.
fn subsets() -> Vec<Vec<&'static str>> {
    (0_u8..16)
        .map(|mask| {
            UNIVERSE
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, name)| *name)
                .collect()
        })
        .collect()
}

/// Property, exhaustive over 16^4 = 65 536 inputs: for every requested set, subject
/// authority, platform ceiling and tenant ceiling drawn from the universe, the permitted set
/// is within the platform ceiling and within the tenant ceiling, and is exactly the four-way
/// intersection — allowed when that intersection is non-empty, refused otherwise.
#[test]
fn property_the_permitted_set_is_within_both_the_platform_and_the_tenant_ceiling() {
    let all = subsets();
    let mut allowed = 0_usize;
    let mut refused = 0_usize;
    for requested in &all {
        for authority in &all {
            for platform in &all {
                for tenant in &all {
                    let records = Records::autonomous(vec![
                        platform_ceiling(platform),
                        tenant_ceiling(tenant),
                    ]);
                    let mut ask = Ask::autonomous(scope(requested, &[10]));
                    ask.subject.authority = scope(authority, &[10]);
                    ask.actor = ask.subject.clone();

                    let decision = ask.evaluate(&records, &Answers::allow());

                    let permitted = action_set(&decision.permitted);
                    let within = |bound: &[&str]| {
                        permitted
                            .iter()
                            .all(|action| bound.contains(&action.as_str()))
                    };
                    assert!(
                        within(platform),
                        "outside the platform ceiling: {decision:?}"
                    );
                    assert!(within(tenant), "outside the tenant ceiling: {decision:?}");
                    assert!(within(authority) && within(requested), "{decision:?}");

                    let expected: BTreeSet<String> = requested
                        .iter()
                        .filter(|action| {
                            authority.contains(action)
                                && platform.contains(action)
                                && tenant.contains(action)
                        })
                        .map(|action| (*action).to_owned())
                        .collect();
                    assert_eq!(permitted, expected, "not exactly the intersection");
                    if expected.is_empty() {
                        assert_refused(&decision, AuthorityClause::NothingPermitted);
                        refused += 1;
                    } else {
                        assert!(decision.allowed, "{decision:?}");
                        allowed += 1;
                    }
                }
            }
        }
    }
    assert_eq!(allowed + refused, 65_536);
    assert!(
        allowed > 0 && refused > 0,
        "the property exercised both outcomes"
    );
}

/// A deterministic generator, so the sampled property is reproducible run to run.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn actions(&mut self) -> Vec<&'static str> {
        // Each element is kept with probability 3/4, so that a meaningful share of the
        // eight-way intersections is non-empty.
        let mask = self.next() | self.next();
        UNIVERSE
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    fn resources(&mut self) -> Vec<u8> {
        // Each element is kept with probability 3/4, so that a meaningful share of the
        // eight-way intersections is non-empty.
        let mask = self.next() | self.next();
        [10_u8, 11, 12]
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, byte)| *byte)
            .collect()
    }
}

/// Property, 20 000 sampled delegated requests: the permitted set never exceeds any input
/// bound — the request, the subject's and the actor's proof authority, the delegation's
/// scope, each ceiling's admitted patterns less its denied ones, and each ceiling's scope —
/// and it is exactly their intersection, actions and resources both.
#[test]
fn property_the_permitted_set_never_exceeds_any_input_bound() {
    let mut random = SplitMix(0x5EED_A63E);
    let mut allowed = 0_usize;
    for _ in 0..20_000 {
        let requested = scope(&random.actions(), &random.resources());
        let subject = scope(&random.actions(), &random.resources());
        let actor = scope(&random.actions(), &random.resources());
        let delegated = scope(&random.actions(), &random.resources());
        let mut platform = platform_ceiling(&random.actions());
        platform.denied_actions = patterns(&random.actions());
        platform.scope = scope(&random.actions(), &random.resources());
        let mut tenant = tenant_ceiling(&random.actions());
        tenant.scope = scope(&random.actions(), &random.resources());

        let records = Records::delegated(
            vec![platform.clone(), tenant.clone()],
            delegation_record(delegated.clone()),
        );
        let mut ask = Ask::delegated(requested.clone());
        ask.subject.authority = subject.clone();
        ask.actor.authority = actor.clone();

        let decision = ask.evaluate(&records, &Answers::allow());

        let admitted = |ceiling: &AgentCapabilityCeiling, action: &str| {
            ceiling
                .allowed_actions
                .iter()
                .any(|pattern| pattern.as_str() == action)
                && !ceiling
                    .denied_actions
                    .iter()
                    .any(|pattern| pattern.as_str() == action)
                && ceiling
                    .scope
                    .actions
                    .iter()
                    .any(|named| named.as_str() == action)
        };
        let expected_actions: BTreeSet<String> = action_set(&requested)
            .into_iter()
            .filter(|action| {
                action_set(&subject).contains(action)
                    && action_set(&actor).contains(action)
                    && action_set(&delegated).contains(action)
                    && admitted(&platform, action)
                    && admitted(&tenant, action)
            })
            .collect();
        let expected_resources: BTreeSet<ResourceId> = resource_set(&requested)
            .into_iter()
            .filter(|id| {
                [&subject, &actor, &delegated, &platform.scope, &tenant.scope]
                    .iter()
                    .all(|bound| resource_set(bound).contains(id))
            })
            .collect();

        for bound in [
            &requested,
            &subject,
            &actor,
            &delegated,
            &platform.scope,
            &tenant.scope,
        ] {
            assert!(
                action_set(&decision.permitted).is_subset(&action_set(bound)),
                "{decision:?}"
            );
            assert!(
                resource_set(&decision.permitted).is_subset(&resource_set(bound)),
                "{decision:?}"
            );
        }
        if expected_actions.is_empty() || expected_resources.is_empty() {
            assert_refused(&decision, AuthorityClause::NothingPermitted);
        } else {
            assert!(decision.allowed, "{decision:?}");
            assert_eq!(action_set(&decision.permitted), expected_actions);
            assert_eq!(resource_set(&decision.permitted), expected_resources);
            allowed += 1;
        }
    }
    assert!(
        allowed > 500,
        "the sample exercised the allowed branch: {allowed}"
    );
}

#[test]
fn two_current_ceilings_on_one_key_deny_with_the_declared_clause_and_neither_is_picked() {
    // Both ceilings would admit the request on their own; one admits more than the other.
    // Picking either would be an allow, so an allow here is a choice the evaluator made.
    let wide = ceiling(40, Some(organization()), &["document.*"], &[]);
    let narrow = ceiling(41, Some(organization()), &["document.read"], &[]);
    for records in [
        vec![wide.clone(), narrow.clone()],
        vec![narrow.clone(), wide.clone()],
    ] {
        let mut with_platform = records.clone();
        with_platform.push(platform_ceiling(&["document.*"]));
        let decision = Ask::autonomous(scope(&["document.read"], &[10]))
            .evaluate(&Records::autonomous(with_platform), &Answers::allow());
        assert_refused(&decision, AuthorityClause::CeilingConflict);
        assert_eq!(decision.reason, DecisionReason::Denied);
    }

    // The same holds on the platform key.
    let decision = Ask::autonomous(scope(&["document.read"], &[10])).evaluate(
        &Records::autonomous(vec![
            ceiling(42, None, &["document.*"], &[]),
            ceiling(43, None, &["document.*"], &[]),
        ]),
        &Answers::allow(),
    );
    assert_refused(&decision, AuthorityClause::CeilingConflict);

    // The read reports the key and both records, and offers neither as current.
    let records = vec![
        wide.clone(),
        narrow.clone(),
        platform_ceiling(&["document.*"]),
    ];
    let read = current_ceilings(&records, &agent_principal(), &organization());
    assert_eq!(read.conflicts.len(), 1);
    assert_eq!(
        read.conflicts[0].key,
        CeilingKey {
            agent_id: agent_principal(),
            organization_id: Some(organization()),
        }
    );
    assert_eq!(read.conflicts[0].ceilings, vec![wide.id, narrow.id]);
    assert_eq!(
        read.current.len(),
        1,
        "only the platform key holds one current ceiling"
    );
    assert_eq!(read.current[0].organization_id, None);

    assert_eq!(
        AuthorityClause::CeilingConflict.phrase(),
        "two current capability ceilings share one agent and organization-or-platform key"
    );
}

#[test]
fn a_ceiling_recorded_for_another_organization_does_not_apply() {
    // A tenant ceiling for another organization that admits nothing does not narrow a
    // request made in this one.
    let elsewhere = ceiling(50, Some(other_organization()), &[], &["document.*"]);
    let records = Records::autonomous(vec![
        platform_ceiling(&["document.*"]),
        tenant_ceiling(&["document.read", "document.write"]),
        elsewhere.clone(),
    ]);
    let decision = Ask::autonomous(scope(&["document.read", "document.write"], &[10]))
        .evaluate(&records, &Answers::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(action_set(&decision.permitted).len(), 2);

    // Nor does one that would admit more: it is not this organization's ceiling, so it is
    // not evidence of one either.
    let generous = ceiling(51, Some(other_organization()), &["document.*"], &[]);
    let decision = Ask::autonomous(scope(&["document.read"], &[10])).evaluate(
        &Records::autonomous(vec![generous.clone()]),
        &Answers::allow(),
    );
    assert_refused(&decision, AuthorityClause::CeilingAbsent);

    let records = [elsewhere, generous];
    let read = current_ceilings(&records, &agent_principal(), &organization());
    assert!(
        read.current.is_empty() && read.conflicts.is_empty(),
        "{read:?}"
    );
}

#[test]
fn the_current_ceiling_for_a_key_is_the_latest_recorded_and_an_earlier_one_is_superseded() {
    let mut earlier = ceiling(60, Some(organization()), &["document.*"], &[]);
    earlier.state = CeilingState::Superseded;
    let later = ceiling(61, Some(organization()), &["document.read"], &[]);
    let records = Records::autonomous(vec![
        platform_ceiling(&["document.*"]),
        earlier.clone(),
        later.clone(),
    ]);

    let decision = Ask::autonomous(scope(&["document.read", "document.write"], &[10]))
        .evaluate(&records, &Answers::allow());

    assert!(decision.allowed, "{decision:?}");
    assert_eq!(
        decision.permitted.actions,
        actions(&["document.read"]),
        "the later ceiling bounds; the superseded one admits nothing further"
    );

    let ceilings = [earlier, later.clone()];
    let read = current_ceilings(&ceilings, &agent_principal(), &organization());
    assert_eq!(read.current, vec![&later]);
    assert!(read.conflicts.is_empty());
}

// ---------------------------------------------------------------------------------------------
// Delegation, actor and organization
// ---------------------------------------------------------------------------------------------

fn delegated_records() -> Records {
    Records::delegated(
        vec![platform_ceiling(&["document.*"])],
        delegation_record(scope(&["document.read"], &[10])),
    )
}

#[test]
fn an_expired_delegation_denies() {
    let mut records = delegated_records();
    records.delegations[0].expires_at = Timestamp::new("2026-01-05T09:00:00Z");
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::DelegationExpired);

    let mut records = delegated_records();
    records.delegations[0].not_before = Some(Timestamp::new("2026-01-05T09:00:01Z"));
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::DelegationNotYetInForce);
}

#[test]
fn a_revoked_delegation_denies() {
    let mut records = delegated_records();
    records.delegations[0].state = DelegationState::Revoked;
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::DelegationRevoked);
}

#[test]
fn a_delegation_naming_another_delegator_delegate_audience_or_execution_denies() {
    let cases: [fn(&mut Delegation); 4] = [
        |delegation| delegation.delegator = PrincipalId::new(uuid(4)),
        |delegation| delegation.delegate = PrincipalId::new(uuid(5)),
        |delegation| delegation.audience = Audience::new("api-b"),
        |delegation| delegation.execution_binding = Some(ExecutionId::new(uuid(6))),
    ];
    for change in cases {
        let mut records = delegated_records();
        change(&mut records.delegations[0]);
        let decision =
            Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
        assert_refused(&decision, AuthorityClause::DelegationMismatch);
    }
}

#[test]
fn a_disabled_actor_denies() {
    let mut records = delegated_records();
    records.standings = vec![
        (user(), PrincipalStanding::Active),
        (agent_principal(), PrincipalStanding::Disabled),
    ];
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::ActorDisabled);

    let mut records = delegated_records();
    records.agents[0].state = AgentState::Retired;
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::AgentRetired);

    // A disabled subject is not rescued by an active actor.
    let mut records = delegated_records();
    records.standings = vec![
        (user(), PrincipalStanding::Disabled),
        (agent_principal(), PrincipalStanding::Active),
    ];
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::SubjectInvalid);
}

#[test]
fn a_mismatched_organization_denies() {
    let requested = scope(&["document.read"], &[10]);

    let mut ask = Ask::delegated(requested.clone());
    ask.actor.organization = other_organization();
    let decision = ask.evaluate(&delegated_records(), &Answers::allow());
    assert_refused(&decision, AuthorityClause::OrganizationMismatch);
    assert_eq!(decision.reason, DecisionReason::TenantMismatch);

    let mut ask = Ask::delegated(requested.clone());
    ask.subject.organization = other_organization();
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::OrganizationMismatch,
    );

    let mut records = delegated_records();
    records.delegations[0].organization_id = other_organization();
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::OrganizationMismatch,
    );

    let mut records = delegated_records();
    records.agents[0].organization_id = other_organization();
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::OrganizationMismatch,
    );

    let mut ask = Ask::delegated(requested);
    ask.context.organization = other_organization();
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::OrganizationMismatch,
    );
}

#[test]
fn a_context_that_does_not_name_the_proven_subject_actor_or_delegation_denies() {
    let requested = scope(&["document.read"], &[10]);
    let changes: [fn(&mut VerifiedContext); 4] = [
        |context| context.subject = PrincipalId::new(uuid(4)),
        |context| context.actor = None,
        |context| context.actor = Some(PrincipalId::new(uuid(5))),
        |context| context.delegation = None,
    ];
    for change in changes {
        let mut ask = Ask::delegated(requested.clone());
        change(&mut ask.context);
        assert_refused(
            &ask.evaluate(&delegated_records(), &Answers::allow()),
            AuthorityClause::ContextMismatch,
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Subject and actor are preserved; expiry is the minimum
// ---------------------------------------------------------------------------------------------

#[test]
fn evaluation_leaves_the_subject_and_the_actor_unchanged() {
    for (ask, records) in [
        (
            Ask::delegated(scope(&["document.read"], &[10])),
            delegated_records(),
        ),
        (
            Ask::autonomous(scope(&["document.read"], &[10])),
            Records::autonomous(vec![platform_ceiling(&["document.*"])]),
        ),
    ] {
        let before = ask.clone();
        let decision = ask.evaluate(&records, &Answers::allow());
        assert!(decision.allowed, "{decision:?}");
        assert_eq!(ask.subject, before.subject);
        assert_eq!(ask.actor, before.actor);
        assert_eq!(ask.context, before.context);
        assert_eq!(decision.subject, before.subject.principal);
        assert_eq!(decision.actor, before.actor.principal);
    }

    // On a refusal as well: the decision names who asked, and never swaps them.
    let mut records = delegated_records();
    records.delegations[0].state = DelegationState::Revoked;
    let ask = Ask::delegated(scope(&["document.read"], &[10]));
    let decision = ask.evaluate(&records, &Answers::allow());
    assert!(!decision.allowed);
    assert_eq!(
        (decision.subject, decision.actor),
        (user(), agent_principal())
    );
}

#[test]
fn the_permitted_expiry_is_the_minimum_across_the_inputs() {
    // subject proof, actor proof, delegation: each in turn is the earliest.
    let instants = [
        (
            "2026-01-05T12:00:00Z",
            "2026-01-05T15:00:00Z",
            "2026-01-05T16:00:00Z",
            "2026-01-05T12:00:00Z",
        ),
        (
            "2026-01-05T15:00:00Z",
            "2026-01-05T12:00:00Z",
            "2026-01-05T16:00:00Z",
            "2026-01-05T12:00:00Z",
        ),
        (
            "2026-01-05T15:00:00Z",
            "2026-01-05T16:00:00Z",
            "2026-01-05T12:00:00Z",
            "2026-01-05T12:00:00Z",
        ),
        // Byte order is not time order: ".5Z" sorts before "Z" and names a later instant;
        // "+02:00" names an instant two hours before the same wall clock in UTC.
        (
            "2026-01-05T12:00:00.5Z",
            "2026-01-05T12:00:00Z",
            "2026-01-05T16:00:00Z",
            "2026-01-05T12:00:00Z",
        ),
        (
            "2026-01-05T13:00:00+02:00",
            "2026-01-05T12:00:00Z",
            "2026-01-05T16:00:00Z",
            "2026-01-05T13:00:00+02:00",
        ),
    ];
    for (subject, actor, delegation, earliest) in instants {
        let mut records = delegated_records();
        records.delegations[0].expires_at = Timestamp::new(delegation);
        let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
        ask.subject.expires_at = Timestamp::new(subject);
        ask.actor.expires_at = Timestamp::new(actor);

        let decision = ask.evaluate(&records, &Answers::allow());

        assert!(decision.allowed, "{decision:?}");
        assert_eq!(
            decision.expires_at,
            Some(Timestamp::new(earliest)),
            "{subject} {actor} {delegation}"
        );
    }

    // An input already expired at the evaluation instant permits nothing.
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.actor.expires_at = Timestamp::new("2026-01-05T08:59:59Z");
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::ProofExpired,
    );

    // A timestamp that names no instant cannot be bounded and is refused.
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.subject.expires_at = Timestamp::new("tomorrow");
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::ProofUnreadable,
    );
}

// ---------------------------------------------------------------------------------------------
// Evidence, chains and approval
// ---------------------------------------------------------------------------------------------

#[test]
fn absent_required_evidence_denies() {
    let requested = scope(&["document.read"], &[10]);

    // No agent record: the actor is no agent.
    let mut records = delegated_records();
    records.agents.clear();
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::ActorNotAgent,
    );

    // No principal record for the actor.
    let mut records = delegated_records();
    records
        .standings
        .retain(|(principal, _)| *principal != agent_principal());
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::ActorNotAgent,
    );

    // No principal record for the subject.
    let mut records = delegated_records();
    records
        .standings
        .retain(|(principal, _)| *principal != user());
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::SubjectInvalid,
    );

    // No current ceiling: an empty intersection of ceilings would bound nothing.
    let mut records = delegated_records();
    records.ceilings.clear();
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::CeilingAbsent,
    );
    let mut records = delegated_records();
    records.ceilings[0].state = CeilingState::Superseded;
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::CeilingAbsent,
    );

    // No delegation record for the named delegation.
    let mut records = delegated_records();
    records.delegations.clear();
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::DelegationAbsent,
    );

    // A delegated request that names no delegation at all.
    let mut ask = Ask::delegated(requested.clone());
    ask.delegation = None;
    ask.context.delegation = None;
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::DelegationAbsent,
    );

    // A port that cannot answer is no evidence, and no allow.
    let mut records = delegated_records();
    records.unavailable = true;
    let decision = Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow());
    assert_refused(&decision, AuthorityClause::Unavailable);
    assert_eq!(decision.reason, DecisionReason::Unavailable);

    let decision = Ask::delegated(requested).evaluate(&delegated_records(), &Unreachable);
    assert_refused(&decision, AuthorityClause::Unavailable);
    assert_eq!(decision.reason, DecisionReason::Unavailable);
}

#[test]
fn a_transitive_delegation_chain_denies() {
    let requested = scope(&["document.read"], &[10]);

    // A delegation recorded as transitive, which the entity invariant never admits.
    let mut records = delegated_records();
    records.delegations[0].transitive = true;
    assert_refused(
        &Ask::delegated(requested.clone()).evaluate(&records, &Answers::allow()),
        AuthorityClause::TransitiveChain,
    );

    // A subject proof that was itself issued through an actor or a delegation: the agent
    // would be acting on authority that was already delegated once.
    let mut ask = Ask::delegated(requested.clone());
    ask.subject.actor = Some(PrincipalId::new(uuid(4)));
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::TransitiveChain,
    );
    let mut ask = Ask::delegated(requested.clone());
    ask.subject.delegation = Some(DelegationId::new(uuid(21)));
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::TransitiveChain,
    );

    // An actor proof that was itself issued through another actor.
    let mut ask = Ask::delegated(requested);
    ask.actor.actor = Some(PrincipalId::new(uuid(4)));
    assert_refused(
        &ask.evaluate(&delegated_records(), &Answers::allow()),
        AuthorityClause::TransitiveChain,
    );
}

#[test]
fn approval_required_yields_allowed_false() {
    let policy = Answers::with(PolicyEffect::ApprovalRequired);
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&delegated_records(), &policy);

    assert!(!decision.allowed, "{decision:?}");
    assert_eq!(decision.reason, DecisionReason::ApprovalRequired);
    assert_eq!(decision.clause, Some(AuthorityClause::ApprovalRequired));
    assert!(decision.permitted.actions.is_empty() && decision.permitted.resources.is_empty());
    assert_eq!(decision.expires_at, None);
    assert_eq!(
        decision.challenges.len(),
        1,
        "the challenge the caller must satisfy is carried"
    );
    assert!(policy.asked.get() > 0);

    // A denial anywhere beats an approval requirement.
    let decision = Ask::delegated(scope(&["document.read"], &[10]))
        .evaluate(&delegated_records(), &Answers::with(PolicyEffect::Deny));
    assert_refused(&decision, AuthorityClause::PolicyDenied);
    let mut records = delegated_records();
    records.delegations[0].state = DelegationState::Revoked;
    let decision = Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &policy);
    assert_refused(&decision, AuthorityClause::DelegationRevoked);
}

/// A policy that refuses every pair with one declared reason.
struct Refuses(DenialReason);

impl PolicyEvaluator for Refuses {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        Err(PolicyError::Denied(self.0))
    }
}

/// A policy refusal keeps the reason policy declared, for every reason the contract can
/// carry, the way `check` keeps it: an approval requirement named as a refusal is answered
/// as the approval it is, with the challenge that clears it; an inability to decide is
/// `Unavailable`; every other reason reaches the caller unchanged.
#[test]
fn a_policy_refusal_reports_the_reason_policy_declared_for_every_reason() {
    for reason in DenialReason::VARIANTS {
        let decision = Ask::delegated(scope(&["document.read"], &[10]))
            .evaluate(&delegated_records(), &Refuses(*reason));
        let (expected, clause) = match reason {
            DenialReason::Denied => (DecisionReason::Denied, AuthorityClause::PolicyDenied),
            DenialReason::ApprovalRequired => (
                DecisionReason::ApprovalRequired,
                AuthorityClause::ApprovalRequired,
            ),
            DenialReason::InvalidCredential => (
                DecisionReason::InvalidCredential,
                AuthorityClause::PolicyDenied,
            ),
            DenialReason::TenantMismatch => (
                DecisionReason::TenantMismatch,
                AuthorityClause::PolicyDenied,
            ),
            DenialReason::AudienceMismatch => (
                DecisionReason::AudienceMismatch,
                AuthorityClause::PolicyDenied,
            ),
            DenialReason::Unavailable => {
                (DecisionReason::Unavailable, AuthorityClause::Unavailable)
            }
            DenialReason::StaleEpoch => (DecisionReason::StaleEpoch, AuthorityClause::PolicyDenied),
        };
        assert!(!decision.allowed, "{reason:?}: {decision:?}");
        assert_eq!(decision.reason, expected, "{reason:?}: {decision:?}");
        assert_eq!(decision.clause, Some(clause), "{reason:?}: {decision:?}");
        assert!(
            decision.permitted.actions.is_empty() && decision.permitted.resources.is_empty(),
            "{reason:?}: {decision:?}"
        );
        assert_eq!(decision.expires_at, None, "{reason:?}: {decision:?}");
        let challenged = *reason == DenialReason::ApprovalRequired;
        assert_eq!(
            decision.challenges.len(),
            usize::from(challenged),
            "{reason:?}: an approval carries the challenge that clears it, a refusal none: \
             {decision:?}"
        );
        if challenged {
            assert_eq!(
                decision.challenges[0].requirement,
                ChallengeRequirement::Approval,
                "the strictest requirement applies when policy named none"
            );
        }
    }
}

#[test]
fn bounds_confined_to_different_spaces_permit_nothing() {
    let mut records = delegated_records();
    records.delegations[0].scope.space = Some(SpaceId::new(uuid(70)));
    let mut ask = Ask::delegated(scope(&["document.read"], &[10]));
    ask.requested.space = Some(SpaceId::new(uuid(71)));
    assert_refused(
        &ask.evaluate(&records, &Answers::allow()),
        AuthorityClause::SpaceConflict,
    );

    // One space named by one bound narrows the permitted set to it.
    let decision =
        Ask::delegated(scope(&["document.read"], &[10])).evaluate(&records, &Answers::allow());
    assert!(decision.allowed, "{decision:?}");
    assert_eq!(decision.permitted.space, Some(SpaceId::new(uuid(70))));
}

// ---------------------------------------------------------------------------------------------
// Every clause is a declared phrase
// ---------------------------------------------------------------------------------------------

const OBLIGATIONS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/architecture/command-obligations.md"
);

/// Every refusal the evaluator can produce is phrased by the contract: each clause names a
/// verbatim substring of `ExchangeCredential`'s declared denial, the command STS consumes the
/// evaluator from. `command-obligations.md` is read rather than the compiled model because
/// `serde_json` is outside this package's dependency ceiling, and `cargo xtask check` pins
/// that row, verbatim, to the contract's own `denied` cause.
#[test]
fn every_clause_is_a_phrase_of_the_declared_exchange_denial() {
    let table = std::fs::read_to_string(OBLIGATIONS).expect("command-obligations.md");
    let row = table
        .lines()
        .find_map(|line| line.strip_prefix("| `mandate.credential.ExchangeCredential` | "))
        .expect("the ExchangeCredential row");
    for clause in AuthorityClause::ALL {
        let phrase = clause.phrase();
        assert!(!phrase.is_empty(), "{clause:?} names no phrase");
        assert!(
            row.contains(phrase),
            "{clause:?}: {phrase:?} is not a phrase of {row:?}"
        );
    }
    assert_eq!(
        AuthorityClause::TransitiveChain.phrase(),
        "transitive delegation is requested"
    );
    assert_eq!(
        AuthorityClause::ApprovalRequired.phrase(),
        "approval is required"
    );
    assert_eq!(
        AuthorityClause::ApprovalRequired.reason(),
        DenialReason::ApprovalRequired
    );
    assert_eq!(
        AuthorityClause::OrganizationMismatch.reason(),
        DenialReason::TenantMismatch
    );
    assert_eq!(
        AuthorityClause::Unavailable.reason(),
        DenialReason::Unavailable
    );
}
