//! `mandate.authorization.Check`, end to end: the acceptance of `story:check-api`.
//!
//! > Given a protected request missing a required approval, when the PEP asks the PDP,
//! > then it receives allowed=false with a structured scoped challenge and decision
//! > identifier.
//!
//! Corpus cases (`tests/security/cases.json`): `approval-required` (`:553`) and
//! `pdp-outage` (`:602`). Both are `mandate.authorization.Check` cases, and `pdp-outage` is
//! the one case in the corpus carrying `story: story:check-api`.

use std::cell::RefCell;

use mandate_authz::decision::{
    ChallengeIssuer, DecisionIdAllocator, Denied, FixedChallenge, SequentialDecisionIds,
};
use mandate_authz::evaluate::Ceiling;
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, Observed};
use mandate_graph::record::Grant;
use mandate_graph::revocation::RevisionView;
use mandate_graph::topology::{Placement, ResourceLookup, ResourceRegistry};
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{AttributeSet, ChallengeRequirement};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ActionPattern, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId,
    AuthzRevision, CorrelationId, CredentialId, DecisionReason, DenialReason, GrantId,
    OrganizationId, OrganizationMembershipId, PolicyId, PolicyVersion, PrincipalId, ResourceId,
    ResourceRef, ResourceType, SpaceId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(principal())
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

fn action() -> Action {
    Action::new("deployment.restart")
}

fn approver() -> PolicyId {
    PolicyId::new(uuid(40))
}

fn deadline() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(organization(), "acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            OrganizationMembershipId::new(uuid(3)),
            organization(),
            principal(),
        )
        .expect("the subject is a member");
    tenancy
}

/// A graph in which the subject holds the `operator` role on the resource.
fn graph() -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    let revision = graph.record_grant(Grant::recorded(
        GrantId::new(uuid(30)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![action()],
            resources: vec![resource()],
            space: None,
        },
        "operator",
    ));
    (graph, revision)
}

/// A policy that can answer and a catalog that knows the role.
fn policy() -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_policy(Policy::recorded(
        approver(),
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
    policy.record_role(organization(), "operator", vec![action()]);
    policy
}

fn issuer() -> FixedChallenge {
    FixedChallenge {
        expires_at: deadline(),
        approver_policy: Some(approver()),
    }
}

fn request<'a>(
    context: &'a VerifiedContext,
    action: &'a Action,
    resource: &'a ResourceRef,
    audience: &'a Audience,
    minimum: &'a AuthzRevision,
    attributes: &'a AttributeSet,
    ceilings: &'a [Ceiling],
) -> CheckRequest<'a> {
    CheckRequest {
        context,
        action,
        resource,
        expected_audience: audience,
        relation: "operator",
        minimum,
        attributes,
        scope: None,
        ceilings,
    }
}

/// The acceptance: a protected request missing a required approval.
#[test]
fn a_request_missing_a_required_approval_is_allowed_false_with_a_scoped_challenge() {
    let context = context();
    let action = action();
    let resource = resource();
    let audience = Audience::new("mandate");
    let attributes = AttributeSet::new();
    let (graph, revision) = graph();
    let mut policy = policy();
    policy.require_approval(
        organization(),
        subject(),
        action.clone(),
        resource.clone(),
        ChallengeRequirement::Approval,
    );
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };
    let mut allocator = SequentialDecisionIds::new();

    let refusal = check(
        &pdp,
        &mut allocator,
        &request(
            &context,
            &action,
            &resource,
            &audience,
            &revision,
            &attributes,
            &[],
        ),
    )
    .expect_err("an approval requirement is not an allow");

    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.reason, DenialReason::ApprovalRequired);
    assert_eq!(refusal.decision.reason, DecisionReason::ApprovalRequired);
    let challenge = refusal
        .decision
        .challenge
        .clone()
        .expect("the refusal carries a structured challenge");
    assert_eq!(
        challenge.action, action,
        "the challenge is scoped to the action asked about"
    );
    assert_eq!(
        challenge.resource, resource,
        "the challenge is scoped to the resource asked about"
    );
    assert_eq!(challenge.approver_policy, approver());
    assert_eq!(challenge.expires_at, deadline());
    assert_eq!(
        refusal.decision.decision_id,
        SequentialDecisionIds::new().next_decision_id(),
        "the decision is identified"
    );
    assert_eq!(
        refusal.decision.policy_version,
        Some(PolicyVersion::new("v1"))
    );
    assert_eq!(refusal.decision.revision, Some(revision));
    assert_eq!(refusal.decision.model_version, None);
}

/// `pdp-outage`: the required decision point cannot answer. The graph's authority is not
/// promoted into a decision nobody made.
#[test]
fn a_decision_point_that_cannot_answer_denies_and_invents_no_permission() {
    let context = context();
    let action = action();
    let resource = resource();
    let audience = Audience::new("mandate");
    let attributes = AttributeSet::new();
    let (graph, revision) = graph();
    let catalog = policy();
    let unreachable = PolicyDouble::new();
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &unreachable,
        catalog: &catalog,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    let refusal = check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &request(
            &context,
            &action,
            &resource,
            &audience,
            &revision,
            &attributes,
            &[],
        ),
    )
    .expect_err("an unavailable decision point denies");

    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.reason, DenialReason::Unavailable);
    assert_eq!(refusal.decision.reason, DecisionReason::Unavailable);
    assert_eq!(refusal.decision.challenge, None);
    assert_eq!(refusal.decision.policy_version, None);
    assert_eq!(
        refusal.decision.decision_id,
        SequentialDecisionIds::new().next_decision_id(),
        "an outage is still a decision, and it is identified"
    );
}

#[test]
fn an_allowed_request_returns_the_decision_the_command_declares_as_its_response() {
    let context = context();
    let action = action();
    let resource = resource();
    let audience = Audience::new("mandate");
    let attributes = AttributeSet::new();
    let (graph, revision) = graph();
    let mut policy = policy();
    policy.allow(organization(), subject(), action.clone(), resource.clone());
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };
    let ceilings = vec![Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: Vec::new(),
    }];

    let decision = check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &request(
            &context,
            &action,
            &resource,
            &audience,
            &revision,
            &attributes,
            &ceilings,
        ),
    )
    .expect("the request is allowed");

    assert!(decision.allowed);
    assert_eq!(decision.reason, DecisionReason::Allowed);
    assert_eq!(decision.revision, Some(revision));
    assert_eq!(decision.policy_version, Some(PolicyVersion::new("v1")));
    assert_eq!(decision.challenge, None);
    assert_eq!(decision.model_version, None);
}

/// A graph that refuses to be asked anything at all. A context that does not bind must
/// read no authority: asking the graph on behalf of a context that never stood is the
/// failure this refuses to let pass.
struct Untouched;

impl GraphRead for Untouched {
    type Revision = AuthzRevision;

    fn check(
        &self,
        _query: &GraphQuery<'_>,
        _minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        unreachable!("the context did not bind, so no authority may be read");
    }
}

impl ResourceLookup for Untouched {
    fn placement(
        &self,
        _organization: &OrganizationId,
        _resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        unreachable!("the context did not bind, so no resource may be read");
    }
}

#[test]
fn a_context_that_does_not_bind_reads_no_authority_and_is_still_a_decision() {
    let context = context();
    let action = action();
    let resource = resource();
    let other_api = Audience::new("other-api");
    let attributes = AttributeSet::new();
    let policy = policy();
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &Untouched,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    let refusal = check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &request(
            &context,
            &action,
            &resource,
            &other_api,
            &AuthzRevision::new("0"),
            &attributes,
            &[],
        ),
    )
    .expect_err("the credential names another audience");

    assert_eq!(refusal.reason, DenialReason::AudienceMismatch);
    assert_eq!(refusal.decision.reason, DecisionReason::AudienceMismatch);
    assert!(!refusal.decision.allowed);
    assert_eq!(
        refusal.decision.decision_id,
        SequentialDecisionIds::new().next_decision_id(),
        "a refusal that read nothing is still an identified decision"
    );
}

/// An issuer that records the context it was asked about.
struct Correlated {
    asked: RefCell<Vec<CorrelationId>>,
}

impl ChallengeIssuer for Correlated {
    fn expires_at(
        &self,
        context: &VerifiedContext,
        _requirement: ChallengeRequirement,
    ) -> Timestamp {
        self.asked.borrow_mut().push(context.correlation.clone());
        deadline()
    }

    fn approver_policy(&self, _organization: &OrganizationId) -> Option<PolicyId> {
        Some(approver())
    }
}

/// `mandate.core.Decision` declares no correlation field, and
/// `mandate.authorization.DecisionRecorded` declares `context` beside `decision`
/// (`authorization.yaml:28-33`), so the correlation the request carried is what the event
/// records. The challenge is issued under that same correlation rather than under one
/// minted for it.
#[test]
fn the_challenge_is_issued_under_the_correlation_the_request_carried() {
    let mut context = context();
    context.correlation = CorrelationId::new("request-9");
    let action = action();
    let resource = resource();
    let audience = Audience::new("mandate");
    let attributes = AttributeSet::new();
    let (graph, revision) = graph();
    let mut policy = policy();
    policy.require_approval(
        organization(),
        subject(),
        action.clone(),
        resource.clone(),
        ChallengeRequirement::Approval,
    );
    let issuer = Correlated {
        asked: RefCell::new(Vec::new()),
    };
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &request(
            &context,
            &action,
            &resource,
            &audience,
            &revision,
            &attributes,
            &[],
        ),
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(
        issuer.asked.borrow().as_slice(),
        &[CorrelationId::new("request-9")]
    );
}

/// Every outcome of one request is one decision, identified once: the allocator is asked
/// exactly once per call, whatever the answer is.
#[test]
fn one_request_mints_one_decision_identity() {
    let context = context();
    let action = action();
    let resource = resource();
    let audience = Audience::new("mandate");
    let attributes = AttributeSet::new();
    let (graph, revision) = graph();
    let mut policy = policy();
    policy.allow(organization(), subject(), action.clone(), resource.clone());
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };
    let mut allocator = SequentialDecisionIds::new();

    for _ in 0..3 {
        check(
            &pdp,
            &mut allocator,
            &request(
                &context,
                &action,
                &resource,
                &audience,
                &revision,
                &attributes,
                &[],
            ),
        )
        .expect("the request is allowed");
    }

    assert_eq!(allocator.issued(), 3);
}

/// The allowed request, as owned parts, so a case can vary exactly one of them and read
/// the reason that comes back.
struct World {
    tenancy: Tenancy,
    graph: GraphDouble,
    policy: PolicyDouble,
    catalog: PolicyDouble,
    issuer: FixedChallenge,
    topology: Topology,
    context: VerifiedContext,
    audience: Audience,
    minimum: AuthzRevision,
}

impl World {
    /// A world in which the request is allowed.
    fn new() -> Self {
        let (graph, minimum) = graph();
        let mut policy = policy();
        policy.allow(organization(), subject(), action(), resource());
        Self {
            tenancy: tenancy(),
            graph,
            policy,
            catalog: policy_catalog(),
            issuer: issuer(),
            topology: Topology::new(),
            context: context(),
            audience: Audience::new("mandate"),
            minimum,
        }
    }

    /// The same world with the grant never recorded, at a revision it has reached.
    fn without_the_grant(mut self) -> Self {
        let mut graph = GraphDouble::new();
        graph.admit_subject(organization(), subject());
        graph
            .register_resource(&context(), &resource(), None)
            .expect("the resource is registered");
        self.minimum = graph.observed();
        self.graph = graph;
        self
    }

    fn decide(&self) -> Result<Decision, Denied> {
        let pdp = Pdp {
            graph: &self.graph,
            policy: &self.policy,
            catalog: &self.catalog,
            issuer: &self.issuer,
            tenancy: &self.tenancy,
            topology: &self.topology,
        };

        check(
            &pdp,
            &mut SequentialDecisionIds::new(),
            &request(
                &self.context,
                &action(),
                &resource(),
                &self.audience,
                &self.minimum,
                &AttributeSet::new(),
                &[],
            ),
        )
    }

    fn reason(&self) -> DenialReason {
        self.decide()
            .expect_err("this world refuses the request")
            .reason
    }
}

/// The catalog half of [`policy`], without the rule that allows.
fn policy_catalog() -> PolicyDouble {
    policy()
}

/// Which reasons a real `mandate.authorization.Check` can reach today, driven end to end
/// rather than asserted of a constructed authority.
///
/// The set is compared against the contract's own variant list, so a reason declared in
/// `mandate.core.DenialReason` and produced by nothing here has to be named as such rather
/// than quietly missing: `StaleEpoch` is that reason, and it has no producer inside this
/// crate's dependency ceiling — no epoch is readable from `mandate-types`, `mandate-model`,
/// `mandate-graph` or `mandate-policy`, and `mandate.core.SecurityEpochTarget` is carried
/// by no port this crate calls. A reason added to the contract fails this test until it is
/// either produced or listed as unreachable.
#[test]
fn the_reasons_a_check_can_produce_today_are_these_six() {
    let allowed = World::new()
        .decide()
        .expect("the unvaried world allows the request");
    assert!(allowed.allowed);

    let mut produced: Vec<DenialReason> = Vec::new();

    // No grant: the graph finds no authority, and an allow from policy is not authority.
    produced.push(World::new().without_the_grant().reason());

    // Policy asks for an approval first.
    let mut approval = World::new();
    approval.policy = policy();
    approval.policy.require_approval(
        organization(),
        subject(),
        action(),
        resource(),
        ChallengeRequirement::Approval,
    );
    produced.push(approval.reason());

    // The organization the context was validated against admits nothing any more.
    let mut closed = World::new();
    closed
        .tenancy
        .close_organization(organization())
        .expect("the organization is closed");
    produced.push(closed.reason());

    // The subject is a member of no organization here.
    let mut stranger = World::new();
    stranger.tenancy = Tenancy::new();
    stranger
        .tenancy
        .create_organization(organization(), "acme")
        .expect("the organization is recorded");
    produced.push(stranger.reason());

    // The credential was issued for another audience.
    let mut elsewhere = World::new();
    elsewhere.audience = Audience::new("other-api");
    produced.push(elsewhere.reason());

    // The policy decision point cannot answer.
    let mut outage = World::new();
    outage.policy = PolicyDouble::new();
    produced.push(outage.reason());

    produced.sort_unstable_by_key(|reason| {
        DenialReason::VARIANTS
            .iter()
            .position(|declared| declared == reason)
            .expect("every reason is declared")
    });
    produced.dedup();

    let unreachable: Vec<DenialReason> = DenialReason::VARIANTS
        .iter()
        .copied()
        .filter(|declared| !produced.contains(declared))
        .collect();

    assert_eq!(
        produced,
        vec![
            DenialReason::Denied,
            DenialReason::ApprovalRequired,
            DenialReason::InvalidCredential,
            DenialReason::TenantMismatch,
            DenialReason::AudienceMismatch,
            DenialReason::Unavailable,
        ]
    );
    assert_eq!(
        unreachable,
        vec![DenialReason::StaleEpoch],
        "the only declared reason no path here produces"
    );
}

/// One `check` of the otherwise-allowed request, made under the given scope.
///
/// The scope reaches two places from one field, and each is a wiring line of its own:
/// `crates/mandate-authz/src/lib.rs:191` carries it into the `Binding` (where its `space`
/// binds) and `:206` into the `Read` (where its `actions` and `resources` are intersected).
/// The three cases below decide one each and the pair together; a wiring line replaced by
/// `None` turns its case into an allow.
fn decide_under(scope: Option<&AuthorityScope>) -> Result<Decision, Denied> {
    let context = context();
    let (graph, revision) = graph();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context: &context,
            action: &action(),
            resource: &resource(),
            expected_audience: &Audience::new("mandate"),
            relation: "operator",
            minimum: &revision,
            attributes: &AttributeSet::new(),
            scope,
            ceilings: &[],
        },
    )
}

/// The requested authority, through the entry point: a request outside the scope it was
/// made under is refused even though every port allows it.
#[test]
fn a_request_outside_the_scope_it_was_made_under_is_refused_through_check() {
    let narrowed = AuthorityScope {
        actions: vec![Action::new("deployment.read")],
        resources: vec![resource()],
        space: None,
    };

    let refusal = decide_under(Some(&narrowed))
        .expect_err("the action asked for is outside the authority the request was made under");

    assert_eq!(refusal.reason, DenialReason::Denied);
    assert!(!refusal.decision.allowed);
}

/// The scope's space, through the entry point: the same field, the other wiring line. The
/// organization holds no such space, so the request does not bind.
#[test]
fn a_request_naming_a_space_the_organization_does_not_hold_is_refused_through_check() {
    let spaced = AuthorityScope {
        actions: vec![action()],
        resources: vec![resource()],
        space: Some(SpaceId::new(uuid(60))),
    };

    let refusal = decide_under(Some(&spaced)).expect_err("no such space in this organization");

    assert_eq!(refusal.reason, DenialReason::TenantMismatch);
}

/// The positive side of both lines: a scope that covers the request allows it, and it names
/// the resource the way the graph names one — by identity, the type being a field of the
/// record and not part of what identifies it (`graph.yaml:8-11`,
/// `crates/mandate-graph/src/double.rs:182-190`). One decision applies one identity rule.
#[test]
fn a_request_inside_the_scope_it_was_made_under_is_allowed_through_check() {
    let covering = AuthorityScope {
        actions: vec![action()],
        resources: vec![ResourceRef {
            resource_type: ResourceType::new("doc"),
            resource_id: resource().resource_id,
        }],
        space: None,
    };

    let decision = decide_under(Some(&covering))
        .expect("the scope names the action and the resource the request is about");

    assert!(decision.allowed);
    assert_eq!(decision.reason, DecisionReason::Allowed);
}
