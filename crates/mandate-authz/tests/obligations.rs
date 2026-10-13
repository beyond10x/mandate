//! The `mandate.authorization.Check` denial conditions that `contracts/obligations/authz.json`
//! binds to a real-path test of this crate and that no test already here decides.
//!
//! Both cases drive [`mandate_authz::check`] — the decision point a PEP calls — rather than
//! [`mandate_authz::evaluate::evaluate`], so what the row claims is the command's own path and
//! not the fold underneath it. Each is written as a pair: the same world allowed, and then the
//! one thing the clause names changed, so the refusal is attributable to that and not to an
//! absent grant, an unbound context or a policy that refuses.
//!
//! * `ceilings deny` — the subject is an agent acting for itself, and its ceiling recorded for
//!   the verified organization does not admit the action the grant carries. Ceilings are an
//!   agent's, keyed by `(agent_id, organization_id)`, and [`mandate_authz::check`] reads them
//!   through [`mandate_authz::agent::AgentAuthorityRead`]; the case measures that the
//!   organization decides, by refusing under this organization's ceiling and allowing under a
//!   deny-everything ceiling recorded for another. That a member who is no agent is bounded by
//!   no agent's ceiling is `adversary_obligations_authz_1`'s, and the delegated case is
//!   `tests/agent_security.rs`'s.
//! * `graph` — the graph reader has not applied the revision the request requires, so it
//!   answers nothing at all. `mandate_graph::port::GraphError::CouldNotAnswer` reaches the
//!   fold as [`mandate_types::DenialReason::Unavailable`]
//!   (`crates/mandate-authz/src/evaluate.rs:273`), which is the graph half of the declared
//!   cause's `the required PDP/graph/credential authority is unavailable`. The two rows that
//!   clause carried before this correction both took the policy port down instead.
//!
//! The corpus's other `mandate.authorization.Check` cases are decided by tests that already
//! exist, and the registry names those rather than restating them here: `approval-required` by
//! `tests/adversary_check.rs` and `tests/adversary_check_2.rs`, `pdp-outage` by
//! `check_contract::a_decision_point_that_cannot_answer_denies_and_invents_no_permission`.
//!
//! Two clauses of the same command carry no row of this file and none of any other, and the
//! document has no place for the ground, so it is here:
//!
//! * `space binding mismatches` defers to `story:declared-writers`.
//!   `crates/mandate-model/src/graph.rs:250` writes `space_id: None` as a literal and is the
//!   only place a `mandate.graph.Resource` is constructed, so the projection
//!   `crates/mandate-authz/src/context.rs:135-137` reads answers `None` for every resource
//!   that has ever been folded and `:138` refuses every request whose scope names a space,
//!   whatever the tenancy, the space and the resource are. A clause whose guard no input can
//!   reach is not decided by a test that asserts the refusal, and the gap is a declared
//!   element with no writer, which is that story's subject.
//! * `Credential-derived context is invalid` defers to `decision-blocker:guards`, beside the
//!   `revoked`, `expired` and `stale` conditions of the same slash-list.
//!   `mandate_types::VerifiedContext::credential` is read at no point in
//!   `crates/mandate-authz/src`, so no value of it changes what `bind` answers; the refusal
//!   `context::an_organization_that_admits_no_authority_refuses_the_context` drives is
//!   `Tenancy::admits(context.organization)`, decided from the field the sibling clause
//!   `tenant` is bound through. Publishing one refusal as two conditions counts it twice.

use mandate_authz::agent::AgentRecords;
use mandate_authz::decision::{Denied, FixedChallenge, SequentialDecisionIds};
use mandate_authz::delegation::{Agent, AgentCapabilityCeiling, AgentState, CeilingState};
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
    AuthorizationModelId, AuthzRevision, CorrelationId, CredentialId, DecisionReason, DenialReason,
    Duration, GrantId, OrganizationId, OrganizationMembershipId, PolicyId, PolicyVersion,
    PrincipalId, ResourceId, ResourceRef, ResourceType, Timestamp, Uuid, VerifiedContext,
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

/// The verified context: `actor` absent, so the request is direct and
/// [`mandate_authz::context::direct`] does not refuse it before a port is read.
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
        .create_organization(&context(), organization(), "acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            &context(),
            MembershipAuthority::VerifiedOrganization,
            OrganizationMembershipId::new(uuid(3)),
            organization(),
            principal(),
        )
        .expect("the subject is a member");
    tenancy
}

/// The grant: the `operator` role over the requested action and resource, held with no
/// expiry, and the revision the reader reached by recording it.
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

/// Policy allows the action and the catalog says `operator` carries it, so nothing but the
/// condition each case names can refuse the request.
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
    policy.record_role(organization(), "operator", vec![action()]);
    policy.allow(organization(), subject(), action(), resource());
    policy
}

/// One capability ceiling of the subject, which is an agent acting for itself: ceilings are
/// keyed by `(agent_id, organization_id)` (`systems/mandate/domains/delegation.yaml:5-6`) and
/// read through the agent port.
fn ceiling(
    byte: u8,
    organization_id: Option<OrganizationId>,
    allowed: &[&str],
    denied: &[&str],
) -> AgentCapabilityCeiling {
    AgentCapabilityCeiling {
        id: AgentCapabilityCeilingId::new(uuid(byte)),
        agent_id: principal(),
        organization_id,
        allowed_actions: allowed
            .iter()
            .map(|name| ActionPattern::new(*name))
            .collect(),
        denied_actions: denied
            .iter()
            .map(|name| ActionPattern::new(*name))
            .collect(),
        scope: AuthorityScope {
            actions: vec![action()],
            resources: vec![resource()],
            space: None,
        },
        max_delegation_ttl: Duration::new("PT1H"),
        state: CeilingState::Recorded,
    }
}

/// The agent's platform ceiling (`organization_id` absent,
/// `systems/mandate/domains/delegation.yaml:5`): applies in every organization and admits the
/// action.
fn permissive() -> AgentCapabilityCeiling {
    ceiling(60, None, &["deployment.*"], &[])
}

/// The agent's ceiling recorded for this organization, not admitting the action the grant
/// carries.
fn organization_ceiling() -> AgentCapabilityCeiling {
    ceiling(
        61,
        Some(organization()),
        &["deployment.*"],
        &["deployment.restart"],
    )
}

/// The agent's ceiling recorded for another organization, admitting nothing and denying
/// everything. Nothing but its `organization_id` separates it from a ceiling that would refuse
/// the request outright, so what it measures is
/// [`mandate_authz::delegation::AgentCapabilityCeiling::applies`].
fn another_organizations_ceiling() -> AgentCapabilityCeiling {
    ceiling(62, Some(OrganizationId::new(uuid(9))), &[], &["*"])
}

/// One `mandate.authorization.Check` of the agent acting for itself, against a reader
/// required to have reached `minimum` and bounded by the agent's `ceilings`.
fn check_under(
    minimum: &AuthzRevision,
    ceilings: &[AgentCapabilityCeiling],
) -> Result<Decision, Denied> {
    let (graph, _) = graph();
    let policy = policy();
    let tenancy = tenancy();
    let topology = Topology::new();
    let issuer = FixedChallenge {
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        approver_policy: Some(PolicyId::new(uuid(40))),
    };
    let agents = AgentRecords {
        agents: vec![Agent {
            id: principal(),
            organization_id: organization(),
            agent_type: "assistant".to_owned(),
            state: AgentState::Recorded,
        }],
        ceilings: ceilings.to_vec(),
        ..AgentRecords::new()
    };
    let pdp = Pdp {
        graph: &graph,
        policy: &policy,
        catalog: &policy,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
        agents: &agents,
    };

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context: &context(),
            action: &action(),
            resource: &resource(),
            expected_audience: &Audience::new("mandate"),
            relation: "operator",
            minimum,
            attributes: &AttributeSet::new(),
            scope: None,
            at: &Timestamp::new("2026-09-17T00:00:00Z"),
        },
    )
}

/// The revision the reader reached, which every request but the outage case requires.
fn reached() -> AuthzRevision {
    graph().1
}

/// `ceilings deny`, through the command's own entry point: a ceiling recorded for the
/// verified organization refuses an action the grant, the catalog and policy all carry.
///
/// The control is the same world under a ceiling that admits the action: it is allowed, so
/// the refusal below is the second ceiling's and not an absent grant, an unbound context or a
/// policy that refuses. Every applicable ceiling intersects (`delegation.yaml:5`), so the
/// permissive one admitting the action does not recover it.
///
/// The second control is what makes the ceiling's `organization` decide rather than ride
/// along: the same request under a ceiling that admits nothing and denies everything,
/// recorded for another organization, is allowed — so the refusal below is attributable to
/// the ceiling having been recorded for *this* organization and not merely to a ceiling
/// existing. `mandate_authz::delegation::AgentCapabilityCeiling::applies` reads that field, and
/// this case drives it at the `check` entry point.
#[test]
fn a_ceiling_recorded_for_the_organization_refuses_an_action_the_grant_carries() {
    let inside =
        check_under(&reached(), &[permissive()]).expect("a ceiling admitting the action allows");
    assert!(inside.allowed);
    assert_eq!(inside.reason, DecisionReason::Allowed);

    let elsewhere = check_under(&reached(), &[permissive(), another_organizations_ceiling()])
        .expect("a ceiling recorded for another organization bounds no request of this one");
    assert!(elsewhere.allowed);
    assert_eq!(elsewhere.reason, DecisionReason::Allowed);

    let refusal = check_under(&reached(), &[permissive(), organization_ceiling()])
        .expect_err("the organization's ceiling does not admit the action");

    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.reason, DenialReason::Denied);
    assert_eq!(refusal.decision.reason, DecisionReason::Denied);
    assert_eq!(
        refusal.decision.challenge, None,
        "a ceiling refusal is not something the caller can answer"
    );
}

/// The `graph` half of `the required PDP/graph/credential authority is unavailable`, through
/// the command's own entry point: a graph reader that has not applied the revision the request
/// requires answers nothing, and nothing is told as an outage rather than as a decision about
/// the caller.
///
/// The control is the same world at the revision the reader reached: it is allowed, so the
/// refusal below is the revision floor's alone. The reason is what separates this from every
/// other row of the clause — a denial would claim the graph decided against the caller, which
/// it did not.
#[test]
fn a_graph_that_has_not_reached_the_required_revision_is_unavailable_and_not_a_denial() {
    let answered =
        check_under(&reached(), &[permissive()]).expect("the reader has applied the revision");
    assert!(answered.allowed);
    assert_eq!(answered.reason, DecisionReason::Allowed);

    let refusal = check_under(&AuthzRevision::new("never-issued"), &[permissive()])
        .expect_err("a reader below the required revision answers nothing");

    assert!(!refusal.decision.allowed);
    assert_eq!(
        refusal.reason,
        DenialReason::Unavailable,
        "an unanswerable graph is an outage, not a decision that the caller lacks authority"
    );
    assert_eq!(refusal.decision.reason, DecisionReason::Unavailable);
    assert_eq!(
        refusal.decision.revision, None,
        "no revision was observed, so the decision claims none"
    );
}
