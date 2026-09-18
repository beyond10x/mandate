//! Adversary pass 1 on `story:check-api`: cases written against the documents the unit
//! cites, not against the behaviour it built.
//!
//! Every scenario below is the *same* allowed request — the subject is a member, the graph
//! holds a covering grant, policy allows, no ceiling refuses — varied in exactly one input,
//! so what each case measures is that one input's effect on the decision.

use mandate_authz::decision::{Denied, FixedChallenge, SequentialDecisionIds};
use mandate_authz::evaluate::Ceiling;
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::double::GraphDouble;
use mandate_graph::record::Grant;
use mandate_graph::topology::ResourceRegistry;
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, Evaluation, PolicyEffect, PolicyError,
    PolicyEvaluator, PolicyRequest,
};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId, AuthzRevision,
    CorrelationId, CredentialId, DenialReason, GrantId, OrganizationId, OrganizationMembershipId,
    PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, Timestamp, Uuid,
    VerifiedContext,
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

/// A resource the request is not about.
fn elsewhere() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(11)),
    }
}

fn action() -> Action {
    Action::new("deployment.restart")
}

/// An action the request is not about.
fn other_action() -> Action {
    Action::new("deployment.read")
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

/// A catalog that knows `operator` carries the action, and a policy that can answer.
fn catalog() -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_policy(mandate_policy::record::Policy::recorded(
        approver(),
        organization(),
        PolicyVersion::new("v1"),
        "source",
    ));
    policy.record_model(mandate_policy::record::AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(41)),
        organization(),
        PolicyVersion::new("v1"),
        "schema",
    ));
    policy.record_role(organization(), "operator", vec![action()]);
    policy
}

/// The same catalog, with the request allowed by policy.
fn allowing() -> PolicyDouble {
    let mut policy = catalog();
    policy.allow(organization(), subject(), action(), resource());
    policy
}

fn issuer() -> FixedChallenge {
    FixedChallenge {
        expires_at: deadline(),
        approver_policy: Some(approver()),
    }
}

/// One `mandate.authorization.Check` of the otherwise-allowed request, varied in the
/// context, the scope it is made under and the policy that answers.
fn decide_with<P: PolicyEvaluator>(
    context: &VerifiedContext,
    scope: Option<&AuthorityScope>,
    policy: &P,
) -> Result<Decision, Denied> {
    let (graph, revision) = graph();
    let catalog = catalog();
    let issuer = issuer();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph: &graph,
        policy,
        catalog: &catalog,
        issuer: &issuer,
        tenancy: &tenancy,
        topology: &topology,
    };
    let ceilings: [Ceiling; 0] = [];

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context,
            action: &action(),
            resource: &resource(),
            expected_audience: &Audience::new("mandate"),
            relation: "operator",
            minimum: &revision,
            attributes: &AttributeSet::new(),
            scope,
            ceilings: &ceilings,
        },
    )
}

/// A policy evaluator that answers one thing, whatever it is asked.
struct Answers(Result<Evaluation, PolicyError>);

impl PolicyEvaluator for Answers {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.0.clone()
    }
}

/// `docs/architecture/combined.md:53`: "Effective authority is the intersection of subject
/// authority, actor ceiling, explicit delegation, **requested authority**, tenant/space/
/// resource, registered target and current policy", and in the same paragraph "an empty
/// source list grants none".
///
/// `mandate.core.AuthorityScope` is "the actions and resources an authority covers"
/// (`crates/mandate-types/src/record.rs:28-43`) and its first canonical sample is the empty
/// one (`record.rs:48`). A request made under a scope that covers no action and no resource
/// has requested nothing, so the intersection is empty.
///
/// `crates/mandate-authz/src/evaluate.rs:88-90` applies exactly that closed direction to a
/// capability ceiling — "an empty `allowed_actions` admits nothing: the same closed
/// direction `combined.md:53` states for an empty source list" — so the two bounds this
/// crate reads are read in opposite directions in one commit.
#[test]
fn a_request_under_an_empty_authority_scope_is_refused() {
    let empty = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    };

    decide_with(&context(), Some(&empty), &allowing())
        .expect_err("a scope that covers no action and no resource grants none");
}

/// The scope names an action, and it is not the one asked for.
#[test]
fn a_request_under_a_scope_that_does_not_name_the_action_is_refused() {
    let narrowed = AuthorityScope {
        actions: vec![other_action()],
        resources: vec![resource()],
        space: None,
    };

    let refusal = decide_with(&context(), Some(&narrowed), &allowing()).expect_err(
        "the request is made under a scope that covers `deployment.read` alone, so \
         `deployment.restart` is outside the requested authority",
    );

    assert!(!refusal.decision.allowed);
}

/// The scope names a resource, and it is not the one asked for.
#[test]
fn a_request_under_a_scope_that_does_not_name_the_resource_is_refused() {
    let narrowed = AuthorityScope {
        actions: vec![action()],
        resources: vec![elsewhere()],
        space: None,
    };

    let refusal = decide_with(&context(), Some(&narrowed), &allowing())
        .expect_err("the scope covers another resource, so this resource is outside it");

    assert!(!refusal.decision.allowed);
}

/// `crates/mandate-authz/Cargo.toml:3` gives this crate "authorization decisions and
/// subject/actor semantics"; `combined.md:53` puts the actor ceiling inside the
/// intersection and forbids "actor removal"; `mandate.core.VerifiedContext` declares
/// `actor: Optional<PrincipalId>` and carries it in its second canonical sample
/// (`crates/mandate-types/src/record.rs:66-72,:119-128`).
///
/// This case measures whether the actor is an input to the decision at all: the same
/// request is decided twice, differing only in an actor the tenancy never admitted and the
/// graph never saw.
#[test]
fn an_actor_the_tenancy_does_not_admit_changes_the_decision() {
    let mut delegated = context();
    delegated.actor = Some(PrincipalId::new(uuid(99)));

    decide_with(&context(), None, &allowing()).expect("the direct request is allowed");

    decide_with(&delegated, None, &allowing()).expect_err(
        "the only difference is an actor no membership admits and no grant names; if this \
         is an allow, `context.actor` is not read by any part of the decision",
    );
}

/// `mandate_policy::port::PolicyError::denial_reason` is "the declared reason the caller is
/// told" and distinguishes a decision against the caller from an inability to decide
/// (`crates/mandate-policy/src/port.rs:257-279`). `crates/mandate-authz/src/evaluate.rs:16-27`
/// promises the same: an inability answers `Unavailable`, a denial answers its own reason.
///
/// A policy denial whose reason is `ApprovalRequired` carries no challenge material — the
/// error type has no room for any — and `decision.rs:186-207` turns the pair into
/// `Unavailable`, so a decision policy did make is reported to the caller as an outage.
#[test]
fn a_policy_denial_naming_approval_required_is_told_under_its_own_name() {
    let refusal = decide_with(
        &context(),
        None,
        &Answers(Err(PolicyError::Denied(DenialReason::ApprovalRequired))),
    )
    .expect_err("a policy denial is not an allow");

    assert_eq!(
        refusal.reason,
        DenialReason::ApprovalRequired,
        "the reason the port declared is the reason the caller is told"
    );
}

/// `mandate_policy::port::Evaluation.challenge` is the challenge material an answer carries
/// (`crates/mandate-policy/src/port.rs:224-232`). An answer that carries one has stated
/// something the caller must satisfy; `crates/mandate-authz/src/decision.rs:156-166` returns
/// an unconditional allow and drops it, because the challenge is read only when the fold
/// came to `ApprovalRequired`.
#[test]
fn a_policy_allow_carrying_a_challenge_is_not_an_unconditional_allow() {
    let outcome = decide_with(
        &context(),
        None,
        &Answers(Ok(Evaluation {
            effect: PolicyEffect::Allow,
            version: PolicyVersion::new("v1"),
            challenge: Some(Challenge {
                requirement: ChallengeRequirement::Reauthentication,
                correlation: CorrelationId::new("correlation"),
            }),
        })),
    );

    match outcome {
        Ok(decision) => assert!(
            decision.challenge.is_some(),
            "an allow that drops the challenge policy attached tells the caller there is \
             nothing to satisfy"
        ),
        Err(refusal) => assert!(!refusal.decision.allowed),
    }
}

/// Determinism: the same inputs decide the same way, identity included, because the
/// allocator is the same fold in both calls.
#[test]
fn two_identical_checks_agree_on_every_field_of_the_decision() {
    let first = decide_with(&context(), None, &allowing()).expect("the request is allowed");
    let second = decide_with(&context(), None, &allowing()).expect("the request is allowed");

    assert_eq!(first, second);
}
