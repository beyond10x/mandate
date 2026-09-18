//! Adversary pass 2 on `story:check-api`: the corrections from round 1, driven end to end
//! through `check` rather than through the functions they were added to.
//!
//! Every scenario is the same allowed request — member subject, covering grant, policy
//! allow, no scope, no ceiling — varied in one input.

use mandate_authz::decision::{Denied, FixedChallenge, SequentialDecisionIds};
use mandate_authz::evaluate::Ceiling;
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, Observed, Unanswered};
use mandate_graph::record::Grant;
use mandate_graph::topology::{Placement, ResourceLookup, ResourceRegistry};
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, Evaluation, PolicyEffect, PolicyError,
    PolicyEvaluator, PolicyRequest, Unanswered as PolicyUnanswered,
};
use mandate_types::{
    Action, ActionPattern, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId,
    AuthzRevision, CorrelationId, CredentialId, DecisionReason, DelegationId, DenialReason,
    ExecutionId, GrantId, OrganizationId, OrganizationMembershipId, PolicyId, PolicyVersion,
    PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId, Timestamp, Uuid, VerifiedContext,
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

/// The parent the resource is registered under, in the ancestry scenarios.
fn folder() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("folder"),
        resource_id: ResourceId::new(uuid(12)),
    }
}

fn action() -> Action {
    Action::new("deployment.restart")
}

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

/// A graph in which the subject holds `operator` on the resource, granted for it by name.
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

/// The same graph, with the resource registered under a parent the grant names instead:
/// the subject holds the relation on the ancestor and inherits it on the child
/// (`crates/mandate-graph/src/topology.rs:8-10`).
fn graph_through_the_parent() -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &folder(), None)
        .expect("the folder is registered");
    graph
        .register_resource(&context(), &resource(), Some(&folder().resource_id))
        .expect("the resource is registered under it");
    let revision = graph.record_grant(Grant::recorded(
        GrantId::new(uuid(31)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![action()],
            resources: vec![folder()],
            space: None,
        },
        "operator",
    ));
    (graph, revision)
}

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

fn allowing() -> PolicyDouble {
    let mut policy = catalog();
    policy.allow(organization(), subject(), action(), resource());
    policy
}

/// A policy that answers with an approval requirement of the named strictness.
fn requiring(requirement: ChallengeRequirement) -> PolicyDouble {
    let mut policy = catalog();
    policy.require_approval(organization(), subject(), action(), resource(), requirement);
    policy
}

fn issuer() -> FixedChallenge {
    FixedChallenge {
        expires_at: deadline(),
        approver_policy: Some(approver()),
    }
}

/// Everything one `check` varies, defaulted to the world in which the request is allowed.
struct World<'a> {
    scope: Option<&'a AuthorityScope>,
    ceilings: &'a [Ceiling],
    issuer: FixedChallenge,
}

impl Default for World<'_> {
    fn default() -> Self {
        Self {
            scope: None,
            ceilings: &[],
            issuer: issuer(),
        }
    }
}

/// One `mandate.authorization.Check`, against the given ports.
fn decide<G, P>(
    graph: &G,
    policy: &P,
    minimum: &AuthzRevision,
    context: &VerifiedContext,
    world: &World<'_>,
) -> Result<Decision, Denied>
where
    G: GraphRead<Revision = AuthzRevision> + ResourceLookup + ?Sized,
    P: PolicyEvaluator + ?Sized,
{
    let catalog = catalog();
    let tenancy = tenancy();
    let topology = Topology::new();
    let pdp = Pdp {
        graph,
        policy,
        catalog: &catalog,
        issuer: &world.issuer,
        tenancy: &tenancy,
        topology: &topology,
    };

    check(
        &pdp,
        &mut SequentialDecisionIds::new(),
        &CheckRequest {
            context,
            action: &action(),
            resource: &resource(),
            expected_audience: &Audience::new("mandate"),
            relation: "operator",
            minimum,
            attributes: &AttributeSet::new(),
            scope: world.scope,
            ceilings: world.ceilings,
        },
    )
}

/// The unvaried world: the allowed request, varied only by `world`.
fn ordinary(world: &World<'_>) -> Result<Decision, Denied> {
    let (graph, revision) = graph();
    decide(&graph, &allowing(), &revision, &context(), world)
}

/// A policy evaluator that answers one thing, whatever it is asked.
struct Answers(Result<Evaluation, PolicyError>);

impl PolicyEvaluator for Answers {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.0.clone()
    }
}

/// A graph that refuses every authority read with one refusal, and resolves resources from
/// a real fold so the context still binds.
struct GraphSaying {
    inner: GraphDouble,
    refusal: GraphError,
}

impl GraphRead for GraphSaying {
    type Revision = AuthzRevision;

    fn check(
        &self,
        _query: &GraphQuery<'_>,
        _minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        Err(self.refusal.clone())
    }
}

impl ResourceLookup for GraphSaying {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        self.inner.placement(organization, resource)
    }
}

// ---------------------------------------------------------------------------------------
// F1, as corrected: the requested authority is folded in by `evaluate::requested`.
// ---------------------------------------------------------------------------------------

/// `mandate.graph.Resource` is identified by its `resource_id` and the type is a field of
/// the record, not part of what identifies it (`graph.yaml:8-11`).
/// `mandate_graph::double::GraphDouble::holds` reads `AuthorityScope.resources` under
/// exactly that rule and says so (`crates/mandate-graph/src/double.rs:182-190`): "A grant
/// naming the right resource id under a stale `resource_type` names the same resource".
///
/// `crates/mandate-authz/src/evaluate.rs:157` reads the same field of the same contract
/// type by whole-`ResourceRef` equality, so one decision applies two identity rules to one
/// value: the graph finds the authority and the requested-authority bound refuses it.
#[test]
fn a_scope_naming_the_resource_by_the_identity_the_graph_accepts_is_inside_it() {
    let aliased = AuthorityScope {
        actions: vec![action()],
        resources: vec![ResourceRef {
            resource_type: ResourceType::new("doc"),
            resource_id: resource().resource_id,
        }],
        space: None,
    };

    ordinary(&World {
        scope: Some(&aliased),
        ..World::default()
    })
    .expect("the scope names the resource the request is about, by its identity");
}

/// The mutant this guards: wiring `scope: None` into the `Read` at
/// `crates/mandate-authz/src/lib.rs:206`. `tests/evaluate.rs:899` calls `evaluate` with the
/// scope directly and stays green under it; no case of the unit's own suite passes a scope
/// through `check` at all (`tests/check_contract.rs:163` is `scope: None` and `World`
/// carries no scope field).
#[test]
fn the_requested_scope_is_wired_through_the_check_entry_point() {
    let narrowed = AuthorityScope {
        actions: vec![other_action()],
        resources: vec![resource()],
        space: None,
    };

    let refusal = ordinary(&World {
        scope: Some(&narrowed),
        ..World::default()
    })
    .expect_err("the request is outside the authority it was made under");

    assert_eq!(refusal.reason, DenialReason::Denied);
    assert!(!refusal.decision.allowed);
}

/// The second uncovered wiring line: `scope: request.scope` into the `Binding` at
/// `crates/mandate-authz/src/lib.rs:191`. `tests/context.rs:238-305` calls `bind` directly
/// and stays green without it; no case of the unit's own suite names a space through
/// `check`. A guard, not a finding — it is green as it stands.
#[test]
fn the_scope_space_is_wired_through_the_check_entry_point() {
    let named = AuthorityScope {
        actions: vec![action()],
        resources: vec![resource()],
        space: Some(SpaceId::new(uuid(60))),
    };

    let refusal = ordinary(&World {
        scope: Some(&named),
        ..World::default()
    })
    .expect_err("the organization holds no such space");

    assert_eq!(refusal.reason, DenialReason::TenantMismatch);
}

/// `AuthorityScope.actions` is a `List<Action>`, not a list of patterns, so a scope naming
/// `deployment.*` names one action nobody can request rather than a family. The closed
/// direction, and the opposite of what the same string means in a ceiling's
/// `List<ActionPattern>`.
#[test]
fn a_scope_naming_a_star_pattern_covers_no_action() {
    let patterned = AuthorityScope {
        actions: vec![Action::new("deployment.*")],
        resources: vec![resource()],
        space: None,
    };

    ordinary(&World {
        scope: Some(&patterned),
        ..World::default()
    })
    .expect_err("a scope names actions by equality, so a star names nothing");
}

/// Inheritance is the graph's rule: authority on an ancestor is authority on every
/// descendant (`crates/mandate-graph/src/topology.rs:8-10`). The requested-authority bound
/// does not follow it — a scope naming the parent does not cover a request about the child,
/// even where the grant that allows the request is the one on that parent.
#[test]
fn a_scope_naming_the_parent_does_not_cover_a_request_about_the_child() {
    let (graph, revision) = graph_through_the_parent();
    let naming_the_parent = AuthorityScope {
        actions: vec![action()],
        resources: vec![folder()],
        space: None,
    };
    let naming_the_child = AuthorityScope {
        actions: vec![action()],
        resources: vec![resource()],
        space: None,
    };

    decide(
        &graph,
        &allowing(),
        &revision,
        &context(),
        &World {
            scope: Some(&naming_the_child),
            ..World::default()
        },
    )
    .expect("authority reaches the child through the parent, and the scope names the child");

    decide(
        &graph,
        &allowing(),
        &revision,
        &context(),
        &World {
            scope: Some(&naming_the_parent),
            ..World::default()
        },
    )
    .expect_err("the scope names the parent alone, and the request is about the child");
}

/// Two bounds refusing at once report one reason, and it does not depend on which of them
/// the fold saw first.
#[test]
fn a_scope_refusal_and_a_ceiling_refusal_agree_on_the_reason() {
    let outside = AuthorityScope {
        actions: vec![other_action()],
        resources: vec![resource()],
        space: None,
    };
    let refusing = [Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.read")],
        denied_actions: Vec::new(),
    }];

    let both = ordinary(&World {
        scope: Some(&outside),
        ceilings: &refusing,
        issuer: issuer(),
    })
    .expect_err("both bounds refuse");
    let scope_alone = ordinary(&World {
        scope: Some(&outside),
        ..World::default()
    })
    .expect_err("the scope refuses");
    let ceiling_alone = ordinary(&World {
        ceilings: &refusing,
        ..World::default()
    })
    .expect_err("the ceiling refuses");

    assert_eq!(both.reason, scope_alone.reason);
    assert_eq!(both.reason, ceiling_alone.reason);
    assert_eq!(both.reason, DenialReason::Denied);
}

// ---------------------------------------------------------------------------------------
// F2, as corrected: `context::direct` refuses what this crate cannot bound.
// ---------------------------------------------------------------------------------------

/// Every shape `mandate.core.VerifiedContext` can take that is not the subject acting as
/// itself under no delegated authority (`crates/mandate-authz/src/context.rs:176-183`).
#[test]
fn every_non_direct_context_is_refused_and_reads_no_authority() {
    let stranger = PrincipalId::new(uuid(99));

    let mut acting_for_another = context();
    acting_for_another.actor = Some(stranger);

    let mut itself_but_delegated = context();
    itself_but_delegated.actor = Some(principal());
    itself_but_delegated.delegation = Some(DelegationId::new(uuid(50)));

    let mut executing = context();
    executing.execution = Some(ExecutionId::new(uuid(51)));

    let mut delegated_without_an_actor = context();
    delegated_without_an_actor.delegation = Some(DelegationId::new(uuid(50)));

    for context in [
        acting_for_another,
        itself_but_delegated,
        executing,
        delegated_without_an_actor,
    ] {
        let (graph, revision) = graph();
        let refusal = decide(&graph, &allowing(), &revision, &context, &World::default())
            .expect_err("a request this crate cannot bound is refused");

        assert_eq!(refusal.reason, DenialReason::Denied);
        assert_eq!(refusal.decision.reason, DecisionReason::Denied);
        assert_eq!(
            refusal.decision.revision, None,
            "a context that did not bind read no authority"
        );
    }

    let mut itself = context();
    itself.actor = Some(principal());
    let (graph, revision) = graph();
    decide(&graph, &allowing(), &revision, &itself, &World::default())
        .expect("an actor equal to the subject is the subject acting as itself");
}

// ---------------------------------------------------------------------------------------
// F3, as corrected: a port's declared reason reaches the caller.
// ---------------------------------------------------------------------------------------

/// Every refusal either port can answer, through `check`. `denial_reason()` is "the
/// declared reason the caller is told" on both ports
/// (`crates/mandate-graph/src/port.rs:115-126`, `crates/mandate-policy/src/port.rs:269-279`).
#[test]
fn every_port_refusal_reaches_the_caller_under_the_reason_the_port_declared() {
    for reason in DenialReason::VARIANTS {
        let (inner, revision) = graph();
        let refusing = GraphSaying {
            inner,
            refusal: GraphError::Denied(*reason),
        };
        let from_graph = decide(
            &refusing,
            &allowing(),
            &revision,
            &context(),
            &World::default(),
        )
        .expect_err("a graph denial is not an allow");
        assert_eq!(from_graph.reason, *reason, "graph denial: {reason:?}");

        let (graph, revision) = graph();
        let from_policy = decide(
            &graph,
            &Answers(Err(PolicyError::Denied(*reason))),
            &revision,
            &context(),
            &World::default(),
        )
        .expect_err("a policy denial is not an allow");
        assert_eq!(from_policy.reason, *reason, "policy denial: {reason:?}");
    }

    for unanswered in Unanswered::ALL {
        let (inner, revision) = graph();
        let down = GraphSaying {
            inner,
            refusal: GraphError::CouldNotAnswer(*unanswered),
        };
        let refusal = decide(&down, &allowing(), &revision, &context(), &World::default())
            .expect_err("an outage is not an allow");
        assert_eq!(refusal.reason, DenialReason::Unavailable);
    }

    for unanswered in PolicyUnanswered::ALL {
        let (graph, revision) = graph();
        let refusal = decide(
            &graph,
            &Answers(Err(PolicyError::CouldNotAnswer(*unanswered))),
            &revision,
            &context(),
            &World::default(),
        )
        .expect_err("an outage is not an allow");
        assert_eq!(refusal.reason, DenialReason::Unavailable);
    }
}

/// The acceptance statement of `story:check-api`: "allowed=false with a structured scoped
/// challenge and decision identifier". A decision that names `ApprovalRequired` and carries
/// no challenge tells the caller an approval is required and gives it nothing to answer —
/// the shape `mandate.core.Decision`'s own approval-required sample forbids
/// (`crates/mandate-model/src/lib.rs:180-188`). Round 1 answered this pair `Unavailable`;
/// the F3 correction propagates the reason and leaves the challenge behind.
#[test]
fn a_decision_reporting_approval_required_carries_the_challenge_to_answer() {
    let (graph, revision) = graph();

    let refusal = decide(
        &graph,
        &Answers(Err(PolicyError::Denied(DenialReason::ApprovalRequired))),
        &revision,
        &context(),
        &World::default(),
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(refusal.decision.reason, DecisionReason::ApprovalRequired);
    assert!(
        refusal.decision.challenge.is_some(),
        "a decision that reports an approval is required states what would clear it"
    );
}

// ---------------------------------------------------------------------------------------
// F4, as corrected: challenge material is a component of the fold.
// ---------------------------------------------------------------------------------------

/// A challenge beside a refusal does not soften it: `combine` gives every refusal
/// precedence over every approval requirement (`precedence.rs:169-174`).
#[test]
fn a_policy_deny_carrying_a_challenge_stays_a_deny() {
    let (graph, revision) = graph();

    let refusal = decide(
        &graph,
        &Answers(Ok(Evaluation {
            effect: PolicyEffect::Deny,
            version: PolicyVersion::new("v1"),
            challenge: Some(Challenge {
                requirement: ChallengeRequirement::Approval,
                correlation: CorrelationId::new("correlation"),
            }),
        })),
        &revision,
        &context(),
        &World::default(),
    )
    .expect_err("a policy deny is not an allow");

    assert_eq!(refusal.reason, DenialReason::Denied);
    assert_eq!(refusal.decision.challenge, None);
}

/// An allow carrying challenge material becomes an approval requirement, and an approval
/// nobody can approve fails closed rather than being issued as one.
#[test]
fn an_allow_carrying_a_challenge_with_no_approver_policy_fails_closed() {
    let (graph, revision) = graph();

    let refusal = decide(
        &graph,
        &Answers(Ok(Evaluation {
            effect: PolicyEffect::Allow,
            version: PolicyVersion::new("v1"),
            challenge: Some(Challenge {
                requirement: ChallengeRequirement::Approval,
                correlation: CorrelationId::new("correlation"),
            }),
        })),
        &revision,
        &context(),
        &World {
            issuer: FixedChallenge {
                expires_at: deadline(),
                approver_policy: None,
            },
            ..World::default()
        },
    )
    .expect_err("an approval nobody can approve is not an allow");

    assert_eq!(refusal.reason, DenialReason::Unavailable);
    assert_eq!(refusal.decision.challenge, None);
}

/// `mandate_policy::precedence::strictest` exists to choose *which* requirement the caller
/// is told to satisfy, and `combined.md:67` makes the choice between a reauthentication the
/// caller clears alone and an approval a second party must give. `mandate.core.Decision`
/// carries the choice nowhere: `DecisionChallenge` declares `approver_policy` and
/// `expires_at` and no requirement (`crates/mandate-model/src/lib.rs:103-116`), so the two
/// answers produce one decision and the PEP cannot tell its caller what to do.
#[test]
fn an_approval_and_a_reauthentication_do_not_produce_the_same_decision() {
    let (first, at) = graph();
    let approval = decide(
        &first,
        &requiring(ChallengeRequirement::Approval),
        &at,
        &context(),
        &World::default(),
    )
    .expect_err("an approval requirement is not an allow");

    let (second, next) = graph();
    let reauthentication = decide(
        &second,
        &requiring(ChallengeRequirement::Reauthentication),
        &next,
        &context(),
        &World::default(),
    )
    .expect_err("a reauthentication requirement is not an allow");

    assert_ne!(
        approval, reauthentication,
        "the requirement precedence chose is not recorded in the decision it chose it for"
    );
}
