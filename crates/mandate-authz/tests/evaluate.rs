//! One graph read and one policy read per request, expanded, ceiling-bounded and folded
//! through deny precedence.
//!
//! Corpus cases (`tests/security/cases.json`): `directory-no-authority` (`:5`) — a
//! principal with no grant holds no authority; `autonomous-ceiling` (`:541`) — a grant
//! that exceeds the platform or tenant ceiling is refused; `graph-revocation` (`:614`) — a
//! grant revoked at revision R is refused for a check requiring R; `pdp-outage` (`:602`) —
//! a required decision point that cannot answer denies and invents no permission.

use std::cell::Cell;

use mandate_authz::evaluate::{Authority, Ceiling, Read, covers, evaluate, requested};
use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, Observed};
use mandate_graph::record::Grant;
use mandate_graph::revocation::{RevisionView, RevocationWriter};
use mandate_graph::topology::ResourceRegistry;
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, Evaluation, PolicyEffect, PolicyError,
    PolicyEvaluator, PolicyRequest,
};
use mandate_policy::precedence::{Combined, Component};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ActionPattern, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId,
    AuthzRevision, CorrelationId, CredentialId, DenialReason, GrantId, OrganizationId, PolicyId,
    PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
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

/// A graph that admits the subject and holds the resource, with no authority on it.
fn graph() -> GraphDouble {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    graph
}

/// The grant `directory-no-authority` says a directory membership never produces, and the
/// one `graph-revocation` revokes.
fn grant() -> Grant {
    Grant::recorded(
        GrantId::new(uuid(30)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![action()],
            resources: vec![resource()],
            space: None,
        },
        "operator",
    )
}

/// A policy that can answer, with the catalog told that `operator` carries the action.
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
    policy
}

fn attributes() -> AttributeSet {
    AttributeSet::new()
}

fn read<'a>(
    context: &'a VerifiedContext,
    subject: &'a AuthoritySubject,
    action: &'a Action,
    resource: &'a ResourceRef,
    minimum: &'a AuthzRevision,
    attributes: &'a AttributeSet,
    ceilings: &'a [Ceiling],
) -> Read<'a> {
    Read {
        context,
        subject,
        action,
        resource,
        relation: "operator",
        minimum,
        attributes,
        scope: None,
        ceilings,
    }
}

/// `directory-no-authority`: the principal is a member and holds no grant, so the graph
/// finds no authority. Policy allowing changes nothing — an allow is not authority.
#[test]
fn a_subject_with_no_grant_holds_no_authority_however_policy_answers() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let graph = graph();
    let minimum = graph.observed();

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &minimum,
            &attributes(),
            &[],
        ),
    );

    assert_eq!(authority.combined, Combined::Denied(DenialReason::Denied));
    assert!(!authority.combined.allowed());
}

#[test]
fn a_grant_the_catalog_says_carries_the_action_and_a_policy_allow_is_an_allow() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[],
        ),
    );

    assert_eq!(authority.combined, Combined::Allowed);
    assert_eq!(authority.revision, Some(revision));
    assert_eq!(authority.policy_version, Some(PolicyVersion::new("v1")));
}

/// The role is known and does not carry the action: an expansion that does not cover is a
/// refusal, never an absence of opinion.
#[test]
fn a_role_that_does_not_carry_the_requested_action_denies() {
    let context = context();
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
    policy.record_role(organization(), "operator", vec![Action::new("read")]);
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[],
        ),
    );

    assert_eq!(authority.combined, Combined::Denied(DenialReason::Denied));
}

/// A role name no catalog knows can never become authority.
#[test]
fn a_role_the_catalog_does_not_know_denies() {
    let context = context();
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
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[],
        ),
    );

    assert_eq!(authority.combined, Combined::Denied(DenialReason::Denied));
}

/// `graph-revocation`: the grant is revoked at revision R, and a check that requires R is
/// answered from the state at R — which no longer carries the grant.
#[test]
fn a_grant_revoked_at_a_revision_carries_no_authority_at_that_revision() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let before = graph.record_grant(grant());
    let revocation = graph
        .revoke_grant(&context, &GrantId::new(uuid(30)))
        .expect("the grant is revoked");

    let allowed_before = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &before,
            &attributes(),
            &[],
        ),
    );
    let after = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revocation.revision,
            &attributes(),
            &[],
        ),
    );

    assert_ne!(before, revocation.revision);
    assert_eq!(
        allowed_before.combined,
        Combined::Denied(DenialReason::Denied),
        "the fold answers from its current state, not from the revision floor"
    );
    assert_eq!(after.combined, Combined::Denied(DenialReason::Denied));
}

/// `graph-revocation`, the other half: a reader that has not reached the required revision
/// answers nothing at all, and nothing is an outage rather than a decision.
#[test]
fn a_revision_the_reader_has_not_applied_is_unavailable_and_not_a_denial_about_the_caller() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    graph.record_grant(grant());

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &AuthzRevision::new("never-issued"),
            &attributes(),
            &[],
        ),
    );

    assert_eq!(
        authority.combined,
        Combined::Denied(DenialReason::Unavailable)
    );
    assert_eq!(authority.revision, None);
}

/// `pdp-outage`: the policy decision point cannot answer. The graph's allow does not
/// become the decision, and no local permission is invented.
#[test]
fn a_policy_decision_point_that_cannot_answer_denies_a_request_the_graph_allows() {
    let context = context();
    let mut graph = graph();
    let revision = graph.record_grant(grant());
    let mut catalog = PolicyDouble::new();
    catalog.record_role(organization(), "operator", vec![action()]);

    let authority = evaluate(
        &graph,
        &PolicyDouble::new(),
        &catalog,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[],
        ),
    );

    assert_eq!(
        authority.combined,
        Combined::Denied(DenialReason::Unavailable)
    );
    assert!(!authority.combined.allowed());
    assert_eq!(authority.policy_version, None);
}

/// `autonomous-ceiling`: a persistent grant that exceeds the ceiling is refused, however
/// the graph and policy answer.
#[test]
fn a_ceiling_that_does_not_admit_the_action_refuses_an_otherwise_allowed_request() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());
    let ceilings = vec![Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.read")],
        denied_actions: Vec::new(),
    }];

    let authority = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &ceilings,
        ),
    );

    assert_eq!(authority.combined, Combined::Denied(DenialReason::Denied));
}

/// `autonomous-ceiling`: every applicable ceiling intersects, so the tenant ceiling can
/// refuse what the platform ceiling admits.
#[test]
fn every_applicable_ceiling_intersects() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());
    let platform = Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: Vec::new(),
    };
    let tenant = Ceiling {
        organization: Some(organization()),
        allowed_actions: vec![ActionPattern::new("deployment.*")],
        denied_actions: vec![ActionPattern::new("deployment.restart")],
    };
    let elsewhere = Ceiling {
        organization: Some(OrganizationId::new(uuid(9))),
        allowed_actions: Vec::new(),
        denied_actions: vec![ActionPattern::new("*")],
    };

    let inside = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            std::slice::from_ref(&platform),
        ),
    );
    let intersected = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[platform.clone(), tenant],
        ),
    );
    let another_tenants = evaluate(
        &graph,
        &policy,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &[platform, elsewhere],
        ),
    );

    assert_eq!(inside.combined, Combined::Allowed);
    assert_eq!(intersected.combined, Combined::Denied(DenialReason::Denied));
    assert_eq!(
        another_tenants.combined,
        Combined::Allowed,
        "a ceiling recorded for another organization does not apply"
    );
}

/// A ceiling bounds and never grants: it cannot turn a request nothing allowed into an
/// allow.
#[test]
fn a_ceiling_that_admits_the_action_grants_nothing_by_itself() {
    let context = context();
    let graph = graph();
    let minimum = graph.observed();
    let ceilings = vec![Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("*")],
        denied_actions: Vec::new(),
    }];

    let authority = evaluate(
        &graph,
        &PolicyDouble::new(),
        &PolicyDouble::new(),
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &minimum,
            &attributes(),
            &ceilings,
        ),
    );

    assert!(!authority.combined.allowed());
    assert_eq!(
        Ceiling {
            organization: None,
            allowed_actions: vec![ActionPattern::new("*")],
            denied_actions: Vec::new(),
        }
        .component(&action()),
        Component::Nothing
    );
}

#[test]
fn a_pattern_covers_the_action_it_names_and_the_prefix_it_ends() {
    let restart = Action::new("deployment.restart");

    assert!(covers(&ActionPattern::new("deployment.restart"), &restart));
    assert!(covers(&ActionPattern::new("deployment.*"), &restart));
    assert!(covers(&ActionPattern::new("*"), &restart));
    assert!(!covers(&ActionPattern::new("deployment.read"), &restart));
    assert!(!covers(&ActionPattern::new("directory.*"), &restart));
    assert!(
        !covers(&ActionPattern::new("deployment"), &restart),
        "a prefix is only a prefix when the pattern says so"
    );
}

/// An empty ceiling admits nothing, the same closed direction an empty source list takes.
#[test]
fn a_ceiling_that_admits_no_pattern_admits_no_action() {
    let empty = Ceiling {
        organization: None,
        allowed_actions: Vec::new(),
        denied_actions: Vec::new(),
    };

    assert!(!empty.admits(&action()));
    assert_eq!(
        empty.component(&action()),
        Component::Denied(DenialReason::Denied)
    );
}

/// A binding refusal carries no port answer, and is still an authority value the one
/// assembly path can read.
#[test]
fn a_refusal_taken_before_any_read_carries_nothing_from_the_ports() {
    let refused = Authority::refused(DenialReason::AudienceMismatch);

    assert_eq!(
        refused.combined,
        Combined::Denied(DenialReason::AudienceMismatch)
    );
    assert_eq!(refused.revision, None);
    assert_eq!(refused.policy_version, None);
    assert!(refused.challenges.is_empty());
}

/// A decision is one question: each port is asked once, whatever the answer is.
struct Counted<'a> {
    graph: &'a GraphDouble,
    policy: &'a PolicyDouble,
    graph_reads: Cell<usize>,
    policy_reads: Cell<usize>,
}

impl GraphRead for Counted<'_> {
    type Revision = AuthzRevision;

    fn check(
        &self,
        query: &GraphQuery<'_>,
        minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        self.graph_reads.set(self.graph_reads.get() + 1);
        self.graph.check(query, minimum)
    }
}

impl PolicyEvaluator for Counted<'_> {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.policy_reads.set(self.policy_reads.get() + 1);
        self.policy.evaluate(request)
    }
}

#[test]
fn each_port_is_read_exactly_once_per_request() {
    let context = context();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());
    let counted = Counted {
        graph: &graph,
        policy: &policy,
        graph_reads: Cell::new(0),
        policy_reads: Cell::new(0),
    };
    let ceilings = vec![Ceiling {
        organization: None,
        allowed_actions: vec![ActionPattern::new("*")],
        denied_actions: Vec::new(),
    }];

    let authority = evaluate(
        &counted,
        &counted,
        &policy,
        &read(
            &context,
            &subject(),
            &action(),
            &resource(),
            &revision,
            &attributes(),
            &ceilings,
        ),
    );

    assert_eq!(authority.combined, Combined::Allowed);
    assert_eq!(counted.graph_reads.get(), 1);
    assert_eq!(counted.policy_reads.get(), 1);
}

/// A hand-rolled deterministic generator, on the pattern of
/// `crates/mandate-types/tests/adversary.rs`: every combination of what the two ports can
/// answer and what the ceiling can say, with the allow set stated independently of the
/// implementation. No property-testing crate is in `Cargo.lock` and none may be added.
#[test]
fn only_a_covering_grant_and_a_policy_allow_inside_every_ceiling_is_an_allow() {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum GraphAnswer {
        Covers,
        NoGrant,
        NotCaughtUp,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PolicyAnswer {
        Allow,
        Deny,
        Approval,
        Unreachable,
    }

    let graph_answers = [
        GraphAnswer::Covers,
        GraphAnswer::NoGrant,
        GraphAnswer::NotCaughtUp,
    ];
    let policy_answers = [
        PolicyAnswer::Allow,
        PolicyAnswer::Deny,
        PolicyAnswer::Approval,
        PolicyAnswer::Unreachable,
    ];
    let ceiling_admits = [true, false];
    let context = context();
    let mut checked = 0_usize;

    for graph_answer in graph_answers {
        for policy_answer in policy_answers {
            for admits in ceiling_admits {
                let mut graph = graph();
                let revision = graph.record_grant(grant());
                let minimum = match graph_answer {
                    GraphAnswer::NotCaughtUp => AuthzRevision::new("never-issued"),
                    GraphAnswer::Covers | GraphAnswer::NoGrant => revision,
                };
                let mut policy = PolicyDouble::new();
                if policy_answer != PolicyAnswer::Unreachable {
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
                }
                if graph_answer == GraphAnswer::Covers {
                    policy.record_role(organization(), "operator", vec![action()]);
                }
                match policy_answer {
                    PolicyAnswer::Allow => {
                        policy.allow(organization(), subject(), action(), resource());
                    }
                    PolicyAnswer::Deny => {
                        policy.deny(organization(), subject(), action(), resource());
                    }
                    PolicyAnswer::Approval => policy.require_approval(
                        organization(),
                        subject(),
                        action(),
                        resource(),
                        ChallengeRequirement::Approval,
                    ),
                    PolicyAnswer::Unreachable => {}
                }
                let ceilings = vec![Ceiling {
                    organization: None,
                    allowed_actions: vec![ActionPattern::new(if admits {
                        "deployment.*"
                    } else {
                        "directory.*"
                    })],
                    denied_actions: Vec::new(),
                }];

                let authority = evaluate(
                    &graph,
                    &policy,
                    &policy,
                    &read(
                        &context,
                        &subject(),
                        &action(),
                        &resource(),
                        &minimum,
                        &attributes(),
                        &ceilings,
                    ),
                );

                let should_allow = graph_answer == GraphAnswer::Covers
                    && policy_answer == PolicyAnswer::Allow
                    && admits;
                assert_eq!(
                    authority.combined.allowed(),
                    should_allow,
                    "graph {graph_answer:?}, policy {policy_answer:?}, ceiling admits {admits}"
                );
                if policy_answer == PolicyAnswer::Unreachable {
                    assert_eq!(authority.policy_version, None);
                }
                checked += 1;
            }
        }
    }

    assert_eq!(checked, 24);
}

/// A scope covering the request, for the cases that vary something else.
fn covering_scope() -> AuthorityScope {
    AuthorityScope {
        actions: vec![action()],
        resources: vec![resource()],
        space: None,
    }
}

/// The fixed half of every request below, owned so a [`Read`] can borrow it. What each
/// case varies is what it measures; everything else is this.
struct Asked {
    context: VerifiedContext,
    subject: AuthoritySubject,
    action: Action,
    resource: ResourceRef,
    attributes: AttributeSet,
}

impl Asked {
    fn new() -> Self {
        Self {
            context: context(),
            subject: subject(),
            action: action(),
            resource: resource(),
            attributes: attributes(),
        }
    }

    fn read<'a>(
        &'a self,
        minimum: &'a AuthzRevision,
        scope: Option<&'a AuthorityScope>,
    ) -> Read<'a> {
        Read {
            context: &self.context,
            subject: &self.subject,
            action: &self.action,
            resource: &self.resource,
            relation: "operator",
            minimum,
            attributes: &self.attributes,
            scope,
            ceilings: &[],
        }
    }
}

/// `combined.md:53` puts requested authority inside the same intersection as every other
/// bound, and states one closed direction for all of them: an empty source list grants
/// none. Every shape a requested scope can take is decided here, so the bound is not read
/// in one direction for a ceiling and the other for a scope.
///
/// The resource is named by identity, which is the rule `mandate-graph` applies to the
/// same field of the same contract type (`crates/mandate-graph/src/double.rs:182-190`,
/// `graph.yaml:8-11`): `resource_type` is a field of the record, not part of what
/// identifies it. `requested` is the only place this crate compares one `ResourceRef` with
/// another — every other resource question is asked of `ResourceLookup::placement`, which
/// applies the port's own rule — so one decision applies one identity rule.
#[test]
fn a_requested_scope_bounds_in_the_same_direction_as_every_other_bound() {
    let empty = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    };
    let other_action = AuthorityScope {
        actions: vec![Action::new("deployment.read")],
        resources: vec![resource()],
        space: None,
    };
    let other_resource = AuthorityScope {
        actions: vec![action()],
        resources: vec![ResourceRef {
            resource_type: ResourceType::new("document"),
            resource_id: ResourceId::new(uuid(11)),
        }],
        space: None,
    };
    let refused = Component::Denied(DenialReason::Denied);

    assert_eq!(
        requested(None, &action(), &resource()),
        Component::Nothing,
        "a request under no scope has narrowed nothing"
    );
    assert_eq!(requested(Some(&empty), &action(), &resource()), refused);
    assert_eq!(
        requested(Some(&other_action), &action(), &resource()),
        refused
    );
    assert_eq!(
        requested(Some(&other_resource), &action(), &resource()),
        refused
    );
    assert_eq!(
        requested(Some(&covering_scope()), &action(), &resource()),
        Component::Nothing,
        "a scope bounds and never grants, exactly as a ceiling does"
    );

    let aliased = AuthorityScope {
        actions: vec![action()],
        resources: vec![ResourceRef {
            resource_type: ResourceType::new("doc"),
            resource_id: resource().resource_id,
        }],
        space: None,
    };
    assert_eq!(
        requested(Some(&aliased), &action(), &resource()),
        Component::Nothing,
        "the same resource under a stale type is the same resource"
    );

    let another_identity = AuthorityScope {
        actions: vec![action()],
        resources: vec![ResourceRef {
            resource_type: resource().resource_type,
            resource_id: ResourceId::new(uuid(11)),
        }],
        space: None,
    };
    assert_eq!(
        requested(Some(&another_identity), &action(), &resource()),
        refused,
        "a different identity is a different resource, type or no type"
    );
}

/// A scope that covers the request cannot make an unallowed request allowed: the bound
/// contributes the identity of the fold, not an allow.
#[test]
fn a_covering_scope_grants_nothing_by_itself() {
    let asked = Asked::new();
    let graph = graph();
    let minimum = graph.observed();
    let scope = covering_scope();

    let authority = evaluate(
        &graph,
        &PolicyDouble::new(),
        &PolicyDouble::new(),
        &asked.read(&minimum, Some(&scope)),
    );

    assert!(!authority.combined.allowed());
}

/// The requested authority refuses through the same fold every other bound refuses
/// through, so a request outside its scope is denied however the ports answered.
#[test]
fn a_request_outside_its_requested_scope_is_denied_through_the_fold() {
    let asked = Asked::new();
    let mut policy = policy();
    policy.allow(organization(), subject(), action(), resource());
    let mut graph = graph();
    let revision = graph.record_grant(grant());
    let covering = covering_scope();
    let narrowed = AuthorityScope {
        actions: vec![Action::new("deployment.read")],
        resources: vec![resource()],
        space: None,
    };

    let inside = evaluate(
        &graph,
        &policy,
        &policy,
        &asked.read(&revision, Some(&covering)),
    );
    let outside = evaluate(
        &graph,
        &policy,
        &policy,
        &asked.read(&revision, Some(&narrowed)),
    );

    assert_eq!(inside.combined, Combined::Allowed);
    assert_eq!(outside.combined, Combined::Denied(DenialReason::Denied));
}

/// A graph that answers one thing, whatever it is asked.
struct GraphAnswers(Result<Observed, GraphError>);

impl GraphRead for GraphAnswers {
    type Revision = AuthzRevision;

    fn check(
        &self,
        _query: &GraphQuery<'_>,
        _minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        self.0.clone()
    }
}

/// A policy that answers one thing, whatever it is asked.
struct PolicyAnswers(Result<Evaluation, PolicyError>);

impl PolicyEvaluator for PolicyAnswers {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        self.0.clone()
    }
}

fn observed() -> Observed {
    Observed {
        revision: AuthzRevision::new("1"),
        through: resource(),
    }
}

fn allowing_evaluation() -> Evaluation {
    Evaluation {
        effect: PolicyEffect::Allow,
        version: PolicyVersion::new("v1"),
        challenge: None,
    }
}

/// Every refusal either port can make reaches the fold under the reason that port itself
/// declares, and only an inability to answer becomes `Unavailable`. The sets are read from
/// the ports' own lists — `DenialReason::VARIANTS`, and each crate's `Unanswered::ALL` —
/// so a variant added to either is decided here the day it is declared.
#[test]
fn every_port_refusal_reaches_the_fold_under_the_reason_that_port_declares() {
    let asked = Asked::new();
    let minimum = AuthzRevision::new("1");
    let mut catalog = PolicyDouble::new();
    catalog.record_role(organization(), "operator", vec![action()]);
    let mut decided = 0_usize;

    for reason in DenialReason::VARIANTS {
        let from_policy = evaluate(
            &GraphAnswers(Ok(observed())),
            &PolicyAnswers(Err(PolicyError::Denied(*reason))),
            &catalog,
            &asked.read(&minimum, None),
        );
        let from_graph = evaluate(
            &GraphAnswers(Err(GraphError::Denied(*reason))),
            &PolicyAnswers(Ok(allowing_evaluation())),
            &catalog,
            &asked.read(&minimum, None),
        );

        assert_eq!(
            from_policy.combined,
            Combined::Denied(*reason),
            "a policy denial is told under its own name"
        );
        assert_eq!(
            from_graph.combined,
            Combined::Denied(*reason),
            "a graph denial is told under its own name"
        );
        decided += 2;
    }

    for unanswered in mandate_policy::port::Unanswered::ALL {
        let authority = evaluate(
            &GraphAnswers(Ok(observed())),
            &PolicyAnswers(Err(PolicyError::CouldNotAnswer(*unanswered))),
            &catalog,
            &asked.read(&minimum, None),
        );

        assert_eq!(
            authority.combined,
            Combined::Denied(DenialReason::Unavailable),
            "an inability to answer is an outage, never a decision about the caller"
        );
        assert_eq!(authority.policy_version, None);
        decided += 1;
    }

    for unanswered in mandate_graph::port::Unanswered::ALL {
        let authority = evaluate(
            &GraphAnswers(Err(GraphError::CouldNotAnswer(*unanswered))),
            &PolicyAnswers(Ok(allowing_evaluation())),
            &catalog,
            &asked.read(&minimum, None),
        );

        assert_eq!(
            authority.combined,
            Combined::Denied(DenialReason::Unavailable)
        );
        assert_eq!(authority.revision, None);
        decided += 1;
    }

    assert_eq!(decided, 20);
}

/// An `Evaluation` states two things — an effect and, optionally, material the caller must
/// satisfy — and both are read whatever the other says. Every combination of the two is
/// decided here, with what it comes to stated independently of how the fold is built.
#[test]
fn challenge_material_is_read_whatever_effect_it_arrives_with() {
    let asked = Asked::new();
    let minimum = AuthzRevision::new("1");
    let mut catalog = PolicyDouble::new();
    catalog.record_role(organization(), "operator", vec![action()]);
    let material = Challenge {
        requirement: ChallengeRequirement::Reauthentication,
        correlation: CorrelationId::new("correlation"),
    };
    let expected = [
        (PolicyEffect::Allow, None, Combined::Allowed),
        (
            PolicyEffect::Allow,
            Some(material.clone()),
            Combined::ApprovalRequired,
        ),
        (
            PolicyEffect::Deny,
            None,
            Combined::Denied(DenialReason::Denied),
        ),
        (
            PolicyEffect::Deny,
            Some(material.clone()),
            Combined::Denied(DenialReason::Denied),
        ),
        (
            PolicyEffect::ApprovalRequired,
            None,
            Combined::ApprovalRequired,
        ),
        (
            PolicyEffect::ApprovalRequired,
            Some(material),
            Combined::ApprovalRequired,
        ),
    ];

    assert_eq!(
        expected.len(),
        PolicyEffect::ALL.len() * 2,
        "every effect is decided with and without material"
    );
    for (effect, challenge, comes_to) in expected {
        let carried = challenge.is_some();

        let authority = evaluate(
            &GraphAnswers(Ok(observed())),
            &PolicyAnswers(Ok(Evaluation {
                effect,
                version: PolicyVersion::new("v1"),
                challenge,
            })),
            &catalog,
            &asked.read(&minimum, None),
        );

        assert_eq!(authority.combined, comes_to, "effect {effect:?}");
        assert_eq!(
            authority.challenges.is_empty(),
            !carried,
            "material policy attached is carried forward, effect {effect:?}"
        );
    }
}
