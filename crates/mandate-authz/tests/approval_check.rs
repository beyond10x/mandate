//! `mandate.authorization.CheckWithApproval`: the second check after an approval-required
//! decision, which consumes the approval it names.
//!
//! `systems/mandate/domains/authorization.yaml` declares the command: `accepted` emits the one
//! `mandate.authorization.ApprovedDecisionRecorded {context, decision, approval}` and moves
//! `mandate.delegation.Approval.consume`; a consumed approval is `wrong-state`; and an
//! unrecorded, foreign or expired approval, or one naming another subject, actor, action or
//! resource, is refused exactly as an unrecorded one. Every other part of the request is
//! decided as `Check` decides it.

use mandate_authz::agent::{AgentAuthorityRead, AgentRecords};
use mandate_authz::command::RefusedAs;
use mandate_authz::decision::{
    ApprovalDenied, ApprovedDecisionRecorded, FixedChallenge, SequentialDecisionIds,
};
use mandate_authz::delegation::{Approval, ApprovalState};
use mandate_authz::event::{DelegationEvent, DelegationProjection};
use mandate_authz::{CheckRequest, Pdp, check, check_with_approval};
use mandate_graph::double::GraphDouble;
use mandate_graph::record::Grant;
use mandate_graph::topology::ResourceRegistry;
use mandate_model::graph::Topology;
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{AttributeSet, ChallengeRequirement};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, ApprovalId, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId,
    AuthzRevision, CorrelationId, CredentialId, DecisionReason, DenialReason, GrantId,
    OrganizationId, OrganizationMembershipId, PolicyId, PolicyVersion, PrincipalId, ResourceId,
    ResourceRef, ResourceType, Timestamp, Uuid, VerifiedContext,
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

fn approver_policy() -> PolicyId {
    PolicyId::new(uuid(40))
}

/// The instant every decision here is taken at.
fn at() -> Timestamp {
    Timestamp::new("2026-09-17T00:00:00Z")
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

/// A graph in which the subject holds the `operator` role on the resource, or holds nothing.
fn graph(granted: bool) -> (GraphDouble, AuthzRevision) {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    if granted {
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
    } else {
        (graph, AuthzRevision::new("0".to_owned()))
    }
}

/// What policy says about the one request every case here makes.
#[derive(Debug, Clone, Copy)]
enum Says {
    RequiresApproval,
    RequiresReauthentication,
    Allows,
    Denies,
}

fn policy(says: Says) -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_policy(Policy::recorded(
        approver_policy(),
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
    match says {
        Says::RequiresApproval => policy.require_approval(
            organization(),
            subject(),
            action(),
            resource(),
            ChallengeRequirement::Approval,
        ),
        Says::RequiresReauthentication => policy.require_approval(
            organization(),
            subject(),
            action(),
            resource(),
            ChallengeRequirement::Reauthentication,
        ),
        Says::Allows => policy.allow(organization(), subject(), action(), resource()),
        Says::Denies => policy.deny(organization(), subject(), action(), resource()),
    }
    policy
}

fn issuer() -> FixedChallenge {
    FixedChallenge {
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        approver_policy: Some(approver_policy()),
    }
}

/// The approval the cases use, answering exactly the request every case makes.
fn approval_id() -> ApprovalId {
    ApprovalId::new(uuid(50))
}

fn approval(id: ApprovalId) -> Approval {
    Approval {
        id,
        organization_id: organization(),
        subject: principal(),
        actor: None,
        action: action(),
        resource: resource(),
        expires_at: Timestamp::new("2026-09-17T01:00:00Z"),
        approver: PrincipalId::new(uuid(60)),
        state: ApprovalState::Recorded,
    }
}

/// One world: the ports and the delegation fold, holding `approvals`.
struct World {
    graph: GraphDouble,
    revision: AuthzRevision,
    policy: PolicyDouble,
    issuer: FixedChallenge,
    tenancy: Tenancy,
    topology: Topology,
    delegations: DelegationProjection,
}

impl World {
    fn new(granted: bool, says: Says, approvals: Vec<Approval>) -> Self {
        let (graph, revision) = graph(granted);
        Self {
            graph,
            revision,
            policy: policy(says),
            issuer: issuer(),
            tenancy: tenancy(),
            topology: Topology::new(),
            delegations: DelegationProjection::holding(AgentRecords {
                approvals,
                ..AgentRecords::new()
            }),
        }
    }

    fn approved(&self, id: ApprovalId) -> Result<ApprovedDecisionRecorded, ApprovalDenied> {
        let context = context();
        let action = action();
        let resource = resource();
        let audience = Audience::new("mandate");
        let attributes = AttributeSet::new();
        let at = at();
        let request = CheckRequest {
            context: &context,
            action: &action,
            resource: &resource,
            expected_audience: &audience,
            relation: "operator",
            minimum: &self.revision,
            attributes: &attributes,
            scope: None,
            at: &at,
        };
        check_with_approval(
            &Pdp {
                graph: &self.graph,
                policy: &self.policy,
                catalog: &self.policy,
                issuer: &self.issuer,
                tenancy: &self.tenancy,
                topology: &self.topology,
                agents: &self.delegations,
            },
            &mut SequentialDecisionIds::new(),
            &request,
            id,
        )
    }

    fn checked(&self) -> Result<mandate_model::Decision, mandate_authz::decision::Denied> {
        let context = context();
        let action = action();
        let resource = resource();
        let audience = Audience::new("mandate");
        let attributes = AttributeSet::new();
        let at = at();
        check(
            &Pdp {
                graph: &self.graph,
                policy: &self.policy,
                catalog: &self.policy,
                issuer: &self.issuer,
                tenancy: &self.tenancy,
                topology: &self.topology,
                agents: &self.delegations,
            },
            &mut SequentialDecisionIds::new(),
            &CheckRequest {
                context: &context,
                action: &action,
                resource: &resource,
                expected_audience: &audience,
                relation: "operator",
                minimum: &self.revision,
                attributes: &attributes,
                scope: None,
                at: &at,
            },
        )
    }

    fn state_of(&self, id: ApprovalId) -> Option<ApprovalState> {
        self.delegations
            .approval(&id)
            .expect("the fold answers")
            .map(|approval| approval.state)
    }
}

/// The acceptance: an approval-required decision, then the second check allows and returns
/// the one event that records the decision and the consumption together.
#[test]
fn an_approval_satisfies_the_approval_required_decision_and_is_consumed_with_it() {
    let world = World::new(true, Says::RequiresApproval, vec![approval(approval_id())]);
    let first = world
        .checked()
        .expect_err("the first check needs an approval");
    assert_eq!(first.reason, DenialReason::ApprovalRequired);

    let recorded = world
        .approved(approval_id())
        .expect("the approval satisfies the requirement");

    assert!(recorded.decision.allowed);
    assert_eq!(recorded.decision.reason, DecisionReason::Allowed);
    assert_eq!(recorded.decision.challenge, None);
    assert_eq!(recorded.decision.revision, Some(world.revision.clone()));
    assert_eq!(
        recorded.decision.policy_version,
        Some(PolicyVersion::new("v1"))
    );
    assert_eq!(recorded.context, context());
    assert_eq!(recorded.approval, approval_id());
    assert_eq!(
        DelegationEvent::from(recorded).ess_name(),
        "mandate.authorization.ApprovedDecisionRecorded"
    );
}

/// The fold applies the event as the approval's consume, so the same id a second time is
/// `wrong-state`, and nothing is emitted for it.
#[test]
fn a_second_use_of_the_same_approval_is_wrong_state() {
    let mut world = World::new(true, Says::RequiresApproval, vec![approval(approval_id())]);
    let recorded = world.approved(approval_id()).expect("the first use allows");
    world.delegations.apply(&DelegationEvent::from(recorded));
    assert_eq!(world.state_of(approval_id()), Some(ApprovalState::Consumed));

    let second = world
        .approved(approval_id())
        .expect_err("a consumed approval satisfies no other check");
    assert_eq!(second.outcome, RefusedAs::WrongState);
    assert_eq!(second.denied.reason, DenialReason::Denied);
    assert!(!second.denied.decision.allowed);
    assert_eq!(second.denied.decision.challenge, None);
}

/// Every mismatch, an unknown id and a foreign approval refuse exactly alike, and the
/// approval stays recorded.
#[test]
fn every_mismatched_approval_refuses_exactly_as_an_unknown_one_and_consumes_nothing() {
    let other = PrincipalId::new(uuid(70));
    let mismatched: Vec<(&str, Approval)> = vec![
        (
            "subject",
            Approval {
                subject: other,
                ..approval(ApprovalId::new(uuid(51)))
            },
        ),
        (
            "actor",
            Approval {
                actor: Some(other),
                ..approval(ApprovalId::new(uuid(52)))
            },
        ),
        (
            "action",
            Approval {
                action: Action::new("deployment.delete"),
                ..approval(ApprovalId::new(uuid(53)))
            },
        ),
        (
            "resource",
            Approval {
                resource: ResourceRef {
                    resource_type: ResourceType::new("document"),
                    resource_id: ResourceId::new(uuid(11)),
                },
                ..approval(ApprovalId::new(uuid(54)))
            },
        ),
        (
            "organization",
            Approval {
                organization_id: OrganizationId::new(uuid(9)),
                ..approval(ApprovalId::new(uuid(55)))
            },
        ),
        (
            "expired",
            Approval {
                expires_at: at(),
                ..approval(ApprovalId::new(uuid(56)))
            },
        ),
    ];
    let world = World::new(
        true,
        Says::RequiresApproval,
        mismatched
            .iter()
            .map(|(_, approval)| approval.clone())
            .collect(),
    );

    let unknown = world
        .approved(ApprovalId::new(uuid(99)))
        .expect_err("an unrecorded approval satisfies nothing");
    assert_eq!(unknown.outcome, RefusedAs::Denied);
    assert_eq!(unknown.denied.reason, DenialReason::Denied);
    assert!(!unknown.denied.decision.allowed);
    assert_eq!(unknown.denied.decision.challenge, None);

    for (mismatch, approval) in &mismatched {
        let refusal = world
            .approved(approval.id)
            .expect_err("a mismatched approval satisfies nothing");
        assert_eq!(
            refusal, unknown,
            "an approval naming another {mismatch} refuses exactly as an unknown one"
        );
        assert_eq!(
            world.state_of(approval.id),
            Some(ApprovalState::Recorded),
            "the {mismatch} mismatch leaves the approval recorded"
        );
    }
}

/// A refusal the graph or policy makes stands with an approval named, and the approval is
/// not consumed: it still satisfies the request once the deny is gone.
#[test]
fn a_graph_or_policy_deny_stands_with_an_approval_named_and_consumes_nothing() {
    for (case, granted, says) in [
        ("graph", false, Says::RequiresApproval),
        ("policy", true, Says::Denies),
    ] {
        let world = World::new(granted, says, vec![approval(approval_id())]);
        let refusal = world
            .approved(approval_id())
            .expect_err("an approval does not override a deny");
        let plain = world.checked().expect_err("check refuses it too");
        assert_eq!(refusal.outcome, RefusedAs::Denied, "{case}");
        assert_eq!(
            refusal.denied, plain,
            "{case}: the refusal check makes stands"
        );
        assert_eq!(
            world.state_of(approval_id()),
            Some(ApprovalState::Recorded),
            "{case}: nothing is consumed"
        );
    }
}

/// An approval is not a reauthentication: the requirement it cannot answer stands.
#[test]
fn an_approval_does_not_clear_a_reauthentication_requirement() {
    let world = World::new(
        true,
        Says::RequiresReauthentication,
        vec![approval(approval_id())],
    );
    let refusal = world
        .approved(approval_id())
        .expect_err("a reauthentication is the caller's own to clear");
    assert_eq!(refusal.denied.reason, DenialReason::Unavailable);
    assert_eq!(
        refusal.denied,
        world.checked().expect_err("check refuses it")
    );
}

/// A request that needs no approval allows, and the approval named is still consumed.
#[test]
fn an_allow_without_an_approval_requirement_still_consumes_the_approval() {
    let mut world = World::new(true, Says::Allows, vec![approval(approval_id())]);
    let recorded = world
        .approved(approval_id())
        .expect("the request is allowed");
    assert!(recorded.decision.allowed);
    assert_eq!(recorded.approval, approval_id());

    world.delegations.apply(&DelegationEvent::from(recorded));
    assert_eq!(world.state_of(approval_id()), Some(ApprovalState::Consumed));
}
