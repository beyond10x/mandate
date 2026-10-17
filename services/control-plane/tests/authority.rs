//! The composition's authority decision: `mandate.authorization.Check`, asked before the
//! composition dispatches a handler.
//!
//! `story:tenancy-authority`. `mandate_authz::check` is the decider that exists and no
//! composition could reach it: `dependency-boundaries.json` gave `mandate-authz` two
//! dependents, both test infrastructure. The cycle that forbids calling it from
//! `mandate-model` does not exist one level up, so the call site is here.
//!
//! # Every decision these cases drive is a double's, and that is the point
//!
//! `mandate_authz::check` reads two ports. `mandate_graph::port::GraphRead` has one
//! implementor outside a test file — `mandate_graph::double::GraphDouble` — and
//! `mandate_policy::port::PolicyEvaluator` has one — `mandate_policy::double::PolicyDouble`.
//! A deployment therefore cannot be configured with anything but a stand-in today, and the
//! refusals below are refusals a stand-in was written to give. They show the composition
//! **asks** and **routes the answer**, which is what this story delivers; they are no
//! evidence that a shipped adapter refuses anything, and the obligations registry must not
//! be told they are. The engine behind the ports is `story:graph-policy-adapter`'s.
//!
//! What *is* decided over live state here is the binding half: `mandate_authz::context::bind`
//! reads `mandate_model::tenancy::Tenancy` and `mandate_model::graph::Topology`, both folds.
//! A caller whose organization does not admit authority, or who is no member of it, is
//! refused before either port is read.

use mandate_authz::agent::{AgentRecords, PrincipalStanding};
use mandate_authz::command::{
    ConfiguredDelegationAdmission, CreateDelegation, SequentialDelegationIds,
    decide_create_delegation, decide_revoke_delegation,
};
use mandate_authz::decision::{FixedChallenge, SequentialDecisionIds};
use mandate_authz::delegation::{Agent, AgentCapabilityCeiling, AgentState, CeilingState};
use mandate_authz::event::{DelegationCreated, DelegationEvent, DelegationProjection};
use mandate_control_plane::adapters::{
    AuthorizationRefusal, Configuration, DelegationUnrecorded, Deployment, Login,
    SeededResourceServer,
};
use mandate_control_plane::authority::{Admission, Admitting, DecisionPoint};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_graph::double::GraphDouble;
use mandate_graph::record::Grant;
use mandate_graph::revocation::RevisionView;
use mandate_graph::topology::ResourceRegistry;
use mandate_model::graph::Topology;
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_policy::double::PolicyDouble;
use mandate_policy::port::AttributeSet;
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, Audience, AuthorityScope, AuthoritySubject,
    AuthorizationModelId, ClientId, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    DelegationId, DenialReason, Duration, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject,
    FederationConnectionId, GrantId, Issuer, OAuthClientId, OrganizationId,
    OrganizationMembershipId, PkceChallenge, PkceMethod, PolicyId, PolicyVersion, PrincipalId,
    RedirectUri, ResourceId, ResourceRef, ResourceServerId, ResourceType, RevocationGuarantee,
    SigningAlgorithm, Timestamp, Transient, Uuid, VerifiedContext,
};

const ISSUER: &str = "https://mandate.example";
const REDIRECT: &str = "https://client.example/callback";
/// 2026-09-19T00:00:00Z, the instant every case is decided at.
const NOW: u64 = 1_789_084_800;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(principal())
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn approver() -> PolicyId {
    PolicyId::new(uuid(0x40))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("authority"),
    }
}

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn verifier() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("ES256")],
        VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new("subject-1"),
            ClientId::new("mandate-at-idp"),
        ),
    )
    .expect("a non-empty algorithm allowlist")
}

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// The resource the composition asks the decision point about, as
/// `Deployment::authorize` names it: the registered target, by its own identity.
fn target_resource(target: ResourceServerId) -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new(mandate_control_plane::authority::RESOURCE_SERVER),
        resource_id: ResourceId::new(*target.as_uuid()),
    }
}

/// The action the composition asks about: the command it is about to dispatch.
fn issue_action() -> Action {
    Action::new(mandate_control_plane::authority::ISSUE_AUTHORIZATION_CODE)
}

/// A tenancy fold that admits the organization and holds the caller as a member. Both
/// reads are `mandate_authz::context::bind`'s and both are decided over the fold.
fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&context(), organization(), "acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            &context(),
            MembershipAuthority::VerifiedOrganization,
            OrganizationMembershipId::new(uuid(0x03)),
            organization(),
            principal(),
        )
        .expect("the subject is a member");
    tenancy
}

/// How the graph double is told about the caller.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
    /// The subject holds the `operator` role over the target.
    Grant,
    /// The subject is admitted and the resource is registered, and no grant is recorded.
    NoGrant,
}

/// How the policy double is told to answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answers {
    /// A current policy and model, and a rule that allows.
    Allow,
    /// A current policy and model, and no rule at all.
    Nothing,
    /// No policy version and no model: the evaluator cannot answer, which fails closed.
    ///
    /// The role catalog still knows the role, and the graph still holds the grant, so the
    /// evaluator's silence is the only refusal in the fold. Withholding the role as well
    /// would make the fold answer `Denied` on the unknown role and the case would be
    /// asserting the wrong reason for the wrong cause.
    Unreachable,
}

/// A decision point over the two doubles, told what to hold and what to answer.
fn decision_point(
    held: Held,
    answers: Answers,
    target: ResourceServerId,
) -> DecisionPoint<GraphDouble, PolicyDouble, PolicyDouble, FixedChallenge, SequentialDecisionIds> {
    let resource = target_resource(target);
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context(), &resource, None)
        .expect("the target is registered in the caller's organization");
    let revision = if held == Held::Grant {
        graph.record_grant(Grant::recorded(
            GrantId::new(uuid(0x30)),
            organization(),
            subject(),
            AuthorityScope {
                actions: vec![issue_action()],
                resources: vec![resource.clone()],
                space: None,
            },
            mandate_control_plane::authority::ISSUANCE_RELATION,
        ))
    } else {
        RevisionView::observed(&graph)
    };

    let policy = policy(answers, target);

    DecisionPoint {
        graph,
        policy: policy.clone(),
        catalog: policy,
        issuer: FixedChallenge {
            expires_at: Timestamp::new("2026-09-19T01:00:00Z"),
            approver_policy: Some(approver()),
        },
        allocator: SequentialDecisionIds::new(),
        tenancy: tenancy(),
        topology: Topology::new(),
        minimum: revision,
        attributes: AttributeSet::new(),
        // No agent record and no event: the read every case before the delegation fold was
        // decided over.
        delegations: DelegationProjection::default(),
    }
}

/// The policy double, told how to answer about the subject on the target.
///
/// A function of its own because `CreateDelegation` asks policy about the delegator too, and
/// a case that creates a delegation asks the same answers the decision point is given.
fn policy(answers: Answers, target: ResourceServerId) -> PolicyDouble {
    let mut policy = PolicyDouble::new();
    policy.record_role(
        organization(),
        mandate_control_plane::authority::ISSUANCE_RELATION,
        vec![issue_action()],
    );
    if answers != Answers::Unreachable {
        policy.record_policy(Policy::recorded(
            approver(),
            organization(),
            PolicyVersion::new("v1"),
            "source",
        ));
        policy.record_model(AuthorizationModel::recorded(
            AuthorizationModelId::new(uuid(0x41)),
            organization(),
            PolicyVersion::new("v1"),
            "schema",
        ));
    }
    if answers == Answers::Allow {
        policy.allow(
            organization(),
            subject(),
            issue_action(),
            target_resource(target),
        );
    }
    policy
}

/// The smallest world the login road needs: one connection, one link, one public client and
/// one registered target.
fn deployment() -> (Wired, ResourceServerId) {
    let mut allocator = 0_u8;
    let seeded: SeededResourceServer = mandate_control_plane::adapters::ResourceServerSeed {
        resource_server_id: Some(ResourceServerId::new(uuid(0xa5))),
        organization: organization(),
        audience: Audience::new("https://api.example"),
        profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }
    .events(&mut || {
        allocator += 1;
        uuid(allocator)
    });

    let mut deployment = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
        },
        verifier(),
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");

    for event in &seeded.events {
        deployment
            .record_credential(event)
            .expect("a readable credential history");
    }
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_values: None,
            },
            jit_provisioning: false,
        })
        .expect("a readable federation history");
    deployment
        .record_federation(&FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(),
            principal_id: principal(),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        })
        .expect("a readable federation history");
    deployment
        .record_federation(&FederationEvent::OAuthClientRegistered {
            context: context(),
            id: client(),
            organization_id: organization(),
            client_type: mandate_types::OAuthClientType::Public,
            secret_verifiers: Vec::new(),
            pkce_required: true,
            trusted_peers: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
        })
        .expect("a readable federation history");
    (deployment, seeded.resource_server_id)
}

fn login(deployment: &mut Wired) -> Login {
    deployment
        .authenticate(&decode::AuthenticateFederation {
            connection_id: connection(),
            proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
        })
        .expect("a linked principal over a configured connection")
}

fn authorize_input(login: &Login, target: ResourceServerId) -> decode::AuthorizePublicClient {
    decode::AuthorizePublicClient {
        client_id: client(),
        redirect_uri: RedirectUri::new(REDIRECT),
        challenge: PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        method: PkceMethod::S256,
        state: "state-1".to_owned(),
        nonce: "nonce-1".to_owned(),
        session_proof: CredentialProof::from_bytes(login.session_proof.expose_material().to_vec()),
        target,
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
    }
}

/// The reason a refusal at the redirect carries, or a panic naming what came back instead.
fn refused_with(refusal: &AuthorizationRefusal) -> (&str, DenialReason) {
    match refusal {
        AuthorizationRefusal::AtRedirect { refusal, .. }
        | AuthorizationRefusal::InPlace(refusal) => (refusal.clause.as_str(), refusal.reason),
    }
}

// ---------------------------------------------------------------------------------------
// The decision point on its own
// ---------------------------------------------------------------------------------------

/// A caller the graph holds no grant for is refused, and the refusal is the declared one.
#[test]
fn a_caller_the_graph_holds_no_grant_for_is_refused_by_the_decision_point() {
    let target = ResourceServerId::new(uuid(0xa5));
    let mut point = decision_point(Held::NoGrant, Answers::Nothing, target);
    let context = context();
    let action = issue_action();
    let resource = target_resource(target);
    let audience = context.audience.clone();

    let denied = point
        .admit(&Admission {
            context: &context,
            action: &action,
            resource: &resource,
            expected_audience: &audience,
            relation: mandate_control_plane::authority::ISSUANCE_RELATION,
            scope: None,
            at: &Timestamp::new("2026-09-19T00:00:00Z"),
        })
        .expect_err("a subject with no grant holds no authority");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert!(!denied.decision.allowed);
}

/// A caller whose organization holds no membership for it is refused over the **fold**,
/// before either port is read. This half of the decision is real.
#[test]
fn a_caller_the_tenancy_fold_holds_no_membership_for_is_refused_before_a_port_is_read() {
    let target = ResourceServerId::new(uuid(0xa5));
    let mut point = decision_point(Held::Grant, Answers::Allow, target);
    point.tenancy = {
        let mut tenancy = Tenancy::new();
        tenancy
            .create_organization(&context(), organization(), "acme")
            .expect("the organization is recorded");
        tenancy
    };
    let context = context();
    let action = issue_action();
    let resource = target_resource(target);
    let audience = context.audience.clone();

    let denied = point
        .admit(&Admission {
            context: &context,
            action: &action,
            resource: &resource,
            expected_audience: &audience,
            relation: mandate_control_plane::authority::ISSUANCE_RELATION,
            scope: None,
            at: &Timestamp::new("2026-09-19T00:00:00Z"),
        })
        .expect_err("a non-member binds to nothing");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
}

// ---------------------------------------------------------------------------------------
// The composition, before handler dispatch
// ---------------------------------------------------------------------------------------

/// The unit's case: the composition refuses an authorization the decision point denies,
/// and the handler is never dispatched — no code comes back.
#[test]
fn an_authorization_the_decision_point_denies_is_refused_before_the_handler_is_dispatched() {
    let (deployment, target) = deployment();
    let mut deployment = deployment.with_authority(Box::new(decision_point(
        Held::NoGrant,
        Answers::Nothing,
        target,
    )));
    let login = login(&mut deployment);

    let refused = deployment
        .authorize(&authorize_input(&login, target))
        .expect_err("a caller holding no authority is refused the code");

    let (clause, reason) = refused_with(&refused);
    assert_eq!(clause, mandate_control_plane::authority::AUTHORITY_DENIED);
    assert_eq!(reason, DenialReason::Denied);
    assert!(
        matches!(refused, AuthorizationRefusal::AtRedirect { .. }),
        "the client and its registered redirect were validated first, so the refusal is the \
         redirect's"
    );
}

/// An authority decision neither port can answer fails closed as `Unavailable` rather than
/// being answered by the other port's yes.
#[test]
fn an_authority_decision_the_policy_port_cannot_answer_refuses_as_unavailable() {
    let (deployment, target) = deployment();
    let mut deployment = deployment.with_authority(Box::new(decision_point(
        Held::Grant,
        Answers::Unreachable,
        target,
    )));
    let login = login(&mut deployment);

    let refused = deployment
        .authorize(&authorize_input(&login, target))
        .expect_err("an evaluator that cannot answer denies");

    let (clause, reason) = refused_with(&refused);
    assert_eq!(clause, mandate_control_plane::authority::AUTHORITY_DENIED);
    assert_eq!(reason, DenialReason::Unavailable);
}

/// The control: the same request, with the same world, allowed. Without this the refusal
/// above is indistinguishable from a guard that refuses everything.
#[test]
fn an_authorization_the_decision_point_allows_reaches_the_handler_and_issues_a_code() {
    let (deployment, target) = deployment();
    let mut deployment = deployment.with_authority(Box::new(decision_point(
        Held::Grant,
        Answers::Allow,
        target,
    )));
    let login = login(&mut deployment);

    let issued = deployment
        .authorize(&authorize_input(&login, target))
        .expect("a caller the decision point allows is issued a code");

    assert_eq!(issued.state, "state-1");
    assert_eq!(issued.redirect_uri, RedirectUri::new(REDIRECT));
}

/// The second control, and the honest record of what a shipped deployment does: a
/// deployment configured with no decision point takes no authority decision at all. The
/// guard is opt-in because the only thing that can be plugged into it today is a double.
#[test]
fn a_deployment_configured_with_no_decision_point_takes_no_authority_decision() {
    let (mut deployment, target) = deployment();
    let login = login(&mut deployment);

    let issued = deployment
        .authorize(&authorize_input(&login, target))
        .expect("no decision point is configured, so no authority is read");

    assert_eq!(issued.state, "state-1");
}

/// A context whose audience is not the one the caller requires is refused, and it is refused
/// over the **fold**: `mandate_authz::context::bind` compares the two before either port is
/// read.
///
/// This case exists because the composition cannot reach this arm. `Deployment::authorize`
/// builds the context's audience and the expectation it passes from **one** read of the
/// credential fold, so the two are equal by construction and `AudienceMismatch` is
/// unreachable from there — recorded at the call site and in `crate::authority`'s header.
/// The binding is still a real refusal of the decision point, and a caller with an
/// independent expectation gets it; that is what this decides.
#[test]
fn a_context_whose_audience_is_not_the_expected_one_is_refused_by_the_decision_point() {
    let target = ResourceServerId::new(uuid(0xa5));
    let mut point = decision_point(Held::Grant, Answers::Allow, target);
    let context = context();
    let action = issue_action();
    let resource = target_resource(target);
    // The caller requires a credential issued for another audience than the one the context
    // carries. Nothing else about the world changes.
    let required = Audience::new("https://other.example");
    assert_ne!(context.audience, required, "the case varies the audience");

    let denied = point
        .admit(&Admission {
            context: &context,
            action: &action,
            resource: &resource,
            expected_audience: &required,
            relation: mandate_control_plane::authority::ISSUANCE_RELATION,
            scope: None,
            at: &Timestamp::new("2026-09-19T00:00:00Z"),
        })
        .expect_err("a credential issued for another audience binds to nothing");

    assert_eq!(denied.reason, DenialReason::AudienceMismatch);
    assert!(!denied.decision.allowed);
}

// ---------------------------------------------------------------------------------------
// The delegation fold the decision point decides over
// ---------------------------------------------------------------------------------------

/// The agent installation the delegated requests are made by.
fn agent() -> PrincipalId {
    PrincipalId::new(uuid(0x5a))
}

/// The instant the delegated requests are decided at: `NOW`, as the deployment reads it.
fn at() -> Timestamp {
    Timestamp::new("2026-09-19T00:00:00Z")
}

/// The authority the agent is bounded to and delegated: the issuance, on the target.
fn issuance_scope(target: ResourceServerId) -> AuthorityScope {
    AuthorityScope {
        actions: vec![issue_action()],
        resources: vec![target_resource(target)],
        space: None,
    }
}

/// The records no command of `mandate.delegation` creates, seeded as
/// `DelegationProjection::fold` takes them: the delegator and the agent are active, the agent
/// is installed in the organization, and — when `ceiling` — bounded by one current tenant
/// ceiling that admits the issuance on the target.
fn records(target: ResourceServerId, ceiling: bool) -> AgentRecords {
    let mut records = AgentRecords::new();
    records.standings = vec![
        (principal(), PrincipalStanding::Active),
        (agent(), PrincipalStanding::Active),
    ];
    records.agents = vec![Agent {
        id: agent(),
        organization_id: organization(),
        agent_type: "assistant".to_owned(),
        state: AgentState::Recorded,
    }];
    if ceiling {
        records.ceilings = vec![AgentCapabilityCeiling {
            id: AgentCapabilityCeilingId::new(uuid(0x5c)),
            agent_id: agent(),
            organization_id: Some(organization()),
            allowed_actions: vec![ActionPattern::new("mandate.credential.*")],
            denied_actions: Vec::new(),
            scope: issuance_scope(target),
            max_delegation_ttl: Duration::new("PT1H"),
            state: CeilingState::Recorded,
        }];
    }
    records
}

/// The context the agent's request is made under: acting for the delegator, under
/// `delegation`.
fn delegated_context(delegation: DelegationId) -> VerifiedContext {
    VerifiedContext {
        actor: Some(agent()),
        delegation: Some(delegation),
        ..context()
    }
}

/// Ask `deployment`'s decision point about the issuance on `target` under `context`.
fn decide(
    deployment: &mut Wired,
    context: &VerifiedContext,
    target: ResourceServerId,
) -> Result<mandate_model::Decision, mandate_authz::decision::Denied> {
    let action = issue_action();
    let resource = target_resource(target);
    deployment
        .admit(&Admission {
            context,
            action: &action,
            resource: &resource,
            expected_audience: &context.audience,
            relation: mandate_control_plane::authority::ISSUANCE_RELATION,
            scope: None,
            at: &at(),
        })
        .expect("the deployment is configured with a decision point")
}

/// The unit's case: a delegation created by `CreateDelegation` and recorded through the
/// deployment is the record the deployment's decision point decides the agent's request over,
/// and the `DelegationRevoked` `RevokeDelegation` decides, recorded the same way, refuses the
/// same request.
///
/// The graph holds the delegator's grant and policy allows it throughout, so the delegation
/// record is the one thing that changes between the three decisions: refused before it is
/// recorded, allowed while it stands, refused once it is revoked.
#[test]
fn a_delegated_request_is_permitted_over_a_delegation_recorded_through_the_deployment_and_refused_after_its_revocation()
 {
    let (deployment, target) = deployment();
    let mut point = decision_point(Held::Grant, Answers::Allow, target);
    point.delegations = DelegationProjection::holding(records(target, true));
    let mut deployment = deployment.with_authority(Box::new(point));
    let admission = ConfiguredDelegationAdmission::new()
        .with_delegator(principal())
        .with_revoker(principal())
        .with_audience(organization(), context().audience);

    let created = decide_create_delegation(
        deployment
            .delegations()
            .expect("a decision point holds the fold"),
        &policy(Answers::Allow, target),
        &admission,
        &mut SequentialDelegationIds::new(),
        &CreateDelegation {
            context: context(),
            delegate: agent(),
            scope: issuance_scope(target),
            audience: context().audience,
            expires_at: Timestamp::new("2026-09-19T00:30:00Z"),
            not_before: None,
            execution_binding: None,
        },
        &at(),
    )
    .expect("the delegator may delegate the issuance to its installed agent");
    let delegated = delegated_context(created.delegation_id);

    let unrecorded = decide(&mut deployment, &delegated, target)
        .expect_err("a delegation decided but not yet recorded bounds nothing");
    assert_eq!(unrecorded.reason, DenialReason::Denied);

    deployment
        .record_delegation(&created.event)
        .expect("a deployment with a decision point records the event");
    let allowed = decide(&mut deployment, &delegated, target)
        .expect("the recorded delegation admits the agent's request");
    assert!(allowed.allowed);

    let revoked = decide_revoke_delegation(
        deployment
            .delegations()
            .expect("a decision point holds the fold"),
        &admission,
        &context(),
        created.delegation_id,
    )
    .expect("the delegator may revoke its own standing delegation");
    deployment
        .record_delegation(&revoked)
        .expect("a deployment with a decision point records the event");
    let refused = decide(&mut deployment, &delegated, target)
        .expect_err("a revoked delegation admits nothing");
    assert_eq!(refused.reason, DenialReason::Denied);
    assert!(!refused.decision.allowed);

    let log = deployment
        .delegations()
        .expect("a decision point holds the fold")
        .log();
    assert_eq!(log, [created.event, revoked].as_slice());
}

/// An agent bounded by no capability ceiling is refused, over a delegation that otherwise
/// admits its request; the control, the same fold with the ceiling, is allowed.
///
/// The delegation is folded from its `DelegationCreated` over the seeded records, because
/// `CreateDelegation` itself refuses a delegate with no ceiling.
#[test]
fn an_agent_request_without_a_ceiling_is_refused_by_the_deployments_decision_point() {
    let delegation = DelegationId::new(uuid(0xd1));
    let decided = |ceiling: bool| {
        let (deployment, target) = deployment();
        let mut point = decision_point(Held::Grant, Answers::Allow, target);
        point.delegations = DelegationProjection::fold(
            records(target, ceiling),
            &[DelegationEvent::Created(Box::new(DelegationCreated {
                context: context(),
                id: delegation,
                delegator: principal(),
                delegate: agent(),
                scope: issuance_scope(target),
                audience: context().audience,
                not_before: None,
                expires_at: Timestamp::new("2026-09-19T00:30:00Z"),
                execution_binding: None,
                created_at: at(),
            }))],
        );
        let mut deployment = deployment.with_authority(Box::new(point));
        decide(&mut deployment, &delegated_context(delegation), target)
    };

    let refused = decided(false).expect_err("no ceiling bounds the agent, so it is refused");
    assert_eq!(refused.reason, DenialReason::Denied);
    assert!(!refused.decision.allowed);
    assert!(
        decided(true)
            .expect("the control: the same fold with the ceiling")
            .allowed,
        "only the ceiling differs between the two"
    );
}

/// A direct request of a principal that is no agent is decided as it was over the empty read,
/// though the fold now holds an agent and a delegation: it reaches the handler and a code is
/// issued, and without the grant it is refused `Denied`.
#[test]
fn a_direct_request_of_a_non_agent_principal_is_decided_as_before_over_the_delegation_fold() {
    let fold = |target| {
        DelegationProjection::fold(
            records(target, true),
            &[DelegationEvent::Created(Box::new(DelegationCreated {
                context: context(),
                id: DelegationId::new(uuid(0xd1)),
                delegator: principal(),
                delegate: agent(),
                scope: issuance_scope(target),
                audience: context().audience,
                not_before: None,
                expires_at: Timestamp::new("2026-09-19T00:30:00Z"),
                execution_binding: None,
                created_at: at(),
            }))],
        )
    };

    let (granted, target) = deployment();
    let mut point = decision_point(Held::Grant, Answers::Allow, target);
    point.delegations = fold(target);
    let mut granted = granted.with_authority(Box::new(point));
    let session = login(&mut granted);
    let issued = granted
        .authorize(&authorize_input(&session, target))
        .expect("a direct caller the decision point allows is issued a code");
    assert_eq!(issued.state, "state-1");

    let (ungranted, target) = deployment();
    let mut point = decision_point(Held::NoGrant, Answers::Nothing, target);
    point.delegations = fold(target);
    let mut ungranted = ungranted.with_authority(Box::new(point));
    let session = login(&mut ungranted);
    let refused = ungranted
        .authorize(&authorize_input(&session, target))
        .expect_err("a direct caller holding no grant is refused, as before");
    assert_eq!(refused_with(&refused).1, DenialReason::Denied);
}

/// A deployment configured with no decision point holds no delegation fold, so it refuses to
/// record a delegation event rather than accepting one nothing will ever read.
#[test]
fn a_deployment_with_no_decision_point_refuses_to_record_a_delegation_event() {
    let (mut deployment, _) = deployment();

    let refused = deployment.record_delegation(&DelegationEvent::Revoked {
        context: context(),
        id: DelegationId::new(uuid(0xd1)),
    });

    assert_eq!(refused, Err(DelegationUnrecorded));
    assert!(deployment.delegations().is_none());
}
