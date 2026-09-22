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

use mandate_authz::decision::{FixedChallenge, SequentialDecisionIds};
use mandate_control_plane::adapters::{
    AuthorizationRefusal, Configuration, Deployment, Login, SeededResourceServer,
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
    Action, Audience, AuthorityScope, AuthoritySubject, AuthorizationModelId, ClientId,
    CorrelationId, CredentialId, CredentialKind, CredentialProof, DenialReason, Duration,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, GrantId,
    Issuer, OAuthClientId, OrganizationId, OrganizationMembershipId, PkceChallenge, PkceMethod,
    PolicyId, PolicyVersion, PrincipalId, RedirectUri, ResourceId, ResourceRef, ResourceServerId,
    ResourceType, RevocationGuarantee, SigningAlgorithm, Timestamp, Transient, Uuid,
    VerifiedContext,
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
        policy.allow(organization(), subject(), issue_action(), resource);
    }

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
    }
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
            keys: Vec::new(),
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
                verified_claim_value: None,
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
            public: true,
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
