//! `ExchangeCredential`, subject-only: a Mandate access credential issued for one resource
//! server is exchanged for a credential for another, when — and only when — the target's
//! registration lists the source among its `allowed_exchange_sources`.
//!
//! What the story's acceptance decides here, at the handler:
//!
//! - an admitted exchange emits `mandate.credential.TokenExchangeAllowed`, and the credential
//!   it issues is for the target, carries the subject credential's subject and organization,
//!   expires no later than the subject credential does, and is answered active by
//!   `IntrospectCredential` once the event is folded;
//! - a source the target does not admit, an expired, revoked or unknown subject credential, an
//!   unknown target, an actor or a delegation, and a scope wider than the subject's are each
//!   refused with a `mandate.credential.TokenExchangeDenied` record and **draw nothing**: no
//!   secret is minted and no identity is handed out
//!   (`story:sts-refusal-draws-nothing`'s discipline).

use mandate_sts::exchange::{
    ExchangeCredential, ExchangeParts, ExchangeRefused, exchange_credential,
};
use mandate_sts::issue::{
    IssueReferenceCredential, ReferenceParts, Sha256Digest, issue_reference_credential,
};
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::resolve::{IntrospectCredential, IntrospectionParts, introspect_credential};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Projection};
use mandate_types::{
    Action, Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    CredentialSecret, DelegationId, Duration, OrganizationId, PrincipalId, ResourceServerId,
    RevocationGuarantee, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn subject() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: subject(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("exchange"),
    }
}

/// The instant the subject credential is issued at.
const ISSUED: &str = "2026-09-19T00:00:00Z";

fn at(instant: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("exchange"),
        at: Timestamp::new(instant),
        epochs: None,
    }
}

fn scope(actions: &[&str]) -> AuthorityScope {
    AuthorityScope {
        actions: actions.iter().map(|action| Action::new(*action)).collect(),
        resources: Vec::new(),
        space: None,
    }
}

fn reference_profile(max_ttl: &str) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new(max_ttl),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

/// The world every case starts from: source `S`, target `T` admitting `S`, a second target
/// `U` admitting nothing, and one reference credential for `S` held by [`subject`].
struct World {
    log: Vec<CredentialEvent>,
    held: Projection,
    source: ResourceServerId,
    target: ResourceServerId,
    closed: ResourceServerId,
    subject_credential: CredentialSecret,
    subject_credential_id: CredentialId,
    subject_expires_at: Timestamp,
    secrets: CountingSecrets,
    allocator: SequentialAllocator,
}

fn register(
    held: &mut Projection,
    log: &mut Vec<CredentialEvent>,
    allocator: &mut SequentialAllocator,
    audience: &str,
    max_ttl: &str,
    sources: Vec<ResourceServerId>,
) -> ResourceServerId {
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new(audience),
            profile: reference_profile(max_ttl),
            allowed_exchange_sources: sources,
        },
        held,
        allocator,
    )
    .expect("a free audience in the caller's own organization");
    held.apply(&registered.event)
        .expect("a readable registration");
    log.push(registered.event);
    registered.resource_server_id
}

fn world() -> World {
    let mut held = Projection::default();
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();
    let mut secrets = CountingSecrets::new();
    let source = register(
        &mut held,
        &mut log,
        &mut allocator,
        "api-s",
        "PT1H",
        Vec::new(),
    );
    let target = register(
        &mut held,
        &mut log,
        &mut allocator,
        "platform-api",
        "PT2H",
        vec![source],
    );
    let closed = register(
        &mut held,
        &mut log,
        &mut allocator,
        "closed-api",
        "PT1H",
        Vec::new(),
    );
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context(),
            target: source,
            requested_scope: scope(&["read", "write"]),
        },
        &at(ISSUED),
        &held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut secrets,
            allocator: &mut allocator,
        },
    )
    .expect("an issuance for an enabled source");
    held.apply(&issued.event).expect("a readable issuance");
    log.push(issued.event);
    World {
        log,
        held,
        source,
        target,
        closed,
        subject_credential: issued.credential,
        subject_credential_id: issued.credential_id,
        subject_expires_at: issued.descriptor.expires_at,
        secrets,
        allocator,
    }
}

fn proof_of(secret: &CredentialSecret) -> CredentialProof {
    CredentialProof::from_bytes(secret.expose_bytes().to_vec())
}

fn input(world: &World, target: ResourceServerId) -> ExchangeCredential {
    ExchangeCredential {
        subject_proof: proof_of(&world.subject_credential),
        actor_proof: None,
        target,
        requested_scope: scope(&["read"]),
        delegation_id: None,
    }
}

/// Run the exchange over the world's own ports, answering the outcome and how many secrets
/// and identities it drew.
fn exchange(
    world: &mut World,
    input: &ExchangeCredential,
    instant: &str,
) -> (
    Result<mandate_sts::issue::CredentialIssued, Box<ExchangeRefused>>,
    u32,
    bool,
) {
    let minted_before = world.secrets.minted();
    let mut untouched = world.allocator.clone();
    let outcome = exchange_credential(
        input,
        &at(instant),
        &world.held,
        ExchangeParts {
            digest: &Sha256Digest,
            resolution: &world.held,
            secrets: &mut world.secrets,
            allocator: &mut world.allocator,
        },
    );
    let drew_identity = world.allocator.next_credential_id() != untouched.next_credential_id();
    (
        outcome,
        world.secrets.minted() - minted_before,
        drew_identity,
    )
}

/// A refusal records `TokenExchangeDenied` for the requested target and draws nothing.
fn refused_drawing_nothing(
    world: &mut World,
    input: &ExchangeCredential,
    instant: &str,
    clause: DenialClause,
) {
    let (outcome, minted, drew) = exchange(world, input, instant);
    let refused = outcome.expect_err("the exchange is refused");
    assert_eq!(refused.denied.clause, clause, "{refused:?}");
    match &refused.event {
        CredentialEvent::TokenExchangeDenied {
            requested_target,
            requested_scope,
            ..
        } => {
            assert_eq!(*requested_target, input.target);
            assert_eq!(*requested_scope, input.requested_scope);
        }
        other => panic!("a refusal records TokenExchangeDenied, got {other:?}"),
    }
    assert_eq!(
        refused.event.ess_name(),
        "mandate.credential.TokenExchangeDenied"
    );
    assert_eq!(minted, 0, "a refusal mints no secret");
    assert!(!drew, "a refusal hands out no identity");
    // Nothing the refusal carries is a record: the fold is where it was.
    let mut refolded = Projection::fold(&world.log).expect("the same log");
    refolded
        .apply(&refused.event)
        .expect("a denial folds into no record");
    assert_eq!(refolded, world.held, "a refusal writes no record");
}

#[test]
fn an_admitted_source_is_exchanged_for_a_credential_for_the_target() {
    let mut world = world();
    let request = input(&world, world.target);
    let (outcome, minted, drew) = exchange(&mut world, &request, "2026-09-19T00:10:00Z");
    let issued = outcome.expect("the target admits the source");
    assert_eq!(minted, 1, "one secret for the one credential");
    assert!(drew, "one identity for the one credential");

    let CredentialEvent::TokenExchangeAllowed {
        context,
        credential_id,
        target,
        descriptor,
        requested_scope,
        reference_verifier,
        ..
    } = &issued.event
    else {
        panic!(
            "an admitted exchange emits TokenExchangeAllowed, got {:?}",
            issued.event
        );
    };
    assert_eq!(
        issued.event.ess_name(),
        "mandate.credential.TokenExchangeAllowed"
    );
    assert_eq!(*target, world.target);
    assert_eq!(*credential_id, issued.credential_id);
    assert_ne!(issued.credential_id, world.subject_credential_id);
    assert!(reference_verifier.is_some(), "the record keeps a verifier");
    assert_eq!(*requested_scope, scope(&["read"]));
    // The issued credential is the target's, for the same subject and organization.
    assert_eq!(descriptor.audience, Audience::new("platform-api"));
    assert_eq!(descriptor.subject, subject());
    assert_eq!(descriptor.organization, organization());
    assert_eq!(descriptor.actor, None, "subject-only: no actor");
    assert_eq!(descriptor.delegation, None, "subject-only: no delegation");
    assert_eq!(descriptor.scope, scope(&["read"]));
    // The context the event carries is the one the subject credential validated to.
    assert_eq!(context.subject, subject());
    assert_eq!(context.organization, organization());
    assert_eq!(context.credential, world.subject_credential_id);

    // Folded, it is answered active to a caller for the target.
    world.held.apply(&issued.event).expect("the exchange folds");
    let exchanged = proof_of(&issued.credential);
    let introspected = introspect_credential(
        &IntrospectCredential {
            caller_proof: exchanged.clone(),
            credential_proof: exchanged,
        },
        &at("2026-09-19T00:11:00Z"),
        &world.held,
        IntrospectionParts {
            digest: &Sha256Digest,
            resolution: &world.held,
        },
    )
    .expect("the exchanged credential is a caller for the target");
    assert!(introspected.active, "the exchanged credential is usable");
    assert_eq!(introspected.credential_id, Some(issued.credential_id));
}

#[test]
fn the_exchanged_credential_expires_no_later_than_the_subject_credential() {
    let mut world = world();
    let request = input(&world, world.target);
    // Fifty minutes into the subject credential's hour; the target's profile would give two.
    let (outcome, _, _) = exchange(&mut world, &request, "2026-09-19T00:50:00Z");
    let issued = outcome.expect("an admitted exchange");
    assert_eq!(issued.descriptor.expires_at, world.subject_expires_at);
}

#[test]
fn a_source_the_target_does_not_admit_is_refused_and_draws_nothing() {
    let mut world = world();
    let request = input(&world, world.closed);
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::SourceUnadmitted,
    );
}

#[test]
fn the_source_itself_is_not_an_admitted_target() {
    let mut world = world();
    let request = input(&world, world.source);
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::SourceUnadmitted,
    );
}

#[test]
fn an_unknown_target_is_refused_and_draws_nothing() {
    let mut world = world();
    let request = input(&world, ResourceServerId::new(uuid(0x99)));
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::TargetUnregistered,
    );
}

#[test]
fn an_expired_subject_credential_is_refused_and_draws_nothing() {
    let mut world = world();
    let request = input(&world, world.target);
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T01:00:00Z",
        DenialClause::SubjectTokenInvalid,
    );
}

#[test]
fn a_revoked_subject_credential_is_refused_and_draws_nothing() {
    let mut world = world();
    let revoked = CredentialEvent::AccessCredentialRevoked {
        context: context(),
        id: world.subject_credential_id,
    };
    world.held.apply(&revoked).expect("a readable revocation");
    world.log.push(revoked);
    let request = input(&world, world.target);
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::SubjectTokenInvalid,
    );
}

#[test]
fn an_unknown_subject_credential_is_refused_and_draws_nothing() {
    let mut world = world();
    let mut request = input(&world, world.target);
    request.subject_proof = CredentialProof::from_bytes(b"no-such-credential".to_vec());
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::SubjectTokenInvalid,
    );
}

#[test]
fn an_empty_subject_proof_is_refused_as_malformed_and_draws_nothing() {
    let mut world = world();
    let mut request = input(&world, world.target);
    request.subject_proof = CredentialProof::from_bytes(Vec::new());
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::ProofMalformed,
    );
}

#[test]
fn an_actor_or_a_delegation_is_refused_because_the_exchange_is_subject_only() {
    let mut world = world();
    let mut with_actor = input(&world, world.target);
    with_actor.actor_proof = Some(proof_of(&world.subject_credential));
    refused_drawing_nothing(
        &mut world,
        &with_actor,
        "2026-09-19T00:10:00Z",
        DenialClause::ExchangeNotSubjectOnly,
    );

    let mut with_delegation = input(&world, world.target);
    with_delegation.delegation_id = Some(DelegationId::new(uuid(0xde)));
    refused_drawing_nothing(
        &mut world,
        &with_delegation,
        "2026-09-19T00:10:00Z",
        DenialClause::ExchangeNotSubjectOnly,
    );
}

#[test]
fn a_scope_wider_than_the_subject_credential_is_refused_and_draws_nothing() {
    let mut world = world();
    let mut request = input(&world, world.target);
    request.requested_scope = scope(&["read", "admin"]);
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::ScopeNotNarrowed,
    );
}

#[test]
fn a_denial_records_the_subject_context_when_the_subject_credential_resolved() {
    let mut world = world();
    let request = input(&world, world.closed);
    let (outcome, _, _) = exchange(&mut world, &request, "2026-09-19T00:10:00Z");
    let refused = outcome.expect_err("the closed target admits no source");
    let CredentialEvent::TokenExchangeDenied { context, .. } = &refused.event else {
        panic!("a TokenExchangeDenied record");
    };
    let context = context.as_ref().expect("the subject credential resolved");
    assert_eq!(context.subject, subject());
    assert_eq!(context.credential, world.subject_credential_id);

    let mut unknown = input(&world, world.target);
    unknown.subject_proof = CredentialProof::from_bytes(b"no-such-credential".to_vec());
    let (outcome, _, _) = exchange(&mut world, &unknown, "2026-09-19T00:10:00Z");
    let refused = outcome.expect_err("an unknown subject credential");
    let CredentialEvent::TokenExchangeDenied { context, .. } = &refused.event else {
        panic!("a TokenExchangeDenied record");
    };
    assert_eq!(
        *context, None,
        "no context is invented for a proof that resolved to nothing"
    );
}

#[test]
fn a_scope_in_another_space_than_the_subject_credential_is_refused() {
    let mut world = world();
    let mut request = input(&world, world.target);
    request.requested_scope.space = Some(mandate_types::SpaceId::new(uuid(0x5a)));
    refused_drawing_nothing(
        &mut world,
        &request,
        "2026-09-19T00:10:00Z",
        DenialClause::ScopeNotNarrowed,
    );
}

// ------------------------------------------- correction round 1, F4: a target named by audience

/// The same request, naming its target by the audience a registration holds.
fn by_audience(world: &World, audience: &str) -> mandate_sts::exchange::ExchangeRequest {
    mandate_sts::exchange::ExchangeRequest {
        subject_proof: proof_of(&world.subject_credential),
        actor_proof: None,
        target: mandate_sts::exchange::ExchangeTarget::Audience(Audience::new(audience)),
        requested_scope: scope(&["read"]),
        delegation_id: None,
    }
}

fn exchange_by_audience(
    world: &mut World,
    request: &mandate_sts::exchange::ExchangeRequest,
) -> (
    Result<mandate_sts::issue::CredentialIssued, Box<ExchangeRefused>>,
    u32,
    bool,
) {
    let minted_before = world.secrets.minted();
    let mut untouched = world.allocator.clone();
    let outcome = mandate_sts::exchange::exchange_request(
        request,
        &at("2026-09-19T00:10:00Z"),
        &world.held,
        ExchangeParts {
            digest: &Sha256Digest,
            resolution: &world.held,
            secrets: &mut world.secrets,
            allocator: &mut world.allocator,
        },
    );
    let drew = world.allocator.next_credential_id() != untouched.next_credential_id();
    (outcome, world.secrets.minted() - minted_before, drew)
}

#[test]
fn a_target_named_by_its_registered_audience_is_resolved_in_the_subjects_organization() {
    let mut world = world();
    let request = by_audience(&world, "platform-api");
    let (outcome, minted, drew) = exchange_by_audience(&mut world, &request);
    let issued = outcome.expect("one enabled registration holds the name");
    assert_eq!((minted, drew), (1, true));
    let CredentialEvent::TokenExchangeAllowed { target, .. } = &issued.event else {
        panic!("TokenExchangeAllowed, got {:?}", issued.event);
    };
    assert_eq!(
        *target, world.target,
        "the name resolved to T's own identity"
    );
    assert_eq!(issued.descriptor.audience, Audience::new("platform-api"));
}

/// No registration of the subject's organization holds the name: refused, recorded, nothing
/// drawn. The name another organization holds is not looked at.
#[test]
fn an_audience_no_registration_of_the_subjects_organization_holds_is_refused_and_recorded() {
    let mut world = world();
    let foreign = register_resource_server(
        &RegisterResourceServer {
            context: VerifiedContext {
                organization: OrganizationId::new(uuid(0x0b)),
                ..context()
            },
            audience: Audience::new("foreign-api"),
            profile: reference_profile("PT1H"),
            allowed_exchange_sources: Vec::new(),
        },
        &world.held,
        &mut world.allocator.clone(),
    )
    .expect("a free audience in another organization");
    world
        .held
        .apply(&foreign.event)
        .expect("a readable registration");
    for name in ["nothing-holds-this", "foreign-api"] {
        let request = by_audience(&world, name);
        let (outcome, minted, drew) = exchange_by_audience(&mut world, &request);
        let refused = outcome.expect_err("no registration of the organization holds it");
        assert_eq!(
            refused.denied.clause,
            DenialClause::TargetUnregistered,
            "{name}"
        );
        assert!(
            matches!(
                refused.event,
                CredentialEvent::TokenExchangeDenied {
                    requested_target: mandate_sts::exchange::UNRESOLVED_TARGET,
                    context: Some(_),
                    ..
                }
            ),
            "{name}: recorded against the unresolved target, with the subject's context"
        );
        assert_eq!((minted, drew), (0, false), "{name}: nothing drawn");
    }
}

/// Two enabled registrations of the organization hold one name — the race
/// `mandate_token::projection` records as ordinary — so the name is not one target, and it is
/// refused rather than resolved to either.
#[test]
fn an_audience_two_registrations_hold_is_refused_rather_than_resolved_to_either() {
    let mut world = world();
    let twin = CredentialEvent::ResourceServerRegistered {
        context: context(),
        id: ResourceServerId::new(uuid(0x77)),
        audience: Audience::new("platform-api"),
        credential_profile: reference_profile("PT2H"),
        allowed_exchange_sources: vec![world.source],
    };
    world
        .held
        .apply(&twin)
        .expect("the log records both registrations");
    let request = by_audience(&world, "platform-api");
    let (outcome, minted, drew) = exchange_by_audience(&mut world, &request);
    let refused = outcome.expect_err("two registrations answer the name");
    assert_eq!(refused.denied.clause, DenialClause::TargetUnregistered);
    assert!(matches!(
        refused.event,
        CredentialEvent::TokenExchangeDenied { .. }
    ));
    assert_eq!((minted, drew), (0, false));
}
