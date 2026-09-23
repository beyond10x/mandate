//! Adversary pass 1 on `story:federated-token-exchange`, at the handler.
//!
//! Privilege widening and boundary probes the unit's own suite does not state: a chain of
//! exchanges, a source or target disabled after the subject credential was issued, a target
//! in another organization, the exchanged credential re-presented, and the expiry boundary.

use mandate_sts::exchange::{
    ExchangeCredential, ExchangeParts, ExchangeRefused, exchange_credential,
};
use mandate_sts::issue::{
    CredentialIssued, IssueReferenceCredential, ReferenceParts, Sha256Digest,
    issue_reference_credential,
};
use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, disable_resource_server,
    register_resource_server,
};
use mandate_sts::{CountingSecrets, IdentityAllocator, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause, Projection};
use mandate_types::{
    Action, Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, CredentialProof,
    CredentialSecret, Duration, OrganizationId, PrincipalId, ResourceServerId, RevocationGuarantee,
    Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn context_in(organization: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary"),
    }
}

fn home() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn other() -> OrganizationId {
    OrganizationId::new(uuid(0x0b))
}

fn at(instant: &str) -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("adversary"),
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

fn profile(max_ttl: &str) -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new(max_ttl),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

const ISSUED: &str = "2026-09-19T00:00:00Z";

struct World {
    held: Projection,
    secrets: CountingSecrets,
    allocator: SequentialAllocator,
    /// `S`: the subject credential's registration.
    source: ResourceServerId,
    /// `T`: admits `S`.
    target: ResourceServerId,
    /// `V`: admits `T` only.
    onward: ResourceServerId,
    /// `X`: another organization's registration, admitting nothing.
    foreign: ResourceServerId,
    subject_credential: CredentialSecret,
    subject_expires_at: Timestamp,
}

impl World {
    fn register(
        &mut self,
        organization: OrganizationId,
        audience: &str,
        max_ttl: &str,
        sources: Vec<ResourceServerId>,
    ) -> ResourceServerId {
        let registered = register_resource_server(
            &RegisterResourceServer {
                context: context_in(organization),
                audience: Audience::new(audience),
                profile: profile(max_ttl),
                allowed_exchange_sources: sources,
            },
            &self.held,
            &mut self.allocator,
        )
        .expect("a free audience");
        self.held
            .apply(&registered.event)
            .expect("a readable registration");
        registered.resource_server_id
    }

    fn disable(&mut self, id: ResourceServerId) {
        let event = disable_resource_server(
            &DisableResourceServer {
                id,
                context: context_in(home()),
            },
            &self.held,
        )
        .expect("an enabled registration of the caller's organization");
        self.held.apply(&event).expect("a readable disable");
    }

    fn exchange(
        &mut self,
        subject: &CredentialSecret,
        target: ResourceServerId,
        requested: AuthorityScope,
        instant: &str,
    ) -> (Result<CredentialIssued, Box<ExchangeRefused>>, u32, bool) {
        let minted_before = self.secrets.minted();
        let mut untouched = self.allocator.clone();
        let outcome = exchange_credential(
            &ExchangeCredential {
                subject_proof: CredentialProof::from_bytes(subject.expose_bytes().to_vec()),
                actor_proof: None,
                target,
                requested_scope: requested,
                delegation_id: None,
            },
            &at(instant),
            &self.held,
            ExchangeParts {
                digest: &Sha256Digest,
                resolution: &self.held,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        );
        let drew = self.allocator.next_credential_id() != untouched.next_credential_id();
        (outcome, self.secrets.minted() - minted_before, drew)
    }

    fn refused(
        &mut self,
        subject: &CredentialSecret,
        target: ResourceServerId,
        instant: &str,
        clause: DenialClause,
    ) {
        let before = self.held.clone();
        let (outcome, minted, drew) = self.exchange(subject, target, scope(&["read"]), instant);
        let refused = outcome.expect_err("the exchange is refused");
        assert_eq!(refused.denied.clause, clause, "{refused:?}");
        assert!(matches!(
            refused.event,
            CredentialEvent::TokenExchangeDenied { .. }
        ));
        assert_eq!(minted, 0, "a refusal mints no secret");
        assert!(!drew, "a refusal hands out no identity");
        assert_eq!(self.held, before, "a refusal writes no record");
    }
}

fn world() -> World {
    let mut world = World {
        held: Projection::default(),
        secrets: CountingSecrets::new(),
        allocator: SequentialAllocator::new(),
        source: ResourceServerId::new(uuid(0)),
        target: ResourceServerId::new(uuid(0)),
        onward: ResourceServerId::new(uuid(0)),
        foreign: ResourceServerId::new(uuid(0)),
        subject_credential: CredentialSecret::from_bytes(Vec::new()),
        subject_expires_at: Timestamp::new(ISSUED),
    };
    world.source = world.register(home(), "api-s", "PT1H", Vec::new());
    world.target = world.register(home(), "platform-api", "PT2H", vec![world.source]);
    world.onward = world.register(home(), "onward-api", "PT2H", vec![world.target]);
    world.foreign = world.register(other(), "foreign-api", "PT2H", Vec::new());
    let issued = issue_reference_credential(
        &IssueReferenceCredential {
            context: context_in(home()),
            target: world.source,
            requested_scope: scope(&["read", "write"]),
        },
        &at(ISSUED),
        &world.held,
        ReferenceParts {
            digest: &Sha256Digest,
            secrets: &mut world.secrets,
            allocator: &mut world.allocator,
        },
    )
    .expect("an issuance for an enabled source");
    world
        .held
        .apply(&issued.event)
        .expect("a readable issuance");
    world.subject_credential = issued.credential;
    world.subject_expires_at = issued.descriptor.expires_at;
    world
}

fn seconds(value: &Timestamp) -> i64 {
    // RFC 3339 `YYYY-MM-DDTHH:MM:SS` on one day is enough for these cases.
    let text = value.as_str();
    let hour: i64 = text[11..13].parse().expect("hour");
    let minute: i64 = text[14..16].parse().expect("minute");
    let second: i64 = text[17..19].parse().expect("second");
    assert_eq!(&text[0..10], "2026-09-19", "{text}");
    hour * 3600 + minute * 60 + second
}

/// A chain `S -> T -> V` where `V` admits `T` only: the second hop is admitted by the letter
/// of `allowed_exchange_sources`, and its credential must still expire no later than the
/// original subject credential and carry no wider scope.
#[test]
fn a_chained_exchange_never_outlives_or_widens_the_original_subject() {
    let mut world = world();
    let subject = world.subject_credential.clone();
    let (first, _, _) = world.exchange(
        &subject,
        world.target,
        scope(&["read"]),
        "2026-09-19T00:50:00Z",
    );
    let first = first.expect("T admits S");
    world.held.apply(&first.event).expect("the first hop folds");

    // `V` does not admit `S` directly.
    world.refused(
        &subject,
        world.onward,
        "2026-09-19T00:51:00Z",
        DenialClause::SourceUnadmitted,
    );
    // The first hop's credential may not widen back to `write`.
    let (wider, minted, _) = world.exchange(
        &first.credential,
        world.onward,
        scope(&["read", "write"]),
        "2026-09-19T00:51:00Z",
    );
    assert_eq!(
        wider.expect_err("wider than the first hop").denied.clause,
        DenialClause::ScopeNotNarrowed
    );
    assert_eq!(minted, 0);

    let (second, _, _) = world.exchange(
        &first.credential,
        world.onward,
        scope(&["read"]),
        "2026-09-19T00:59:00Z",
    );
    let second = second.expect("V admits T");
    assert!(
        seconds(&second.descriptor.expires_at) <= seconds(&world.subject_expires_at),
        "{:?} outlives the original subject's {:?}",
        second.descriptor.expires_at,
        world.subject_expires_at
    );
    assert_eq!(second.descriptor.audience, Audience::new("onward-api"));
}

/// The exchanged credential presented again for its own target: `T` does not list `T`.
#[test]
fn the_exchanged_credential_cannot_be_re_exchanged_into_its_own_target() {
    let mut world = world();
    let subject = world.subject_credential.clone();
    let (first, _, _) = world.exchange(
        &subject,
        world.target,
        scope(&["read"]),
        "2026-09-19T00:10:00Z",
    );
    let first = first.expect("T admits S");
    world.held.apply(&first.event).expect("folds");
    world.refused(
        &first.credential,
        world.target,
        "2026-09-19T00:11:00Z",
        DenialClause::SourceUnadmitted,
    );
}

/// The source registration disabled after the subject credential was issued.
#[test]
fn a_subject_credential_of_a_disabled_source_is_refused_and_draws_nothing() {
    let mut world = world();
    world.disable(world.source);
    let subject = world.subject_credential.clone();
    world.refused(
        &subject,
        world.target,
        "2026-09-19T00:10:00Z",
        // Re-pinned by coordinator ruling (M2 correction 2): an unusable subject token is SubjectTokenInvalid.
        DenialClause::SubjectTokenInvalid,
    );
}

#[test]
fn a_disabled_target_is_refused_and_draws_nothing() {
    let mut world = world();
    world.disable(world.target);
    let subject = world.subject_credential.clone();
    world.refused(
        &subject,
        world.target,
        "2026-09-19T00:10:00Z",
        DenialClause::TargetDisabled,
    );
}

#[test]
fn a_target_of_another_organization_is_refused_and_draws_nothing() {
    let mut world = world();
    let subject = world.subject_credential.clone();
    world.refused(
        &subject,
        world.foreign,
        "2026-09-19T00:10:00Z",
        DenialClause::OrganizationMismatch,
    );
}

/// At the instant the subject credential expires, it is no longer exchangeable.
#[test]
fn a_subject_credential_is_not_exchangeable_at_its_own_expiry_instant() {
    let mut world = world();
    let subject = world.subject_credential.clone();
    let expiry = world.subject_expires_at.as_str().to_owned();
    world.refused(
        &subject,
        world.target,
        &expiry,
        // Re-pinned by coordinator ruling (M2 correction 2): an unusable subject token is SubjectTokenInvalid.
        DenialClause::SubjectTokenInvalid,
    );
}

/// A sub-second request instant one fraction before the subject's expiry: the issued
/// credential still expires no later than the subject.
#[test]
fn a_fractional_request_instant_does_not_push_the_expiry_past_the_subject() {
    let mut world = world();
    let subject = world.subject_credential.clone();
    let (outcome, _, _) = world.exchange(
        &subject,
        world.target,
        scope(&["read"]),
        "2026-09-19T00:59:58.999Z",
    );
    let issued = outcome.expect("still live");
    assert!(
        seconds(&issued.descriptor.expires_at) <= seconds(&world.subject_expires_at),
        "{:?} > {:?}",
        issued.descriptor.expires_at,
        world.subject_expires_at
    );
}
