//! `mandate.credential.IssueAuthorizationCode`.
//!
//! The command the control plane's `AuthorizePublicClient` assembles an input for and never
//! calls (`crates/mandate-federation/src/authorize.rs`): the STS decides it, mints the code,
//! and records the non-reversible verifier of it and nothing else.
//!
//! Two things are worth saying about what is checked here. The **target** rule is the one
//! wave B landed for an issuance (`services/sts/src/issue.rs`, `admitted_target`): the
//! registration resolves, it is the caller's organization's, it is enabled, and its
//! published profile issues the family a redemption returns. It is deliberately *not* "and
//! still holds its audience" — `services/sts/tests/adversary_profiles_2.rs` is the case that
//! shows why, and `crates/mandate-token/src/projection.rs` documents the race it comes from.
//! The **client** rule is this command's own: the code is bound to a registered, enabled
//! public client of the same organization, read through a port because
//! `mandate.federation.OAuthClient` is another domain's record and `mandate-sts` has no
//! `mandate-federation` dependency (`dependency-boundaries.json`).

use mandate_sts::code::{
    AuthorizationCodeParts, CodeIssuance, CodeLifetime, IssueAuthorizationCode, OAuthClientReads,
    RecordedClients,
};
use mandate_sts::issue::Sha256Digest;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{
    AuthorizationCode, AuthorizationCodeState, CodeProjection, InMemoryCodeLog, StreamVersion,
};
use mandate_sts::{CountingSecrets, RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{DenialClause, Denied, Projection, RefusedOutcome};
use mandate_token::verifier::{CredentialDomain, verifier_for, verifier_in};
use mandate_types::{
    Audience, AuthorityScope, CorrelationId, CredentialId, CredentialKind, DenialReason, Duration,
    OAuthClientId, OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri,
    ResourceServerId, RevocationGuarantee, SessionId, Timestamp, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("code"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("code"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
}

fn scope() -> AuthorityScope {
    AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
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

fn self_contained_profile() -> CredentialProfile {
    CredentialProfile {
        name: "self-contained".to_owned(),
        kind: CredentialKind::SelfContained,
        revocation: RevocationGuarantee::BoundedOffline,
        max_ttl: Duration::new("PT15M"),
        positive_cache_ttl: Duration::new("PT0S"),
        requires_online_authorization: false,
    }
}

/// The S256 challenge of RFC 7636's own example verifier.
fn challenge() -> PkceChallenge {
    PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
}

/// The redirect the fixture client has registered, and the one every code is issued for.
fn authorized_redirect() -> RedirectUri {
    RedirectUri::new("https://client.example/callback")
}

/// The deployment's code-lifetime ceiling: five minutes, RFC 6749 section 4.1.2's "maximum
/// of 10 minutes" taken conservatively. There is no default — a deployment names it.
fn issuance() -> CodeIssuance {
    CodeIssuance::new(CodeLifetime::new(Duration::new("PT5M")))
}

/// A client the registry answers every question about: registered, enabled, public, and
/// carrying the one redirect these cases issue for.
fn registered_client() -> RecordedClients {
    RecordedClients::new()
        .enabled(client(), organization(10))
        .redirect(client(), authorized_redirect())
}

fn registered(
    organization_id: OrganizationId,
    audience: &str,
    profile: CredentialProfile,
) -> (Projection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization_id),
            audience: Audience::new(audience),
            profile,
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let id = outcome.resource_server_id;
    (
        Projection::fold(&[outcome.event]).expect("one creation"),
        id,
    )
}

fn input(target: ResourceServerId, organization_id: OrganizationId) -> IssueAuthorizationCode {
    IssueAuthorizationCode {
        context: context(organization_id),
        client_id: client(),
        session_id: SessionId::new(uuid(0x5e)),
        target,
        requested_scope: scope(),
        challenge: challenge(),
        method: PkceMethod::S256,
        redirect_uri: authorized_redirect(),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
    }
}

/// One deployment: a registered target, a registered enabled client, a counter of what was
/// minted.
struct Deployment {
    servers: Projection,
    target: ResourceServerId,
    clients: RecordedClients,
    secrets: CountingSecrets,
    allocator: SequentialAllocator,
}

impl Deployment {
    fn new() -> Self {
        let (servers, target) = registered(organization(10), "api-a", reference_profile());
        Self {
            servers,
            target,
            clients: registered_client(),
            secrets: CountingSecrets::new(),
            allocator: SequentialAllocator::new(),
        }
    }

    fn issue(
        &mut self,
        input: &IssueAuthorizationCode,
    ) -> Result<mandate_sts::code::AuthorizationCodeIssuance, Denied> {
        issuance().issue(
            input,
            &request(),
            &self.servers,
            &self.clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut self.secrets,
                allocator: &mut self.allocator,
            },
        )
    }
}

#[test]
fn an_issuance_records_the_verifier_of_the_code_it_returns_and_never_the_code() {
    let mut deployment = Deployment::new();
    let target = deployment.target;

    let outcome = deployment
        .issue(&input(target, organization(10)))
        .expect("a registered enabled target and client of the caller's organization");

    assert_eq!(
        deployment.secrets.minted(),
        1,
        "the code is minted once and returned once"
    );
    let folded = CodeProjection::fold(std::slice::from_ref(&outcome.event)).expect("one creation");
    let recorded = folded
        .authorization_code(&outcome.code_id)
        .expect("the code record");
    assert_eq!(
        recorded.verifier,
        verifier_in(
            &Sha256Digest,
            CredentialDomain::AuthorizationCodeVerifier,
            &outcome.code
        ),
        "the record carries the verifier of the code that was returned"
    );
    let payload = serde_json::to_string(&outcome.event).expect("the payload encodes");
    assert!(
        !payload.contains(
            std::str::from_utf8(mandate_types::Transient::expose_material(&outcome.code))
                .expect("the fixture's secret is text")
        ),
        "the emitted payload does not carry the code: {payload}"
    );
}

/// The code has its own digest domain, so a code presented where a reference secret is
/// expected resolves to nothing and the other way round
/// (`crates/mandate-token/src/verifier.rs`).
#[test]
fn the_code_is_recorded_in_its_own_digest_domain() {
    let mut deployment = Deployment::new();
    let target = deployment.target;

    let outcome = deployment
        .issue(&input(target, organization(10)))
        .expect("a registered enabled target");

    let folded = CodeProjection::fold(&[outcome.event]).expect("one creation");
    let recorded = folded
        .authorization_code(&outcome.code_id)
        .expect("the code record")
        .verifier;
    assert_ne!(
        recorded,
        verifier_for(&Sha256Digest, &outcome.code),
        "a code and a reference secret never share a verifier space"
    );
}

#[test]
fn the_recorded_code_carries_every_declared_field_of_the_request() {
    let mut deployment = Deployment::new();
    let target = deployment.target;
    let input = input(target, organization(10));

    let outcome = deployment
        .issue(&input)
        .expect("a registered enabled target");

    let folded = CodeProjection::fold(&[outcome.event]).expect("one creation");
    assert_eq!(
        folded.authorization_code(&outcome.code_id),
        Some(AuthorizationCode {
            id: outcome.code_id,
            client_id: input.client_id,
            session_id: input.session_id,
            verifier: verifier_in(
                &Sha256Digest,
                CredentialDomain::AuthorizationCodeVerifier,
                &outcome.code
            ),
            challenge: input.challenge.clone(),
            method: input.method,
            redirect_uri: input.redirect_uri.clone(),
            expires_at: input.expires_at.clone(),
            target,
            scope: input.requested_scope.clone(),
            state: AuthorizationCodeState::Issued,
        })
    );
}

/// `code_id` is the command's response identity, minted through the allocator port: no
/// crate in this crate's dependency ceiling generates a UUID.
#[test]
fn the_identity_is_the_allocators_and_two_issuances_are_two_codes() {
    let mut deployment = Deployment::new();
    let target = deployment.target;

    let one = deployment
        .issue(&input(target, organization(10)))
        .expect("the first");
    let two = deployment
        .issue(&input(target, organization(10)))
        .expect("the second");

    assert_ne!(one.code_id, two.code_id);
    assert_ne!(one.code, two.code);
    let folded = CodeProjection::fold(&[one.event, two.event]).expect("two creations, two records");
    assert_eq!(folded.authorization_codes().len(), 2);
}

/// Each refusal, by the clause it names, and none of them mints anything: "fail closed; no
/// credential, authority or lifecycle mutation on refusal".
#[test]
fn each_declared_refusal_names_its_clause_and_mints_nothing() {
    let unregistered = ResourceServerId::new(uuid(0x39));
    let (disabled_target_fold, disabled_target) = {
        let (servers, id) = registered(organization(10), "api-a", reference_profile());
        let event = mandate_sts::registry::disable_resource_server(
            &mandate_sts::registry::DisableResourceServer {
                id,
                context: context(organization(10)),
            },
            &servers,
        )
        .expect("an enabled registration");
        let mut servers = servers;
        servers.apply(&event).expect("the disablement");
        (servers, id)
    };
    let (self_contained_fold, self_contained_target) =
        registered(organization(10), "api-b", self_contained_profile());
    let (other_tenant_fold, other_tenant_target) =
        registered(organization(11), "api-a", reference_profile());

    let cases: Vec<(
        &str,
        Projection,
        RecordedClients,
        IssueAuthorizationCode,
        Denied,
    )> = vec![
        (
            "an unregistered target",
            registered(organization(10), "api-a", reference_profile()).0,
            registered_client(),
            input(unregistered, organization(10)),
            Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered),
        ),
        (
            "a target of another organization",
            other_tenant_fold,
            registered_client(),
            input(other_tenant_target, organization(10)),
            Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::OrganizationMismatch,
            ),
        ),
        (
            "a disabled target",
            disabled_target_fold,
            registered_client(),
            input(disabled_target, organization(10)),
            Denied::new(DenialReason::Denied, DenialClause::TargetDisabled),
        ),
        (
            "a target whose profile issues the other family",
            self_contained_fold,
            registered_client(),
            input(self_contained_target, organization(10)),
            Denied::new(DenialReason::Denied, DenialClause::ProfileUnadmitted),
        ),
        (
            "a client no registration answers for",
            registered(organization(10), "api-a", reference_profile()).0,
            RecordedClients::new(),
            input(
                registered(organization(10), "api-a", reference_profile()).1,
                organization(10),
            ),
            Denied::new(DenialReason::Denied, DenialClause::ClientUnregistered),
        ),
        (
            "a client of another organization",
            registered(organization(10), "api-a", reference_profile()).0,
            RecordedClients::new()
                .enabled(client(), organization(11))
                .redirect(client(), authorized_redirect()),
            input(
                registered(organization(10), "api-a", reference_profile()).1,
                organization(10),
            ),
            Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::ClientOutsideOrganization,
            ),
        ),
        (
            "a disabled client",
            registered(organization(10), "api-a", reference_profile()).0,
            RecordedClients::new()
                .disabled(client(), organization(10))
                .redirect(client(), authorized_redirect()),
            input(
                registered(organization(10), "api-a", reference_profile()).1,
                organization(10),
            ),
            Denied::new(DenialReason::Denied, DenialClause::ClientDisabled),
        ),
        (
            "a challenge that is the S256 challenge of no verifier",
            registered(organization(10), "api-a", reference_profile()).0,
            registered_client(),
            IssueAuthorizationCode {
                challenge: PkceChallenge::new("too-short"),
                ..input(
                    registered(organization(10), "api-a", reference_profile()).1,
                    organization(10),
                )
            },
            Denied::new(
                DenialReason::InvalidCredential,
                DenialClause::ChallengeMalformed,
            ),
        ),
        (
            "an expiry that is not after the request instant",
            registered(organization(10), "api-a", reference_profile()).0,
            registered_client(),
            IssueAuthorizationCode {
                expires_at: Timestamp::new("2026-09-19T00:00:00Z"),
                ..input(
                    registered(organization(10), "api-a", reference_profile()).1,
                    organization(10),
                )
            },
            Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded),
        ),
        (
            "an expiry that names no instant",
            registered(organization(10), "api-a", reference_profile()).0,
            registered_client(),
            IssueAuthorizationCode {
                expires_at: Timestamp::new("whenever"),
                ..input(
                    registered(organization(10), "api-a", reference_profile()).1,
                    organization(10),
                )
            },
            Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded),
        ),
    ];

    for (what, servers, clients, command, expected) in cases {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        let denied = issuance()
            .issue(
                &command,
                &request(),
                &servers,
                &clients,
                AuthorizationCodeParts {
                    digest: &Sha256Digest,
                    secrets: &mut secrets,
                    allocator: &mut allocator,
                },
            )
            .expect_err(what);

        assert_eq!(denied, expected, "{what}");
        assert_eq!(
            denied.outcome,
            RefusedOutcome::Denied,
            "{what}: this command declares no wrong-state outcome"
        );
        assert_eq!(secrets.minted(), 0, "{what}: a refusal mints no code");
    }
}

/// The accepted outcome's event is the only thing that reaches the log, and it reaches it
/// through the same compare-and-set every append goes through.
#[test]
fn the_issued_event_is_appended_as_one_group_on_the_codes_own_stream() {
    let mut deployment = Deployment::new();
    let target = deployment.target;
    let outcome = deployment
        .issue(&input(target, organization(10)))
        .expect("a registered enabled target");
    let mut log = InMemoryCodeLog::new();

    let version = log
        .append(
            &outcome.code_id,
            StreamVersion::INITIAL,
            std::slice::from_ref(&outcome.event),
        )
        .expect("an untouched stream");

    assert_eq!(version, StreamVersion::INITIAL.advance());
    assert_eq!(
        log.projection()
            .authorization_code(&outcome.code_id)
            .map(|code| code.state),
        Some(AuthorizationCodeState::Issued)
    );
}

/// The double answers the port and nothing else: a client it never recorded is unregistered,
/// and "unregistered" and "registered and disabled" are different answers.
#[test]
fn the_client_double_tells_unregistered_from_disabled() {
    let clients = RecordedClients::new()
        .enabled(client(), organization(10))
        .disabled(OAuthClientId::new(uuid(0x0d)), organization(10));

    assert_eq!(
        clients.client_organization(&client()),
        Some(organization(10))
    );
    assert_eq!(clients.is_enabled(&client()), Some(true));
    assert_eq!(
        clients.is_enabled(&OAuthClientId::new(uuid(0x0d))),
        Some(false)
    );
    assert_eq!(
        clients.client_organization(&OAuthClientId::new(uuid(0x0e))),
        None
    );
    assert_eq!(clients.is_enabled(&OAuthClientId::new(uuid(0x0e))), None);
}

/// **A client the registry does not answer "public" for is refused.**
///
/// `IssueAuthorizationCode`'s declared denial names a "registered **public** client"
/// (`credential.yaml`; `docs/architecture/command-obligations.md:13`), and the STS is the
/// second line behind the control-plane adapter that has already decided it: a code bound to
/// a confidential client is a code the authorization-code-with-PKCE road never authorizes.
/// Both values are driven, and so is the reader that cannot answer at all.
#[test]
fn a_client_the_registry_does_not_answer_public_for_is_refused() {
    let (servers, target) = registered(organization(10), "api-a", reference_profile());
    let command = input(target, organization(10));

    let refuse = |clients: &RecordedClients| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        issuance().issue(
            &command,
            &request(),
            &servers,
            clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
    };

    // Registered, enabled, and confidential.
    assert_eq!(
        refuse(
            &RecordedClients::new()
                .confidential(client(), organization(10))
                .redirect(client(), authorized_redirect())
        )
        .expect_err("a confidential client"),
        Denied::new(DenialReason::Denied, DenialClause::ClientNotPublic)
    );

    // A reader that holds no answer has not decided that the client is public.
    assert_eq!(
        refuse(
            &RecordedClients::new()
                .unanswerable(client(), organization(10))
                .redirect(client(), authorized_redirect())
        )
        .expect_err("a reader that cannot answer"),
        Denied::new(DenialReason::Unavailable, DenialClause::ClientNotPublic)
    );

    // And the accepted value, so the case decides the question rather than the refusal.
    refuse(
        &RecordedClients::new()
            .enabled(client(), organization(10))
            .redirect(client(), authorized_redirect()),
    )
    .expect("a registered, enabled, public client");
}

/// **A redirect the client's registration does not carry is refused at issuance.**
///
/// The declared denial names "exact redirect URI". Before this the STS recorded whatever
/// redirect it was handed and honoured it byte for byte at redemption, so a code could be
/// minted bound to a redirect no registration was ever consulted for. The comparison is the
/// same byte-exact one the redemption makes ([`mandate_sts::binding::authorized_redirect`]):
/// a registration that carries `https://client.example/callback` does not carry
/// `https://client.example/callback/`.
#[test]
fn a_redirect_the_registration_does_not_carry_is_refused_at_issuance() {
    let (servers, target) = registered(organization(10), "api-a", reference_profile());

    let refuse = |clients: &RecordedClients, presented: &str| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        issuance().issue(
            &IssueAuthorizationCode {
                redirect_uri: RedirectUri::new(presented),
                ..input(target, organization(10))
            },
            &request(),
            &servers,
            clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
    };
    let registered_one = RecordedClients::new()
        .enabled(client(), organization(10))
        .redirect(client(), authorized_redirect());

    assert_eq!(
        refuse(&registered_one, "https://attacker.example/steal")
            .expect_err("a redirect the registration does not carry"),
        Denied::new(DenialReason::Denied, DenialClause::RedirectUnregistered)
    );
    // Byte-exact, the same way the redemption compares: no normalization of any kind.
    for near in [
        "https://client.example/callback/",
        "https://client.example:443/callback",
        "HTTPS://client.example/callback",
        "https://client.example/%63allback",
    ] {
        assert_eq!(
            refuse(&registered_one, near).expect_err(near),
            Denied::new(DenialReason::Denied, DenialClause::RedirectUnregistered),
            "{near} is not the redirect the registration carries"
        );
    }
    // A reader that holds no redirect set for the client has decided nothing.
    assert_eq!(
        refuse(
            &RecordedClients::new().enabled(client(), organization(10)),
            "https://client.example/callback"
        )
        .expect_err("a reader that cannot answer"),
        Denied::new(
            DenialReason::Unavailable,
            DenialClause::RedirectUnregistered
        )
    );

    refuse(&registered_one, "https://client.example/callback")
        .expect("the exact redirect the registration carries");
}

/// **The deployment's code-lifetime ceiling bounds the expiry, at the bound and either side
/// of it.**
///
/// The contract declares no maximum code lifetime — no entity invariant, no profile field
/// and no `mandate.core` type carries one — so the ceiling is the deployment's and
/// [`CodeIssuance`] takes it as a constructor argument with no default. What the declared
/// denial calls "bounded expiry validation" is therefore two bounds: after the request
/// instant, and no later than the request instant plus this one.
#[test]
fn the_deployments_code_lifetime_ceiling_bounds_the_expiry() {
    let (servers, target) = registered(organization(10), "api-a", reference_profile());
    let clients = registered_client();
    let issue = |bound: &str, expires_at: &str| {
        let mut secrets = CountingSecrets::new();
        let mut allocator = SequentialAllocator::new();
        CodeIssuance::new(CodeLifetime::new(Duration::new(bound))).issue(
            &IssueAuthorizationCode {
                expires_at: Timestamp::new(expires_at),
                ..input(target, organization(10))
            },
            &request(),
            &servers,
            &clients,
            AuthorizationCodeParts {
                digest: &Sha256Digest,
                secrets: &mut secrets,
                allocator: &mut allocator,
            },
        )
    };
    let unbounded = Denied::new(DenialReason::Denied, DenialClause::ExpiryUnbounded);

    // The request instant is 2026-09-19T00:00:00Z and the bound is five minutes.
    issue("PT5M", "2026-09-19T00:04:59Z").expect("inside the ceiling");
    issue("PT5M", "2026-09-19T00:05:00Z").expect("exactly at the ceiling");
    assert_eq!(
        issue("PT5M", "2026-09-19T00:05:01Z").expect_err("one second past the ceiling"),
        unbounded
    );
    assert_eq!(
        issue("PT5M", "9999-12-31T23:59:59Z").expect_err("nearly eight thousand years"),
        unbounded
    );

    // The floor is unchanged, and it is the request instant.
    assert_eq!(
        issue("PT5M", "2026-09-19T00:00:00Z").expect_err("not after the request instant"),
        unbounded
    );
    issue("PT5M", "2026-09-19T00:00:01Z").expect("one second is a lifetime, if short");

    // A bound that names no span is a bound this handler cannot apply, and it fails closed
    // rather than issuing an unbounded code.
    assert_eq!(
        issue("whenever", "2026-09-19T00:01:00Z").expect_err("a bound that names no span"),
        unbounded
    );
    assert_eq!(
        issue("P1M", "2026-09-19T00:01:00Z")
            .expect_err("a calendar designator is not a number of seconds"),
        unbounded
    );
}

/// The ceiling is a value the deployment names and the type carries it verbatim: nothing
/// here supplies one, and two deployments with different ceilings are different issuers.
#[test]
fn the_code_lifetime_is_the_deployments_and_has_no_default() {
    let five = CodeLifetime::new(Duration::new("PT5M"));

    assert_eq!(five.as_duration(), &Duration::new("PT5M"));
    assert_eq!(
        CodeIssuance::new(five.clone()).lifetime(),
        &CodeLifetime::new(Duration::new("PT5M"))
    );
    assert_ne!(five, CodeLifetime::new(Duration::new("PT10M")));
}
