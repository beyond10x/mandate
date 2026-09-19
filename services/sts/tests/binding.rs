//! What a redemption re-reads before it consumes anything: the client, the exact redirect,
//! the tenant, and the session's epochs.
//!
//! `RedeemAuthorizationCode`'s declared denial names all four — "client, redirect URI or
//! S256 verifier mismatches; the bound client is disabled; source/session epoch is stale;
//! registered target is disabled or outside the verified tenant" — and its accepted summary
//! says where they are read from: "the generated context on the emitted event takes its
//! subject, organization and audience from the code record and the session it names through
//! the STS's session port ... The epoch whose staleness the denial names is the session's
//! own, resolved through that same port, because a redemption presents no source credential
//! of its own."
//!
//! Each re-read is a function here rather than a paragraph in the redemption, so each can be
//! given the shape it refuses and be shown to name the clause the contract does.

use mandate_sts::binding::{
    EpochStanding, RecordedSessions, SessionBinding, SessionReads, authorized_redirect,
    bound_client, fresh_session, target_in_tenant,
};
use mandate_sts::code::RecordedClients;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::store::{AuthorizationCode, AuthorizationCodeState};
use mandate_sts::{RequestContext, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{DenialClause, Denied, Projection, ResourceServer};
use mandate_types::{
    Audience, AuthorityScope, AuthorizationCodeId, CorrelationId, CredentialId, CredentialKind,
    CredentialVerifier, DenialReason, Duration, EpochSnapshotRef, OAuthClientId, OrganizationId,
    PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SecurityEpochTarget, SessionId, Timestamp, Uuid, VerifiedContext,
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

fn session_id() -> SessionId {
    SessionId::new(uuid(0x5e))
}

fn snapshot() -> EpochSnapshotRef {
    EpochSnapshotRef::new(uuid(0x60))
}

fn subject() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn request() -> RequestContext {
    RequestContext {
        correlation: CorrelationId::new("binding"),
        at: Timestamp::new("2026-09-19T00:00:00Z"),
        epochs: None,
    }
}

fn session() -> SessionBinding {
    SessionBinding {
        id: session_id(),
        subject: subject(),
        organization: organization(10),
        epochs: Some(snapshot()),
        expires_at: Timestamp::new("2026-09-19T12:00:00Z"),
        revoked: false,
    }
}

fn code(target: ResourceServerId) -> AuthorizationCode {
    AuthorizationCode {
        id: AuthorizationCodeId::new(uuid(0xac)),
        client_id: client(),
        session_id: session_id(),
        verifier: CredentialVerifier::new("recorded-verifier"),
        challenge: PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        method: PkceMethod::S256,
        redirect_uri: RedirectUri::new("https://client.example/callback"),
        expires_at: Timestamp::new("2026-09-19T00:05:00Z"),
        target,
        scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
        state: AuthorizationCodeState::Issued,
    }
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: subject(),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("binding"),
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

fn registered(organization_id: OrganizationId, audience: &str) -> (Projection, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &RegisterResourceServer {
            context: context(organization_id),
            audience: Audience::new(audience),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience");
    let id = outcome.resource_server_id;
    (
        Projection::fold(&[outcome.event]).expect("one creation"),
        id,
    )
}

fn enabled_clients() -> RecordedClients {
    RecordedClients::new()
        .enabled(client(), organization(10))
        .redirect(
            client(),
            RedirectUri::new("https://client.example/callback"),
        )
}

/// The port answers three things and nothing else, and each of its "no" answers is its own
/// answer: an unrecorded session is not a revoked one, and an unrecorded snapshot is not a
/// current one.
#[test]
fn the_double_answers_the_port_and_tells_its_three_absences_apart() {
    let sessions = RecordedSessions::new()
        .session(session())
        .current(snapshot());

    assert_eq!(sessions.resolve(&session_id()), Some(session()));
    assert_eq!(sessions.resolve(&SessionId::new(uuid(0x5f))), None);
    assert_eq!(
        sessions.epoch_standing(&snapshot()),
        Some(EpochStanding::Current)
    );
    assert_eq!(
        sessions.epoch_standing(&EpochSnapshotRef::new(uuid(0x61))),
        None,
        "a snapshot the reader does not record is not a current one"
    );

    let stale = RecordedSessions::new().session(session()).stale(
        snapshot(),
        SecurityEpochTarget::Organization(organization(10)),
    );
    assert_eq!(
        stale.epoch_standing(&snapshot()),
        Some(EpochStanding::Stale(SecurityEpochTarget::Organization(
            organization(10)
        )))
    );
}

#[test]
fn a_presented_client_that_is_not_the_codes_is_refused() {
    let (_, target) = registered(organization(10), "api-a");

    let denied = bound_client(
        &code(target),
        &OAuthClientId::new(uuid(0x0d)),
        &organization(10),
        &enabled_clients(),
    )
    .expect_err("the presented client is not the one the code is bound to");

    assert_eq!(
        denied,
        Denied::new(DenialReason::Denied, DenialClause::ClientMismatch)
    );
}

#[test]
fn the_codes_client_is_re_read_against_the_registry_and_the_tenant() {
    let (_, target) = registered(organization(10), "api-a");

    assert_eq!(
        bound_client(
            &code(target),
            &client(),
            &organization(10),
            &RecordedClients::new()
        )
        .expect_err("no registration answers for the client"),
        Denied::new(DenialReason::Denied, DenialClause::ClientUnregistered)
    );
    assert_eq!(
        bound_client(
            &code(target),
            &client(),
            &organization(10),
            &RecordedClients::new().enabled(client(), organization(11))
        )
        .expect_err("the client is another organization's"),
        Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::ClientOutsideOrganization
        )
    );
    assert_eq!(
        bound_client(
            &code(target),
            &client(),
            &organization(10),
            &RecordedClients::new().disabled(client(), organization(10))
        )
        .expect_err("the bound client is disabled"),
        Denied::new(DenialReason::Denied, DenialClause::ClientDisabled)
    );
    bound_client(
        &code(target),
        &client(),
        &organization(10),
        &enabled_clients(),
    )
    .expect("a registered, enabled client of the session's organization");
}

/// **The redirect comparison is byte-exact and normalizes nothing.**
///
/// "Redirect differs from exact registered/authorized URI" (`tests/security/cases.json`,
/// `pkce-redirect`). Every entry here is a URI that some normalizing comparison would call
/// equal to the one the code authorized — case in the scheme or the host, a trailing slash,
/// the default port written out, a percent-encoding of an unreserved character, a dot
/// segment, an empty query or fragment — and each is refused. The class is enumerated rather
/// than sampled, because a comparison that normalized any one of them would admit a redirect
/// the authorization request never authorized.
#[test]
fn the_redirect_comparison_is_byte_exact_and_normalizes_nothing() {
    let (_, target) = registered(organization(10), "api-a");
    let code = code(target);

    for presented in [
        "https://client.example/callback/",
        "https://client.example:443/callback",
        "HTTPS://client.example/callback",
        "https://CLIENT.EXAMPLE/callback",
        "https://client.example/Callback",
        "https://client.example/%63allback",
        "https://client.example/./callback",
        "https://client.example/callback?",
        "https://client.example/callback#",
        "https://client.example/callback ",
        " https://client.example/callback",
        "http://client.example/callback",
    ] {
        assert_eq!(
            authorized_redirect(&code, &RedirectUri::new(presented)).expect_err(presented),
            Denied::new(DenialReason::Denied, DenialClause::RedirectMismatch),
            "{presented} is not the redirect the code authorized"
        );
    }

    authorized_redirect(&code, &RedirectUri::new("https://client.example/callback"))
        .expect("the exact redirect the code authorized");
}

/// **Five conditions, two clauses, and both clauses are phrases the declared denial carries.**
///
/// `RedeemAuthorizationCode`'s denial names "source/session epoch is stale" and, for
/// everything else a session can fail at, nothing nearer than "narrowing/atomic issuance
/// validation fails". So the session's own three failures share
/// [`DenialClause::SessionUnusable`] and the epoch's two share
/// [`DenialClause::SessionEpochStale`], with [`Denied::reason`] carrying what a caller can
/// act on: an invalid credential, a stale epoch, or a reader that could not answer.
#[test]
fn each_way_a_session_fails_the_re_read_names_a_declared_clause() {
    let code = code(registered(organization(10), "api-a").1);
    let unusable = Denied::new(
        DenialReason::InvalidCredential,
        DenialClause::SessionUnusable,
    );

    assert_eq!(
        fresh_session(&code, &RecordedSessions::new(), &request())
            .expect_err("the session resolves to nothing"),
        unusable
    );
    assert_eq!(
        fresh_session(
            &code,
            &RecordedSessions::new()
                .session(SessionBinding {
                    revoked: true,
                    ..session()
                })
                .current(snapshot()),
            &request()
        )
        .expect_err("the session is revoked"),
        unusable
    );
    assert_eq!(
        fresh_session(
            &code,
            &RecordedSessions::new()
                .session(SessionBinding {
                    expires_at: Timestamp::new("2026-09-18T23:00:00Z"),
                    ..session()
                })
                .current(snapshot()),
            &request()
        )
        .expect_err("the session expired before the request instant"),
        unusable
    );
    assert_eq!(
        fresh_session(
            &code,
            &RecordedSessions::new()
                .session(SessionBinding {
                    expires_at: Timestamp::new("whenever"),
                    ..session()
                })
                .current(snapshot()),
            &request()
        )
        .expect_err("a session that cannot be dated is not one this handler certifies"),
        unusable
    );
    // The epoch half, and the reason is what tells its two conditions apart.
    assert_eq!(
        fresh_session(
            &code,
            &RecordedSessions::new().session(session()),
            &request()
        )
        .expect_err("the snapshot the session names resolves to nothing"),
        Denied::new(DenialReason::Unavailable, DenialClause::SessionEpochStale)
    );
    assert_eq!(
        fresh_session(
            &code,
            &RecordedSessions::new().session(session()).stale(
                snapshot(),
                SecurityEpochTarget::Organization(organization(10))
            ),
            &request()
        )
        .expect_err("the generation the snapshot names has moved"),
        Denied::new(DenialReason::StaleEpoch, DenialClause::SessionEpochStale)
    );
}

/// The declared reason for a stale epoch is `StaleEpoch` and not `Denied`: the contract
/// carries one for exactly this, and a redemption that reported it as an ordinary denial
/// would hide the one condition a caller can fix by authenticating again.
#[test]
fn a_stale_session_epoch_is_refused_with_the_declared_reason() {
    let code = code(registered(organization(10), "api-a").1);

    for target in [
        SecurityEpochTarget::Principal(subject()),
        SecurityEpochTarget::Organization(organization(10)),
    ] {
        let sessions = RecordedSessions::new()
            .session(session())
            .stale(snapshot(), target.clone());

        assert_eq!(
            fresh_session(&code, &sessions, &request()).expect_err("the epoch has moved"),
            Denied::new(DenialReason::StaleEpoch, DenialClause::SessionEpochStale)
        );
    }
}

/// A session the reader records with no snapshot at all has no epoch binding to be stale
/// against, and the response's `epochs` is `Optional` for exactly that. It is not read as
/// "unresolved": nothing failed to resolve.
#[test]
fn a_session_that_names_no_snapshot_is_admitted_and_binds_no_epoch() {
    let code = code(registered(organization(10), "api-a").1);
    let sessions = RecordedSessions::new().session(SessionBinding {
        epochs: None,
        ..session()
    });

    let bound = fresh_session(&code, &sessions, &request()).expect("a live session");

    assert_eq!(bound.epochs, None);
    assert_eq!(bound.organization, organization(10));
    assert_eq!(bound.subject, subject());
}

#[test]
fn the_accepted_session_is_the_one_the_code_names() {
    let code = code(registered(organization(10), "api-a").1);
    let sessions = RecordedSessions::new()
        .session(session())
        .current(snapshot());

    let bound = fresh_session(&code, &sessions, &request()).expect("a live, current session");

    assert_eq!(bound, session());
}

#[test]
fn the_target_is_re_read_against_the_organization_the_session_binds() {
    let (servers, target) = registered(organization(10), "api-a");

    assert_eq!(
        target_in_tenant(&code(target), &servers, &organization(11))
            .expect_err("the registration is another organization's"),
        Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch
        )
    );
    assert_eq!(
        target_in_tenant(
            &code(ResourceServerId::new(uuid(0x39))),
            &servers,
            &organization(10)
        )
        .expect_err("no registration answers for the target"),
        Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered)
    );

    let disabled = {
        let event = mandate_sts::registry::disable_resource_server(
            &mandate_sts::registry::DisableResourceServer {
                id: target,
                context: context(organization(10)),
            },
            &servers,
        )
        .expect("an enabled registration");
        let mut servers = servers.clone();
        servers.apply(&event).expect("the disablement");
        servers
    };
    assert_eq!(
        target_in_tenant(&code(target), &disabled, &organization(10))
            .expect_err("the registered target is disabled"),
        Denied::new(DenialReason::Denied, DenialClause::TargetDisabled)
    );

    let admitted: ResourceServer = target_in_tenant(&code(target), &servers, &organization(10))
        .expect("a registered, enabled target of the session's organization");
    assert_eq!(admitted.id, target);
    assert_eq!(admitted.audience, Audience::new("api-a"));
}
