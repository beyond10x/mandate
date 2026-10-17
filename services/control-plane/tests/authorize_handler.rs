//! `Deployment::authorize` and `Deployment::authorize_browser` deciding what only the handler
//! can read: the target a request resolves to, the trusted peers of the client that backs
//! it, and the organization of the session and of the client.
//!
//! `crates/mandate-server/tests/obligations.rs` names the cases here for the
//! `AuthorizeClient` clauses the handler establishes, because that crate cannot run the
//! handler itself.

use mandate_control_plane::adapters::{
    AuthorizationRefusal, BrowserAuthorization, Configuration, Deployment, Login, Refusal,
    ResourceServerSeed,
};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::Clock;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::CredentialEvent;
use mandate_types::{
    Audience, AuthorityScope, ClientId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DenialReason, Duration, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, Issuer, OAuthClientId, OAuthClientType,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SigningAlgorithm, Timestamp, Transient, Uuid, VerifiedContext,
};

const ISSUER: &str = "https://mandate.example";
/// 2026-09-11T00:00:00Z.
const START: u64 = 1_789_084_800;
const STATE: &str = "state-1";

/// A clock that always answers the same instant.
#[derive(Debug, Clone, Copy)]
struct Fixed;

impl Clock for Fixed {
    fn unix_seconds(&self) -> u64 {
        START
    }
}

type Wired = Deployment<ConstructedVerifier, Fixed, CountingSecrets, SequentialAllocator>;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

/// The organization the session signs in to.
fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

/// Another organization, which the session is not of.
fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0f))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

/// The client every request is made as, unless a case says otherwise.
fn requester() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

/// The client that backs [`backed_target`], listing only [`peer`] as a trusted peer.
fn backing() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0b))
}

/// The client [`backing`] lists.
fn peer() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0d))
}

fn redirect_of(client: OAuthClientId) -> RedirectUri {
    RedirectUri::new(format!("https://client-{client}.example/callback"))
}

fn context(organization: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("authorize-handler"),
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

/// A public client of `organization`, registered with its own redirect, listing `peers`.
fn registered(
    id: OAuthClientId,
    organization: OrganizationId,
    peers: Vec<OAuthClientId>,
) -> FederationEvent {
    FederationEvent::OAuthClientRegistered {
        context: context(organization),
        id,
        organization_id: organization,
        client_type: OAuthClientType::Public,
        secret_verifiers: Vec::new(),
        pkce_required: true,
        trusted_peers: peers,
        post_logout_redirect_uris: Vec::new(),
        redirect_uris: vec![redirect_of(id)],
        pkce_method: PkceMethod::S256,
    }
}

/// The resource server `tag` of the session's organization, backed by `client` when one is
/// named.
fn server(deployment: &mut Wired, tag: u8, client: Option<OAuthClientId>) -> ResourceServerId {
    let mut allocated = 0_u8;
    let seeded = ResourceServerSeed {
        resource_server_id: Some(ResourceServerId::new(uuid(tag))),
        organization: organization(),
        audience: Audience::new(format!("https://api-{tag}.example")),
        profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
        client_id: client,
    }
    .events(&mut || {
        allocated += 1;
        uuid(allocated)
    });
    for event in &seeded.events {
        deployment
            .record_credential(event)
            .expect("a readable credential history");
    }
    seeded.resource_server_id
}

fn disable_server(deployment: &mut Wired, id: ResourceServerId) {
    deployment
        .record_credential(&CredentialEvent::ResourceServerDisabled {
            context: context(organization()),
            id,
        })
        .expect("the registration was recorded");
}

/// One connection and one link in [`organization`], and the clients the cases name:
/// [`requester`], [`peer`] and [`backing`] (which lists only [`peer`]).
fn deployment() -> Wired {
    let mut deployment = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
        },
        verifier(),
        Fixed,
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
    for event in [
        FederationEvent::FederationConnectionCreated {
            context: context(organization()),
            connection_id: connection(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_values: None,
            },
            jit_provisioning: false,
        },
        FederationEvent::ExternalPrincipalLinked {
            context: context(organization()),
            connection_id: connection(),
            principal_id: PrincipalId::new(uuid(0x51)),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        },
        registered(requester(), organization(), Vec::new()),
        registered(peer(), organization(), Vec::new()),
        registered(backing(), organization(), vec![peer()]),
    ] {
        deployment
            .record_federation(&event)
            .expect("a readable federation history");
    }
    deployment
}

fn login(deployment: &mut Wired) -> Login {
    deployment
        .authenticate(&decode::AuthenticateFederation {
            connection_id: connection(),
            proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
        })
        .expect("a linked principal over a configured connection")
}

fn proof_of(login: &Login) -> CredentialProof {
    CredentialProof::from_bytes(login.session_proof.expose_material().to_vec())
}

fn request(
    login: &Login,
    client: OAuthClientId,
    target: Option<ResourceServerId>,
) -> decode::AuthorizeClient {
    decode::AuthorizeClient {
        client_id: client,
        redirect_uri: redirect_of(client),
        challenge: Some(PkceChallenge::new(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )),
        method: Some(PkceMethod::S256),
        state: STATE.to_owned(),
        nonce: "nonce-1".to_owned(),
        session_proof: proof_of(login),
        target,
        identity_scopes: None,
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
    }
}

/// The browser form of [`request`], presenting `session` and `prompt`.
fn browser(
    client: OAuthClientId,
    session: Option<decode::PresentedSession>,
    prompt: Option<decode::Prompt>,
) -> decode::AuthorizeBrowser {
    decode::AuthorizeBrowser {
        client_id: client,
        redirect_uri: redirect_of(client),
        challenge: Some(PkceChallenge::new(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )),
        method: Some(PkceMethod::S256),
        state: STATE.to_owned(),
        nonce: "nonce-1".to_owned(),
        target: None,
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
        identity_scopes: None,
        session,
        prompt,
        bindings: Vec::new(),
    }
}

/// A refusal at the client's redirect, naming `clause`, with the exact state.
fn at_redirect(client: OAuthClientId, clause: &str) -> AuthorizationRefusal {
    AuthorizationRefusal::AtRedirect {
        refusal: Refusal {
            clause: clause.to_owned(),
            reason: DenialReason::Denied,
        },
        redirect_uri: redirect_of(client),
        state: STATE.to_owned(),
    }
}

/// The refusal an unknown client is answered with: in place, since no redirect is validated.
fn unknown_client() -> AuthorizationRefusal {
    AuthorizationRefusal::InPlace(Refusal {
        clause: "ClientUnknown".to_owned(),
        reason: DenialReason::Denied,
    })
}

// ------------------------------------------------- a named target another client backs

/// "a named target is backed by a client that does not list this client as a trusted peer":
/// a client the backing client does not list is refused at its redirect, and no code is
/// issued for the backing client's audience.
#[test]
fn an_unlisted_client_naming_a_backed_target_is_refused() {
    let mut deployment = deployment();
    let backed = server(&mut deployment, 0xb5, Some(backing()));
    let login = login(&mut deployment);

    let refused = deployment
        .authorize(&request(&login, requester(), Some(backed)))
        .expect_err("the backing client does not list the requester");

    assert_eq!(refused, at_redirect(requester(), "TargetPeerUnlisted"));
}

/// The listed peer, the same request otherwise, is issued its code; and a target that names
/// the requester itself, or no client, needs no listing.
#[test]
fn a_listed_peer_naming_a_backed_target_is_issued_its_code() {
    let mut deployment = deployment();
    let backed = server(&mut deployment, 0xb5, Some(backing()));
    let own = server(&mut deployment, 0xb6, Some(requester()));
    let unbacked = server(&mut deployment, 0xb7, None);
    let login = login(&mut deployment);

    let issued = deployment
        .authorize(&request(&login, peer(), Some(backed)))
        .unwrap_or_else(|refused| panic!("the listed peer is refused: {refused:?}"));
    assert_eq!(issued.state, STATE);
    assert_eq!(issued.redirect_uri, redirect_of(peer()));

    for target in [own, unbacked] {
        deployment
            .authorize(&request(&login, requester(), Some(target)))
            .unwrap_or_else(|refused| panic!("{target}: {refused:?}"));
    }
}

/// A backing client that is disabled lists no one any more.
#[test]
fn a_disabled_backing_client_admits_no_peer() {
    let mut deployment = deployment();
    let backed = server(&mut deployment, 0xb5, Some(backing()));
    deployment
        .record_federation(&FederationEvent::OAuthClientDisabled {
            context: context(organization()),
            id: backing(),
        })
        .expect("the backing client was registered");
    let login = login(&mut deployment);

    let refused = deployment
        .authorize(&request(&login, peer(), Some(backed)))
        .expect_err("a disabled backing client lists no one");

    assert_eq!(refused, at_redirect(peer(), "TargetPeerUnlisted"));
}

// ------------------------------------------------------ the target of an untargeted request

/// "no target is named and not exactly one enabled resource server backs the client": two
/// enabled registrations naming the client are refused rather than chosen between.
#[test]
fn an_untargeted_request_with_two_enabled_backing_servers_is_refused() {
    let mut deployment = deployment();
    server(&mut deployment, 0xa5, Some(requester()));
    server(&mut deployment, 0xa6, Some(requester()));
    let login = login(&mut deployment);

    let refused = deployment
        .authorize(&request(&login, requester(), None))
        .expect_err("two enabled registrations back the client");

    assert_eq!(refused, at_redirect(requester(), "TargetAmbiguous"));
}

/// A disabled registration naming the client is passed over: the one enabled registration
/// is the target, whichever was registered first. With none enabled, the request is
/// refused as one no registration backs.
#[test]
fn an_untargeted_request_passes_over_a_disabled_backing_server() {
    let mut deployment = deployment();
    let first = server(&mut deployment, 0xa5, Some(requester()));
    disable_server(&mut deployment, first);
    let second = server(&mut deployment, 0xa6, Some(requester()));
    let login = login(&mut deployment);

    let issued = deployment
        .authorize(&request(&login, requester(), None))
        .unwrap_or_else(|refused| panic!("the enabled registration is the target: {refused:?}"));
    assert_eq!(issued.state, STATE);

    disable_server(&mut deployment, second);
    let refused = deployment
        .authorize(&request(&login, requester(), None))
        .expect_err("no enabled registration backs the client");
    assert_eq!(refused, at_redirect(requester(), "TargetUnknown"));
}

// ------------------------------------------------- another organization's client, and cookie

/// A client of another organization, enabled or disabled, is answered exactly as a client
/// nobody registered, so a session holder learns nothing about another organization's
/// records.
#[test]
fn a_foreign_client_is_answered_as_an_unknown_one() {
    let mut deployment = deployment();
    let foreign = OAuthClientId::new(uuid(0x1c));
    let foreign_disabled = OAuthClientId::new(uuid(0x1d));
    for event in [
        registered(foreign, other_organization(), Vec::new()),
        registered(foreign_disabled, other_organization(), Vec::new()),
        FederationEvent::OAuthClientDisabled {
            context: context(other_organization()),
            id: foreign_disabled,
        },
    ] {
        deployment
            .record_federation(&event)
            .expect("a readable federation history");
    }
    let login = login(&mut deployment);

    for client in [foreign, foreign_disabled, OAuthClientId::new(uuid(0x1e))] {
        let refused = deployment
            .authorize(&request(&login, client, None))
            .expect_err("no client of this organization");
        assert_eq!(refused, unknown_client(), "{client}");
    }
}

/// A cookie naming a usable session of another organization than the client's is a browser
/// to sign in again, exactly as a cookie naming no usable session: the request is not
/// refused in place. A bearer credential of another organization is still refused.
#[test]
fn a_cookie_of_another_organization_signs_in_again() {
    let mut deployment = deployment();
    let foreign = OAuthClientId::new(uuid(0x1c));
    deployment
        .record_federation(&registered(foreign, other_organization(), Vec::new()))
        .expect("a readable federation history");
    server(&mut deployment, 0xa5, Some(requester()));
    let login = login(&mut deployment);
    let cookie = || Some(decode::PresentedSession::Cookie(proof_of(&login)));

    // The same cookie authorizes its own organization's client: the control.
    assert!(matches!(
        deployment.authorize_browser(&browser(requester(), cookie(), None)),
        Ok(BrowserAuthorization::Authorized(_))
    ));

    // No relying party is configured here, so signing in again is `SessionRequired`, the
    // answer a browser with no usable session gets, and `prompt=none` is `login_required`
    // at the foreign client's own redirect.
    assert!(matches!(
        deployment.authorize_browser(&browser(foreign, cookie(), None)),
        Ok(BrowserAuthorization::SessionRequired)
    ));
    match deployment.authorize_browser(&browser(foreign, cookie(), Some(decode::Prompt::None))) {
        Ok(BrowserAuthorization::LoginRequired {
            redirect_uri,
            state,
        }) => {
            assert_eq!(redirect_uri, redirect_of(foreign));
            assert_eq!(state, STATE);
        }
        other => panic!("login_required at the foreign client's redirect: {other:?}"),
    }

    // A bearer credential is a deliberate presentation, and is refused as before.
    let bearer = deployment.authorize_browser(&browser(
        foreign,
        Some(decode::PresentedSession::Bearer(proof_of(&login))),
        None,
    ));
    assert!(
        matches!(&bearer, Err(refused) if *refused == unknown_client()),
        "{bearer:?}"
    );
}
