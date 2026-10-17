//! One clock read per request: every instant a request decides is the one instant it was
//! served at (`Deployment::now`'s header).
//!
//! The cases drive the deployment with a clock that moves forward one second on **every**
//! read, the worst a host clock can do to a request whose handling straddles a second. A
//! handler that reads the clock twice sees two instants, and anything it derives from the
//! second read is measured from an instant the request was not served at.
//!
//! The defect these decide: `Deployment::authorize` read the instant once for the request
//! and again for the code's expiry, so a second ticking between the two reads produced an
//! expiry one second past the ceiling `mandate_sts::code` admits (`request.at` plus the
//! code lifetime). The STS refused `ExpiryUnbounded`, which the authorization endpoint
//! answers as `server_error`. The login's session expiry was read the same way.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mandate_control_plane::adapters::{
    Configuration, Deployment, Login, SeededResourceServer, instant,
};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::Clock;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_types::{
    Audience, AuthorityScope, ClientId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, Duration, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject,
    FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PkceChallenge, PkceMethod,
    PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee, SigningAlgorithm, Timestamp,
    Transient, Uuid, VerifiedContext,
};

const ISSUER: &str = "https://mandate.example";
const REDIRECT: &str = "https://client.example/callback";
/// 2026-09-11T00:00:00Z, the clock's first reading.
const START: u64 = 1_789_084_800;
/// `PT8H`, the session lifetime every case configures.
const SESSION_LIFETIME: i64 = 8 * 3600;

/// A clock that answers one second later on every read.
///
/// A clone shares the reading, so a case can see where the clock stands after a request.
#[derive(Debug, Clone)]
struct SteppingClock(Arc<AtomicU64>);

impl SteppingClock {
    fn starting_at(seconds: u64) -> Self {
        Self(Arc::new(AtomicU64::new(seconds)))
    }

    /// The reading the next `unix_seconds` call answers, without taking it.
    fn next(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Clock for SteppingClock {
    fn unix_seconds(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

type Wired = Deployment<ConstructedVerifier, SteppingClock, CountingSecrets, SequentialAllocator>;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("one-clock-read"),
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

/// One connection, one link, one public client and one registered target, served by a
/// clock that steps on every read.
fn deployment(clock: SteppingClock) -> (Wired, ResourceServerId) {
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
        clock,
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");

    for event in &seeded.events {
        deployment
            .record_credential(event)
            .expect("a readable credential history");
    }
    for event in [
        FederationEvent::FederationConnectionCreated {
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
            subject_format: mandate_types::SubjectFormat::MandatePrincipal,
            replaced_connector_id: None,
        },
        FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(),
            principal_id: PrincipalId::new(uuid(0x51)),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        },
        FederationEvent::OAuthClientRegistered {
            context: context(),
            id: client(),
            organization_id: organization(),
            client_type: mandate_types::OAuthClientType::Public,
            secret_verifiers: Vec::new(),
            pkce_required: true,
            trusted_peers: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            id_token_signed_response_alg: None,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
        },
    ] {
        deployment
            .record_federation(&event)
            .expect("a readable federation history");
    }
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

fn authorize_input(login: &Login, target: ResourceServerId) -> decode::AuthorizeClient {
    decode::AuthorizeClient {
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

/// An authorization request whose handling straddles a clock second is issued its code:
/// the code's expiry is measured from the request's one instant, so it sits exactly on the
/// ceiling the STS admits rather than a second past it.
#[test]
fn an_authorization_request_a_clock_second_passes_during_is_issued_its_code() {
    let clock = SteppingClock::starting_at(START);
    let (mut deployment, target) = deployment(clock);
    let login = login(&mut deployment);

    let answered = deployment.authorize(&authorize_input(&login, target));

    let issued = answered.unwrap_or_else(|refused| {
        panic!("a second passing during the request refused it: {refused:?}")
    });
    assert_eq!(issued.state, "state-1");
}

/// A login whose handling straddles a clock second opens a session that expires exactly
/// one session lifetime after the instant the login was served at, never later.
#[test]
fn a_login_a_clock_second_passes_during_expires_one_lifetime_after_its_own_instant() {
    let clock = SteppingClock::starting_at(START);
    let (mut deployment, _) = deployment(clock.clone());
    let served_at = i64::try_from(clock.next()).expect("an instant in range");

    let login = login(&mut deployment);

    assert_eq!(
        login.expires_at,
        instant::at(served_at + SESSION_LIFETIME),
        "the session's expiry is measured from the login's one instant"
    );
}
