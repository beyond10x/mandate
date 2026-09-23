//! RFC 8693 token exchange at `/oauth/token`, composed: `story:federated-token-exchange`.
//!
//! A federated login opens a session; the code flow issues a credential for resource server
//! `S`; that credential is presented as the `subject_token` of a token-exchange grant naming
//! resource server `T`, whose registration lists `S` among its `allowed_exchange_sources`.
//! What is decided here is the composition's half of the acceptance:
//!
//! - over HTTP, the exchange answers RFC 8693 section 2.2.1's response and the credential it
//!   issues is answered active by `/oauth/introspect`, for the same subject;
//! - in process, an admitted exchange records `TokenExchangeAllowed` and folds the credential
//!   it issued; a refused one records `TokenExchangeDenied` and folds nothing.
//!
//! The doubles are the ones `tests/serve.rs` names — `ConstructedVerifier`, `FixedClock`,
//! `CountingSecrets`, `SequentialAllocator` — and are named here for the same reason.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration as HostDuration;

use mandate_control_plane::adapters::{Configuration, Deployment};
use mandate_control_plane::serve::{Limits, Listener};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_server::decode::{self, Request};
use mandate_sts::code::CodeLifetime;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{CredentialEvent, DenialClause};
use mandate_types::value::encode_base64;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialKind, Duration, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OAuthClientId,
    OrganizationId, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SigningAlgorithm, Timestamp, Uuid, VerifiedContext,
};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://client.example/callback";
const ISSUER: &str = "https://mandate.example";
/// 2026-09-19T00:00:00Z.
const NOW: u64 = 1_789_084_800;

const EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x0c))
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
        correlation: CorrelationId::new("exchange"),
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

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// The three registrations every case reads.
#[derive(Clone, Copy)]
struct Targets {
    /// `S`: the registration the subject credential is issued for.
    source: ResourceServerId,
    /// `T`: admits `S`.
    target: ResourceServerId,
    /// `U`: admits nothing.
    closed: ResourceServerId,
}

/// One connection, one link, one public client and the three registrations.
fn deployment(clock: FixedClock) -> (Wired, Targets) {
    let mut allocator = SequentialAllocator::new();
    let mut registrations = mandate_token::projection::Projection::default();
    let mut events = Vec::new();
    let mut register = |audience: &str, sources: Vec<ResourceServerId>| {
        let registered = register_resource_server(
            &RegisterResourceServer {
                context: context(),
                audience: Audience::new(audience),
                profile: reference_profile(),
                allowed_exchange_sources: sources,
            },
            &registrations,
            &mut allocator,
        )
        .expect("a free audience in the caller's own organization");
        registrations
            .apply(&registered.event)
            .expect("a readable registration");
        events.push(registered.event);
        registered.resource_server_id
    };
    let source = register("https://api.example", Vec::new());
    let target = register("platform-api", vec![source]);
    let closed = register("https://closed.example", Vec::new());

    let mut deployment = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        ConstructedVerifier::admitting(
            &[SigningAlgorithm::new("ES256")],
            VerifiedProof::new(
                Issuer::new("https://idp.example"),
                ExternalSubject::new("subject-1"),
                ClientId::new("mandate-at-idp"),
            ),
        )
        .expect("a non-empty algorithm allowlist"),
        clock,
        CountingSecrets::new(),
        // A fresh allocator: it mints credential identities under a prefix of their own,
        // so none collides with the three registration identities minted above.
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
    for event in &events {
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
                verified_claim_value: None,
            },
            jit_provisioning: false,
        },
        FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(),
            principal_id: principal(),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        },
        FederationEvent::OAuthClientRegistered {
            context: context(),
            id: client(),
            organization_id: organization(),
            public: true,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
        },
    ] {
        deployment
            .record_federation(&event)
            .expect("a readable federation history");
    }
    (
        deployment,
        Targets {
            source,
            target,
            closed,
        },
    )
}

// ------------------------------------------------------------------ the in-process road

fn form(path: &str, body: &str) -> Request {
    Request::new("POST", path)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(body.as_bytes().to_vec())
}

fn encoded(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A login, an authorization for `target` and a redemption, in process: the credential the
/// code flow issues, in its wire form.
fn code_flow_credential(deployment: &mut Wired, target: ResourceServerId) -> String {
    let login = deployment
        .authenticate(
            &decode::authenticate_federation(
                &Request::new("POST", "/v1/federation/login")
                    .with_header("Content-Type", "application/json")
                    .with_body(
                        format!(
                            r#"{{"connection_id":"{}","proof":"{}"}}"#,
                            connection(),
                            encode_base64(b"an idp proof")
                        )
                        .into_bytes(),
                    ),
            )
            .expect("a declared login"),
        )
        .expect("the login opens a session");
    let authorization = deployment
        .authorize(
            &decode::authorize_public_client(
                &Request::new(
                    "GET",
                    &format!(
                        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                         &code_challenge={CHALLENGE}&code_challenge_method=S256&state=s\
                         &nonce=n&target={target}&scope=read%20write",
                        client(),
                        encoded(REDIRECT)
                    ),
                )
                .with_header(
                    "Authorization",
                    &format!(
                        "Bearer {}",
                        encode_base64(login.session_proof.expose_bytes())
                    ),
                ),
            )
            .expect("a declared authorization request"),
        )
        .expect("the authorization issues a code");
    let token = deployment
        .redeem(
            &decode::redeem_authorization_code(&form(
                "/oauth/token",
                &format!(
                    "grant_type=authorization_code&client_id={}&code={}&code_verifier={VERIFIER}\
                     &redirect_uri={}",
                    client(),
                    encoded(&encode_base64(authorization.code.expose_bytes())),
                    encoded(REDIRECT)
                ),
            ))
            .expect("a declared token request"),
        )
        .expect("the code redeems");
    encode_base64(token.credential.expose_bytes())
}

fn exchange_body(subject_token: &str, target: ResourceServerId, scope: &str) -> String {
    format!(
        "grant_type={}&subject_token={}&subject_token_type={}&audience={target}&scope={}",
        encoded(EXCHANGE_GRANT),
        encoded(subject_token),
        encoded(ACCESS_TOKEN_TYPE),
        encoded(scope)
    )
}

fn decoded_exchange(body: &str) -> decode::ExchangeCredential {
    decode::exchange_credential(&form("/oauth/token", body)).expect("a declared exchange")
}

#[test]
fn an_admitted_exchange_records_token_exchange_allowed_and_folds_the_credential() {
    let (mut deployment, targets) = deployment(FixedClock::at(NOW));
    let subject_token = code_flow_credential(&mut deployment, targets.source);
    let credentials_before = deployment.credentials().credentials().len();

    let exchanged = deployment
        .exchange(&decoded_exchange(&exchange_body(
            &subject_token,
            targets.target,
            "read",
        )))
        .expect("T admits S");
    assert_eq!(exchanged.descriptor.audience, Audience::new("platform-api"));
    assert_eq!(exchanged.descriptor.subject, principal());
    assert_eq!(exchanged.descriptor.organization, organization());
    assert!(exchanged.expires_in > 0 && exchanged.expires_in <= 3600);

    let recorded = deployment.exchanges();
    assert_eq!(recorded.len(), 1, "one exchange, one record");
    let CredentialEvent::TokenExchangeAllowed {
        credential_id,
        target,
        ..
    } = &recorded[0]
    else {
        panic!(
            "an admitted exchange records TokenExchangeAllowed, got {:?}",
            recorded[0]
        );
    };
    assert_eq!(*credential_id, exchanged.credential_id);
    assert_eq!(*target, targets.target);
    assert_eq!(
        deployment.credentials().credentials().len(),
        credentials_before + 1,
        "the issued credential is folded"
    );
    assert!(
        deployment
            .credentials()
            .access_credential(&exchanged.credential_id)
            .is_some_and(|record| record.target == targets.target)
    );
}

#[test]
fn a_refused_exchange_records_token_exchange_denied_and_folds_nothing() {
    let (mut deployment, targets) = deployment(FixedClock::at(NOW));
    let subject_token = code_flow_credential(&mut deployment, targets.source);
    let before = deployment.credentials().clone();

    for (body, clause) in [
        (
            exchange_body(&subject_token, targets.closed, "read"),
            DenialClause::SourceUnadmitted,
        ),
        (
            exchange_body(&subject_token, ResourceServerId::new(uuid(0x99)), "read"),
            DenialClause::TargetUnregistered,
        ),
        (
            exchange_body(
                &encode_base64(b"no such credential"),
                targets.target,
                "read",
            ),
            DenialClause::CallerProofInvalid,
        ),
        (
            exchange_body(&subject_token, targets.target, "read admin"),
            DenialClause::ScopeNotNarrowed,
        ),
    ] {
        let refused = deployment
            .exchange(&decoded_exchange(&body))
            .expect_err("the exchange is refused");
        assert_eq!(refused.clause, clause, "{body}");
    }
    let recorded = deployment.exchanges();
    assert_eq!(recorded.len(), 4, "every refusal is recorded");
    for record in recorded {
        assert!(
            matches!(record, CredentialEvent::TokenExchangeDenied { .. }),
            "a refusal records TokenExchangeDenied, got {record:?}"
        );
    }
    assert_eq!(
        *deployment.credentials(),
        before,
        "a refusal folds no credential"
    );
}

#[test]
fn an_expired_subject_credential_is_refused_and_recorded() {
    let clock = FixedClock::at(NOW);
    let (mut deployment, targets) = deployment(clock.clone());
    let subject_token = code_flow_credential(&mut deployment, targets.source);
    // The code-flow credential lives for the code's own five minutes at most.
    clock.advance(3600);
    let refused = deployment
        .exchange(&decoded_exchange(&exchange_body(
            &subject_token,
            targets.target,
            "read",
        )))
        .expect_err("an expired subject credential");
    assert_eq!(refused.clause, DenialClause::CallerProofInvalid);
    assert!(matches!(
        deployment.exchanges(),
        [CredentialEvent::TokenExchangeDenied { .. }]
    ));
}

// ------------------------------------------------------------------------- over HTTP

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(presented, _)| presented.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|_| panic!("a JSON body, got {:?}", self.body))
    }
}

fn post(address: SocketAddr, path: &str, body: &str, headers: &[(&str, &str)]) -> Response {
    let mut raw = format!(
        "POST {path} HTTP/1.1\r\nHost: mandate.example\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    raw.push_str(body);
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(5)))
        .expect("a read bound on the case's own socket");
    stream
        .write_all(raw.as_bytes())
        .expect("the request is written");
    let mut read = Vec::new();
    stream.read_to_end(&mut read).expect("the response is read");
    let text = String::from_utf8_lossy(&read).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("a response with a head and a body, got {text:?}"));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    Response {
        status,
        headers: lines
            .filter_map(|line| line.split_once(": "))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        body: body.to_owned(),
    }
}

/// Serve a deployment that has already run the code flow for `S`, and answer the subject
/// token that flow issued.
fn serving() -> (SocketAddr, Targets, String) {
    let (mut deployment, targets) = deployment(FixedClock::at(NOW));
    let subject_token = code_flow_credential(&mut deployment, targets.source);
    let listener = Listener::bind(
        "127.0.0.1:0",
        Limits {
            read_timeout: HostDuration::from_millis(400),
            ..Limits::default()
        },
    )
    .expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    (address, targets, subject_token)
}

#[test]
fn the_exchange_is_served_over_http_and_introspection_answers_its_credential_active() {
    let (address, targets, subject_token) = serving();

    let exchanged = post(
        address,
        "/oauth/token",
        &exchange_body(&subject_token, targets.target, "read"),
        &[],
    );
    assert_eq!(
        exchanged.status, 200,
        "the exchange answered {}",
        exchanged.body
    );
    assert_eq!(exchanged.header("Cache-Control"), Some("no-store"));
    assert_eq!(exchanged.header("Pragma"), Some("no-cache"));
    // RFC 8693 section 2.2.1.
    let document = exchanged.json();
    assert_eq!(document["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(document["token_type"], "Bearer");
    let expires_in = document["expires_in"]
        .as_i64()
        .expect("RFC 8693 section 2.2.1's expires_in, in seconds");
    assert!(expires_in > 0 && expires_in <= 3600, "{expires_in}");
    let credential = document["access_token"]
        .as_str()
        .expect("an access_token")
        .to_owned();
    assert_ne!(
        credential, subject_token,
        "a new credential, not the subject's"
    );

    // The downstream platform validates it by introspection, speaking for `T`.
    let introspected = post(
        address,
        "/oauth/introspect",
        &format!("token={}", encoded(&credential)),
        &[("Authorization", &format!("Bearer {credential}"))],
    );
    assert_eq!(introspected.status, 200, "{}", introspected.body);
    let answer = introspected.json();
    assert_eq!(answer["active"], true, "{}", introspected.body);
    assert_eq!(answer["aud"], "platform-api");
    assert_eq!(answer["sub"], principal().to_string());
}

#[test]
fn a_refused_exchange_is_answered_invalid_request_and_issues_nothing() {
    let (address, targets, subject_token) = serving();
    for body in [
        exchange_body(&subject_token, targets.closed, "read"),
        exchange_body(&subject_token, ResourceServerId::new(uuid(0x99)), "read"),
        exchange_body(
            &encode_base64(b"no such credential"),
            targets.target,
            "read",
        ),
    ] {
        let refused = post(address, "/oauth/token", &body, &[]);
        assert_eq!(refused.status, 400, "{body}: {}", refused.body);
        // RFC 8693 section 2.2.2: the subject token or the target is unacceptable.
        assert_eq!(refused.json()["error"], "invalid_request", "{body}");
        assert_eq!(refused.header("Cache-Control"), Some("no-store"));
        assert!(refused.json().get("access_token").is_none());
    }
    let scoped = post(
        address,
        "/oauth/token",
        &exchange_body(&subject_token, targets.target, "read admin"),
        &[],
    );
    assert_eq!(scoped.status, 400);
    assert_eq!(scoped.json()["error"], "invalid_scope");
}

#[test]
fn the_metadata_document_advertises_the_exchange_grant() {
    let (address, _, _) = serving();
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .write_all(
            b"GET /.well-known/oauth-authorization-server HTTP/1.1\r\nHost: mandate.example\r\n\r\n",
        )
        .expect("the request is written");
    let mut read = String::new();
    stream.read_to_string(&mut read).expect("the response");
    let (_, body) = read.split_once("\r\n\r\n").expect("a body");
    let document: serde_json::Value = serde_json::from_str(body).expect("RFC 8414 JSON");
    let grants: Vec<&str> = document["grant_types_supported"]
        .as_array()
        .expect("grant_types_supported")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(grants.contains(&EXCHANGE_GRANT), "{grants:?}");
    assert!(grants.contains(&"authorization_code"), "{grants:?}");
}
