//! The login road, end to end, over raw `std::net::TcpStream`.
//!
//! No client crate is admitted (`story:product-listener`, ruling D2), so every request here
//! is bytes written to a socket and every response is bytes read back off it. The listener
//! binds `127.0.0.1:0` on a thread and the cases drive the four routes the route table
//! declares, the two documents it publishes, and the refusals.
//!
//! # The doubles used here, named
//!
//! * [`mandate_federation::verifier::ConstructedVerifier`] — a **double** for
//!   `FederationVerifier`. It performs no cryptography and returns the [`VerifiedProof`] it
//!   was built with. A real signed proof needs `jsonwebtoken`, which is not in this
//!   package's dependency ceiling (`dependency-boundaries.json`), so the real
//!   `mandate_federation::verifier_real::RealVerifier` is what `src/main.rs` wires and what
//!   no case here can reach.
//! * [`mandate_federation::verifier_real::FixedClock`] — a **double** for `Clock`, so the
//!   road is decided at one stated instant rather than at whatever the host clock reads.
//! * [`mandate_sts::CountingSecrets`] and [`mandate_sts::SequentialAllocator`] — **doubles**
//!   for `SecretSource` and `IdentityAllocator`. Both mint predictable values; `src/main.rs`
//!   wires the system CSPRNG.
//!
//! Everything else is the shipped path: the decoders, the route table, the two documents,
//! the three port adapters, the folds and the four handlers.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration as HostDuration;

use mandate_control_plane::adapters::{Configuration, Deployment};
use mandate_control_plane::serve::{Limits, Listener};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_sts::code::CodeLifetime;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::Projection as CredentialProjection;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialKind, Duration, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OAuthClientId,
    OrganizationId, PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee,
    SigningAlgorithm, Timestamp, Uuid, VerifiedContext,
};

/// RFC 7636 appendix B's code verifier and the S256 challenge of it.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const REDIRECT: &str = "https://client.example/callback";
const ISSUER: &str = "https://mandate.example";

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
        correlation: CorrelationId::new("serve"),
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

/// The verifier double: it returns exactly the proof the connection is configured for.
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

/// A deployment holding one connection, one link, one public client and one registered
/// target — the smallest world the login road needs.
fn deployment() -> (Wired, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let registered = register_resource_server(
        &RegisterResourceServer {
            context: context(),
            audience: Audience::new("https://api.example"),
            profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        },
        &CredentialProjection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let target = registered.resource_server_id;

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
    );

    deployment
        .record_credential(&registered.event)
        .expect("a readable credential history");
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
    (deployment, target)
}

/// Bind on an ephemeral port and serve the road on a thread of its own.
fn serving() -> (SocketAddr, ResourceServerId) {
    let listener = Listener::bind(
        "127.0.0.1:0",
        Limits {
            read_timeout: HostDuration::from_millis(400),
            ..Limits::default()
        },
    )
    .expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let (mut deployment, target) = deployment();
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    (address, target)
}

/// One response, as the bytes off the socket.
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
}

/// Write raw bytes and read the whole response back; the listener closes the connection.
fn exchange(address: SocketAddr, raw: &[u8]) -> Response {
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(5)))
        .expect("a read bound on the case's own socket");
    stream.write_all(raw).expect("the request is written");
    stream.flush().expect("the request is flushed");
    read_response(&mut stream)
}

fn read_response(stream: &mut TcpStream) -> Response {
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("the response is read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("a response with a head and a body, got {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("a status line");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("a status code in {status_line:?}"));
    let headers = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    Response {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// Percent-encode everything outside RFC 3986's unreserved set.
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

fn get(path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut raw = format!("GET {path} HTTP/1.1\r\nHost: mandate.example\r\n");
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    raw.into_bytes()
}

fn post(path: &str, media_type: &str, body: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut raw = format!(
        "POST {path} HTTP/1.1\r\nHost: mandate.example\r\nContent-Type: {media_type}\r\n\
         Content-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    raw.push_str(body);
    raw.into_bytes()
}

fn member(body: &str, name: &str) -> String {
    let document: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|_| panic!("a JSON body, got {body:?}"));
    document
        .get(name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("a `{name}` member in {body}"))
        .to_owned()
}

/// The `code` the authorization endpoint redirected with.
fn code_of(location: &str) -> String {
    let (_, query) = location
        .split_once('?')
        .expect("a redirect carrying a query");
    let form = mandate_proto::oauth::decode_form(query).expect("a declared query");
    form.get("code").expect("a code parameter").to_owned()
}

// ---------------------------------------------------------------------------------------
// The acceptance: the four road routes answer end to end
// ---------------------------------------------------------------------------------------

#[test]
fn the_login_road_is_served_end_to_end_over_http() {
    let (address, target) = serving();

    // 1. A login opens a session.
    let login = exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &format!(
                r#"{{"connection_id":"{}","proof":"{}"}}"#,
                connection(),
                mandate_types::value::encode_base64(b"an idp proof")
            ),
            &[],
        ),
    );
    assert_eq!(login.status, 200, "the login answered {}", login.body);
    let session_proof = member(&login.body, "session_proof");
    assert!(
        !member(&login.body, "session_id").is_empty(),
        "the declared `session_id` response"
    );

    // 2. An authorization request yields a code.
    let authorize = exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyzzy\
                 &nonce=n-0S6&target={}&scope={}",
                client(),
                encoded(REDIRECT),
                target,
                encoded("read")
            ),
            &[("Authorization", &format!("Bearer {session_proof}"))],
        ),
    );
    assert_eq!(
        authorize.status, 302,
        "RFC 6749 section 4.1.2 answers with a redirect; got {}",
        authorize.body
    );
    let location = authorize
        .header("Location")
        .expect("a Location header")
        .to_owned();
    assert!(
        location.starts_with(REDIRECT),
        "the redirect is the one the client registered, got {location}"
    );
    assert!(
        location.contains("state=xyzzy"),
        "RFC 6749 section 4.1.2 returns the exact state received, got {location}"
    );
    let code = code_of(&location);

    // 3. The token endpoint issues the credential.
    let token = exchange(
        address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &format!(
                "grant_type=authorization_code&client_id={}&code={}&code_verifier={VERIFIER}\
                 &redirect_uri={}",
                client(),
                encoded(&code),
                encoded(REDIRECT)
            ),
            &[],
        ),
    );
    assert_eq!(
        token.status, 200,
        "the token endpoint answered {}",
        token.body
    );
    assert_eq!(
        token.header("Cache-Control"),
        Some("no-store"),
        "RFC 6749 section 5.1"
    );
    assert_eq!(token.header("Pragma"), Some("no-cache"));
    assert_eq!(member(&token.body, "token_type"), "Bearer");
    let credential = member(&token.body, "access_token");

    // 4. Introspection answers active for it.
    let introspect = exchange(
        address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}", encoded(&credential)),
            &[("Authorization", &format!("Bearer {credential}"))],
        ),
    );
    assert_eq!(
        introspect.status, 200,
        "introspection answered {}",
        introspect.body
    );
    let document: serde_json::Value =
        serde_json::from_str(&introspect.body).expect("RFC 7662 section 2.2's JSON");
    assert_eq!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(true),
        "the credential the road just issued is usable; got {}",
        introspect.body
    );
}

#[test]
fn a_generated_command_path_is_refused() {
    let (address, _) = serving();
    for path in [
        "/mandate.credential/commands/RedeemAuthorizationCode",
        "/mandate.federation/commands/AuthorizePublicClient",
        "/mandate.identity/commands/RevokeSession",
    ] {
        let refused = exchange(address, &post(path, "application/json", "{}", &[]));
        assert_eq!(
            refused.status, 404,
            "{path} is not a product route and nothing serves it"
        );
        assert_eq!(
            member(&refused.body, "error"),
            "invalid_request",
            "the refusal is an RFC 6749 error body"
        );
    }
}

#[test]
fn the_metadata_document_lists_only_product_routes() {
    let (address, _) = serving();
    let served = exchange(
        address,
        &get("/.well-known/oauth-authorization-server", &[]),
    );
    assert_eq!(served.status, 200);

    let document: serde_json::Value =
        serde_json::from_str(&served.body).expect("RFC 8414 section 2's JSON");
    for (member_name, path) in [
        ("authorization_endpoint", "/oauth/authorize"),
        ("token_endpoint", "/oauth/token"),
        ("introspection_endpoint", "/oauth/introspect"),
        ("jwks_uri", "/oauth/jwks"),
    ] {
        let advertised = document
            .get(member_name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("a `{member_name}` member in {}", served.body));
        assert_eq!(advertised, format!("{ISSUER}{path}"));
        assert!(
            !mandate_server::routes::is_generated_command_path(path),
            "{path} is a product route and not a generated command projection"
        );
    }
    assert_eq!(
        document.get("issuer").and_then(serde_json::Value::as_str),
        Some(ISSUER)
    );
}

#[test]
fn the_jwks_document_is_served_and_carries_no_private_member() {
    let (address, _) = serving();
    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200);
    let document: serde_json::Value =
        serde_json::from_str(&served.body).expect("RFC 7517 section 5's JSON");
    assert!(
        document
            .get("keys")
            .is_some_and(serde_json::Value::is_array),
        "the set is a `keys` array, got {}",
        served.body
    );
    for private in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        assert!(
            !served.body.contains(&format!("\"{private}\"")),
            "RFC 7517 section 9.2's private members are outside the admitted set"
        );
    }
}

// ---------------------------------------------------------------------------------------
// The transport's own refusals
// ---------------------------------------------------------------------------------------

#[test]
fn a_malformed_request_line_is_refused_without_panicking() {
    let (address, _) = serving();
    let refused = exchange(address, b"this is not a request line\r\n\r\n");
    assert_eq!(refused.status, 400);
    assert_eq!(member(&refused.body, "error"), "invalid_request");

    // And the listener is still serving.
    let served = exchange(
        address,
        &get("/.well-known/oauth-authorization-server", &[]),
    );
    assert_eq!(served.status, 200);
}

#[test]
fn an_oversize_header_block_is_refused() {
    let (address, _) = serving();
    let mut raw = String::from("GET /oauth/jwks HTTP/1.1\r\nHost: mandate.example\r\n");
    for index in 0..512 {
        raw.push_str(&format!("X-Filler-{index}: {}\r\n", "a".repeat(128)));
    }
    raw.push_str("\r\n");
    let refused = exchange(address, raw.as_bytes());
    assert_eq!(
        refused.status, 400,
        "a head this listener will not read is refused by its size"
    );
    assert_eq!(member(&refused.body, "error"), "invalid_request");

    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200, "the listener is still serving");
}

#[test]
fn an_incomplete_request_is_refused_without_panicking() {
    let (address, _) = serving();
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(5)))
        .expect("a read bound on the case's own socket");
    // A request line and one header, and then nothing: the head never terminates.
    stream
        .write_all(b"POST /oauth/token HTTP/1.1\r\nHost: mandate.example\r\n")
        .expect("the partial request is written");
    stream.flush().expect("the partial request is flushed");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("the listener closes rather than holding the connection open");

    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200, "the listener is still serving");
}

#[test]
fn a_keep_alive_request_still_gets_connection_close() {
    let (address, _) = serving();
    let served = exchange(
        address,
        &get("/oauth/jwks", &[("Connection", "keep-alive")]),
    );
    assert_eq!(served.status, 200);
    assert_eq!(
        served.header("Connection"),
        Some("close"),
        "this listener serves one request per connection and says so"
    );
}

#[test]
fn a_product_route_refuses_a_method_it_does_not_declare() {
    let (address, _) = serving();
    let refused = exchange(address, &get("/oauth/token", &[]));
    assert_eq!(refused.status, 405);
    assert_eq!(refused.header("Allow"), Some("POST"));
    assert_eq!(member(&refused.body, "error"), "invalid_request");
}

#[test]
fn the_token_endpoint_refuses_an_unknown_code_as_a_declared_denial() {
    let (address, _) = serving();
    let refused = exchange(
        address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &format!(
                "grant_type=authorization_code&client_id={}&code={}&code_verifier={VERIFIER}\
                 &redirect_uri={}",
                client(),
                encoded(&mandate_types::value::encode_base64(
                    b"a code nothing issued"
                )),
                encoded(REDIRECT)
            ),
            &[],
        ),
    );
    assert_eq!(refused.status, 400);
    assert_eq!(
        member(&refused.body, "error"),
        "invalid_grant",
        "RFC 6749 section 5.2: the grant presented is invalid"
    );
    assert_eq!(refused.header("Cache-Control"), Some("no-store"));
}
