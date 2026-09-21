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

use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration as HostDuration, Instant};

use mandate_control_plane::adapters::{Configuration, Deployment, read_connection_seed, read_key};
use mandate_control_plane::serve::{Limits, Listener};
use mandate_federation::record::{FederationConnection, FederationEvent};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_federation::{Denied as FederationDenied, FederationVerifier};
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::registry::{RegisterResourceServer, register_resource_server};
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::Projection as CredentialProjection;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialKind, CredentialProof, DenialReason,
    Duration, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId,
    Issuer, OAuthClientId, OrganizationId, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    RevocationGuarantee, SigningAlgorithm, Timestamp, Uuid, VerifiedContext,
};

/// RFC 7636 appendix B's code verifier and the S256 challenge of it.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const REDIRECT: &str = "https://client.example/callback";

/// A registered redirection endpoint URI carrying a query component, which RFC 6749
/// section 3.1.2 admits in as many words: "The endpoint URI MAY include an
/// `application/x-www-form-urlencoded` formatted query component ... which MUST be retained
/// when adding additional query parameters."
const REDIRECT_WITH_QUERY: &str = "https://client.example/callback?tenant=acme";

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
/// target — the smallest world the login road needs, with the redirect URI the client
/// registers, the two configured lifetimes and the clock as its parameters.
fn deployment_configured(
    redirect: &str,
    code_lifetime: &str,
    session_lifetime: &str,
    clock: FixedClock,
) -> (Wired, ResourceServerId) {
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
            code_lifetime: CodeLifetime::new(Duration::new(code_lifetime)),
            session_lifetime: Duration::new(session_lifetime),
            keys: Vec::new(),
        },
        verifier(),
        clock,
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");

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
            redirect_uris: vec![RedirectUri::new(redirect)],
            pkce_method: PkceMethod::S256,
        })
        .expect("a readable federation history");
    (deployment, target)
}

/// The limits every case here serves under: the shipped defaults, with a read timeout short
/// enough that a case which stops writing is answered rather than waited on.
fn test_limits() -> Limits {
    Limits {
        read_timeout: HostDuration::from_millis(400),
        ..Limits::default()
    }
}

/// Bind on an ephemeral port and serve the road on a thread of its own.
fn serving_with(redirect: &str, limits: Limits) -> (SocketAddr, ResourceServerId) {
    let (address, target, _) = serving_full(redirect, "PT5M", "PT8H", limits);
    (address, target)
}

/// The same, with both lifetimes stated and the clock handed back so a case can move it.
fn serving_full(
    redirect: &str,
    code_lifetime: &str,
    session_lifetime: &str,
    limits: Limits,
) -> (SocketAddr, ResourceServerId, FixedClock) {
    let listener =
        Listener::bind("127.0.0.1:0", limits).expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let clock = FixedClock::at(NOW);
    let (mut deployment, target) =
        deployment_configured(redirect, code_lifetime, session_lifetime, clock.clone());
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    (address, target, clock)
}

fn serving() -> (SocketAddr, ResourceServerId) {
    serving_with(REDIRECT, test_limits())
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

/// A `POST` whose declared `Content-Length` is stated by the case rather than measured, and
/// whose body is whatever bytes the case puts on the wire. The whole request is written in
/// one call, so the head and every byte behind it arrive in one segment.
fn raw_post(path: &str, media_type: &str, declared_length: &str, on_the_wire: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: mandate.example\r\nContent-Type: {media_type}\r\n\
         Content-Length: {declared_length}\r\n\r\n{on_the_wire}"
    )
    .into_bytes()
}

/// The login body the road opens a session with.
fn login_body() -> String {
    format!(
        r#"{{"connection_id":"{}","proof":"{}"}}"#,
        connection(),
        mandate_types::value::encode_base64(b"an idp proof")
    )
}

/// Open a session and answer with the `session_proof` the login handed back.
fn session_proof(address: SocketAddr) -> String {
    let login = exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &login_body(),
            &[],
        ),
    );
    assert_eq!(login.status, 200, "the login answered {}", login.body);
    member(&login.body, "session_proof")
}

/// The authorization request the road makes, with the redirect and the target as parameters.
fn authorize(
    address: SocketAddr,
    target: ResourceServerId,
    proof: &str,
    redirect: &str,
) -> Response {
    exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyzzy\
                 &nonce=n-0S6&target={target}&scope={}",
                client(),
                encoded(redirect),
                encoded("read")
            ),
            &[("Authorization", &format!("Bearer {proof}"))],
        ),
    )
}

/// The token request body for a presented code.
fn token_body(code: &str, redirect: &str) -> String {
    format!(
        "grant_type=authorization_code&client_id={}&code={}&code_verifier={VERIFIER}\
         &redirect_uri={}",
        client(),
        encoded(code),
        encoded(redirect)
    )
}

/// The query component of a `Location`, decoded as the `application/x-www-form-urlencoded`
/// form RFC 6749 section 4.1.2 makes it.
fn redirect_form(location: &str) -> mandate_proto::oauth::Form {
    let (_, query) = location
        .split_once('?')
        .expect("a redirect carrying a query component");
    mandate_proto::oauth::decode_form(query)
        .unwrap_or_else(|_| panic!("an x-www-form-urlencoded query, got {location}"))
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

// ---------------------------------------------------------------------------------------
// The `Location` the authorization endpoint composes (correction round 1, F1 and F2)
// ---------------------------------------------------------------------------------------

/// RFC 6749 section 3.1.2 admits a query component on the registered redirection endpoint
/// URI and requires it to "be retained when adding additional query parameters"; section
/// 4.1.2 adds `code` and `state` **to the query component** of that URI. So the separator is
/// `&` where the registered URI already carries a `?`, and `?` where it does not — one
/// composer decides it for both branches.
#[test]
fn a_registered_redirect_carrying_a_query_keeps_it_and_adds_the_code_to_it() {
    let (address, target) = serving_with(REDIRECT_WITH_QUERY, test_limits());
    let proof = session_proof(address);
    let answered = authorize(address, target, &proof, REDIRECT_WITH_QUERY);
    assert_eq!(
        answered.status, 302,
        "RFC 6749 section 4.1.2 answers with a redirect; got {}",
        answered.body
    );
    let location = answered
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let form = redirect_form(&location);
    assert_eq!(
        form.get("tenant"),
        Some("acme"),
        "RFC 6749 section 3.1.2: the registered query component is retained, got {location}"
    );
    assert_eq!(
        form.get("state"),
        Some("xyzzy"),
        "RFC 6749 section 4.1.2: the exact state received, got {location}"
    );
    assert!(
        form.get("code").is_some_and(|code| !code.is_empty()),
        "RFC 6749 section 4.1.2: the code is a parameter of the query, got {location}"
    );
}

/// The same composer on the error branch of RFC 6749 section 4.1.2.1: `error` and `state`
/// are parameters of the query, not text behind a second `?`. The refusal driven here — a
/// target outside the client's tenant — is raised after the client and its registered
/// redirect are validated, which is what makes it a redirect rather than a rendered body.
#[test]
fn an_error_redirect_adds_its_parameters_to_a_registered_query() {
    let (address, _) = serving_with(REDIRECT_WITH_QUERY, test_limits());
    let proof = session_proof(address);
    let outside = ResourceServerId::new(uuid(0x77));
    let answered = authorize(address, outside, &proof, REDIRECT_WITH_QUERY);
    assert_eq!(
        answered.status, 302,
        "RFC 6749 section 4.1.2.1 redirects the error to the validated redirect URI; got {}",
        answered.body
    );
    let location = answered
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let form = redirect_form(&location);
    assert_eq!(
        form.get("tenant"),
        Some("acme"),
        "the registered query component is retained on the error branch too, got {location}"
    );
    assert!(
        form.get("error").is_some(),
        "RFC 6749 section 4.1.2.1: `error` is a parameter of the query, got {location}"
    );
    assert_eq!(
        form.get("state"),
        Some("xyzzy"),
        "RFC 6749 section 4.1.2.1: the exact state received, got {location}"
    );
}

// ---------------------------------------------------------------------------------------
// The declared `Content-Length` is the frame (correction round 1, F3)
// ---------------------------------------------------------------------------------------

/// RFC 9112 section 6: the `Content-Length` field value is the message body's length in
/// octets, and it frames the message. Bytes on the connection past that length are not part
/// of this request — to a proxy in front of this listener they are the start of the next one,
/// which is the same disagreement a repeated `Content-Length` is refused for.
///
/// The request declares a truthful length for a token form and puts seven more bytes behind
/// it. Framed honestly, the decoder sees the declared prefix — a well-formed token request
/// naming a code nothing issued, which is `invalid_grant`. If the trailing bytes are read
/// they are an undeclared `evil` parameter and the answer is `invalid_request`.
#[test]
fn bytes_behind_the_declared_content_length_are_not_part_of_the_request() {
    let (address, _) = serving();
    let declared = token_body(
        &mandate_types::value::encode_base64(b"a code nothing issued"),
        REDIRECT,
    );
    let refused = exchange(
        address,
        &raw_post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &declared.len().to_string(),
            &format!("{declared}&evil=1"),
        ),
    );
    assert_eq!(
        member(&refused.body, "error"),
        "invalid_grant",
        "the framed request is the declared {} bytes and the seven behind them are not part \
         of it; got {}",
        declared.len(),
        refused.body
    );
}

/// The same rule at its boundary: a request that declares no body carries none, even when
/// the road's own credential is on the wire behind its head. A credential issued here would
/// be issued for a body this listener was told it did not have.
#[test]
fn a_content_length_of_zero_frames_an_empty_body_and_issues_nothing() {
    let (address, target) = serving();
    let proof = session_proof(address);
    let answered = authorize(address, target, &proof, REDIRECT);
    assert_eq!(
        answered.status, 302,
        "the authorization answered {}",
        answered.body
    );
    let code = code_of(answered.header("Location").expect("a Location header"));

    let refused = exchange(
        address,
        &raw_post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            "0",
            &token_body(&code, REDIRECT),
        ),
    );
    assert_ne!(
        refused.status, 200,
        "RFC 9112 section 6: no grant was presented, so no credential is issued; got {}",
        refused.body
    );
    assert!(
        !refused.body.contains("access_token"),
        "no credential reaches a request that declared an empty body; got {}",
        refused.body
    );
}

/// A declared length above what this listener reads is refused on the declaration, before a
/// body byte is read: the answer is the ceiling refusal and not the "body is incomplete" a
/// listener that waited for bytes nobody sent would reach.
#[test]
fn a_declared_length_above_the_read_bound_is_refused_before_the_body_is_read() {
    let (address, _) = serving();
    let refused = exchange(
        address,
        &raw_post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            "1000000",
            "",
        ),
    );
    assert_eq!(refused.status, 400);
    assert_eq!(
        member(&refused.body, "error_description"),
        "the request is larger than this endpoint reads",
        "the declared length decided it, not the bytes that never arrived; got {}",
        refused.body
    );
}

// ---------------------------------------------------------------------------------------
// `Content-Length = 1*DIGIT` (correction round 1, F4)
// ---------------------------------------------------------------------------------------

/// RFC 9112 section 6.3: `Content-Length = 1*DIGIT`, and a message received without
/// `Transfer-Encoding` and with an invalid `Content-Length` "has invalid framing" the
/// recipient treats as an unrecoverable error. `str::parse::<usize>` admits a leading `+`,
/// so a value no conformant reader accepts was read here as a length — and a proxy that
/// refused it and this listener that accepted it frame the same connection two ways.
#[test]
fn a_content_length_that_is_not_one_star_digit_is_refused() {
    let (address, _) = serving();
    let body = login_body();
    for declared in [
        format!("+{}", body.len()),
        "0x53".to_owned(),
        "8 3".to_owned(),
        "83abc".to_owned(),
        String::new(),
    ] {
        let refused = exchange(
            address,
            &raw_post("/v1/federation/login", "application/json", &declared, &body),
        );
        assert_eq!(
            refused.status, 400,
            "`{declared}` is not 1*DIGIT and the framing is invalid; got {}",
            refused.body
        );
        assert_eq!(member(&refused.body, "error"), "invalid_request");
    }
}

/// The other half of the rule, so that refusing a sign does not become refusing a header
/// RFC 9112 admits: the optional whitespace around a field value is **not** part of the
/// value (RFC 9112 section 5), `httparse` strips it, and what is left is `1*DIGIT` and is
/// served.
#[test]
fn optional_whitespace_around_a_content_length_is_not_part_of_it() {
    let (address, _) = serving();
    let body = login_body();
    for declared in [format!(" {}", body.len()), format!("{} ", body.len())] {
        let served = exchange(
            address,
            &raw_post("/v1/federation/login", "application/json", &declared, &body),
        );
        assert_eq!(
            served.status, 200,
            "`{declared}` trims to 1*DIGIT and frames a login; got {}",
            served.body
        );
    }
}

// ---------------------------------------------------------------------------------------
// The request target's four forms (correction round 1, F7)
// ---------------------------------------------------------------------------------------

/// RFC 9112 section 3.2.2: "a server MUST accept the absolute-form in requests, even though
/// HTTP/1.1 clients will only send them in requests to proxies". The target is reduced to
/// its origin-form before the route lookup, so the route it names is the route it reaches.
#[test]
fn an_absolute_form_request_target_reaches_the_route_it_names() {
    let (address, _) = serving();
    let served = exchange(address, &get(&format!("{ISSUER}/oauth/jwks"), &[]));
    assert_eq!(
        served.status, 200,
        "the absolute-form target names the JWKS route; got {}",
        served.body
    );

    // The reduction keeps the query component and the method the route declares: this one
    // is the token endpoint's path under a method it does not serve.
    let refused = exchange(address, &get("http://mandate.example/oauth/token?a=b", &[]));
    assert_eq!(refused.status, 405, "got {}", refused.body);
    assert_eq!(refused.header("Allow"), Some("POST"));
}

/// RFC 9112 section 3.2 declares four forms and this listener serves two of them. The
/// authority-form is `CONNECT`'s and the asterisk-form is `OPTIONS`'s server-wide target;
/// neither names a path, so neither is dispatched — and neither is silently read as one.
#[test]
fn an_authority_form_or_asterisk_form_target_is_refused() {
    let (address, _) = serving();
    for target in ["mandate.example:443", "*"] {
        let refused = exchange(address, &get(target, &[]));
        assert_eq!(
            refused.status, 400,
            "{target} names no path this listener serves; got {}",
            refused.body
        );
        assert_eq!(member(&refused.body, "error"), "invalid_request");
    }

    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200, "the listener is still serving");
}

// ---------------------------------------------------------------------------------------
// One connection at a time, and the deadline that bounds it (correction round 1, F5)
// ---------------------------------------------------------------------------------------

/// This listener answers one connection at a time (`src/serve.rs`'s accept loop), so the time
/// one client takes is the time every other client waits. What bounds that wait is
/// [`Limits::request_deadline`]: the whole exchange — every read of the head and the body and
/// the write of the response — finishes within it or is refused.
///
/// The probe: one connection dribbles a byte every 200 ms, under the read timeout, so no
/// single read ever times out and only the deadline ends it. A second client sends one
/// complete request for a document that reads no state at all, and is answered within the
/// deadline and a margin rather than within the three seconds the dribble would otherwise
/// take.
#[test]
fn a_second_client_is_answered_within_the_deadline_while_one_connection_dribbles() {
    let deadline = HostDuration::from_millis(600);
    let (address, _) = serving_with(
        REDIRECT,
        Limits {
            request_deadline: deadline,
            ..test_limits()
        },
    );
    let slow = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("the listener accepts");
        // Fifteen bytes of a request line that never ends, one every 200 ms: three seconds
        // of connection, every read of it inside the 400 ms read timeout.
        for byte in b"GET /oauth/jwks" {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(HostDuration::from_millis(200));
        }
    });
    // Long enough that the slow connection is the one being read when the second arrives.
    std::thread::sleep(HostDuration::from_millis(250));

    let started = Instant::now();
    let served = exchange(address, &get("/oauth/jwks", &[]));
    let waited = started.elapsed();
    let _ = slow.join();

    assert_eq!(served.status, 200, "the JWKS document is served");
    assert!(
        waited < deadline + HostDuration::from_millis(500),
        "a second client waited {waited:?} behind one dribbling connection, which the \
         {deadline:?} deadline bounds"
    );
}

/// The connection that lapsed is refused, and the refusal is a response rather than a closed
/// socket: the client learns its request was not framed in time.
#[test]
fn a_request_that_does_not_finish_within_the_deadline_is_refused() {
    let (address, _) = serving_with(
        REDIRECT,
        Limits {
            request_deadline: HostDuration::from_millis(400),
            ..test_limits()
        },
    );
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(5)))
        .expect("a read bound on the case's own socket");
    // Three bytes of a request line, one every 150 ms, and then nothing: every read of them
    // is inside the 400 ms read timeout and only the deadline ends the exchange. The case
    // stops writing before the deadline lapses, so the refusal is read off a connection
    // nothing is still sending into.
    for byte in b"GET" {
        if stream.write_all(&[*byte]).is_err() {
            break;
        }
        let _ = stream.flush();
        std::thread::sleep(HostDuration::from_millis(150));
    }
    let refused = read_response(&mut stream);
    assert_eq!(
        refused.status, 400,
        "the exchange did not finish within the deadline; got {}",
        refused.body
    );
    assert_eq!(member(&refused.body, "error"), "invalid_request");

    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200, "the listener is still serving");
}

// ---------------------------------------------------------------------------------------
// The binary's own refusals (correction round 1, F6)
// ---------------------------------------------------------------------------------------

/// A configuration `clap` accepted is not a configuration this deployment can serve. A
/// `--code-lifetime` naming no span made every authorization request fail while the process
/// ran and answered success to its operator; an issuer that is not an issuer identifier
/// publishes a metadata document naming one that is not.
///
/// Both are refused where they are read, with the refusal on stderr and exit status 2 — which
/// is neither the 0 of a served process nor the 1 of a listener that could not bind.
#[test]
fn a_configuration_the_binary_cannot_serve_is_refused_with_exit_status_two() {
    for (argument, value) in [
        ("--code-lifetime", "PT"),
        ("--session-lifetime", "P1M"),
        ("--issuer", "ftp://mandate.example"),
        ("--issuer", "https://mandate.example?tenant=acme"),
    ] {
        let refused = std::process::Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--issuer",
                "https://mandate.example",
                argument,
                value,
            ])
            .output()
            .expect("the composition binary runs");
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{argument} {value} names a configuration this deployment cannot serve; got {}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            !refused.stderr.is_empty(),
            "{argument} {value} was refused without saying why"
        );
    }
}

// ---------------------------------------------------------------------------------------
// The registered redirection URI has to be able to carry a response (round 2, F1 and F2)
// ---------------------------------------------------------------------------------------

/// RFC 6749 sections 4.1.2 and 4.1.2.1 add `code`, `state` and `error` **to the query
/// component** of the registered redirection URI, and section 3.1.2 requires a query the URI
/// already carries to be retained. Both hold only if the result is still an
/// `application/x-www-form-urlencoded` form — so the registered query is parsed before it is
/// extended, and a URI whose query is not a form, or which already names one of the three
/// response parameters, carries no response at all.
///
/// That is a **client-registration** fault and not the end user's decision, so it is answered
/// in place: RFC 6749 section 4.1.2.1 says a server whose redirection URI is invalid "MUST
/// NOT automatically redirect".
#[test]
fn a_registered_redirect_whose_query_cannot_carry_the_response_is_refused_in_place() {
    for (registered, why) in [
        (
            "https://client.example/callback?x",
            "a segment with no `=` is not a form",
        ),
        (
            "https://client.example/callback?%zz=1",
            "a truncated escape is not a form",
        ),
        (
            "https://client.example/callback?state=registered",
            "a registered `state` would be returned beside the client's own",
        ),
        (
            "https://client.example/callback?code=already",
            "a registered `code` would be returned beside the issued one",
        ),
        (
            "https://client.example/callback?error=none",
            "a registered `error` would be read as a refusal",
        ),
    ] {
        let (address, target) = serving_with(registered, test_limits());
        let proof = session_proof(address);
        let refused = authorize(address, target, &proof, registered);
        assert_eq!(
            refused.status, 400,
            "{registered}: {why}; got {} {}",
            refused.status, refused.body
        );
        assert_eq!(
            refused.header("Location"),
            None,
            "RFC 6749 section 4.1.2.1 does not redirect to a redirection URI it cannot \
             compose a response into; {registered}"
        );
        assert_eq!(member(&refused.body, "error"), "invalid_request");
    }
}

/// The other end of the same rule: a query component that is present and **empty** is an
/// empty form, names no response parameter, and is extended without the stray `&` that made
/// `?&code=…` unreadable.
#[test]
fn an_empty_registered_query_component_is_extended_into_a_readable_form() {
    let registered = "https://client.example/callback?";
    let (address, target) = serving_with(registered, test_limits());
    let proof = session_proof(address);
    let redirected = authorize(address, target, &proof, registered);
    assert_eq!(
        redirected.status, 302,
        "an empty query component carries a response; got {}",
        redirected.body
    );
    let location = redirected
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let form = redirect_form(&location);
    assert!(form.get("code").is_some(), "a code parameter in {location}");
    assert_eq!(form.get("state"), Some("xyzzy"), "the exact state received");
}

/// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST NOT include a fragment
/// component." Nothing between `RegisterOAuthClient` and the `Location` header reads that
/// sentence, and by RFC 3986 section 3.5 every parameter appended after a `#` is inside the
/// fragment — a component the redirection endpoint never receives. The URI carries no
/// response, so it is refused in place rather than redirected to.
#[test]
fn a_registered_redirect_carrying_a_fragment_is_refused_in_place() {
    let registered = "https://client.example/callback#done";
    let (address, target) = serving_with(registered, test_limits());
    let proof = session_proof(address);
    let refused = authorize(address, target, &proof, registered);
    assert_eq!(
        refused.status, 400,
        "a fragment carries no response parameter; got {}",
        refused.body
    );
    assert_eq!(refused.header("Location"), None);
    assert_eq!(member(&refused.body, "error"), "invalid_request");
}

/// The error branch is the same composer and answers the same way: a refusal that would be
/// redirected under RFC 6749 section 4.1.2.1 is rendered instead when the registered URI
/// cannot carry it. The refusal driven here — a target outside the client's tenant — is one
/// that *is* redirected when the registered URI is composable.
#[test]
fn the_error_branch_is_rendered_when_the_registered_redirect_cannot_carry_it() {
    let registered = "https://client.example/callback#done";
    let (address, _) = serving_with(registered, test_limits());
    let proof = session_proof(address);
    let outside = ResourceServerId::new(uuid(0x77));
    let refused = authorize(address, outside, &proof, registered);
    assert_eq!(
        refused.status, 400,
        "the error is rendered, not redirected; got {}",
        refused.body
    );
    assert_eq!(refused.header("Location"), None);
}

// ---------------------------------------------------------------------------------------
// RFC 9112 section 3.2's other requirement: the Host (round 2, F3)
// ---------------------------------------------------------------------------------------

/// "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request
/// message that lacks a Host header field and to any request message that contains more than
/// one Host header field line or a Host header field with an invalid field value."
///
/// Two Host lines is the request-smuggling shape the MUST exists for: a front end routing on
/// the first and a listener reading neither do not agree on who the request was addressed to.
#[test]
fn an_http_1_1_request_naming_no_host_or_two_hosts_is_refused() {
    let (address, _) = serving();
    for (raw, why) in [
        ("GET /oauth/jwks HTTP/1.1\r\n\r\n", "lacks a Host"),
        (
            "GET /oauth/jwks HTTP/1.1\r\nHost: mandate.example\r\nHost: evil.example\r\n\r\n",
            "names two Hosts",
        ),
        (
            "GET /oauth/jwks HTTP/1.1\r\nHost: \r\n\r\n",
            "names an empty Host",
        ),
    ] {
        let refused = exchange(address, raw.as_bytes());
        assert_eq!(
            refused.status, 400,
            "RFC 9112 section 3.2: a request that {why} is refused; got {} {}",
            refused.status, refused.body
        );
        assert_eq!(member(&refused.body, "error"), "invalid_request");
    }

    let served = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(served.status, 200, "the listener is still serving");
}

/// The boundary of that rule, so that requiring a Host does not become requiring one of a
/// version that never had to send it: RFC 9112 section 3.2 obliges the field in HTTP/1.1
/// messages, and an HTTP/1.0 request that omits it is not malformed. Two Host lines are
/// refused at either version — that framing is ambiguous whoever sent it.
#[test]
fn an_http_1_0_request_may_omit_the_host_but_not_repeat_it() {
    let (address, _) = serving();
    let served = exchange(address, b"GET /oauth/jwks HTTP/1.0\r\n\r\n");
    assert_eq!(
        served.status, 200,
        "HTTP/1.0 sends no Host and is not refused for it; got {}",
        served.body
    );
    let refused = exchange(
        address,
        b"GET /oauth/jwks HTTP/1.0\r\nHost: a.example\r\nHost: b.example\r\n\r\n",
    );
    assert_eq!(refused.status, 400, "got {}", refused.body);
}

// ---------------------------------------------------------------------------------------
// The lifetimes, at both ends (round 2, F4 and F6)
// ---------------------------------------------------------------------------------------

/// The admitted end of the upper bound, driven through the STS rather than read off the
/// check: a code lifetime of a year renders an expiry `services/sts/src/lib.rs`'s reader
/// reads back, so the authorization endpoint answers with a code.
#[test]
fn a_code_lifetime_of_a_year_still_issues_a_code() {
    let (address, target, _) = serving_full(REDIRECT, "PT8760H", "PT8760H", test_limits());
    let proof = session_proof(address);
    let redirected = authorize(address, target, &proof, REDIRECT);
    assert_eq!(redirected.status, 302, "got {}", redirected.body);
    let location = redirected
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let form = redirect_form(&location);
    assert_eq!(form.get("error"), None, "no refusal in {location}");
    assert!(form.get("code").is_some(), "a code in {location}");
}

/// **A code is redeemable only while the session it was issued under is fresh**
/// (`services/sts/src/binding.rs`: the bound session must be strictly before its `expires_at`
/// at the request instant, or the redemption is `SessionUnusable`). So a session lifetime
/// below the code lifetime shortens the code's usable life, which is why
/// `Configuration::checked` admits one and says so rather than refusing it.
///
/// Measured rather than asserted: the code is issued under a session with an hour to live,
/// the clock moves past that hour while the code's own five minutes are far from over, and
/// the redemption is refused with no credential.
#[test]
fn a_code_is_redeemable_only_while_its_session_is_fresh() {
    let (address, target, clock) = serving_full(REDIRECT, "PT5M", "PT1H", test_limits());
    let proof = session_proof(address);
    let redirected = authorize(address, target, &proof, REDIRECT);
    assert_eq!(redirected.status, 302, "got {}", redirected.body);
    let code = code_of(redirected.header("Location").expect("a Location header"));

    // Past the session's hour, inside the code's five minutes — which is only possible
    // because the two lifetimes are configured independently.
    clock.advance(3_600 + 1);
    let refused = exchange(
        address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body(&code, REDIRECT),
            &[],
        ),
    );
    assert_ne!(
        refused.status, 200,
        "the session the code was issued under has expired; got {}",
        refused.body
    );
    assert!(
        !refused.body.contains("access_token"),
        "no credential is issued against an expired session; got {}",
        refused.body
    );
}

// ---------------------------------------------------------------------------------------
// The two seeds `serve` is configured with: `--connection` and `--key`
// ---------------------------------------------------------------------------------------

/// RFC 7515 appendix A.3's public P-256 key, as the JWK document `--key` reads.
const KEY_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig","alg":"ES256",
  "crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

/// The same key, carrying RFC 7517 section 9.2's private member. A published document is
/// assembled from names a constructor admitted, and `d` is not one of them.
const PRIVATE_KEY_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig",
  "alg":"ES256","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;

/// A second key under the same `kid`, so that a set naming one `kid` twice is a *set* the
/// flags can name rather than one no caller could construct.
const REPEATED_KID_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig",
  "alg":"ES256","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;

/// Where a case's flag documents are written: cargo's own per-target scratch directory, so
/// nothing here writes outside the build tree.
fn seed_file(name: &str, body: &str) -> PathBuf {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join("seeds");
    std::fs::create_dir_all(&directory).expect("a writable scratch directory");
    let path = directory.join(name);
    std::fs::write(&path, body).expect("the flag document is written");
    path
}

fn seed_path(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// The `--connection` document: the issuer, the client and the organization the verifier
/// double and the registered OAuth client agree on.
///
/// `link` decides whether the document also carries the external-principal link. The login
/// resolves its principal through one (`crates/mandate-federation/src/authenticate.rs:118`),
/// so a document without it is a connection the road can select and authenticates nobody
/// unless the connection admits just-in-time provisioning.
fn connection_document(connection_id: Option<&str>, link: bool) -> String {
    connection_document_admitting(connection_id, link, false)
}

/// The same document with `jit_provisioning` stated: whether a first login through this
/// connection creates the principal and the link it resolves through, or refuses.
fn connection_document_admitting(
    connection_id: Option<&str>,
    link: bool,
    jit_provisioning: bool,
) -> String {
    let identity = match connection_id {
        Some(id) => format!(r#""connection_id":"{id}","#),
        None => String::new(),
    };
    let linked = if link {
        format!(
            r#","link":{{"principal_id":"{principal}","external_principal_id":"{external}",
              "subject":"subject-1","linked_at":"2026-09-01T00:00:00Z"}}"#,
            principal = principal(),
            external = ExternalPrincipalId::new(uuid(0xe2)),
        )
    } else {
        String::new()
    };
    format!(
        r#"{{{identity}"organization":"{organization}","issuer":"https://idp.example",
          "client_id":"mandate-at-idp",
          "tenant_resolution":{{"configured_organization":"{organization}"}},
          "jit_provisioning":{jit_provisioning}{linked}}}"#,
        organization = organization(),
    )
}

/// A deployment whose connection and key are read from the two flag documents, through the
/// same library path `src/main.rs` reads them with.
///
/// The registered OAuth client and the registered target are still seeded here as a library
/// caller: **no flag in this story carries either**, so an operator holding only
/// `--connection` and `--key` reaches step 1 of the road and no further.
fn deployment_from_documents(
    connection_path: &Path,
    key_path: &Path,
) -> (Wired, ResourceServerId, FederationConnectionId) {
    let seed = read_connection_seed(connection_path).expect("a connection document serve reads");
    let key = read_key(key_path).expect("a JWK document serve publishes");

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
            keys: vec![key],
        },
        verifier(),
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");

    deployment
        .record_credential(&registered.event)
        .expect("a readable credential history");

    let mut minted = 0xe7_u8;
    let mut allocate = || {
        minted = minted.wrapping_add(1);
        uuid(minted)
    };
    let seeded = seed.events(&mut allocate);
    for event in &seeded.events {
        deployment
            .record_federation(event)
            .expect("a readable federation history");
    }

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

    (deployment, target, seeded.connection_id)
}

/// Bind an ephemeral port and serve a deployment configured from the two flag documents.
fn serving_from_documents(
    connection_path: &Path,
    key_path: &Path,
) -> (SocketAddr, ResourceServerId, FederationConnectionId) {
    let listener =
        Listener::bind("127.0.0.1:0", test_limits()).expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let (mut deployment, target, connection_id) =
        deployment_from_documents(connection_path, key_path);
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    (address, target, connection_id)
}

/// Run `serve` with these extra arguments and read back what it did, bounded.
///
/// Bounded because a document this deployment *accepts* serves until it is killed: a case
/// that expects a refusal and gets a running server must fail rather than hang forever.
fn serve_with(extra: &[&str]) -> std::process::Output {
    let mut arguments = vec![
        "serve",
        "--listen",
        "127.0.0.1:0",
        "--issuer",
        "https://mandate.example",
    ];
    arguments.extend_from_slice(extra);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
        .args(&arguments)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the composition binary runs");
    let deadline = Instant::now() + HostDuration::from_secs(20);
    loop {
        match child.try_wait().expect("the child process is waitable") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                break;
            }
            None => std::thread::sleep(HostDuration::from_millis(20)),
        }
    }
    child
        .wait_with_output()
        .expect("the process's own output is read back")
}

/// The acceptance: two flag documents configure a deployment, and one login completes over a
/// real socket — login, authorization, token, introspection, in that order.
#[test]
fn the_flag_documents_configure_a_deployment_that_completes_one_login_end_to_end() {
    let stated = FederationConnectionId::new(uuid(0xc1));
    let connection_path = seed_file(
        "road-connection.json",
        &connection_document(Some(&stated.to_string()), true),
    );
    let key_path = seed_file("road-key.json", KEY_DOCUMENT);
    let (address, target, connection_id) = serving_from_documents(&connection_path, &key_path);
    assert_eq!(
        connection_id, stated,
        "the document's own `connection_id` is the one that was seeded"
    );

    // The key the flag carried is the document a client reads, and `{"keys":[]}` is not it.
    let published = exchange(address, &get("/oauth/jwks", &[]));
    assert_eq!(
        published.status, 200,
        "the key set answered {}",
        published.body
    );
    assert!(
        published.body.contains("login-key-1"),
        "`--key` publishes the key it read, got {}",
        published.body
    );
    assert!(
        !published.body.contains("\"d\""),
        "RFC 7517 section 9.2's private members are not published, got {}",
        published.body
    );

    // 1. The login opens a session against the seeded connection.
    let login = exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &format!(
                r#"{{"connection_id":"{connection_id}","proof":"{}"}}"#,
                mandate_types::value::encode_base64(b"an idp proof")
            ),
            &[],
        ),
    );
    assert_eq!(login.status, 200, "the login answered {}", login.body);
    assert!(
        !member(&login.body, "session_id").is_empty(),
        "the declared `session_id` response"
    );
    let proof = member(&login.body, "session_proof");

    // 2. The authorization request redirects with a code, under an S256 challenge.
    let redirected = authorize(address, target, &proof, REDIRECT);
    assert_eq!(
        redirected.status, 302,
        "RFC 6749 section 4.1.2 answers with a redirect; got {}",
        redirected.body
    );
    let location = redirected
        .header("Location")
        .expect("a Location header")
        .to_owned();
    assert!(
        location.contains("state=xyzzy"),
        "RFC 6749 section 4.1.2 returns the exact state received, got {location}"
    );
    let code = code_of(&location);

    // 3. The token endpoint redeems the code with the verifier.
    let token = exchange(
        address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body(&code, REDIRECT),
            &[],
        ),
    );
    assert_eq!(
        token.status, 200,
        "the token endpoint answered {}",
        token.body
    );
    let credential = member(&token.body, "access_token");

    // 4. Introspection answers active for the credential the road just issued.
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

/// A connection document naming no link **and admitting no provisioning** is a connection the
/// road selects and cannot authenticate: `authenticate_federation` resolves the principal
/// through an explicit link, and `jit_provisioning` is the only thing that admits creating
/// one. Measured, so the `link` member is not an invention: provision-ahead stays a supported
/// mode, and this is what a deployment using neither is answered.
#[test]
fn a_connection_document_naming_no_link_selects_a_connection_and_authenticates_nobody() {
    let stated = FederationConnectionId::new(uuid(0xc2));
    let connection_path = seed_file(
        "unlinked-connection.json",
        &connection_document(Some(&stated.to_string()), false),
    );
    let key_path = seed_file("unlinked-key.json", KEY_DOCUMENT);
    let (address, _, connection_id) = serving_from_documents(&connection_path, &key_path);

    let login = exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &format!(
                r#"{{"connection_id":"{connection_id}","proof":"{}"}}"#,
                mandate_types::value::encode_base64(b"an idp proof")
            ),
            &[],
        ),
    );
    assert_eq!(
        login.status, 400,
        "no principal is linked through this connection; got {}",
        login.body
    );
    assert!(
        login.body.contains("access_denied"),
        "`LinkAbsent` carries `DenialReason::Denied`, which is `access_denied` and not the \
         `invalid_request` a connection nobody seeded answers; got {}",
        login.body
    );
}

/// An operator who cannot learn the `connection_id` cannot call the login route, so a
/// document naming none is allocated one and the binary prints it before it binds.
#[test]
fn a_connection_document_naming_no_id_is_allocated_one_and_prints_it() {
    let path = seed_file(
        "allocated-connection.json",
        &connection_document(None, true),
    );
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--issuer",
            "https://mandate.example",
            "--connection",
            seed_path(&path),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the composition binary runs");
    let mut printed = String::new();
    let mut reader = std::io::BufReader::new(child.stdout.take().expect("a piped stdout"));
    reader
        .read_line(&mut printed)
        .expect("the seeded connection is printed");
    let _ = child.kill();
    let refused = child
        .wait_with_output()
        .expect("the process's own output is read back");
    assert!(
        !printed.trim().is_empty(),
        "the binary printed no seeded connection; it said {} on stderr",
        String::from_utf8_lossy(&refused.stderr)
    );
    let identity = printed
        .split_whitespace()
        .next_back()
        .expect("a last word on the printed line");
    assert!(
        identity.len() == 36 && identity.split('-').count() == 5,
        "the printed line ends in the seeded `connection_id`, got {printed:?}"
    );
}

/// Every refusal of either flag document is a **configuration** refusal: exit status 2, not
/// the 1 of a listener that could not bind, and the file it read is named.
///
/// The class, enumerated: a path that does not open, a body that is not JSON, a body missing
/// a declared member, a JWK parameter outside `Jwk::ADMITTED_PARAMETERS`, and a JWK parameter
/// that is not text. A duplicated JSON member and a parameter colliding with a declared
/// member are the two `JwkRefusal` cases a JSON object cannot carry to `Jwk::new` — a
/// `serde_json` object holds one value per name, and the four declared members are read by
/// name before the rest are passed on.
#[test]
fn every_refusal_of_a_flag_document_exits_two_and_names_the_file() {
    let absent = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("seeds")
        .join("no-such-document.json");
    let cases = [
        ("--connection", absent.clone(), "a path that does not open"),
        (
            "--connection",
            seed_file("malformed-connection.json", "{"),
            "a body that is not JSON",
        ),
        (
            "--connection",
            seed_file(
                "incomplete-connection.json",
                r#"{"issuer":"https://idp.example"}"#,
            ),
            "a body missing the declared members",
        ),
        (
            "--key",
            seed_file("private-key.json", PRIVATE_KEY_DOCUMENT),
            "a JWK carrying private material",
        ),
        (
            "--key",
            seed_file(
                "untyped-key.json",
                r#"{"kty":"EC","kid":"k","use":"sig","alg":"ES256","crv":1}"#,
            ),
            "a JWK parameter that is not text",
        ),
    ];
    for (flag, path, why) in cases {
        let refused = serve_with(&[flag, seed_path(&path)]);
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{flag} naming {why} is a configuration refusal; it said {}",
            String::from_utf8_lossy(&refused.stderr)
        );
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(
            said.contains(seed_path(&path)),
            "the refusal of {why} names the file it read, got {said}"
        );
    }
}

/// Two `--key` documents under one `kid` name a set no reader can resolve a signature
/// against, and that is decided at startup rather than answered as a 500 to every client
/// that reads the key set. `ConfigurationRefused::Keys` is the variant already declared for
/// it.
#[test]
fn two_key_documents_naming_one_kid_are_refused_before_the_socket_is_bound() {
    let first = seed_file("first-key.json", KEY_DOCUMENT);
    let second = seed_file("second-key.json", REPEATED_KID_DOCUMENT);
    let refused = serve_with(&["--key", seed_path(&first), "--key", seed_path(&second)]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "one `kid` names at most one key; it said {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains("kid"),
        "the refusal says which member collided, got {said}"
    );
}

// ---------------------------------------------------------------------------------------
// The first login of a user nobody provisioned: `story:federated-jit-login`
// ---------------------------------------------------------------------------------------

/// A deployment holding one connection and nothing linked through it — the world a
/// first-time user of a customer's platform meets — over the fixed verifier double.
///
/// No OAuth client and no registered target: these cases stop at step 1 of the road.
fn deployment_unlinked(jit_provisioning: bool) -> (Wired, FederationConnectionId) {
    deployment_verified_by(verifier(), jit_provisioning)
}

/// The same, with the verifier as a parameter, because one case turns on what the port
/// answers rather than on what the connection says.
fn deployment_verified_by<V: FederationVerifier>(
    verifier: V,
    jit_provisioning: bool,
) -> (
    Deployment<V, FixedClock, CountingSecrets, SequentialAllocator>,
    FederationConnectionId,
) {
    let mut deployment = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        verifier,
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
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
            jit_provisioning,
        })
        .expect("a readable federation history");
    (deployment, connection())
}

/// The login the verifier double admits, as the decoded input the route hands the adapter.
fn login_input(connection_id: FederationConnectionId) -> decode::AuthenticateFederation {
    decode::AuthenticateFederation {
        connection_id,
        proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
    }
}

/// The acceptance: a first-time user of a customer's platform logs in over the served road,
/// through a connection that admits provisioning and has no link seeded ahead of it.
///
/// Measured before this story: the same request answered `400 access_denied`, because the
/// composition returned `AuthenticateFederation`'s `LinkAbsent` and never reached
/// `ProvisionExternalPrincipal`.
///
/// It is carried through all four routes rather than stopped at the session, because that is
/// the measurement of what the provisioned principal needs to be *usable*: the composition
/// seeds no `mandate.identity.Principal` for it — the event that would is
/// `mandate.federation.ExternalPrincipalProvisioned` in its generated shape, which the
/// library cannot name (see `adapters.rs`'s header) — and a road that completes without one
/// is a road that reads none.
#[test]
fn a_first_login_on_a_connection_that_admits_provisioning_completes_the_whole_road() {
    let stated = FederationConnectionId::new(uuid(0xc3));
    let connection_path = seed_file(
        "jit-connection.json",
        &connection_document_admitting(Some(&stated.to_string()), false, true),
    );
    let key_path = seed_file("jit-key.json", KEY_DOCUMENT);
    let (address, target, connection_id) = serving_from_documents(&connection_path, &key_path);

    // 1. The login provisions the principal it then opens a session for.
    let login = exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &format!(
                r#"{{"connection_id":"{connection_id}","proof":"{}"}}"#,
                mandate_types::value::encode_base64(b"an idp proof")
            ),
            &[],
        ),
    );
    assert_eq!(
        login.status, 200,
        "a connection admitting provisioning opens the first login a session; got {}",
        login.body
    );
    assert!(
        !member(&login.body, "session_id").is_empty(),
        "the declared `session_id` response, got {}",
        login.body
    );
    assert!(
        !member(&login.body, "principal_id").is_empty(),
        "the principal the first login created, got {}",
        login.body
    );
    assert_eq!(
        member(&login.body, "organization_id"),
        organization().to_string(),
        "the session is established in the connection's own organization, got {}",
        login.body
    );
    let proof = member(&login.body, "session_proof");

    // 2. That session authorizes, under the same epoch snapshot any other login gets.
    let redirected = authorize(address, target, &proof, REDIRECT);
    assert_eq!(
        redirected.status, 302,
        "the provisioned principal's session authorizes; got {}",
        redirected.body
    );
    let code = code_of(redirected.header("Location").expect("a Location header"));

    // 3 and 4. The code redeems, and the credential it issued introspects active.
    let token = exchange(
        address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body(&code, REDIRECT),
            &[],
        ),
    );
    assert_eq!(
        token.status, 200,
        "the token endpoint answered {}",
        token.body
    );
    let credential = member(&token.body, "access_token");
    let introspect = exchange(
        address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}", encoded(&credential)),
            &[("Authorization", &format!("Bearer {credential}"))],
        ),
    );
    let document: serde_json::Value =
        serde_json::from_str(&introspect.body).expect("RFC 7662 section 2.2's JSON");
    assert_eq!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(true),
        "a credential issued to a just-in-time principal is usable; got {}",
        introspect.body
    );
}

/// A connection that does not admit provisioning answers the declared `LinkAbsent` refusal,
/// unchanged, and creates nothing — `decision-blocker:jit-provisioning`'s second required
/// case, and the guarantee the flag is a guarantee of: "denies the first login and creates
/// nothing" (`federation.yaml:4`).
#[test]
fn a_connection_that_does_not_admit_provisioning_refuses_the_first_login_and_creates_nothing() {
    let (mut deployment, connection_id) = deployment_unlinked(false);

    let refusal = deployment
        .authenticate(&login_input(connection_id))
        .expect_err("a connection that admits no provisioning authenticates nobody");

    assert_eq!(
        refusal.clause, "LinkAbsent",
        "the refusal is `AuthenticateFederation`'s own, not a clause of a command the caller \
         never made"
    );
    assert_eq!(
        refusal.reason,
        DenialReason::Denied,
        "the declared reason of `LinkAbsent`"
    );
    assert!(
        deployment.federation().links().is_empty(),
        "a connection that does not admit provisioning creates no principal and no link, got \
         {:?}",
        deployment.federation().links()
    );
}

/// The acceptance, twice over: the first login provisions exactly one link through
/// `ConfiguredFederation`, and a second login by the same subject resolves *that* link and
/// provisions nothing.
///
/// The fold is what is asserted and not the status: a second provisioning would put a second
/// record in `links()` under a second principal, and a status says nothing about either.
#[test]
fn a_first_login_provisions_one_link_and_a_second_resolves_it_and_provisions_nothing() {
    let (mut deployment, connection_id) = deployment_unlinked(true);

    let first = deployment
        .authenticate(&login_input(connection_id))
        .expect("a connection admitting provisioning opens the first login a session");

    let provisioned = deployment.federation().links().to_vec();
    assert_eq!(
        provisioned.len(),
        1,
        "one first login creates exactly one `ExternalPrincipal`, got {provisioned:?}"
    );
    let link = &provisioned[0];
    assert_eq!(
        link.link_method,
        ExternalLinkMethod::ConfiguredFederation,
        "the link a configured connection creates is `ConfiguredFederation`"
    );
    assert_eq!(
        link.subject,
        ExternalSubject::new("subject-1"),
        "the link holds the validated subject, exactly as the issuer issued it"
    );
    assert_eq!(
        link.principal_id, first.principal_id,
        "the session is established for the principal the provisioning created"
    );

    let second = deployment
        .authenticate(&login_input(connection_id))
        .expect("the second login resolves the link the first one made");

    assert_eq!(
        second.principal_id, first.principal_id,
        "the second login resolves the principal the first created rather than a new one"
    );
    assert_ne!(
        second.session_id, first.session_id,
        "each login opens its own session"
    );
    assert_eq!(
        deployment.federation().links(),
        provisioned.as_slice(),
        "the second login provisions nothing: the fold holds exactly the record the first \
         login wrote"
    );
}

/// A verifier double that validates a **different subject on every call**, and counts them.
///
/// Named here as the case that uses it requires. It is not a claim about identity providers:
/// it is the one construction in which the *retry* resolves no link either, because with the
/// shipped fold a provisioning creates exactly the key the retry then looks the link up
/// under. `FederationVerifier` is a port and nothing in this composition may assume an
/// implementation answers twice the same; what the case pins is that the port is consulted
/// three times for one login — authenticate, provision, authenticate — and not a fourth.
struct RotatingSubjects {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl FederationVerifier for RotatingSubjects {
    fn verify(
        &self,
        _connection: &FederationConnection,
        _proof: &CredentialProof,
    ) -> Result<VerifiedProof, FederationDenied> {
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new(format!("subject-{call}")),
            ClientId::new("mandate-at-idp"),
        ))
    }
}

/// One retry, never a loop: a second `LinkAbsent` is returned as the login's answer, and
/// nothing is driven a third time.
///
/// A composition that retried on the retry's own refusal would provision a second link, and a
/// third, and never answer at all — so the case is answered on a thread with a deadline, a
/// hang being a failure that reports nothing.
#[test]
fn a_second_link_absent_is_returned_and_the_sequence_does_not_run_again() {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (deployment, connection_id) = deployment_verified_by(
        RotatingSubjects {
            calls: std::sync::Arc::clone(&calls),
        },
        true,
    );

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut deployment = deployment;
        let answered = deployment.authenticate(&login_input(connection_id));
        let _ = sender.send((answered.err(), deployment.federation().links().len()));
    });
    let (refusal, links) = receiver
        .recv_timeout(HostDuration::from_secs(10))
        .expect("one retry answers; a loop does not");

    let refusal = refusal.expect("the retry resolved no link either");
    assert_eq!(
        refusal.clause, "LinkAbsent",
        "the second refusal is returned as it stands"
    );
    assert_eq!(
        links, 1,
        "`ProvisionExternalPrincipal` was driven exactly once"
    );
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "one login consults the verifier three times: authenticate, provision, authenticate"
    );
}
