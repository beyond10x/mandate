//! Adversary pass 1 against `story:product-listener`: the served road and its transport.
//!
//! Every case here drives the shipped listener over a raw `std::net::TcpStream`, exactly as
//! `tests/serve.rs` does and with the same doubles it names
//! (`ConstructedVerifier`, `FixedClock`, `CountingSecrets`, `SequentialAllocator`). Nothing
//! in this file is an implementation change; the fixture is a copy of `tests/serve.rs`'s,
//! parameterized on the two configuration values a case needs to vary — the redirect URI the
//! client registers, and the code lifetime the deployment is configured with.
//!
//! The cases are named for the property they assert, not for the defect they found, so that a
//! correction unit turns each one green without rewriting it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration as HostDuration, Instant};

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

/// The redirect `tests/serve.rs` registers: no query component.
const REDIRECT: &str = "https://client.example/callback";

/// A redirect carrying a query component, which RFC 6749 section 3.1.2 admits in as many
/// words: "The endpoint URI MAY include an `application/x-www-form-urlencoded` formatted
/// query component ... which MUST be retained when adding additional query parameters."
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
        correlation: CorrelationId::new("adversary"),
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

/// `tests/serve.rs`'s deployment, with the registered redirect URI and the configured code
/// lifetime as parameters.
fn deployment_with(redirect: &str, code_lifetime: &str) -> (Wired, ResourceServerId) {
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
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
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

/// Bind on an ephemeral port and serve the road on a thread of its own.
fn serving_with(redirect: &str, code_lifetime: &str) -> (SocketAddr, ResourceServerId) {
    let listener = Listener::bind(
        "127.0.0.1:0",
        Limits {
            read_timeout: HostDuration::from_millis(400),
            // Correction round 1 (F5): the listener answers one connection at a time and
            // `Limits::request_deadline` is what bounds every other client's wait. The
            // shipped default is 10 s, which is longer than this case's dribble lasts, so
            // the case states the deadline it asserts against.
            request_deadline: HostDuration::from_millis(600),
            ..Limits::default()
        },
    )
    .expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let (mut deployment, target) = deployment_with(redirect, code_lifetime);
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    (address, target)
}

fn serving() -> (SocketAddr, ResourceServerId) {
    serving_with(REDIRECT, "PT5M")
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

fn post(path: &str, media_type: &str, body: &str) -> Vec<u8> {
    raw_post(path, media_type, &body.len().to_string(), body)
}

/// A `POST` whose declared `Content-Length` is stated by the case rather than measured, and
/// whose body is whatever bytes the case wants on the wire. The whole request is one
/// `write_all`, so the head and every body byte arrive in one segment.
fn raw_post(path: &str, media_type: &str, declared_length: &str, on_the_wire: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: mandate.example\r\nContent-Type: {media_type}\r\n\
         Content-Length: {declared_length}\r\n\r\n{on_the_wire}"
    )
    .into_bytes()
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

/// The login body `tests/serve.rs` posts.
fn login_body() -> String {
    format!(
        r#"{{"connection_id":"{}","proof":"{}"}}"#,
        connection(),
        mandate_types::value::encode_base64(b"an idp proof")
    )
}

/// Open a session and return the `session_proof` the login handed back.
fn session_proof(address: SocketAddr) -> String {
    let login = exchange(
        address,
        &post("/v1/federation/login", "application/json", &login_body()),
    );
    assert_eq!(login.status, 200, "the login answered {}", login.body);
    member(&login.body, "session_proof")
}

/// The authorization request `tests/serve.rs` drives, with the redirect and the state as
/// parameters.
fn authorize(
    address: SocketAddr,
    target: ResourceServerId,
    proof: &str,
    redirect: &str,
    state: &str,
) -> Response {
    exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256&state={}\
                 &nonce=n-0S6&target={target}&scope={}",
                client(),
                encoded(redirect),
                encoded(state),
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

// ---------------------------------------------------------------------------------------
// 1. The `Location` header the authorization endpoint composes
// ---------------------------------------------------------------------------------------

/// RFC 6749 section 3.1.2: a registered redirection endpoint URI MAY carry a query
/// component, and it "MUST be retained when adding additional query parameters". Section
/// 4.1.2 then requires the `code` and `state` to be added to the query component of the
/// redirection URI — so a client that registered `.../callback?tenant=acme` must still be
/// able to read `code` and `state` out of the query it is redirected to.
#[test]
fn a_redirect_uri_that_already_carries_a_query_still_returns_a_readable_code_and_state() {
    let (address, target) = serving_with(REDIRECT_WITH_QUERY, "PT5M");
    let proof = session_proof(address);
    let answered = authorize(address, target, &proof, REDIRECT_WITH_QUERY, "xyzzy");
    assert_eq!(
        answered.status, 302,
        "RFC 6749 section 4.1.2 answers with a redirect; got {}",
        answered.body
    );
    let location = answered
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let (_, query) = location
        .split_once('?')
        .expect("a redirect carrying a query component");
    let form = mandate_proto::oauth::decode_form(query)
        .unwrap_or_else(|_| panic!("an x-www-form-urlencoded query, got {location}"));
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
        "RFC 6749 section 4.1.2: the code is a parameter of the redirect query, got {location}"
    );
}

/// The same property for the error redirect of RFC 6749 section 4.1.2.1: `error` and `state`
/// are parameters of the query, not text glued after a second `?`. The refusal driven here
/// is a target outside the client's tenant, which is raised *after* the client and its
/// registered redirect are validated and is therefore redirected (`story:product-listener`,
/// the `review-result:wave-d-login-adapters-adversary-2` F4 ruling).
#[test]
fn an_error_redirect_to_a_redirect_uri_with_a_query_is_still_readable() {
    let (address, _) = serving_with(REDIRECT_WITH_QUERY, "PT5M");
    let proof = session_proof(address);
    let unregistered = ResourceServerId::new(uuid(0x77));
    let answered = exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256&state=xyzzy\
                 &nonce=n-0S6&target={unregistered}&scope={}",
                client(),
                encoded(REDIRECT_WITH_QUERY),
                encoded("read")
            ),
            &[("Authorization", &format!("Bearer {proof}"))],
        ),
    );
    assert_eq!(
        answered.status, 302,
        "RFC 6749 section 4.1.2.1 redirects the error to the validated redirect URI; got {}",
        answered.body
    );
    let location = answered
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let (_, query) = location
        .split_once('?')
        .expect("a redirect carrying a query component");
    let form = mandate_proto::oauth::decode_form(query)
        .unwrap_or_else(|_| panic!("an x-www-form-urlencoded query, got {location}"));
    assert!(
        form.get("error").is_some(),
        "RFC 6749 section 4.1.2.1: `error` is a parameter of the redirect query, got {location}"
    );
    assert_eq!(
        form.get("state"),
        Some("xyzzy"),
        "RFC 6749 section 4.1.2.1: the exact state received, got {location}"
    );
}

/// What held, kept as a case: a `state` carrying `&`, `#`, `%`, a space and non-ASCII is
/// returned exactly, so a correction to the two cases above must not reach it by trimming
/// the encoding.
#[test]
fn the_exact_state_survives_the_redirect_for_every_character_the_decoder_admits() {
    let (address, target) = serving();
    let proof = session_proof(address);
    let state = "a&b#c%d e\u{e9}\u{2028}";
    let answered = authorize(address, target, &proof, REDIRECT, state);
    assert_eq!(
        answered.status, 302,
        "RFC 6749 section 4.1.2 answers with a redirect; got {}",
        answered.body
    );
    let location = answered
        .header("Location")
        .expect("a Location header")
        .to_owned();
    let (_, query) = location
        .split_once('?')
        .expect("a redirect carrying a query component");
    let form = mandate_proto::oauth::decode_form(query)
        .unwrap_or_else(|_| panic!("an x-www-form-urlencoded query, got {location}"));
    assert_eq!(
        form.get("state"),
        Some(state),
        "RFC 6749 section 4.1.2: \"the exact value received from the client\", got {location}"
    );
}

// ---------------------------------------------------------------------------------------
// 2. Request framing: what `Content-Length` declares is what the request carries
// ---------------------------------------------------------------------------------------

/// RFC 9112 section 6: the `Content-Length` field value is the message body's length in
/// octets, and it is the frame. Bytes on the connection past that length are not part of
/// this request — to a proxy in front of this listener they are the start of the next one.
/// `src/serve.rs:207-215` already takes that rule for a repeated `Content-Length` ("a
/// request whose framing two readers may disagree on, and it is refused rather than
/// resolved"); this case asserts the same rule for the length itself.
///
/// The request declares a truthful length for a token form and puts seven more bytes on the
/// wire behind it. Honestly framed, the request the decoder sees is the declared prefix — a
/// well-formed token request naming a code nothing issued, which is the declared
/// unknown-code denial `invalid_grant` (`tests/serve.rs`'s own case pins that answer). If
/// the trailing bytes reach the decoder they are an undeclared `evil` parameter and the
/// answer is `invalid_request`, which is how this case tells the two apart.
#[test]
fn bytes_past_the_declared_content_length_are_not_read_as_part_of_this_request() {
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
        "the request this listener framed is the declared {} bytes, and the seven bytes \
         behind them are not part of it; got {}",
        declared.len(),
        refused.body
    );
}

/// The same rule at its boundary: a request that declares it carries no body carries none.
/// RFC 9112 section 6 — a `Content-Length` of zero frames an empty body, and every byte
/// behind the head belongs to whatever reads the connection next.
///
/// The road is driven end to end and only the token request lies about its length. A
/// credential issued here is a credential issued for a request body this listener was told
/// it did not have.
#[test]
fn a_request_declaring_no_body_is_not_served_from_the_bytes_behind_its_head() {
    let (address, target) = serving();
    let proof = session_proof(address);
    let answered = authorize(address, target, &proof, REDIRECT, "xyzzy");
    assert_eq!(
        answered.status, 302,
        "the authorization answered a redirect"
    );
    let location = answered.header("Location").expect("a Location header");
    let (_, query) = location.split_once('?').expect("a redirect query");
    let form = mandate_proto::oauth::decode_form(query).expect("a declared query");
    let code = form.get("code").expect("a code parameter").to_owned();

    let answered = exchange(
        address,
        &raw_post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            "0",
            &token_body(&code, REDIRECT),
        ),
    );
    assert_ne!(
        answered.status, 200,
        "RFC 9112 section 6: the request declared an empty body, so no grant was presented \
         and no credential is issued; got {}",
        answered.body
    );
}

/// RFC 9112 section 6.3: `Content-Length = 1*DIGIT`. A value carrying a sign is not a
/// `Content-Length`, and a message "received without `Transfer-Encoding` and with an invalid
/// `Content-Length` header field" has invalid framing, which the recipient must treat as an
/// unrecoverable error. Rust's `str::parse::<usize>` admits a leading `+`, so a value no
/// conformant reader accepts is read here as a length — and a proxy that refused it and this
/// listener that accepted it frame the same connection two different ways.
#[test]
fn a_content_length_carrying_a_sign_is_refused() {
    let (address, _) = serving();
    let body = login_body();
    let answered = exchange(
        address,
        &raw_post(
            "/v1/federation/login",
            "application/json",
            &format!("+{}", body.len()),
            &body,
        ),
    );
    assert_eq!(
        answered.status,
        400,
        "RFC 9112 section 6.3: `+{}` is not `1*DIGIT` and the framing is invalid; got {}",
        body.len(),
        answered.body
    );
}

// ---------------------------------------------------------------------------------------
// 3. One connection, and every other client
// ---------------------------------------------------------------------------------------

/// A listener that answers one client answers the next one. `src/serve.rs:105-110` accepts
/// and answers in one sequential loop, so the time a second client waits is the time the
/// first connection takes — and the first connection's time is the *client's* to choose,
/// bounded only by the per-read timeout multiplied by `Limits::max_head_bytes`.
///
/// The probe: one connection dribbles a byte every 300 ms, under the 400 ms read timeout
/// this fixture configures, while a second client sends one complete request for a document
/// that reads no state at all. The bound asserted is generous — 1.5 s for a request that is
/// answered in under a millisecond when nothing else is connected.
#[test]
fn a_second_client_is_answered_while_one_connection_is_slow() {
    let (address, _) = serving();
    let slow = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(address).expect("the listener accepts");
        // Ten bytes of a request line, one every 300 ms: three seconds of a head that never
        // ends, every read inside the 400 ms timeout.
        for byte in b"GET /oauth" {
            if stream.write_all(&[*byte]).is_err() {
                return;
            }
            let _ = stream.flush();
            std::thread::sleep(HostDuration::from_millis(300));
        }
    });
    // Long enough that the slow connection is the one being read when the second arrives.
    std::thread::sleep(HostDuration::from_millis(500));

    let started = Instant::now();
    let served = exchange(address, &get("/oauth/jwks", &[]));
    let waited = started.elapsed();
    let _ = slow.join();

    assert_eq!(served.status, 200, "the JWKS document is served");
    assert!(
        waited < HostDuration::from_millis(1_500),
        "a second client waited {waited:?} for a document behind one slow connection: the \
         accept loop answers one connection at a time, so one client sets every other \
         client's latency"
    );
}

// ---------------------------------------------------------------------------------------
// 4. A configuration the binary accepts
// ---------------------------------------------------------------------------------------

/// `src/main.rs:73` builds `CodeLifetime::new(Duration::new(code_lifetime))` from the
/// `--code-lifetime` argument without deciding whether the text names a span, and
/// `adapters::instant::span_of` answers `None` for one that does not — which
/// `src/adapters.rs` turns into `0` with `unwrap_or(0)`. A lifetime of zero seconds puts the
/// code's `expires_at` at the request instant, which `services/sts/src/code.rs:649` refuses.
///
/// So a string `clap` accepted and the process started with disables the authorization
/// endpoint for every client, and nothing — not the exit status, not a startup line, not the
/// refusal the client receives — says the configuration is the reason. Either the
/// configuration is refused where it is read, or it is honoured; it is not silently zero.
#[test]
fn a_code_lifetime_the_binary_accepts_is_not_silently_zero() {
    // What `mandate-control-plane serve --code-lifetime PT` constructs. Correction round 1
    // (F6) took the first half of this case's own disjunction — "either the configuration is
    // refused where it is read, or it is honoured" — so there is no deployment to drive a
    // road over and the refusal itself is the observable.
    let refused = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        verifier(),
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    );
    assert!(
        refused.is_err(),
        "a `--code-lifetime` naming no span is refused where it is read, rather than becoming \
         a zero that disables the authorization endpoint for every client"
    );
}

// ---------------------------------------------------------------------------------------
// 5. The request target
// ---------------------------------------------------------------------------------------

/// RFC 9112 section 3.2.2: "a server MUST accept the absolute-form in requests, even though
/// HTTP/1.1 clients will only send them in requests to proxies". The listener dispatches
/// `httparse`'s target verbatim through `Request::route_path`, which splits on `?` and
/// nothing else, so an absolute-form target reaches the route table as
/// `http://mandate.example/oauth/jwks` and matches no route.
#[test]
fn an_absolute_form_request_target_reaches_the_route_it_names() {
    let (address, _) = serving();
    let served = exchange(address, &get(&format!("{ISSUER}/oauth/jwks"), &[]));
    assert_eq!(
        served.status, 200,
        "RFC 9112 section 3.2.2: the absolute-form target names the JWKS route; got {}",
        served.body
    );
}
