//! Adversary pass 2 against `story:product-listener`, after correction round 1.
//!
//! Every case here drives the shipped listener over a raw `std::net::TcpStream`, exactly as
//! `tests/serve.rs` and `tests/adversary_listener_1.rs` do, or calls the one `pub`
//! configuration reader the composition exposes. Nothing under `src/` is touched.
//!
//! The doubles are the ones `tests/serve.rs` names: `ConstructedVerifier`, `FixedClock`,
//! `CountingSecrets`, `SequentialAllocator`. Everything else is the shipped path.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration as HostDuration, Instant};

use mandate_control_plane::adapters::{
    Configuration, ConfigurationRefused, Deployment, IssuerRefused,
};
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
        correlation: CorrelationId::new("adversary-2"),
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

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// What one served world hands back: the two registered targets and the clock behind it.
struct World {
    address: SocketAddr,
    target: ResourceServerId,
    other_target: ResourceServerId,
    clock: FixedClock,
}

/// `tests/serve.rs`'s deployment, with the registered redirect URI, the code lifetime and the
/// session lifetime as parameters, and a **second** registered target so that a case can hold
/// two credentials for two audiences.
fn deployment_with(
    redirect: &str,
    code_lifetime: &str,
    session_lifetime: &str,
    clock: FixedClock,
) -> (Wired, ResourceServerId, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let mut credentials = CredentialProjection::default();
    let mut registered = Vec::new();
    for audience in ["https://api.example", "https://other.example"] {
        let outcome = register_resource_server(
            &RegisterResourceServer {
                context: context(),
                audience: Audience::new(audience),
                profile: reference_profile(),
                allowed_exchange_sources: Vec::new(),
            },
            &credentials,
            &mut allocator,
        )
        .expect("a free audience in the caller's own organization");
        let _ = credentials.apply(&outcome.event);
        registered.push(outcome);
    }

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

    for outcome in &registered {
        deployment
            .record_credential(&outcome.event)
            .expect("a readable credential history");
    }
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
    (
        deployment,
        registered[0].resource_server_id,
        registered[1].resource_server_id,
    )
}

/// The limits every case serves under unless it states its own: the shipped defaults with a
/// read timeout short enough that a case which stops writing is answered rather than waited on.
fn test_limits() -> Limits {
    Limits {
        read_timeout: HostDuration::from_millis(400),
        ..Limits::default()
    }
}

fn serving_full(
    redirect: &str,
    code_lifetime: &str,
    session_lifetime: &str,
    limits: Limits,
) -> World {
    let listener =
        Listener::bind("127.0.0.1:0", limits).expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let clock = FixedClock::at(NOW);
    let (mut deployment, target, other_target) =
        deployment_with(redirect, code_lifetime, session_lifetime, clock.clone());
    std::thread::spawn(move || {
        let _ = listener.serve(&mut deployment);
    });
    World {
        address,
        target,
        other_target,
        clock,
    }
}

fn serving_registering(redirect: &str) -> World {
    serving_full(redirect, "PT5M", "PT8H", test_limits())
}

fn serving() -> World {
    serving_registering(REDIRECT)
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

    fn location(&self) -> String {
        self.header("Location")
            .unwrap_or_else(|| panic!("a Location header, got {} {}", self.status, self.body))
            .to_owned()
    }
}

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

fn login_body() -> String {
    format!(
        r#"{{"connection_id":"{}","proof":"{}"}}"#,
        connection(),
        mandate_types::value::encode_base64(b"an idp proof")
    )
}

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

#[allow(clippy::too_many_arguments)]
fn authorize_as(
    address: SocketAddr,
    target: ResourceServerId,
    proof: &str,
    redirect: &str,
    state: &str,
    client_id: &str,
) -> Response {
    exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={}\
                 &code_challenge={CHALLENGE}&code_challenge_method=S256&state={}\
                 &nonce=n-0S6&target={target}&scope={}",
                encoded(redirect),
                encoded(state),
                encoded("read")
            ),
            &[("Authorization", &format!("Bearer {proof}"))],
        ),
    )
}

fn authorize(
    address: SocketAddr,
    target: ResourceServerId,
    proof: &str,
    redirect: &str,
    state: &str,
) -> Response {
    authorize_as(
        address,
        target,
        proof,
        redirect,
        state,
        &client().to_string(),
    )
}

fn token_body(code: &str, redirect: &str) -> String {
    format!(
        "grant_type=authorization_code&client_id={}&code={}&code_verifier={VERIFIER}\
         &redirect_uri={}",
        client(),
        encoded(code),
        encoded(redirect)
    )
}

/// Drive the whole road once and answer with the credential the token endpoint issued.
fn credential_for(world: &World, target: ResourceServerId) -> String {
    let proof = session_proof(world.address);
    let redirected = authorize(world.address, target, &proof, REDIRECT, "xyzzy");
    assert_eq!(
        redirected.status, 302,
        "the authorization answered {}",
        redirected.body
    );
    let code = code_of(&redirected.location());
    let token = exchange(
        world.address,
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
    member(&token.body, "access_token")
}

/// The **query component** of a URI, as RFC 3986 section 3.4 delimits it: it begins at the
/// first `?` and ends at the first `#`. A `?` that follows a `#` is inside the fragment and is
/// not a query delimiter at all.
fn query_component(uri: &str) -> Option<&str> {
    let before_fragment = uri.split('#').next().unwrap_or(uri);
    before_fragment.split_once('?').map(|(_, query)| query)
}

/// The fragment component, as RFC 3986 section 3.5 delimits it.
f
fn code_of(location: &str) -> String {
    let query = query_component(location)
        .unwrap_or_else(|| panic!("a redirect carrying a query component, got {location}"));
    let form = mandate_proto::oauth::decode_form(query).unwrap_or_else(|error| {
        panic!("an x-www-form-urlencoded query, got {location}: {error:?}")
    });
    form.get("code")
        .unwrap_or_else(|| panic!("a code parameter in {location}"))
        .to_owned()
}

// ---------------------------------------------------------------------------------------
// 1. The one redirect composer, driven against the registered query it says it retains
// ---------------------------------------------------------------------------------------

/// **`redirect_to` extends the registered query without reading it, and both ends of that
/// query are places the extension is not a form.**
///
/// Correction round 1 (F1/F2) made the separator `&` where the registered URI carries a `?`.
/// The rule it states is RFC 6749 section 3.1.2's — the registered query "MUST be retained
/// when adding additional query parameters" — and sections 4.1.2 and 4.1.2.1 then require the
/// `code`, `state` and `error` to be parameters *of that query*. A parameter is a parameter
/// only if the result is still an `application/x-www-form-urlencoded` form, and this
/// deployment's own reader of that form is `mandate_proto::oauth::decode_form`, which is what
/// a client of this road would use.
///
/// Two registered URIs RFC 6749 section 3.1.2 admits, neither of them rejected anywhere
/// between `RegisterOAuthClient` and the `Location` header:
///
/// * `…/callback?` — a query component that is present and empty. `contains('?')` is true, so
///   the composer writes `?&code=…`, whose first segment is the empty string: no `=`, which
///   `decode_form` refuses as `FormError::MalformedPair`.
/// * `…/callback?state=registered` — a registered parameter that happens to share a name with
///   a response parameter. The composer appends a second `state`, and the client is left with
///   a query naming `state` twice, which `decode_form` refuses as `FormError::DuplicateKey`
///   and which every other reader resolves by picking one of the two. RFC 6749 section 4.1.2
///   requires "the exact value received from the client", and a client that reads the first
///   `state` reads the registrant's, not its own.
///
/// The fix is in the composer: the registered query is parsed before it is extended, and a
/// registered URI whose query is not a form, or which already names `code`, `state` or
/// `error`, is a refusal — in place, like every other refusal raised before the redirect is
/// trustworthy — rather than a `Location` no client can read.
#[test]
fn the_composed_redirect_query_is_a_form_a_client_can_read() {
    // Correction round 2 (F1) took the composer's half of the fix and split these two: a
    // query component that is present and empty is an empty form and is extended into a
    // readable one, and a query that already names a response parameter carries no response
    // at all and is refused in place — never redirected to (RFC 6749 section 4.1.2.1).
    for (registered, composes, why) in [
        (
            "https://client.example/callback?",
            true,
            "an empty query component leaves an empty first segment",
        ),
        (
            "https://client.example/callback?state=registered",
            false,
            "a registered `state` is not replaced and not merged",
        ),
    ] {
        let world = serving_registering(registered);
        let proof = session_proof(world.address);
        let redirected = authorize(world.address, world.target, &proof, registered, "xyzzy");
        if !composes {
            assert_eq!(
                redirected.status, 400,
                "{registered} carries no response ({why}), so it is refused in place; got {}",
                redirected.body
            );
            assert_eq!(
                redirected.header("Location"),
                None,
                "RFC 6749 section 4.1.2.1 does not redirect to an invalid redirection URI"
            );
            continue;
        }
        assert_eq!(
            redirected.status, 302,
            "the authorization answered {}",
            redirected.body
        );
        let location = redirected.location();
        let query =
            query_component(&location).unwrap_or_else(|| panic!("a query component in {location}"));
        let form = mandate_proto::oauth::decode_form(query).unwrap_or_else(|error| {
            panic!(
                "RFC 6749 section 4.1.2 adds `code` and `state` to the query component of the \
                 registered redirection URI, so the result is still a form: {why}. \
                 `decode_form` refused {location:?} with {error:?}"
            )
        });
        assert!(
            form.get("code").is_some(),
            "a `code` parameter in {location}"
        );
        assert_eq!(
            form.get("state"),
            Some("xyzzy"),
            "RFC 6749 section 4.1.2 returns the exact state received from the client; {location}"
        );
    }
}

/// **A registered redirection URI carrying a fragment sends the `code` into the fragment.**
///
/// RFC 6749 section 3.1.2: "The redirection endpoint URI MUST NOT include a fragment
/// component." Nothing between `RegisterOAuthClient` (`crates/mandate-federation/src/
/// register_client.rs`, which delegates every URI question to a deployment policy hook) and
/// `redirect_to` reads that sentence: `RedirectUri` is an unvalidated newtype, the authorize
/// decoder's `free_text` admits `#`, the byte-for-byte registration match admits it, and the
/// composer's `contains('?')` is false for `…/callback#done`, so it writes a `?` **after** the
/// `#`.
///
/// The result is `https://client.example/callback#done?code=…&state=…`: by RFC 3986 section
/// 3.5 everything past the first `#` is the fragment, so the authorization code is in a
/// component a browser never sends to the redirection endpoint. The grant is unreachable, and
/// the code is left in a component that is logged and shared differently from a query.
///
/// The fix is a refusal, in whichever of the two places the deployment decides URIs — the
/// registration, so the URI never becomes registered, or the composer, so a `Location` that
/// cannot carry a response parameter is never written.
#[test]
fn a_registered_redirect_carrying_a_fragment_does_not_bury_the_response_in_it() {
    let registered = "https://client.example/callback#done";
    let world = serving_registering(registered);
    let proof = session_proof(world.address);
    let redirected = authorize(world.address, world.target, &proof, registered, "xyzzy");
    // Correction round 2 (F2) took the second of the two places this case names — the
    // composer — so the code is not buried in the fragment because no code is redirected at
    // all: a registered URI carrying a fragment carries no response, and RFC 6749 section
    // 4.1.2.1 renders that in place rather than redirecting to an invalid redirection URI.
    assert_eq!(
        redirected.status, 400,
        "the authorization answered {}",
        redirected.body
    );
    assert_eq!(
        redirected.header("Location"),
        None,
        "nothing is redirected to a redirection URI that cannot carry a response"
    );
    assert!(
        !redirected.body.contains("code="),
        "and no code reaches the client by another route: {}",
        redirected.body
    );
}

// ---------------------------------------------------------------------------------------
// 2. RFC 9112 section 3.2, the half the correction did not take
// ---------------------------------------------------------------------------------------

/// **An HTTP/1.1 request naming no host is served.**
///
/// Correction round 1 (F7) took RFC 9112 section 3.2 as this listener's own contract and
/// decides all four request-target forms in `origin_form`. The same section's other
/// requirement is not decided anywhere: "A server MUST respond with a 400 (Bad Request) status
/// code to any HTTP/1.1 request message that lacks a Host header field and to any request
/// message that contains more than one Host header field line or a Host header field with an
/// invalid field value" (RFC 9112 section 3.2, and RFC 7230 section 5.4 before it).
///
/// `read_request` reads exactly two header names — `Content-Length` and `Transfer-Encoding` —
/// and `Host` is not among them, so a request that names no authority at all is dispatched,
/// and so is one naming two different authorities. The second is the request smuggling and
/// cache-poisoning shape the MUST exists for: a front end that routes on the first `Host` and
/// this listener that reads neither do not agree on who the request was addressed to.
#[test]
fn an_http_1_1_request_is_refused_when_it_names_no_host_or_names_two() {
    let world = serving();
    for (raw, why) in [
        (
            "GET /oauth/jwks HTTP/1.1\r\n\r\n".to_owned(),
            "lacks a Host header field",
        ),
        (
            "GET /oauth/jwks HTTP/1.1\r\nHost: mandate.example\r\nHost: evil.example\r\n\r\n"
                .to_owned(),
            "contains more than one Host header field line",
        ),
    ] {
        let answered = exchange(world.address, raw.as_bytes());
        assert_eq!(
            answered.status, 400,
            "RFC 9112 section 3.2: a server MUST respond 400 to an HTTP/1.1 request that {why}; \
             got {} {}",
            answered.status, answered.body
        );
    }
}

// ---------------------------------------------------------------------------------------
// 3. The startup refusal, driven against the failure it was added to stop
// ---------------------------------------------------------------------------------------

/// **A configured code lifetime can still be one this deployment serves logins under and
/// refuses every authorization for — with nothing said at startup.**
///
/// Correction round 1 (F6) is `Deployment::new -> Result<_, ConfigurationRefused>`, and the
/// failure it names is exactly this one: "a `--code-lifetime` naming no span becomes zero
/// through `unwrap_or(0)`, so the process starts and serves logins while refusing every
/// authorization with no startup error" (adversary pass 1, F6). The check that landed reads
/// only the lower end: `span_of_lifetime` refuses `None` and refuses a span that is not
/// positive.
///
/// The upper end is open, and it fails in the same shape rather than a different one. The
/// authorization handler computes `expires_at = instant::at(now + code_lifetime)`, and
/// `instant::at` renders the year with `{year:04}` — four digits is a minimum, not a maximum.
/// A span that puts the instant past the year 9999 renders a five-digit year, and
/// `mandate_sts::instant::seconds_of` reads `text[4]` expecting `-`, so it refuses the
/// timestamp this deployment itself produced. `issue_authorization_code` answers that with
/// `ExpiryUnbounded`, which correction round 1 (F8) now renders as `server_error`.
///
/// So `--code-lifetime PT99999999H` — a well-formed ISO 8601 duration `clap` takes,
/// `span_of` reads and `Configuration::checked` admits — starts a process that logs every user
/// in and answers `error=server_error` to every authorization request it is sent. The exit
/// status is 0 and the operator is told nothing, which is the sentence F6 was written against.
///
/// The fix is the other half of the same check: `Configuration::checked` bounds the lifetime
/// above as well as below — a span whose instant this deployment cannot render and read back
/// is `CodeLifetimeUnbounded` at startup, not `server_error` per request.
#[test]
fn a_code_lifetime_this_deployment_cannot_render_is_refused_at_startup() {
    // Correction round 2 (F4) bounds the lifetime above as well as below, so this is decided
    // where the configuration is read and there is no deployment to drive a road over.
    let lifetime = "PT99999999H";
    let refused = Configuration {
        issuer: ISSUER.to_owned(),
        code_lifetime: CodeLifetime::new(Duration::new(lifetime)),
        session_lifetime: Duration::new("PT8H"),
        keys: Vec::new(),
    }
    .checked();
    assert_eq!(
        refused.err(),
        Some(ConfigurationRefused::CodeLifetimeUnbounded),
        "a `--code-lifetime` of {lifetime} renders an expiry no reader on this road reads \
         back, and every authorization under it would answer `server_error`"
    );
    // The same value at the session's end of the configuration.
    assert_eq!(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new(lifetime),
            keys: Vec::new(),
        }
        .checked()
        .err(),
        Some(ConfigurationRefused::SessionLifetimeUnbounded),
        "a `--session-lifetime` of {lifetime}"
    );
}

/// The configuration matrix `Configuration::checked` decides, read as the document it is.
///
/// Green here is the answer, and it is recorded so the pass says what it probed.
#[test]
fn the_configuration_reader_answers_each_named_value() {
    let configured = |issuer: &str, code: &str, session: &str| Configuration {
        issuer: issuer.to_owned(),
        code_lifetime: CodeLifetime::new(Duration::new(code)),
        session_lifetime: Duration::new(session),
        keys: Vec::new(),
    };

    // The issuer identifier, RFC 8414 section 2.
    for (issuer, expected) in [
        (
            "http://mandate.example",
            Err(ConfigurationRefused::Issuer(
                IssuerRefused::SchemeUnadmitted,
            )),
        ),
        (
            "https://mandate.example//",
            Err(ConfigurationRefused::Issuer(
                IssuerRefused::RepeatedTrailingSlash,
            )),
        ),
        (
            "https://mandate.example?tenant=a",
            Err(ConfigurationRefused::Issuer(IssuerRefused::QueryComponent)),
        ),
        (
            "https://mandate.example#f",
            Err(ConfigurationRefused::Issuer(
                IssuerRefused::FragmentComponent,
            )),
        ),
        (
            "https://",
            Err(ConfigurationRefused::Issuer(IssuerRefused::HostMissing)),
        ),
        // RFC 8414 section 2 admits a path component on the issuer identifier.
        (
            "https://mandate.example/path",
            Ok("https://mandate.example/path"),
        ),
        ("https://mandate.example/", Ok("https://mandate.example")),
        // The loopback exception, and a host that only looks like it.
        ("http://127.0.0.1:8080", Ok("http://127.0.0.1:8080")),
        ("http://localhost", Ok("http://localhost")),
        (
            "http://127.0.0.1.evil.example",
            Err(ConfigurationRefused::Issuer(
                IssuerRefused::SchemeUnadmitted,
            )),
        ),
    ] {
        let answered = configured(issuer, "PT5M", "PT8H").checked();
        match (answered, expected) {
            (Ok(configuration), Ok(normalised)) => assert_eq!(
                configuration.issuer, normalised,
                "{issuer} normalises to {normalised}"
            ),
            (Err(refusal), Err(expected)) => {
                assert_eq!(refusal, expected, "{issuer}");
            }
            (answered, expected) => panic!("{issuer}: got {answered:?}, wanted {expected:?}"),
        }
    }

    // The two lifetimes.
    for lifetime in ["PT", "P0D", "PT0S", "-PT5M", "P1M", "", "5m"] {
        assert_eq!(
            configured(ISSUER, lifetime, "PT8H").checked().err(),
            Some(ConfigurationRefused::CodeLifetimeUnbounded),
            "a code lifetime of {lifetime:?} names no positive span"
        );
        assert_eq!(
            configured(ISSUER, "PT5M", lifetime).checked().err(),
            Some(ConfigurationRefused::SessionLifetimeUnbounded),
            "a session lifetime of {lifetime:?} names no positive span"
        );
    }
    assert!(
        configured(ISSUER, "PT1S", "PT8H").checked().is_ok(),
        "one second is a positive span"
    );
    // A session shorter than the code it will outlive is admitted, and nothing states it.
    assert!(
        configured(ISSUER, "PT5M", "PT1S").checked().is_ok(),
        "a session lifetime below the code lifetime is admitted"
    );
}

// ---------------------------------------------------------------------------------------
// 4. The request target's four forms, read past the two cases the unit wrote
// ---------------------------------------------------------------------------------------

/// `origin_form` decides RFC 9112 section 3.2's four forms. These are the ones the unit's own
/// two cases do not name: a path beginning `//`, a target carrying a fragment, an absolute-form
/// with a port, with an uppercase scheme and host, and with userinfo, and a percent-encoded `?`
/// that must not become a query delimiter.
#[test]
fn the_request_target_forms_reach_the_routes_they_name() {
    let world = serving();
    for (target, served, why) in [
        (
            "http://mandate.example:8080/oauth/jwks",
            true,
            "absolute-form with a port names the same path",
        ),
        (
            "HTTP://MANDATE.EXAMPLE/oauth/jwks",
            true,
            "RFC 3986 section 3.1: the scheme is case-insensitive",
        ),
        (
            "http://a@mandate.example/oauth/jwks",
            true,
            "RFC 3986 section 3.2.1: userinfo is part of the authority, not the path",
        ),
        (
            "//oauth/jwks",
            false,
            "RFC 3986 section 3.3: a path-absolute cannot begin with //, and this one names no \
             route",
        ),
        (
            "/oauth/jwks#frag",
            false,
            "RFC 9112 section 3.2.1: a request target carries no fragment",
        ),
        (
            "/oauth/jwks%3Fx",
            false,
            "a percent-encoded `?` is a path character and not a query delimiter",
        ),
    ] {
        let answered = exchange(world.address, &get(target, &[]));
        assert_eq!(
            answered.status == 200,
            served,
            "{target}: {why}; got {} {}",
            answered.status,
            answered.body
        );
    }
}

// ---------------------------------------------------------------------------------------
// 5. The deadline, measured rather than read
// ---------------------------------------------------------------------------------------

/// `src/serve.rs`'s module documentation states the bound in as many words: "One connection is
/// therefore bounded by `request_deadline + write_timeout`, and so is every other client's wait
/// behind it." Three clients, each measured against it: one that dribbles a body byte at a time
/// under the read timeout, one that opens the connection and sends nothing at all, and one that
/// writes a whole request and then never reads the response.
#[test]
fn one_connection_is_bounded_as_the_module_documentation_states() {
    let deadline = HostDuration::from_millis(600);
    let write_timeout = HostDuration::from_millis(400);
    let limits = Limits {
        read_timeout: HostDuration::from_millis(400),
        write_timeout,
        request_deadline: deadline,
        ..Limits::default()
    };
    let bound = deadline + write_timeout + HostDuration::from_millis(600);

    // (a) The head arrives whole, then one body byte at a time, each read inside the read
    // timeout, for longer than the deadline.
    let world = serving_full(REDIRECT, "PT5M", "PT8H", limits.clone());
    let started = Instant::now();
    let mut stream = TcpStream::connect(world.address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(10)))
        .expect("a read bound on the case's own socket");
    stream
        .write_all(
            b"POST /v1/federation/login HTTP/1.1\r\nHost: mandate.example\r\n\
              Content-Type: application/json\r\nContent-Length: 40\r\n\r\n",
        )
        .expect("the head is written");
    for _ in 0..40 {
        if stream.write_all(b"x").is_err() {
            break;
        }
        let _ = stream.flush();
        std::thread::sleep(HostDuration::from_millis(200));
    }
    let dribbled = read_response(&mut stream);
    let waited = started.elapsed();
    assert_eq!(dribbled.status, 400, "got {}", dribbled.body);
    assert!(
        waited < bound,
        "a dribbling body held the connection {waited:?}, past the documented \
         request_deadline + write_timeout"
    );

    // (b) A client that opens the connection and sends nothing.
    let world = serving_full(REDIRECT, "PT5M", "PT8H", limits.clone());
    let started = Instant::now();
    let mut silent = TcpStream::connect(world.address).expect("the listener accepts");
    silent
        .set_read_timeout(Some(HostDuration::from_secs(10)))
        .expect("a read bound on the case's own socket");
    let answered = read_response(&mut silent);
    let waited = started.elapsed();
    assert_eq!(answered.status, 400, "got {}", answered.body);
    assert!(
        waited < bound,
        "a connection that sent nothing was held {waited:?}"
    );

    // (c) A client that writes a whole request and never reads the response; the listener must
    // still come back round the accept loop for the client behind it.
    let world = serving_full(REDIRECT, "PT5M", "PT8H", limits);
    let mut deaf = TcpStream::connect(world.address).expect("the listener accepts");
    deaf.write_all(&get("/oauth/jwks", &[]))
        .expect("the request is written");
    deaf.flush().expect("the request is flushed");
    let started = Instant::now();
    let behind = exchange(world.address, &get("/oauth/jwks", &[]));
    let waited = started.elapsed();
    drop(deaf);
    assert_eq!(behind.status, 200, "got {}", behind.body);
    assert!(
        waited < bound,
        "the client behind a connection nobody was reading waited {waited:?}"
    );
}

// ---------------------------------------------------------------------------------------
// 6. The grant, twice; and what the session proof still opens
// ---------------------------------------------------------------------------------------

/// RFC 6749 section 4.1.2: "The client MUST NOT use the authorization code more than once. If
/// an authorization code is used more than once, the authorization server MUST deny the
/// request." The second redemption carries no credential and is a declared denial, and the
/// credential the first one issued is not collateral damage.
#[test]
fn one_authorization_code_is_redeemed_once() {
    let world = serving();
    let proof = session_proof(world.address);
    let redirected = authorize(world.address, world.target, &proof, REDIRECT, "xyzzy");
    assert_eq!(redirected.status, 302, "got {}", redirected.body);
    let code = code_of(&redirected.location());

    let first = exchange(
        world.address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body(&code, REDIRECT),
            &[],
        ),
    );
    assert_eq!(
        first.status, 200,
        "the first redemption answered {}",
        first.body
    );
    let credential = member(&first.body, "access_token");

    let second = exchange(
        world.address,
        &post(
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body(&code, REDIRECT),
            &[],
        ),
    );
    assert_eq!(
        second.status, 400,
        "RFC 6749 section 4.1.2: the second use of one code is denied; got {}",
        second.body
    );
    assert_eq!(
        member(&second.body, "error"),
        "invalid_grant",
        "RFC 6749 section 5.2: a code that is not valid is `invalid_grant`"
    );
    assert!(
        !second.body.contains("access_token"),
        "the second redemption answered a credential: {}",
        second.body
    );

    // The credential the one winner took is still the credential it took.
    let introspected = exchange(
        world.address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}", encoded(&credential)),
            &[("Authorization", &format!("Bearer {credential}"))],
        ),
    );
    assert_eq!(introspected.status, 200, "got {}", introspected.body);
    let document: serde_json::Value =
        serde_json::from_str(&introspected.body).expect("RFC 7662 section 2.2's JSON");
    assert_eq!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(true),
        "the refused replay revoked the credential the first redemption issued: {}",
        introspected.body
    );
}

/// A session proof is evidence of one session, and the session's own `expires_at` is what ends
/// it. The clock the deployment reads is the case's, so the case moves it past the configured
/// session lifetime and presents the same proof again. Nothing about the proof changed; the
/// session it names has expired, and the answer is a rendered refusal rather than a redirect —
/// the refusal is raised before the client and its registered redirect are validated.
#[test]
fn a_session_proof_stops_opening_an_authorization_when_its_session_expires() {
    let world = serving_full(REDIRECT, "PT5M", "PT1H", test_limits());
    let proof = session_proof(world.address);
    let first = authorize(world.address, world.target, &proof, REDIRECT, "xyzzy");
    assert_eq!(first.status, 302, "got {}", first.body);

    // A second code from the same session, before anything expires: allowed, and stated here
    // because nothing else states it.
    let second = authorize(world.address, world.target, &proof, REDIRECT, "again");
    assert_eq!(
        second.status, 302,
        "a session opens more than one authorization; got {}",
        second.body
    );
    assert_ne!(
        code_of(&first.location()),
        code_of(&second.location()),
        "two authorizations from one session are two codes"
    );

    world.clock.advance(3_601);
    let expired = authorize(world.address, world.target, &proof, REDIRECT, "xyzzy");
    assert_eq!(
        expired.status, 400,
        "the session behind the proof expired an hour ago; got {} {}",
        expired.status, expired.body
    );
    assert_eq!(
        expired.header("Location"),
        None,
        "a refusal raised before the client is validated is rendered, never redirected"
    );
}

/// The session proof names the session; `client_id` is a request parameter. A proof presented
/// with a client nobody registered is refused in place, and the code it would have carried is
/// never minted.
#[test]
fn a_session_proof_presented_with_an_unregistered_client_is_refused_in_place() {
    let world = serving();
    let proof = session_proof(world.address);
    let refused = authorize_as(
        world.address,
        world.target,
        &proof,
        REDIRECT,
        "xyzzy",
        &OAuthClientId::new(uuid(0x0d)).to_string(),
    );
    assert_eq!(
        refused.status, 400,
        "got {} {}",
        refused.status, refused.body
    );
    assert_eq!(
        refused.header("Location"),
        None,
        "RFC 6749 section 4.1.2.1: a refusal raised before the redirect URI is validated is \
         never redirected to the presented one"
    );
    assert_eq!(member(&refused.body, "error"), "unauthorized_client");
}

// ---------------------------------------------------------------------------------------
// 7. Introspection, and the audience it must not cross
// ---------------------------------------------------------------------------------------

/// **A caller holding a credential for one audience must not learn anything about a credential
/// for another.** RFC 7662 section 2.2: "the authorization server ... MUST ... determine
/// whether the protected resource is authorized to introspect this particular token"; section
/// 4 is explicit that an endpoint answering for tokens outside the caller's own resource is an
/// information leak. Both credentials here are the road's own: two registered targets, two
/// authorizations, two redemptions, one session.
#[test]
fn introspection_does_not_answer_across_audiences() {
    let world = serving();
    let mine = credential_for(&world, world.target);
    let theirs = credential_for(&world, world.other_target);

    let answered = exchange(
        world.address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}", encoded(&theirs)),
            &[("Authorization", &format!("Bearer {mine}"))],
        ),
    );
    let document: serde_json::Value = serde_json::from_str(&answered.body)
        .unwrap_or_else(|_| panic!("a JSON body, got {}", answered.body));
    assert_ne!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(true),
        "a caller holding a credential for one audience was answered `active: true` for a \
         credential issued to another: {}",
        answered.body
    );
    assert!(
        !answered.body.contains("\"sub\""),
        "the subject of another audience's credential is in the answer: {}",
        answered.body
    );
}

/// RFC 7662 section 2.2: a token the server cannot resolve is `active: false` and a 200, not an
/// error — the caller's own standing is the only thing an error speaks about. And
/// `token_type_hint` is section 2.1's optional parameter, which `INTROSPECT_PARAMETERS` admits
/// and discards.
#[test]
fn introspection_answers_an_unknown_token_and_admits_the_declared_hint() {
    let world = serving();
    let caller = credential_for(&world, world.target);

    let unknown = mandate_types::value::encode_base64(b"a credential nobody issued");
    let answered = exchange(
        world.address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}", encoded(&unknown)),
            &[("Authorization", &format!("Bearer {caller}"))],
        ),
    );
    assert_eq!(
        answered.status, 200,
        "RFC 7662 section 2.2: an unresolvable token is `active: false`; got {}",
        answered.body
    );
    let document: serde_json::Value =
        serde_json::from_str(&answered.body).expect("RFC 7662 section 2.2's JSON");
    assert_eq!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(false),
        "got {}",
        answered.body
    );

    let hinted = exchange(
        world.address,
        &post(
            "/oauth/introspect",
            "application/x-www-form-urlencoded",
            &format!("token={}&token_type_hint=access_token", encoded(&caller)),
            &[("Authorization", &format!("Bearer {caller}"))],
        ),
    );
    assert_eq!(
        hinted.status, 200,
        "RFC 7662 section 2.1 declares `token_type_hint`; got {}",
        hinted.body
    );
    let document: serde_json::Value =
        serde_json::from_str(&hinted.body).expect("RFC 7662 section 2.2's JSON");
    assert_eq!(
        document.get("active").and_then(serde_json::Value::as_bool),
        Some(true),
        "got {}",
        hinted.body
    );
}

// ---------------------------------------------------------------------------------------
// 8. The exact state, once more, through the value that decodes to two parameters
// ---------------------------------------------------------------------------------------

/// RFC 6749 section 4.1.2 returns "the exact value received from the client". The value here
/// percent-decodes to `a&code=x`: a client that re-encoded it wrongly would compose a
/// `Location` naming `code` twice, and the first of the two would be the caller's.
#[test]
fn a_state_that_decodes_to_another_parameter_round_trips_exactly() {
    let world = serving();
    let proof = session_proof(world.address);
    let redirected = authorize(world.address, world.target, &proof, REDIRECT, "a&code=x");
    assert_eq!(redirected.status, 302, "got {}", redirected.body);
    let location = redirected.location();
    let form = mandate_proto::oauth::decode_form(
        query_component(&location).unwrap_or_else(|| panic!("a query in {location}")),
    )
    .unwrap_or_else(|error| panic!("a form in {location}: {error:?}"));
    assert_eq!(
        form.get("state"),
        Some("a&code=x"),
        "the exact state, in {location}"
    );
    assert_eq!(
        form.keys().collect::<Vec<_>>(),
        vec!["code", "state"],
        "two parameters and no third smuggled in by the state: {location}"
    );
}
