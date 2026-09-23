//! Adversarial pass 1 on `story:relying-party-code-flow`: the composition binary as the
//! relying party of an external OIDC IdP, driven by the conditions the unit's own suite does
//! not build.
//!
//! Each case stands its own loopback RS256 test IdP, whose discovery document the case can
//! add members to or replace an endpoint in, and a `serve` child configured against it. The
//! browser is driven by hand, as in `tests/relying_party.rs`. No key is committed; the client
//! secret is written to this run's scratch directory and named on the command line by path.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use mandate_types::value::{decode_base64, encode_base64};

const CHILD: &str = "mandate-control-plane";
const AS_ISSUER: &str = "https://mandate.example";
const CALLBACK: &str = "https://mandate.example/v1/federation/callback";
const IDP_CLIENT: &str = "platform-rp";
const IDP_SECRET: &str = "adversary-secret-value";
const SECRET_REFERENCE: &str = "primary-idp";
const IDP_KID: &str = "idp-rsa-1";
const TENANT_CLAIM: &str = "https://idp.example/claims/org_id";
const TENANT_VALUE: &str = "org-4711";
const PAIRWISE_SUB: &str = "p7Qx2Lk9-rZ0aWm4Yc1_pairwise";
const LISTEN_DEADLINE: Duration = Duration::from_secs(30);
/// `PENDING_CAPACITY` in `services/control-plane/src/adapters.rs`, the shipped default.
const SHIPPED_PENDING_CAPACITY: usize = 4096;
const AS_KEY_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig","alg":"ES256",
  "crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn organization() -> String {
    "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a".to_owned()
}

fn connection() -> String {
    "c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0".to_owned()
}

fn base64url(bytes: &[u8]) -> String {
    encode_base64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("ASCII");
                out.push(u8::from_str_radix(hex, 16).expect("a percent escape"));
                index += 2;
            }
            other => out.push(other),
        }
        index += 1;
    }
    String::from_utf8(out).expect("UTF-8")
}

fn form(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs()
}

// ------------------------------------------------------------------------------- HTTP

struct Response {
    status: u16,
    /// The response head exactly as it arrived, line by line.
    head_lines: Vec<String>,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(held, _)| held.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn get(address: SocketAddr, target: &str) -> Response {
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("a read timeout");
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a response head");
    let head_lines: Vec<String> = head.split("\r\n").map(ToOwned::to_owned).collect();
    let status = head_lines
        .first()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let headers = head_lines
        .iter()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Response {
        status,
        head_lines,
        headers,
        body: body.to_owned(),
    }
}

fn target_of(url: &str) -> String {
    let rest = url.split_once("://").expect("an absolute URL").1;
    let offset = rest.find('/').expect("a path");
    rest[offset..].to_owned()
}

// --------------------------------------------------------------------------- the IdP

struct Grant {
    challenge: String,
    nonce: String,
    redirect_uri: String,
}

struct IdpState {
    issuer: String,
    /// Members added to (or replacing members of) the discovery document.
    discovery_extra: serde_json::Map<String, serde_json::Value>,
    grants: BTreeMap<String, Grant>,
    issued: usize,
    token_calls: usize,
}

struct TestIdp {
    address: SocketAddr,
    state: Arc<Mutex<IdpState>>,
}

impl TestIdp {
    fn start(discovery_extra: impl Fn(&str) -> serde_json::Value) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").expect("a loopback socket");
        let address = socket.local_addr().expect("the bound address");
        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("a generated RSA key");
        let issuer = format!("http://{address}");
        let extra = match discovery_extra(&issuer) {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        let state = Arc::new(Mutex::new(IdpState {
            issuer,
            discovery_extra: extra,
            grants: BTreeMap::new(),
            issued: 0,
            token_calls: 0,
        }));
        let serving = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in socket.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = answer(stream, &key, &serving);
            }
        });
        Self { address, state }
    }

    fn issuer(&self) -> String {
        format!("http://{}", self.address)
    }

    fn held(&self) -> std::sync::MutexGuard<'_, IdpState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn answer(
    mut stream: TcpStream,
    key: &RsaKeyPair,
    state: &Arc<Mutex<IdpState>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8(body).unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));

    let mut held = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let issuer = held.issuer.clone();
    let (status, extra, payload) = match (method.as_str(), path) {
        ("GET", "/.well-known/openid-configuration") => {
            let mut document = serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            });
            for (name, value) in &held.discovery_extra {
                document[name] = value.clone();
            }
            (200, String::new(), document.to_string())
        }
        ("GET", "/jwks") => {
            let public = key.public_key();
            (
                200,
                String::new(),
                serde_json::json!({"keys": [{
                    "kty": "RSA", "kid": IDP_KID, "use": "sig", "alg": "RS256",
                    "n": base64url(public.modulus().big_endian_without_leading_zero()),
                    "e": base64url(public.exponent().big_endian_without_leading_zero()),
                }]})
                .to_string(),
            )
        }
        ("GET", "/authorize") => {
            let parameters = form(query);
            held.issued += 1;
            let code = format!("idp-code-{}", held.issued);
            held.grants.insert(
                code.clone(),
                Grant {
                    challenge: parameters["code_challenge"].clone(),
                    nonce: parameters["nonce"].clone(),
                    redirect_uri: parameters["redirect_uri"].clone(),
                },
            );
            let location = format!(
                "{}?code={}&state={}&iss={}",
                parameters["redirect_uri"],
                percent_encode(&code),
                percent_encode(&parameters["state"]),
                percent_encode(&issuer),
            );
            (302, format!("Location: {location}\r\n"), String::new())
        }
        ("POST", "/token") => {
            held.token_calls += 1;
            let authenticated = headers
                .get("authorization")
                .and_then(|value| value.strip_prefix("Basic "))
                .and_then(|encoded| decode_base64(encoded).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .as_deref()
                .and_then(|pair| pair.split_once(':'))
                .is_some_and(|(client, secret)| {
                    percent_decode(client) == IDP_CLIENT && percent_decode(secret) == IDP_SECRET
                });
            let parameters = form(&body);
            let grant = parameters
                .get("code")
                .and_then(|code| held.grants.remove(code));
            match grant {
                Some(grant)
                    if authenticated
                        && parameters.get("redirect_uri") == Some(&grant.redirect_uri)
                        && base64url(
                            digest(
                                &SHA256,
                                parameters
                                    .get("code_verifier")
                                    .map(String::as_bytes)
                                    .unwrap_or_default(),
                            )
                            .as_ref(),
                        ) == grant.challenge =>
                {
                    let token = id_token(key, &issuer, &grant.nonce);
                    (
                        200,
                        "Cache-Control: no-store\r\n".to_owned(),
                        serde_json::json!({"token_type": "Bearer", "id_token": token}).to_string(),
                    )
                }
                _ => (
                    400,
                    String::new(),
                    r#"{"error":"invalid_grant"}"#.to_owned(),
                ),
            }
        }
        _ => (404, String::new(), String::new()),
    };
    drop(held);
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        _ => "Not Found",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )?;
    stream.flush()
}

fn id_token(key: &RsaKeyPair, issuer: &str, nonce: &str) -> String {
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": IDP_KID});
    let issued = now();
    let claims = serde_json::json!({
        "iss": issuer,
        "aud": IDP_CLIENT,
        "sub": PAIRWISE_SUB,
        "iat": issued,
        "exp": issued + 300,
        "nonce": nonce,
        TENANT_CLAIM: TENANT_VALUE,
    });
    let signing_input = format!(
        "{}.{}",
        base64url(header.to_string().as_bytes()),
        base64url(claims.to_string().as_bytes())
    );
    let mut signature = vec![0_u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .expect("an RS256 signature");
    format!("{signing_input}.{}", base64url(&signature))
}

// ------------------------------------------------------------------ the served child

struct Scratch(PathBuf);

impl Scratch {
    fn new(case: &str) -> Self {
        let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("adversary-rp-flow-1")
            .join(format!("run-{}", std::process::id()))
            .join(case);
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a writable scratch directory");
        Self(directory)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, body).expect("the document is written");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Served {
    child: Option<Child>,
    lines: Receiver<String>,
    _draining: Option<JoinHandle<()>>,
}

impl Served {
    fn spawn(arguments: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("the composition binary runs");
        let stdout = child.stdout.take().expect("a piped stdout");
        let (sending, lines) = channel();
        let draining = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let _ = sending.send(line.clone());
            }
        });
        Self {
            child: Some(child),
            lines,
            _draining: Some(draining),
        }
    }

    fn address(&mut self) -> SocketAddr {
        let deadline = Instant::now() + LISTEN_DEADLINE;
        let prefix = format!("{CHILD}: listening on ");
        loop {
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(25))
                && let Some(address) = line.trim().strip_prefix(&prefix)
            {
                return address.parse().expect("a socket address");
            }
            assert!(Instant::now() < deadline, "the child never listened");
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Stood {
    idp: TestIdp,
    _served: Served,
    address: SocketAddr,
    _scratch: Scratch,
}

fn stand(case: &str, discovery_extra: impl Fn(&str) -> serde_json::Value) -> Stood {
    let idp = TestIdp::start(discovery_extra);
    let scratch = Scratch::new(case);
    let connection_document = format!(
        r#"{{"connection_id":"{connection}","organization":"{organization}",
          "issuer":"{issuer}","client_id":"{IDP_CLIENT}","algorithm":"RS256",
          "tenant_resolution":{{"configured_organization":"{organization}",
            "verified_claim_name":"{TENANT_CLAIM}","verified_claim_value":"{TENANT_VALUE}"}},
          "jit_provisioning":true,
          "relying_party":{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}"}}}}"#,
        connection = connection(),
        organization = organization(),
        issuer = idp.issuer(),
    );
    let connection_path = scratch.write("connection.json", &connection_document);
    let key_path = scratch.write("key.json", AS_KEY_DOCUMENT);
    let secret_path = scratch.write("client-secret", &format!("{IDP_SECRET}\n"));
    let arguments = vec![
        "serve".to_owned(),
        "--listen".to_owned(),
        "127.0.0.1:0".to_owned(),
        "--issuer".to_owned(),
        AS_ISSUER.to_owned(),
        "--connection".to_owned(),
        connection_path.to_str().expect("UTF-8").to_owned(),
        "--key".to_owned(),
        key_path.to_str().expect("UTF-8").to_owned(),
        "--client-secret-file".to_owned(),
        format!(
            "{SECRET_REFERENCE}={}",
            secret_path.to_str().expect("UTF-8")
        ),
    ];
    let mut served = Served::spawn(&arguments);
    let address = served.address();
    Stood {
        idp,
        _served: served,
        address,
        _scratch: scratch,
    }
}

fn no_extra(_: &str) -> serde_json::Value {
    serde_json::json!({})
}

fn authorize(stood: &Stood) -> Response {
    get(
        stood.address,
        &format!("/v1/federation/authorize?connection_id={}", connection()),
    )
}

/// Mandate's authorize and the IdP's authorize: the callback query the IdP wrote, as a form.
fn to_the_idp_and_back(stood: &Stood) -> BTreeMap<String, String> {
    let started = authorize(stood);
    assert_eq!(started.status, 302, "{}", started.body);
    let location = started.header("Location").expect("a Location").to_owned();
    let at_idp = get(stood.idp.address, &target_of(&location));
    assert_eq!(at_idp.status, 302);
    let back = at_idp.header("Location").expect("a Location").to_owned();
    form(
        back.strip_prefix(&format!("{CALLBACK}?"))
            .expect("the IdP returns to the registered redirect URI"),
    )
}

fn callback(stood: &Stood, parameters: &[(&str, &str)]) -> Response {
    let query: Vec<String> = parameters
        .iter()
        .map(|(name, value)| format!("{name}={}", percent_encode(value)))
        .collect();
    get(
        stood.address,
        &format!("/v1/federation/callback?{}", query.join("&")),
    )
}

fn opened_a_session(response: &Response) -> bool {
    response.status == 200 && response.body.contains("session_id")
}

// ---------------------------------------------------------------------------- the cases

/// RFC 9207 section 2.4: a client that has the IdP's metadata stating
/// `authorization_response_iss_parameter_supported: true` MUST reject an authorization
/// response that does not carry `iss`. `decode.rs` names RFC 9207 as the reason `iss` is
/// read; the handler only compares it when present, so dropping it is a way past the check.
#[test]
fn a_callback_without_iss_from_an_idp_that_advertises_it_opens_nothing() {
    let stood = stand(
        "iss-advertised",
        |_| serde_json::json!({"authorization_response_iss_parameter_supported": true}),
    );
    let returned = to_the_idp_and_back(&stood);
    assert!(returned.contains_key("iss"), "the IdP sent iss");
    let completed = callback(
        &stood,
        &[("code", &returned["code"]), ("state", &returned["state"])],
    );
    assert!(
        !opened_a_session(&completed),
        "an authorization response without the iss its IdP advertises opened a session: {}",
        completed.body
    );
}

/// `RelyingParty`'s own doc (`adapters.rs`): a pending sign-in is "taken out on the first
/// callback that names it whatever that callback's outcome". An IdP's error response
/// (`error=access_denied&state=…`, OIDC Core 3.1.2.6) names the state and is refused, and the
/// state is still there to be completed afterwards.
#[test]
fn an_idp_error_response_naming_the_state_consumes_it() {
    let stood = stand("error-response", no_extra);
    let returned = to_the_idp_and_back(&stood);
    let errored = callback(
        &stood,
        &[("error", "access_denied"), ("state", &returned["state"])],
    );
    assert!(!opened_a_session(&errored), "{}", errored.body);
    let later = callback(
        &stood,
        &[
            ("code", &returned["code"]),
            ("state", &returned["state"]),
            ("iss", &returned["iss"]),
        ],
    );
    assert!(
        !opened_a_session(&later),
        "a state a refused callback named was used again: {}",
        later.body
    );
    assert_eq!(stood.idp.held().token_calls, 0, "no code was redeemed");
}

/// The pending store is one global map, filled by an anonymous `GET` and never evicted
/// before its 600 s lifetime: whoever sends `PENDING_CAPACITY` authorize requests denies
/// every other browser a sign-in, through every connection, for ten minutes at a time.
#[test]
fn anonymous_authorize_requests_cannot_lock_every_other_browser_out_of_signing_in() {
    let stood = stand("pending-lockout", no_extra);
    for _ in 0..SHIPPED_PENDING_CAPACITY {
        let started = authorize(&stood);
        assert_eq!(started.status, 302, "{}", started.body);
    }
    let victim = authorize(&stood);
    assert_eq!(
        victim.status, 302,
        "a browser was refused a sign-in because an anonymous caller filled the pending store: \
         {} {}",
        victim.status, victim.body
    );
}

/// The `authorization_endpoint` the IdP's discovery document names is written verbatim into
/// this deployment's `Location` header. `UreqJwks::admits` reads the origin alone, so a CR LF
/// later in the string is admitted, and the IdP's bytes become headers of Mandate's own
/// response: a `Set-Cookie` on Mandate's origin here.
#[test]
fn a_discovered_authorization_endpoint_cannot_write_headers_into_mandates_response() {
    let stood = stand("header-injection", |issuer| {
        serde_json::json!({
            "authorization_endpoint": format!("{issuer}/authorize\r\nSet-Cookie: injected=1")
        })
    });
    let started = authorize(&stood);
    let injected: Vec<&String> = started
        .head_lines
        .iter()
        .filter(|line| line.to_ascii_lowercase().starts_with("set-cookie"))
        .collect();
    assert!(
        injected.is_empty(),
        "the IdP's discovery document wrote a header into Mandate's response: {injected:?} \
         (status {})",
        started.status
    );
}
