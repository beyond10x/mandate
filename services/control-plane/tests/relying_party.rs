//! The composition binary as the **relying party** of an external OIDC IdP: a browser opens
//! `GET /v1/federation/authorize`, is sent to the IdP, comes back to
//! `GET /v1/federation/callback`, and the child redeems the code at the IdP's token endpoint
//! with HTTP Basic client authentication and a PKCE verifier (`story:relying-party-code-flow`).
//!
//! # The test IdP
//!
//! [`TestIdp`] is a loopback HTTP issuer standing beside the child. It publishes a discovery
//! document, a JWK Set holding one RS256 key generated when the case runs, an authorization
//! endpoint that records the challenge and nonce it was sent and redirects with a code, and a
//! token endpoint that admits **only** `client_secret_basic`, checks the S256 verifier against
//! the recorded challenge, and answers a signed ID token. Its `sub` is **pairwise** — an
//! opaque string no identifier in this file names — and its tenant claim is **URL-named**
//! (`https://idp.example/claims/org_id`).
//!
//! The case drives the browser itself: it reads each `Location` and follows it by hand, so
//! nothing here depends on a user agent.
//!
//! **No key is committed**, and the client secret is written to a file in this run's scratch
//! directory and named on the command line by path only.

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
const IDP_SECRET: &str = "s3cr3t:with&reserved=chars";
const SECRET_REFERENCE: &str = "primary-idp";
const IDP_KID: &str = "idp-rsa-1";
const TENANT_CLAIM: &str = "https://idp.example/claims/org_id";
const TENANT_VALUE: &str = "org-4711";
/// Pairwise: opaque, per client, and no identifier this file names.
const PAIRWISE_SUB: &str = "p7Qx2Lk9-rZ0aWm4Yc1_pairwise";
const LISTEN_DEADLINE: Duration = Duration::from_secs(30);
const AS_KEY_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig","alg":"ES256",
  "crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn organization() -> String {
    "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a".to_owned()
}

fn connection() -> String {
    "c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0".to_owned()
}

// ---------------------------------------------------------------------------- encodings

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

/// A query or form, decoded. A repeated key is a failure of the case, not a pick.
fn form(text: &str) -> BTreeMap<String, String> {
    let mut decoded = BTreeMap::new();
    for pair in text.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        assert!(
            decoded
                .insert(percent_decode(key), percent_decode(value))
                .is_none(),
            "{key} repeated in {text}"
        );
    }
    decoded
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
    send(address, "GET", target, &[], None)
}

/// One request: the method, the target, extra header lines, and an optional JSON body.
fn send(
    address: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    json: Option<&str>,
) -> Response {
    let mut stream = TcpStream::connect(address).expect("the listener accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("a read timeout");
    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = json {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    head.push_str(json.unwrap_or_default());
    stream
        .write_all(head.as_bytes())
        .expect("the request is written");
    let mut raw = String::new();
    stream
        .read_to_string(&mut raw)
        .expect("the response is read");
    let (head, body) = raw.split_once("\r\n\r\n").expect("a response head");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Response {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// The origin-form target of an absolute URL on a loopback host.
fn target_of(url: &str) -> String {
    let rest = url.split_once("://").expect("an absolute URL").1;
    let offset = rest.find('/').expect("a path");
    rest[offset..].to_owned()
}

// --------------------------------------------------------------------------- the IdP

/// How the test IdP departs from a correct one, for the case that drives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    None,
    /// The ID token carries a nonce the authorization request never sent.
    Nonce,
    /// The authorization endpoint records a challenge the request never sent, so the
    /// verifier the relying party presents does not redeem it.
    Challenge,
    /// The discovery document advertises `iss` in the authorization response (RFC 9207).
    AdvertiseIss,
}

struct Grant {
    challenge: String,
    nonce: String,
    redirect_uri: String,
}

struct IdpState {
    issuer: String,
    tamper: Tamper,
    grants: BTreeMap<String, Grant>,
    issued: usize,
    token_calls: usize,
    basic_refused: usize,
    pkce_refused: usize,
    /// The last ID token the token endpoint answered, for the case that presents it
    /// elsewhere.
    last_id_token: Option<String>,
}

struct TestIdp {
    address: SocketAddr,
    state: Arc<Mutex<IdpState>>,
}

impl TestIdp {
    fn start(tamper: Tamper) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").expect("a loopback socket");
        let address = socket.local_addr().expect("the bound address");
        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("a generated RSA key");
        let state = Arc::new(Mutex::new(IdpState {
            issuer: format!("http://{address}"),
            tamper,
            grants: BTreeMap::new(),
            issued: 0,
            token_calls: 0,
            basic_refused: 0,
            pkce_refused: 0,
            last_id_token: None,
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
        ("GET", "/.well-known/openid-configuration") => (
            200,
            String::new(),
            serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "authorization_response_iss_parameter_supported":
                    held.tamper == Tamper::AdvertiseIss,
            })
            .to_string(),
        ),
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
            let challenge = if held.tamper == Tamper::Challenge {
                base64url(digest(&SHA256, b"a verifier nobody holds").as_ref())
            } else {
                parameters["code_challenge"].clone()
            };
            held.grants.insert(
                code.clone(),
                Grant {
                    challenge,
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
            let presented = headers
                .get("authorization")
                .and_then(|value| value.strip_prefix("Basic "))
                .and_then(|encoded| decode_base64(encoded).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok());
            let authenticated = presented
                .as_deref()
                .and_then(|pair| pair.split_once(':'))
                .is_some_and(|(client, secret)| {
                    percent_decode(client) == IDP_CLIENT && percent_decode(secret) == IDP_SECRET
                });
            let parameters = form(&body);
            if !authenticated || parameters.contains_key("client_secret") {
                held.basic_refused += 1;
                (
                    401,
                    "WWW-Authenticate: Basic\r\n".to_owned(),
                    r#"{"error":"invalid_client"}"#.to_owned(),
                )
            } else {
                let grant = parameters
                    .get("code")
                    .and_then(|code| held.grants.remove(code));
                match grant {
                    Some(grant)
                        if parameters.get("grant_type").map(String::as_str)
                            == Some("authorization_code")
                            && parameters.get("redirect_uri") == Some(&grant.redirect_uri) =>
                    {
                        let verifier = parameters.get("code_verifier").cloned().unwrap_or_default();
                        if base64url(digest(&SHA256, verifier.as_bytes()).as_ref())
                            != grant.challenge
                        {
                            held.pkce_refused += 1;
                            (
                                400,
                                String::new(),
                                r#"{"error":"invalid_grant"}"#.to_owned(),
                            )
                        } else {
                            let nonce = if held.tamper == Tamper::Nonce {
                                "a-nonce-nobody-sent".to_owned()
                            } else {
                                grant.nonce
                            };
                            let token = id_token(key, &issuer, &nonce);
                            held.last_id_token = Some(token.clone());
                            (
                                200,
                                "Cache-Control: no-store\r\n".to_owned(),
                                serde_json::json!({
                                    "access_token": "opaque-idp-access-token",
                                    "token_type": "Bearer",
                                    "expires_in": 300,
                                    "id_token": token,
                                })
                                .to_string(),
                            )
                        }
                    }
                    _ => (
                        400,
                        String::new(),
                        r#"{"error":"invalid_grant"}"#.to_owned(),
                    ),
                }
            }
        }
        _ => (404, String::new(), String::new()),
    };
    drop(held);
    let reason = match status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
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

/// An RS256 ID token for the pairwise subject, carrying the URL-named tenant claim.
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

/// One case's scratch directory, removed when the case ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(case: &str) -> Self {
        let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("relying-party")
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
    printed: Arc<Mutex<String>>,
    draining: Option<JoinHandle<()>>,
    stderr: Option<std::process::ChildStderr>,
}

impl Served {
    fn spawn(arguments: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the composition binary runs");
        let stdout = child.stdout.take().expect("a piped stdout");
        let stderr = child.stderr.take();
        let printed = Arc::new(Mutex::new(String::new()));
        let accumulating = Arc::clone(&printed);
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
                accumulating
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push_str(&line);
                let _ = sending.send(line.clone());
            }
        });
        Self {
            child: Some(child),
            lines,
            printed,
            draining: Some(draining),
            stderr,
        }
    }

    fn output(&mut self) -> (String, String) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(draining) = self.draining.take() {
            let _ = draining.join();
        }
        let out = self
            .printed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut err = String::new();
        if let Some(mut handle) = self.stderr.take() {
            let _ = handle.read_to_string(&mut err);
        }
        (out, err)
    }

    fn address(&mut self) -> SocketAddr {
        let deadline = Instant::now() + LISTEN_DEADLINE;
        let prefix = format!("{CHILD}: listening on ");
        loop {
            let exited = self
                .child
                .as_mut()
                .is_none_or(|child| child.try_wait().is_ok_and(|status| status.is_some()));
            if exited {
                let (out, err) = self.output();
                panic!("the child exited before it listened; stdout {out:?}, stderr {err:?}");
            }
            if let Ok(line) = self.lines.recv_timeout(Duration::from_millis(25))
                && let Some(address) = line.trim().strip_prefix(&prefix)
            {
                return address.parse().expect("a socket address");
            }
            if Instant::now() >= deadline {
                let (out, err) = self.output();
                panic!("the child never listened; stdout {out:?}, stderr {err:?}");
            }
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

/// The IdP, the child serving a connection to it, and the child's address.
struct Stood {
    idp: TestIdp,
    served: Served,
    address: SocketAddr,
    _scratch: Scratch,
}

/// Where the callback sends the browser once a session is open: the embedding
/// application's page.
const RETURN_URI: &str = "https://app.example/signed-in";

fn stand(case: &str, tamper: Tamper, secret_in_file: &str) -> Stood {
    let idp = TestIdp::start(tamper);
    let scratch = Scratch::new(case);
    let connection_document = format!(
        r#"{{"connection_id":"{connection}","organization":"{organization}",
          "issuer":"{issuer}","client_id":"{IDP_CLIENT}","algorithm":"RS256",
          "tenant_resolution":{{"configured_organization":"{organization}",
            "verified_claim_name":"{TENANT_CLAIM}","verified_claim_value":"{TENANT_VALUE}"}},
          "jit_provisioning":true,
          "relying_party":{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}",
            "return_uri":"{RETURN_URI}"}}}}"#,
        connection = connection(),
        organization = organization(),
        issuer = idp.issuer(),
    );
    let connection_path = scratch.write("connection.json", &connection_document);
    let key_path = scratch.write("key.json", AS_KEY_DOCUMENT);
    let secret_path = scratch.write("client-secret", &format!("{secret_in_file}\n"));
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
        served,
        address,
        _scratch: scratch,
    }
}

/// The browser-binding cookie's name.
const BINDING_COOKIE: &str = "__Host-mandate-rp";

/// What a browser holds after the IdP has sent it back: the callback query the IdP wrote
/// and the binding cookie the authorize step set.
struct Returned {
    query: String,
    cookie: String,
}

impl Returned {
    fn parameters(&self) -> BTreeMap<String, String> {
        form(&self.query)
    }
}

/// Mandate's authorize and the IdP's authorize, as a browser follows them.
fn to_the_idp_and_back(stood: &Stood) -> Returned {
    to_the_idp_and_back_holding(stood, None, None)
}

/// The same, with the embedding application's `app_state` on the authorize request.
fn to_the_idp_and_back_with(stood: &Stood, app_state: Option<&str>) -> Returned {
    to_the_idp_and_back_holding(stood, app_state, None)
}

/// The same, from a browser already holding the binding cookie `holding`.
fn to_the_idp_and_back_holding(
    stood: &Stood,
    app_state: Option<&str>,
    holding: Option<&str>,
) -> Returned {
    let bound = app_state.map_or_else(String::new, |value| format!("&app_state={value}"));
    let headers: Vec<(&str, &str)> = holding.map(|c| ("Cookie", c)).into_iter().collect();
    let started = send(
        stood.address,
        "GET",
        &format!(
            "/v1/federation/authorize?connection_id={}{bound}",
            connection()
        ),
        &headers,
        None,
    );
    assert_eq!(
        started.status, 302,
        "the browser is sent to the IdP: {}",
        started.body
    );
    let set_cookie = started
        .header("Set-Cookie")
        .expect("the authorize step binds the browser")
        .to_owned();
    let attributes: Vec<&str> = set_cookie.split(';').map(str::trim).collect();
    for required in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(attributes.contains(&required), "{required} in {set_cookie}");
    }
    assert!(
        !attributes.iter().any(|a| a.starts_with("Domain")),
        "a __Host- cookie names no Domain: {set_cookie}"
    );
    let cookie = attributes[0].to_owned();
    let (name, value) = cookie.split_once('=').expect("name=value");
    assert_eq!(name, BINDING_COOKIE);
    assert!(value.len() >= 22, "an unguessable binding");

    let location = started.header("Location").expect("a Location").to_owned();
    let authorization_endpoint = format!("{}/authorize?", stood.idp.issuer());
    let query = location
        .strip_prefix(&authorization_endpoint)
        .unwrap_or_else(|| panic!("{location} is the IdP's authorization endpoint"));
    let parameters = form(query);
    assert_eq!(parameters["response_type"], "code");
    assert_eq!(parameters["client_id"], IDP_CLIENT);
    assert_eq!(parameters["redirect_uri"], CALLBACK);
    assert_eq!(parameters["code_challenge_method"], "S256");
    assert_eq!(parameters["code_challenge"].len(), 43);
    assert!(
        parameters["scope"]
            .split(' ')
            .any(|scope| scope == "openid")
    );
    assert!(parameters["state"].len() >= 22, "an unguessable state");
    assert!(parameters["nonce"].len() >= 22, "an unguessable nonce");
    assert_ne!(parameters["state"], parameters["nonce"]);
    assert_ne!(parameters["state"], value, "the binding is not the state");
    assert!(
        !location.contains(IDP_SECRET) && !location.contains(&percent_encode(IDP_SECRET)),
        "the client secret never reaches the browser"
    );

    let at_idp = get(stood.idp.address, &target_of(&location));
    assert_eq!(at_idp.status, 302);
    let back = at_idp.header("Location").expect("a Location").to_owned();
    Returned {
        query: back
            .strip_prefix(&format!("{CALLBACK}?"))
            .expect("the IdP returns to the registered redirect URI")
            .to_owned(),
        cookie,
    }
}

/// The callback, as the browser that holds `cookie` reaches it with `query`.
fn callback(stood: &Stood, query: &str, cookie: Option<&str>) -> Response {
    let headers: Vec<(&str, &str)> = cookie.map(|c| ("Cookie", c)).into_iter().collect();
    send(
        stood.address,
        "GET",
        &format!("/v1/federation/callback?{query}"),
        &headers,
        None,
    )
}

/// The whole walk: out to the IdP and back to the callback, as one browser.
fn walk(stood: &Stood) -> (Returned, Response) {
    let returned = to_the_idp_and_back(stood);
    let completed = callback(stood, &returned.query, Some(&returned.cookie));
    (returned, completed)
}

/// The handoff code a completed callback sent the browser to the return URI with, if it did.
fn handoff_of(response: &Response) -> Option<String> {
    if response.status != 302 {
        return None;
    }
    let location = response.header("Location")?;
    let query = location.strip_prefix(&format!("{RETURN_URI}?"))?;
    form(query).get("handoff").cloned()
}

/// The embedding application's server-to-server exchange of a handoff code.
fn exchange(stood: &Stood, code: &str) -> Response {
    exchange_with(stood, code, None)
}

/// The exchange, presenting the embedding application's own `app_state`.
fn exchange_with(stood: &Stood, code: &str, app_state: Option<&str>) -> Response {
    let mut body = serde_json::json!({ "handoff": code });
    if let Some(value) = app_state {
        body["app_state"] = value.into();
    }
    send(
        stood.address,
        "POST",
        "/v1/federation/handoff",
        &[],
        Some(&body.to_string()),
    )
}

/// Whether a callback opened a session: it sent the browser on with a handoff code.
fn opened_a_session(response: &Response) -> bool {
    handoff_of(response).is_some()
}

/// The clauses the child recorded for the callbacks it refused, off its own stderr.
fn refused_for(stood: &mut Stood) -> String {
    let (_, err) = stood.served.output();
    err.lines()
        .filter_map(|line| {
            line.strip_prefix("mandate-control-plane: refused relying-party callback ")
        })
        .collect::<Vec<&str>>()
        .join(",")
}

// ---------------------------------------------------------------------------- the cases

#[test]
fn a_browser_signs_in_through_the_code_flow_and_a_replayed_state_opens_nothing() {
    let mut stood = stand("signs-in", Tamper::None, IDP_SECRET);
    let (returned, completed) = walk(&stood);
    let code = handoff_of(&completed)
        .unwrap_or_else(|| panic!("a handoff: {} {}", completed.status, completed.body));
    assert!(code.len() >= 22, "an unguessable handoff code");
    assert_eq!(completed.header("Cache-Control"), Some("no-store"));
    assert!(
        !completed.body.contains("session_proof")
            && !completed
                .header("Location")
                .unwrap_or_default()
                .contains("session"),
        "the session proof never rides the browser's navigation"
    );
    let cleared = completed
        .header("Set-Cookie")
        .expect("the binding is cleared");
    assert!(
        cleared.starts_with(&format!("{BINDING_COOKIE}=;")) && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert_eq!(stood.idp.held().token_calls, 1);

    let exchanged = exchange(&stood, &code);
    assert_eq!(exchanged.status, 200, "{}", exchanged.body);
    assert_eq!(exchanged.header("Cache-Control"), Some("no-store"));
    let login: serde_json::Value =
        serde_json::from_str(&exchanged.body).expect("a JSON login response");
    assert_eq!(login["organization_id"], organization().as_str());
    assert!(
        login["session_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );
    assert!(
        login["session_proof"]
            .as_str()
            .is_some_and(|proof| !proof.is_empty())
    );

    // The same state again, from the same browser: single-use, so nothing is redeemed.
    let replayed = callback(&stood, &returned.query, Some(&returned.cookie));
    assert!(!opened_a_session(&replayed), "{}", replayed.body);
    assert_eq!(
        stood.idp.held().token_calls,
        1,
        "a replayed state reaches no IdP"
    );

    let (out, err) = stood.served.output();
    assert!(
        !out.contains(IDP_SECRET) && !err.contains(IDP_SECRET),
        "the client secret is in no output: {out:?} {err:?}"
    );
    assert!(
        err.contains("mandate-control-plane: refused relying-party callback StateMismatch"),
        "the replay was refused as a used state: {err:?}"
    );
}

#[test]
fn a_handoff_code_is_exchanged_once_and_an_unknown_one_never() {
    let mut stood = stand("handoff-once", Tamper::None, IDP_SECRET);
    let (_, completed) = walk(&stood);
    let code = handoff_of(&completed).expect("a handoff code");
    assert_eq!(exchange(&stood, &code).status, 200);
    let again = exchange(&stood, &code);
    assert_ne!(again.status, 200, "{}", again.body);
    assert!(!again.body.contains("session_proof"), "{}", again.body);
    let unknown = exchange(&stood, "a-handoff-code-nobody-was-given");
    assert_ne!(unknown.status, 200, "{}", unknown.body);
    let (_, err) = stood.served.output();
    assert_eq!(
        err.matches("refused relying-party handoff SessionUnknown")
            .count(),
        2,
        "{err}"
    );
}

#[test]
fn a_wrong_state_opens_nothing_and_redeems_nothing() {
    let mut stood = stand("wrong-state", Tamper::None, IDP_SECRET);
    let returned = to_the_idp_and_back(&stood);
    let forged = format!(
        "code={}&state={}",
        percent_encode(&returned.parameters()["code"]),
        percent_encode("a-state-this-deployment-never-issued"),
    );
    let completed = callback(&stood, &forged, Some(&returned.cookie));
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(
        stood.idp.held().token_calls,
        0,
        "an unknown state reaches no IdP"
    );
    assert_eq!(refused_for(&mut stood), "StateMismatch");
}

/// F5: login CSRF. A callback URL completed by a client that is not the browser that
/// started the sign-in — no binding cookie, or another browser's — opens nothing, reaches
/// no IdP, and uses the state up.
#[test]
fn a_callback_from_another_browser_opens_nothing_and_uses_the_state_up() {
    let mut stood = stand("browser-binding", Tamper::None, IDP_SECRET);
    let first = to_the_idp_and_back(&stood);
    let without = callback(&stood, &first.query, None);
    assert!(!opened_a_session(&without), "{}", without.body);
    let later = callback(&stood, &first.query, Some(&first.cookie));
    assert!(
        !opened_a_session(&later),
        "a state an unbound callback named was used again"
    );

    let second = to_the_idp_and_back(&stood);
    let other = to_the_idp_and_back(&stood);
    let crossed = callback(&stood, &second.query, Some(&other.cookie));
    assert!(!opened_a_session(&crossed), "{}", crossed.body);
    let doubled = format!("{}; {}", other.cookie, other.cookie);
    let ambiguous = callback(&stood, &other.query, Some(&doubled));
    assert!(!opened_a_session(&ambiguous), "{}", ambiguous.body);

    assert_eq!(stood.idp.held().token_calls, 0, "no code was redeemed");
    assert_eq!(
        refused_for(&mut stood),
        "StateMismatch,StateMismatch,StateMismatch,StateMismatch"
    );
}

/// F3: an IdP error response names the state, is refused, and uses it up — the same
/// browser cannot complete that sign-in afterwards — and nothing of the IdP's text is
/// echoed.
#[test]
fn an_idp_error_response_uses_the_state_up_and_echoes_nothing() {
    let mut stood = stand("idp-error", Tamper::None, IDP_SECRET);
    let returned = to_the_idp_and_back(&stood);
    let state = returned.parameters()["state"].clone();
    let errored = callback(
        &stood,
        &format!(
            "error=access_denied&error_description={}&error_uri={}&state={}",
            percent_encode("<script>marker-from-the-idp</script>"),
            percent_encode("https://idp.example/why"),
            percent_encode(&state)
        ),
        Some(&returned.cookie),
    );
    assert!(!opened_a_session(&errored), "{}", errored.body);
    assert!(
        !errored.body.contains("marker-from-the-idp") && !errored.body.contains("idp.example/why"),
        "{}",
        errored.body
    );
    let later = callback(&stood, &returned.query, Some(&returned.cookie));
    assert!(!opened_a_session(&later), "{}", later.body);
    assert_eq!(stood.idp.held().token_calls, 0, "no code was redeemed");
    assert_eq!(refused_for(&mut stood), "ProofInvalid,StateMismatch");
}

/// F2: RFC 9207 section 2.4. The IdP advertises `iss` in its authorization response, so a
/// callback that carries none is refused before any code is redeemed — and one that carries
/// it signs in.
#[test]
fn a_callback_without_the_iss_its_idp_advertises_opens_nothing() {
    let mut stood = stand("iss-advertised", Tamper::AdvertiseIss, IDP_SECRET);
    let returned = to_the_idp_and_back(&stood);
    let parameters = returned.parameters();
    assert!(parameters.contains_key("iss"), "the IdP sent iss");
    let stripped = format!(
        "code={}&state={}",
        percent_encode(&parameters["code"]),
        percent_encode(&parameters["state"])
    );
    let completed = callback(&stood, &stripped, Some(&returned.cookie));
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(stood.idp.held().token_calls, 0, "no code was redeemed");

    let (_, carried) = walk(&stood);
    assert!(opened_a_session(&carried), "{}", carried.body);
    assert_eq!(refused_for(&mut stood), "IssuerMismatch");
}

/// F10: a connection that signs browsers in through its IdP admits no ID token presented at
/// `/v1/federation/login` — not even a valid one this IdP signed for this client — because
/// that route has no nonce to bind it to.
#[test]
fn a_relying_party_connection_admits_no_proof_at_the_login_route() {
    let mut stood = stand("login-refused", Tamper::None, IDP_SECRET);
    let (_, completed) = walk(&stood);
    assert!(opened_a_session(&completed), "{}", completed.body);
    let token = stood
        .idp
        .held()
        .last_id_token
        .clone()
        .expect("the IdP issued an ID token");
    let presented = send(
        stood.address,
        "POST",
        "/v1/federation/login",
        &[],
        Some(
            &serde_json::json!({
                "connection_id": connection(),
                "proof": encode_base64(token.as_bytes()),
            })
            .to_string(),
        ),
    );
    assert_ne!(presented.status, 200, "{}", presented.body);
    assert!(!presented.body.contains("session_id"), "{}", presented.body);
    let (_, err) = stood.served.output();
    assert!(
        err.contains("refused mandate.federation.AuthenticateFederation NonceMismatch"),
        "{err}"
    );
}

/// A: two tabs of one browser sign in at once. The second authorize keeps the first tab's
/// binding beside its own, each callback removes only its own, and both complete — in
/// either order.
#[test]
fn two_tabs_of_one_browser_each_complete_their_own_sign_in() {
    let stood = stand("two-tabs-own", Tamper::None, IDP_SECRET);
    let first = to_the_idp_and_back(&stood);
    let second = to_the_idp_and_back_holding(&stood, None, Some(&first.cookie));
    let first_binding = first.cookie.split_once('=').expect("name=value").1;
    let held = second.cookie.split_once('=').expect("name=value").1;
    let bindings: Vec<&str> = held.split('.').collect();
    assert_eq!(bindings.len(), 2, "{held}");
    assert_eq!(
        bindings[0], first_binding,
        "the first tab's binding is kept"
    );

    // The first tab returns first, from the browser that holds both.
    let completed = callback(&stood, &first.query, Some(&second.cookie));
    assert!(opened_a_session(&completed), "{}", completed.body);
    let left = completed
        .header("Set-Cookie")
        .expect("the used binding is dropped");
    let left_value = left
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .expect("name=value")
        .1;
    assert_eq!(
        left_value, bindings[1],
        "only the second tab's binding is left"
    );
    assert!(!left.contains("Max-Age=0"), "{left}");

    let remaining = format!("{BINDING_COOKIE}={left_value}");
    let completed = callback(&stood, &second.query, Some(&remaining));
    assert!(opened_a_session(&completed), "{}", completed.body);
    let cleared = completed
        .header("Set-Cookie")
        .expect("the last binding is cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    // A callback naming a state nobody issued changes nothing the browser holds.
    let forged = callback(&stood, "code=x&state=nobody-issued-this", Some(&remaining));
    assert!(!opened_a_session(&forged));
    assert!(
        forged.header("Set-Cookie").is_none(),
        "the browser's cookie is left alone"
    );
}

/// E: the handoff is bound to the embedding application. An attacker who completes a
/// sign-in of their own and delivers its handoff code to a victim's application redeems
/// nothing there — the victim's application presents its own `app_state` — and the code is
/// used up by the attempt, so the attacker cannot then redeem it either.
#[test]
fn an_attackers_handoff_presented_with_another_app_state_redeems_nothing() {
    let mut stood = stand("app-state", Tamper::None, IDP_SECRET);
    let attacker = to_the_idp_and_back_with(&stood, Some("attacker-app-state"));
    let completed = callback(&stood, &attacker.query, Some(&attacker.cookie));
    let code = handoff_of(&completed).expect("the attacker's own sign-in completed");
    let location = completed.header("Location").expect("a Location").to_owned();
    let returned = form(location.split_once('?').expect("a query").1);
    assert_eq!(
        returned.get("app_state").map(String::as_str),
        Some("attacker-app-state"),
        "the app_state comes back beside the handoff: {location}"
    );

    let at_victim = exchange_with(&stood, &code, Some("victim-app-state"));
    assert_ne!(at_victim.status, 200, "{}", at_victim.body);
    assert!(
        !at_victim.body.contains("session_proof"),
        "{}",
        at_victim.body
    );
    let afterwards = exchange_with(&stood, &code, Some("attacker-app-state"));
    assert_ne!(
        afterwards.status, 200,
        "the refused attempt used the code up"
    );

    // A handoff bound to an app_state is not redeemed without one, and is with the right one.
    let own = to_the_idp_and_back_with(&stood, Some("the-apps-own-state"));
    let own_code =
        handoff_of(&callback(&stood, &own.query, Some(&own.cookie))).expect("a handoff code");
    assert_ne!(exchange(&stood, &own_code).status, 200);
    let again = to_the_idp_and_back_with(&stood, Some("the-apps-own-state"));
    let again_code =
        handoff_of(&callback(&stood, &again.query, Some(&again.cookie))).expect("a handoff code");
    let redeemed = exchange_with(&stood, &again_code, Some("the-apps-own-state"));
    assert_eq!(redeemed.status, 200, "{}", redeemed.body);

    // An app_state outside the URL-safe set, or over the bound, is refused at authorize and
    // sets no binding.
    for bad in ["has%20space", "semi%3Bcolon", &"a".repeat(257)] {
        let refused = get(
            stood.address,
            &format!(
                "/v1/federation/authorize?connection_id={}&app_state={bad}",
                connection()
            ),
        );
        assert_eq!(refused.status, 400, "{bad}: {}", refused.body);
        assert!(refused.header("Set-Cookie").is_none(), "{bad}");
    }
    let (_, err) = stood.served.output();
    // The victim's application, the used-up retry, and the exchange without an app_state.
    let refused: Vec<&str> = err
        .lines()
        .filter_map(|line| {
            line.strip_prefix("mandate-control-plane: refused relying-party handoff ")
        })
        .collect();
    assert_eq!(
        refused,
        vec!["StateMismatch", "SessionUnknown", "StateMismatch"],
        "{err}"
    );
}

#[test]
fn a_wrong_nonce_opens_nothing() {
    let mut stood = stand("wrong-nonce", Tamper::Nonce, IDP_SECRET);
    let (_, completed) = walk(&stood);
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(stood.idp.held().token_calls, 1, "the code was redeemed");
    assert_eq!(refused_for(&mut stood), "NonceMismatch");
}

#[test]
fn a_pkce_mismatch_opens_nothing() {
    let mut stood = stand("pkce-mismatch", Tamper::Challenge, IDP_SECRET);
    let (_, completed) = walk(&stood);
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(
        stood.idp.held().pkce_refused,
        1,
        "the IdP refused the verifier"
    );
    assert_eq!(refused_for(&mut stood), "ProofInvalid");
}

#[test]
fn a_refused_basic_authentication_opens_nothing() {
    let mut stood = stand("basic-refused", Tamper::None, "not-the-secret");
    let (_, completed) = walk(&stood);
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(
        stood.idp.held().basic_refused,
        1,
        "the IdP refused the client"
    );
    assert_eq!(refused_for(&mut stood), "ProofInvalid");
}

#[test]
fn every_redemption_authenticates_with_http_basic_and_no_secret_in_the_body() {
    // The Basic check above counts a request whose secret is in the body as refused too, so
    // a relying party that sent `client_secret_post` could not pass the signing-in case.
    // This pins the count that makes that true.
    let stood = stand("basic-only", Tamper::None, IDP_SECRET);
    let (_, completed) = walk(&stood);
    assert!(opened_a_session(&completed), "{}", completed.body);
    let held = stood.idp.held();
    assert_eq!((held.token_calls, held.basic_refused), (1, 0));
    assert_eq!(held.issued, 1);
}

// ------------------------------------------------------- in process: the two stores

use mandate_control_plane::adapters::{
    ConnectionSeed, HANDOFF_CAPACITY, HANDOFF_LIFETIME, OnceStore, PENDING_CAPACITY,
    PENDING_LIFETIME, SeedRefused, relying_party_connection,
};

/// F4 and F6: a value is answered once, never after its lifetime, and a full store evicts
/// its oldest value rather than refusing the next one.
#[test]
fn a_once_store_answers_once_expires_and_evicts_the_oldest_when_full() {
    let mut store = OnceStore::new(60, 3);
    store.insert("a".to_owned(), 1, 100);
    assert_eq!(store.take("a", 159), Some(1));
    assert_eq!(store.take("a", 159), None, "taken once");

    store.insert("b".to_owned(), 2, 100);
    assert_eq!(store.take("b", 160), None, "expired at its lifetime");

    for (key, at) in [("c", 200), ("d", 201), ("e", 202), ("f", 203)] {
        store.insert(key.to_owned(), at, at);
    }
    assert_eq!(store.len(), 3, "bounded by its capacity");
    assert_eq!(store.take("c", 203), None, "the oldest was evicted");
    assert_eq!(store.take("d", 203), Some(201));
    assert_eq!(store.take("f", 203), Some(203));

    // Taking out of the middle and inserting again, many times, stays bounded.
    let mut churned = OnceStore::new(600, 4);
    for round in 0..10_000_u64 {
        churned.insert(format!("k{round}"), round, round / 100);
        if round % 2 == 0 {
            churned.take(&format!("k{round}"), round / 100);
        }
    }
    assert!(churned.len() <= 4);
}

#[test]
fn the_shipped_bounds_are_the_ones_the_findings_named() {
    assert_eq!((PENDING_LIFETIME, PENDING_CAPACITY), (600, 4096));
    assert_eq!(HANDOFF_CAPACITY, PENDING_CAPACITY);
    assert_eq!(HANDOFF_LIFETIME, 60, "a handoff code is short-lived");
}

/// F9: the token endpoint receives the client secret, so the hosts it may be on are the
/// relying party's own list, and a host listed for fetching keys is not on it.
#[test]
fn the_endpoint_hosts_are_the_relying_partys_own_and_never_the_key_hosts() {
    let scratch = Scratch::new("endpoint-hosts");
    let secret = scratch.write("secret", "s\n");
    let secrets: BTreeMap<String, PathBuf> = [(SECRET_REFERENCE.to_owned(), secret)]
        .into_iter()
        .collect();
    let seed = |relying_party: &str| -> ConnectionSeed {
        serde_json::from_str(&format!(
            r#"{{"organization":"{organization}","issuer":"https://idp.example",
              "client_id":"{IDP_CLIENT}","jwks_hosts":["keys.idp.example"],
              "tenant_resolution":{{"configured_organization":"{organization}"}},
              "jit_provisioning":false,"relying_party":{relying_party}}}"#,
            organization = organization(),
        ))
        .expect("a connection document")
    };
    let path = Path::new("connection.json");
    let keys_only = seed(&format!(
        r#"{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}"}}"#
    ));
    let configured = relying_party_connection(path, &keys_only, &secrets)
        .expect("admitted")
        .expect("a relying party");
    assert!(configured.allowed_hosts.is_empty(), "{configured:?}");

    let listed = seed(&format!(
        r#"{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}",
            "endpoint_hosts":["login.idp.example"]}}"#
    ));
    let configured = relying_party_connection(path, &listed, &secrets)
        .expect("admitted")
        .expect("a relying party");
    assert_eq!(
        configured.allowed_hosts,
        vec!["login.idp.example".to_owned()]
    );

    for unusable in [
        "https://app.example/signed-in#fragment",
        "https://app.example/signed-in?handoff=x",
        "http://app.example/signed-in",
        "https://app.example/signed in",
    ] {
        let document = seed(&format!(
            r#"{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}",
                "return_uri":"{unusable}"}}"#
        ));
        assert!(
            matches!(
                relying_party_connection(path, &document, &secrets),
                Err(SeedRefused::ReturnUriUnusable { .. })
            ),
            "{unusable}"
        );
    }
}
