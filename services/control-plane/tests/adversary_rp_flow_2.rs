//! Adversarial pass 2 on `story:relying-party-code-flow`, against the correction that added the
//! browser-binding cookie, the single-use handoff and oldest-first eviction.
//!
//! The harness is `tests/relying_party.rs`'s, copied: a loopback RS256 test IdP and a `serve`
//! child per case, the browser driven by hand. Where a case needs a browser's cookie jar it
//! keeps one ([`Jar`]) and applies every `Set-Cookie` the child answers, so the outcome
//! observed is the one a browser would reach, and every sign-in is completed through the
//! handoff exchange rather than read off the callback.

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
            .join("adversary-rp-flow-2")
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

fn stand(case: &str, tamper: Tamper, secret_in_file: &str, return_uri: &str) -> Stood {
    let idp = TestIdp::start(tamper);
    let scratch = Scratch::new(case);
    let connection_document = format!(
        r#"{{"connection_id":"{connection}","organization":"{organization}",
          "issuer":"{issuer}","client_id":"{IDP_CLIENT}","algorithm":"RS256",
          "tenant_resolution":{{"configured_organization":"{organization}",
            "verified_claim_name":"{TENANT_CLAIM}","verified_claim_value":"{TENANT_VALUE}"}},
          "jit_provisioning":true,
          "relying_party":{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}",
            "return_uri":"{return_uri}"}}}}"#,
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

/// Mandate's authorize and the IdP's authorize, as a browser follows them.
fn to_the_idp_and_back(stood: &Stood) -> Returned {
    let started = get(
        stood.address,
        &format!("/v1/federation/authorize?connection_id={}", connection()),
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
    let (_, query) = location.split_once('?')?;
    form(query).get("handoff").cloned()
}

/// The embedding application's server-to-server exchange of a handoff code.
fn exchange(stood: &Stood, code: &str) -> Response {
    send(
        stood.address,
        "POST",
        "/v1/federation/handoff",
        &[],
        Some(&serde_json::json!({ "handoff": code }).to_string()),
    )
}

/// Whether a callback signed the browser in, observed as the embedding application observes
/// it: the callback sent a handoff code, and exchanging that code answered a session.
fn signed_in(stood: &Stood, callback: &Response) -> bool {
    let Some(code) = handoff_of(callback) else {
        return false;
    };
    let exchanged = exchange(stood, &code);
    exchanged.status == 200
        && serde_json::from_str::<serde_json::Value>(&exchanged.body)
            .ok()
            .and_then(|login| login["session_id"].as_str().map(str::to_owned))
            .is_some_and(|id| !id.is_empty())
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

/// One browser's cookie for the child's origin: the binding cookie, as a browser holds it
/// after applying every `Set-Cookie` the child answered it.
struct Jar(Option<String>);

impl Jar {
    fn holding(cookie: &str) -> Self {
        Self(Some(cookie.to_owned()))
    }

    /// Apply a response's `Set-Cookie` for the binding cookie, as a browser does: a
    /// `Max-Age=0` removes it, anything else replaces it.
    fn apply(&mut self, response: &Response) {
        let Some(set) = response.header("Set-Cookie") else {
            return;
        };
        let attributes: Vec<&str> = set.split(';').map(str::trim).collect();
        let Some((name, _)) = attributes[0].split_once('=') else {
            return;
        };
        if name != BINDING_COOKIE {
            return;
        }
        if attributes.contains(&"Max-Age=0") {
            self.0 = None;
        } else {
            self.0 = Some(attributes[0].to_owned());
        }
    }

    fn cookie(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// The callback, as the browser holding `jar` reaches it, with the jar updated from the
/// answer.
fn callback_in(stood: &Stood, query: &str, jar: &mut Jar) -> Response {
    let answered = callback(stood, query, jar.cookie());
    jar.apply(&answered);
    answered
}

// ---------------------------------------------------------------------------- the cases

/// Any page the victim visits while the IdP is signing them in can send the victim's
/// browser, top level, to `/v1/federation/callback` with a state it made up. `SameSite=Lax`
/// sends the binding cookie on that navigation, and the callback answers **every** request —
/// an unknown state, even one the decoder refuses — with a `Set-Cookie` that removes the
/// binding (`services/control-plane/src/serve.rs`, the `Callback` arm). The victim's real
/// callback then arrives without it and is refused. The sign-in the made-up callback
/// "named" was nobody's; the binding it removed was the victim's.
#[test]
fn a_callback_naming_a_state_nobody_issued_does_not_end_the_victims_sign_in() {
    let mut stood = stand("unrelated-callback", Tamper::None, IDP_SECRET, RETURN_URI);
    let victim = to_the_idp_and_back(&stood);
    let mut jar = Jar::holding(&victim.cookie);

    // The attacker's navigation: a state and a code this deployment never issued.
    let forged = callback_in(
        &stood,
        "code=attacker-code&state=a-state-this-deployment-never-issued",
        &mut jar,
    );
    assert_ne!(forged.status, 302, "{}", forged.body);

    let completed = callback_in(&stood, &victim.query, &mut jar);
    assert!(
        signed_in(&stood, &completed),
        "the victim's own callback, after an unrelated one, signed nobody in: {} {} (jar {:?}, \
         refused {})",
        completed.status,
        completed.body,
        jar.cookie(),
        refused_for(&mut stood)
    );
}

/// Two sign-ins in one browser — two tabs, or a retry after the first stalled at the IdP.
/// The second authorize replaces the binding cookie, so the first tab's callback is refused;
/// that alone would be a limitation. But the refused callback also removes the cookie, so the
/// second tab — the one whose binding the browser actually holds — is refused too, and the
/// user is signed in by neither.
#[test]
fn a_stale_tab_returning_first_does_not_refuse_the_sign_in_the_browser_holds() {
    let mut stood = stand("two-tabs", Tamper::None, IDP_SECRET, RETURN_URI);
    let first = to_the_idp_and_back(&stood);
    let second = to_the_idp_and_back(&stood);
    // The browser holds the cookie the later authorize response set.
    let mut jar = Jar::holding(&second.cookie);

    let stale = callback_in(&stood, &first.query, &mut jar);
    assert!(!signed_in(&stood, &stale), "{}", stale.body);

    let current = callback_in(&stood, &second.query, &mut jar);
    assert!(
        signed_in(&stood, &current),
        "the sign-in whose binding the browser held was refused after a stale tab returned: \
         {} {} (jar {:?}, refused {})",
        current.status,
        current.body,
        jar.cookie(),
        refused_for(&mut stood)
    );
}

/// `PENDING_CAPACITY` in `services/control-plane/src/adapters.rs`.
const SHIPPED_PENDING_CAPACITY: usize = 4096;

/// Oldest-first eviction replaced pass 1's lock-out with an eviction: anonymous authorize
/// requests — no credential, one public `connection_id` — push a waiting browser's sign-in
/// out of the one store every connection shares. `SHIPPED_PENDING_CAPACITY` of them between
/// the victim's authorize and its callback is enough, and nothing bounds who sends them.
///
/// **The defect is open**, and this case pins today's documented behaviour rather than the
/// fixed one (coordinator ruling, correction round 2): the residual defence is the ingress
/// rate limit, and the fix is `story:authorize-flood-eviction`. When that story lands, this
/// assertion must flip back to `signed_in`.
#[test]
fn anonymous_authorize_requests_evict_a_waiting_browser_until_story_authorize_flood_eviction_lands()
{
    let mut stood = stand("evicted", Tamper::None, IDP_SECRET, RETURN_URI);
    let victim = to_the_idp_and_back(&stood);
    let target = format!("/v1/federation/authorize?connection_id={}", connection());
    for sent in 0..SHIPPED_PENDING_CAPACITY {
        let flooded = get(stood.address, &target);
        assert_eq!(flooded.status, 302, "authorize {sent}: {}", flooded.body);
    }
    let mut jar = Jar::holding(&victim.cookie);
    let completed = callback_in(&stood, &victim.query, &mut jar);
    assert!(
        !signed_in(&stood, &completed),
        "{SHIPPED_PENDING_CAPACITY} anonymous authorize requests no longer evict a waiting \
         browser's sign-in: story:authorize-flood-eviction has landed, so flip this case back \
         to asserting the sign-in succeeds ({} {})",
        completed.status,
        completed.body,
    );
    assert_eq!(
        refused_for(&mut stood),
        "StateMismatch",
        "evicted, and so unknown"
    );
}

/// The seed admits a `return_uri` whose query names `state` (it refuses only `handoff`),
/// the child starts, and the callback's composer (`redirect_to`, which refuses a query
/// naming `code`, `state` or `error`) then answers **every** completed sign-in with a `400`
/// — after the IdP redeemed the code and a session was opened and held for a handoff nobody
/// is told.
///
/// Re-pinned by coordinator ruling (M1 final correction): the seed now refuses a query naming
/// `state` (decision C, pinned by the case below), so this case uses a benign query the seed
/// admits and still asserts that an admitted `return_uri` completes a sign-in.
#[test]
fn a_return_uri_the_seed_admits_is_one_the_callback_can_send_the_browser_to() {
    let mut stood = stand(
        "return-query",
        Tamper::None,
        IDP_SECRET,
        "https://app.example/signed-in?tab=home",
    );
    let (_, completed) = walk(&stood);
    let redeemed = stood.idp.held().token_calls;
    assert!(
        signed_in(&stood, &completed),
        "a return_uri the seed admitted answered a completed sign-in with {} {} after {} code \
         redemption(s) (refused {})",
        completed.status,
        completed.body,
        redeemed,
        refused_for(&mut stood)
    );
}

// ------------------------------------------------------- in process: the seed's rule

use mandate_control_plane::adapters::{ConnectionSeed, SeedRefused, relying_party_connection};

fn seed_with_return_uri(return_uri: &str) -> ConnectionSeed {
    serde_json::from_str(&format!(
        r#"{{"organization":"{organization}","issuer":"https://idp.example",
          "client_id":"{IDP_CLIENT}",
          "tenant_resolution":{{"configured_organization":"{organization}"}},
          "jit_provisioning":false,
          "relying_party":{{"redirect_uri":"{CALLBACK}","client_secret":"{SECRET_REFERENCE}",
            "return_uri":"{return_uri}"}}}}"#,
        organization = organization(),
    ))
    .expect("a connection document")
}

fn return_uri_refused(return_uri: &str) -> bool {
    // One directory per URI: the two cases below run in parallel.
    let scratch = Scratch::new(&format!("seed-{}", percent_encode(return_uri)));
    let secret = scratch.write("secret", "s\n");
    let secrets: BTreeMap<String, PathBuf> = [(SECRET_REFERENCE.to_owned(), secret)]
        .into_iter()
        .collect();
    matches!(
        relying_party_connection(
            Path::new("connection.json"),
            &seed_with_return_uri(return_uri),
            &secrets
        ),
        Err(SeedRefused::ReturnUriUnusable { .. })
    )
}

/// `return_uri_is_usable` documents "`http` on the loopback interface" and decides it with
/// `starts_with("http://localhost")` and `starts_with("http://127.0.0.1")`, so a plaintext
/// URI on any host whose name begins with those characters — or that puts them in the
/// userinfo — is admitted, and the handoff code, a bearer redeemable without client
/// authentication, is sent to it over plaintext.
#[test]
fn a_plaintext_return_uri_is_admitted_only_on_the_loopback_interface() {
    let admitted: Vec<&str> = [
        "http://localhost.attacker.example/signed-in",
        "http://127.0.0.1.attacker.example/signed-in",
        "http://localhost@attacker.example/signed-in",
        "http://localhostattacker.example/signed-in",
    ]
    .into_iter()
    .filter(|uri| !return_uri_refused(uri))
    .collect();
    assert!(
        admitted.is_empty(),
        "plaintext non-loopback return URIs admitted: {admitted:?}"
    );
}

/// The seed's rule and the callback's composer disagree on a `return_uri` query: every URI
/// here starts the child and then cannot carry a handoff — `redirect_to` refuses the first
/// four (a response parameter, a query that is not a form), and the fifth is answered with
/// `handoff` twice once its query is decoded.
#[test]
fn the_seed_refuses_every_return_uri_the_callback_cannot_compose_a_handoff_onto() {
    let admitted: Vec<&str> = [
        "https://app.example/signed-in?state=keep",
        "https://app.example/signed-in?code=1",
        "https://app.example/signed-in?error=none",
        "https://app.example/signed-in?a=%zz",
        "https://app.example/signed-in?hand%6Fff=x",
    ]
    .into_iter()
    .filter(|uri| !return_uri_refused(uri))
    .collect();
    assert!(
        admitted.is_empty(),
        "return URIs the seed admits and the callback cannot use: {admitted:?}"
    );
}
