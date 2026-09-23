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

fn stand(case: &str, tamper: Tamper, secret_in_file: &str) -> Stood {
    let idp = TestIdp::start(tamper);
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

/// The browser's walk: Mandate's authorize, the IdP's authorize, and back to Mandate's
/// callback. Answers the callback's query as the IdP wrote it, and the callback's response.
fn walk(stood: &Stood) -> (String, Response) {
    let started = get(
        stood.address,
        &format!("/v1/federation/authorize?connection_id={}", connection()),
    );
    assert_eq!(
        started.status, 302,
        "the browser is sent to the IdP: {}",
        started.body
    );
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
    assert!(
        !location.contains(IDP_SECRET) && !location.contains(&percent_encode(IDP_SECRET)),
        "the client secret never reaches the browser"
    );

    let at_idp = get(stood.idp.address, &target_of(&location));
    assert_eq!(at_idp.status, 302);
    let back = at_idp.header("Location").expect("a Location").to_owned();
    let callback_query = back
        .strip_prefix(&format!("{CALLBACK}?"))
        .expect("the IdP returns to the registered redirect URI")
        .to_owned();
    let completed = get(
        stood.address,
        &format!("/v1/federation/callback?{callback_query}"),
    );
    (callback_query, completed)
}

fn opened_a_session(response: &Response) -> bool {
    response.status == 200 && response.body.contains("session_id")
}

/// The clause the child recorded for the callback it refused, off its own stderr.
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
    let (callback_query, completed) = walk(&stood);
    assert_eq!(completed.status, 200, "{}", completed.body);
    let login: serde_json::Value =
        serde_json::from_str(&completed.body).expect("a JSON login response");
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
    assert_eq!(completed.header("Cache-Control"), Some("no-store"));
    assert_eq!(stood.idp.held().token_calls, 1);

    // The same state again: single-use, so nothing is redeemed and nothing opens.
    let replayed = get(
        stood.address,
        &format!("/v1/federation/callback?{callback_query}"),
    );
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
fn a_wrong_state_opens_nothing_and_redeems_nothing() {
    let mut stood = stand("wrong-state", Tamper::None, IDP_SECRET);
    let started = get(
        stood.address,
        &format!("/v1/federation/authorize?connection_id={}", connection()),
    );
    assert_eq!(started.status, 302, "{}", started.body);
    let location = started.header("Location").expect("a Location").to_owned();
    let at_idp = get(stood.idp.address, &target_of(&location));
    let back = at_idp.header("Location").expect("a Location").to_owned();
    let parameters = form(back.split_once('?').expect("a query").1);
    let forged = format!(
        "/v1/federation/callback?code={}&state={}",
        percent_encode(&parameters["code"]),
        percent_encode("a-state-this-deployment-never-issued"),
    );
    let completed = get(stood.address, &forged);
    assert!(!opened_a_session(&completed), "{}", completed.body);
    assert_eq!(
        stood.idp.held().token_calls,
        0,
        "an unknown state reaches no IdP"
    );
    assert_eq!(refused_for(&mut stood), "StateMismatch");
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
    assert_eq!(completed.status, 200, "{}", completed.body);
    let held = stood.idp.held();
    assert_eq!((held.token_calls, held.basic_refused), (1, 0));
    assert_eq!(held.issued, 1);
}
