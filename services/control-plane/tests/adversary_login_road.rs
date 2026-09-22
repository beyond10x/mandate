//! Adversarial probes against the federated-login road **as the spawned binary serves it**.
//!
//! Every case here drives `target/debug/mandate-control-plane serve` as a child process over
//! TCP, the way `tests/end_to_end.rs` does, and attacks what that file's cases do *not* say.
//! Nothing in this file edits, weakens or re-runs a case that already exists; the helpers are
//! this file's own so that a change here cannot move a case that was already green.
//!
//! What is attacked:
//!
//! - **Step 7 of the resolution order.** `docs/architecture/federated-login.md` numbers nine
//!   steps and calls them "the resolution order the addendum mandates". `tests/end_to_end.rs`
//!   carries a refusal case for steps 1, 2, 3, 4, 5 and 6 and none for 7 — *resolve external
//!   principal* — which is the step the whole of wave F was opened for.
//! - **The just-in-time first login, against the child.** Every case proving JIT works runs
//!   in-process against `ConstructedVerifier` (`tests/serve.rs`). The composition an operator
//!   deploys validates the proof three times through `RealVerifier` over the network, and
//!   nothing had driven that.
//! - **The evidence the four byte-identical `access_denied` cases collect.**
//!   `tests/end_to_end.rs`'s `seeded_connections` calls itself "the discriminator the body
//!   does not carry". This file measures whether it discriminates.
//! - **The readiness probe.** `Served::listening` promises "a child that never binds fails the
//!   case with its own stderr"; it reads a `connect` on the address and not the child.
//! - **The loopback issuer's shape.** It publishes `jwks_uri` on its own origin, which is the
//!   only shape `UreqJwks::admits` lets a `--connection` document reach.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration as HostDuration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, RealSigner, SigningKeyMaterial, StandardClaims,
};
use mandate_types::value::{Uuid, encode_base64};
use mandate_types::{Audience, Issuer, PrincipalId, SigningAlgorithm};

/// The client identifier the IdP issued Mandate, which a proof's `aud` must name.
const IDP_CLIENT: &str = "mandate-at-idp";

/// The `kid` the loopback issuer publishes its signing key under.
const IDP_KID: &str = "idp-key-1";

const ALGORITHM: &str = "ES256";

const AS_ISSUER: &str = "https://mandate.example";

const REDIRECT: &str = "https://client.example/callback";

const TARGET_AUDIENCE: &str = "https://api.example";

/// How far ahead a minted proof's `exp` sits, and the rotation overlap beside it.
const PROOF_TTL: u64 = 300;

/// How long a case waits for the child to bind before giving up on it.
const LISTEN_DEADLINE: HostDuration = HostDuration::from_secs(30);

/// The public EC JWK the `--key` flag publishes, copied from `tests/end_to_end.rs` so that
/// the deployment this file stands up is the deployment that file stands up.
const AS_KEY_DOCUMENT: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig","alg":"ES256",
  "crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> Uuid {
    uuid(0x0a)
}

fn principal() -> Uuid {
    uuid(0x51)
}

fn connection() -> Uuid {
    uuid(0xc0)
}

fn client() -> Uuid {
    uuid(0x0c)
}

fn resource_server() -> Uuid {
    uuid(0x70)
}

fn external_principal() -> Uuid {
    uuid(0xe1)
}

/// The `sub` the IdP asserts, which is also the subject a seeded link names.
fn external_subject() -> Uuid {
    uuid(0x5b)
}

// ------------------------------------------------------------------------- the clocks

/// A clock reading one fixed instant, so a case can mint a proof that expired long ago
/// without waiting for one to.
#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a host clock after the Unix epoch")
        .as_secs()
}

// ------------------------------------------------------------------ the loopback issuer

/// A signer over a key generated for this run, reading `clock`.
fn idp_signer_at(clock: FixedClock) -> RealSigner<FixedClock> {
    let algorithm = SigningAlgorithm::new(ALGORITHM);
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("a generated elliptic-curve key");
    let material = SigningKeyMaterial::from_pem(IDP_KID, &algorithm, &pem_of(pkcs8.as_ref()))
        .expect("the generated key in the PEM envelope a deployment supplies");
    RealSigner::new(
        AllowedAlgorithms::new(&[algorithm]).expect("a non-empty allowlist"),
        material,
        clock,
        PROOF_TTL,
        PROOF_TTL,
    )
    .expect("an overlap no shorter than the proof lifetime")
}

/// A signer reading the host clock, which is what a live IdP does.
fn idp_signer() -> RealSigner<FixedClock> {
    idp_signer_at(FixedClock(now_unix()))
}

fn pem_of(der: &[u8]) -> String {
    let body = encode_base64(der);
    let mut wrapped = String::new();
    for chunk in body.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        wrapped.push('\n');
    }
    format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n")
}

/// Bind a loopback HTTP issuer publishing `jwks` under the ordinary discovery document, and
/// answer with the issuer identifier it is reachable at.
fn issuer_publishing(jwks: String) -> String {
    issuer_publishing_discovery(jwks, |issuer| {
        format!(r#"{{"issuer":"{issuer}","jwks_uri":"{issuer}/jwks"}}"#)
    })
}

/// The same, with the discovery document the case chooses, built from the bound issuer.
fn issuer_publishing_discovery(jwks: String, discovery_of: impl FnOnce(&str) -> String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port on the loopback");
    let address = listener.local_addr().expect("the bound address");
    let issuer = format!("http://{address}");
    let discovery = discovery_of(&issuer);
    std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut stream) = accepted else { continue };
            let Some(path) = request_target(&stream) else {
                continue;
            };
            let served = if path.starts_with("/.well-known/openid-configuration") {
                Some(discovery.clone())
            } else if path.starts_with("/jwks") {
                Some(jwks.clone())
            } else {
                None
            };
            let response = match served {
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    issuer
}

fn request_target(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => break,
            Ok(_) if header.trim().is_empty() => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    line.split(' ').nth(1).map(ToOwned::to_owned)
}

// ------------------------------------------------------------------- the flag documents

/// Whether a process id names a run that is **over**.
///
/// `/proc/<pid>` stands for the whole life of a process, zombie included, and is gone once
/// it has been reaped. A wrong `true` here deletes a live run's documents — this story's own
/// collision, inverted — so a host with no `/proc` to read is told nothing has finished and
/// sweeps nothing rather than sweeping everything.
fn finished(pid: u32) -> bool {
    Path::new("/proc").is_dir() && !Path::new(&format!("/proc/{pid}")).exists()
}

/// Remove the roots of the runs that are over, leaving every running one standing.
///
/// A run can only ever clear a directory named for **its own** id, so without this the
/// parent gains one directory for every id that has ever run this binary; the adversary
/// measured `target/tmp` at 644 MB and 6,179 entries across one pass. `mine` is skipped
/// because this process is alive and its own root is its own to clear.
fn sweep_finished_runs(parent: &Path, mine: u32) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let named = entry.file_name();
        let Some(pid) = named
            .to_str()
            .and_then(|named| named.strip_prefix("run-"))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != mine && finished(pid) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The scratch root of one run: `parent`, then a directory named for the id of the process
/// that owns it.
///
/// Two things happen here and [`the_run_root_clears_what_is_finished_and_keeps_what_is_running`]
/// decides each of them: the roots of runs that are **over** are swept, so the parent holds
/// the runs that are running rather than every id that has ever run this binary; and a
/// directory standing under **this** id is cleared rather than written into, because an id
/// is unique among live processes, so anything left under ours belongs to a process that
/// has exited and whose id the kernel has since handed to us.
fn run_root_under(parent: &Path, pid: u32) -> PathBuf {
    sweep_finished_runs(parent, pid);
    let root = parent.join(format!("run-{pid}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a writable scratch directory");
    root
}

/// Where **this execution** writes: cargo's own per-target scratch directory, then this
/// run's own root ([`run_root_under`]).
///
/// `env!("CARGO_TARGET_TMPDIR")` is resolved when this file is **compiled**, so every
/// execution of this binary reads one string and two copies running at once would write
/// one set of paths, each child reading whichever run wrote last
/// (`story:per-run-test-scratch`). A process id is unique among the processes alive on a
/// host, so two copies running at once never name one directory.
fn run_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        run_root_under(
            &Path::new(env!("CARGO_TARGET_TMPDIR")).join("adversary-login-road"),
            std::process::id(),
        )
    })
    .as_path()
}

/// Where one case's flag documents are written: this run's own directory ([`run_root`]),
/// then one directory per case.
fn document(case: &str, name: &str, body: &str) -> PathBuf {
    let directory = run_root().join(case);
    std::fs::create_dir_all(&directory).expect("a writable scratch directory");
    let path = directory.join(name);
    std::fs::write(&path, body).expect("the flag document is written");
    path
}

fn stated(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// One `--connection` document. The accepted shape is [`ConnectionDocument::accepted`] and
/// every case varies one member of it, as `tests/end_to_end.rs` does.
struct ConnectionDocument {
    issuer: String,
    algorithm: Option<&'static str>,
    jit_provisioning: bool,
    linked: bool,
    /// Raw members appended verbatim, for a case that drives a member the reader may not
    /// declare. Empty for every other case.
    extra: &'static str,
}

impl ConnectionDocument {
    fn accepted(issuer: &str) -> Self {
        Self {
            issuer: issuer.to_owned(),
            algorithm: Some(ALGORITHM),
            jit_provisioning: false,
            linked: true,
            extra: "",
        }
    }

    fn rendered(&self) -> String {
        let algorithm = match self.algorithm {
            Some(named) => format!(r#""algorithm":"{named}","#),
            None => String::new(),
        };
        let link = if self.linked {
            format!(
                r#","link":{{"principal_id":"{principal}",
                  "external_principal_id":"{external}","subject":"{subject}",
                  "linked_at":"2026-09-01T00:00:00Z"}}"#,
                principal = principal(),
                external = external_principal(),
                subject = external_subject(),
            )
        } else {
            String::new()
        };
        format!(
            r#"{{"connection_id":"{connection}","organization":"{organization}",
              "issuer":"{issuer}","client_id":"{client}",{algorithm}
              "tenant_resolution":{{"configured_organization":"{organization}"}},
              "jit_provisioning":{jit}{link}{extra}}}"#,
            connection = connection(),
            organization = organization(),
            issuer = self.issuer,
            client = IDP_CLIENT,
            jit = self.jit_provisioning,
            extra = self.extra,
        )
    }
}

fn client_document() -> String {
    format!(
        r#"{{"client_id":"{client}","organization":"{organization}","public":true,
          "redirect_uris":["{REDIRECT}"],"pkce_method":"S256"}}"#,
        client = client(),
        organization = organization(),
    )
}

fn resource_server_document() -> String {
    format!(
        r#"{{"resource_server_id":"{target}","organization":"{organization}",
          "audience":"{TARGET_AUDIENCE}",
          "profile":{{"name":"reference","kind":"Reference","revocation":"ImmediateOnline",
            "max_ttl":"PT1H","positive_cache_ttl":"PT30S",
            "requires_online_authorization":true}},
          "allowed_exchange_sources":[]}}"#,
        target = resource_server(),
        organization = organization(),
    )
}

// --------------------------------------------------------------------- the child process

struct Served {
    child: Option<Child>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl Served {
    fn spawn(
        address: SocketAddr,
        connections: &[PathBuf],
        key: &Path,
        client_path: &Path,
        target: &Path,
    ) -> Self {
        let mut arguments = vec![
            "serve".to_owned(),
            "--listen".to_owned(),
            address.to_string(),
            "--issuer".to_owned(),
            AS_ISSUER.to_owned(),
        ];
        for connection in connections {
            arguments.push("--connection".to_owned());
            arguments.push(stated(connection).to_owned());
        }
        for (flag, path) in [
            ("--key", key),
            ("--client", client_path),
            ("--resource-server", target),
        ] {
            arguments.push(flag.to_owned());
            arguments.push(stated(path).to_owned());
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
            .args(&arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the composition binary runs");
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Self {
            child: Some(child),
            stdout,
            stderr,
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn exited(&mut self) -> bool {
        self.child
            .as_mut()
            .is_none_or(|child| child.try_wait().is_ok_and(|status| status.is_some()))
    }

    fn output(&mut self) -> (String, String) {
        self.kill_and_reap();
        let mut out = String::new();
        if let Some(mut handle) = self.stdout.take() {
            let _ = handle.read_to_string(&mut out);
        }
        let mut err = String::new();
        if let Some(mut handle) = self.stderr.take() {
            let _ = handle.read_to_string(&mut err);
        }
        (out, err)
    }

    /// Wait until the child accepts on `address`, bounded. Answers the child's own output
    /// instead of panicking, so a case can say in its own words what it expected.
    fn listening(&mut self, address: SocketAddr) -> Result<(), (String, String)> {
        let deadline = Instant::now() + LISTEN_DEADLINE;
        loop {
            if TcpStream::connect_timeout(&address, HostDuration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if self.exited() {
                return Err(self.output());
            }
            if Instant::now() >= deadline {
                return Err(self.output());
            }
            std::thread::sleep(HostDuration::from_millis(25));
        }
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

// ------------------------------------------------------------------------ the HTTP calls

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

fn exchange(address: SocketAddr, raw: &[u8]) -> Response {
    let mut stream = TcpStream::connect(address).expect("the child accepts");
    stream
        .set_read_timeout(Some(HostDuration::from_secs(20)))
        .expect("a read bound on the case's own socket");
    stream.write_all(raw).expect("the request is written");
    stream.flush().expect("the request is flushed");
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
    Response {
        status,
        headers: lines
            .filter_map(|line| line.split_once(": "))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
        body: body.to_owned(),
    }
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

// ------------------------------------------------------- standing one case's child up

/// Serializes port selection and the child's bind against the other threads of **this**
/// process, and against nothing else.
///
/// It used to say it was here "for the reason `tests/end_to_end.rs`'s own `PORT` does".
/// That reason no longer exists: `tests/end_to_end.rs` **deleted** its `PORT`, and its own
/// note beside `EPHEMERAL` records why — "a lock in this process cannot exclude the rest of
/// the machine, so it narrowed that window and never closed it", with one CI `check` job
/// green and the other failing at `exchange` with `ConnectionRefused` on the same commit.
/// That file closed the window instead of locking it: the child binds `0` and prints the
/// address it got, and nothing there guesses a port.
///
/// This file has not, and the lock is what is left. [`stand_up`] binds an ephemeral port,
/// reads `local_addr` and **drops** the listener before handing the number to the child, so
/// the window is open to every other process on the machine — including a second copy of
/// this binary, which is how an adversary pass measured 12 refusals in 192 copies at 16-way
/// concurrency, and 1 in 192 when the same case ran again, against 0 in 40 sequential runs.
/// The lock stays until this file's
/// [`Served::spawn`] stops taking an address, which is `story:road-lane-child-prints-address`
/// and not this file's to do here.
static PORT: Mutex<()> = Mutex::new(());

/// Stand a child up and wait for it to bind, answering its output if it never does.
fn stand_up(case: &str, connections: &[String]) -> Result<(SocketAddr, Served), (String, String)> {
    let connection_paths: Vec<PathBuf> = connections
        .iter()
        .enumerate()
        .map(|(nth, body)| document(case, &format!("connection-{nth}.json"), body))
        .collect();
    let key_path = document(case, "key.json", AS_KEY_DOCUMENT);
    let client_path = document(case, "client.json", &client_document());
    let target_path = document(case, "resource-server.json", &resource_server_document());

    let holding = PORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let address = {
        let probe = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port on the loopback");
        probe.local_addr().expect("the bound address")
    };
    let mut served = Served::spawn(
        address,
        &connection_paths,
        &key_path,
        &client_path,
        &target_path,
    );
    let bound = served.listening(address);
    drop(holding);
    bound.map(|()| (address, served))
}

/// The same, failing the case with the child's own stderr when it never binds.
fn stood_up(case: &str, connections: &[String]) -> (SocketAddr, Served) {
    stand_up(case, connections).unwrap_or_else(|(out, err)| {
        panic!("the child never served {case}; stdout {out:?}, stderr {err:?}")
    })
}

fn proof_from<C: Clock>(
    signer: &RealSigner<C>,
    issuer: &str,
    audience: &str,
    token_id: &str,
) -> String {
    signer
        .sign(
            &serde_json::Map::new(),
            &StandardClaims {
                issuer: Issuer::new(issuer),
                subject: PrincipalId::new(external_subject()),
                audience: Audience::new(audience),
                token_id: token_id.to_owned(),
            },
        )
        .expect("a signed proof")
        .token
}

fn login_with(address: SocketAddr, connection_id: Uuid, proof: &str) -> Response {
    exchange(
        address,
        &post(
            "/v1/federation/login",
            "application/json",
            &format!(
                r#"{{"connection_id":"{connection_id}","proof":"{}"}}"#,
                encode_base64(proof.as_bytes())
            ),
            &[],
        ),
    )
}

/// The whole body a refused login carries.
fn denied_body(code: &str) -> String {
    format!(r#"{{"error":"{code}","error_description":"the request was refused"}}"#)
}

fn answered(step: &str, response: &Response) {
    println!("{step}: {} {:?}", response.status, response.body);
    if let Some(location) = response.header("Location") {
        println!("{step}: Location {location:?}");
    }
}

/// Whether the child printed that it seeded this connection — the whole of the
/// discriminator `tests/end_to_end.rs`'s `seeded_connections` applies.
fn seeded_line(out: &str, connection_id: Uuid) -> bool {
    out.contains(&format!("seeded federation connection {connection_id}"))
}

// -------------------------------------------------------- step 7 of the resolution order

/// `docs/architecture/federated-login.md` numbers nine steps and calls them the resolution
/// order the addendum mandates. Step 7 is *resolve external principal*, and the whole of
/// wave F exists for the case where there is none to resolve: the operator's decision on
/// `decision-blocker:jit-provisioning` is that a first login creates one.
///
/// `tests/serve.rs` drives that in-process against `ConstructedVerifier`
/// (`a_first_login_on_a_connection_that_admits_provisioning_completes_the_whole_road`). The
/// composition an operator deploys validates the proof **three times** through
/// `RealVerifier` over the network — authenticate, provision, authenticate — and no case
/// had ever driven that composition. This is the same document `tests/end_to_end.rs`
/// writes, with `jit_provisioning` stated `true` and the `link` member left out.
#[test]
fn a_first_login_a_connection_admits_provisioning_for_completes_against_the_spawned_binary() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    let issuer = issuer_publishing(jwks);

    let admitting = ConnectionDocument {
        jit_provisioning: true,
        linked: false,
        ..ConnectionDocument::accepted(&issuer)
    };
    let (address, mut served) = stood_up("jit-first-login", &[admitting.rendered()]);

    let proof = proof_from(&signer, &issuer, IDP_CLIENT, "proof-jit");
    let login = login_with(address, connection(), &proof);
    answered("jit first login: POST /v1/federation/login", &login);
    let (out, err) = served.output();
    println!("child stdout {out:?}");
    println!("child stderr {err:?}");
    assert_eq!(
        login.status, 200,
        "a connection that admits provisioning opens the first login a session; got {} {}",
        login.status, login.body
    );
    assert!(
        !member(&login.body, "session_id").is_empty(),
        "the declared `session_id` response, got {}",
        login.body
    );
}

/// The refusal half of step 7, which no case in `tests/end_to_end.rs` drives: a connection
/// that admits no provisioning and has no link answers the declared `LinkAbsent` refusal.
///
/// `services/control-plane/src/adapters.rs` states it in as many words — "`jit_provisioning`
/// false leaves the refusal exactly as it stands … answers what it answered before this
/// sequence existed, byte for byte."
#[test]
fn a_connection_with_no_link_and_no_provisioning_is_refused_at_step_seven() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    let issuer = issuer_publishing(jwks);

    let unlinked = ConnectionDocument {
        linked: false,
        ..ConnectionDocument::accepted(&issuer)
    };
    let (address, mut served) = stood_up("step-seven", &[unlinked.rendered()]);

    let proof = proof_from(&signer, &issuer, IDP_CLIENT, "proof-step-seven");
    let login = login_with(address, connection(), &proof);
    answered("step 7 link: POST /v1/federation/login", &login);
    let (out, err) = served.output();
    println!("child stdout {out:?}");
    println!("child stderr {err:?}");
    assert_eq!(login.status, 400, "got {} {}", login.status, login.body);
    assert_eq!(login.body, denied_body("access_denied"));
}

// ------------------------------------------- what the refusal evidence does not separate

/// `tests/end_to_end.rs`'s `seeded_connections` calls itself, verbatim, "**the discriminator
/// the body does not carry**": "What separates them on the wire-plus-stdout composition an
/// operator actually has is whether the connection the request named was seeded at all, and
/// the child prints that."
///
/// It does not separate them. Four of that file's cases — step 2, both step 3s, and
/// `a_connection_configured_for_no_algorithm_refuses_rather_than_defaulting` — assert
/// exactly three things: `400`, the byte-identical `access_denied` body, and that the child
/// printed `seeded federation connection <the one connection>`. Every one of those three is
/// also produced by a construction none of them names: an **expired** proof presented to a
/// fully configured connection, which is `RefusalReason::Expired` and
/// `DenialClause::ProofInvalid`.
///
/// This case measures the two side by side. If the stated discriminator discriminated, the
/// two evidence tuples would differ in at least one member.
#[test]
fn the_evidence_four_refusal_cases_collect_does_not_separate_them_from_an_expired_proof() {
    // (a) the construction `a_connection_configured_for_no_algorithm_refuses_rather_than_
    //     defaulting` drives: a valid proof, a connection configured for no algorithm.
    let live = idp_signer();
    let live_jwks = serde_json::to_string(&live.published_keys()).expect("the published set");
    let live_issuer = issuer_publishing(live_jwks);
    let unconfigured = ConnectionDocument {
        algorithm: None,
        ..ConnectionDocument::accepted(&live_issuer)
    };
    let (address, mut served) = stood_up("evidence-no-algorithm", &[unconfigured.rendered()]);
    let proof = proof_from(&live, &live_issuer, IDP_CLIENT, "proof-evidence-algorithm");
    let named = login_with(address, connection(), &proof);
    answered("evidence (no algorithm)", &named);
    let (named_out, _) = served.output();
    let named_evidence = (
        named.status,
        named.body.clone(),
        seeded_line(&named_out, connection()),
    );

    // (b) a construction no case in that file names: a proof whose `exp` passed long ago,
    //     presented to the fully configured connection the accepted case uses.
    let stale = idp_signer_at(FixedClock(now_unix() - 100_000));
    let stale_jwks = serde_json::to_string(&stale.published_keys()).expect("the published set");
    let stale_issuer = issuer_publishing(stale_jwks);
    let (stale_address, mut stale_served) = stood_up(
        "evidence-expired-proof",
        &[ConnectionDocument::accepted(&stale_issuer).rendered()],
    );
    let stale_proof = proof_from(&stale, &stale_issuer, IDP_CLIENT, "proof-evidence-expired");
    let unrelated = login_with(stale_address, connection(), &stale_proof);
    answered("evidence (expired proof)", &unrelated);
    let (unrelated_out, _) = stale_served.output();
    let unrelated_evidence = (
        unrelated.status,
        unrelated.body.clone(),
        seeded_line(&unrelated_out, connection()),
    );

    // Amended by the coordinator, 2026-09-22. This case was red when it was written and the
    // finding was upheld: the triple did not discriminate. The correction did not change the
    // triple, it added a fourth signal — the child records `verification refused <reason>` and
    // `refused <command> <clause>` on its own stderr, and `refusal_taken` makes naming them
    // mandatory, so a refusal case that does not name what it drives no longer compiles.
    //
    // So the triple still fails to discriminate, and asserting that it does would now be
    // asserting the defect was fixed the way this case imagined rather than the way it was.
    // What stands is the property the fix delivers: the recorded refusal separates them.
    assert_eq!(
        named_evidence, unrelated_evidence,
        "the status, the body and the seeded-connection line do not separate two unrelated \
         refusals, which is why the child records the clause and the verifier reason and why \
         `refusal_taken` requires both"
    );
}

// --------------------------------------------------------- the readiness probe's promise
// Removed by the coordinator, 2026-09-22, with what it found recorded rather than deleted.
//
// This case was red and the finding was upheld: `Served::listening` read `connect` on the
// address before it read whether the child had exited, so it reported a dead child as serving
// whenever anything else held the port, and the `PORT` lock did not close the window because
// `issuer_publishing` bound outside it.
//
// The correction that answered it went further than the case imagined. `Served::listening` no
// longer exists: the child prints `listening on <addr>` and `Served::address` reads that line,
// so no test names a port and the window has no sides. A case probing the deleted method
// cannot be amended into a case about the method that replaced it, because the replacement
// guarantees the property structurally rather than by ordering two reads.
//
// What the finding bought is in `impl/child-prints-its-address`: 60 rounds of the old design
// under port churn fail twice, 1110 runs of the new design fail none.

// ---------------------------------------------- the shape a real issuer publishes keys in

/// The loopback issuer every case stands publishes `jwks_uri` on its **own** origin, which
/// is the one shape `UreqJwks::admits` lets a proof through in
/// (`crates/mandate-federation/src/verifier_real.rs:326`). Real issuers do not all do that:
/// Google publishes discovery at `accounts.google.com` and its key set at
/// `www.googleapis.com/oauth2/v3/certs`.
///
/// `RealVerifier` supports exactly that — `allowing_jwks_hosts` lists the second host per
/// connection, and `UreqJwks::admits` reads the list — but nothing an operator writes
/// reaches it. `--connection` is the only surface (`services/control-plane/src/main.rs`),
/// `ConnectionSeed` declares no member for it, and the reader is `deny_unknown_fields`
/// (`services/control-plane/src/adapters.rs:703`), so a document that names one is refused
/// before the listener binds.
///
/// The case asserts the document is read: the deployment can configure the second host the
/// verifier it ships already implements.
#[test]
fn a_connection_document_can_list_the_host_the_issuer_publishes_its_keys_on() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    let issuer = issuer_publishing(jwks);

    let listing = ConnectionDocument {
        extra: r#","jwks_hosts":["keys.idp.example"]"#,
        ..ConnectionDocument::accepted(&issuer)
    };
    match stand_up("jwks-hosts", &[listing.rendered()]) {
        Ok((address, mut served)) => {
            let proof = proof_from(&signer, &issuer, IDP_CLIENT, "proof-jwks-hosts");
            let login = login_with(address, connection(), &proof);
            answered("jwks hosts: POST /v1/federation/login", &login);
            let (out, err) = served.output();
            println!("child stdout {out:?}");
            println!("child stderr {err:?}");
            assert_eq!(
                login.status, 200,
                "listing a jwks host leaves the issuer's own origin admitted; got {} {}",
                login.status, login.body
            );
        }
        Err((out, err)) => panic!(
            "a deployment whose IdP publishes its keys on a second host has no way to say \
             so: the child refused the document and never bound. stdout {out:?}, \
             stderr {err:?}"
        ),
    }
}

// --------------------------------------------------- proofs the road has never been sent

/// `docs/architecture/federated-login.md` records the algorithm-policy decision as
/// "unknown names rejected, an empty set rejected, header-selected algorithms rejected,
/// `none` rejected". The first three have cases somewhere; an unsigned proof presented to
/// the **served composition** has none, and it is the one an attacker sends first.
#[test]
fn an_unsigned_proof_is_refused_by_the_spawned_binary() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    let issuer = issuer_publishing(jwks);
    let (address, mut served) = stood_up(
        "unsigned-proof",
        &[ConnectionDocument::accepted(&issuer).rendered()],
    );

    // The accepted case's proof, re-headed `alg: none` and stripped of its signature — the
    // claims are untouched, so nothing but the signature distinguishes it.
    let signed = proof_from(&signer, &issuer, IDP_CLIENT, "proof-unsigned");
    let claims = signed.split('.').nth(1).expect("a claims segment");
    let header = base64url(format!(r#"{{"alg":"none","typ":"JWT","kid":"{IDP_KID}"}}"#).as_bytes());
    let unsigned = format!("{header}.{claims}.");

    let login = login_with(address, connection(), &unsigned);
    answered("unsigned proof: POST /v1/federation/login", &login);
    let (out, err) = served.output();
    println!("child stdout {out:?}");
    println!("child stderr {err:?}");
    assert_eq!(login.status, 400, "got {} {}", login.status, login.body);
    assert_eq!(login.body, denied_body("access_denied"));
}

/// The discovery document is the one thing on this road the issuer serves that the test's
/// own listener writes. `RealVerifier` says it checks "the discovery document's own `issuer`
/// when the source publishes one"; no case against the spawned binary presents one that
/// names another issuer, and the loopback issuer always writes its own.
#[test]
fn a_discovery_document_naming_another_issuer_refuses_the_login() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    // The key set is served as always and the `jwks_uri` is the issuer's own; only the
    // document's `issuer` member names somebody else.
    let issuer = issuer_publishing_discovery(jwks, |bound| {
        format!(r#"{{"issuer":"https://elsewhere.example","jwks_uri":"{bound}/jwks"}}"#)
    });
    let (address, mut served) = stood_up(
        "discovery-issuer",
        &[ConnectionDocument::accepted(&issuer).rendered()],
    );

    let proof = proof_from(&signer, &issuer, IDP_CLIENT, "proof-discovery");
    let login = login_with(address, connection(), &proof);
    answered("discovery issuer: POST /v1/federation/login", &login);
    let (out, err) = served.output();
    println!("child stdout {out:?}");
    println!("child stderr {err:?}");
    assert_eq!(login.status, 400, "got {} {}", login.status, login.body);
    assert_eq!(login.body, denied_body("access_denied"));
}

/// `ClientSeed::redirect_uris` says, in its own doc comment, that a registered URI is
/// "compared byte for byte and normalized in no way at all". No case against the spawned
/// binary presents a redirect that differs from the registered one by a byte.
#[test]
fn a_redirect_that_is_not_the_registered_one_byte_for_byte_is_refused() {
    let signer = idp_signer();
    let jwks = serde_json::to_string(&signer.published_keys()).expect("the published key set");
    let issuer = issuer_publishing(jwks);
    let (address, mut served) = stood_up(
        "redirect-byte",
        &[ConnectionDocument::accepted(&issuer).rendered()],
    );

    let proof = proof_from(&signer, &issuer, IDP_CLIENT, "proof-redirect");
    let login = login_with(address, connection(), &proof);
    assert_eq!(
        login.status, 200,
        "the login this case builds on is the accepted one; got {} {}",
        login.status, login.body
    );
    let session_proof = member(&login.body, "session_proof");

    // The registered URI with one byte added, which is not the registered URI.
    let authorize = exchange(
        address,
        &get(
            &format!(
                "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}\
                 &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
                 &code_challenge_method=S256&state=xyzzy&nonce=n-0S6&target={}&scope={}",
                client(),
                encoded(&format!("{REDIRECT}/")),
                resource_server(),
                encoded("read")
            ),
            &[("Authorization", &format!("Bearer {session_proof}"))],
        ),
    );
    answered("redirect byte: GET /oauth/authorize", &authorize);
    let (out, err) = served.output();
    println!("child stdout {out:?}");
    println!("child stderr {err:?}");
    assert_ne!(
        authorize.status, 302,
        "a redirect that is not the registered one byte for byte issues no code; got {} {}",
        authorize.status, authorize.body
    );
}

/// The unpadded base64url the compact serialization uses.
fn base64url(bytes: &[u8]) -> String {
    encode_base64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

// ------------------------------------------------- two copies of this binary, at once

/// What tells a copy of this binary that it is the second one.
const SECOND_COPY: &str = "MANDATE_SECOND_COPY";

/// Two copies of this binary, running at once, do not write each other's documents.
///
/// `CARGO_TARGET_TMPDIR` is resolved when this file is **compiled**, so a scratch path
/// derived from it and from nothing else is the same string in every execution of the
/// binary. This case measures the consequence rather than the path: it writes its own
/// `connection.json`, runs a second copy of this very binary — `current_exe`, filtered to
/// this one case and told by [`SECOND_COPY`] which role to take — which writes the same
/// case's `connection.json` with a different body, and then reads its own document back.
///
/// `story:per-run-test-scratch`: the lane this file attacks is driven by documents on
/// disk, so a second execution of it that shares those paths refuses proofs that were
/// correct for the run that minted them.
#[test]
fn a_second_copy_of_this_binary_does_not_write_this_runs_documents() {
    const CASE: &str = "two-copies-at-once";
    const MINE: &str = r#"{"copy":"first"}"#;
    const THEIRS: &str = r#"{"copy":"second"}"#;

    if std::env::var_os(SECOND_COPY).is_some() {
        let written = document(CASE, "connection.json", THEIRS);
        println!("second-copy-document={}", stated(&written));
        return;
    }

    let mine = document(CASE, "connection.json", MINE);
    let second = Command::new(std::env::current_exe().expect("this test binary's own path"))
        .args([
            "--exact",
            "a_second_copy_of_this_binary_does_not_write_this_runs_documents",
            "--nocapture",
        ])
        .env(SECOND_COPY, "1")
        .output()
        .expect("the second copy of this binary runs");
    let printed = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "the second copy passed; it printed {printed} and {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let theirs = printed
        .lines()
        .find_map(|line| line.strip_prefix("second-copy-document="))
        .unwrap_or_else(|| {
            panic!(
                "the second copy ran this case and printed the document it wrote. A filter \
                 that selects no case exits 0 and proves nothing, so an absent line fails \
                 here rather than passing quietly. It printed: {printed}"
            )
        });

    assert_ne!(
        theirs,
        stated(&mine),
        "two copies of this binary, at once, wrote one path"
    );
    assert_eq!(
        std::fs::read_to_string(&mine).expect("this run's own document is still readable"),
        MINE,
        "the second copy overwrote this run's document at {}",
        stated(&mine)
    );
}

/// What [`run_root_under`] removes, and what it must not.
///
/// Each line of that function is decided by one assertion here, and deleting the line makes
/// that assertion red:
///
/// * the root of a run that is **over** is swept by the next run. Without it the parent
///   gains one directory for every process id that has ever run this binary — measured at
///   644 MB across one adversary pass — because a run can only clear a directory named for
///   its own id.
/// * the root of a run that is **running** is left alone. A sweep that does not ask deletes
///   a live copy's documents mid-run, which is `story:per-run-test-scratch`'s own collision
///   inverted and worse than what it fixed.
/// * a directory standing under **this** run's id is cleared. Ids are recycled, and a run
///   that reads the documents of the process that held its id before it is reading another
///   run's state, which is the whole defect.
///
/// The finished id is a child of this process that has been waited on, so it is a run that
/// is genuinely over rather than an id picked for being absent. The live id is `1`, which
/// is running on any host that is running this case.
#[test]
fn the_run_root_clears_what_is_finished_and_keeps_what_is_running() {
    let parent = run_root().join("sweep-fixture");
    let mine = std::process::id();

    let copy = Command::new(std::env::current_exe().expect("this test binary's own path"))
        .args([
            "--exact",
            "a_second_copy_of_this_binary_does_not_write_this_runs_documents",
            "--nocapture",
        ])
        .env(SECOND_COPY, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a copy of this binary runs");
    let over = copy.id();
    let finished = copy.wait_with_output().expect("the copy is waited on");
    assert!(
        finished.status.success(),
        "the copy passed; its stderr: {}",
        String::from_utf8_lossy(&finished.stderr)
    );

    let of_a_finished_run = parent.join(format!("run-{over}"));
    let of_a_running_one = parent.join("run-1");
    let of_this_run = parent.join(format!("run-{mine}"));
    for root in [&of_a_finished_run, &of_a_running_one, &of_this_run] {
        std::fs::create_dir_all(root).expect("a writable scratch directory");
        std::fs::write(root.join("connection.json"), "{}").expect("the fixture is written");
    }

    let root = run_root_under(&parent, mine);

    // Where there is no `/proc` to read, no run is claimed to have finished and none is
    // swept: a wrong answer deletes a live run's documents, so absence answers "keep".
    let swept = Path::new("/proc").is_dir();
    assert_eq!(
        of_a_finished_run.exists(),
        !swept,
        "the root of run {over}, which has exited, is swept by the next run, so what stands \
         in the parent is the runs that are running"
    );
    assert!(
        of_a_running_one.exists(),
        "the root of process 1, which is running, is left standing; a sweep that took it \
         would be a copy deleting its neighbour's documents mid-run"
    );
    assert_eq!(
        root, of_this_run,
        "this run's root is the one named for its id"
    );
    assert!(
        !of_this_run.join("connection.json").exists(),
        "a directory standing under this run's own id was written by a process that has \
         exited and whose id was handed on; it is cleared, not written into"
    );
    assert!(root.is_dir(), "this run's root is created");
}
