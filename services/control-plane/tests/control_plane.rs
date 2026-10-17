//! `--config-dir`: a directory of documents is the same configuration as the flags.
//!
//! The binary is spawned twice, once with each document named by its flag and once with the
//! same documents laid out in a directory, and what it prints before it serves is compared.
//! Nothing here binds a port of its own: both children take `127.0.0.1:0`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_mandate-control-plane");

const ORGANIZATION: &str = "00000000-0000-4000-8000-000000000001";
const CONNECTION: &str = "00000000-0000-4000-8000-000000000002";
const CLIENT: &str = "00000000-0000-4000-8000-000000000003";
const TARGET: &str = "00000000-0000-4000-8000-000000000004";

const KEY: &str = r#"{"kty":"EC","kid":"login-key-1","use":"sig","alg":"ES256",
  "crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn connection() -> String {
    format!(
        r#"{{"connection_id":"{CONNECTION}","organization":"{ORGANIZATION}",
          "issuer":"https://idp.example","client_id":"mandate-at-idp","algorithm":"ES256",
          "tenant_resolution":{{"configured_organization":"{ORGANIZATION}"}},
          "jit_provisioning":false}}"#
    )
}

fn client() -> String {
    format!(
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","client_type":"public",
          "redirect_uris":["https://client.example/callback"],"pkce_method":"S256"}}"#
    )
}

fn resource_server() -> String {
    format!(
        r#"{{"resource_server_id":"{TARGET}","organization":"{ORGANIZATION}",
          "audience":"https://api.example",
          "profile":{{"name":"reference","kind":"Reference","revocation":"ImmediateOnline",
            "max_ttl":"PT1H","positive_cache_ttl":"PT30S",
            "requires_online_authorization":true}},
          "allowed_exchange_sources":[]}}"#
    )
}

/// A scratch directory under the build's own, removed first so a rerun starts empty.
fn scratch(case: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("config-dir-{case}"));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("a scratch directory");
    root
}

fn write(path: &Path, body: &str) -> PathBuf {
    fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    fs::write(path, body).expect("a document");
    path.to_path_buf()
}

/// A child that is killed and reaped however the case ends.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the binary printed before it served, with the one line that names a kernel-chosen
/// port left out: it is the only line that differs between two runs of one configuration.
fn printed_configuration(arguments: &[String]) -> Vec<String> {
    let mut child = Command::new(BINARY)
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--issuer",
            "https://mandate.example",
        ])
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the composition binary runs");
    let stdout = child.stdout.take().expect("a piped stdout");
    let _guard = Reaped(child);
    let mut printed = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("a line of stdout");
        if line.contains("listening on") {
            return printed;
        }
        printed.push(line);
    }
    panic!("the child ended before it listened; it printed {printed:?}");
}

fn status_of(arguments: &[String]) -> (Option<i32>, String) {
    let output = Command::new(BINARY)
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--issuer",
            "https://mandate.example",
        ])
        .args(arguments)
        .output()
        .expect("the composition binary runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn flag(name: &str, path: &Path) -> [String; 2] {
    [
        name.to_owned(),
        path.to_str().expect("a UTF-8 path").to_owned(),
    ]
}

#[test]
fn config_dir_equivalent_to_flags() {
    let root = scratch("equivalent");
    let directory = root.join("mounted");
    let by_flag = root.join("by-flag");
    let documents = [
        ("connections", "a.json", connection()),
        ("keys", "a.json", KEY.to_owned()),
        ("clients", "a.json", client()),
        ("resource-servers", "a.json", resource_server()),
    ];
    let mut flags = Vec::new();
    for ((subdirectory, name, body), option) in
        documents
            .iter()
            .zip(["--connection", "--key", "--client", "--resource-server"])
    {
        write(&directory.join(subdirectory).join(name), body);
        let path = write(&by_flag.join(subdirectory).join(name), body);
        flags.extend(flag(option, &path));
    }

    let from_flags = printed_configuration(&flags);
    let from_directory = printed_configuration(&flag("--config-dir", &directory));
    assert!(!from_flags.is_empty(), "the flags configured nothing");
    assert_eq!(from_flags.len(), 3, "{from_flags:?}");
    assert_eq!(from_directory, from_flags);

    // A mount's own bookkeeping is not a document.
    write(&directory.join("..data").join("ignored"), "x");
    assert_eq!(
        printed_configuration(&flag("--config-dir", &directory)),
        from_flags
    );
}

#[test]
fn config_dir_refuses_an_unknown_file() {
    let root = scratch("unknown");
    let directory = root.join("mounted");
    write(&directory.join("keys").join("a.json"), KEY);
    write(&directory.join("notes.txt"), "not a document");
    let (code, stderr) = status_of(&flag("--config-dir", &directory));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("notes.txt"), "{stderr}");

    let inside = root.join("inside");
    write(&inside.join("keys").join("a.txt"), KEY);
    let (code, stderr) = status_of(&flag("--config-dir", &inside));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("a.txt"), "{stderr}");

    let (code, stderr) = status_of(&flag("--config-dir", &root.join("absent")));
    assert_eq!(code, Some(2), "{stderr}");
}

// ==================================================================================
// Confidential clients: secret references (story:oidc-static-client-registry, fork F2 A)
// ==================================================================================

/// Two secrets that clear the entropy floor, as `openssl rand -base64 32` writes them.
const SECRET_A: &str = "q3Zk8vN1pR6tW0yB4mD9fH2jL7sX5cA+gE/uKoIeT0s=";
const SECRET_B: &str = "Hn5Vd0Qe2Wc7Rx9Ts4Yb1Uz6Ia8Ok3Pl+Jm/Gf0Lr2E=";
/// The fragment of each secret a channel is searched for: long enough to be the secret, short
/// enough to catch a truncated rendering.
const PROBES: [&str; 4] = ["q3Zk8vN1pR6t", "IeT0s", "Hn5Vd0Qe2Wc7", "Lr2E="];

fn confidential_client(secret_ref: &str) -> String {
    format!(
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","name":"App A",
          "client_type":"confidential","secret_ref":{secret_ref},
          "redirect_uris":["https://app-a.example/oauth2/callback"],"pkce_method":"S256",
          "post_logout_redirect_uris":["https://app-a.example/"]}}"#
    )
}

/// The binary's stdout up to and including its listening line, and everything it wrote to
/// stderr by the time it was killed.
fn served_channels(arguments: &[String]) -> (Vec<String>, String) {
    use std::io::Read as _;
    let mut child = Command::new(BINARY)
        .args([
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--issuer",
            "https://mandate.example",
        ])
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the composition binary runs");
    let stdout = child.stdout.take().expect("a piped stdout");
    let mut stderr = child.stderr.take().expect("a piped stderr");
    let mut printed = Vec::new();
    let mut listened = false;
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("a line of stdout");
        listened = line.contains("listening on");
        printed.push(line);
        if listened {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let mut written = String::new();
    stderr.read_to_string(&mut written).expect("stderr is text");
    assert!(
        listened,
        "the child ended before it listened: {printed:?} {written}"
    );
    (printed, written)
}

fn assert_no_secret(channel: &str, rendered: &str) {
    for probe in PROBES {
        assert!(
            !rendered.contains(probe),
            "{channel} carries secret material `{probe}`: {rendered}"
        );
    }
}

/// `--client` naming `secret_ref: "app-a"` and `--client-secret-file app-a=PATH` starts, and
/// the client line it prints carries the client and no secret byte.
#[test]
fn client_secret_reference_resolved() {
    let root = scratch("secret-resolved");
    let secret = write(&root.join("app-a.secret"), &format!("{SECRET_A}\n"));
    let client = write(
        &root.join("client.json"),
        &confidential_client(r#""app-a""#),
    );
    let mut arguments = flag("--client", &client).to_vec();
    arguments.extend([
        "--client-secret-file".to_owned(),
        format!("app-a={}", secret.display()),
    ]);

    let (stdout, stderr) = served_channels(&arguments);

    assert!(
        stdout
            .iter()
            .any(|line| line.ends_with(&format!("seeded oauth client {CLIENT} (App A)"))),
        "{stdout:?}"
    );
    assert_no_secret("stdout", &stdout.join("\n"));
    assert_no_secret("stderr", &stderr);
}

/// An unresolved reference, a secret under the entropy floor, and a redirect URI with a
/// fragment each exit 2 naming the client document, before the listener binds.
#[test]
fn client_secret_reference_unresolved_exits_2() {
    let root = scratch("secret-unresolved");
    let weak = write(&root.join("weak.secret"), "password1234\n");
    let strong = write(&root.join("strong.secret"), SECRET_A);
    let unresolved = write(
        &root.join("unresolved.json"),
        &confidential_client(r#""absent""#),
    );
    let weakly = write(&root.join("weakly.json"), &confidential_client(r#""weak""#));
    let fragment = write(
        &root.join("fragment.json"),
        &confidential_client(r#""strong""#).replace("/callback", "/callback#x"),
    );
    let files = [
        "--client-secret-file".to_owned(),
        format!("weak={}", weak.display()),
        "--client-secret-file".to_owned(),
        format!("strong={}", strong.display()),
    ];

    for (document, names) in [
        (&unresolved, "absent"),
        (&weakly, "entropy"),
        (&fragment, "fragment"),
    ] {
        let mut arguments = flag("--client", document).to_vec();
        arguments.extend(files.iter().cloned());
        let output = Command::new(BINARY)
            .args([
                "serve",
                "--listen",
                "127.0.0.1:0",
                "--issuer",
                "https://mandate.example",
            ])
            .args(&arguments)
            .output()
            .expect("the composition binary runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(
            stderr.contains(document.to_str().expect("a UTF-8 path")),
            "the refusal names the client document: {stderr}"
        );
        assert!(stderr.contains(names), "{stderr}");
        assert!(!stdout.contains("listening on"), "{stdout}");
        assert!(!stderr.contains("password1234"), "{stderr}");
        assert_no_secret("stderr", &stderr);
    }
}

/// Two secret references both authenticate: the client carries two verifiers, each
/// secret presents one of them, and a third secret presents neither (rotation, fork F2 A).
#[test]
fn client_secret_two_verifiers() {
    use mandate_control_plane::adapters::{ClientSeeding, read_client_seed};
    use mandate_federation::record::FederationEvent;
    use mandate_types::{OAuthClientSecret, VerifierKey, client_secret_presents};

    const KEY_MATERIAL: &[u8] = b"a-test-verifier-key-of-at-least-32-bytes";
    let key = || VerifierKey::from_bytes(KEY_MATERIAL.to_vec()).expect("a key");
    let root = scratch("secret-two");
    let secrets = [
        ("old".to_owned(), write(&root.join("old.secret"), SECRET_A)),
        ("new".to_owned(), write(&root.join("new.secret"), SECRET_B)),
    ]
    .into_iter()
    .collect();
    let path = write(
        &root.join("client.json"),
        &confidential_client(r#"["old","new"]"#),
    );
    let seed = read_client_seed(&path).expect("a document serve reads");

    let mut seeding = ClientSeeding::with_secrets(key(), secrets);
    let seeded = seeding
        .admit(&path, &seed, &mut || {
            unreachable!("the client states its id")
        })
        .expect("two references are admitted");
    seeding.settled().expect("no trusted peer");
    let [
        FederationEvent::OAuthClientRegistered {
            secret_verifiers, ..
        },
    ] = seeded.events.as_slice()
    else {
        panic!("one registration: {:?}", seeded.events);
    };
    assert_eq!(secret_verifiers.len(), 2);
    for secret in [SECRET_A, SECRET_B] {
        assert!(client_secret_presents(
            &key(),
            secret_verifiers,
            &OAuthClientSecret::presented(secret.as_bytes().to_vec())
        ));
    }
    assert!(!client_secret_presents(
        &key(),
        secret_verifiers,
        &OAuthClientSecret::presented(b"Zr4qL9x2Tn8vB1mK7pW3sD6fH0jG5cYeQa".to_vec())
    ));

    // The binary starts with both, too.
    let mut arguments = flag("--client", &path).to_vec();
    for (name, file) in [("old", "old.secret"), ("new", "new.secret")] {
        arguments.extend([
            "--client-secret-file".to_owned(),
            format!("{name}={}", root.join(file).display()),
        ]);
    }
    let (stdout, _) = served_channels(&arguments);
    assert!(
        stdout.iter().any(|line| line.contains(CLIENT)),
        "{stdout:?}"
    );

    // A third reference is more than the contract admits.
    let excess = write(
        &root.join("excess.json"),
        &confidential_client(r#"["old","new","third"]"#),
    );
    let refused = ClientSeeding::with_secrets(key(), std::collections::BTreeMap::new())
        .admit(
            &excess,
            &read_client_seed(&excess).expect("a document serve reads"),
            &mut || unreachable!("refused first"),
        )
        .expect_err("three references are refused");
    assert!(
        refused.to_string().contains("ConfidentialVerifierExcess"),
        "{refused}"
    );
}

/// No secret byte on any of the four channels: stdout, stderr, the seeded events (as the
/// fold and the wire would carry them), and every `Debug` rendering on the path.
#[test]
fn client_secret_never_rendered_on_any_channel() {
    use mandate_control_plane::adapters::{ClientSeeding, read_client_seed};
    use mandate_types::{OAuthClientSecret, VerifierKey};

    let root = scratch("secret-channels");
    let old = write(&root.join("old.secret"), SECRET_A);
    let new = write(&root.join("new.secret"), SECRET_B);
    let path = write(
        &root.join("client.json"),
        &confidential_client(r#"["old","new"]"#),
    );

    // stdout and stderr of the running binary.
    let mut arguments = flag("--client", &path).to_vec();
    arguments.extend([
        "--client-secret-file".to_owned(),
        format!("old={}", old.display()),
        "--client-secret-file".to_owned(),
        format!("new={}", new.display()),
    ]);
    let (stdout, stderr) = served_channels(&arguments);
    assert_no_secret("stdout", &stdout.join("\n"));
    assert_no_secret("stderr", &stderr);

    // The events, in their serialized and their Debug forms.
    let seed = read_client_seed(&path).expect("a document serve reads");
    let key = VerifierKey::from_bytes(b"a-test-verifier-key-of-at-least-32-bytes".to_vec())
        .expect("a key");
    let mut seeding = ClientSeeding::with_secrets(
        key,
        [("old".to_owned(), old.clone()), ("new".to_owned(), new)]
            .into_iter()
            .collect(),
    );
    let seeded = seeding
        .admit(&path, &seed, &mut || {
            unreachable!("the client states its id")
        })
        .expect("admitted");
    for event in &seeded.events {
        assert_no_secret(
            "event",
            &serde_json::to_string(event).expect("an event serializes"),
        );
    }

    // Debug: the seed, the seeded client, the key, a secret and a weak-secret refusal.
    assert_no_secret("Debug", &format!("{seed:?} {seeded:?} {seeding:?}"));
    assert_no_secret(
        "Debug",
        &format!(
            "{:?} {:#?}",
            OAuthClientSecret::presented(SECRET_A.as_bytes().to_vec()),
            OAuthClientSecret::configured(SECRET_B.as_bytes().to_vec()).expect("strong")
        ),
    );
    let weak = write(&root.join("weak.secret"), "IeT0sIeT0sIeT0s");
    let refused = ClientSeeding::with_secrets(
        VerifierKey::from_bytes(b"a-test-verifier-key-of-at-least-32-bytes".to_vec())
            .expect("a key"),
        [("old".to_owned(), weak)].into_iter().collect(),
    )
    .admit(
        &path,
        &read_client_seed(&write(
            &root.join("weak.json"),
            &confidential_client(r#""old""#),
        ))
        .expect("a document"),
        &mut || unreachable!("refused first"),
    )
    .expect_err("a weak secret is refused");
    assert_no_secret("Debug", &format!("{refused:?} {refused}"));
}

/// A seeded confidential client requires PKCE unless its document says otherwise (fork F3
/// B), and only a confidential client may say otherwise.
#[test]
fn seeded_confidential_client_defaults_to_pkce_required() {
    use mandate_control_plane::adapters::{ClientSeeding, read_client_seed};
    use mandate_federation::record::FederationEvent;
    use mandate_types::VerifierKey;

    let root = scratch("pkce-default");
    let secret = write(&root.join("a.secret"), SECRET_A);
    let seeding = || {
        ClientSeeding::with_secrets(
            VerifierKey::from_bytes(b"a-test-verifier-key-of-at-least-32-bytes".to_vec())
                .expect("a key"),
            [("a".to_owned(), secret.clone())].into_iter().collect(),
        )
    };
    let pkce_of = |body: String| {
        let path = write(&root.join("client.json"), &body);
        let seed = read_client_seed(&path).expect("a document serve reads");
        seeding()
            .admit(&path, &seed, &mut || {
                unreachable!("the client states its id")
            })
            .map(|seeded| match seeded.events.as_slice() {
                [FederationEvent::OAuthClientRegistered { pkce_required, .. }] => *pkce_required,
                other => panic!("one registration: {other:?}"),
            })
    };

    assert_eq!(pkce_of(confidential_client(r#""a""#)).ok(), Some(true));
    assert_eq!(
        pkce_of(confidential_client(r#""a""#).replace(
            r#""pkce_method":"S256","#,
            r#""pkce_method":"S256","pkce_required":false,"#
        ))
        .ok(),
        Some(false),
        "a confidential client may opt out"
    );
    let public_optional = pkce_of(format!(
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","client_type":"public",
          "redirect_uris":["https://client.example/callback"],"pkce_method":"S256",
          "pkce_required":false}}"#
    ))
    .expect_err("a public client may not");
    assert!(
        public_optional
            .to_string()
            .contains("PublicClientPkceOptional"),
        "{public_optional}"
    );
    let public_with_secret = pkce_of(format!(
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","client_type":"public",
          "secret_ref":"a","redirect_uris":["https://client.example/callback"],
          "pkce_method":"S256"}}"#
    ))
    .expect_err("a public client states no secret");
    assert!(
        public_with_secret
            .to_string()
            .contains("PublicClientVerifier"),
        "{public_with_secret}"
    );
}

/// A trusted peer must be a seeded client of the same organization, and not the client
/// itself; two documents may name each other.
#[test]
fn seeded_trusted_peers_are_settled_against_the_whole_set() {
    use mandate_control_plane::adapters::{ClientSeeding, read_client_seed};

    const OTHER: &str = "00000000-0000-4000-8000-000000000005";
    let root = scratch("trusted-peers");
    let document = |id: &str, peers: &str| {
        format!(
            r#"{{"client_id":"{id}","organization":"{ORGANIZATION}","client_type":"public",
              "redirect_uris":["https://client.example/callback"],"pkce_method":"S256",
              "trusted_peers":[{peers}]}}"#
        )
    };
    let seed_all = |documents: &[(&str, String)]| {
        let mut seeding = ClientSeeding::new();
        for (name, body) in documents {
            let path = write(&root.join(name), body);
            let seed = read_client_seed(&path).expect("a document serve reads");
            seeding.admit(&path, &seed, &mut || unreachable!("stated"))?;
        }
        seeding.settled()
    };

    seed_all(&[
        ("a.json", document(CLIENT, &format!(r#""{OTHER}""#))),
        ("b.json", document(OTHER, &format!(r#""{CLIENT}""#))),
    ])
    .expect("two clients may trust each other");
    let unknown = seed_all(&[("a.json", document(CLIENT, &format!(r#""{OTHER}""#)))])
        .expect_err("an unseeded peer is refused");
    assert!(
        unknown.to_string().contains("TrustedPeerUnknown"),
        "{unknown}"
    );
    assert!(unknown.to_string().contains("a.json"), "{unknown}");
    let itself = seed_all(&[("a.json", document(CLIENT, &format!(r#""{CLIENT}""#)))])
        .expect_err("the client itself is refused");
    assert!(itself.to_string().contains("TrustedPeerSelf"), "{itself}");
}
