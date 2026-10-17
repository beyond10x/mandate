//! `--config-dir`: a directory of documents is the same configuration as the flags.
//!
//! The binary is spawned twice, once with each document named by its flag and once with the
//! same documents laid out in a directory, and what it prints before it serves is compared.
//! Nothing here binds a port of its own: both children take `127.0.0.1:0`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

const BINARY: &str = env!("CARGO_BIN_EXE_mandate-control-plane");

const ORGANIZATION: &str = "00000000-0000-4000-8000-000000000001";
const CONNECTION: &str = "00000000-0000-4000-8000-000000000002";
const CLIENT: &str = "00000000-0000-4000-8000-000000000003";
const TARGET: &str = "00000000-0000-4000-8000-000000000004";

/// A P-256 private key generated now, as the PKCS#8 PEM `--signing-key` mounts. No private
/// key byte is written into this file.
fn key() -> String {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("a P-256 key is generated");
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        mandate_types::value::encode_base64(pkcs8.as_ref())
    )
}

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
        r#"{{"client_id":"{CLIENT}","organization":"{ORGANIZATION}","public":true,
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
        // A mounted key's record identity is allocated per run; the name it was mounted
        // under is the configuration, so that is what is compared.
        let line = match line.split_once("registered signing key ") {
            Some((head, rest)) => format!(
                "{head}registered signing key {}",
                rest.split_once(' ').map_or(rest, |(_, tail)| tail)
            ),
            None => line,
        };
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
        ("clients", "a.json", client()),
        ("resource-servers", "a.json", resource_server()),
    ];
    let mut flags = Vec::new();
    for ((subdirectory, name, body), option) in
        documents
            .iter()
            .zip(["--connection", "--client", "--resource-server"])
    {
        write(&directory.join(subdirectory).join(name), body);
        let path = write(&by_flag.join(subdirectory).join(name), body);
        flags.extend(flag(option, &path));
    }
    // A signing key is a file named for its `NAME`, as `--signing-key NAME=PATH` names it.
    let signing_key = key();
    write(&directory.join("signing-keys").join("login"), &signing_key);
    let path = write(&by_flag.join("signing-keys").join("login"), &signing_key);
    flags.extend([
        "--signing-key".to_owned(),
        format!("login={}", path.to_str().expect("a UTF-8 path")),
    ]);

    let from_flags = printed_configuration(&flags);
    let from_directory = printed_configuration(&flag("--config-dir", &directory));
    assert!(!from_flags.is_empty(), "the flags configured nothing");
    assert_eq!(from_flags.len(), 4, "{from_flags:?}");
    assert!(
        from_flags
            .iter()
            .any(|line| line.ends_with("registered signing key from `login`")),
        "{from_flags:?}"
    );
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
    write(&directory.join("clients").join("a.json"), &client());
    write(&directory.join("notes.txt"), "not a document");
    let (code, stderr) = status_of(&flag("--config-dir", &directory));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("notes.txt"), "{stderr}");

    let inside = root.join("inside");
    write(&inside.join("clients").join("a.txt"), &client());
    let (code, stderr) = status_of(&flag("--config-dir", &inside));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("a.txt"), "{stderr}");

    // `keys/` held the retired `--key` documents and is no longer a document directory: a
    // mount still carrying one is refused rather than silently publishing nothing.
    let retired = root.join("retired");
    write(&retired.join("keys").join("a.json"), "{}");
    let (code, stderr) = status_of(&flag("--config-dir", &retired));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("keys"), "{stderr}");

    let (code, stderr) = status_of(&flag("--config-dir", &root.join("absent")));
    assert_eq!(code, Some(2), "{stderr}");
}
