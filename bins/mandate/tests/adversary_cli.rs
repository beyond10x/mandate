//! Adversary pass 1 on `story:pkce-sessions`, unit D: the CLI primitive.
//!
//! Two documents are driven against the binary:
//!
//! * `.engineering/planning/story/pkce-sessions.md`, coordinator decisions — "The CLI
//!   prints the challenge, never the verifier ... A freshly generated verifier is
//!   credential material and `AGENTS.md` forbids raw credentials in logs and fixtures".
//! * RFC 7636 section 4.1, which the same change encodes in
//!   `crates/mandate-federation/src/pkce.rs:69-79` as `verifier_is_well_formed`: a code
//!   verifier is 43 to 128 characters of `[A-Za-z0-9-._~]`.
//!
//! The expected challenges below were computed independently of this workspace, with
//! CPython's `hashlib.sha256` and `base64.urlsafe_b64encode`, so they check the binary's
//! hand-written base64url encoder rather than restating it.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// RFC 7636 appendix B's published pair. A test vector, not credential material.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mandate"))
        .args(arguments)
        .output()
        .expect("the binary under test runs")
}

fn run_with_stdin(arguments: &[&str], written: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mandate"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test runs");
    if let Some(mut stdin) = child.stdin.take() {
        // A binary that never reads stdin closes the pipe; that is not this test's claim.
        let _ = stdin.write_all(written.as_bytes());
    }
    child
        .wait_with_output()
        .expect("the binary under test exits")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
}

/// Five verifiers in the declared form and the challenges an independent SHA-256 and
/// base64url implementation answers for them, including both length boundaries.
#[test]
fn the_binary_agrees_with_an_independent_s256_implementation() {
    let vectors = [
        (RFC_VERIFIER.to_owned(), RFC_CHALLENGE.to_owned()),
        (
            "A".repeat(43),
            "DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo".to_owned(),
        ),
        (
            "~".repeat(43),
            "dOHT1ivLVSPsewADt8TAZF2T2lLYTZ4BymCwTRKpihg".to_owned(),
        ),
        (
            format!("abc{}", "-._~".repeat(10)),
            "dk0JOgDnoRl5J0qSsTycnDIruUao-lgSVQf36xDyXaY".to_owned(),
        ),
        (
            "0".repeat(128),
            "RXJXkcR7MmGMxXuIND4rzuw7CgG4O8l9FEosvBGiDD0".to_owned(),
        ),
        (
            format!("{}Z", "a".repeat(127)),
            "mFVGhQ_rf1id3gzc0aGLOMRg2bZah_2Oh0gO3y_FwuY".to_owned(),
        ),
    ];

    for (verifier, expected) in vectors {
        let output = run(&["pkce-challenge", &verifier]);

        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(
            stdout_of(&output),
            expected,
            "verifier of {} characters",
            verifier.len()
        );
    }
}

/// Every real S256 challenge is the unpadded base64url encoding of 32 bytes, so its final
/// character's alphabet index is a multiple of four. The binary's output has that shape;
/// `crates/mandate-federation/src/pkce.rs`'s `StandInDigest` — the only implementation of
/// the port the library predicate is ever tested against — does not.
#[test]
fn the_printed_challenge_has_the_shape_of_a_thirty_two_byte_digest() {
    for verifier in [RFC_VERIFIER.to_owned(), "A".repeat(43), "0".repeat(128)] {
        let printed = stdout_of(&run(&["pkce-challenge", &verifier]));

        assert_eq!(printed.len(), 43, "{printed}");
        let last = ALPHABET
            .iter()
            .position(|entry| *entry == printed.as_bytes()[42])
            .expect("the printed challenge is base64url");
        assert_eq!(last % 4, 0, "{printed} decodes to exactly 32 bytes");
    }
}

/// The same change decides what a code verifier is
/// (`crates/mandate-federation/src/pkce.rs:69-79`, RFC 7636 section 4.1) and refuses
/// anything else before it digests it. The binary that exists to derive a challenge for a
/// verifier applies none of it: it prints a challenge for a value the core it serves will
/// refuse at redemption, and for a non-ASCII value RFC 7636 section 4.2 does not define a
/// digest of at all.
#[test]
fn a_verifier_outside_rfc_7636_section_4_1_is_refused() {
    let outside = [
        ("empty", String::new()),
        ("one character", "a".to_owned()),
        ("forty-two characters", "a".repeat(42)),
        ("one hundred and twenty-nine characters", "a".repeat(129)),
        ("two hundred characters", "a".repeat(200)),
        ("an interior space", format!("{} b", "a".repeat(41))),
        ("a trailing newline", format!("{}\n", "a".repeat(43))),
        ("non-ascii", format!("{}ünïcöde", "a".repeat(36))),
    ];

    for (label, verifier) in outside {
        let output = run(&["pkce-challenge", &verifier]);

        assert!(
            !output.status.success(),
            "{label} is not a code verifier, and a challenge was printed for it anyway: {}",
            stdout_of(&output)
        );
    }
}

/// RFC 7636 section 4.1 puts `-` in the unreserved set, and section 4.1's recommended
/// generation is base64url over 32 random octets — an alphabet whose first character is
/// `-` about one time in sixty-four. clap reads a leading `-` as a flag, so the binary
/// refuses roughly one in sixty-four correctly generated verifiers outright, and the
/// unit's own cases never see it because the appendix B vector begins with `d`.
#[test]
fn a_verifier_that_begins_with_a_hyphen_is_still_a_code_verifier() {
    let vectors = [
        (
            format!("{}abc", "-._~".repeat(10)),
            "rpMOCY0WfS5THycY5m5x09DbL6TMXzEQKrMRc1ncehQ",
        ),
        (
            format!("-{}", "a".repeat(42)),
            "Y70fIUCZbil-iISRzVlZiOsj2Wp7-t5aXMz2bKocmSg",
        ),
    ];

    for (verifier, expected) in vectors {
        let output = run(&["pkce-challenge", &verifier]);

        assert!(
            output.status.success(),
            "a verifier beginning with `-` is in the declared form: {:?}, {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
        assert_eq!(stdout_of(&output), expected);
    }
}

/// The verifier reaches the binary only as a command-line argument, and a command-line
/// argument is credential material placed where the operator cannot take it back: it is
/// recorded by every interactive shell's history file and is readable, for the lifetime
/// of the process, by any process of the same user. A stdin path costs one clap attribute
/// and removes both.
#[test]
fn the_verifier_can_be_supplied_without_placing_it_on_the_command_line() {
    let output = run_with_stdin(&["pkce-challenge"], &format!("{RFC_VERIFIER}\n"));

    assert!(
        output.status.success(),
        "a verifier read from stdin never enters argv: {:?}, {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(stdout_of(&output), RFC_CHALLENGE);
}

/// The mechanism the case above is about, demonstrated rather than asserted, on a process
/// that is not the binary under test: an argument handed to any process is readable from
/// `/proc/<pid>/cmdline` while it runs.
#[cfg(target_os = "linux")]
#[test]
fn an_argument_of_a_running_process_is_readable_from_proc() {
    // `read` is a shell builtin, so the shell does not exec over its own argv, and it
    // blocks on a stdin this test holds open rather than racing the reader below.
    let mut child = Command::new("/bin/sh")
        .args(["-c", "read line", RFC_VERIFIER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("/bin/sh runs");

    // Between fork and exec the entry still shows this test binary's own argv, so the
    // wait is on the shell having taken the pid over, not on the value being looked for.
    let mut rendering = String::new();
    for _ in 0..200 {
        if let Ok(raw) = std::fs::read(format!("/proc/{}/cmdline", child.id())) {
            let text = String::from_utf8_lossy(&raw).replace('\0', " ");
            if text.starts_with("/bin/sh") {
                rendering = text;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        rendering.contains(RFC_VERIFIER),
        "an argument is readable by any process of the user while the process runs: {rendering}"
    );
}
