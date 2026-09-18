//! Adversary pass 2 on `story:pkce-sessions`, unit D: the corrected CLI.
//!
//! Round 1 moved the verifier off `argv` and added a form check whose refusal
//! deliberately does not echo the value — `bins/mandate/src/main.rs:61-63`: "The refusal
//! names the declared form and never the value: a message that echoed the verifier would
//! put credential material in every log that captured this binary's standard error."
//!
//! That is a property of the whole binary's standard error, not of one function, and the
//! argument parser writes to the same stream. This file drives the stated property
//! against every path that reaches it, and then exercises the standard-input path the
//! correction added at its edges.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// RFC 7636 appendix B's published pair. A test vector, not credential material — and the
/// point of the first case is that the binary cannot tell the difference.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mandate"))
        .args(arguments)
        .output()
        .expect("the binary under test runs")
}

fn run_with_stdin(arguments: &[&str], written: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mandate"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary under test runs");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(written);
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

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// The binary has exactly one subcommand, so omitting it is the slip an operator makes,
/// and the value they omitted it in front of is a complete, well-formed code verifier.
/// The argument parser prints that value back on standard error, which is the channel
/// `main.rs:61-63` says must never carry it.
#[test]
fn no_path_to_standard_error_echoes_the_value_it_refused() {
    let refused = run(&[RFC_VERIFIER]);

    assert!(!refused.status.success(), "{:?}", refused.status);
    assert!(
        !stderr_of(&refused).contains(RFC_VERIFIER),
        "a verifier given without the subcommand is credential material the binary must \
         not print: {}",
        stderr_of(&refused)
    );
}

/// The path the correction did guard, kept beside the one above so the difference is one
/// line of evidence rather than an argument.
#[test]
fn the_form_refusal_still_names_the_form_and_not_the_value() {
    let refused = run(&["pkce-challenge", "too-short"]);

    assert_eq!(refused.status.code(), Some(1));
    let rendering = stderr_of(&refused);
    assert!(!rendering.contains("too-short"), "{rendering}");
    assert!(rendering.contains("RFC 7636"), "{rendering}");
}

// ---------------------------------------------------------------------------
// The standard-input path, at its edges.
// ---------------------------------------------------------------------------

#[test]
fn the_standard_input_path_accepts_every_line_ending_and_none() {
    for (label, written) in [
        ("bare newline", format!("{RFC_VERIFIER}\n")),
        ("carriage return and newline", format!("{RFC_VERIFIER}\r\n")),
        ("no line ending at all", RFC_VERIFIER.to_owned()),
        (
            "a second line that is not read",
            format!("{RFC_VERIFIER}\nsecond-line-ignored\n"),
        ),
    ] {
        let output = run_with_stdin(&["pkce-challenge"], written.as_bytes());

        assert!(output.status.success(), "{label}: {:?}", output.status);
        assert_eq!(stdout_of(&output), RFC_CHALLENGE, "{label}");
    }
}

/// A closed input carries no verifier, and a blank line is not one either. The two are
/// told apart by the message, and neither prints a challenge.
#[test]
fn an_empty_or_blank_standard_input_prints_no_challenge() {
    let closed = run_with_stdin(&["pkce-challenge"], b"");
    assert_eq!(closed.status.code(), Some(1));
    assert_eq!(stdout_of(&closed), "");
    assert!(
        stderr_of(&closed).contains("standard input"),
        "{}",
        stderr_of(&closed)
    );

    let blank = run_with_stdin(&["pkce-challenge"], b"\n");
    assert_eq!(blank.status.code(), Some(1));
    assert_eq!(stdout_of(&blank), "");
    assert!(
        stderr_of(&blank).contains("RFC 7636"),
        "{}",
        stderr_of(&blank)
    );
}

/// Standard input is bytes, and a code verifier is ASCII. Neither the invalid sequence
/// nor any part of the line reaches standard error.
#[test]
fn a_standard_input_that_is_not_text_is_refused_without_echoing_it() {
    let refused = run_with_stdin(&["pkce-challenge"], b"\xff\xfe\xfd-marker-\n");

    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(stdout_of(&refused), "");
    assert!(
        !stderr_of(&refused).contains("marker"),
        "{}",
        stderr_of(&refused)
    );
}

/// The lengths RFC 7636 section 4.1 bounds, read from standard input rather than argv, and
/// the hyphen-leading value that argv could not carry before the correction.
#[test]
fn the_standard_input_path_applies_the_same_form_check_as_the_positional() {
    let accepted = [
        "a".repeat(43),
        "a".repeat(128),
        format!("-{}", "a".repeat(42)),
        "-._~".repeat(11).chars().take(43).collect(),
    ];
    for verifier in accepted {
        let from_stdin = run_with_stdin(&["pkce-challenge"], format!("{verifier}\n").as_bytes());
        let from_argv = run(&["pkce-challenge", &verifier]);

        assert!(
            from_stdin.status.success(),
            "{verifier}: {}",
            stderr_of(&from_stdin)
        );
        assert_eq!(stdout_of(&from_stdin), stdout_of(&from_argv), "{verifier}");
    }

    for verifier in [
        "a".repeat(42),
        "a".repeat(129),
        format!("{} b", "a".repeat(41)),
    ] {
        let from_stdin = run_with_stdin(&["pkce-challenge"], format!("{verifier}\n").as_bytes());
        let from_argv = run(&["pkce-challenge", &verifier]);

        assert_eq!(from_stdin.status.code(), Some(1), "{verifier}");
        assert_eq!(from_argv.status.code(), Some(1), "{verifier}");
    }
}

/// The positional wins and standard input is not consumed; the two never combine into a
/// value neither side supplied.
#[test]
fn a_positional_argument_wins_over_standard_input() {
    let output = run_with_stdin(&["pkce-challenge", RFC_VERIFIER], b"a-different-line\n");

    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(stdout_of(&output), RFC_CHALLENGE);
}

/// A refusal for the form and a refusal from the argument parser are different failures
/// and carry different statuses, so a script can tell "that is not a verifier" from
/// "that is not how this is called".
#[test]
fn the_two_kinds_of_refusal_carry_different_statuses() {
    assert_eq!(run(&["pkce-challenge", "short"]).status.code(), Some(1));
    assert_eq!(run(&["pkce-challenge", "a", "b"]).status.code(), Some(2));
    assert_eq!(run(&["serve"]).status.code(), Some(2));
}

/// The help an operator reads must not contain anything shaped like a real verifier: an
/// example in the declared form invites being pasted, and a challenge derived from a
/// published example is the one thing in this system that looks safe and is not.
#[test]
fn no_help_text_carries_a_token_in_the_declared_verifier_form() {
    for arguments in [
        vec!["--help"],
        vec!["-h"],
        vec!["pkce-challenge", "--help"],
        vec!["pkce-challenge", "-h"],
        vec!["help", "pkce-challenge"],
    ] {
        let output = run(&arguments);

        assert!(
            output.status.success(),
            "{arguments:?}: {:?}",
            output.status
        );
        for token in stdout_of(&output).split_whitespace() {
            let unreserved = token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            });
            assert!(
                !(unreserved && (43..=128).contains(&token.len())),
                "{arguments:?} prints a token in the declared verifier form: {token}"
            );
        }
    }
}
