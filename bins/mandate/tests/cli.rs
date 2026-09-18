//! The `mandate` binary's local PKCE primitive, and the surface `xtask` asserts.
//!
//! The binary is reached through `env!("CARGO_BIN_EXE_mandate")`, which cargo sets for an
//! integration test of the package that declares the binary, so no dev-dependency is
//! needed and the dependency ceiling is unchanged.
//!
//! The computation is local and secret-free in RFC 8252's sense: no client secret is
//! involved, PKCE stands in its place. The challenge is printed; the verifier never is.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// RFC 7636 Appendix B's published example, which is a test vector rather than credential
/// material: this exact verifier digests to this exact challenge under S256.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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
    let mut stdin = child
        .stdin
        .take()
        .expect("the child's standard input is piped");
    stdin
        .write_all(written.as_bytes())
        .expect("the child reads its standard input");
    drop(stdin);
    child
        .wait_with_output()
        .expect("the binary under test exits")
}

#[test]
fn the_subcommand_prints_the_s256_challenge_of_the_verifier_and_nothing_else() {
    let output = run(&["pkce-challenge", RFC_VERIFIER]);

    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(
        String::from_utf8(output.stdout).expect("the challenge is ASCII"),
        format!("{RFC_CHALLENGE}\n")
    );
    assert_eq!(String::from_utf8(output.stderr).expect("utf-8"), "");
}

#[test]
fn the_verifier_is_never_printed() {
    let output = run(&["pkce-challenge", RFC_VERIFIER]);
    let rendering = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !rendering.contains(RFC_VERIFIER),
        "the verifier is credential material and is never printed: {rendering}"
    );
}

#[test]
fn distinct_verifiers_produce_distinct_challenges() {
    let first = run(&["pkce-challenge", RFC_VERIFIER]).stdout;
    let second = run(&["pkce-challenge", &RFC_VERIFIER.replace('d', "e")]).stdout;

    assert_ne!(first, second);
}

/// `xtask/src/main.rs:322-327` runs both of these against the built binary and requires a
/// zero status from each.
#[test]
fn help_and_version_still_exit_zero() {
    for flag in ["--help", "--version"] {
        let output = run(&[flag]);

        assert!(output.status.success(), "{flag}: {:?}", output.status);
        assert!(!output.stdout.is_empty(), "{flag} writes something");
    }
}

/// `xtask/src/main.rs:322-327` requires a non-zero status for `serve`: runtime
/// capabilities are not implemented, and a binary that accepts a runtime command claims
/// one it does not have.
#[test]
fn serve_is_still_refused() {
    let refused = run(&["serve"]);

    assert!(!refused.status.success(), "{:?}", refused.status);
}

#[test]
fn the_subcommand_requires_its_verifier() {
    for arguments in [vec![], vec!["pkce-challenge"]] {
        let refused = run(&arguments);

        assert!(!refused.status.success(), "{arguments:?}");
    }
}

/// The form check the core applies at redemption
/// (`mandate_federation::pkce::verifier_is_well_formed`, RFC 7636 section 4.1) is applied
/// here too: a challenge this binary prints for a value the core would refuse is a
/// challenge nobody can redeem.
#[test]
fn a_value_outside_the_declared_verifier_form_is_refused_without_being_echoed() {
    for outside in [
        "",
        "too-short",
        &"a".repeat(129),
        &format!("{} b", "a".repeat(41)),
    ] {
        let output = run(&["pkce-challenge", outside]);

        assert!(
            !output.status.success(),
            "{outside:?} is not a code verifier"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).is_empty(),
            "a refusal prints no challenge"
        );
        let complaint = String::from_utf8_lossy(&output.stderr).into_owned();
        if !outside.is_empty() {
            assert!(
                !complaint.contains(outside),
                "the refusal names the declared form, never the value: {complaint}"
            );
        }
        assert!(
            complaint.contains("RFC 7636"),
            "the refusal names the declared form: {complaint}"
        );
    }
}

/// The verifier reaches the binary without entering `argv`, and by the same computation:
/// standard input and the positional argument answer the same challenge.
#[test]
fn a_verifier_read_from_standard_input_answers_the_same_challenge() {
    let from_stdin = run_with_stdin(&["pkce-challenge"], &format!("{RFC_VERIFIER}\n"));

    assert!(from_stdin.status.success(), "{:?}", from_stdin.status);
    assert_eq!(
        String::from_utf8_lossy(&from_stdin.stdout).trim_end(),
        RFC_CHALLENGE
    );
    assert_eq!(
        from_stdin.stdout,
        run(&["pkce-challenge", RFC_VERIFIER]).stdout
    );
}

/// `--help` is where an operator learns that standard input is the way that keeps the
/// verifier out of `argv`, so the help text has to say it.
#[test]
fn the_help_text_says_the_verifier_may_be_supplied_on_standard_input() {
    let output = run(&["pkce-challenge", "--help"]);

    assert!(output.status.success(), "{:?}", output.status);
    let help = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        help.contains("standard input"),
        "the help text names standard input: {help}"
    );
    assert!(
        help.contains("argv"),
        "the help text says why standard input is the one to use: {help}"
    );
}

/// The rule the parser refusal is an instance of: *no* path to standard error carries an
/// argument value. The reported instance was the forgotten subcommand; this is every
/// parser-error shape the binary has, each given a well-formed verifier to quote back,
/// and each asserted to carry the one fixed line instead.
#[test]
fn no_parser_refusal_echoes_an_argument_value() {
    for arguments in [
        vec![RFC_VERIFIER],
        vec!["pkce-challenge", RFC_VERIFIER, RFC_VERIFIER],
        vec!["--not-a-flag", RFC_VERIFIER],
        vec!["pkce-challenge", "--not-a-flag", RFC_VERIFIER],
        vec!["serve", RFC_VERIFIER],
        vec!["help", RFC_VERIFIER],
    ] {
        let refused = run(&arguments);
        let complaint = String::from_utf8_lossy(&refused.stderr).into_owned();

        assert_eq!(refused.status.code(), Some(2), "{arguments:?}");
        assert!(
            !complaint.contains(RFC_VERIFIER),
            "{arguments:?} echoed the value it refused: {complaint}"
        );
        assert_eq!(
            complaint.trim_end(),
            "mandate: unrecognized input; run `mandate pkce-challenge --help`",
            "{arguments:?}"
        );
        assert!(
            String::from_utf8_lossy(&refused.stdout).is_empty(),
            "{arguments:?} printed something on standard output"
        );
    }
}
