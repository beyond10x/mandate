//! The `mandate` binary: local, secret-free computations only.
//!
//! Runtime capabilities are not implemented and this binary opens no socket: `xtask`
//! requires `serve` to exit non-zero (`xtask/src/main.rs:322-327`). It links no workspace
//! crate — `dependency-boundaries.json` admits `clap`, `serde_json` and `sha2` here and
//! nothing else — so the S256 derivation and the form check below are its own, and the
//! domain crate's equivalents sit behind a port for the mirror-image reason.
//!
//! # Nothing this binary writes carries an argument value
//!
//! Not the form refusal, and not the argument parser's either: the one subcommand means
//! the slip an operator makes is `mandate <verifier>`, and clap's own rendering of an
//! unrecognized subcommand quotes what it refused. The parse is therefore
//! [`Parser::try_parse`] and the refusal is written here, naming no value. Help and
//! version carry none and are printed as clap wrote them.
//!
//! # Where the verifier comes from
//!
//! Standard input, by preference. A code verifier is credential material, and an argument
//! is credential material the operator cannot take back: every interactive shell records
//! it in a history file, and `/proc/<pid>/cmdline` hands it to any process of the same
//! user for as long as this one runs. The positional argument stays for scripts that have
//! already solved that themselves.

use std::io::{self, BufRead};
use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

/// RFC 7636 section 4.1: a code verifier is at least 43 characters.
const VERIFIER_MINIMUM_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is at most 128 characters.
const VERIFIER_MAXIMUM_LENGTH: usize = 128;

/// Mandate foundation scaffold; runtime capabilities are not implemented.
#[derive(Parser)]
#[command(name = "mandate", version, arg_required_else_help = true)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

/// The local computations this binary performs.
#[derive(Subcommand)]
enum Command {
    /// Print the S256 PKCE challenge of a code verifier, reading it from standard input.
    ///
    /// The challenge is public and is what a public client sends; the verifier is
    /// credential material and is never printed, logged or stored. Supplying it on
    /// standard input is what keeps it out of `argv`, where the shell's history file and
    /// `/proc/<pid>/cmdline` would both carry it; the positional argument is for scripts
    /// that have already dealt with that.
    PkceChallenge {
        /// The code verifier. Omit it to read one line from standard input.
        #[arg(allow_hyphen_values = true)]
        verifier: Option<String>,
    },
}

fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error) => return refused(&error),
    };
    match args.command {
        Command::PkceChallenge { verifier } => pkce_challenge(verifier),
    }
}

/// Report a parser refusal without echoing what it refused.
///
/// A parser error renders the offending argument, and the argument this binary is given
/// is a code verifier: `mandate <verifier>` — the subcommand forgotten — would put
/// credential material on standard error, the channel the form refusal is careful to keep
/// clean. The two refusals also carry different statuses, so a script can tell "that is
/// not a verifier" (1) from "that is not how this is called" (2).
fn refused(error: &clap::Error) -> ExitCode {
    match error.kind() {
        // Help and version are not refusals: clap writes them to standard output and
        // neither carries a value the caller supplied.
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = error.print();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("mandate: unrecognized input; run `mandate pkce-challenge --help`");
            ExitCode::from(2)
        }
    }
}

/// Derive and print the challenge, or refuse the value for its form.
///
/// The refusal names the declared form and never the value: a message that echoed the
/// verifier would put credential material in every log that captured this binary's
/// standard error.
fn pkce_challenge(verifier: Option<String>) -> ExitCode {
    let verifier = match verifier {
        Some(verifier) => verifier,
        None => match read_line() {
            Ok(line) => line,
            Err(error) => {
                eprintln!("mandate: no code verifier on standard input: {error}");
                return ExitCode::FAILURE;
            }
        },
    };
    if !verifier_is_well_formed(&verifier) {
        eprintln!(
            "mandate: not a code verifier. RFC 7636 section 4.1 declares {VERIFIER_MINIMUM_LENGTH} to {VERIFIER_MAXIMUM_LENGTH} characters of [A-Za-z0-9-._~]."
        );
        return ExitCode::FAILURE;
    }
    println!("{}", s256_challenge(&verifier));
    ExitCode::SUCCESS
}

/// One line of standard input, without its line ending.
///
/// # Errors
///
/// Returns the read error, and an end of input as one: a closed input carries no verifier.
fn read_line() -> io::Result<String> {
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line)? == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_owned())
}

/// Whether a value is a code verifier in the form RFC 7636 section 4.1 declares: 43 to 128
/// characters of the unreserved set `[A-Za-z0-9-._~]`.
///
/// The set is ASCII, so a value that passes it has one byte per character and RFC 7636
/// section 4.2's `ASCII(verifier)` is defined for it. The core refuses anything else at
/// redemption (`mandate_federation::pkce::verifier_is_well_formed`), so a challenge
/// printed for such a value could never be redeemed.
fn verifier_is_well_formed(verifier: &str) -> bool {
    verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        && (VERIFIER_MINIMUM_LENGTH..=VERIFIER_MAXIMUM_LENGTH).contains(&verifier.len())
}

/// `BASE64URL-ENCODE(SHA256(ASCII(verifier)))`, RFC 7636 section 4.2.
fn s256_challenge(verifier: &str) -> String {
    base64url(&Sha256::digest(verifier.as_bytes()))
}

/// Unpadded base64url, RFC 4648 section 5.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..=chunk.len() {
            let shift = 18 - 6 * index;
            text.push(char::from(ALPHABET[((accumulator >> shift) & 63) as usize]));
        }
    }
    text
}
