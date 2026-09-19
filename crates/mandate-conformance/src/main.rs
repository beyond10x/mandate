//! `mandate-conform`: run an ESS conformance suite against the real Mandate handlers.
//!
//! The surface is frozen here and the behaviour arrives with `story:conformance-target`:
//! `--suite`, `--impl-digest` and `--out`, and nothing else. Freezing it first is what lets
//! `story:conform-gate` and the story's own gate name the invocation before there is anything
//! to invoke; a surface that moved afterwards would invalidate every command line already
//! written against it.
//!
//! Until then every run refuses, non-zero and by name, so that a caller who wires this into a
//! pipeline today gets a failure that says which story owns the gap rather than an empty
//! output directory that reads like a passing run. `xtask`'s binary check
//! (`xtask/src/main.rs`) holds that open from the other side: `--help` and `--version` must
//! exit zero and `serve` must not, so this binary cannot quietly grow a runtime command.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

/// What every run says until `story:conformance-target` lands.
const UNIMPLEMENTED: &str = "not yet implemented: story:conformance-target";

/// Run a conformance suite against the Mandate implementation and record what happened.
#[derive(Parser)]
#[command(name = "mandate-conform", version, arg_required_else_help = true)]
struct Args {
    /// The admitted conformance suite to execute, as JSON.
    #[arg(long, value_name = "PATH")]
    suite: PathBuf,

    /// The digest of the implementation under test, recorded in the report.
    #[arg(long, value_name = "HEX")]
    impl_digest: String,

    /// The directory `report.json`, `run.json` and `injections.json` are written to.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

fn main() -> ExitCode {
    ExitCode::from(conform(Args::parse()))
}

/// Refuse the run, naming the story that will implement it.
///
/// Returns the process status, so the refusal is decided by a value a test can read rather
/// than by a call to [`std::process::exit`] that a test could only observe by spawning.
/// Non-zero is the contract `xtask` checks: a caller must not be able to mistake "nothing ran"
/// for "everything passed".
fn conform(args: Args) -> u8 {
    let Args {
        suite,
        impl_digest,
        out,
    } = args;
    eprintln!("mandate-conform: {UNIMPLEMENTED}");
    eprintln!(
        "mandate-conform: no scenario was read from {}, no report was written under {}, and nothing was recorded for implementation {}",
        suite.display(),
        out.display(),
        impl_digest
    );
    1
}

#[cfg(test)]
mod tests {
    use super::{Args, conform};
    use clap::{CommandFactory, Parser};

    /// The frozen surface parses, and the three checks `xtask` runs against this binary hold.
    ///
    /// `--help` and `--version` exit zero, anything that looks like a runtime command does
    /// not, and a complete, well-formed invocation still refuses. The last one is the check
    /// that matters: a binary that exited zero on a run it did not perform would report an
    /// unimplemented target as a passing conformance run.
    #[test]
    fn the_frozen_surface_refuses_every_run() {
        Args::command().debug_assert();

        for flag in ["--help", "--version"] {
            let error = Args::try_parse_from(["mandate-conform", flag])
                .err()
                .unwrap_or_else(|| panic!("{flag} parsed as a run"));
            assert_eq!(error.exit_code(), 0, "{flag} does not exit zero");
        }

        let error = Args::try_parse_from(["mandate-conform", "serve"])
            .err()
            .expect("serve parsed as a run");
        assert_ne!(error.exit_code(), 0, "serve exits zero");

        let error = Args::try_parse_from(["mandate-conform"])
            .err()
            .expect("no arguments parsed as a run");
        assert_ne!(error.exit_code(), 0, "a bare invocation exits zero");

        let args = Args::try_parse_from([
            "mandate-conform",
            "--suite",
            "suite.json",
            "--impl-digest",
            "000000000000",
            "--out",
            "out",
        ])
        .expect("the frozen surface refused its own arguments");
        assert_ne!(conform(args), 0, "an unimplemented run exits zero");
    }
}
