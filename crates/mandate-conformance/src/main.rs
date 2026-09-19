//! `mandate-conform`: run an ESS conformance suite against the real Mandate handlers.
//!
//! The surface is the one `story:conform-gate` was written against and this story froze:
//! `--suite`, `--impl-digest`, `--out`, and nothing else.
//!
//! # Exit zero on a written report, whatever the report says
//!
//! A conformance verdict is a fact the report carries, not a fact the process status
//! carries, and the two mean different things: a non-zero exit says *the run did not
//! happen*, and a `conformance_status` of `failed` says *the run happened and the
//! implementation does not yet satisfy the specification*. Collapsing them would make the
//! gate unable to tell a target that crashed from one that reported 46 scenarios it cannot
//! drive — and `initiative:drift-enforcement`'s release stance turns on exactly that
//! distinction. So a run that wrote a report exits zero and the gate reads the report.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use mandate_conformance::Executed;

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
    ExitCode::from(conform(&Args::parse()))
}

/// Execute the suite and write the three documents, reporting the process status.
///
/// Returns the status as a value a test can read rather than calling
/// [`std::process::exit`], which a test could only observe by spawning.
fn conform(args: &Args) -> u8 {
    let suite = match std::fs::read_to_string(&args.suite) {
        Ok(suite) => suite,
        Err(error) => {
            eprintln!(
                "mandate-conform: {} could not be read: {error}",
                args.suite.display()
            );
            return 1;
        }
    };
    let executed = match Executed::of(&suite, &args.impl_digest) {
        Ok(executed) => executed,
        Err(error) => {
            eprintln!("mandate-conform: the suite was not executed: {error}");
            return 1;
        }
    };
    if let Err(error) = executed.write(&args.out) {
        eprintln!(
            "mandate-conform: {} could not be written: {error}",
            args.out.display()
        );
        return 1;
    }
    eprintln!(
        "mandate-conform: {} conformance_status={:?}",
        args.out.display(),
        executed.conformance_status
    );
    0
}

#[cfg(test)]
mod tests {
    use super::{Args, conform};
    use clap::{CommandFactory, Parser};

    /// The frozen surface parses, and the three checks `xtask` runs against this binary hold.
    #[test]
    fn the_frozen_surface_parses_and_refuses_what_it_must() {
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
    }

    /// A suite that cannot be read is a run that did not happen, and exits non-zero.
    ///
    /// The other half of the exit contract argued at the module: a written report exits
    /// zero whatever its verdict, and nothing else does.
    #[test]
    fn a_suite_that_cannot_be_read_exits_non_zero() {
        let args = Args::try_parse_from([
            "mandate-conform",
            "--suite",
            "a-path-no-run-wrote.json",
            "--impl-digest",
            "000000000000",
            "--out",
            "a-directory-no-run-wrote",
        ])
        .expect("the frozen surface refused its own arguments");
        assert_eq!(conform(&args), 1, "an unreadable suite exited zero");
    }
}
