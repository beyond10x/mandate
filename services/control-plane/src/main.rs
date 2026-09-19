//! `mandate-control-plane`: the composition binary. `serve --listen <addr>` binds the login
//! road's listener over a deployment whose folds start empty; seeding them from an event
//! log is the next milestone (ruling D4, `story:product-listener`).

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mandate_control_plane::adapters::{Configuration, Deployment, SystemAllocator, SystemSecrets};
use mandate_control_plane::serve::{Limits, Listener};
use mandate_federation::verifier_real::{AllowedAlgorithms, RealVerifier, SystemClock, UreqJwks};
use mandate_sts::code::CodeLifetime;
use mandate_types::{Duration, SigningAlgorithm};

#[derive(Parser)]
#[command(name = "mandate-control-plane", version, arg_required_else_help = true)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Bind the address and serve the login road until the process ends.
    Serve {
        /// The socket address to bind.
        #[arg(long)]
        listen: SocketAddr,
        /// The issuer identifier the metadata document is published under.
        #[arg(long)]
        issuer: String,
        /// The longest lifetime of an authorization code, as an ISO 8601 duration.
        #[arg(long, default_value = "PT5M")]
        code_lifetime: String,
        /// The longest lifetime of a federated session, as an ISO 8601 duration.
        #[arg(long, default_value = "PT8H")]
        session_lifetime: String,
    },
}

fn main() -> ExitCode {
    let Args { action } = Args::parse();
    match action {
        Action::Serve {
            listen,
            issuer,
            code_lifetime,
            session_lifetime,
        } => match serve(listen, issuer, &code_lifetime, &session_lifetime) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("mandate-control-plane: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn serve(
    listen: SocketAddr,
    issuer: String,
    code_lifetime: &str,
    session_lifetime: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let allowed = AllowedAlgorithms::configured(&[
        SigningAlgorithm::new("ES256"),
        SigningAlgorithm::new("RS256"),
    ])?;
    let verifier = RealVerifier::new(allowed, UreqJwks::new(), SystemClock);
    let mut deployment = Deployment::new(
        Configuration {
            issuer,
            code_lifetime: CodeLifetime::new(Duration::new(code_lifetime)),
            session_lifetime: Duration::new(session_lifetime),
            keys: Vec::new(),
        },
        verifier,
        SystemClock,
        SystemSecrets::open()?,
        SystemAllocator::open()?,
    );
    let listener = Listener::bind(listen, Limits::default())?;
    listener.serve(&mut deployment)?;
    Ok(())
}
