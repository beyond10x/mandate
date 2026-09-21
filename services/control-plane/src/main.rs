//! `mandate-control-plane`: the composition binary. `serve --listen <addr>` binds the login
//! road's listener over a deployment whose folds start empty; seeding them from an event
//! log is the next milestone (ruling D4, `story:product-listener`).

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mandate_control_plane::adapters::{
    Configuration, ConfigurationRefused, Deployment, SystemAllocator, SystemSecrets,
};
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

/// Why the process did not serve, and which exit status says so.
///
/// The two are not the same failure and do not answer the same status: a configuration the
/// deployment cannot honour is the operator's to correct and exits **2**, and a listener that
/// could not bind or a host resource that could not be opened exits 1. A `--code-lifetime`
/// naming no span used to become a zero, and the process served logins while refusing every
/// authorization with nothing anywhere saying why.
enum Refused {
    Configuration(ConfigurationRefused),
    Start(Box<dyn std::error::Error>),
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
            Err(Refused::Configuration(refusal)) => {
                eprintln!("mandate-control-plane: {refusal}");
                ExitCode::from(2)
            }
            Err(Refused::Start(error)) => {
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
) -> Result<(), Refused> {
    // The configuration is decided before a socket, a key or the host CSPRNG is touched: an
    // operator who mistyped a duration learns it from the exit status, not from a client.
    let configuration = Configuration {
        issuer,
        code_lifetime: CodeLifetime::new(Duration::new(code_lifetime)),
        session_lifetime: Duration::new(session_lifetime),
        keys: Vec::new(),
    }
    .checked()
    .map_err(Refused::Configuration)?;

    let allowed = AllowedAlgorithms::configured(&[
        SigningAlgorithm::new("ES256"),
        SigningAlgorithm::new("RS256"),
    ])
    .map_err(|error| Refused::Start(Box::new(error)))?;
    let verifier = RealVerifier::new(allowed, UreqJwks::new(), SystemClock);
    let secrets = SystemSecrets::open().map_err(|error| Refused::Start(Box::new(error)))?;
    let allocator = SystemAllocator::open().map_err(|error| Refused::Start(Box::new(error)))?;
    let mut deployment = Deployment::new(configuration, verifier, SystemClock, secrets, allocator)
        .map_err(Refused::Configuration)?;
    let listener = Listener::bind(listen, Limits::default())
        .map_err(|error| Refused::Start(Box::new(error)))?;
    listener
        .serve(&mut deployment)
        .map_err(|error| Refused::Start(Box::new(error)))?;
    Ok(())
}
