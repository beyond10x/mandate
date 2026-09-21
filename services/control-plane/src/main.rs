//! `mandate-control-plane`: the composition binary. `serve --listen <addr>` binds the login
//! road's listener over a deployment seeded, per process, from the documents `--connection`
//! and `--key` name; seeding the folds from an event log is the next milestone (ruling D4,
//! `story:product-listener`).
//!
//! **What the two flags do not carry.** A registered OAuth public client and a registered
//! resource-server target — the two records the authorization endpoint reads after the
//! session — have no flag here. A process configured from these two documents alone serves
//! `POST /v1/federation/login` and refuses `GET /oauth/authorize`, and closing that is the
//! registration road's own story rather than this one's.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mandate_control_plane::adapters::{
    Configuration, ConfigurationRefused, ConnectionSeed, Deployment, SeedRefused, SystemAllocator,
    SystemSecrets, read_connection_seed, read_key,
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
        /// A federation connection to seed, as a JSON document. Repeatable.
        ///
        /// The seeded `connection_id` is printed, because the login route selects on it.
        #[arg(long = "connection", value_name = "PATH")]
        connections: Vec<PathBuf>,
        /// A public JWK the JWK Set document publishes, as a JSON document. Repeatable.
        #[arg(long = "key", value_name = "PATH")]
        keys: Vec<PathBuf>,
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
    /// A `--connection` or `--key` document that configures no deployment. The same **2** as
    /// [`Refused::Configuration`], and separate only because it names the file it read.
    Seed(SeedRefused),
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
            connections,
            keys,
        } => match serve(
            listen,
            issuer,
            &code_lifetime,
            &session_lifetime,
            &connections,
            &keys,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(Refused::Configuration(refusal)) => {
                eprintln!("mandate-control-plane: {refusal}");
                ExitCode::from(2)
            }
            Err(Refused::Seed(refusal)) => {
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
    connections: &[PathBuf],
    keys: &[PathBuf],
) -> Result<(), Refused> {
    // Every document is read before a socket, a key or the host CSPRNG is touched: an
    // operator who mistyped a duration — or wrote a key nobody can publish — learns it from
    // the exit status, not from a client.
    let seeds = connections
        .iter()
        .map(|path| Ok((path.clone(), read_connection_seed(path)?)))
        .collect::<Result<Vec<(PathBuf, ConnectionSeed)>, SeedRefused>>()
        .map_err(Refused::Seed)?;
    let published = keys
        .iter()
        .map(|path| read_key(path))
        .collect::<Result<Vec<_>, SeedRefused>>()
        .map_err(Refused::Seed)?;

    let configuration = Configuration {
        issuer,
        code_lifetime: CodeLifetime::new(Duration::new(code_lifetime)),
        session_lifetime: Duration::new(session_lifetime),
        keys: published,
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
    let mut allocator = SystemAllocator::open().map_err(|error| Refused::Start(Box::new(error)))?;

    // The identities the documents state none for are minted from the same CSPRNG every
    // other identity this deployment mints comes from, before the allocator is handed over.
    let mut seeded = Vec::with_capacity(seeds.len());
    for (path, seed) in &seeds {
        let mut allocate = || allocator.next_uuid();
        seeded.push((path, seed.events(&mut allocate)));
    }

    let mut deployment = Deployment::new(configuration, verifier, SystemClock, secrets, allocator)
        .map_err(Refused::Configuration)?;
    for (path, connection) in seeded {
        for event in &connection.events {
            deployment
                .record_federation(event)
                .map_err(|error| SeedRefused::Unseedable {
                    path: path.clone(),
                    error,
                })
                .map_err(Refused::Seed)?;
        }
        // An operator who cannot learn the id cannot call the login route, which selects on
        // it. Printed before the listener binds, so it is readable whether or not the bind
        // succeeds.
        println!(
            "mandate-control-plane: seeded federation connection {}",
            connection.connection_id
        );
    }

    let listener = Listener::bind(listen, Limits::default())
        .map_err(|error| Refused::Start(Box::new(error)))?;
    listener
        .serve(&mut deployment)
        .map_err(|error| Refused::Start(Box::new(error)))?;
    Ok(())
}
