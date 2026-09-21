//! `mandate-control-plane`: the composition binary. `serve --listen <addr>` binds the login
//! road's listener over a deployment seeded, per process, from the documents `--connection`,
//! `--key`, `--client` and `--resource-server` name; seeding the folds from an event log is
//! the next milestone (ruling D4, `story:product-listener`).
//!
//! **What the four flags carry, and why there are four.** `--connection` and `--key`
//! configure the login route and the published key set. `--client` and `--resource-server`
//! carry the two records the *authorization* endpoint reads after the session — a registered
//! OAuth public client and a registered resource-server target. A process configured from
//! the first two alone serves `POST /v1/federation/login` and refuses
//! `GET /oauth/authorize`, which is the state `story:served-login-end-to-end` closed.
//!
//! **Every identity is printed.** A caller who cannot learn the connection, the client and
//! the target cannot call the three routes that select on them, so each is written to stdout
//! before the listener binds — readable whether or not the bind succeeds.
//!
//! **The documents are decided together, by the commands they are the inputs of.** Every
//! guard `RegisterFederationConnection` states is a guard about the connections already
//! held, so `--connection` documents are admitted one at a time against a fold of the ones
//! before ([`mandate_control_plane::adapters::ConnectionSeeding`]) and a set this process
//! cannot serve is refused before the socket — not seeded, printed as seeded, and then
//! denied at every login. The same holds one level down for a repeated `kid` across `--key`
//! documents and a repeated `connection_id` across `--connection` documents.
//!
//! **What is trusted, and what would stop it being trusted.** A seeded link's
//! `principal_id` is taken as written: this process records no `mandate.identity` principal,
//! so `LinkExternalPrincipal`'s own guard — the principal must be recorded, and recorded in
//! this connection's organization — has nothing to read and would refuse every first link.
//! Two documents placing one principal in two organizations *is* decidable and is refused;
//! one document placing it anywhere is not. A principal record in this process arrives with
//! the folds seeded from an event log (ruling D4, `story:declared-writers`), and that is
//! what would close it. There is deliberately no `--principal` flag.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mandate_control_plane::adapters::{
    ClientSeed, Configuration, ConfigurationRefused, ConnectionSeed, ConnectionSeeding, Deployment,
    ResourceServerSeed, SeedRefused, SystemAllocator, SystemSecrets, key_set, read_client_seed,
    read_connection_seed, read_key, read_resource_server_seed,
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
        /// A registered OAuth client to seed, as a JSON document. Repeatable.
        ///
        /// The seeded `client_id` is printed, because the authorization route selects on it.
        #[arg(long = "client", value_name = "PATH")]
        clients: Vec<PathBuf>,
        /// A registered resource server to seed, as a JSON document. Repeatable.
        ///
        /// The seeded `resource_server_id` is printed, because an authorization request
        /// names the target by it.
        #[arg(long = "resource-server", value_name = "PATH")]
        resource_servers: Vec<PathBuf>,
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
            clients,
            resource_servers,
        } => match serve(&Serving {
            listen,
            issuer,
            code_lifetime,
            session_lifetime,
            connections,
            keys,
            clients,
            resource_servers,
        }) {
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

/// What one `serve` invocation was asked to stand up.
///
/// The parameters are a value rather than eight positional arguments because four of them
/// are now `Vec<PathBuf>` and three are text, and a caller that transposed two of those
/// would compile.
struct Serving {
    listen: SocketAddr,
    issuer: String,
    code_lifetime: String,
    session_lifetime: String,
    connections: Vec<PathBuf>,
    keys: Vec<PathBuf>,
    clients: Vec<PathBuf>,
    resource_servers: Vec<PathBuf>,
}

fn serve(serving: &Serving) -> Result<(), Refused> {
    // Every document is read before a socket, a key or the host CSPRNG is touched: an
    // operator who mistyped a duration — or wrote a key nobody can publish — learns it from
    // the exit status, not from a client.
    let seeds = serving
        .connections
        .iter()
        .map(|path| Ok((path.clone(), read_connection_seed(path)?)))
        .collect::<Result<Vec<(PathBuf, ConnectionSeed)>, SeedRefused>>()
        .map_err(Refused::Seed)?;
    let client_seeds = serving
        .clients
        .iter()
        .map(|path| Ok((path.clone(), read_client_seed(path)?)))
        .collect::<Result<Vec<(PathBuf, ClientSeed)>, SeedRefused>>()
        .map_err(Refused::Seed)?;
    let target_seeds = serving
        .resource_servers
        .iter()
        .map(|path| Ok((path.clone(), read_resource_server_seed(path)?)))
        .collect::<Result<Vec<(PathBuf, ResourceServerSeed)>, SeedRefused>>()
        .map_err(Refused::Seed)?;
    // The path is carried beside the key, because a repeated `kid` is a refusal about two
    // **files** and `Jwks::new` knows neither of them.
    let published = key_set(
        serving
            .keys
            .iter()
            .map(|path| Ok((path.clone(), read_key(path)?)))
            .collect::<Result<Vec<_>, SeedRefused>>()
            .map_err(Refused::Seed)?,
    )
    .map_err(Refused::Seed)?;

    let configuration = Configuration {
        issuer: serving.issuer.clone(),
        code_lifetime: CodeLifetime::new(Duration::new(&serving.code_lifetime)),
        session_lifetime: Duration::new(&serving.session_lifetime),
        keys: published,
    }
    .checked()
    .map_err(Refused::Configuration)?;

    let allowed = AllowedAlgorithms::configured(&[
        SigningAlgorithm::new("ES256"),
        SigningAlgorithm::new("RS256"),
    ])
    .map_err(|error| Refused::Start(Box::new(error)))?;
    let secrets = SystemSecrets::open().map_err(|error| Refused::Start(Box::new(error)))?;
    let mut allocator = SystemAllocator::open().map_err(|error| Refused::Start(Box::new(error)))?;

    // The identities the documents state none for are minted from the same CSPRNG every
    // other identity this deployment mints comes from, before the allocator is handed over.
    //
    // Each document is decided against the ones before it, through
    // `mandate.federation.RegisterFederationConnection` itself: a connection this process
    // cannot serve is refused here rather than seeded and denied at every login.
    let mut seeding = ConnectionSeeding::new();
    let mut seeded = Vec::with_capacity(seeds.len());
    for (path, seed) in &seeds {
        let mut allocate = || allocator.next_uuid();
        let admitted = seeding
            .admit(path, seed, &mut allocate)
            .map_err(Refused::Seed)?;
        seeded.push((path, seed, admitted));
    }
    let mut seeded_clients = Vec::with_capacity(client_seeds.len());
    for (path, seed) in &client_seeds {
        let mut allocate = || allocator.next_uuid();
        seeded_clients.push((path, seed.events(&mut allocate)));
    }
    let mut seeded_targets = Vec::with_capacity(target_seeds.len());
    for (path, seed) in &target_seeds {
        let mut allocate = || allocator.next_uuid();
        seeded_targets.push((path, seed.events(&mut allocate)));
    }

    // The algorithm is per connection and the connection's identity is only known once it
    // has been allocated, so the verifier is configured here rather than at construction.
    // A connection whose document names no algorithm is left unconfigured deliberately:
    // `RealVerifier` has no default and refuses every proof through it
    // (`RefusalReason::ConnectionAlgorithmUnconfigured`), which is the closed answer.
    let mut verifier = RealVerifier::new(allowed, UreqJwks::new(), SystemClock);
    for (path, seed, connection) in &seeded {
        let Some(algorithm) = &seed.algorithm else {
            continue;
        };
        verifier = verifier
            .configure_connection(connection.connection_id, algorithm)
            .map_err(|error| SeedRefused::Algorithm {
                path: (*path).clone(),
                error,
            })
            .map_err(Refused::Seed)?;
    }

    let mut deployment = Deployment::new(configuration, verifier, SystemClock, secrets, allocator)
        .map_err(Refused::Configuration)?;
    for (path, _, connection) in seeded {
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
    for (path, client) in seeded_clients {
        for event in &client.events {
            deployment
                .record_federation(event)
                .map_err(|error| SeedRefused::Unseedable {
                    path: path.clone(),
                    error,
                })
                .map_err(Refused::Seed)?;
        }
        // The same reason the connection's id is printed: `GET /oauth/authorize` selects on
        // this one.
        println!(
            "mandate-control-plane: seeded oauth client {}",
            client.client_id
        );
    }
    for (path, target) in seeded_targets {
        for event in &target.events {
            deployment
                .record_credential(event)
                .map_err(|error| SeedRefused::UnseedableCredential {
                    path: path.clone(),
                    error,
                })
                .map_err(Refused::Seed)?;
        }
        // The same reason again: an authorization request names the target by this id.
        println!(
            "mandate-control-plane: seeded resource server {}",
            target.resource_server_id
        );
    }

    let listener = Listener::bind(serving.listen, Limits::default())
        .map_err(|error| Refused::Start(Box::new(error)))?;
    listener
        .serve(&mut deployment)
        .map_err(|error| Refused::Start(Box::new(error)))?;
    Ok(())
}
