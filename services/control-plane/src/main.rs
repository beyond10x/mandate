//! `mandate-control-plane`: the composition binary. `serve --listen <addr>` binds the login
//! road's listener over a deployment seeded, per process, from the documents `--connection`,
//! `--signing-key`, `--client` and `--resource-server` name; seeding the folds from an event log is
//! the next milestone (ruling D4, `story:product-listener`).
//!
//! **What the four flags carry, and why there are four.** `--connection` and `--signing-key`
//! configure the login route and the keys the deployment signs with and publishes. `--client` and `--resource-server`
//! carry the two records the *authorization* endpoint reads after the session — a registered
//! OAuth public client and a registered resource-server target. A process configured from
//! the first two alone serves `POST /v1/federation/login` and refuses
//! `GET /oauth/authorize`, which is the state `story:served-login-end-to-end` closed.
//!
//! **Every identity is printed.** A caller who cannot learn the connection, the client and
//! the target cannot call the three routes that select on them, so each is written to stdout
//! before the listener binds — readable whether or not the bind succeeds.
//!
//! **And so is the address.** `--listen` may name port `0`, which asks the kernel for
//! whichever port is free and leaves only the bound socket knowing which that was, so the
//! address is written to stdout once `Listener::bind` has succeeded and before anything is
//! served. A caller that instead had to *choose* a port bound one, read it and released it
//! before handing it over, and in the interval between that release and this process's bind
//! the port was free for anything on the machine to take — a window no code here could
//! close, because none of it runs during the window. There is nothing to choose now.
//!
//! **The documents are decided together, and all four flags are covered.** A set this
//! process cannot serve is refused before the socket — not seeded, printed as seeded, and
//! then denied at every request. Each flag goes through the reader that can decide it, and
//! each reader is named here so that a flag added later is visibly not covered rather than
//! silently uncovered, which is what `--client` and `--resource-server` were:
//!
//! | Flag | Admitted by | What is decided against the documents before it |
//! |---|---|---|
//! | `--connection` | [`mandate_control_plane::adapters::ConnectionSeeding`] | every guard of `RegisterFederationConnection`, plus a repeated `connection_id` and a principal linked across two organizations |
//! | `--signing-key` | [`mandate_control_plane::adapters::MountedKeys`], then `RegisterSigningKey` through [`mandate_control_plane::adapters::Deployment::mount_signing_keys`] | a repeated name, material that is not one admitted private key, and the same material under two names |
//! | `--client` | [`mandate_control_plane::adapters::ClientSeeding`] | a repeated `client_id` |
//! | `--resource-server` | [`mandate_control_plane::adapters::TargetSeeding`] | every guard of `RegisterResourceServer` — an ambiguous audience above all — plus a repeated `resource_server_id`, and then the whole set is settled against `Projection::audience_conflicts` |
//!
//! **Why two of them run the command and two do not.** A document is put through the
//! command it is the inputs of wherever that command's guards are about the *records*:
//! `RegisterFederationConnection` and `RegisterResourceServer` both are, so both run.
//! `RegisterOAuthClient`'s three guards are all about a **caller** — client-administration
//! authority, the organization binding, and an admitted redirect URI — behind a port whose
//! only implementation here is a fixture, and this seeding authenticates no caller, so
//! running it would mean inventing a registration policy to satisfy a guard about a caller
//! that does not exist. `ClientSeeding` decides what the documents alone decide, and its
//! header says what that leaves.
//!
//! **What is trusted, and what would stop it being trusted.** A seeded link's
//! `principal_id` is taken as written: this process records no `mandate.identity` principal
//! for it, so `LinkExternalPrincipal`'s own guard — the principal must be recorded, and recorded in
//! this connection's organization — has nothing to read and would refuse every first link.
//! Two documents placing one principal in two organizations *is* decidable and is refused;
//! one document placing it anywhere is not. A principal record in this process arrives with
//! the folds seeded from an event log (ruling D4, `story:declared-writers`), and that is
//! what would close it. There is deliberately no `--principal` flag.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mandate_control_plane::adapters::{
    ClientSeed, ClientSeeding, Configuration, ConfigurationRefused, ConnectionSeed,
    ConnectionSeeding, Deployment, MountedKeys, RelyingParty, ResourceServerSeed,
    SIGNED_TTL_SECONDS, SIGNING_OVERLAP_SECONDS, SeedRefused, SystemAllocator, SystemSecrets,
    TargetSeeding, configure_verifier, read_client_seed, read_connection_seed,
    read_resource_server_seed, read_signing_key, relying_party_connection,
};
use mandate_control_plane::serve::{Limits, Listener};
use mandate_federation::idp_token::UreqIdpToken;
use mandate_federation::record::FederationConnection;
use mandate_federation::verifier::{ClaimType, VerifiedProof};
use mandate_federation::verifier_real::{AllowedAlgorithms, RealVerifier, SystemClock, UreqJwks};
use mandate_federation::{Denied, FederationVerifier};
use mandate_sts::code::CodeLifetime;
use mandate_sts::keys::{RecordedSigner, SigningKeyAdministration};
use mandate_token::signing_real::{
    AllowedAlgorithms as SigningAlgorithms, SystemClock as SigningClock,
};
use mandate_types::CredentialProof;
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
        /// A private key the deployment signs with, mounted under a name. Repeatable.
        ///
        /// The value is `NAME=PATH`: `PATH` is one PEM private key — `PRIVATE KEY` (PKCS#8)
        /// for ES256 or RS256, or `RSA PRIVATE KEY` for RS256 — and `NAME` is the reference
        /// its `SigningKey` record resolves it through. Each is registered at startup, in the
        /// order given, and its record's identity — the `kid` it is published under — is
        /// printed.
        #[arg(long = "signing-key", value_name = "NAME=PATH", value_parser = named_path)]
        signing_keys: Vec<(String, PathBuf)>,
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
        /// A file holding an IdP client secret, named for the `--connection` documents whose
        /// `relying_party.client_secret` refers to it. Repeatable.
        ///
        /// The value is `NAME=PATH`: the flag carries where the secret is, never the secret.
        #[arg(long = "client-secret-file", value_name = "NAME=PATH", value_parser = named_path)]
        client_secret_files: Vec<(String, PathBuf)>,
        /// A directory of documents, read as if each were given to its flag. Repeatable.
        ///
        /// It holds `connections/`, `clients/` and `resource-servers/`, each of `*.json`
        /// documents; `client-secrets/`, each file of which is the client secret named for it;
        /// and `signing-keys/`, each file of which is the signing key named for it. They are read in file-name order and after the documents the flags
        /// name. Any other entry is refused, exit 2. A name starting with `..` is a mount's
        /// own bookkeeping and is skipped.
        #[arg(long = "config-dir", value_name = "DIR")]
        config_dirs: Vec<PathBuf>,
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
    /// A `--connection` or `--signing-key` file that configures no deployment. The same
    /// **2** as [`Refused::Configuration`], and separate only because it names the file it
    /// read.
    Seed(SeedRefused),
    /// A `--config-dir` that cannot be read as documents. The same **2**.
    ConfigDir(String),
    /// Two `--client-secret-file` flags give one name. The same **2**.
    RepeatedSecretName(String),
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
            signing_keys,
            clients,
            resource_servers,
            client_secret_files,
            config_dirs,
        } => match serve(&Serving {
            listen,
            issuer,
            code_lifetime,
            session_lifetime,
            connections,
            signing_keys,
            clients,
            resource_servers,
            client_secret_files,
            config_dirs,
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
            Err(Refused::ConfigDir(refusal)) => {
                eprintln!("mandate-control-plane: {refusal}");
                ExitCode::from(2)
            }
            Err(Refused::RepeatedSecretName(name)) => {
                eprintln!(
                    "mandate-control-plane: the client secret name `{name}` is given by more \
                     than one --client-secret-file"
                );
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
    signing_keys: Vec<(String, PathBuf)>,
    clients: Vec<PathBuf>,
    resource_servers: Vec<PathBuf>,
    client_secret_files: Vec<(String, PathBuf)>,
    config_dirs: Vec<PathBuf>,
}

fn serve(given: &Serving) -> Result<(), Refused> {
    // The directories are read first and appended to what the flags named, so the rest of this
    // function is the one path every document takes, whichever way it arrived.
    let serving = &with_config_dirs(given)?;
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
    // Each key file is read now, as every document is: a file that is not one private key
    // this deployment signs with, and a name given twice, are refused before the socket.
    let mounted = MountedKeys::new(
        serving
            .signing_keys
            .iter()
            .map(|(name, path)| read_signing_key(name, path))
            .collect::<Result<Vec<_>, SeedRefused>>()
            .map_err(Refused::Seed)?,
    )
    .map_err(Refused::Seed)?;

    let configuration = Configuration {
        issuer: serving.issuer.clone(),
        code_lifetime: CodeLifetime::new(Duration::new(&serving.code_lifetime)),
        session_lifetime: Duration::new(&serving.session_lifetime),
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
    // The other two flags, on the same terms. Each document is decided against the ones
    // before it — `--client` against the clients already seeded, `--resource-server`
    // through `mandate.credential.RegisterResourceServer` itself — and the whole
    // `--resource-server` set is then settled, because the command's audience guard is a
    // read-then-write one and cannot answer for a pair the fold already held.
    let mut client_seeding = ClientSeeding::new();
    let mut seeded_clients = Vec::with_capacity(client_seeds.len());
    for (path, seed) in &client_seeds {
        let mut allocate = || allocator.next_uuid();
        let admitted = client_seeding
            .admit(path, seed, &mut allocate)
            .map_err(Refused::Seed)?;
        seeded_clients.push((path, admitted));
    }
    let mut target_seeding = TargetSeeding::new();
    let mut seeded_targets = Vec::with_capacity(target_seeds.len());
    for (path, seed) in &target_seeds {
        let mut allocate = || allocator.next_uuid();
        let admitted = target_seeding
            .admit(path, seed, &mut allocate)
            .map_err(Refused::Seed)?;
        seeded_targets.push((path, admitted));
    }
    target_seeding.settled().map_err(Refused::Seed)?;

    // The algorithm and the hosts this connection's key set may be fetched from are per
    // connection, and the connection's identity is only known once it has been allocated,
    // so the verifier is configured here rather than at construction.
    // `adapters::configure_verifier` is that step, and it is over there because a binary's
    // `main` is reachable from no case.
    let mut verifier = RealVerifier::new(allowed, UreqJwks::new(), SystemClock);
    for (path, seed, connection) in &seeded {
        verifier = configure_verifier(verifier, path, seed, connection.connection_id)
            .map_err(Refused::Seed)?;
    }

    // The relying party: every connection whose document names one, with its client secret
    // read now from the file its reference names, before a socket is bound. A reference no
    // flag resolves, and a name two flags give, are the operator's to correct.
    let mut secret_files = BTreeMap::new();
    for (name, path) in &serving.client_secret_files {
        if secret_files.insert(name.clone(), path.clone()).is_some() {
            return Err(Refused::RepeatedSecretName(name.clone()));
        }
    }
    let mut relying_party = RelyingParty::new(Box::new(UreqIdpToken::new()));
    let mut relies = false;
    for (path, seed, connection) in &seeded {
        if let Some(configured) =
            relying_party_connection(path, seed, &secret_files).map_err(Refused::Seed)?
        {
            relying_party = relying_party.with_connection(connection.connection_id, configured);
            relies = true;
        }
    }

    let mut deployment = Deployment::new(
        configuration,
        RecordingVerifier(verifier),
        SystemClock,
        secrets,
        allocator,
    )
    .map_err(Refused::Configuration)?;
    if relies {
        deployment = deployment.with_relying_party(relying_party);
    }
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

    // The signing keys, registered through `mandate.credential.RegisterSigningKey` in the
    // order given, with the signer following the records after each. The identity printed
    // is the `kid` the key signs and is published under.
    let signing_allowed = SigningAlgorithms::new(&[
        SigningAlgorithm::new("ES256"),
        SigningAlgorithm::new("RS256"),
    ])
    .map_err(|error| Refused::Start(Box::new(error)))?;
    let signer = RecordedSigner::new(
        signing_allowed.clone(),
        SigningClock,
        SIGNED_TTL_SECONDS,
        SIGNING_OVERLAP_SECONDS,
    )
    .map_err(|error| Refused::Start(Box::new(error)))?;
    let registered = deployment
        .mount_signing_keys(
            &SigningKeyAdministration::new(signing_allowed),
            signer,
            mounted,
        )
        .map_err(Refused::Seed)?;
    for (name, id) in registered {
        println!("mandate-control-plane: registered signing key {id} from `{name}`");
    }

    let listener = Listener::bind(serving.listen, Limits::default())
        .map_err(|error| Refused::Start(Box::new(error)))?;
    // The address the socket **has**, which is not always the one `--listen` named: port 0
    // is a request for whichever port the kernel has free, and only the bound socket knows
    // which that was. Printed after the bind and before a byte is served, so a caller learns
    // it from a process that already holds it.
    //
    // **This is what closes the window.** A caller that needed a port had to bind one
    // itself, read it, release it and pass it here — and between the release and this bind
    // the port belonged to nobody, so any process on the machine could take it. Nothing
    // this process does could shorten that window, because the window is outside it. Saying
    // which port was bound removes the need to choose one.
    let bound = listener
        .local_addr()
        .map_err(|error| Refused::Start(Box::new(error)))?;
    println!("mandate-control-plane: listening on {bound}");
    listener
        .serve(&mut deployment)
        .map_err(|error| Refused::Start(Box::new(error)))?;
    Ok(())
}

/// A `--signing-key` or `--client-secret-file` value: `NAME=PATH`, both halves present.
fn named_path(value: &str) -> Result<(String, PathBuf), String> {
    match value.split_once('=') {
        Some((name, path)) if !name.is_empty() && !path.is_empty() => {
            Ok((name.to_owned(), PathBuf::from(path)))
        }
        _ => Err("expected NAME=PATH".to_owned()),
    }
}

/// The real verifier, recording **the reason it refused for** on stderr.
///
/// # Why the clause the listener records is not enough
///
/// `mandate_federation::DenialClause::ProofInvalid` is one clause over twenty
/// `RefusalReason`s: a malformed token, a `typ` that is not a JWT, an unread `crit`, an
/// absent or unknown `kid`, a key set that could not be read, a malformed key, a key whose
/// algorithm is not the configured one, an invalid signature, malformed claims, an absent,
/// past or too-distant expiry, a proof not yet valid, an unverifiable sender constraint,
/// and an absent or over-long subject (`crates/mandate-federation/src/verifier_real.rs`,
/// `refused`). Collapsing them is right on the wire and right in the contract — they are
/// one declared denial — but it leaves an operator unable to tell "your IdP rotated a key
/// and we cannot see the new one" from "somebody is presenting forged proofs", which are
/// the same clause and opposite incidents.
///
/// `RealVerifier` already keeps the reasons, bounded, for exactly this
/// (`RealVerifier::refusals`, whose own documentation records that the material a refusal
/// was about "is not here and never was"). This reads the newest one after a refusal and
/// writes its name beside the clause.
///
/// # Why reading the last entry is sound
///
/// `Listener::serve` is a sequential accept loop — one connection accepted, answered and
/// closed before the next, over `&mut Deployment` — so no second request can have refused
/// between this call and this read. If that listener ever serves connections concurrently,
/// this reads the wrong request's reason and must be replaced by one the verifier returns
/// directly.
///
/// **The refusal path only.** A verification that succeeds is not touched, and nothing here
/// runs for an accepted login.
struct RecordingVerifier(RealVerifier<UreqJwks, SystemClock>);

impl FederationVerifier for RecordingVerifier {
    fn verify(
        &self,
        connection: &FederationConnection,
        proof: &CredentialProof,
    ) -> Result<VerifiedProof, Denied> {
        let verified = self.0.verify(connection, proof);
        if verified.is_err()
            && let Some(reason) = self.0.refusals().last()
        {
            eprintln!("mandate-control-plane: verification refused {reason:?}");
        }
        verified
    }

    fn tenant_claim_refused(&self, kind: ClaimType) {
        self.0.tenant_claim_refused(kind);
        eprintln!("mandate-control-plane: tenant resolution refused TenantClaimNotText({kind:?})");
    }
}

/// The `--config-dir` subdirectories that hold `*.json` documents, and the flag each stands
/// for. A directory of documents is the flags written as a layout, so each name is the flag's.
const DOCUMENT_DIRECTORIES: [&str; 3] = ["connections", "clients", "resource-servers"];

/// The directory of client secrets: each file is one, and its name is the `NAME` of
/// `--client-secret-file NAME=PATH`.
const SECRET_DIRECTORY: &str = "client-secrets";

/// The directory of signing keys: each file is one PEM private key, and its name is the
/// `NAME` of `--signing-key NAME=PATH`.
const SIGNING_KEY_DIRECTORY: &str = "signing-keys";

/// What the flags named, followed by what every `--config-dir` holds.
fn with_config_dirs(given: &Serving) -> Result<Serving, Refused> {
    let mut serving = Serving {
        listen: given.listen,
        issuer: given.issuer.clone(),
        code_lifetime: given.code_lifetime.clone(),
        session_lifetime: given.session_lifetime.clone(),
        connections: given.connections.clone(),
        signing_keys: given.signing_keys.clone(),
        clients: given.clients.clone(),
        resource_servers: given.resource_servers.clone(),
        client_secret_files: given.client_secret_files.clone(),
        config_dirs: Vec::new(),
    };
    for directory in &given.config_dirs {
        let top = entries(directory)?;
        for (name, path) in &top {
            let known = DOCUMENT_DIRECTORIES.contains(&name.as_str())
                || name == SECRET_DIRECTORY
                || name == SIGNING_KEY_DIRECTORY;
            if !known || !path.is_dir() {
                return Err(unknown(path, "is not one of the document directories"));
            }
        }
        for (name, path) in top {
            if name == SECRET_DIRECTORY || name == SIGNING_KEY_DIRECTORY {
                let named = if name == SECRET_DIRECTORY {
                    &mut serving.client_secret_files
                } else {
                    &mut serving.signing_keys
                };
                for (entry, file) in entries(&path)? {
                    if !file.is_file() {
                        return Err(unknown(&file, "is not a file"));
                    }
                    named.push((entry, file));
                }
                continue;
            }
            let target = match name.as_str() {
                "connections" => &mut serving.connections,
                "clients" => &mut serving.clients,
                _ => &mut serving.resource_servers,
            };
            for (document, file) in entries(&path)? {
                if !file.is_file() || !document.ends_with(".json") {
                    return Err(unknown(&file, "is not a `*.json` document"));
                }
                target.push(file);
            }
        }
    }
    Ok(serving)
}

/// The entries of a directory in file-name order, without a mount's `..` bookkeeping.
fn entries(directory: &std::path::Path) -> Result<Vec<(String, PathBuf)>, Refused> {
    let unreadable = |error: std::io::Error| {
        Refused::ConfigDir(format!(
            "the --config-dir `{}` cannot be read: {error}",
            directory.display()
        ))
    };
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(unknown(&entry.path(), "has a name that is not text"));
        };
        if !name.starts_with("..") {
            found.push((name, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

fn unknown(path: &std::path::Path, why: &str) -> Refused {
    Refused::ConfigDir(format!("the --config-dir entry `{}` {why}", path.display()))
}
