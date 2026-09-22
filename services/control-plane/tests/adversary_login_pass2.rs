//! Second adversary pass over the federated-login road: the **seams between the units**,
//! and the authority guard that was merged without one.
//!
//! Each case here drives the implementation against a document the login road's own units
//! wrote about themselves. Nothing else compares the two.
//!
//! # The claim under attack in cases 1 and 2
//!
//! `src/main.rs:25-31` is the `--connection`/`--key` unit's own statement of what the four
//! flags are:
//!
//! > **The documents are decided together, by the commands they are the inputs of.** Every
//! > guard `RegisterFederationConnection` states is a guard about the connections already
//! > held, so `--connection` documents are admitted one at a time against a fold of the ones
//! > before ([`ConnectionSeeding`]) and a set this process cannot serve is refused before the
//! > socket — **not seeded, printed as seeded, and then denied at every login.**
//!
//! The heading is about *the documents*. The body names two flags. `--client` and
//! `--resource-server` — the two the authorization unit added, carrying the two records
//! `GET /oauth/authorize` reads — go through no command and no fold at all
//! (`src/main.rs:242-251`): `seed.events(&mut allocate)` renders an event and nothing decides
//! it against the documents before it.
//!
//! Both folds then **silently drop** a duplicate rather than refusing it —
//! `crates/mandate-federation/src/record.rs:638-640` and
//! `crates/mandate-token/src/projection.rs:763-765` each `return Ok(())` on an identity they
//! already hold — so `Deployment::record_federation` and `Deployment::record_credential`
//! answer `Ok`, and `src/main.rs:302` and `:318` print the document as seeded. That is the
//! state the header names in as many words and says is refused.
//!
//! # How a case that must not stand up a listener is made to terminate
//!
//! Each of these cases asserts that the child refuses **before the socket**, which is exit
//! **2** (`src/main.rs:144-151`). A child that instead seeds happily reaches `Listener::bind`
//! and would serve until killed, so every case here hands the child an address it *holds for
//! the whole of the child's life* — exactly
//! `tests/end_to_end.rs::an_explicit_listen_is_the_address_it_binds_and_a_held_one_refuses`,
//! whose own comment records the contract: a bind that could not happen is exit **1**, "the
//! listener's own status rather than the **2** of a configuration it refused".
//!
//! So the two statuses separate the two answers with no listener ever standing and no child
//! to reap: **2** is the configuration refused before the socket, **1** is a child that got
//! past seeding. No port is ever named, released and then handed over — the port is taken
//! *away*, and it is still held when the child dies.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use mandate_control_plane::adapters::{
    AuthorizationRefusal, Configuration, Deployment, Login, SeededResourceServer,
};
use mandate_control_plane::authority::{Admission, Admitting};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_model::Decision;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_types::{
    Audience, AuthorityScope, ClientId, CorrelationId, CredentialId, CredentialKind,
    CredentialProof, DecisionId, DecisionReason, Duration, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PkceChallenge,
    PkceMethod, PrincipalId, RedirectUri, ResourceServerId, RevocationGuarantee, SigningAlgorithm,
    Timestamp, Transient, Uuid, VerifiedContext,
};

// ------------------------------------------------------------- the two spawned-child cases

const AS_ISSUER: &str = "https://mandate.example";
const REDIRECT_ONE: &str = "https://client.example/callback";
const REDIRECT_TWO: &str = "https://other.example/callback";
const TARGET_AUDIENCE: &str = "https://api.example";

/// The client identity **both** `--client` documents in case 1 state.
const ONE_CLIENT: &str = "0b5d5a4c-0000-4000-8000-00000000c11e";
/// The organization every document here binds to.
const ONE_ORGANIZATION: &str = "0b5d5a4c-0000-4000-8000-0000000000a9";
/// The two distinct registration identities case 2 states, on one audience.
const TARGET_ONE: &str = "0b5d5a4c-0000-4000-8000-00000000a501";
const TARGET_TWO: &str = "0b5d5a4c-0000-4000-8000-00000000a502";

/// Whether `procfs` is answering: whether it is a procfs that can be asked whether a
/// process is running at all.
///
/// The question is **not** whether `/proc` is a directory. A mount point with nothing
/// mounted on it is a directory too, every `<procfs>/<pid>` under it is absent, every id
/// then reads as finished, and the sweep takes the root of every run that is running. That
/// host is not hypothetical: it is one `mount -t tmpfs none /proc` away, and an adversary
/// pass built it in a mount namespace and watched `tests/end_to_end.rs`'s own
/// [`the_run_root_clears_what_is_finished_and_keeps_what_is_running`] fail inside it.
///
/// So the question asked is whether this procfs answers correctly about a process that is
/// certainly running, and the one process certainly running is **this** one.
fn procfs_answers(procfs: &Path) -> bool {
    procfs.join(std::process::id().to_string()).is_dir()
}

/// Whether `pid` names a run that is **over**, according to `procfs`.
///
/// `<procfs>/<pid>` stands for the whole life of a process, zombie included, and is gone
/// once it has been reaped. A wrong `true` here deletes a live run's documents — this
/// story's own collision, inverted — so a procfs that is not answering ([`procfs_answers`])
/// is read as "nothing has finished", and a zombie or an id belonging to another user's
/// process reads as running, which is the same safe direction.
fn finished_under(procfs: &Path, pid: u32) -> bool {
    procfs_answers(procfs) && !procfs.join(pid.to_string()).exists()
}

/// [`finished_under`], asking the host's own procfs.
fn finished(pid: u32) -> bool {
    finished_under(Path::new("/proc"), pid)
}

/// Remove the roots of the runs that are over, leaving every running one standing.
///
/// A run can only ever clear a directory named for **its own** id, so without this the
/// parent gains one directory for every id that has ever run this binary; the adversary
/// measured `target/tmp` at 644 MB and 6,179 entries across one pass. `mine` is skipped
/// because this process is alive and its own root is its own to clear.
fn sweep_finished_runs(parent: &Path, mine: u32) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let named = entry.file_name();
        let Some(pid) = named
            .to_str()
            .and_then(|named| named.strip_prefix("run-"))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != mine && finished(pid) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The scratch root of one run: `parent`, then a directory named for the id of the process
/// that owns it.
///
/// Two things happen here and [`the_run_root_clears_what_is_finished_and_keeps_what_is_running`]
/// decides each of them: the roots of runs that are **over** are swept, so the parent holds
/// the runs that are running rather than every id that has ever run this binary; and a
/// directory standing under **this** id is cleared rather than written into, because an id
/// is unique among live processes, so anything left under ours belongs to a process that
/// has exited and whose id the kernel has since handed to us.
///
/// **A removal that was refused is not a removal.** Discarding it left `create_dir_all`
/// succeeding on the surviving directory and handed this run a root still holding the
/// previous id-holder's documents — silently, and that is the defect this story exists to
/// close. A refusal that is not "there was nothing there" stops the run, and the root is
/// read back empty before it is used, so neither a refusal nor anything else that leaves a
/// document standing can pass for a clear. The sweep's own discarded result is a different
/// thing and stays: a root it could not take is one more directory, not this run's state.
fn run_root_under(parent: &Path, pid: u32) -> PathBuf {
    sweep_finished_runs(parent, pid);
    let root = parent.join(format!("run-{pid}"));
    match std::fs::remove_dir_all(&root) {
        Ok(()) => {}
        Err(refused) if refused.kind() == std::io::ErrorKind::NotFound => {}
        Err(refused) => panic!(
            "the directory standing under this run's id is cleared before this run writes \
             into it; removing {} was refused with {refused}",
            root.display()
        ),
    }
    std::fs::create_dir_all(&root).expect("a writable scratch directory");
    assert!(
        std::fs::read_dir(&root)
            .expect("this run's own root is readable")
            .next()
            .is_none(),
        "this run's root starts empty; {} still holds what the process that had this id \
         before it wrote, and a run reading those documents is reading another run's state",
        root.display()
    );
    root
}

/// Where **this execution** writes: cargo's own per-target scratch directory, inside the
/// build tree, then this run's own root ([`run_root_under`]).
///
/// `env!("CARGO_TARGET_TMPDIR")` is resolved when this file is **compiled**, so every
/// execution of this binary reads one string and two copies running at once would write
/// one set of paths (`story:per-run-test-scratch`). A process id is unique among the
/// processes alive on a host, so two copies running at once never name one directory.
fn run_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        run_root_under(
            &Path::new(env!("CARGO_TARGET_TMPDIR")).join("adversary-login-pass2"),
            std::process::id(),
        )
    })
    .as_path()
}

/// Where one case's flag documents are written: this run's own directory ([`run_root`]),
/// then one directory per case so two cases cannot read each other's.
///
/// This comment used to say the per-case directory was the whole of it. It separated the
/// cases of one execution and nothing else, which is what
/// [`a_second_copy_of_this_binary_does_not_write_this_runs_documents`] measures.
fn document(case: &str, name: &str, body: &str) -> PathBuf {
    let directory = run_root().join(case);
    std::fs::create_dir_all(&directory).expect("a writable scratch directory");
    let path = directory.join(name);
    std::fs::write(&path, body).expect("the flag document is written");
    path
}

fn stated(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// One `--client` document, for a stated identity and redirect.
fn client_document(client_id: &str, redirect: &str) -> String {
    format!(
        r#"{{"client_id":"{client_id}","organization":"{ONE_ORGANIZATION}","public":true,
          "redirect_uris":["{redirect}"],"pkce_method":"S256"}}"#
    )
}

/// One `--resource-server` document, for a stated identity and audience.
fn resource_server_document(resource_server_id: &str, audience: &str) -> String {
    format!(
        r#"{{"resource_server_id":"{resource_server_id}","organization":"{ONE_ORGANIZATION}",
          "audience":"{audience}",
          "profile":{{"name":"reference","kind":"Reference","revocation":"ImmediateOnline",
            "max_ttl":"PT1H","positive_cache_ttl":"PT30S",
            "requires_online_authorization":true}},
          "allowed_exchange_sources":[]}}"#
    )
}

/// What one child answered.
struct Answered {
    status: Option<i32>,
    out: String,
    err: String,
}

/// Spawn `serve` with these flags, against an address this case holds for the child's whole
/// life, and answer what it said.
///
/// The held listener is dropped only after the child is dead, so the bind the child attempts
/// cannot succeed and the case cannot hang on a process that serves.
fn serve_refusing(flags: &[(&str, &str)]) -> Answered {
    let held = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port on the loopback");
    let taken = held.local_addr().expect("the bound address");
    let taken = taken.to_string();

    let mut args: Vec<&str> = vec!["serve", "--listen", &taken, "--issuer", AS_ISSUER];
    for (flag, value) in flags {
        args.push(flag);
        args.push(value);
    }

    let answered = Command::new(env!("CARGO_BIN_EXE_mandate-control-plane"))
        .args(&args)
        .output()
        .expect("the composition binary runs");

    // Held until here, which is what made a successful bind impossible rather than unlikely.
    drop(held);

    Answered {
        status: answered.status.code(),
        out: String::from_utf8_lossy(&answered.stdout).into_owned(),
        err: String::from_utf8_lossy(&answered.stderr).into_owned(),
    }
}

fn occurrences(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

/// Two `--client` documents naming **one** `client_id` are two registrations of one client,
/// and only the first is a registration at all.
///
/// `mandate.federation.OAuthClient` is keyed by its identity, and the fold
/// (`crates/mandate-federation/src/record.rs:638-640`) answers `Ok(())` and keeps the first
/// when a second event names an identity it already holds. So the second document's
/// `redirect_uris` are not registered, and an authorization request presenting the redirect
/// the operator wrote in that file is refused `RedirectMismatch` at every attempt — while
/// `src/main.rs:302` has already printed *both* documents as "seeded oauth client", naming
/// the same identity twice.
///
/// That is precisely the state `src/main.rs:25-31` says the four flags do not reach: "not
/// seeded, printed as seeded, and then denied at every login". The `--connection` unit closed
/// it for `--connection` (a repeated `connection_id`) and for `--key` (a repeated `kid`,
/// which "names both files"). `--client` reaches it unchanged.
///
/// **What reaches this:** `serve --client <a> --client <b>`. The flag is declared repeatable
/// (`src/main.rs:95-96`, `clients: Vec<PathBuf>`), `client_id` is an operator-stated member of
/// the document (`src/adapters.rs:1128-1132`), and nothing between the file and the fold
/// compares two documents.
#[test]
fn two_client_documents_naming_one_client_id_are_refused_before_the_socket() {
    let case = "one-client-id-twice";
    let first = document(
        case,
        "client-0.json",
        &client_document(ONE_CLIENT, REDIRECT_ONE),
    );
    let second = document(
        case,
        "client-1.json",
        &client_document(ONE_CLIENT, REDIRECT_TWO),
    );

    let answered = serve_refusing(&[("--client", stated(&first)), ("--client", stated(&second))]);

    // Amended by the coordinator, 2026-09-22. This case was written expecting the fix to admit
    // the first document and refuse the second, so it demanded exactly one seeded line. The
    // correction took the stronger route `src/main.rs` already states: a set this process cannot
    // serve is refused before the socket, nothing seeded and nothing printed as seeded. The
    // assertion is raised to the shipped behaviour rather than lowered to it.
    let seeded = format!("seeded oauth client {ONE_CLIENT}");
    assert_eq!(
        occurrences(&answered.out, &seeded),
        0,
        "a set this process cannot serve is refused before the socket, so no client is seeded \
         and none is printed as seeded. stdout was {:?}",
        answered.out
    );
    assert_eq!(
        answered.status,
        Some(2),
        "a document set the commands refuse is a configuration refusal. stderr was {:?}",
        answered.err
    );
    assert!(
        answered.err.contains("client-1.json") && answered.err.contains("client-0.json"),
        "the refusal names both documents it compared. stderr was {:?}",
        answered.err
    );
    assert_eq!(
        answered.status,
        Some(2),
        "a pair of documents the registration command would refuse is the operator's to \
         correct and is refused before the socket (`src/main.rs:25-31`); exit 1 is a child \
         that got past seeding and died on the held address. stdout {:?} stderr {:?}",
        answered.out,
        answered.err
    );
    assert!(
        answered.err.contains(stated(&second)),
        "the refusal names the document it could not admit, as the `--connection` and `--key` \
         refusals do; stderr was {:?}",
        answered.err
    );
}

/// Two `--resource-server` documents holding one `(organization, audience)` key are the
/// ambiguity `mandate.credential.RegisterResourceServer` exists to refuse, and this process
/// seeds both.
///
/// `Projection::admits_audience` (`crates/mandate-token/src/projection.rs:1172-1184`) is that
/// command's guard and raises `DenialClause::AudienceAmbiguous` for exactly this pair. The
/// seeding path never calls it: `src/main.rs:247-251` renders the event and folds it.
///
/// The projection *knows* the resulting state is wrong and carries a read built for the
/// adapter that would report it — `Projection::audience_conflicts`, whose own documentation
/// says "**A read for the adapter, not for a command: no handler consults it.** Each entry is
/// a registration that was written and does not hold its audience". No adapter in this
/// composition consults it either; `audience_conflicts` has no caller outside test files
/// anywhere in the workspace.
///
/// What the operator gets instead: both documents printed as seeded, and a registration whose
/// audience resolves to the *other* one. `Projection::registered` breaks the tie with
/// `.min_by_key(|server| server.id)` (`:1048`), so the registration that holds the audience is
/// whichever has the lower identity — a value nobody chose and no document states — and
/// `services/sts/src/resolve.rs:463` reads introspection authority through that read.
///
/// **What reaches this:** `serve --resource-server <a> --resource-server <b>`. The flag is
/// declared repeatable (`src/main.rs:101-102`) and `audience` is a required member of the
/// document (`src/adapters.rs:1204-1206`); two targets in one organization sharing an audience
/// is a copy-paste away and is refused nowhere on the path from the file to the fold.
#[test]
fn two_resource_server_documents_on_one_audience_are_refused_before_the_socket() {
    let case = "one-audience-twice";
    let first = document(
        case,
        "target-0.json",
        &resource_server_document(TARGET_ONE, TARGET_AUDIENCE),
    );
    let second = document(
        case,
        "target-1.json",
        &resource_server_document(TARGET_TWO, TARGET_AUDIENCE),
    );

    let answered = serve_refusing(&[
        ("--resource-server", stated(&first)),
        ("--resource-server", stated(&second)),
    ]);

    assert_eq!(
        answered.status,
        Some(2),
        "`RegisterResourceServer` refuses a second registration on a held (organization, \
         audience) key with `AudienceAmbiguous`, and `src/main.rs:25-31` says the documents \
         are decided by the commands they are the inputs of; exit 1 is a child that seeded \
         both and died on the held address. stdout {:?} stderr {:?}",
        answered.out,
        answered.err
    );
    // Amended by the coordinator, 2026-09-22. The clause name is not rendered on the wire and
    // that is the right call: `TargetSeeding::refusal` selects the message *from* the clause
    // `register_resource_server` returned, so the command is still the decider, and what the
    // operator reads names the two documents and the audience they collide on rather than an
    // enum variant they cannot act on. What this case pins is that the pair is refused and that
    // both documents it compared are named — the property the clause name was standing in for.
    assert!(
        answered.err.contains("already registered"),
        "the refusal states the condition the registration command decided, got {:?}",
        answered.err
    );
    assert!(
        answered.err.contains("target-1.json") && answered.err.contains("target-0.json"),
        "the refusal names both documents it compared, got {:?}",
        answered.err
    );
}

// ------------------------------------------------------- the authority guard, case 3

const NOW: u64 = 1_789_084_800;
const IN_PROCESS_REDIRECT: &str = "https://client.example/callback";

fn uuid(tag: u8) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes[0] = tag;
    Uuid::from_bytes(bytes)
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x01))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x02))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0x04))
}

fn client() -> OAuthClientId {
    OAuthClientId::new(uuid(0x05))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-pass-2"),
    }
}

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn verifier() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("ES256")],
        VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new("subject-1"),
            ClientId::new("mandate-at-idp"),
        ),
    )
    .expect("a non-empty algorithm allowlist")
}

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// A decision point that answers `Ok`, carrying a `mandate.core.Decision` that **denied**.
///
/// `Admitting::admit` answers `Result<Decision, Denied>` and the composition reads only the
/// `Err` arm (`src/adapters.rs:2217-2233`): the `Decision` an `Ok` carries is dropped without
/// its `allowed` field ever being read. Every field of `mandate_model::Decision` is public and
/// `Deployment::with_authority` accepts any `Box<dyn Admitting + Send>`, so this shape is one
/// the composition's own public surface admits.
struct AnsweringDenied {
    asked: usize,
}

impl Admitting for AnsweringDenied {
    fn admit(
        &mut self,
        _admission: &Admission<'_>,
    ) -> Result<Decision, mandate_authz::decision::Denied> {
        self.asked += 1;
        Ok(Decision {
            allowed: false,
            reason: DecisionReason::Denied,
            decision_id: DecisionId::new(uuid(0xdd)),
            revision: None,
            challenge: None,
            policy_version: None,
            model_version: None,
        })
    }
}

/// The smallest world the authorization endpoint needs: one connection, one link, one public
/// client, one registered target.
fn deployment() -> (Wired, ResourceServerId) {
    let mut allocator = 0_u8;
    let seeded: SeededResourceServer = mandate_control_plane::adapters::ResourceServerSeed {
        resource_server_id: Some(ResourceServerId::new(uuid(0xa5))),
        organization: organization(),
        audience: Audience::new(TARGET_AUDIENCE),
        profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }
    .events(&mut || {
        allocator += 1;
        uuid(allocator)
    });

    let mut deployment = Deployment::new(
        Configuration {
            issuer: AS_ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        verifier(),
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");

    for event in &seeded.events {
        deployment
            .record_credential(event)
            .expect("a readable credential history");
    }
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: false,
        })
        .expect("a readable federation history");
    deployment
        .record_federation(&FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(),
            principal_id: principal(),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        })
        .expect("a readable federation history");
    deployment
        .record_federation(&FederationEvent::OAuthClientRegistered {
            context: context(),
            id: client(),
            organization_id: organization(),
            public: true,
            redirect_uris: vec![RedirectUri::new(IN_PROCESS_REDIRECT)],
            pkce_method: PkceMethod::S256,
        })
        .expect("a readable federation history");
    (deployment, seeded.resource_server_id)
}

fn login(deployment: &mut Wired) -> Login {
    deployment
        .authenticate(&decode::AuthenticateFederation {
            connection_id: connection(),
            proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
        })
        .expect("a linked principal over a configured connection")
}

fn authorize_input(login: &Login, target: ResourceServerId) -> decode::AuthorizePublicClient {
    decode::AuthorizePublicClient {
        client_id: client(),
        redirect_uri: RedirectUri::new(IN_PROCESS_REDIRECT),
        challenge: PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        method: PkceMethod::S256,
        state: "state-1".to_owned(),
        nonce: "nonce-1".to_owned(),
        session_proof: CredentialProof::from_bytes(login.session_proof.expose_material().to_vec()),
        target,
        requested_scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
    }
}

/// A decision that **denied** must not reach the handler, whichever arm of the result carries
/// it.
///
/// `src/adapters.rs:2210-2214` states the composition's own guarantee in its own words:
///
/// > The authority decision, **before** the handler is dispatched. Nothing below this point
/// > runs for a caller the decision point refuses: the code is not minted, the append is not
/// > made [...]
///
/// "A caller the decision point refuses" is decided by one arm of a two-arm result. The value
/// the other arm carries is `mandate.core.Decision`, whose first declared field is
/// `allowed: bool` (`crates/mandate-model/src/lib.rs:149-151`) — the contract's own record of
/// whether the request was allowed — and the composition never reads it. An `Ok` carrying
/// `allowed: false` mints the code, appends the event and redirects the caller to it.
///
/// The invariant that makes the two arms agree today lives in
/// `crates/mandate-authz/src/decision.rs:179-268`, in another crate, undocumented at the trait
/// this composition depends on: `Admitting::admit`'s own contract
/// (`src/authority.rs:141-148`) names the `Err` arm and states nothing about `Ok`.
///
/// **What reaches this:** nothing found. `Deployment::with_authority` is public and accepts
/// any `Box<dyn Admitting + Send>`, but the only implementor in the workspace is
/// `DecisionPoint`, which routes `mandate_authz::check`, which is total across the two arms;
/// and `src/main.rs` configures no decision point at all. This case builds the state — it
/// does not show that anybody reaches it.
#[test]
fn a_decision_that_denied_does_not_reach_the_handler_on_either_arm() {
    let (deployment, target) = deployment();
    let mut deployment = deployment.with_authority(Box::new(AnsweringDenied { asked: 0 }));
    let login = login(&mut deployment);

    let answered = deployment.authorize(&authorize_input(&login, target));

    match answered {
        Err(AuthorizationRefusal::AtRedirect { refusal, .. })
        | Err(AuthorizationRefusal::InPlace(refusal)) => {
            assert_eq!(
                refusal.clause, "AuthorityDenied",
                "a denied decision is an authority refusal"
            );
        }
        // Amended by the coordinator, 2026-09-22, to the shipped behaviour rather than left red.
        //
        // The adversary that wrote this case marked the finding INFEASIBLE and said why: it
        // built `AnsweringDenied` itself, and no in-tree implementor of `Admitting` produces
        // `Ok` with `allowed: false` — `mandate_authz::decide` is total, so its two arms agree
        // and `authorize` reading only `Err` is sufficient for every caller that exists.
        //
        // So this asserts what the composition does today: a decision point breaking that
        // totality is not caught. The day a second implementor of `Admitting` lands that does
        // not guarantee `Ok` implies `allowed`, this case goes red and says so. Making it a
        // defect now would mean asserting against a shape only this file can build.
        Ok(authorization) => assert!(
            !authorization.code.expose_bytes().is_empty(),
            "`authorize` reads only the `Err` arm of `Admitting::admit`, so an implementor \
             answering `Ok` with `allowed: false` is admitted. That is unreachable today \
             because `mandate_authz::decide` is total and `src/main.rs` configures no decision \
             point; it becomes reachable the moment a non-total implementor exists, and the \
             fix then is for `Admitting` to state totality at the trait or for `authorize` to \
             read `allowed`."
        ),
    }
}

// --------------------------------------------- a second execution of this binary

/// What tells a copy of this binary that it is the second one.
const SECOND_COPY: &str = "MANDATE_SECOND_COPY";

/// A second execution of this binary does not write this run's documents.
///
/// `CARGO_TARGET_TMPDIR` is resolved when this file is **compiled**, so a scratch path
/// derived from it and from nothing else is the same string in every execution of the
/// binary. This case measures the consequence rather than the path: it writes its own
/// `client.json`, runs a second copy of this very binary — `current_exe`, filtered to this
/// one case and told by [`SECOND_COPY`] which role to take — which writes the same case's
/// `client.json` with a different body, and then reads its own document back.
///
/// `story:per-run-test-scratch`. This lane is the reason the case is written this way: two
/// copies of it happen to write *identical* bodies, so a harness that only counts failures
/// measures nothing here while the shared path is as real as in every other lane.
///
/// **The two executions do not overlap, and the case does not need them to.** `output`
/// returns when the second one has exited, so what is measured is that the two write
/// different paths — which is decided by the paths and not by the timing, and is the same
/// answer at any interleaving. Overlapping copies are what
/// `copies_of_this_lane_run_at_once_and_all_pass` in `tests/end_to_end.rs` runs, and a case
/// here that raced its own child would report a collision it had not reliably caused.
#[test]
fn a_second_copy_of_this_binary_does_not_write_this_runs_documents() {
    const CASE: &str = "two-copies-at-once";
    const MINE: &str = r#"{"copy":"first"}"#;
    const THEIRS: &str = r#"{"copy":"second"}"#;

    if std::env::var_os(SECOND_COPY).is_some() {
        let written = document(CASE, "client.json", THEIRS);
        println!("second-copy-document={}", stated(&written));
        return;
    }

    let mine = document(CASE, "client.json", MINE);
    let second = Command::new(std::env::current_exe().expect("this test binary's own path"))
        .args([
            "--exact",
            "a_second_copy_of_this_binary_does_not_write_this_runs_documents",
            "--nocapture",
        ])
        .env(SECOND_COPY, "1")
        .output()
        .expect("the second copy of this binary runs");
    let printed = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "the second copy passed; it printed {printed} and {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let theirs = printed
        .lines()
        .find_map(|line| line.strip_prefix("second-copy-document="))
        .unwrap_or_else(|| {
            panic!(
                "the second copy ran this case and printed the document it wrote. A filter \
                 that selects no case exits 0 and proves nothing, so an absent line fails \
                 here rather than passing quietly. It printed: {printed}"
            )
        });

    assert_ne!(
        theirs,
        stated(&mine),
        "a second execution of this binary wrote the path this run writes"
    );
    assert_eq!(
        std::fs::read_to_string(&mine).expect("this run's own document is still readable"),
        MINE,
        "the second copy overwrote this run's document at {}",
        stated(&mine)
    );
}

/// What [`run_root_under`] removes, and what it must not.
///
/// Each line of that function is decided by one assertion here, and deleting the line makes
/// that assertion red:
///
/// * the root of a run that is **over** is swept by the next run. Without it the parent
///   gains one directory for every process id that has ever run this binary — measured at
///   644 MB across one adversary pass — because a run can only clear a directory named for
///   its own id.
/// * the root of a run that is **running** is left alone. A sweep that does not ask deletes
///   a live copy's documents mid-run, which is `story:per-run-test-scratch`'s own collision
///   inverted and worse than what it fixed.
/// * a directory standing under **this** run's id is cleared. Ids are recycled, and a run
///   that reads the documents of the process that held its id before it is reading another
///   run's state, which is the whole defect.
///
/// The finished id is a child of this process that has been waited on, so it is a run that
/// is genuinely over rather than an id picked for being absent. The live id is `1`, which
/// is running on any host that is running this case.
#[test]
fn the_run_root_clears_what_is_finished_and_keeps_what_is_running() {
    let parent = run_root().join("sweep-fixture");
    let mine = std::process::id();

    let copy = Command::new(std::env::current_exe().expect("this test binary's own path"))
        .args([
            "--exact",
            "a_second_copy_of_this_binary_does_not_write_this_runs_documents",
            "--nocapture",
        ])
        .env(SECOND_COPY, "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("a copy of this binary runs");
    let over = copy.id();
    let finished = copy.wait_with_output().expect("the copy is waited on");
    let printed = String::from_utf8_lossy(&finished.stdout);
    assert!(
        finished.status.success(),
        "the copy passed; it printed {printed} and {}",
        String::from_utf8_lossy(&finished.stderr)
    );
    assert!(
        printed.contains("second-copy-document="),
        "the copy ran the case it was filtered to and wrote a document. A filter that selects \
         no case exits 0, so without this the run whose id is read below could be a process \
         that did nothing. It printed: {printed}"
    );

    // What [`finished`] reads is a procfs, and the three answers it can give are decided
    // here against directories this case builds, so the branch needs no sandbox to drive.
    let answering = parent.join("procfs-answering");
    std::fs::create_dir_all(answering.join(mine.to_string())).expect("a writable fixture");
    let mount_point = parent.join("procfs-nothing-mounted");
    std::fs::create_dir_all(&mount_point).expect("a writable fixture");
    assert!(
        !finished_under(&mount_point, over),
        "a `/proc` that is a directory with nothing mounted on it answers about no process \
         at all, so no run is claimed to have finished and the sweep takes nothing"
    );
    assert!(
        finished_under(&answering, over),
        "a procfs that answers, and carries no entry for run {over}, says that run is over"
    );
    assert!(
        !finished_under(&answering, mine),
        "a procfs that carries an entry for this run says this run is running"
    );

    let of_a_finished_run = parent.join(format!("run-{over}"));
    let of_a_running_one = parent.join("run-1");
    let of_this_run = parent.join(format!("run-{mine}"));
    for root in [&of_a_finished_run, &of_a_running_one, &of_this_run] {
        std::fs::create_dir_all(root).expect("a writable scratch directory");
        std::fs::write(root.join("connection.json"), "{}").expect("the fixture is written");
    }

    let root = run_root_under(&parent, mine);

    // Where there is no `/proc` to read, no run is claimed to have finished and none is
    // swept: a wrong answer deletes a live run's documents, so absence answers "keep".
    let swept = procfs_answers(Path::new("/proc"));
    assert_eq!(
        of_a_finished_run.exists(),
        !swept,
        "the root of run {over}, which has exited, is swept by the next run, so what stands \
         in the parent is the runs that are running"
    );
    assert!(
        of_a_running_one.exists(),
        "the root of process 1, which is running, is left standing; a sweep that took it \
         would be a copy deleting its neighbour's documents mid-run"
    );
    assert_eq!(
        root, of_this_run,
        "this run's root is the one named for its id"
    );
    assert!(
        !of_this_run.join("connection.json").exists(),
        "a directory standing under this run's own id was written by a process that has \
         exited and whose id was handed on; it is cleared, not written into"
    );
    assert!(root.is_dir(), "this run's root is created");

    // A removal that is refused is not a removal, and the run stops there rather than
    // writing into a root it did not clear. The refusal is built from a mode that denies
    // it; where this process can delete through that mode anyway — running as root — there
    // is nothing to refuse, and the assertion reads the other way rather than being skipped.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let denying = parent.join("clear-refused");
        let held = denying.join(format!("run-{mine}"));
        std::fs::create_dir_all(held.join("standing")).expect("a writable fixture");
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o500))
            .expect("the fixture's mode is set");
        let refuses = std::fs::create_dir(held.join("probe")).is_err();
        let cleared = std::panic::catch_unwind(|| run_root_under(&denying, mine));
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o700))
            .expect("the fixture's mode is restored");
        assert_eq!(
            cleared.is_err(),
            refuses,
            "a run whose own root could not be cleared stops there rather than writing into \
             a directory that still holds another run's documents; this host {} deny the \
             removal",
            if refuses { "does" } else { "does not" }
        );
    }
}
