mod conform;
mod coverage;
mod documents;
mod emit;
mod licenses;
mod mutants;
mod obligations_registry;
mod receipt;
use clap::{Parser, Subcommand};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Check,
    Adopt,
    Generate,
    Contracts,
    Boundaries,
    Licenses,
    Corpus,
    /// Every named mutant of `tests/mutants/`, applied to a copy of this tree and refused by
    /// the target it names; the copy, the build directory and the bounds are in [`mutants`].
    Mutants,
    /// The conformance gate: the suite re-synthesized and byte-compared, the target run over
    /// the implementation digest, the outcomes and injections compared with the authored
    /// ledgers, every non-passed scenario attributed to a live story; `--release` binds the
    /// recorded evidence to this tree. The rules are in [`conform`].
    Conform {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        release: bool,
    },
    /// The obligations registry: every external denial clause of an implemented command bound
    /// to the real-path test that decides it, or deferred to a live story; `--write` rewrites
    /// `contracts/conformance/obligations-report.json` from the registry.
    ObligationsRegistry {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        write: bool,
    },
    /// The coverage map: every compiled contract element mapped to its implementation and
    /// the checks that decide it, with the per-kind table. `root` is the checkout whose
    /// manifest and compiled model are read; the planning store is always this workspace's.
    Coverage {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    Documents {
        /// The checkout whose *documents* are read. Defaults to this workspace; pointing it at
        /// a copy is how this step's own failure is reproduced without editing the tree it
        /// guards. It relocates the documents only: the planning store they are compared against
        /// is always this workspace's own, so a copy cannot answer for itself.
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
}
fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        return Err(format!("{program} {args:?}: {status}").into());
    }
    Ok(())
}
fn output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new(program).args(args).output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    Ok(out.stdout)
}
fn version(program: &str, expected: &str) -> Result<()> {
    let bytes = output(program, &["--version"])?;
    if String::from_utf8_lossy(&bytes).trim() != expected {
        return Err(format!("required tool: {expected}").into());
    }
    Ok(())
}
fn files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, dir: &Path, map: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let p = entry?.path();
            if p.file_name().is_some_and(|n| n == ".ess-output") {
                continue;
            }
            if p.is_dir() {
                walk(root, &p, map)?;
            } else {
                map.insert(p.strip_prefix(root)?.to_owned(), fs::read(p)?);
            }
        }
        Ok(())
    }
    let mut map = BTreeMap::new();
    walk(root, root, &mut map)?;
    Ok(map)
}
fn generate(root: &Path) -> Result<()> {
    version("ess", "ess 0.26.0")?;
    for kind in ["schema", "openapi", "docs", "docs-ir"] {
        let out = root;
        run(
            "ess",
            &[
                "generate",
                "--path",
                "systems/mandate",
                "--kind",
                kind,
                "--out",
                out.to_str().ok_or("invalid path")?,
            ],
        )?;
    }
    ir(root)?;
    // The sixth kind: Rust shapes for the three kinds ESS 0.26.0's Rust target does not admit.
    // Emitted from the file [`ir`] just wrote, so the shapes and the model [`contracts`]
    // compares them against are the same bytes rather than two compilations of one source.
    emit::emit(root)?;
    // The eighth kind: the conformance suite, synthesized from the specification and its
    // authored scenarios the way `conform` re-synthesizes it.
    conformance_suite(root)?;
    // The seventh kind: the coverage receipt, binding the manifest and every projection input
    // by digest, written from this tree into the same output root the projections went to.
    receipt::receipt(Path::new("."), root)
}
/// The fifth kind: the compiled model itself, as canonical JSON.
///
/// The other four are projections *of* the model — schemas, an OpenAPI document, prose — and
/// none of them is the model. `story:contract-shapes` emits Rust shapes from the compiled IR,
/// so without this file the emitter's input is whatever `ess specify compile` answers at the
/// moment it runs, and a change in the model reaches the emitted shapes with nothing in
/// between recording that the input moved. Committed here, it is covered by [`contracts`]
/// like every other generated file: [`files`] walks the whole tree, so `ir/system.json` is
/// byte-compared against a fresh compilation on every gate run.
///
/// The IR is taken from standard output rather than `ess specify compile --out`, so the path
/// is this repository's decision and the committed bytes are exactly the ones `corpus` already
/// reads from the same command.
fn ir(root: &Path) -> Result<()> {
    let compiled = output(
        "ess",
        &[
            "specify",
            "compile",
            "--path",
            "systems/mandate",
            "--format",
            "json",
        ],
    )?;
    let directory = root.join("ir");
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("system.json"), &compiled)?;
    Ok(())
}
fn contracts() -> Result<()> {
    run("ess", &["specify", "validate", "--path", "systems/mandate"])?;
    let root = PathBuf::from("target/xtask-contract-regeneration");
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    generate(&root)?;
    if files(&root)? != files(Path::new("generated"))? {
        return Err("projection drift: run cargo xtask generate and review".into());
    }
    println!("ESS projections match deterministically");
    Ok(())
}
/// Enroll the committed `generated/` tree as ESS-owned output. Once per checkout, by hand.
///
/// ESS 0.26.0 will not write over bytes it does not own, so `cargo xtask generate` in a fresh
/// tree stops at `unowned output destination: schema/commands/…` before writing anything.
/// Ownership is recorded in `generated/.ess-output/`, which `.gitignore` excludes and should:
/// the ledger states what *this* checkout wrote, which is a fact about a machine and not about
/// the contract, and committing one would hand every clone another clone's answer. The cost is
/// that every new worktree starts unowned and needs this step once.
///
/// [`contracts`] runs first, and it is doing two jobs. It produces the settled reference the
/// adoption enrolls against, at `target/xtask-contract-regeneration`. And it refuses if the
/// committed tree differs from a fresh projection by one byte — which is the check that makes
/// adoption safe to automate at all. Adopting an already-drifted tree would enroll the drift
/// as the owned state, and the next `generate` would then overwrite it silently instead of
/// refusing: a drift check turned into a drift launderer.
///
/// Deliberately not part of [`Action::Check`]. The gate's job on an unadopted tree is to fail,
/// not to repair it; a `check` that adopted its own inputs would report on a tree it had just
/// changed.
fn adopt() -> Result<()> {
    contracts()?;
    for kind in ["schema", "openapi", "docs", "docs-ir"] {
        let owner = format!("projection:{kind}");
        run(
            "ess",
            &[
                "generate",
                "output",
                "adopt",
                "--ownership-root",
                "generated",
                "--from",
                "target/xtask-contract-regeneration",
                "--owner",
                &owner,
            ],
        )?;
    }
    println!("generated/ output adopted for 4 projection owners");
    Ok(())
}
/// Every workspace member, counted. A member added without a `dependency-boundaries.json`
/// entry falls through to the `external` allowlist and is checked against the wrong policy,
/// so the count is what makes the policy's silence a failure rather than a default.
const PACKAGES: usize = 22;
/// Every member that has its own entry: the workspace's libraries, `mandate-sts` (a library
/// target since wave B) and `mandate-control-plane` (the composition, a library target since
/// wave D); everything but the other two service binaries, `bins/mandate` and `xtask`.
const LIBRARIES: usize = 18;
fn boundaries() -> Result<()> {
    let metadata: Value = serde_json::from_slice(&output(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    )?)?;
    let policy: Value = serde_json::from_slice(&fs::read("dependency-boundaries.json")?)?;
    let libraries = policy["libraries"].as_object().ok_or("library policy")?;
    let packages = metadata["packages"].as_array().ok_or("packages")?;
    if packages.len() != PACKAGES || libraries.len() != LIBRARIES {
        return Err(format!("expected {PACKAGES} packages and {LIBRARIES} libraries").into());
    }
    for p in packages {
        let name = p["name"].as_str().ok_or("package name")?;
        if p["version"] != "0.2.0"
            || p["edition"] != "2024"
            || p["rust_version"] != "1.98.1"
            || p["license"] != "Apache-2.0"
            || p["publish"] != serde_json::json!([])
        {
            return Err(format!("package metadata violation: {name}").into());
        }
        for dep in p["dependencies"].as_array().ok_or("dependencies")? {
            let d = dep["name"].as_str().ok_or("dependency name")?;
            let allowed = libraries.get(name).unwrap_or(&policy["external"]);
            if !allowed
                .as_array()
                .ok_or("boundary policy")?
                .iter()
                .any(|v| v == d)
            {
                return Err(format!("forbidden dependency {name} -> {d}").into());
            }
        }
    }
    println!("{PACKAGES} packages satisfy metadata and dependency boundaries");
    Ok(())
}
/// Every crate the lock resolves carries a license `deny.toml` allows, including the ones
/// cargo-deny's own graph drops. The fold and the reason for it are in [`licenses`].
fn licenses() -> Result<()> {
    let allowed = licenses::allowed(&fs::read_to_string("deny.toml")?)?;
    let metadata: Value = serde_json::from_slice(&output(
        "cargo",
        &["metadata", "--locked", "--format-version", "1"],
    )?)?;
    let counted = licenses::audit(&metadata, &allowed)?;
    println!("{counted} resolved crates carry an allowed license");
    Ok(())
}
/// Every command the contract declares is named in `command-obligations.md`, with its declared
/// denial text verbatim, and the table names nothing the contract does not declare. A command
/// missing from the table is a denial no reader of the contract can find; a row whose text has
/// drifted misreports one.
///
/// The row's subject is the **externally caused** refusal: the one a caller can provoke and
/// therefore the one an obligations table is read for. Selecting it by `condition.kind` rather
/// than by "the first outcome carrying an `error`" is what keeps that true as the contract
/// grows. A `wrong-state` refusal is an error outcome too, and it is declared before the
/// external one on any command that has both, so the positional reader would silently start
/// publishing a state-machine message as the command's obligation — a wrong row, printed by a
/// green gate. Exactly one externally caused outcome per command is required in both
/// directions: none leaves the table with nothing to state, and two leave it ambiguous which
/// text the row must carry.
fn obligations(ir: &Value) -> Result<()> {
    let commands = ir["commands"].as_object().ok_or("ESS command index")?;
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    for (name, command) in commands {
        let mut external = command["outcomes"]
            .as_array()
            .ok_or("command outcomes")?
            .iter()
            .filter(|outcome| outcome["condition"]["kind"] == "external");
        let refusal = external
            .next()
            .ok_or_else(|| format!("{name} declares no externally caused outcome"))?;
        if external.next().is_some() {
            return Err(format!(
                "{name} declares more than one externally caused outcome; \
                 an obligations row can carry only one denial text"
            )
            .into());
        }
        if !refusal["error"].is_string() {
            return Err(format!("{name}'s externally caused outcome names no error").into());
        }
        let cause = refusal["condition"]["cause"]
            .as_str()
            .ok_or_else(|| format!("{name} refusal states no external cause"))?;
        declared.insert(name.clone(), cause.to_owned());
    }
    let table = fs::read_to_string("docs/architecture/command-obligations.md")?;
    let mut recorded: BTreeMap<String, String> = BTreeMap::new();
    for line in table.lines() {
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let (name, rest) = rest.split_once("` | ").ok_or("obligations row")?;
        let text = rest.strip_suffix(" |").ok_or("obligations row")?;
        if recorded.insert(name.to_owned(), text.to_owned()).is_some() {
            return Err(format!("duplicate obligations row {name}").into());
        }
    }
    for (name, cause) in &declared {
        match recorded.get(name) {
            None => return Err(format!("no obligations row for {name}").into()),
            Some(text) if text != cause => {
                return Err(format!(
                    "obligations row for {name} does not match its declared denial"
                )
                .into());
            }
            Some(_) => {}
        }
    }
    for name in recorded.keys() {
        if !declared.contains_key(name) {
            return Err(format!("obligations row {name} names no declared command").into());
        }
    }
    println!(
        "{} commands named in command-obligations.md",
        declared.len()
    );
    Ok(())
}
fn corpus() -> Result<()> {
    let ir: Value = serde_json::from_slice(&output(
        "ess",
        &[
            "specify",
            "compile",
            "--path",
            "systems/mandate",
            "--format",
            "json",
        ],
    )?)?;
    let commands = ir["commands"].as_object().ok_or("ESS command index")?;
    let v: Value = serde_json::from_slice(&fs::read("tests/security/cases.json")?)?;
    if v["format"] != "mandate-security-cases/1" {
        return Err("unknown corpus".into());
    }
    let cases = v["cases"].as_array().ok_or("cases")?;
    let mut ids = BTreeSet::new();
    let mut categories = BTreeSet::new();
    for c in cases {
        for f in ["id", "category", "story", "given", "action", "expected"] {
            if c[f].as_str().is_none_or(|s| s.trim().is_empty()) {
                return Err(format!("missing {f}: {c}").into());
            }
        }
        let id = c["id"].as_str().ok_or("id")?;
        if !ids.insert(id) {
            return Err(format!("duplicate case {id}").into());
        }
        categories.insert(c["category"].as_str().ok_or("category")?);
        let story = c["story"]
            .as_str()
            .ok_or("story")?
            .strip_prefix("story:")
            .ok_or("story id")?;
        if !Path::new(&format!(".engineering/planning/story/{story}.md")).is_file() {
            return Err(format!("missing owner for {id}").into());
        }
        if c["level"] != "contract-scenario" {
            return Err("corpus cannot claim runtime enforcement".into());
        }
        let references = c["commands"].as_array().ok_or("missing command coverage")?;
        if references.is_empty() {
            return Err(format!("no command coverage for {id}").into());
        }
        for reference in references {
            let command = reference.as_str().ok_or("command reference")?;
            if !commands.contains_key(command) {
                return Err(format!("unknown command {command} in case {id}").into());
            }
        }
    }
    for required in [
        "directory",
        "linking",
        "tenancy",
        "credential",
        "epoch",
        "pkce",
        "exchange",
        "authority",
        "containment",
        "audit",
    ] {
        if !categories.contains(required) {
            return Err(format!("missing category {required}").into());
        }
    }
    for line in fs::read_to_string("docs/sources/SHA256SUMS")?.lines() {
        let (hash, name) = line.split_once("  ").ok_or("source digest")?;
        if hash
            != format!(
                "{:x}",
                Sha256::digest(fs::read(Path::new("docs/sources").join(name))?)
            )
        {
            return Err(format!("source changed: {name}").into());
        }
    }
    obligations(&ir)?;
    println!(
        "{} contract scenarios traced; source hashes match; no runtime enforcement claimed",
        cases.len()
    );
    Ok(())
}
/// Every declared document exists, is not empty, and every row set it says it read from the
/// planning store still equals what the store answers now. Without this step nothing in the gate
/// opens `docs/architecture/` beyond `command-obligations.md`, so a document deliverable could be
/// emptied and every step stayed green.
/// The coverage step: the manifest against the compiled model, the store, the compiled test
/// binaries and the committed receipt; the per-kind table is what it prints. The rules are
/// in [`coverage`].
/// The mutation controls: every named mutant applied to a copy of this tree and refused by
/// the target it names, printed as the table the review-result carries. Last in `check`,
/// since it rebuilds targets in the copy.
fn mutation_controls() -> Result<()> {
    println!("{}", mutants::mutants(Path::new("."))?);
    Ok(())
}

/// The obligations registry step: the seven `contracts/obligations/<crate>.json` files
/// against the compiled model, the store, the compiled test binaries and the committed
/// report; the per-crate table is what it prints. The rules are in [`obligations_registry`].
fn obligations_registry_step(root: &Path, write: bool) -> Result<()> {
    let table = if write {
        obligations_registry::obligations_registry_write(root)?
    } else {
        obligations_registry::obligations_registry(root)?
    };
    println!("{table}");
    Ok(())
}

/// The conformance gate step; the per-story attribution table is what it prints.
fn conform_step(root: &Path, release: bool) -> Result<()> {
    println!("{}", conform::conform(root, release)?);
    Ok(())
}

/// Synthesize the conformance suite into `<root>/conformance/suite.json`: with
/// `--scenarios systems/mandate` first, and without it only when ESS refuses the explicit
/// list as selecting no authored file (the list is empty today). ESS exits non-zero while
/// writing a complete suite when the specification carries refusals, so the artifact, not the
/// status, decides.
fn conformance_suite(root: &Path) -> Result<()> {
    let out = root.join("conformance").join("suite.json");
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&out);
    let target = out.to_str().ok_or("invalid path")?;
    let with_scenarios = Command::new("ess")
        .args([
            "verify",
            "conform",
            "synthesize",
            "--path",
            "systems/mandate",
            "--scenarios",
            "systems/mandate",
            "--suite-format",
            "5",
            "--out",
            target,
        ])
        .output()?;
    if out.is_file() {
        return Ok(());
    }
    let refusal = String::from_utf8_lossy(&with_scenarios.stderr);
    if !refusal.contains("the explicit scenarios list selected no authored files") {
        return Err(format!("ess verify conform synthesize: {}", refusal.trim()).into());
    }
    let bare = Command::new("ess")
        .args([
            "verify",
            "conform",
            "synthesize",
            "--path",
            "systems/mandate",
            "--suite-format",
            "5",
            "--out",
            target,
        ])
        .output()?;
    if !out.is_file() {
        let refusal = String::from_utf8_lossy(&bare.stderr);
        return Err(format!(
            "ess verify conform synthesize wrote no suite: {}",
            refusal.trim()
        )
        .into());
    }
    Ok(())
}

fn coverage_map(root: &Path) -> Result<()> {
    println!("{}", coverage::coverage(root)?);
    Ok(())
}

fn documents(root: &Path) -> Result<()> {
    let workspace = std::env::current_dir()?;
    let blocked = documents::store_blocked(&workspace)?;
    println!("{}", documents::documents(root, &blocked)?);
    Ok(())
}
fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    if let Err(e) = std::env::set_current_dir(root) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let result: Result<()> = (|| match Args::parse().command {
        Action::Adopt => adopt(),
        Action::Generate => generate(Path::new("generated")),
        Action::Contracts => contracts(),
        Action::Boundaries => boundaries(),
        Action::Licenses => licenses(),
        Action::Corpus => corpus(),
        Action::Mutants => mutation_controls(),
        Action::ObligationsRegistry { root, write } => obligations_registry_step(&root, write),
        Action::Conform { root, release } => conform_step(&root, release),
        Action::Coverage { root } => coverage_map(&root),
        Action::Documents { root } => documents(&root),
        Action::Check => {
            if !String::from_utf8_lossy(&output("rustc", &["--version"])?)
                .starts_with("rustc 1.98.1 ")
            {
                return Err("Rust 1.98.1 required".into());
            }
            version("aep", "protocol 0.55.0")?;
            run("cargo", &["fmt", "--all", "--", "--check"])?;
            run(
                "cargo",
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
            )?;
            run("cargo", &["test", "--workspace", "--locked"])?;
            run("cargo", &["build", "--workspace", "--locked"])?;
            boundaries()?;
            corpus()?;
            contracts()?;
            run("cargo", &["deny", "--locked", "check"])?;
            licenses()?;
            run("aep", &["plan", "artifact", "validate"])?;
            documents(Path::new("."))?;
            coverage_map(Path::new("."))?;
            obligations_registry_step(Path::new("."), false)?;
            conform_step(Path::new("."), false)?;
            // Five binaries refuse `serve`; `mandate-control-plane` serves the login road
            // (`story:product-listener`, ruling D3) and is proven by its own listener cases.
            for b in [
                "mandate",
                "mandate-authz",
                "mandate-conform",
                "mandate-sts",
                "mandate-worker",
            ] {
                let p = format!("target/debug/{b}");
                for flag in ["--help", "--version"] {
                    output(&p, &[flag])?;
                }
                if Command::new(&p).arg("serve").output()?.status.success() {
                    return Err(format!("{b} accepts runtime commands").into());
                }
            }
            mutation_controls()?;
            Ok(())
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
