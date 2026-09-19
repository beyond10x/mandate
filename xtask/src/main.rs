mod documents;
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
    Corpus,
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
    ir(root)
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
/// Every member that has its own entry: the workspace's libraries, everything but the four
/// service binaries, `bins/mandate` and `xtask`.
const LIBRARIES: usize = 16;
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
        if p["version"] != "0.1.0"
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
        Action::Corpus => corpus(),
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
            run("aep", &["plan", "artifact", "validate"])?;
            documents(Path::new("."))?;
            for b in [
                "mandate",
                "mandate-authz",
                "mandate-conform",
                "mandate-control-plane",
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
