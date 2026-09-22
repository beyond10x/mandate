//! The conformance gate: the suite the contract synthesizes, run against the real handlers,
//! with every scenario that does not pass naming the live story whose gap it is.
//!
//! `story:conformance-target` built the target and froze its surface
//! (`mandate-conform --suite --impl-digest --out`). This step is what makes its answer a
//! *gate* rather than a report somebody ran once: it re-derives the suite, runs the target,
//! and compares what came back with two committed ledgers, both ways.
//!
//! # The five comparisons, and why each one is here
//!
//! 1. **The suite is a fresh synthesis.** `generated/conformance/suite.json` is byte-compared
//!    with what `ess verify conform synthesize --suite-format 5` writes from `systems/mandate`
//!    today. A contract change that nobody regenerated moves those bytes, and a suite that
//!    drifted is a corpus proving something about a specification the tree no longer has.
//! 2. **The suite is a synthesis of *this* specification.** Its `provenance.spec_digest` must
//!    equal the `x-ess-provenance.source_digest` every generated schema carries, and the
//!    coverage receipt must be current for `systems/mandate`. The first binds the suite to the
//!    projections; the second binds the projections to the sources.
//! 3. **The outcomes are the ones the tree expects, and every one of them that did not pass
//!    says whose gap it is.** `contracts/expected-outcomes.json` states, per scenario, what the
//!    target answers. Set equality both ways with the report, `skipped == 0`, and the counts
//!    column by column: a scenario that vanishes, one that appears, and one whose outcome moved
//!    are three different failures and each is named. Then every row that did not pass —
//!    `unsupported` as much as `failed` — names a story this workspace's store holds on a rung
//!    that is not terminal, and every row that does not is named in one refusal. Comparing the
//!    outcome set alone applied the honesty rule to the `failed` half of the corpus and to no
//!    other: 63 `unsupported` rows stated an outcome and no owner, the target's own ledger
//!    answered for them, and a reader of the authored ledger — who reads it and not
//!    `crates/mandate-conformance` — was told "unsupported" and nothing else.
//! 4. **The honesty ledger did not move.** `contracts/conformance/injections.json` is
//!    byte-compared with the run's. Every standing double, every armed port and every refusal
//!    before dispatch is a row in it, so a double that quietly started answering differently
//!    is a failing gate rather than a passing scenario.
//! 5. **Every gap has a live owner.** No scenario that did not pass is unattributed, none is
//!    attributed twice, and no attribution names a story whose work is over.
//!
//! # The two ledgers and which one answers
//!
//! `injections.json` is the target's own output and is compiled into `mandate-conformance`: it
//! is the authority for every scenario the target refused before dispatch or does not support,
//! and such a row moves by changing that crate. The authored ledger **restates** that owner and
//! does not decide it: the two are compared and a disagreement is refused, so the restatement
//! is a claim the gate checks rather than a second place the answer is kept.
//! `contracts/expected-outcomes.json` is authored here and is the authority for a scenario that
//! *executed* and whose expectation was unmet —
//! the target marks those `story:conform-gate`, which is not an attribution but a statement
//! that the attribution is not made there. A scenario named by both with two different stories
//! is refused: one gap, one owner (`story:conform-gate`, ruling 2, wave D second half).
//!
//! # The verdict is the report's, never the exit status
//!
//! `mandate-conform` exits zero on any written report by design, because a non-zero exit means
//! *the run did not happen* and a `conformance_status` of `failed` means *it did*. This step
//! therefore reads `report.json` and never the status — and the same reasoning runs the other
//! way for `ess verify conform synthesize`, which exits 1 on the 52 pre-existing refusals
//! while writing a complete suite: it is spawned tolerantly and decided on its artifact.
//!
//! # Which checkout answers for what
//!
//! `root` is the checkout whose **suite, projections, ESS sources and ledgers** are read, which
//! is what makes a doctored copy under `target/` the way this step's own failures are
//! reproduced. The **planning store** is always this workspace's own — a copy must not be able
//! to answer whether the story it names is still live — and so is the **compiled target
//! binary**, which is this workspace's code under test. `--release` reads the artifact and the
//! journal from **`root`** — the recorded evidence is a claim about the checkout under release
//! — and runs `git` in the **checkout the implementation digest was taken over**
//! (`Seams::sources`, this workspace in the wired gate), because what it decides is whether
//! those sources have moved.
use crate::emit;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The ledger format this step reads, and the only one.
pub const FORMAT: &str = "mandate-expected-outcomes/1";

/// The report format the frozen target writes.
const REPORT_FORMAT: &str = "ess-conformance-report/2";

/// The receipt format `crate::receipt` writes, re-read here to bind the sources.
const RECEIPT_FORMAT: &str = "mandate-coverage-receipt/1";

/// The ESS this repository is pinned to, as `generate()` requires it and as the receipt
/// records it.
const ESS_VERSION: &str = "ess 0.26.0";

/// Every outcome a row may state. `skipped` is deliberately not one of them: a skipped
/// scenario is a scenario nothing decided, and the gate requires the count to be zero rather
/// than giving the ledger a way to record one.
const OUTCOMES: [&str; 4] = ["passed", "failed", "unsupported", "error"];

/// The columns of the report's own count table, compared one by one.
const COLUMNS: [&str; 6] = [
    "total",
    "passed",
    "failed",
    "error",
    "unsupported",
    "skipped",
];

/// The rung a story is on when naming it answers nothing.
const TERMINAL: [&str; 3] = ["implemented", "archived", "rejected"];

/// The target's marker on a scenario it executed and did not attribute: this story's own id.
/// It is not an attribution, and a ledger that repeats it is refused.
const MARKER: &str = "story:conform-gate";

/// ESS's own words for a specification whose `scenarios:` list holds nothing, which is how
/// this step decides whether to pass `--scenarios` at all.
const EMPTY_LIST: &str = "the explicit scenarios list selected no authored files";

/// The kind `aep plan artifact evidence --kind` records for a conformance run, and the only
/// kind a release is decided on. Measured against a scratch copy of this store: the recorder
/// writes `args.kind` verbatim, so an `approval` or a `test_result` about the same artifact is
/// a record of something else (`review-result:wave-d-conform-gate-adversary-2` F5).
const CONFORMANCE_KIND: &str = "ess_conformance";

/// The pathspec that selects exactly what [`implementation_digest`] digests.
///
/// `crates/*/src` alone selects **nothing** in git — measured against this repository, where
/// `git diff --name-only HEAD~1 HEAD -- 'crates/*/src'` is empty and the same diff with
/// `crates/*/src/*` names eleven files — so the trailing component is what makes the rule a
/// rule rather than a check that always passes.
const IMPLEMENTATION: [&str; 3] = ["crates/*/src/*", "services/*/src/*", "systems"];

/// The reason the target records for a scenario it executed whose expectation was unmet, and
/// the one reason whose attribution is read from `contracts/expected-outcomes.json`.
const UNMET: &str = "expectation-unmet";

/// What a copy of a checkout must not answer for itself.
///
/// Three things the step reads are not properties of the artifacts under `root`: whether the
/// story an attribution names is still live, which sources the implementation digest is taken
/// over, and what the target answered. The first two are this workspace's in the wired gate
/// ([`Seams::workspace`]) and a fixture's in a case, and the third is a run of the real binary
/// that no fixture can otherwise doctor — which is why a `skipped` or an `error` answer has a
/// case at all (`review-result:wave-d-conform-gate-adversary-1` F5, F8).
pub struct Seams {
    /// The directory holding one markdown file per story, whose frontmatter states its rung.
    pub stories: PathBuf,
    /// The checkout whose `crates/*/src`, `services/*/src` and `systems/` are digested.
    pub sources: PathBuf,
    /// Applied to the report the run wrote, before anything reads it.
    pub doctor: Option<fn(&mut Value)>,
}

impl Seams {
    /// The seams the wired gate runs with: this workspace's store and this workspace's sources.
    ///
    /// # Errors
    ///
    /// When this file's own compilation directory has no parent, which is the workspace root.
    pub fn workspace() -> Result<Self> {
        let workspace = workspace()?;
        Ok(Self {
            stories: workspace.join(".engineering/planning/story"),
            sources: workspace,
            doctor: None,
        })
    }
}

/// This workspace, read from where this file was compiled rather than from the working
/// directory: the binary sets the working directory to the root and a test binary does not,
/// and the store and the target binary must be the same ones either way.
fn workspace() -> Result<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root")?
        .to_owned())
}

/// The gate as `cargo xtask conform` runs it: [`decide`] with this workspace's seams.
///
/// # Errors
///
/// Every refusal [`decide`] states.
pub fn conform(root: &Path, release: bool) -> Result<String> {
    decide(root, release, &Seams::workspace()?)
}

/// The suite, the run, both ledgers, the attribution and the two tables.
///
/// # Errors
///
/// Every refusal names the file or the scenario it is about: a suite that is not a fresh
/// synthesis, a digest or a toolchain that disagrees, a target that wrote no report, a scenario
/// the ledger does not carry or carries and the run does not, an outcome or a count that moved,
/// a scenario the run skipped or could not decide, an injections ledger that moved a byte, a
/// scenario with no story or two, a story on a terminal rung, and under `release` an artifact
/// validated against another specification or an evidence record the implementation has moved
/// since.
pub fn decide(root: &Path, release: bool, seams: &Seams) -> Result<String> {
    let workspace = workspace()?;
    let workspace = workspace.as_path();
    let scratch = scratch(workspace, root)?;

    let suite = suite(root, &scratch)?;
    let specification = suite["provenance"]["spec_digest"]
        .as_str()
        .ok_or("the suite states no provenance.spec_digest")?
        .to_owned();
    let schemas = projections(root, &specification)?;
    sources(root)?;

    let implementation = implementation_digest(&seams.sources)?;
    let out = scratch.join("out");
    let mut report = execute(workspace, root, &implementation, &out)?;
    if let Some(doctor) = seams.doctor {
        doctor(&mut report);
    }
    if report["format"] != REPORT_FORMAT {
        return Err(format!(
            "{}: {} is not the report format {REPORT_FORMAT} the frozen target writes",
            out.join("report.json").display(),
            report["format"]
        )
        .into());
    }
    if report["spec_digest"].as_str() != Some(specification.as_str()) {
        return Err(format!(
            "{}: the report was produced against {} and the suite against {specification}",
            out.join("report.json").display(),
            report["spec_digest"]
        )
        .into());
    }

    let expected = expected(root)?;
    let counts = outcomes(&expected, &report, root, &seams.stories)?;
    let ledger = injections(root, &out)?;
    let attribution = attribute(&seams.stories, root, &expected, &ledger)?;

    if release {
        evidence(root, &seams.sources, &specification)?;
    }

    table(
        &suite,
        &specification,
        &implementation,
        schemas,
        &counts,
        &attribution,
        release,
    )
}

/// A scratch directory of this root's own, under the workspace's `target/`.
///
/// Of the workspace's own, never of `root`: `root` is read, and a step that wrote into the
/// tree it is deciding about would be deciding about a tree it had just changed.
fn scratch(workspace: &Path, root: &Path) -> Result<PathBuf> {
    let name = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_owned())
        .file_name()
        .map_or_else(|| "root".to_owned(), |name| name.to_string_lossy().into());
    let scratch = workspace.join("target/xtask-conform").join(name);
    if scratch.exists() {
        fs::remove_dir_all(&scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    }
    fs::create_dir_all(&scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    Ok(scratch)
}

/// One `ess verify conform synthesize`, with or without the scenario list.
///
/// Spawned tolerantly in both forms: `synthesize` exits 1 on the 52 scenarios the contract
/// refuses to synthesize while writing a complete suite for the other 146, so the artifact is
/// the answer and the status is not.
fn synthesize(specification: &Path, out: &Path, scenarios: bool) -> Result<std::process::Output> {
    let specification = specification.to_str().ok_or("invalid path")?;
    let mut arguments: Vec<&str> = vec!["verify", "conform", "synthesize", "--path", specification];
    if scenarios {
        arguments.extend(["--scenarios", specification]);
    }
    arguments.extend([
        "--suite-format",
        "5",
        "--out",
        out.to_str().ok_or("invalid path")?,
    ]);
    Ok(Command::new("ess")
        .args(&arguments)
        .output()
        .map_err(|e| format!("ess verify conform synthesize: {e}"))?)
}

/// The committed suite, proved to be what a fresh synthesis of `root`'s sources writes today.
fn suite(root: &Path, scratch: &Path) -> Result<Value> {
    let committed_path = root.join("generated/conformance/suite.json");
    let committed = fs::read(&committed_path).map_err(|e| {
        format!(
            "{}: {e}; the suite is a generated projection and `cargo xtask generate` writes it",
            committed_path.display()
        )
    })?;

    let fresh_path = scratch.join("suite.json");
    let specification = root.join("systems/mandate");
    // Twice, and the second time without `--scenarios`: whether the specification lists
    // scenario files is ESS's reading of `ess-inputs.yaml`, not a scan written here. Both
    // scans that were written here got it wrong — one called `scenarios: []  # note`
    // non-empty, the other let a comment line end a list that had items
    // (`review-result:wave-d-conform-gate-adversary-2` F1/F2) — and the synthesizer already
    // answers the question exactly, by refusing the flag against an empty list with
    // [`EMPTY_LIST`] in its own words. Any other refusal is this step's refusal, and
    // `generate()` mirrors both invocations.
    let mut synthesized = synthesize(&specification, &fresh_path, true)?;
    if !fresh_path.is_file() && String::from_utf8_lossy(&synthesized.stderr).contains(EMPTY_LIST) {
        synthesized = synthesize(&specification, &fresh_path, false)?;
    }
    let fresh = fs::read(&fresh_path).map_err(|_| {
        format!(
            "ess verify conform synthesize --suite-format 5 wrote no suite at {}: {}",
            fresh_path.display(),
            String::from_utf8_lossy(&synthesized.stderr)
                .lines()
                .last()
                .unwrap_or_default()
        )
    })?;

    if fresh != committed {
        let at = fresh
            .iter()
            .zip(&committed)
            .position(|(l, r)| l != r)
            .unwrap_or_else(|| fresh.len().min(committed.len()));
        return Err(format!(
            "{}: not what `ess verify conform synthesize --suite-format 5` writes from {} \
             today — {} committed bytes against {} synthesized, first differing at byte {at}; \
             run cargo xtask generate and review the suite",
            committed_path.display(),
            root.join("systems/mandate").display(),
            committed.len(),
            fresh.len(),
        )
        .into());
    }
    Ok(serde_json::from_slice(&committed)
        .map_err(|e| format!("{}: {e}", committed_path.display()))?)
}

/// Every generated schema agrees with the suite about which specification this is.
///
/// All of them, not one: a projection regenerated from other sources and committed beside the
/// rest is exactly the drift the digest is carried for, and a reader of a single file cannot
/// see it. Returns how many were read, so a selection that found nothing cannot pass for
/// agreement.
fn projections(root: &Path, specification: &str) -> Result<usize> {
    let directory = root.join("generated/schema");
    let mut files: Vec<PathBuf> = Vec::new();
    walk(&directory, &mut files)?;
    let mut read = 0_usize;
    for path in files {
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let schema: Value = serde_json::from_slice(&fs::read(&path)?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let digest = schema["x-ess-provenance"]["source_digest"]
            .as_str()
            .ok_or_else(|| {
                format!(
                    "{}: states no x-ess-provenance.source_digest",
                    path.display()
                )
            })?;
        if digest != specification {
            return Err(format!(
                "{}: projected from {digest}, and the suite from {specification}",
                path.display()
            )
            .into());
        }
        read += 1;
    }
    if read == 0 {
        return Err(format!(
            "{}: no generated schema to agree with the suite's specification digest",
            directory.display()
        )
        .into());
    }
    Ok(read)
}

/// The coverage receipt is current for the sources the suite was synthesized from, and names
/// the toolchain that just synthesized it.
///
/// The receipt's `source_digest` is a digest over the `systems/mandate` **tree**
/// (`crate::receipt`), not ESS's own `source_digest`, so it is not the suite's `spec_digest`
/// and cannot be compared with it. What it can answer is the question the acceptance asks —
/// whether a source changed without the receipt following — and that is what is decided here.
///
/// The receipt records `ess_version` for one stated reason (`crate::receipt`): a repin that
/// changes the projections without changing a source leaves every digest equal and the version
/// is the only thing that moved. So the version is read here, and held against both the pin
/// `generate()` requires and the `ess` that just synthesized the suite this run compared
/// (`review-result:wave-d-conform-gate-adversary-1` F4).
fn sources(root: &Path) -> Result<()> {
    let path = root.join("generated/coverage/receipt.json");
    let receipt: Value =
        serde_json::from_slice(&fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    if receipt["format"] != RECEIPT_FORMAT {
        return Err(format!(
            "{}: {} is not the receipt format {RECEIPT_FORMAT}",
            path.display(),
            receipt["format"]
        )
        .into());
    }
    let sources = root.join("systems/mandate");
    let digest = tree_digest(std::slice::from_ref(&sources), &sources)?;
    if receipt["source_digest"].as_str() != Some(digest.as_str()) {
        return Err(format!(
            "{}: recorded source_digest {} against {} for {} today; the sources moved without \
             the receipt following",
            path.display(),
            receipt["source_digest"],
            digest,
            sources.display()
        )
        .into());
    }

    let recorded = receipt["ess_version"]
        .as_str()
        .ok_or_else(|| format!("{}: records no ess_version", path.display()))?;
    let out = Command::new("ess")
        .arg("--version")
        .output()
        .map_err(|e| format!("ess --version: {e}"))?;
    let running = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if recorded != running {
        return Err(format!(
            "{}: ess_version {recorded} projected this corpus and {running} synthesized the              suite it was compared against",
            path.display()
        )
        .into());
    }
    if running != ESS_VERSION {
        return Err(format!(
            "{}: ess_version {recorded}, and this repository is pinned to {ESS_VERSION}",
            path.display()
        )
        .into());
    }
    Ok(())
}

/// The digest of the implementation under test: the first 12 hex of one digest over every
/// source file of `crates/*/src`, `services/*/src` and `systems/`.
///
/// Those three are what a conformance answer can change: the handlers, the services that
/// compose them and the contract they are decided against. The framing is `crate::receipt`'s —
/// each file contributes its path, a separator no path can contain, its length and its bytes,
/// in sorted path order — so two trees that differ only in where one file ends and the next
/// begins cannot reach the same digest.
///
/// # Errors
///
/// When a source directory cannot be read, and when the root holds none of the three.
pub fn implementation_digest(root: &Path) -> Result<String> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for workspace in ["crates", "services"] {
        let directory = root.join(workspace);
        if !directory.is_dir() {
            continue;
        }
        let mut members: Vec<PathBuf> = fs::read_dir(&directory)
            .map_err(|e| format!("{}: {e}", directory.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path().join("src")))
            .filter(|src| src.is_dir())
            .collect();
        members.sort();
        roots.append(&mut members);
    }
    let systems = root.join("systems");
    if systems.is_dir() {
        roots.push(systems);
    }
    if roots.is_empty() {
        return Err(format!(
            "{}: holds no crates/*/src, no services/*/src and no systems/, so there is no              implementation to digest — every such root would answer the same digest of nothing",
            root.display()
        )
        .into());
    }
    let digest = tree_digest(&roots, root)?;
    Ok(digest.chars().take(12).collect())
}

/// One digest over several directories, each file framed by its path relative to `base`.
fn tree_digest(roots: &[PathBuf], base: &Path) -> Result<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for directory in roots {
        walk(directory, &mut files)?;
    }
    let mut framed: Vec<(String, Vec<u8>)> = Vec::new();
    for path in files {
        let relative = path.strip_prefix(base).unwrap_or(&path).to_owned();
        framed.push((
            relative.to_string_lossy().into_owned(),
            fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        ));
    }
    framed.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical: Vec<u8> = Vec::new();
    for (path, bytes) in &framed {
        canonical.extend_from_slice(path.as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes.len().to_string().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes);
    }
    Ok(emit::digest(&canonical))
}

fn walk(directory: &Path, into: &mut Vec<PathBuf>) -> Result<()> {
    if !directory.exists() {
        return Err(format!("{}: no such directory", directory.display()).into());
    }
    for entry in fs::read_dir(directory).map_err(|e| format!("{}: {e}", directory.display()))? {
        let path = entry
            .map_err(|e| format!("{}: {e}", directory.display()))?
            .path();
        if path.is_dir() {
            walk(&path, into)?;
        } else {
            into.push(path);
        }
    }
    Ok(())
}

/// Build the target once per process, and answer where the binary is.
///
/// Once because the cases in `xtask/tests/conform.rs` drive this step a dozen times over a
/// dozen roots, and the binary they all run is this workspace's own — the code under test,
/// never the copy's.
fn built(workspace: &Path) -> Result<&'static PathBuf> {
    static ONCE: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();
    match ONCE.get_or_init(|| build(workspace)) {
        Ok(binary) => Ok(binary),
        Err(error) => Err(error.clone().into()),
    }
}

fn build(workspace: &Path) -> std::result::Result<PathBuf, String> {
    let built = Command::new("cargo")
        .current_dir(workspace)
        .args(["build", "--locked", "-p", "mandate-conformance"])
        .output()
        .map_err(|error| format!("cargo build -p mandate-conformance: {error}"))?;
    if !built.status.success() {
        return Err(format!(
            "cargo build --locked -p mandate-conformance: {}\n{}",
            built.status,
            String::from_utf8_lossy(&built.stderr).trim()
        ));
    }
    let binary = workspace.join("target/debug/mandate-conform");
    if !binary.is_file() {
        return Err(format!(
            "{}: cargo build -p mandate-conformance wrote no binary",
            binary.display()
        ));
    }
    Ok(binary)
}

/// Run the target over the committed suite and read the report it wrote.
///
/// The status is deliberately not consulted: the target exits zero on any written report, so
/// the only thing a status can say here is that no report exists, which is what the missing
/// file says with the stderr beside it.
fn execute(workspace: &Path, root: &Path, implementation: &str, out: &Path) -> Result<Value> {
    let binary = built(workspace)?;
    let suite = root.join("generated/conformance/suite.json");
    let run = Command::new(binary)
        .args([
            "--suite",
            suite.to_str().ok_or("invalid path")?,
            "--impl-digest",
            implementation,
            "--out",
            out.to_str().ok_or("invalid path")?,
        ])
        .output()
        .map_err(|e| format!("{}: {e}", binary.display()))?;
    let report = out.join("report.json");
    let bytes = fs::read(&report).map_err(|_| {
        format!(
            "{}: the target wrote no report: {}",
            report.display(),
            String::from_utf8_lossy(&run.stderr).trim()
        )
    })?;
    Ok(serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", report.display()))?)
}

/// One authored ledger row: what the target answers, and whose gap it is when it does not pass.
struct Row {
    outcome: String,
    blocked_on: Option<String>,
}

/// `contracts/expected-outcomes.json`, read strictly.
///
/// Strictly because an unknown key is the way an attribution goes quietly unread: a row
/// carrying `story:` instead of `blocked_on:` would state an owner nothing in this step ever
/// looks at, and the gate would pass on a scenario nobody owns.
fn expected(root: &Path) -> Result<BTreeMap<String, Row>> {
    let path = root.join("contracts/expected-outcomes.json");
    let document: Value =
        serde_json::from_slice(&fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    if document["format"] != FORMAT {
        return Err(format!(
            "{}: {} is not the ledger format {FORMAT}",
            path.display(),
            document["format"]
        )
        .into());
    }
    for key in document
        .as_object()
        .ok_or("the ledger is no object")?
        .keys()
    {
        if key != "format" && key != "scenarios" {
            return Err(format!("{}: {key} is no key of {FORMAT}", path.display()).into());
        }
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for scenario in document["scenarios"]
        .as_array()
        .ok_or_else(|| format!("{}: states no scenarios", path.display()))?
    {
        let object = scenario
            .as_object()
            .ok_or_else(|| format!("{}: {scenario} is no row", path.display()))?;
        for key in object.keys() {
            if key != "id" && key != "outcome" && key != "blocked_on" {
                return Err(format!("{}: {key} is no key of a row", path.display()).into());
            }
        }
        let id = scenario["id"]
            .as_str()
            .ok_or_else(|| format!("{}: a row names no scenario", path.display()))?;
        let outcome = scenario["outcome"]
            .as_str()
            .filter(|outcome| OUTCOMES.contains(outcome))
            .ok_or_else(|| format!("{id}: {} is no outcome", scenario["outcome"]))?;
        if outcome == "error" {
            return Err(format!(
                "{id}: an `error` is a check the runner could not execute — an inconclusive \
                 scenario, not an expectation, and a ledger that records one can go green on a \
                 scenario nothing decided; the run's error count is held to the same zero as its \
                 skipped count"
            )
            .into());
        }
        let blocked_on = match &scenario["blocked_on"] {
            Value::Null => None,
            Value::String(story) => Some(story.clone()),
            other => return Err(format!("{id}: {other} is no story id").into()),
        };
        if outcome == "passed" && blocked_on.is_some() {
            return Err(format!(
                "{id}: passed and blocked on {}; a story that blocks nothing is not an owner",
                blocked_on.unwrap_or_default()
            )
            .into());
        }
        if rows
            .insert(
                id.to_owned(),
                Row {
                    outcome: outcome.to_owned(),
                    blocked_on,
                },
            )
            .is_some()
        {
            return Err(format!("{id}: two rows name this scenario").into());
        }
    }
    Ok(rows)
}

/// The report's outcomes against the ledger's, both ways, its counts column by column, and
/// every row that did not pass naming a live story of its own.
fn outcomes(
    expected: &BTreeMap<String, Row>,
    report: &Value,
    root: &Path,
    stories: &Path,
) -> Result<BTreeMap<String, usize>> {
    let path = root.join("contracts/expected-outcomes.json");
    let mut observed: BTreeMap<String, String> = BTreeMap::new();
    let outcomes = report["outcomes"]
        .as_object()
        .ok_or("the report states no outcomes")?;
    for (outcome, scenarios) in outcomes {
        for scenario in scenarios
            .as_array()
            .ok_or_else(|| format!("the report's {outcome} outcomes are no list"))?
        {
            let id = scenario
                .as_str()
                .ok_or_else(|| format!("the report's {outcome} outcomes name no scenario"))?;
            if let Some(first) = observed.insert(id.to_owned(), outcome.clone()) {
                return Err(format!(
                    "{id}: the report answers both {first} and {outcome} for one scenario"
                )
                .into());
            }
            // Named here rather than left to the count columns: a run that skipped a scenario
            // or could not execute its check decided nothing about it, and the scenario is the
            // subject of the correction, not the column
            // (`review-result:wave-d-conform-gate-adversary-1` F8).
            if outcome == "skipped" {
                return Err(format!(
                    "{id}: the run skipped it; a skipped scenario decides nothing and the suite \
                     that can skip one can go green by selecting less"
                )
                .into());
            }
            if outcome == "error" {
                return Err(format!(
                    "{id}: the run could not execute its check — an inconclusive scenario, not a \
                     verdict, and the gate holds the error count to the same zero as the skipped \
                     count"
                )
                .into());
            }
        }
    }

    for (id, outcome) in &observed {
        match expected.get(id) {
            None => {
                return Err(format!(
                    "{id}: the run answers {outcome} and {} carries no row for it",
                    path.display()
                )
                .into());
            }
            Some(row) if &row.outcome != outcome => {
                return Err(format!(
                    "{id}: {} expects {} and the run answers {outcome}",
                    path.display(),
                    row.outcome
                )
                .into());
            }
            Some(_) => {}
        }
    }
    for id in expected.keys() {
        if !observed.contains_key(id) {
            return Err(format!(
                "{id}: {} carries a row and the run answers nothing for it",
                path.display()
            )
            .into());
        }
    }

    // Every row that did not pass, `unsupported` as much as `failed`, names a live story
    // *here*. Comparing the outcome set alone let the honesty rule be applied to the `failed`
    // half of the corpus and to no other: the target's own ledger answered for what it does
    // not support, so 63 rows stated an outcome and no owner and this step read past them.
    // What the two ledgers disagree about is still [`attribute`]'s; what the authored one
    // does not say at all is this step's, because a reader of the authored ledger reads it
    // and not the target's source.
    //
    // Every offending row is named in one refusal rather than the first of them: a step that
    // returns on row one reports a corpus as having a single unowned scenario, which is how
    // an unowned corpus is mistaken for an unowned row.
    let mut unowned: Vec<String> = Vec::new();
    for (id, row) in expected {
        if row.outcome == "passed" {
            continue;
        }
        match &row.blocked_on {
            None => unowned.push(format!(
                "  {id}: answered {} and names no story",
                row.outcome
            )),
            Some(story) => {
                if let Some(why) = not_live(stories, story) {
                    unowned.push(format!(
                        "  {id}: answered {} and is blocked on {why}",
                        row.outcome
                    ));
                }
            }
        }
    }
    if !unowned.is_empty() {
        return Err(format!(
            "{}: {} of its {} rows did not pass and name no live story; a `failed` or an \
             `unsupported` row whose owner is unstated or over is a gap the corpus reports and \
             nobody is answerable for:\n{}",
            path.display(),
            unowned.len(),
            expected.len(),
            unowned.join("\n")
        )
        .into());
    }

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    counts.insert("total".to_owned(), expected.len());
    for outcome in OUTCOMES {
        counts.insert(
            outcome.to_owned(),
            expected
                .values()
                .filter(|row| row.outcome == outcome)
                .count(),
        );
    }
    counts.insert("skipped".to_owned(), 0);
    for column in COLUMNS {
        let stated = report["counts"][column]
            .as_u64()
            .ok_or_else(|| format!("the report states no {column} count"))?;
        let ours = *counts.get(column).unwrap_or(&0);
        if usize::try_from(stated).unwrap_or(usize::MAX) != ours {
            return Err(format!(
                "the run counts {stated} {column} and {} accounts for {ours}",
                path.display()
            )
            .into());
        }
    }
    Ok(counts)
}

/// What the target recorded about each scenario it did not execute, byte-compared.
struct Injections {
    /// The scenarios the target executed and did not attribute: their owner is authored.
    unmet: BTreeSet<String>,
    /// The scenarios the target itself attributed, and to which story.
    blocked: BTreeMap<String, String>,
}

/// The committed honesty ledger against the run's, byte for byte, and then read.
fn injections(root: &Path, out: &Path) -> Result<Injections> {
    let path = root.join("contracts/conformance/injections.json");
    let committed = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let produced_path = out.join("injections.json");
    let produced =
        fs::read(&produced_path).map_err(|e| format!("{}: {e}", produced_path.display()))?;
    if committed != produced {
        let at = committed
            .iter()
            .zip(&produced)
            .position(|(l, r)| l != r)
            .unwrap_or_else(|| committed.len().min(produced.len()));
        return Err(format!(
            "{}: not what this run wrote — {} committed bytes against {} produced, first \
             differing at byte {at}; a double, an arming or a refusal before dispatch moved",
            path.display(),
            committed.len(),
            produced.len()
        )
        .into());
    }

    let document: Value =
        serde_json::from_slice(&committed).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ledger = Injections {
        unmet: BTreeSet::new(),
        blocked: BTreeMap::new(),
    };
    for row in document["blocked"]
        .as_array()
        .ok_or_else(|| format!("{}: states no blocked rows", path.display()))?
    {
        let scenario = row["scenario"]
            .as_str()
            .ok_or_else(|| format!("{}: a blocked row names no scenario", path.display()))?;
        let reason = row["reason"]
            .as_str()
            .ok_or_else(|| format!("{scenario}: a blocked row states no reason"))?;
        let story = row["blocked_on"]
            .as_str()
            .ok_or_else(|| format!("{scenario}: a blocked row names no story"))?;
        if reason == UNMET {
            ledger.unmet.insert(scenario.to_owned());
            continue;
        }
        if let Some(first) = ledger.blocked.insert(scenario.to_owned(), story.to_owned())
            && first != story
        {
            return Err(format!(
                "{scenario}: {} attributes one scenario to both {first} and {story}",
                path.display()
            )
            .into());
        }
    }
    Ok(ledger)
}

/// Every scenario that did not pass has exactly one live story, and the table of them.
///
/// The three counts per story are its rows, the rows the **authored** ledger names it in, and
/// the rows the **target's** does. They overlap by design and are not a partition: since every
/// non-passed row is authored ([`outcomes`]), `authored` is the whole count and `recorded` is
/// how much of it the target says in its own source as well. Reporting them as a partition is
/// what made the table read `authored 0` for 63 rows while the ledger attributed every one.
fn attribute(
    stories: &Path,
    root: &Path,
    expected: &BTreeMap<String, Row>,
    ledger: &Injections,
) -> Result<BTreeMap<String, (usize, usize, usize)>> {
    let authored = root.join("contracts/expected-outcomes.json");
    let recorded = root.join("contracts/conformance/injections.json");
    let mut table: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();

    for (id, row) in expected {
        if row.outcome == "passed" {
            continue;
        }
        let stated = row.blocked_on.as_deref();
        let target = ledger.blocked.get(id).map(String::as_str);
        if let (Some(stated), Some(target)) = (stated, target)
            && stated != target
        {
            return Err(format!(
                "{id}: {} names {stated} and {} names {target}; one gap has one owner",
                authored.display(),
                recorded.display()
            )
            .into());
        }
        let story = if ledger.unmet.contains(id) {
            stated.ok_or_else(|| {
                format!(
                    "{id}: the run executed it and its expectation was unmet, and {} names no \
                     story for it",
                    authored.display()
                )
            })?
        } else {
            match (target, stated) {
                (Some(target), _) => target,
                (None, Some(stated)) => stated,
                (None, None) => {
                    return Err(format!(
                        "{id}: answered {} and neither {} nor {} names a story for it",
                        row.outcome,
                        authored.display(),
                        recorded.display()
                    )
                    .into());
                }
            }
        };

        if story == MARKER {
            return Err(format!(
                "{id}: {MARKER} is the target's marker for a scenario it did not attribute, not \
                 an owner; name the live story whose gap it is in {}",
                authored.display()
            )
            .into());
        }
        if let Some(why) = not_live(stories, story) {
            return Err(format!(
                "{id}: blocked on {why}; the ledger answers \"whose gap is this\" with work \
                 nobody is doing"
            )
            .into());
        }
        let counts = table.entry(story.to_owned()).or_insert((0, 0, 0));
        counts.0 += 1;
        if stated.is_some() {
            counts.1 += 1;
        }
        if target.is_some() {
            counts.2 += 1;
        }
    }
    Ok(table)
}

/// Why naming this story answers nothing, or `None` when it is a live owner.
///
/// The one reader of "is this a live owner", for both places a `blocked_on` is read: [`outcomes`]
/// requires one of the authored ledger, [`attribute`] of whichever ledger answers. Two readers
/// are two answers, and the stale one is the one that lets a row through — which is the shape of
/// the defect this check exists for, one rung down.
///
/// The clause it returns is the tail of its caller's sentence, so a caller states the scenario
/// and what it answered and this states what is wrong with the owner it named.
fn not_live(stories: &Path, story: &str) -> Option<String> {
    let Some(name) = story.strip_prefix("story:") else {
        return Some(format!("{story:?}, which is no story id"));
    };
    let file = stories.join(format!("{name}.md"));
    if !file.is_file() {
        return Some(format!("{story}, which the planning store does not hold"));
    }
    terminal_rung(&file)
        .map(|rung| format!("{story}, which the store reports `{rung}`, a terminal rung"))
}

/// The story's frontmatter `status:` when it is a terminal rung of the story lifecycle.
///
/// # Why it is here as well as in `crate::coverage`
///
/// It is the same reader and it should be one function. `crate::coverage::terminal_rung` is
/// `pub` for exactly that, and this step cannot call it while
/// `xtask/tests/adversary_conform_1.rs` — a file this unit does not own — declares `mod emit;`
/// and `mod conform;` and no `mod coverage;`: a `crate::coverage` path here stops that test
/// crate compiling. The parsing is therefore kept identical and
/// `xtask/tests/conform.rs::a_quoted_or_commented_status_is_read_as_terminal` drives **both**
/// readers over the same files, so the two cannot drift while that case runs. The patch that
/// removes this copy is `xtask-main-conform-wiring.patch`'s neighbour in the unit's scratch.
///
/// Read from the frontmatter only — the block between the first two `---` lines — so a
/// `status:` in the body is prose, not a claim; and read as a *value*, so `"implemented"` and
/// `implemented  # closed at wave D` are the rung they state rather than strings no rung
/// matches (`review-result:wave-d-conform-gate-adversary-1` F9).
///
/// # Errors
///
/// None: an unreadable story, a story with no frontmatter and a story on a live rung are all
/// `None`, and the caller decides what an absent file means.
#[must_use]
pub fn terminal_rung(story: &Path) -> Option<String> {
    let text = fs::read_to_string(story).ok()?;
    let mut fences = 0_u8;
    for line in text.lines() {
        if line.trim() == "---" {
            fences += 1;
            if fences == 2 {
                break;
            }
            continue;
        }
        if fences == 1
            && let Some(value) = line.strip_prefix("status:")
        {
            let value = rung(value);
            return TERMINAL.contains(&value.as_str()).then_some(value);
        }
    }
    None
}

/// A frontmatter scalar as its value: without a trailing comment, and unquoted.
fn rung(value: &str) -> String {
    let value = match value.split_once(" #") {
        Some((before, _)) => before,
        None => value,
    };
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .unwrap_or(value)
        .trim()
        .to_owned()
}

/// Under `--release`: the specification the store validated is this one, and the evidence it
/// recorded was taken against an implementation that has not moved since.
///
/// A library tag may ship `conformance_status: failed` — that is the release stance of
/// `initiative:drift-enforcement`, and it is what lets a specification-first repository publish
/// before every scenario passes. What it may not ship is a *stale* claim.
///
/// # What the store writes, and therefore what is read
///
/// Two things, and nothing that looks like them. `aep plan artifact set --model-digest` writes
/// `model_digest:` into the artifact's **frontmatter**, and that is the only digest the
/// document holds. `aep plan artifact evidence` appends an `aep.evidence.record/v1` line to
/// `.engineering/planning/journal.jsonl` carrying the `--ref` it was given; the document
/// carries no evidence section at all. A reader that scanned the prose for something
/// digest-shaped read a paragraph as a record
/// (`review-result:wave-d-conform-gate-adversary-1` F1/F3).
///
/// The reference is `git:<sha>`, and what it decides is whether the implementation has moved:
/// `git diff --quiet <sha> HEAD -- crates services systems` in the checkout under test. The
/// implementation digest is not compared here, because the evidence record does not carry one;
/// the commit it names is the stronger statement, and `git` is the producer that decides it.
fn evidence(root: &Path, sources: &Path, specification: &str) -> Result<()> {
    let path = root.join(".engineering/planning/executable-system-specification/mandate.md");
    let text = fs::read_to_string(&path).map_err(|e| {
        format!(
            "{}: {e}; a release is decided on the executable system specification the store \
             holds, and there is none to read",
            path.display()
        )
    })?;
    let recorded = frontmatter(&text, "model_digest").ok_or_else(|| {
        format!(
            "{}: its frontmatter states no model_digest; `aep plan artifact set --model-digest` \
             is what records the specification a release was validated against",
            path.display()
        )
    })?;
    if recorded != specification {
        return Err(format!(
            "{}: model_digest {recorded} was validated, and the suite was synthesized from \
             {specification}",
            path.display()
        )
        .into());
    }

    let journal = root.join(".engineering/planning/journal.jsonl");
    let lines = fs::read_to_string(&journal).map_err(|e| {
        format!(
            "{}: {e}; the evidence a release is decided on is an aep.evidence.record/v1 line in \
             the store's journal",
            journal.display()
        )
    })?;
    let reference = latest_evidence(&lines).ok_or_else(|| {
        format!(
            "{}: records no {CONFORMANCE_KIND} evidence for \
             executable-system-specification:mandate; `aep plan artifact evidence --kind \
             {CONFORMANCE_KIND} --source \'cargo xtask conform\' --ref git:<sha>` is what \
             records one",
            journal.display()
        )
    })?;
    let commit = reference.strip_prefix("git:").ok_or_else(|| {
        format!(
            "{}: the latest {CONFORMANCE_KIND} evidence references {reference}, which names no \
             commit; a release is decided on `git:<sha>`",
            journal.display()
        )
    })?;

    // The working tree first. Everything else in this step reads the working tree — the
    // digest, the build, the run — so a rule that compared two commits would bless sources
    // nothing ran (`review-result:wave-d-conform-gate-adversary-2` F3).
    let uncommitted = git(sources, &["status", "--porcelain", "--"], &IMPLEMENTATION)?;
    let dirty = String::from_utf8_lossy(&uncommitted.stdout);
    if let Some(first) = dirty.lines().next() {
        return Err(format!(
            "{}: {} is not in any commit, and the evidence a release is decided on names one; \
             the implementation under test is not the implementation the record can point at",
            sources.display(),
            first.get(3..).unwrap_or(first).trim()
        )
        .into());
    }

    let moved = git(
        sources,
        &["diff", "--quiet", commit, "HEAD", "--"],
        &IMPLEMENTATION,
    )?;
    match moved.status.code() {
        Some(0) => Ok(()),
        Some(1) => Err(format!(
            "{}: the latest {CONFORMANCE_KIND} evidence was taken at {commit} and the \
             implementation has moved since ({}); the recorded run is about other sources",
            journal.display(),
            IMPLEMENTATION.join(" ")
        )
        .into()),
        _ => Err(format!(
            "{}: the latest {CONFORMANCE_KIND} evidence references {reference}, which this \
             checkout cannot resolve: {}",
            journal.display(),
            String::from_utf8_lossy(&moved.stderr).trim()
        )
        .into()),
    }
}

/// One `git` in the checkout the implementation digest was taken over, with the pathspec that
/// selects exactly that set.
fn git(sources: &Path, arguments: &[&str], pathspec: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("git")
        .current_dir(sources)
        .args(arguments)
        .args(pathspec)
        .output()
        .map_err(|e| format!("git {}: {e}", arguments.join(" ")))?)
}

/// One frontmatter key's value: the block between the first two `---` lines, and nothing else.
fn frontmatter(text: &str, key: &str) -> Option<String> {
    let mut fences = 0_u8;
    for line in text.lines() {
        if line.trim() == "---" {
            fences += 1;
            if fences == 2 {
                break;
            }
            continue;
        }
        if fences == 1
            && let Some(value) = line.strip_prefix(key)
            && let Some(value) = value.strip_prefix(':')
        {
            return Some(rung(value));
        }
    }
    None
}

/// The reference of the **latest conformance** evidence record the journal holds for this
/// artifact.
///
/// Three filters, and each one is load-bearing. The entity, the id and the event type say the
/// record is about this artifact; `args.kind` says it is a conformance run, because
/// `aep plan artifact evidence` takes `--kind` free and `--ref` on every kind, so an approval
/// recorded afterwards would otherwise supply the commit a release is decided on. And the
/// latest is chosen by `payload.at`, the instant the recorder wrote, rather than by file order:
/// the journal is append-only today, and a rule that depends on that is a rule that breaks the
/// day a store is compacted (`review-result:wave-d-conform-gate-adversary-2` F5).
fn latest_evidence(lines: &str) -> Option<String> {
    let mut latest: Option<(i64, String)> = None;
    for line in lines.lines() {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if event["entity"] != "executable-system-specification"
            || event["id"] != "mandate"
            || event["type"] != "aep.evidence.record/v1"
            || event["args"]["kind"] != CONFORMANCE_KIND
        {
            continue;
        }
        let Some(reference) = event["args"]["reference"]
            .as_str()
            .or_else(|| event["payload"]["change"]["reference"].as_str())
        else {
            continue;
        };
        let at = event["payload"]["at"].as_i64().unwrap_or_default();
        if latest.as_ref().is_none_or(|(newest, _)| at >= *newest) {
            latest = Some((at, reference.to_owned()));
        }
    }
    latest.map(|(_, reference)| reference)
}

/// The counts table and the attribution table, as a reader of conformance sees them.
fn table(
    suite: &Value,
    specification: &str,
    implementation: &str,
    schemas: usize,
    counts: &BTreeMap<String, usize>,
    attribution: &BTreeMap<String, (usize, usize, usize)>,
    release: bool,
) -> Result<String> {
    let mut report = String::new();
    let scenarios = suite["scenarios"]
        .as_object()
        .map_or(0, serde_json::Map::len);
    writeln!(
        report,
        "conformance: {scenarios} scenarios synthesized from {specification} ({schemas} \
         projections agree), run against {implementation}{}",
        if release {
            ", release evidence bound"
        } else {
            ""
        }
    )?;
    let mut header = String::new();
    let mut values = String::new();
    for column in COLUMNS {
        write!(header, "| {column:>11} ")?;
        write!(values, "| {:>11} ", counts.get(column).unwrap_or(&0))?;
    }
    writeln!(report, "{header}|")?;
    writeln!(report, "{values}|")?;
    writeln!(
        report,
        "| {:>11} | {:>10} | {:>10} | story",
        "not passed", "authored", "recorded"
    )?;
    for (story, (rows, authored, recorded)) in attribution {
        writeln!(
            report,
            "| {rows:>11} | {authored:>10} | {recorded:>10} | {story}"
        )?;
    }
    Ok(report)
}
