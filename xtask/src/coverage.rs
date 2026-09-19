//! The gate's reader for `contracts/coverage.json`: every element of the contract, mapped to
//! what implements it and to the checks that decide it.
//!
//! The registries `mandate_types::realizes!` expands prove one third of the contract and say
//! nothing about the rest, so a reader of them alone reads a claim about the whole model. The
//! manifest is the other two thirds, **authored** rather than generated: a map derived from
//! the registries could not disagree with them, and a map that cannot disagree is not
//! evidence. What is machine-checked is every way the authored map can be wrong.
//!
//! Eight things are decided here, and deliberately no more:
//!
//! 1. the manifest's element set is the compiled model's element set, both ways, kind for
//!    kind — a command, event, entity, type or error the contract declares and nothing names
//!    fails, and so does an entry naming an element nothing declares;
//! 2. one element has one entry, so one element has one realizer;
//! 3. every `implemented` entry names a crate that **runs the per-crate manifest case**, at
//!    least one symbol that implements it, and at least one test that decides it:
//!    - a symbol's path root is `crate` or a **member of this workspace**, read from `cargo
//!      metadata --no-deps` and never from the build stream, which mentions every resolved
//!      dependency;
//!    - a symbol rooted in [`GENERATED_CRATE`] is refused outright. ESS emits one shape per
//!      declared element, so the generated projection of an element distinguishes nothing
//!      about whether anything implements it;
//!    - a test id is one a compiled binary **lists and runs** — an `#[ignore]`d case is
//!      listed exactly as a running one and is subtracted — and at least one of them belongs
//!      to the package the entry names as its crate;
//! 4. every `declared` entry names a story the planning store holds and carries no
//!    implementation — no crate, no symbol, no test — and states a reason;
//! 5. every `deferred` entry names a blocker `aep plan artifact blocked` reports as `open`
//!    **and** reports as holding that entry's story; and a `declared` entry whose story the
//!    store does hold is a `deferred` entry that was relabelled;
//! 6. the manifest is written one entry to a line;
//! 7. [`ACCOUNTING_CRATES`] — the crates an `implemented` entry may name — is exactly the set
//!    of crates a compiled test binary lists a per-crate manifest case for, so the list
//!    cannot quietly outlive the cases it stands for;
//! 8. every workspace member holding a `tests/contract_agreement.rs` is an accounting crate
//!    or is named in [`AGREEMENT_ALLOWANCES`] with a reason, so a crate cannot run a
//!    reconciliation no entry of the manifest answers to.
//!
//! # What an entry states
//!
//! One JSON object to a line, in `entries`:
//!
//! ```text
//! {"element":…,"kind":…,"status":…,"story":…,"crate":…,"impl":[…],"tests":[…]}
//! {"element":…,"kind":…,"status":…,"story":…,"impl":[],"tests":[],"reason":…}
//! {"element":…,"kind":…,"status":…,"story":…,"impl":[],"tests":[],"blocker":…,"reason":…}
//! ```
//!
//! `kind` is the compiled model's index the element sits in; `status` is one of
//! [`STATUSES`]. An `implemented` entry carries `crate`, `impl` and `tests` and no `reason`;
//! a `declared` entry carries `reason` and none of the three; a `deferred` entry carries
//! `blocker` as well. A `declared` or `deferred` entry names a story that is not on a terminal
//! rung of its lifecycle (`implemented`, `archived`, `rejected`), read from the story's own
//! frontmatter: a map that answers "who implements this" with work that is over answers
//! nothing. A `.State` element follows its record: it is `implemented` only where the crate
//! that folds the record registers its **own** lifecycle enum; where the record is not
//! `implemented` it carries the record's status, story and blocker; where the record is
//! `implemented` and no crate registers the enum it is `declared` on the story that will.
//!
//! The last of those is not cosmetic. `mandate-authz`, `mandate-graph` and `mandate-policy`
//! run the per-crate case and cannot parse JSON — `dependency-boundaries.json` gives none of
//! them `serde_json` — so each reads its own entries as lines. A reflowed manifest would
//! leave those three cases finding nothing and passing, which is the shape of failure this
//! step exists to refuse: a green exit from a check that selected nothing.
//!
//! # What is **not** decided here, and where it is
//!
//! That a named symbol exists is the compiler's: `realizes!` expands each registry entry into
//! a `use` of the symbol, so a symbol that moved does not build. That the manifest names the
//! *same* symbol the registry does is each crate's own case, which asserts the manifest's
//! `implemented` entries for that crate equal its `ESS_REALIZATIONS`, element and symbol
//! both. This step therefore checks the shape of a symbol and the reachability of a crate,
//! and leaves identity to the two checks that can decide it.
//!
//! # Which checkout answers for what
//!
//! `root` is the checkout whose **manifest and compiled model** are read. The planning store
//! and the compiled test binaries are always this workspace's own, never derived from `root`:
//! a copy must not be able to answer for itself. That is the rule [`crate::documents`] already
//! applies, and it is what makes `Action::Coverage { root }` safe for the data mutants of
//! `story:mutation-controls`.
use crate::documents::{Blocker, store_blocked};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The manifest format this step reads, and the only one.
pub const FORMAT: &str = "mandate-coverage/1";

/// Every crate that runs the per-crate manifest case, and therefore the only crates an
/// `implemented` entry may name.
///
/// Eight are registrars — each invokes `mandate_types::realizes!` and its
/// `tests/contract_agreement.rs` asserts the manifest's entries for it equal its
/// `ESS_REALIZATIONS` — and the ninth is `mandate-types`, whose `tests/inventory.rs` asserts
/// the same against the conformance account. A crate that runs no case could carry an entry
/// nothing reconciles, which is a coverage claim with no reader.
///
/// `mandate-token` was the eighth registrar to arrive and it arrived late: it round-tripped
/// `mandate.core.CredentialDescriptor` and `mandate.core.CredentialProfile` against the
/// generated shapes in its own agreement suite while this manifest reported both `deferred`
/// on a decision blocker, and nothing could see the contradiction because the only rule was
/// "an entry may not name a crate that runs no case". The rule that closes that is check 8
/// above, which starts from the tree rather than from this list.
pub const ACCOUNTING_CRATES: [&str; 9] = [
    "mandate-authz",
    "mandate-federation",
    "mandate-graph",
    "mandate-identity",
    "mandate-model",
    "mandate-policy",
    "mandate-sts",
    "mandate-token",
    "mandate-types",
];

/// The compiled model's five element indexes, and the `kind` a manifest entry writes for each.
const INDEXES: [(&str, &str); 5] = [
    ("commands", "command"),
    ("events", "event"),
    ("entities", "entity"),
    ("errors", "error"),
    ("types", "type"),
];

const STATUSES: [&str; 3] = ["implemented", "declared", "deferred"];

/// What one `cargo test --no-run` pass over the workspace answers, together with one
/// `cargo metadata --no-deps`: every test a compiled binary lists **and runs**, and every
/// member this workspace is made of.
#[derive(Debug, Default)]
pub struct Compiled {
    /// `<package>::<target>::<test>` for every case a compiled test binary lists and
    /// `cargo test` runs.
    ///
    /// An `#[ignore]`d case is listed by `--list` in exactly the form a running one is, and
    /// is never run; it is subtracted here, so an entry whose only named check is ignored
    /// names a check that decides nothing and is refused.
    pub tests: BTreeSet<String>,
    /// Every **workspace member**, with `-` written as `_`: the path roots a symbol may
    /// take.
    ///
    /// Read from `cargo metadata --no-deps`, which is the question "is this one of ours".
    /// The `--message-format=json` build stream is not: it carries a `package_id` for every
    /// resolved dependency as well, so while this set was built from it a symbol rooted in
    /// `serde_json` passed a check whose entire content is that its root is a crate of this
    /// workspace.
    pub crates: BTreeSet<String>,
    /// Every workspace member by package name, with the directory its manifest sits in.
    ///
    /// The directory is what lets [`agreement_crates`] ask which members hold a
    /// `tests/contract_agreement.rs` without a name-to-path convention written here:
    /// `services/sts` is the package `mandate-sts`.
    pub packages: BTreeMap<String, PathBuf>,
}

/// One `cargo test --no-run` pass per process.
///
/// The pass is the expensive half of this step and its answer does not change while the
/// process runs, so the cases in `xtask/tests/coverage.rs` share one. A failure is cached as
/// its text: a second call must not silently retry a build that already failed.
///
/// # Errors
///
/// When the workspace does not build, or a compiled test binary cannot be asked what it
/// holds.
pub fn compiled(workspace: &Path) -> Result<&'static Compiled> {
    static ONCE: OnceLock<std::result::Result<Compiled, String>> = OnceLock::new();
    match ONCE.get_or_init(|| compile(workspace).map_err(|error| error.to_string())) {
        Ok(compiled) => Ok(compiled),
        Err(error) => Err(error.clone().into()),
    }
}

/// Build every test binary the workspace declares, and ask each one what it holds.
///
/// `--no-run` is what makes the id set the compiler's answer rather than a list written here:
/// a case renamed, moved or deleted leaves the manifest naming an id no binary lists.
fn compile(workspace: &Path) -> Result<Compiled> {
    let packages = members(workspace)?;
    let crates = packages.keys().map(|name| name.replace('-', "_")).collect();
    let built = Command::new("cargo")
        .current_dir(workspace)
        .args([
            "test",
            "--workspace",
            "--locked",
            "--no-run",
            "--message-format=json",
        ])
        .output()
        .map_err(|error| format!("cargo test --workspace --no-run: {error}"))?;
    if !built.status.success() {
        return Err(format!(
            "cargo test --workspace --locked --no-run: {}\n{}",
            built.status,
            String::from_utf8_lossy(&built.stderr).trim()
        )
        .into());
    }

    let mut compiled = Compiled {
        tests: BTreeSet::new(),
        crates,
        packages,
    };
    for line in String::from_utf8_lossy(&built.stdout).lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(package) = message["package_id"].as_str().map(package_name) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let (Some(executable), Some(target)) = (
            message["executable"].as_str(),
            message["target"]["name"].as_str(),
        ) else {
            continue;
        };
        let listed = cases(executable, &[])?;
        let ignored = cases(executable, &["--ignored"])?;
        if !ignored.is_subset(&listed) {
            return Err(format!(
                "{executable} --list --ignored lists {} case(s) its --list does not, so the \
                 subtraction of the ignored cases is reading something other than the same \
                 index",
                ignored.difference(&listed).count()
            )
            .into());
        }
        for name in listed.difference(&ignored) {
            compiled
                .tests
                .insert(format!("{package}::{target}::{name}"));
        }
    }
    if compiled.tests.is_empty() {
        return Err("cargo test --workspace --no-run built no test binary".into());
    }
    Ok(compiled)
}

/// Every case a compiled test binary lists, and only the `#[ignore]`d ones when `selector`
/// is `["--ignored"]`.
///
/// `--list` prints an ignored case exactly as it prints a running one, so the running set is
/// the difference of the two and not anything the first list can be read for on its own.
fn cases(executable: &str, selector: &[&str]) -> Result<BTreeSet<String>> {
    let listed = Command::new(executable)
        .args(["--list", "--format", "terse"])
        .args(selector)
        .output()
        .map_err(|error| format!("{executable} --list: {error}"))?;
    if !listed.status.success() {
        return Err(format!("{executable} --list: {}", listed.status).into());
    }
    Ok(String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|case| case.strip_suffix(": test").map(str::to_owned))
        .collect())
}

/// Every member of the workspace, by package name, with the directory its manifest sits in.
///
/// `--no-deps` is the whole point: the resolved dependency graph answers a different
/// question from the one the symbol check asks.
fn members(workspace: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let listed = Command::new("cargo")
        .current_dir(workspace)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .map_err(|error| format!("cargo metadata --no-deps: {error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "cargo metadata --no-deps: {}\n{}",
            listed.status,
            String::from_utf8_lossy(&listed.stderr).trim()
        )
        .into());
    }
    let metadata: Value = serde_json::from_slice(&listed.stdout)
        .map_err(|error| format!("cargo metadata --no-deps: {error}"))?;
    let listed = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata --no-deps states no packages")?;
    let mut members = BTreeMap::new();
    for package in listed {
        let (Some(name), Some(manifest)) =
            (package["name"].as_str(), package["manifest_path"].as_str())
        else {
            continue;
        };
        let directory = Path::new(manifest)
            .parent()
            .ok_or_else(|| format!("{manifest}: names no directory"))?
            .to_owned();
        members.insert(name.to_owned(), directory);
    }
    if members.is_empty() {
        return Err("cargo metadata --no-deps listed no workspace member".into());
    }
    Ok(members)
}

/// The package name inside a cargo package id.
///
/// Cargo writes `path+file:///…/<directory>#<name>@<version>` when the directory and the
/// package name differ — `services/sts#mandate-sts@0.2.0` — and
/// `path+file:///…/<name>#<version>` when they do not. Reading the directory in both cases
/// would call `mandate-sts` `sts`, and every test id of that package would name a package
/// nothing builds.
fn package_name(id: &str) -> String {
    let (path, tail) = id.split_once('#').unwrap_or((id, ""));
    match tail.split_once('@') {
        Some((name, _)) => name.to_owned(),
        None => path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .to_owned(),
    }
}

/// The step: the manifest and compiled model of `root`, against this workspace's store and
/// this workspace's compiled test binaries.
///
/// # Errors
///
/// Every failure the manifest holds, one per line, rather than the first: one run names the
/// whole correction.
pub fn coverage(root: &Path) -> Result<String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root")?;
    let blocked = store_blocked(workspace)?;
    let compiled = compiled(workspace)?;
    decide(root, workspace, &blocked, compiled)
}

/// Every check, with the store's answer and the compiled set supplied.
///
/// # Errors
///
/// Every failure the manifest holds, one per line.
pub fn decide(
    root: &Path,
    workspace: &Path,
    blocked: &[Blocker],
    compiled: &Compiled,
) -> Result<String> {
    let path = root.join("contracts/coverage.json");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let manifest: Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    if manifest["format"] != FORMAT {
        return Err(format!(
            "{}: {} is not the coverage manifest format {FORMAT}",
            path.display(),
            manifest["format"]
        )
        .into());
    }
    let entries = manifest["entries"]
        .as_array()
        .ok_or_else(|| format!("{}: the manifest states no entries", path.display()))?;

    let mut problems: Vec<String> = Vec::new();

    // The form the three crates that cannot parse JSON read. An entry that shares a line with
    // another is an entry those three never see, and a check that selects nothing exits 0.
    let on_own_line = text
        .lines()
        .filter(|line| line.starts_with("{\"element\":\""))
        .count();
    if on_own_line != entries.len() {
        problems.push(format!(
            "{}: the manifest is not written one entry to a line — {on_own_line} of {} entries \
             open a line, and `mandate-authz`, `mandate-graph` and `mandate-policy` read their \
             own entries as lines",
            path.display(),
            entries.len()
        ));
    }

    accounting(compiled, &mut problems);
    agreements(compiled, &mut problems);

    let declared = model(root)?;
    let store: BTreeMap<&str, &Blocker> = blocked.iter().map(|b| (b.id.as_str(), b)).collect();
    let stories = workspace.join(".engineering/planning/story");

    let mut named: BTreeMap<String, usize> = BTreeMap::new();
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for entry in entries {
        let Some(element) = entry["element"].as_str() else {
            problems.push(format!("{}: an entry names no element", path.display()));
            continue;
        };
        *named.entry(element.to_owned()).or_default() += 1;
        let Some(status) = entry["status"].as_str().filter(|s| STATUSES.contains(s)) else {
            problems.push(format!("{element}: {} is no status", entry["status"]));
            continue;
        };
        *counts
            .entry((
                entry["kind"].as_str().unwrap_or_default().to_owned(),
                status.to_owned(),
            ))
            .or_default() += 1;

        match declared.get(element) {
            None => problems.push(format!(
                "{element}: an entry for an element the compiled model does not declare"
            )),
            Some(kind) if entry["kind"] != *kind => problems.push(format!(
                "{element}: the entry calls it a {}, the compiled model declares a {kind}",
                entry["kind"]
            )),
            Some(_) => {}
        }

        let story = entry["story"].as_str().unwrap_or_default();
        match story.strip_prefix("story:") {
            None => problems.push(format!("{element}: {story:?} is no story id")),
            Some(name) if !stories.join(format!("{name}.md")).is_file() => problems.push(format!(
                "{element}: names {story}, which the planning store does not hold"
            )),
            Some(name) if status != "implemented" => {
                if let Some(rung) = terminal_rung(&stories.join(format!("{name}.md"))) {
                    problems.push(format!(
                        "{element}: {status} on {story}, which the store reports `{rung}`, a \
                         terminal rung; the map answers \"who implements this\" with work \
                         that is over"
                    ));
                }
            }
            Some(_) => {}
        }
        let held: Vec<&str> = store
            .values()
            .filter(|blocker| blocker.status == "open" && blocker.blocks.contains(story))
            .map(|blocker| blocker.id.as_str())
            .collect();

        match status {
            "implemented" => implemented(entry, element, compiled, &mut problems),
            _ => unimplemented_entry(entry, element, status, &held, &store, &mut problems),
        }
    }

    states_follow_records(entries, &mut problems);

    for (element, entries) in &named {
        if *entries > 1 {
            problems.push(format!(
                "{element}: {entries} entries name this element; one declared element has one \
                 realizer"
            ));
        }
    }
    for element in declared.keys() {
        if !named.contains_key(element) {
            problems.push(format!(
                "{element}: the compiled model declares it and the manifest has no entry for it"
            ));
        }
    }

    if !problems.is_empty() {
        return Err(problems.join("\n").into());
    }
    Ok(table(&counts, entries.len()))
}

/// The name every per-crate manifest case shares, whichever half of the account it decides.
const MANIFEST_CASE: &str = "the_coverage_manifest_names_exactly_what_this_crate_";

/// [`ACCOUNTING_CRATES`] is exactly the set of crates that run a per-crate manifest case.
///
/// The list is what lets an `implemented` entry name a crate, so a hand-maintained list is
/// the defect and a missing entry only its symptom. Both directions are therefore decided
/// against the compiled test set rather than against this file: a crate named here that
/// stopped running its case would let every entry it holds through unreconciled — the exact
/// silent pass this step exists to refuse — and a crate that started running one and is not
/// named here would have its entries refused as belonging to a crate that reconciles nothing.
fn accounting(compiled: &Compiled, problems: &mut Vec<String>) {
    let running: BTreeSet<&str> = compiled
        .tests
        .iter()
        .filter(|id| {
            id.rsplit("::")
                .next()
                .is_some_and(|case| case.starts_with(MANIFEST_CASE))
        })
        .filter_map(|id| id.split("::").next())
        .collect();
    let listed: BTreeSet<&str> = ACCOUNTING_CRATES.iter().copied().collect();
    for crate_name in listed.difference(&running) {
        problems.push(format!(
            "{crate_name}: named as a crate an implemented entry may claim, and no compiled \
             test binary lists a {MANIFEST_CASE}… case for it; its entries reconcile against \
             nothing"
        ));
    }
    for crate_name in running.difference(&listed) {
        problems.push(format!(
            "{crate_name}: runs a {MANIFEST_CASE}… case and is not named in \
             ACCOUNTING_CRATES, so the manifest may name no entry for it"
        ));
    }
}

/// The crate ESS emits: the contract re-expressed as Rust, one shape per declared element.
///
/// It is a member of this workspace and therefore passes "the root is a crate of ours",
/// which is why it is named here. A shape the compiler writes for **every** declared element
/// distinguishes nothing between an element something implements and one nothing does, so an
/// entry whose implementation is that shape is a claim with no content — and 23 derived
/// `.State` entries were exactly that claim.
/// The story's frontmatter `status:` when it is a terminal rung of the story lifecycle.
///
/// Read from the frontmatter only — the block between the first two `---` lines — so a
/// `status:` in the body is prose, not a claim.
fn terminal_rung(story: &Path) -> Option<String> {
    const TERMINAL: [&str; 3] = ["implemented", "archived", "rejected"];
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
            let value = value.trim();
            return TERMINAL.contains(&value).then(|| value.to_owned());
        }
    }
    None
}

/// A `.State` element follows its record (module doc, *What an entry states*): both branches
/// of the rule, decided over the manifest itself.
fn states_follow_records(entries: &[Value], problems: &mut Vec<String>) {
    let by_element: BTreeMap<&str, &Value> = entries
        .iter()
        .filter_map(|entry| entry["element"].as_str().map(|name| (name, entry)))
        .collect();
    for (element, entry) in &by_element {
        let Some(record) = element.strip_suffix(".State") else {
            continue;
        };
        if entry["status"] == "implemented" {
            continue;
        }
        let Some(held) = by_element.get(record) else {
            problems.push(format!(
                "{element}: a .State with no entry for its record {record}"
            ));
            continue;
        };
        if held["status"] == "implemented" {
            if entry["status"] != "declared" || !entry["blocker"].is_null() {
                problems.push(format!(
                    "{element}: its record is implemented and no crate registers its lifecycle \
                     enum, so it is `declared` on the story that will, with no blocker; the \
                     entry says {} on {} with blocker {}",
                    entry["status"], entry["story"], entry["blocker"]
                ));
            }
            continue;
        }
        for key in ["status", "story", "blocker"] {
            if entry[key] != held[key] {
                problems.push(format!(
                    "{element}: {key} {} against its record's {}",
                    entry[key], held[key]
                ));
            }
        }
    }
}

/// The per-crate case that reconciles a crate's `ESS_UNREALIZED` registry with the manifest.
const UNREALIZED_CLAUSE: &str = "no_unrealized_element_contradicts_the_coverage_manifest";

const GENERATED_CRATE: &str = "mandate_contract";

/// Every workspace member that holds a `tests/contract_agreement.rs` and is deliberately
/// **not** an accounting crate, with the reason it is not.
///
/// Empty, and that is the point: an agreement suite is the reconciliation an `implemented`
/// entry answers to, so a crate that runs one and reconciles no entry is a suite whose
/// result no coverage reader ever sees. `mandate-token` was exactly that — it round-tripped
/// `mandate.core.CredentialDescriptor` and `mandate.core.CredentialProfile` against the
/// generated shapes while the manifest reported both `deferred` on a blocker.
pub const AGREEMENT_ALLOWANCES: [(&str, &str); 0] = [];

/// Every workspace member holding a `tests/contract_agreement.rs`.
///
/// Read from the member list rather than from a directory walk with a name convention:
/// `services/sts` is the package `mandate-sts`, and a scan that took the directory name
/// would ask about a crate nothing builds.
#[must_use]
pub fn agreement_crates(compiled: &Compiled) -> BTreeSet<&str> {
    compiled
        .packages
        .iter()
        .filter(|(_, directory)| directory.join("tests/contract_agreement.rs").is_file())
        .map(|(package, _)| package.as_str())
        .collect()
}

/// A crate that runs an agreement suite either reconciles its own coverage entries or is
/// named, with a reason, as one that deliberately does not.
///
/// This is [`accounting`]'s rule read from the other end. That one refuses a crate named in
/// [`ACCOUNTING_CRATES`] whose case no binary lists; this one refuses a crate whose suite
/// exists and whose entries nothing reconciles, which is how `mandate-token` came to
/// round-trip two authored types while the manifest called them blocked.
fn agreements(compiled: &Compiled, problems: &mut Vec<String>) {
    let allowed: BTreeMap<&str, &str> = AGREEMENT_ALLOWANCES.iter().copied().collect();
    let holding = agreement_crates(compiled);
    if holding.is_empty() {
        problems.push(
            "no workspace member holds a tests/contract_agreement.rs, so the agreement check \
             selected nothing"
                .to_owned(),
        );
    }
    for package in &holding {
        if ACCOUNTING_CRATES.contains(package) {
            continue;
        }
        match allowed.get(package) {
            Some(reason) if !reason.trim().is_empty() => {}
            Some(_) => problems.push(format!(
                "{package}: allowed to run an agreement suite that reconciles no coverage \
                 entry, with no reason given"
            )),
            None => problems.push(format!(
                "{package}: runs a tests/contract_agreement.rs and is neither an accounting \
                 crate nor named in AGREEMENT_ALLOWANCES with a reason, so whatever its \
                 agreement suite decides, no entry of the manifest answers to it"
            )),
        }
    }
    for (package, _) in AGREEMENT_ALLOWANCES {
        if !holding.contains(package) {
            problems.push(format!(
                "{package}: named in AGREEMENT_ALLOWANCES and holds no \
                 tests/contract_agreement.rs; the allowance stands for nothing"
            ));
        }
    }
    for (package, directory) in &compiled.packages {
        let Ok(source) = fs::read_to_string(directory.join("src/lib.rs")) else {
            continue;
        };
        if !source.contains("pub const ESS_UNREALIZED") {
            continue;
        }
        let suite =
            fs::read_to_string(directory.join("tests/contract_agreement.rs")).unwrap_or_default();
        if !suite.contains(UNREALIZED_CLAUSE) {
            problems.push(format!(
                "{package}: declares ESS_UNREALIZED and its agreement suite never runs \
                 `{UNREALIZED_CLAUSE}`, so its statement that it realizes none of those \
                 elements is an account no gate reads"
            ));
        }
    }
}

/// The checks an `implemented` entry carries.
fn implemented(entry: &Value, element: &str, compiled: &Compiled, problems: &mut Vec<String>) {
    let owner = entry["crate"].as_str().unwrap_or_default();
    match entry["crate"].as_str() {
        None => problems.push(format!(
            "{element}: implemented and names no crate; a claim nothing reconciles"
        )),
        Some(name) if !ACCOUNTING_CRATES.contains(&name) => problems.push(format!(
            "{element}: implemented by {name}, which runs no manifest case; an implemented \
             entry names a crate that reconciles its own entries"
        )),
        Some(_) => {}
    }

    let symbols = entry["impl"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if symbols.is_empty() {
        problems.push(format!(
            "{element}: implemented and names no symbol that implements it"
        ));
    }
    for symbol in symbols {
        let symbol = symbol.as_str().unwrap_or_default();
        let root = symbol.split("::").next().unwrap_or_default();
        if symbol.split("::").any(str::is_empty) {
            problems.push(format!("{element}: {symbol:?} is no symbol path"));
        } else if root == GENERATED_CRATE {
            problems.push(format!(
                "{element}: {symbol} is the generated projection of the contract; ESS emits \
                 one shape per declared element, so it implements none of them"
            ));
        } else if root != "crate" && !compiled.crates.contains(root) {
            problems.push(format!(
                "{element}: {symbol} names {root}, which is no member of this workspace"
            ));
        }
    }

    let tests = entry["tests"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if tests.is_empty() {
        problems.push(format!(
            "{element}: implemented and names no test that decides it"
        ));
    }
    let mut own = false;
    for test in tests {
        let test = test.as_str().unwrap_or_default();
        if !compiled.tests.contains(test) {
            problems.push(format!(
                "{element}: names the test {test}, which no compiled test binary lists and \
                 runs"
            ));
        }
        if test.split("::").next() == Some(owner) {
            own = true;
        }
    }
    if !tests.is_empty() && !own {
        problems.push(format!(
            "{element}: implemented by {owner} and names no test of that package; a check \
             that decides an element is run by the crate that implements it, and existence \
             alone lets any id in the workspace satisfy any element"
        ));
    }
}

/// The checks a `declared` or `deferred` entry carries.
fn unimplemented_entry(
    entry: &Value,
    element: &str,
    status: &str,
    held: &[&str],
    store: &BTreeMap<&str, &Blocker>,
    problems: &mut Vec<String>,
) {
    for (key, what) in [
        ("crate", "a crate"),
        ("impl", "a symbol"),
        ("tests", "a test"),
    ] {
        let empty = entry[key].is_null() || entry[key].as_array().is_some_and(Vec::is_empty);
        if !empty {
            problems.push(format!(
                "{element}: {status} and names {what} — a {status} element carries no \
                 implementation, and {} says it does",
                entry[key]
            ));
        }
    }
    if entry["reason"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        problems.push(format!("{element}: {status} with no reason"));
    }

    match status {
        "deferred" => {
            let blocker = entry["blocker"].as_str().unwrap_or_default();
            match store.get(blocker) {
                None => problems.push(format!(
                    "{element}: deferred on {blocker}, which `aep plan artifact blocked` does \
                     not report"
                )),
                Some(held_by) if held_by.status != "open" => problems.push(format!(
                    "{element}: deferred on {blocker}, which the store reports as `{}`, not \
                     `open`",
                    held_by.status
                )),
                Some(held_by)
                    if !held_by
                        .blocks
                        .contains(entry["story"].as_str().unwrap_or("")) =>
                {
                    problems.push(format!(
                        "{element}: deferred on {blocker}, which holds {} and not {}",
                        held_by
                            .blocks
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", "),
                        entry["story"]
                    ));
                }
                Some(_) => {}
            }
        }
        _ if !held.is_empty() => problems.push(format!(
            "{element}: declared, and the store reports {} holding its story; an element whose \
             owner is blocked is deferred",
            held.join(", ")
        )),
        _ => {}
    }
}

/// Every element the compiled model declares, with the kind a manifest entry writes for it.
fn model(root: &Path) -> Result<BTreeMap<String, &'static str>> {
    let path = root.join("generated/ir/system.json");
    let compiled: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut declared = BTreeMap::new();
    for (index, kind) in INDEXES {
        let elements = compiled[index]
            .as_object()
            .ok_or_else(|| format!("{}: no {index} index", path.display()))?;
        for element in elements.keys() {
            declared.insert(element.clone(), kind);
        }
    }
    Ok(declared)
}

/// The per-kind, per-status table the step prints.
fn table(counts: &BTreeMap<(String, String), usize>, entries: usize) -> String {
    let mut report = String::new();
    let mut totals = [0_usize; 3];
    report.push_str("kind     implemented  declared  deferred  total\n");
    for (_, kind) in INDEXES {
        let row: Vec<usize> = STATUSES
            .iter()
            .map(|status| {
                counts
                    .get(&((*kind).to_owned(), (*status).to_owned()))
                    .copied()
                    .unwrap_or_default()
            })
            .collect();
        for (total, count) in totals.iter_mut().zip(&row) {
            *total += count;
        }
        report.push_str(&format!(
            "{kind:<8} {:>11}  {:>8}  {:>8}  {:>5}\n",
            row[0],
            row[1],
            row[2],
            row.iter().sum::<usize>()
        ));
    }
    report.push_str(&format!(
        "{:<8} {:>11}  {:>8}  {:>8}  {:>5}\n",
        "all", totals[0], totals[1], totals[2], entries
    ));
    report.push_str(&format!(
        "{entries} contract elements mapped; {} implemented, {} declared, {} deferred",
        totals[0], totals[1], totals[2]
    ));
    report
}
