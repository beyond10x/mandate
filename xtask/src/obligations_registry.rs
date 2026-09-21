//! The gate's reader for `contracts/obligations/`: every external denial clause an implemented
//! command can produce, mapped to the real-path test that decides it.
//!
//! `contracts/coverage.json` answers "does anything implement this command, and does any test
//! decide it" — one row per element, and a command whose declared refusal names six conditions
//! is `implemented` there the moment one of them is driven. The question a denial contract is
//! read for is the other one: whether **each** condition it publishes is one something refuses
//! on. Splitting the declared cause into its clauses is what makes the unrefused ones
//! countable, and a count is the only thing that can fall.
//!
//! Eleven things are decided here, and deliberately no more:
//!
//! 1. the directory holds one document per crate in [`CRATES`] and nothing else, each naming
//!    its own crate and [`FORMAT`];
//! 2. the documents' `domains` partition every domain the compiled model gives a command to,
//!    so every command has exactly one document and none has two;
//! 3. the command set is the compiled model's, both ways, and an `implemented` command sits in
//!    the document whose crate `contracts/coverage.json` names for it — which is what keeps the
//!    partition from being arbitrary where it decides anything;
//! 4. a command's status may not disagree with that manifest, and a command the manifest does
//!    not call `implemented` is `deferred` here on the manifest's own story and blocker, with
//!    no clause: there is no implementation for a clause to be a claim about;
//! 5. every clause is a **verbatim substring** of its command's declared `condition.cause`;
//! 6. every test id is one a compiled binary **lists and runs** — an `#[ignore]`d case is
//!    subtracted by [`crate::coverage::compiled`] — and a clause, `no-state-change` or
//!    `addendum` row names a test of the document's own crate, because existence alone would
//!    let any id in the workspace satisfy any obligation. A `cases` row may name a test of that
//!    crate or of one of the two packages in [`WIRE`], which decide a security case at the
//!    wire, and of no other;
//! 7. every clause of an `implemented` command carries at least one `denial` row on the **real**
//!    path, or `blocked_on` a live story — never both, so the report's columns partition;
//! 8. a `path: double` row **never covers**, and one obligation carries rows of **one path
//!    only**. A double refuses because it was written to refuse, so a clause whose only
//!    evidence is a double has no evidence that the shipped path refuses at all; it is counted
//!    in its own column and still carries `blocked_on`. A double row beside a real row would be
//!    counted in neither column, so where two conditions of one clause have different deciders
//!    the clause is split into them;
//! 9. every `blocked_on` names a story the planning store holds whose frontmatter `status:` is
//!    not a terminal rung, or an open blocker. That is the rule the registry's acceptance turns
//!    on: once a binding story is `implemented`, every clause still deferred to it fails;
//! 10. every step of the addendum's resolution order (§5.2, steps 1–9) is named by at least one
//!     document, with the step's own line verbatim, and never twice in one document;
//! 11. every id in `tests/security/cases.json` is bound or deferred exactly once across the
//!     directory, and no row names an id that file does not carry.
//!
//! A `denial_audit` obligation is `deferred` for every implemented command while
//! `decision-blocker:audit-routing` is open, and is counted in neither the numerator nor the
//! denominator: an obligation nothing can discharge is not a gap in this crate's work.
//!
//! # Which checkout answers for what
//!
//! `root` is the checkout whose **registry, manifest, compiled model, corpus and addendum** are
//! read. The planning store and the compiled test binaries are always supplied by the caller
//! from this workspace: a copy must not be able to answer for itself. That is the rule
//! [`crate::coverage`] already applies, and it is what makes `Action::ObligationsRegistry
//! { root }` safe for the data mutants of `story:mutation-controls`.
use crate::coverage::Compiled;
use crate::documents::Blocker;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The registry format this step reads, and the only one.
pub const FORMAT: &str = "mandate-obligations/1";

/// The report format this step writes, and the only one.
pub const REPORT_FORMAT: &str = "mandate-obligations-report/1";

/// Every crate the registry holds a document for.
///
/// These are the crates `contracts/coverage.json` names as implementing a command. A crate that
/// starts implementing one and has no document here is refused by check 2 — its domain would be
/// a domain no document claims — so this list cannot quietly outlive the set it stands for.
pub const CRATES: [&str; 7] = [
    "mandate-authz",
    "mandate-federation",
    "mandate-graph",
    "mandate-identity",
    "mandate-model",
    "mandate-policy",
    "mandate-sts",
];

/// The kinds a row inside `clauses` may take.
const CLAUSE_KINDS: [&str; 3] = ["denial", "accepted", "precedence"];

/// The kind a row inside `no_state_change` takes.
const STATE_KIND: &str = "no-state-change";

/// The kind a row inside `denial_audit` takes.
const AUDIT_KIND: &str = "denial-audit";

/// The blocker that holds every command's audit obligation.
const AUDIT_BLOCKER: &str = "decision-blocker:audit-routing";

/// What decided a clause: the shipped path, or a stand-in for it.
const PATHS: [&str; 2] = ["real", "double"];

/// The two packages a `cases` row may name besides the entry's own crate.
///
/// A security scenario is decided where it is decided, and `pkce-missing` and `pkce-plain` are
/// decided at the wire — the request never reaches a handler. The allowance is these two and is
/// bounded here rather than left as "any package", which is the exemption round one had and
/// which let a case row of any crate answer for any other.
const WIRE: [&str; 2] = ["mandate-proto", "mandate-server"];

/// The report this step writes and byte-compares.
const REPORT: &str = "contracts/conformance/obligations-report.json";

/// The columns of the report, in the order they are written and printed.
const COLUMNS: [&str; 4] = ["clauses", "real_covered", "double_only", "deferred"];

/// The step: the registry of `root`, against this workspace's store and compiled test binaries.
///
/// # Errors
///
/// Every failure the registry holds, one per line, rather than the first: one run names the
/// whole correction.
pub fn obligations_registry(root: &Path) -> Result<String> {
    run(root, false)
}

/// The step, writing `contracts/conformance/obligations-report.json` rather than comparing it.
///
/// # Errors
///
/// Every failure the registry holds, one per line.
pub fn obligations_registry_write(root: &Path) -> Result<String> {
    run(root, true)
}

fn run(root: &Path, write: bool) -> Result<String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root")?;
    let blocked = crate::documents::store_blocked(workspace)?;
    let compiled = crate::coverage::compiled(workspace)?;
    decide(
        root,
        &workspace.join(".engineering/planning/story"),
        &blocked,
        compiled,
        write,
    )
}

/// Every check, with the store's story directory, the store's blockers and the compiled set
/// supplied.
///
/// # Errors
///
/// Every failure the registry holds, one per line.
pub fn decide(
    root: &Path,
    stories: &Path,
    blocked: &[Blocker],
    compiled: &Compiled,
    write: bool,
) -> Result<String> {
    let mut problems: Vec<String> = Vec::new();
    let documents = documents(root, &mut problems)?;
    let declared = model(root)?;
    let realized = realized(root)?;
    let order = resolution_order(root)?;
    let corpus = corpus(root)?;
    let open: BTreeSet<&str> = blocked
        .iter()
        .filter(|blocker| blocker.status == "open")
        .map(|blocker| blocker.id.as_str())
        .collect();
    let live = Live { stories, open };

    let owner = domains(&documents, &declared, &mut problems);
    let mut counts: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    let mut named: BTreeMap<String, usize> = BTreeMap::new();
    let mut steps: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    let mut bound: BTreeMap<String, usize> = BTreeMap::new();

    for (crate_name, document) in &documents {
        let row = counts.entry(crate_name.as_str()).or_default();
        for entry in document["commands"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let Some(command) = entry["command"].as_str() else {
                problems.push(format!("{crate_name}: an entry names no command"));
                continue;
            };
            *named.entry(command.to_owned()).or_default() += 1;
            let Some(declared) = declared.get(command) else {
                problems.push(format!(
                    "{command}: an entry for a command the compiled model does not declare"
                ));
                continue;
            };
            match owner.get(declared.domain.as_str()) {
                Some(held) if held != crate_name => problems.push(format!(
                    "{command}: filed with {crate_name}, whose domains do not hold \
                     {}; {held} claims that domain",
                    declared.domain
                )),
                _ => {}
            }
            command_entry(
                crate_name,
                command,
                entry,
                declared,
                realized.get(command),
                compiled,
                &live,
                row,
                &mut problems,
            );
        }

        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for entry in document["addendum"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let Some(step) = entry["step"].as_u64() else {
                problems.push(format!("{crate_name}: an addendum row names no step"));
                continue;
            };
            match order.get(&step) {
                None => problems.push(format!(
                    "{crate_name}: an addendum row names step {step}, which the resolution \
                     order does not have"
                )),
                Some(text) if entry["requirement"].as_str() != Some(text.as_str()) => problems
                    .push(format!(
                        "{crate_name}: addendum step {step} states {}, and the addendum's own \
                         line is {text:?}",
                        entry["requirement"]
                    )),
                Some(_) => {}
            }
            if !seen.insert(step) {
                problems.push(format!(
                    "{crate_name}: addendum step {step} is stated twice in one document"
                ));
            }
            steps.entry(step).or_default().insert(crate_name.as_str());
            obligation(
                &format!("{crate_name}: addendum step {step}"),
                entry,
                &CLAUSE_KINDS,
                &CLAUSE_KINDS,
                &[crate_name.as_str()],
                compiled,
                &live,
                &mut problems,
            );
        }

        for entry in document["cases"].as_array().map_or(&[][..], Vec::as_slice) {
            let Some(case) = entry["case"].as_str() else {
                problems.push(format!("{crate_name}: a case row names no case"));
                continue;
            };
            *bound.entry(case.to_owned()).or_default() += 1;
            if !corpus.contains(case) {
                problems.push(format!(
                    "{case}: a case row that names no case tests/security/cases.json holds"
                ));
            }
            // A security case is decided end to end, and `pkce-missing` and `pkce-plain` are
            // decided at the wire, so a case row may name a test of the entry's crate or of
            // one of the two wire packages — and of no other.
            obligation(
                &format!("case {case}"),
                entry,
                &CLAUSE_KINDS,
                &CLAUSE_KINDS,
                &[crate_name.as_str(), WIRE[0], WIRE[1]],
                compiled,
                &live,
                &mut problems,
            );
        }
    }

    for (command, entries) in &named {
        if *entries > 1 {
            problems.push(format!(
                "{command}: {entries} entries name this command; one command has one document"
            ));
        }
    }
    for command in declared.keys() {
        if !named.contains_key(command) {
            problems.push(format!(
                "{command}: the compiled model declares it and the registry has no entry for it"
            ));
        }
    }
    for (step, text) in &order {
        if !steps.contains_key(step) {
            problems.push(format!(
                "resolution order step {step}, {text:?}: no document names it, so the addendum \
                 requirement has no reader"
            ));
        }
    }
    for case in &corpus {
        if !bound.contains_key(case) {
            problems.push(format!(
                "{case}: tests/security/cases.json holds it and no document binds it"
            ));
        }
    }
    for (case, rows) in &bound {
        if *rows > 1 {
            problems.push(format!(
                "{case}: {rows} rows bind this case; one case has one row"
            ));
        }
    }

    let rendered = report(&counts);
    let path = root.join(REPORT);
    if write {
        fs::write(&path, &rendered).map_err(|error| format!("{}: {error}", path.display()))?;
    } else {
        let committed = fs::read_to_string(&path).unwrap_or_default();
        if committed != rendered {
            problems.push(format!(
                "{}: the committed report is not the one this registry produces; run cargo \
                 xtask obligations-registry --write",
                path.display()
            ));
        }
    }

    if !problems.is_empty() {
        return Err(problems.join("\n").into());
    }
    Ok(table(&counts))
}

/// What the store answers about a `blocked_on`.
struct Live<'a> {
    stories: &'a Path,
    open: BTreeSet<&'a str>,
}

impl Live<'_> {
    /// The reason `id` may not be deferred to, or `None` when it may.
    fn refusal(&self, id: &str) -> Option<String> {
        if let Some(name) = id.strip_prefix("story:") {
            let story = self.stories.join(format!("{name}.md"));
            if !story.is_file() {
                return Some(format!("{id}, which the planning store does not hold"));
            }
            return crate::coverage::terminal_rung(&story).map(|rung| {
                format!(
                    "{id}, which the store reports `{rung}`, a terminal rung; the work it \
                     defers to is over"
                )
            });
        }
        if id.contains("-blocker:") {
            return (!self.open.contains(id)).then(|| {
                format!("{id}, which `aep plan artifact blocked` does not report as `open`")
            });
        }
        Some(format!("{id}, which is no story id and no blocker id"))
    }
}

/// Every document the registry directory holds, by crate.
fn documents(root: &Path, problems: &mut Vec<String>) -> Result<Vec<(String, Value)>> {
    let directory = root.join("contracts/obligations");
    let mut held: BTreeSet<String> = BTreeSet::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".json") {
            held.insert(stem.to_owned());
        }
    }
    let mut documents = Vec::new();
    for crate_name in CRATES {
        let stem = crate_name.trim_start_matches("mandate-");
        held.remove(stem);
        let path = directory.join(format!("{stem}.json"));
        let text = fs::read_to_string(&path).map_err(|error| {
            format!(
                "{}: {error}; every crate in CRATES holds a document",
                path.display()
            )
        })?;
        let document: Value =
            serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if document["format"] != FORMAT {
            problems.push(format!(
                "{}: {} is not the obligations format {FORMAT}",
                path.display(),
                document["format"]
            ));
        }
        if document["crate"].as_str() != Some(crate_name) {
            problems.push(format!(
                "{}: the document names the crate {}, and its file name says {crate_name}",
                path.display(),
                document["crate"]
            ));
        }
        documents.push((crate_name.to_owned(), document));
    }
    for stem in held {
        problems.push(format!(
            "{}/{stem}.json: a document for a crate CRATES does not name, so whatever it \
             states, no reader of the registry answers to it",
            directory.display()
        ));
    }
    Ok(documents)
}

/// Every domain a document claims, by domain, with the two directions decided against the
/// compiled model.
fn domains<'a>(
    documents: &'a [(String, Value)],
    declared: &BTreeMap<String, Declared>,
    problems: &mut Vec<String>,
) -> BTreeMap<&'a str, &'a str> {
    let with_commands: BTreeSet<&str> = declared
        .values()
        .map(|command| command.domain.as_str())
        .collect();
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    for (crate_name, document) in documents {
        for domain in document["domains"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
        {
            let Some(domain) = domain.as_str() else {
                problems.push(format!("{crate_name}: a domain that is no name"));
                continue;
            };
            if let Some(held) = owner.insert(domain, crate_name.as_str()) {
                problems.push(format!(
                    "{domain}: claimed by {held} and by {crate_name}; one domain has one document"
                ));
            }
            if !with_commands.contains(domain) {
                problems.push(format!(
                    "{crate_name}: claims {domain}, which the compiled model gives no command"
                ));
            }
        }
    }
    for domain in &with_commands {
        if !owner.contains_key(domain) {
            problems.push(format!(
                "{domain}: the compiled model gives it a command and no document claims it"
            ));
        }
    }
    owner
}

/// What the compiled model declares about one command.
struct Declared {
    domain: String,
    cause: String,
}

/// Every command the compiled model declares, with its domain and its declared external cause.
fn model(root: &Path) -> Result<BTreeMap<String, Declared>> {
    let path = root.join("generated/ir/system.json");
    let compiled: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let commands = compiled["commands"]
        .as_object()
        .ok_or_else(|| format!("{}: no commands index", path.display()))?;
    let mut declared = BTreeMap::new();
    for (name, command) in commands {
        let cause = command["outcomes"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .find(|outcome| outcome["condition"]["kind"] == "external")
            .and_then(|outcome| outcome["condition"]["cause"].as_str())
            .ok_or_else(|| format!("{name}: declares no externally caused outcome with a cause"))?;
        declared.insert(
            name.clone(),
            Declared {
                domain: command["domain"].as_str().unwrap_or_default().to_owned(),
                cause: cause.to_owned(),
            },
        );
    }
    Ok(declared)
}

/// Every command entry of `contracts/coverage.json`, by element.
fn realized(root: &Path) -> Result<BTreeMap<String, Value>> {
    let path = root.join("contracts/coverage.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(manifest["entries"]
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .filter(|entry| entry["kind"] == "command")
        .filter_map(|entry| {
            entry["element"]
                .as_str()
                .map(|element| (element.to_owned(), entry.clone()))
        })
        .collect())
}

/// The addendum's §5.2 resolution order, by step, each line verbatim.
fn resolution_order(root: &Path) -> Result<BTreeMap<u64, String>> {
    let path = root.join("docs/sources/architecture-addendum.md");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let after = text
        .split_once("## 5.2 Resolution order")
        .ok_or_else(|| format!("{}: no §5.2 Resolution order", path.display()))?
        .1;
    let block = after
        .split("```")
        .nth(1)
        .ok_or_else(|| format!("{}: §5.2 states no resolution order", path.display()))?;
    let mut order = BTreeMap::new();
    for line in block.lines() {
        let line = line.trim();
        let Some((step, requirement)) = line.split_once(". ") else {
            continue;
        };
        if let Ok(step) = step.parse::<u64>() {
            order.insert(step, requirement.to_owned());
        }
    }
    if order.keys().copied().collect::<Vec<_>>() != (1..=9).collect::<Vec<_>>() {
        return Err(format!(
            "{}: §5.2 states steps {:?}, and the requirement is the nine of the resolution order",
            path.display(),
            order.keys().collect::<Vec<_>>()
        )
        .into());
    }
    Ok(order)
}

/// Every id in the security corpus.
fn corpus(root: &Path) -> Result<BTreeSet<String>> {
    let path = root.join("tests/security/cases.json");
    let corpus: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let cases: BTreeSet<String> = corpus["cases"]
        .as_array()
        .ok_or_else(|| format!("{}: states no cases", path.display()))?
        .iter()
        .filter_map(|case| case["id"].as_str().map(str::to_owned))
        .collect();
    if cases.is_empty() {
        return Err(format!("{}: states no case id", path.display()).into());
    }
    Ok(cases)
}

/// The checks one command entry carries, and its contribution to the crate's columns.
#[allow(clippy::too_many_arguments)]
fn command_entry(
    crate_name: &str,
    command: &str,
    entry: &Value,
    declared: &Declared,
    realized: Option<&Value>,
    compiled: &Compiled,
    live: &Live,
    counts: &mut [usize; 4],
    problems: &mut Vec<String>,
) {
    let status = entry["status"].as_str().unwrap_or_default();
    let manifest = realized.map_or("", |entry| entry["status"].as_str().unwrap_or_default());
    let implemented = manifest == "implemented";
    match (status, implemented) {
        ("implemented", true) | ("deferred", false) => {}
        _ => {
            problems.push(format!(
                "{command}: the coverage manifest reports it `{manifest}` and the registry says \
                 `{status}`; a command the manifest calls implemented is implemented here and \
                 any other status there is deferred here"
            ));
            return;
        }
    }

    if !implemented {
        let manifest = realized.expect("a status came from an entry");
        for key in ["story", "blocker"] {
            if entry[key].as_str() != manifest[key].as_str() {
                problems.push(format!(
                    "{command}: deferred on {key} {}, and the coverage manifest says {}",
                    entry[key], manifest[key]
                ));
            }
        }
        for key in ["clauses", "no_state_change"] {
            if !entry[key].as_array().is_some_and(Vec::is_empty) {
                problems.push(format!(
                    "{command}: deferred and states {key} {}; a deferred command has no \
                     implementation for a clause to be a claim about",
                    entry[key]
                ));
            }
        }
        if !entry["denial_audit"].is_null() {
            problems.push(format!(
                "{command}: deferred and states a denial_audit obligation"
            ));
        }
        return;
    }

    if let Some(manifest) = realized
        && manifest["crate"].as_str() != Some(crate_name)
    {
        problems.push(format!(
            "{command}: filed with {crate_name}, and the coverage manifest says {} implements it",
            manifest["crate"]
        ));
    }

    let binding = format!(
        "story:obligations-{}",
        crate_name.trim_start_matches("mandate-")
    );
    let clauses = entry["clauses"].as_array().map_or(&[][..], Vec::as_slice);
    if clauses.is_empty() {
        problems.push(format!(
            "{command}: implemented and states no clause of its declared denial"
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let stated: Vec<&str> = clauses
        .iter()
        .filter_map(|clause| clause["clause"].as_str())
        .collect();
    tiles(command, &declared.cause, &stated, problems);
    for clause in clauses {
        let Some(text) = clause["clause"].as_str() else {
            problems.push(format!("{command}: a clause that is no text"));
            continue;
        };
        if !declared.cause.contains(text) {
            problems.push(format!(
                "{command}: the clause {text:?} is no verbatim substring of its declared cause, \
                 so it states an obligation the contract does not publish"
            ));
        }
        if !seen.insert(text) {
            problems.push(format!("{command}: the clause {text:?} is stated twice"));
        }
        for other in &stated {
            if *other != text && other.contains(text) {
                problems.push(format!(
                    "{command}: the clause {text:?} lies inside its own clause {other:?}; a \
                     tiling has one clause per position of the cause, and two claim that \
                     position twice — the overlap is counted again in `clauses` and can be \
                     counted again in `real_covered` with no new condition decided"
                ));
            }
        }
        counts[0] += 1;
        let covered = obligation(
            &format!("{command}: {text:?}"),
            clause,
            &CLAUSE_KINDS,
            &["denial"],
            &[crate_name],
            compiled,
            live,
            problems,
        );
        match covered {
            Covered::Real => counts[1] += 1,
            Covered::Double => {
                counts[2] += 1;
                // A clause whose only evidence is a double has no shipped decider — that is
                // what `double` is defined to mean — so no test the crate's binding story can
                // write binds it. Deferring it there publishes an obligation as waiting on
                // work that cannot discharge it; the deferral names the story that owns the
                // port's real implementation.
                if clause["blocked_on"].as_str() == Some(binding.as_str()) {
                    problems.push(format!(
                        "{command}: the clause {text:?} is reached only by a double, so its \
                         deciding code is not shipped, and it defers to {binding}, which owns \
                         a test file; a double-backed clause defers to the story that owns the \
                         port's real implementation"
                    ));
                }
            }
            Covered::Neither => counts[3] += 1,
        }
    }

    obligation(
        &format!("{command}: no-state-change"),
        &no_state_change(entry),
        &[STATE_KIND],
        &[STATE_KIND],
        &[crate_name],
        compiled,
        live,
        problems,
    );

    // The audit of a refusal is an obligation nothing in this workspace can discharge while
    // the routing decision is open, so it is counted in neither column. The moment that
    // blocker closes the deferral stops being admitted and every command owes a real row —
    // the same transition the binding stories carry, decided against the store rather than
    // against a date.
    let audit = &entry["denial_audit"];
    if live.open.contains(AUDIT_BLOCKER) {
        if audit["status"] != "deferred" || audit["blocker"] != AUDIT_BLOCKER {
            problems.push(format!(
                "{command}: its denial_audit obligation states {} on {}, and every command's is \
                 deferred on {AUDIT_BLOCKER} while that blocker is open",
                audit["status"], audit["blocker"]
            ));
        }
        if !audit["tests"].as_array().is_some_and(Vec::is_empty) {
            problems.push(format!(
                "{command}: its denial_audit obligation is deferred and names {}; a deferred \
                 obligation is counted in neither column and may name no test",
                audit["tests"]
            ));
        }
    } else {
        obligation(
            &format!("{command}: denial-audit"),
            audit,
            &[AUDIT_KIND],
            &[AUDIT_KIND],
            &[crate_name],
            compiled,
            live,
            problems,
        );
    }
}

/// The command's `no_state_change` rows in the shape [`obligation`] reads, with the
/// command-level `blocked_on` as its deferral.
fn no_state_change(entry: &Value) -> Value {
    let mut obligation = serde_json::Map::new();
    obligation.insert("tests".to_owned(), entry["no_state_change"].clone());
    if !entry["blocked_on"].is_null() {
        obligation.insert("blocked_on".to_owned(), entry["blocked_on"].clone());
    }
    Value::Object(obligation)
}

/// Everything a cause may hold between two clauses, and nothing else.
///
/// The cause enumerates its conditions; what sits between them is punctuation and the words
/// that join a list. A run of anything else between two clauses is a condition the clause list
/// does not account for.
const JOINERS: [&str; 2] = ["or", "and"];

/// The clauses of one command, in order, account for every character of its declared cause
/// exactly once, apart from the separators that join them.
///
/// Each clause being *a* substring of the cause is the weaker half of the rule and the only
/// half round one had a reader for. It admits a clause list that has quietly lost one: the
/// condition stops being published, `clauses` and `deferred` both fall, and the run exits 0 —
/// the count falling by deletion rather than by work, which is the one move this file exists
/// to prevent. It equally admits a clause nested inside another, which claims one position of
/// the cause twice and can raise `real_covered` with nothing new decided.
///
/// The walk is therefore positional: each clause is found **after** the one before it, and the
/// gap between them, the head before the first and the tail after the last, must each be
/// nothing but separators. An unaccounted run is quoted, so the refusal names the condition
/// that went missing rather than the clause that is still there.
fn tiles(command: &str, cause: &str, clauses: &[&str], problems: &mut Vec<String>) {
    let mut cursor = 0_usize;
    for text in clauses {
        let Some(offset) = cause[cursor..].find(text) else {
            problems.push(format!(
                "{command}: the clause {text:?} has no occurrence in its declared cause after \
                 the clause before it; the clauses of a command tile its cause in the order \
                 the cause states them, and a clause that lies inside or before its \
                 predecessor claims a position twice"
            ));
            return;
        };
        separators(command, &cause[cursor..cursor + offset], problems);
        cursor += offset + text.len();
    }
    separators(command, &cause[cursor..], problems);
}

/// One run between two clauses: separators only, or the condition it holds is named.
fn separators(command: &str, run: &str, problems: &mut Vec<String>) {
    let unaccounted: String = run
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | ';' | '/' | '.')
        })
        .filter(|word| !word.is_empty() && !JOINERS.contains(word))
        .collect::<Vec<&str>>()
        .join(" ");
    if !unaccounted.is_empty() {
        problems.push(format!(
            "{command}: its declared cause states {run:?}, which no clause accounts for — the \
             clause list does not tile the cause, so the obligation {unaccounted:?} is \
             published by the contract and by nothing in this registry"
        ));
    }
}

/// What covers one obligation.
enum Covered {
    Real,
    Double,
    Neither,
}

/// The rows of one obligation — a clause, a no-state-change, an addendum step, a case — and the
/// rule that it is covered on the real path or deferred to live work, never both and never
/// neither.
#[allow(clippy::too_many_arguments)]
fn obligation(
    what: &str,
    entry: &Value,
    kinds: &[&str],
    covers: &[&str],
    owners: &[&str],
    compiled: &Compiled,
    live: &Live,
    problems: &mut Vec<String>,
) -> Covered {
    let rows = entry["tests"].as_array().map_or(&[][..], Vec::as_slice);
    let mut real = false;
    let mut double = false;
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    for row in rows {
        let id = row["id"].as_str().unwrap_or_default();
        if !compiled.tests.contains(id) {
            problems.push(format!(
                "{what}: names the test {id}, which no compiled test binary lists and runs"
            ));
        } else if !owners.contains(&id.split("::").next().unwrap_or_default()) {
            problems.push(format!(
                "{what}: names the test {id}, and this row is decided by a test {} runs; \
                 existence alone lets any id in the workspace satisfy any obligation",
                owners.join(" or ")
            ));
        }
        let kind = row["kind"].as_str().unwrap_or_default();
        if !kinds.contains(&kind) {
            problems.push(format!(
                "{what}: the row {id} is a {kind}, and this obligation admits {}",
                kinds.join(", ")
            ));
        }
        let path = row["path"].as_str().unwrap_or_default();
        if !PATHS.contains(&path) {
            problems.push(format!("{what}: the row {id} states the path {path:?}"));
        }
        match (path, row["double"].as_str()) {
            ("double", None | Some("")) => problems.push(format!(
                "{what}: the row {id} is on the double path and names no double"
            )),
            ("real", Some(double)) => problems.push(format!(
                "{what}: the row {id} is on the real path and names the double {double}"
            )),
            _ => {}
        }
        if PATHS.contains(&path) {
            paths.insert(path);
        }
        if covers.contains(&kind) {
            match path {
                "real" => real = true,
                "double" => double = true,
                _ => {}
            }
        }
    }

    // A double row belongs where the real path does not cover. Absorbed into an obligation a
    // real row already covers it is counted in no column at all — neither `real_covered`, which
    // the real row already holds, nor `double_only` — so the condition it stands in for is
    // published as decided on the real path. That is the shape this step exists to refuse: a
    // green exit from a check that counted nothing. One obligation therefore carries rows of
    // one path only.
    if paths.len() > 1 {
        let doubles: Vec<&str> = rows
            .iter()
            .filter(|row| row["path"] == "double")
            .filter_map(|row| row["id"].as_str())
            .collect();
        problems.push(format!(
            "{what}: carries rows on both paths — the double row(s) {} sit beside a real row. A \
             double row belongs where the real path does not cover; where two conditions of one \
             clause have different deciders, the clause is split into them",
            doubles.join(", ")
        ));
    }

    let deferral = entry["blocked_on"].as_str();
    match (real, deferral) {
        (true, Some(id)) => problems.push(format!(
            "{what}: covered on the real path by {} row(s) and deferred to {id}; a covered \
             obligation is not also a gap",
            rows.len()
        )),
        (false, None) => problems.push(format!(
            "{what}: no row decides it on the real path and it defers to nothing. A double \
             refuses because it was written to refuse, so it never covers; state blocked_on \
             the story that will bind it"
        )),
        (false, Some(id)) => {
            if let Some(reason) = live.refusal(id) {
                problems.push(format!("{what}: deferred to {reason}"));
            }
        }
        (true, None) => {}
    }

    if real {
        Covered::Real
    } else if double {
        Covered::Double
    } else {
        Covered::Neither
    }
}

/// The report, written one crate to a line so a reader of the diff sees which column moved.
fn report(counts: &BTreeMap<&str, [usize; 4]>) -> String {
    let mut totals = [0_usize; 4];
    let mut rows = Vec::new();
    for crate_name in CRATES {
        let row = counts.get(crate_name).copied().unwrap_or_default();
        for (total, count) in totals.iter_mut().zip(row) {
            *total += count;
        }
        rows.push(format!("    \"{crate_name}\": {}", object(&row)));
    }
    format!(
        "{{\n  \"format\": \"{REPORT_FORMAT}\",\n  \"crates\": {{\n{}\n  }},\n  \"totals\": {}\n}}\n",
        rows.join(",\n"),
        object(&totals)
    )
}

fn object(row: &[usize; 4]) -> String {
    let fields: Vec<String> = COLUMNS
        .iter()
        .zip(row)
        .map(|(column, count)| format!("\"{column}\": {count}"))
        .collect();
    format!("{{{}}}", fields.join(", "))
}

/// The per-crate table the step prints.
fn table(counts: &BTreeMap<&str, [usize; 4]>) -> String {
    let mut totals = [0_usize; 4];
    let mut report = String::from("crate               clauses  real  double  deferred\n");
    for crate_name in CRATES {
        let row = counts.get(crate_name).copied().unwrap_or_default();
        for (total, count) in totals.iter_mut().zip(row) {
            *total += count;
        }
        report.push_str(&format!(
            "{crate_name:<18} {:>8}  {:>4}  {:>6}  {:>8}\n",
            row[0], row[1], row[2], row[3]
        ));
    }
    report.push_str(&format!(
        "{:<18} {:>8}  {:>4}  {:>6}  {:>8}\n",
        "all", totals[0], totals[1], totals[2], totals[3]
    ));
    report.push_str(&format!(
        "{} external denial clauses; {} decided on the real path, {} reached only by a double, \
         {} deferred",
        totals[0], totals[1], totals[2], totals[3]
    ));
    report
}
