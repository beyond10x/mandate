//! Adversary pass 1 against `story:obligation-registry`: the registry read as the document it
//! claims to be, driven against the step and the data the same unit shipped.
//!
//! Every case here states a rule `contracts/obligations/README.md` or the story's amended
//! Acceptance states in its own words, and decides it against the committed registry or a
//! doctored copy of it. The fixture pattern is `xtask/tests/obligations_registry.rs`'s: what
//! the step reads is copied into a scratch root under `target/`, one thing is changed, and the
//! same entry point is driven at that root with the seven binding stories written beside this
//! workspace's own store.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/coverage.rs"]
mod coverage;
#[path = "../src/obligations_registry.rs"]
mod obligations_registry;
#[path = "../src/receipt.rs"]
mod receipt;

use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// The seven binding stories the rulings create, as the store will hold them: `status: draft`,
/// which is not a terminal rung.
const BINDING: [&str; 7] = [
    "authz",
    "federation",
    "graph",
    "identity",
    "model",
    "policy",
    "sts",
];

/// A story directory: this workspace's own store, plus the seven binding stories.
fn stories(root: &Path) -> PathBuf {
    let directory = root.join("story");
    fs::create_dir_all(&directory).expect("fixture story directory");
    for entry in fs::read_dir(repo().join(".engineering/planning/story")).expect("the store") {
        let entry = entry.expect("a story");
        fs::copy(entry.path(), directory.join(entry.file_name())).expect("copy a story");
    }
    for name in BINDING {
        fs::write(
            directory.join(format!("obligations-{name}.md")),
            format!(
                "---\nformat: aep.planning-md/1\nid: story:obligations-{name}\nkind: story\n\
                 status: draft\ntitle: Bind mandate-{name}'s denial clauses to real-path tests\n\
                 ---\n"
            ),
        )
        .expect("write a binding story");
    }
    directory
}

/// A root holding exactly what the step reads from one.
fn fixture(name: &str) -> PathBuf {
    let root = repo()
        .join("target/xtask-adversary-obligations-1")
        .join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    for directory in [
        "contracts/obligations",
        "contracts/conformance",
        "generated/ir",
        "tests/security",
        "docs/sources",
    ] {
        fs::create_dir_all(root.join(directory)).expect("fixture directory");
    }
    for file in [
        "contracts/coverage.json",
        "contracts/conformance/obligations-report.json",
        "generated/ir/system.json",
        "tests/security/cases.json",
        "docs/sources/architecture-addendum.md",
    ] {
        fs::copy(repo().join(file), root.join(file)).expect("copy what the step reads");
    }
    for entry in fs::read_dir(repo().join("contracts/obligations")).expect("the registry") {
        let entry = entry.expect("a registry document");
        fs::copy(
            entry.path(),
            root.join("contracts/obligations").join(entry.file_name()),
        )
        .expect("copy a registry document");
    }
    root
}

fn document(root: &Path, crate_short: &str) -> Value {
    let path = root.join(format!("contracts/obligations/{crate_short}.json"));
    serde_json::from_str(&fs::read_to_string(&path).expect("the document")).expect("valid JSON")
}

fn write_document(root: &Path, crate_short: &str, document: &Value) {
    let path = root.join(format!("contracts/obligations/{crate_short}.json"));
    let mut text = serde_json::to_string_pretty(document).expect("serialize");
    text.push('\n');
    fs::write(path, text).expect("write the document");
}

fn run(root: &Path) -> std::result::Result<String, String> {
    let workspace = repo();
    let blocked = documents::store_blocked(&workspace).expect("the store answers");
    let compiled = coverage::compiled(&workspace).expect("the workspace test set");
    obligations_registry::decide(
        root,
        &stories(&root.join("planning")),
        &blocked,
        compiled,
        false,
    )
    .map_err(|error| error.to_string())
}

/// The committed registry, by crate.
fn registry() -> Vec<(String, Value)> {
    let directory = repo().join("contracts/obligations");
    let mut documents = Vec::new();
    for entry in fs::read_dir(&directory).expect("the registry directory") {
        let entry = entry.expect("a registry entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        let text = fs::read_to_string(entry.path()).expect("a registry document");
        let value: Value = serde_json::from_str(&text).expect("valid JSON");
        documents.push((value["crate"].as_str().expect("a crate").to_owned(), value));
    }
    documents.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(documents.len(), 7, "seven documents");
    documents
}

fn rows(value: &Value) -> &[Value] {
    value.as_array().map_or(&[][..], Vec::as_slice)
}

/// A clause is covered on the real path exactly as `obligations_registry::obligation` decides
/// it: a `denial` row whose `path` is `real`.
fn covered_real(clause: &Value) -> bool {
    rows(&clause["tests"])
        .iter()
        .any(|row| row["kind"] == "denial" && row["path"] == "real")
}

fn holds_double(clause: &Value) -> bool {
    rows(&clause["tests"])
        .iter()
        .any(|row| row["path"] == "double")
}

/// `contracts/obligations/README.md`, *A test row*:
///
/// > **A `double` row never covers a clause.** It is counted in its own column of the report
/// > and the clause still carries `blocked_on`.
///
/// Both halves are false of a clause that holds a `double` row *and* a covering `real` denial
/// row: the step returns `Covered::Real` for it, so the double is counted in no column of
/// `contracts/conformance/obligations-report.json`, and the `(true, Some(id))` arm forbids the
/// `blocked_on` the README says the clause still carries. The committed registry holds such a
/// clause.
#[test]
fn a_clause_holding_a_double_row_is_counted_in_the_double_column_and_carries_blocked_on() {
    let mut swallowed = Vec::new();
    for (crate_name, document) in registry() {
        for entry in rows(&document["commands"]) {
            if entry["status"] != "implemented" {
                continue;
            }
            for clause in rows(&entry["clauses"]) {
                if !holds_double(clause) {
                    continue;
                }
                if covered_real(clause) || clause["blocked_on"].as_str().is_none() {
                    let doubles: Vec<&str> = rows(&clause["tests"])
                        .iter()
                        .filter(|row| row["path"] == "double")
                        .filter_map(|row| row["id"].as_str())
                        .collect();
                    swallowed.push(format!(
                        "{crate_name} / {} / {:?}: real_covered={}, blocked_on={}, \
                         double row(s) counted in no column: {doubles:?}",
                        entry["command"].as_str().unwrap_or_default(),
                        clause["clause"].as_str().unwrap_or_default(),
                        covered_real(clause),
                        clause["blocked_on"]
                    ));
                }
            }
        }
    }
    assert!(
        swallowed.is_empty(),
        "a `double` row never covers a clause, is counted in its own column of the report and \
         leaves the clause carrying `blocked_on` (contracts/obligations/README.md, *A test \
         row*). These double rows are counted in neither `real_covered` nor `double_only`, and \
         the condition they stand in for is counted as decided on the real path:\n  {}",
        swallowed.join("\n  ")
    );
}

/// The report's `double_only` column counts every clause a `double` row backs.
///
/// `contracts/conformance/obligations-report.json` is what a reader of the conformance target
/// reads instead of the seven documents, and the README says the three columns partition the
/// clauses with a double-backed clause landing in `double_only`. A double row absorbed into a
/// `real_covered` clause is in none of the three, so the published total is not the number of
/// clauses whose only evidence for some condition is a double.
#[test]
fn the_reports_double_only_total_is_the_number_of_clauses_a_double_row_backs() {
    let mut backed = 0_usize;
    for (_, document) in registry() {
        for entry in rows(&document["commands"]) {
            if entry["status"] != "implemented" {
                continue;
            }
            backed += rows(&entry["clauses"])
                .iter()
                .filter(|clause| holds_double(clause))
                .count();
        }
    }
    let report: Value = serde_json::from_str(
        &fs::read_to_string(repo().join("contracts/conformance/obligations-report.json"))
            .expect("the committed report"),
    )
    .expect("valid JSON");
    let published = report["totals"]["double_only"]
        .as_u64()
        .expect("a double_only total") as usize;
    assert_eq!(
        published, backed,
        "the committed report publishes double_only={published}, and {backed} clauses of \
         implemented commands hold a `path: double` row; the difference is the double row(s) \
         sitting inside a clause a real row already covers, which are counted in no column"
    );
}

/// The story's amended Acceptance (2026-09-19):
///
/// > … **every named test is compiled and runs and belongs to the entry's crate** …
///
/// The step applies that rule to `clauses` and `no_state_change` rows and exempts `addendum`
/// and `cases` rows from it (`obligations_registry.rs:237-247`, `:265-275`, both passing
/// `same_crate: false`). The exemption is stated in the README, not in the Acceptance, and the
/// committed registry uses it.
#[test]
fn every_test_the_registry_names_belongs_to_the_entry_crate() {
    let mut elsewhere = Vec::new();
    for (crate_name, document) in registry() {
        // Coordinator amendment (Acceptance amended 2026-09-21): a `cases` row may name a test
        // of the two packages that decide a security case at the wire, and no other.
        let mut check = |what: String, tests: &Value, wire: bool| {
            for row in rows(tests) {
                let id = row["id"].as_str().unwrap_or_default();
                let package = id.split("::").next().unwrap_or_default();
                let admitted = package == crate_name
                    || (wire && (package == "mandate-proto" || package == "mandate-server"));
                if !admitted {
                    elsewhere.push(format!("{what}: {id}"));
                }
            }
        };
        for entry in rows(&document["commands"]) {
            let command = entry["command"].as_str().unwrap_or_default();
            for clause in rows(&entry["clauses"]) {
                check(
                    format!("{crate_name} / {command} / clause"),
                    &clause["tests"],
                    false,
                );
            }
            check(
                format!("{crate_name} / {command} / no_state_change"),
                &entry["no_state_change"],
                false,
            );
        }
        for entry in rows(&document["addendum"]) {
            check(
                format!("{crate_name} / addendum step {}", entry["step"]),
                &entry["tests"],
                false,
            );
        }
        for entry in rows(&document["cases"]) {
            check(
                format!(
                    "{crate_name} / case {}",
                    entry["case"].as_str().unwrap_or_default()
                ),
                &entry["tests"],
                true,
            );
        }
    }
    assert!(
        elsewhere.is_empty(),
        "every named test belongs to the entry's crate (story:obligation-registry, Acceptance \
         amended 2026-09-21: a cases row may also name mandate-proto or mandate-server). These \
         rows name a test of a package the amended rule does not admit:\n  {}",
        elsewhere.join("\n  ")
    );
}

/// The same rule, driven through the step rather than read off the data.
///
/// A `double` row added to a clause a real row already covers changes nothing the step
/// decides: the clause stays `Covered::Real`, no column moves, so the committed report still
/// matches and the run is accepted. The README's rule — a double row is counted in its own
/// column — has no reader, which is why the row already in `graph.json` passes.
#[test]
fn the_step_refuses_a_double_row_added_to_a_clause_a_real_row_already_covers() {
    let root = fixture("double-inside-a-covered-clause");
    let mut graph = document(&root, "graph");
    let at = rows(&graph["commands"])
        .iter()
        .position(|entry| entry["command"] == "mandate.graph.WriteRelationship")
        .expect("WriteRelationship has an entry");
    // The precondition is built here rather than read out of the committed document. Which
    // clauses a crate covers on the real path is a thing a ruling moves — after
    // `review-result:wave-d-obligations-graph-adversary-2` this command covers none, every
    // decider behind it being a port `mandate_graph::double::GraphDouble` is the only
    // implementor of — and a case that searches the shipped data for its own precondition
    // measures that data, not the rule it exists to decide.
    let clause = 0;
    let name = graph["commands"][at]["clauses"][clause]["clause"].clone();
    graph["commands"][at]["clauses"][clause]["tests"] = json!([
        {
            "id": "mandate-graph::obligations::a_relationship_write_on_another_organizations_resource_is_a_tenant_mismatch",
            "kind": "denial",
            "path": "real"
        },
        {
            "id": "mandate-graph::double::a_parent_that_does_not_resolve_is_denied",
            "kind": "denial",
            "path": "double",
            "double": "mandate_graph::double::GraphDouble"
        }
    ]);
    // A clause a real row covers carries no deferral; leaving one would refuse the run for
    // the other reason and the case would pass having measured nothing.
    graph["commands"][at]["clauses"][clause]
        .as_object_mut()
        .expect("a clause is an object")
        .remove("blocked_on");
    assert!(
        covered_real(&graph["commands"][at]["clauses"][clause]),
        "the fixture states the precondition: a clause a real row covers"
    );
    write_document(&root, "graph", &graph);

    let error = match run(&root) {
        Ok(report) => panic!(
            "a `double` row was added to the clause {name} of \
             mandate.graph.WriteRelationship, which a real row already covers. The README says \
             a double row is counted in its own column of the report and leaves the clause \
             carrying `blocked_on`; the step accepted the registry and the report did not \
             move:\n{report}"
        ),
        Err(error) => error,
    };
    assert!(
        error.contains("double"),
        "the refusal names the double row; it said:\n{error}"
    );
}
