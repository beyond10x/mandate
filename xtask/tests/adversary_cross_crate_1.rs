//! Adversary pass 1 against `story:cross-crate-clauses`: the rules the unit wrote into
//! `contracts/obligations/README.md` and the step's module doc, driven against the step the
//! same unit shipped.
//!
//! The fixture pattern is `xtask/tests/obligations_registry.rs`'s: what the step reads is
//! copied into a scratch root under `target/`, one thing is changed, and the same entry point
//! is driven at that root with the seven binding stories written beside this workspace's own
//! store.
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

const BINDING: [&str; 7] = [
    "authz",
    "federation",
    "graph",
    "identity",
    "model",
    "policy",
    "sts",
];

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

fn fixture(name: &str) -> PathBuf {
    let root = repo()
        .join("target/xtask-obligations-cases/adversary-cross-crate-1")
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

fn command_at(document: &Value, command: &str) -> usize {
    document["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .position(|entry| entry["command"] == command)
        .unwrap_or_else(|| panic!("{command}: one entry"))
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

fn failure(root: &Path) -> String {
    match run(root) {
        Ok(report) => panic!("the doctored registry was accepted:\n{report}"),
        Err(error) => error,
    }
}

/// The real-path denial row of `mandate.tenancy.AddTeamMembership`'s "team" clause, read out
/// of the document rather than restated.
fn team_row(document: &Value, at: usize) -> Value {
    document["commands"][at]["clauses"]
        .as_array()
        .expect("clauses")
        .iter()
        .find(|clause| clause["clause"] == "team")
        .and_then(|clause| clause["tests"].get(0).cloned())
        .expect("the team clause names a real-path denial test")
}

/// An empty clause names no condition. It is a verbatim substring of every cause and the
/// tiling walk places it at offset zero, so with the sibling-containment check gone nothing
/// refuses it — and backed by a real-path denial row it is counted in `clauses` and in
/// `real_covered` with nothing new decided. The README's words: a nested clause "can raise
/// `real_covered` with nothing new decided". The removed check refused `""`, because every
/// sibling contains it (`git show 9c4ca4a:xtask/src/obligations_registry.rs`, the loop over
/// `stated`).
#[test]
fn an_empty_clause_is_refused_and_counts_nothing() {
    let root = fixture("empty-clause");
    let mut model = document(&root, "model");
    let at = command_at(&model, "mandate.tenancy.AddTeamMembership");
    let row = team_row(&model, at);
    model["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses")
        .insert(0, json!({"clause": "", "tests": [row]}));
    write_document(&root, "model", &model);
    let error = failure(&root);
    assert!(
        error.contains("\"\""),
        "the refusal names the empty clause:\n{error}"
    );
}

/// "or" is a list joiner, not a condition — the step's own `JOINERS` says so — and it lies
/// inside the sibling "principal is unresolved or outside the verified organization". The
/// removed containment check refused it; the tiling walk places it at the " or " between
/// "team" and "principal …" and admits it, so a joiner becomes a clause counted in
/// `real_covered` by a test that decides the "team" condition and nothing else.
#[test]
fn a_joiner_stated_as_a_clause_is_refused() {
    let root = fixture("joiner-clause");
    let mut model = document(&root, "model");
    let at = command_at(&model, "mandate.tenancy.AddTeamMembership");
    let row = team_row(&model, at);
    let clauses = model["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let team = clauses
        .iter()
        .position(|clause| clause["clause"] == "team")
        .expect("the team clause");
    clauses.insert(team + 1, json!({"clause": "or", "tests": [row]}));
    write_document(&root, "model", &model);
    let error = failure(&root);
    assert!(
        error.contains("\"or\""),
        "the refusal names the joiner stated as a clause:\n{error}"
    );
}

/// README: "A `double` value is a `::`-separated Rust path into a library target … A stand-in
/// … nothing outside that binary can name" is refused. `mandate_identity::port` is a private
/// module (`crates/mandate-identity/src/lib.rs:134`, `mod port;`), so
/// `mandate_identity::port::IdentityLog` is a path nothing outside the library can name — it
/// does not resolve — while `crates/mandate-identity/src/port.rs` declares
/// `pub struct IdentityLog`. The step reads that file and admits the path. Every row naming
/// the committed double is re-pointed, so the one-path-per-id rule is not what refuses.
#[test]
fn a_double_through_a_private_module_is_refused() {
    let root = fixture("double-through-a-private-module");
    let text =
        fs::read_to_string(root.join("contracts/obligations/identity.json")).expect("the document");
    assert!(
        text.contains("\"mandate_identity::IdentityLog\""),
        "the committed identity document names the re-exported double"
    );
    fs::write(
        root.join("contracts/obligations/identity.json"),
        text.replace(
            "\"mandate_identity::IdentityLog\"",
            "\"mandate_identity::port::IdentityLog\"",
        ),
    )
    .expect("write the document");
    let error = failure(&root);
    assert!(
        error.contains("mandate_identity::port::IdentityLog"),
        "the refusal names the unnameable path:\n{error}"
    );
}

/// README: "The field sits on a clause and on nothing else". A command entry is the most
/// natural place to misplace it — "this whole command is decided in mandate-sts" — and the
/// step checks addendum and case rows for it and nothing else, so it is ignored in silence.
#[test]
fn decided_in_on_a_command_entry_is_refused() {
    let root = fixture("decided-in-on-a-command");
    let mut federation = document(&root, "federation");
    let at = command_at(&federation, "mandate.federation.AuthorizePublicClient");
    federation["commands"][at]["decided_in"] = Value::String("mandate-sts".to_owned());
    write_document(&root, "federation", &federation);
    let error = failure(&root);
    assert!(
        error.contains("decided_in"),
        "the refusal names the misplaced field:\n{error}"
    );
}

/// The same rule for a `no_state_change` row: it is held to the entry's crate whatever it
/// says, and the field it carries is read by nothing.
#[test]
fn decided_in_on_a_no_state_change_row_is_refused() {
    let root = fixture("decided-in-on-a-no-state-change-row");
    let mut federation = document(&root, "federation");
    let at = command_at(&federation, "mandate.federation.AuthorizePublicClient");
    federation["commands"][at]["no_state_change"][0]["decided_in"] =
        Value::String("mandate-sts".to_owned());
    write_document(&root, "federation", &federation);
    let error = failure(&root);
    assert!(
        error.contains("decided_in"),
        "the refusal names the misplaced field:\n{error}"
    );
}
