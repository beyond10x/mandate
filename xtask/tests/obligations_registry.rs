//! The obligations-registry step's cases, decided against the committed registry and doctored
//! copies of it.
//!
//! Every case copies what the step reads from a root — `contracts/obligations/`,
//! `contracts/coverage.json`, `contracts/conformance/obligations-report.json`,
//! `generated/ir/system.json`, `tests/security/cases.json` and the architecture addendum —
//! into a scratch root under `target/`, changes exactly one thing, and drives the same entry
//! point at that root. That is the pattern `xtask/tests/coverage.rs:38-45` already uses, and
//! the scratch root is what `Action::ObligationsRegistry { root }` exists for.
//!
//! # The story directory is a fixture here, and why
//!
//! The registry defers an unbound clause to `story:obligations-<crate>`, the seven binding
//! stories `story:obligation-registry`'s rulings create. This checkout's planning store does
//! not hold them yet — the coordinator's store commit lands them — so every case supplies the
//! story directory explicitly: this workspace's own store, copied, with the seven binding
//! stories written beside it. What is *not* faked is the rule that reads them:
//! [`a_clause_deferred_to_a_story_the_store_does_not_hold_is_refused`] and
//! [`a_clause_deferred_to_an_implemented_story_is_refused`] drive the same reader with a store
//! that answers, and both refuse. Until the store commit lands,
//! `cargo xtask obligations-registry` on this tree reports the 103 clauses whose binding story
//! is absent; that is the dependency, not a defect in the step.
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

use serde_json::Value;
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

/// The seven binding stories, as the store will hold them once the coordinator's store commit
/// lands: one file each, `status: draft`, which is not a terminal rung.
const BINDING: [&str; 7] = [
    "authz",
    "federation",
    "graph",
    "identity",
    "model",
    "policy",
    "sts",
];

/// A story directory: this workspace's own, plus the seven binding stories.
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
    let root = repo().join("target/xtask-obligations-cases").join(name);
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

/// The entry for `command` in `crate_short`'s document, by index.
fn command_at(document: &Value, command: &str) -> usize {
    document["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .position(|entry| entry["command"] == command)
        .unwrap_or_else(|| panic!("{command}: one entry"))
}

/// The index of the first clause of `command` that names a test.
fn bound_clause(document: &Value, at: usize) -> usize {
    document["commands"][at]["clauses"]
        .as_array()
        .expect("clauses")
        .iter()
        .position(|clause| !clause["tests"].as_array().expect("tests").is_empty())
        .expect("one bound clause")
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

/// The committed registry agrees with the compiled model, the coverage manifest, the security
/// corpus, the addendum and the compiled test binaries, and its report is the one on disk.
#[test]
fn the_committed_registry_is_accepted_and_its_report_is_the_committed_one() {
    let root = fixture("committed");
    let report = run(&root).expect("the committed registry is decided");
    // `Action::ObligationsRegistry { root }` is the coordinator's to wire; until then this is
    // the only place the per-crate table a reader of the registry sees is produced.
    println!("{report}");
    for crate_name in obligations_registry::CRATES {
        assert!(
            report.contains(crate_name),
            "the table states {crate_name}:\n{report}"
        );
    }
    assert!(
        report.contains("clauses"),
        "the table names its columns:\n{report}"
    );
}

/// A clause is a verbatim substring of its command's declared cause, and nothing else makes it
/// one. This is the rule that keeps the registry a reading of the contract rather than a second
/// document about it.
#[test]
fn a_clause_the_declared_cause_does_not_carry_is_refused() {
    let root = fixture("clause-not-declared");
    let mut document = document(&root, "sts");
    let at = command_at(&document, "mandate.credential.RegisterResourceServer");
    document["commands"][at]["clauses"][0]["clause"] =
        Value::String("audience registration is contradictory".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("audience registration is contradictory")
            && error.contains("mandate.credential.RegisterResourceServer"),
        "the refusal names the clause and its command:\n{error}"
    );
}

/// A test id no compiled binary lists and runs is a check that decides nothing.
#[test]
fn a_test_no_compiled_binary_lists_is_refused() {
    let root = fixture("test-not-compiled");
    let mut document = document(&root, "sts");
    let at = command_at(&document, "mandate.credential.RegisterResourceServer");
    let clause = bound_clause(&document, at);
    document["commands"][at]["clauses"][clause]["tests"][0]["id"] =
        Value::String("mandate-sts::declared_denials::a_case_that_was_renamed".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("a_case_that_was_renamed"),
        "the refusal names the id:\n{error}"
    );
}

/// A clause of a command `mandate-sts` implements is decided by a test `mandate-sts` runs.
/// Existence alone would let any id in the workspace satisfy any clause.
#[test]
fn a_denial_test_of_another_crate_is_refused() {
    let root = fixture("test-of-another-crate");
    let mut document = document(&root, "sts");
    let at = command_at(&document, "mandate.credential.RegisterResourceServer");
    let clause = bound_clause(&document, at);
    document["commands"][at]["clauses"][clause]["tests"][0]["id"] =
        Value::String("mandate-federation::authenticate::a_disabled_connection_denies".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate-federation::authenticate::a_disabled_connection_denies")
            && error.contains("mandate-sts"),
        "the refusal names the id and the crate that must run it:\n{error}"
    );
}

/// An unbound clause deferred to a story whose work is over is a gap with nobody left to close
/// it. This is the transition the registry's acceptance turns on: once a binding story is
/// `implemented`, every clause still deferred to it fails.
#[test]
fn a_clause_deferred_to_an_implemented_story_is_refused() {
    let root = fixture("blocked-on-implemented");
    let mut document = document(&root, "sts");
    let at = command_at(&document, "mandate.credential.RegisterResourceServer");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let deferred = clauses
        .iter()
        .position(|clause| !clause["blocked_on"].is_null())
        .expect("one deferred clause");
    clauses[deferred]["blocked_on"] = Value::String("story:tenancy-topology".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("story:tenancy-topology") && error.contains("implemented"),
        "the refusal names the story and the rung the store reports:\n{error}"
    );
}

/// A story the planning store does not hold is a deferral to nothing.
#[test]
fn a_clause_deferred_to_a_story_the_store_does_not_hold_is_refused() {
    let root = fixture("blocked-on-absent");
    let mut document = document(&root, "sts");
    let at = command_at(&document, "mandate.credential.RegisterResourceServer");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let deferred = clauses
        .iter()
        .position(|clause| !clause["blocked_on"].is_null())
        .expect("one deferred clause");
    clauses[deferred]["blocked_on"] = Value::String("story:no-such-story".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("story:no-such-story"),
        "the refusal names the story:\n{error}"
    );
}

/// The registry's command set is the compiled model's, both ways.
#[test]
fn a_command_the_registry_does_not_name_is_refused() {
    let root = fixture("command-missing");
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RevokeGrant");
    document["commands"]
        .as_array_mut()
        .expect("commands")
        .remove(at);
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.RevokeGrant"),
        "the refusal names the command:\n{error}"
    );
}

#[test]
fn a_command_the_compiled_model_does_not_declare_is_refused() {
    let root = fixture("command-extra");
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RevokeGrant");
    let mut extra = document["commands"][at].clone();
    extra["command"] = Value::String("mandate.graph.RevokeEverything".to_owned());
    document["commands"]
        .as_array_mut()
        .expect("commands")
        .push(extra);
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.RevokeEverything"),
        "the refusal names the command:\n{error}"
    );
}

/// A double refuses because it was written to refuse. Turning the one real-path row of a
/// covered clause into a double row leaves the clause with no evidence that the shipped path
/// refuses, and the step says so rather than counting it.
#[test]
fn a_double_row_does_not_cover_the_clause_it_names() {
    let root = fixture("double-does-not-cover");
    let mut document = document(&root, "authz");
    let at = command_at(&document, "mandate.authorization.Check");
    let clause = bound_clause(&document, at);
    // Read out of the document rather than restated here. A clause text is a binding
    // story's to split as the declared cause enumerates conditions, and a literal of it
    // in this file turns every such split into a failure of the step's own suite.
    let text = document["commands"][at]["clauses"][clause]["clause"]
        .as_str()
        .expect("the clause states its text")
        .to_owned();
    let tests = document["commands"][at]["clauses"][clause]["tests"]
        .as_array_mut()
        .expect("tests");
    for row in tests.iter_mut() {
        row["path"] = Value::String("double".to_owned());
        row["double"] = Value::String("mandate_authz::double::ContextDouble".to_owned());
    }
    write_document(&root, "authz", &document);
    let error = failure(&root);
    assert!(
        error.contains(&text),
        "the refusal names the clause {text:?} a double cannot cover:\n{error}"
    );
}

/// The clauses only a double reaches are counted in their own column, and are never part of
/// what the real path covers.
#[test]
fn the_double_only_column_holds_the_clauses_no_real_path_row_covers() {
    let root = fixture("double-column");
    let report = run(&root).expect("the committed registry is decided");
    let written: Value = serde_json::from_str(
        &fs::read_to_string(root.join("contracts/conformance/obligations-report.json"))
            .expect("the report"),
    )
    .expect("valid JSON");
    let policy = &written["crates"]["mandate-policy"];
    assert_eq!(
        policy["real_covered"], 0,
        "no mandate-policy clause is covered on the real path yet:\n{report}"
    );
    assert!(
        policy["double_only"].as_u64().expect("a count") > 0,
        "mandate-policy's supersede clauses are reached by PolicyDouble alone:\n{report}"
    );
    for crate_name in obligations_registry::CRATES {
        let row = &written["crates"][crate_name];
        let parts = ["real_covered", "double_only", "deferred"]
            .iter()
            .map(|key| row[key].as_u64().expect("a count"))
            .sum::<u64>();
        assert_eq!(
            row["clauses"].as_u64().expect("a count"),
            parts,
            "{crate_name}: the three columns partition its clauses"
        );
    }
}

/// The report is the run's own answer, and the committed one is compared byte for byte.
#[test]
fn the_report_moves_when_a_row_moves() {
    let root = fixture("report-moves");
    let before: Value = serde_json::from_str(
        &fs::read_to_string(root.join("contracts/conformance/obligations-report.json"))
            .expect("the committed report"),
    )
    .expect("valid JSON");

    let mut document = document(&root, "authz");
    let at = command_at(&document, "mandate.authorization.Check");
    let clause = bound_clause(&document, at);
    document["commands"][at]["clauses"][clause]["tests"] = Value::Array(Vec::new());
    document["commands"][at]["clauses"][clause]["blocked_on"] =
        Value::String("story:obligations-authz".to_owned());
    write_document(&root, "authz", &document);

    let error = failure(&root);
    assert!(
        error.contains("obligations-registry --write"),
        "the drift names the command that moves the report:\n{error}"
    );

    let workspace = repo();
    let blocked = documents::store_blocked(&workspace).expect("the store answers");
    let compiled = coverage::compiled(&workspace).expect("the workspace test set");
    obligations_registry::decide(
        &root,
        &stories(&root.join("planning")),
        &blocked,
        compiled,
        true,
    )
    .expect("the registry is decided once the report is rewritten");
    let after: Value = serde_json::from_str(
        &fs::read_to_string(root.join("contracts/conformance/obligations-report.json"))
            .expect("the rewritten report"),
    )
    .expect("valid JSON");
    assert_eq!(
        after["crates"]["mandate-authz"]["real_covered"]
            .as_u64()
            .expect("a count")
            + 1,
        before["crates"]["mandate-authz"]["real_covered"]
            .as_u64()
            .expect("a count"),
        "one clause left the real-path column"
    );
    assert_eq!(
        after["crates"]["mandate-authz"]["clauses"], before["crates"]["mandate-authz"]["clauses"],
        "the denominator did not move"
    );
}

/// Writing the report twice writes the same bytes, and those are the bytes on disk.
#[test]
fn the_written_report_is_byte_stable_and_is_the_committed_one() {
    let root = fixture("byte-stable");
    let path = root.join("contracts/conformance/obligations-report.json");
    let committed = fs::read(&path).expect("the committed report");
    let workspace = repo();
    let blocked = documents::store_blocked(&workspace).expect("the store answers");
    let compiled = coverage::compiled(&workspace).expect("the workspace test set");
    let directory = stories(&root.join("planning"));

    fs::remove_file(&path).expect("clear the report");
    obligations_registry::decide(&root, &directory, &blocked, compiled, true).expect("write once");
    let first = fs::read(&path).expect("the written report");
    obligations_registry::decide(&root, &directory, &blocked, compiled, true).expect("write twice");
    let second = fs::read(&path).expect("the rewritten report");

    assert_eq!(first, second, "two writes of one registry are one file");
    assert_eq!(
        String::from_utf8_lossy(&committed),
        String::from_utf8_lossy(&first),
        "the committed report is the one this registry produces"
    );
}

/// Every id the security corpus carries is bound or deferred, and the registry names no case
/// the corpus does not hold.
#[test]
fn a_case_the_security_corpus_does_not_hold_is_refused() {
    let root = fixture("case-not-in-corpus");
    let mut document = document(&root, "graph");
    document["cases"][0]["case"] = Value::String("graph-revocation-2".to_owned());
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("graph-revocation-2"),
        "the refusal names the case:\n{error}"
    );
}

#[test]
fn a_case_the_registry_does_not_bind_is_refused() {
    let root = fixture("case-missing");
    let mut document = document(&root, "graph");
    document["cases"].as_array_mut().expect("cases").clear();
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("graph-revocation"),
        "the refusal names the case nothing binds:\n{error}"
    );
}

/// A step of the addendum's resolution order that no document names is a requirement with no
/// reader, and a requirement whose text has drifted misreports one.
#[test]
fn a_resolution_step_no_document_names_is_refused() {
    let root = fixture("addendum-missing");
    let mut document = document(&root, "federation");
    let rows = document["addendum"].as_array_mut().expect("addendum");
    rows.retain(|row| row["step"] != 3);
    write_document(&root, "federation", &document);
    let error = failure(&root);
    assert!(
        error.contains("validate signature"),
        "the refusal names the step:\n{error}"
    );
}

#[test]
fn a_resolution_step_whose_text_is_not_the_addendums_is_refused() {
    let root = fixture("addendum-drifted");
    let mut document = document(&root, "federation");
    let rows = document["addendum"].as_array_mut().expect("addendum");
    let at = rows
        .iter()
        .position(|row| row["step"] == 3)
        .expect("step three");
    rows[at]["requirement"] = Value::String("check the signature".to_owned());
    write_document(&root, "federation", &document);
    let error = failure(&root);
    assert!(
        error.contains("check the signature"),
        "the refusal names the drifted text:\n{error}"
    );
}

/// The registry may not disagree with the coverage manifest about whether a command is
/// implemented; the two would then answer one question two ways.
#[test]
fn a_status_the_coverage_manifest_contradicts_is_refused() {
    let root = fixture("status-disagrees");
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RevokeGrant");
    document["commands"][at]["status"] = Value::String("deferred".to_owned());
    document["commands"][at]["clauses"] = Value::Array(Vec::new());
    document["commands"][at]["story"] = Value::String("story:graph-policy".to_owned());
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.RevokeGrant") && error.contains("implemented"),
        "the refusal names the command and what the manifest says:\n{error}"
    );
}

/// An implemented command with no `no-state-change` case and no deferral is a denial nothing
/// says leaves the projection where it was.
#[test]
fn an_implemented_command_with_neither_a_no_state_change_case_nor_a_deferral_is_refused() {
    let root = fixture("no-state-change-missing");
    let mut document = document(&root, "model");
    let at = command_at(&document, "mandate.tenancy.CreateTeam");
    document["commands"][at]["no_state_change"] = Value::Array(Vec::new());
    write_document(&root, "model", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate.tenancy.CreateTeam"),
        "the refusal names the command:\n{error}"
    );
}

/// An addendum row is held to the same-crate rule the clause rows are: the crate that states it
/// decides a step of the resolution order is the crate whose test decides it. The exemption the
/// first round gave these rows left the addendum half of the rule with no reader at all.
#[test]
fn an_addendum_row_naming_a_test_of_another_crate_is_refused() {
    let root = fixture("addendum-of-another-crate");
    let mut document = document(&root, "federation");
    let rows = document["addendum"].as_array_mut().expect("addendum");
    let at = rows
        .iter()
        .position(|row| row["step"] == 2)
        .expect("step two");
    rows[at]["tests"][0]["id"] = Value::String(
        "mandate-sts::declared_denials::every_refusal_register_resource_server_produces_has_a_row"
            .to_owned(),
    );
    write_document(&root, "federation", &document);
    let error = failure(&root);
    assert!(
        error.contains("every_refusal_register_resource_server_produces_has_a_row")
            && error.contains("mandate-federation"),
        "the refusal names the id and the crate that must run it:\n{error}"
    );
}

/// A security case is decided end to end, and the two packages that decide one at the wire are
/// named. Any other package is refused: the allowance is bounded, not an exemption.
#[test]
fn a_case_row_naming_a_package_that_is_neither_the_entry_crate_nor_the_wire_is_refused() {
    let root = fixture("case-of-a-third-package");
    let mut document = document(&root, "sts");
    let rows = document["cases"].as_array_mut().expect("cases");
    let at = rows
        .iter()
        .position(|row| row["case"] == "reference-revoked")
        .expect("reference-revoked has a row");
    rows[at]["tests"][0]["id"] =
        Value::String("mandate-federation::authenticate::a_disabled_connection_denies".to_owned());
    write_document(&root, "sts", &document);
    let error = failure(&root);
    assert!(
        error.contains("mandate-federation::authenticate::a_disabled_connection_denies"),
        "the refusal names the id:\n{error}"
    );
}

/// The other half of the same bound: a case a wire package decides may name that package's
/// test, and the step admits it.
#[test]
fn a_case_row_naming_a_wire_package_is_admitted() {
    let root = fixture("case-at-the-wire");
    let mut document = document(&root, "model");
    let rows = document["cases"].as_array_mut().expect("cases");
    let at = rows
        .iter()
        .position(|row| row["case"] == "cross-tenant-resource")
        .expect("cross-tenant-resource has a row");
    rows[at]["tests"][0]["id"] = Value::String(
        "mandate-server::decode::pkce_plain_is_refused_at_the_authorization_endpoint".to_owned(),
    );
    write_document(&root, "model", &document);
    run(&root).expect("a case decided at the wire names the wire package's test");
}

/// The clauses of one command tile its cause **in order**. A tiling read out of order would
/// let one position of the cause be claimed twice while another goes unclaimed, which is the
/// same defect as an overlap wearing a different shape.
#[test]
fn a_clause_stated_before_the_clause_it_follows_in_the_cause_is_refused() {
    let root = fixture("clauses-out-of-order");
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RegisterResource");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let last = clauses.len() - 1;
    clauses.swap(1, last);
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("hierarchy admission fails") || error.contains("parent is unresolved"),
        "the refusal names a clause the walk could not place:\n{error}"
    );
}

/// The tail of the cause is accounted for too. Dropping the last clause leaves a run of the
/// declared denial that no clause claims, and the obligation stops being published at all —
/// the count falling by deletion rather than by work.
#[test]
fn a_clause_list_that_leaves_the_tail_of_the_cause_unaccounted_is_refused() {
    let root = fixture("clauses-short-tail");
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RegisterResource");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    clauses.pop();
    write_document(&root, "graph", &document);
    let error = failure(&root);
    assert!(
        error.contains("hierarchy admission fails"),
        "the refusal quotes the unaccounted tail:\n{error}"
    );
}

/// A clause whose only evidence is a double has no shipped decider — that is what `double` is
/// defined to mean — so no test the crate's binding story could write binds it. Driven through
/// the step rather than read off the committed data, so the rule holds for a document the
/// binding stories edit later.
#[test]
fn a_double_only_clause_deferred_to_the_crates_binding_story_is_refused() {
    let root = fixture("double-deferred-to-the-binding-story");
    let mut document = document(&root, "policy");
    let at = command_at(&document, "mandate.policy.SupersedePolicy");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let double = clauses
        .iter()
        .position(|clause| {
            clause["tests"]
                .as_array()
                .expect("tests")
                .iter()
                .any(|row| row["path"] == "double")
        })
        .expect("one double-backed clause");
    clauses[double]["blocked_on"] = Value::String("story:obligations-policy".to_owned());
    write_document(&root, "policy", &document);
    let error = failure(&root);
    assert!(
        error.contains("story:obligations-policy"),
        "the refusal names the story that cannot discharge it:\n{error}"
    );
}
