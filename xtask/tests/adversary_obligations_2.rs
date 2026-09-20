//! Adversary pass 2 against `story:obligation-registry`, after correction round 1: the split
//! the correction introduced, read against the evidence it claims, and the clause set read as
//! the tiling of the declared cause the README says it is.
//!
//! Round 1 ruled that a clause whose conditions have different deciders is split into those
//! conditions. Four clauses were split into seven. Two questions the ruling leaves open are
//! decided here: whether the half declared covered is the half the named test decides, and
//! whether anything at all holds the clause *set* to the cause once splitting is a thing the
//! author may do.
//!
//! The fixture pattern is `xtask/tests/obligations_registry.rs`'s and
//! `xtask/tests/adversary_obligations_1.rs`'s: what the step reads is copied into a scratch
//! root under `target/`, one thing is changed, the report is regenerated at that root so the
//! byte comparison is not what answers, and the same entry point is driven there.
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
        .join("target/xtask-adversary-obligations-2")
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

fn drive(root: &Path, write: bool) -> std::result::Result<String, String> {
    let workspace = repo();
    let blocked = documents::store_blocked(&workspace).expect("the store answers");
    let compiled = coverage::compiled(&workspace).expect("the workspace test set");
    obligations_registry::decide(
        root,
        &stories(&root.join("planning")),
        &blocked,
        compiled,
        write,
    )
    .map_err(|error| error.to_string())
}

/// The step at `root`, with the report regenerated first.
///
/// Every case below changes the clause *set*, which moves the report; regenerating it is what
/// `cargo xtask obligations-registry --write` is documented to be for, and it is what a binding
/// story editing its own document would run. Doing it here is what keeps the byte comparison
/// from being the thing that answers: what is left is whether the step has any reader for the
/// change itself.
fn run_after_write(root: &Path) -> std::result::Result<String, String> {
    let _ = drive(root, true);
    drive(root, false)
}

fn rows(value: &Value) -> &[Value] {
    value.as_array().map_or(&[][..], Vec::as_slice)
}

/// The index of `command` in a document's `commands`.
fn command_at(document: &Value, command: &str) -> usize {
    rows(&document["commands"])
        .iter()
        .position(|entry| entry["command"] == command)
        .unwrap_or_else(|| panic!("{command}: one entry"))
}

/// The report at `root`, parsed.
fn report(root: &Path) -> Value {
    let text = fs::read_to_string(root.join("contracts/conformance/obligations-report.json"))
        .expect("the report");
    serde_json::from_str(&text).expect("valid JSON")
}

/// Every `(command, phrase)` `services/sts/tests/declared_denials.rs`'s `ROWS` table
/// attributes a `DenialClause` discriminator to.
///
/// The table is read as a document, which is what its own doc comment says it is written to be
/// read as: *"`services/sts/tests/adversary_transaction_2.rs` reads this table as a document —
/// a row's command is a line that is nothing but a quoted element name"*. A row's command is
/// such a line; a row's authority is a `Source::DenialPhrase("…")` line. `Source::WrongState`
/// and `Source::EntityInvariant` rows carry no phrase and are not read.
fn precedent() -> Vec<(String, String)> {
    let path = repo().join("services/sts/tests/declared_denials.rs");
    let text = fs::read_to_string(&path).expect("the STS precedent table");
    let table = text
        .split_once("const ROWS:")
        .expect("the ROWS table")
        .1
        .split_once("\n];")
        .expect("the end of the ROWS table")
        .0;
    let mut command = String::new();
    let mut attributed = Vec::new();
    for line in table.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('"')
            && let Some(name) = rest.strip_suffix("\",")
            && name.starts_with("mandate.")
        {
            command = name.to_owned();
        }
        if let Some(rest) = line
            .split_once("Source::DenialPhrase(\"")
            .map(|split| split.1)
            && let Some(phrase) = rest.split_once("\")").map(|split| split.0)
        {
            assert!(
                !command.is_empty(),
                "a phrase before any command in {}",
                path.display()
            );
            attributed.push((command.clone(), phrase.to_owned()));
        }
    }
    assert!(
        attributed.len() >= 40,
        "the table is read as a document and holds its rows; {} found in {}",
        attributed.len(),
        path.display()
    );
    attributed
}

/// `contracts/obligations/README.md`, *A command*:
///
/// > The granularity is the one `services/sts/tests/declared_denials.rs` established by hand
/// > for the eleven STS commands — one clause per condition the cause enumerates, so **several
/// > of that file's discriminators may answer to one clause**.
///
/// The clause is therefore the coarser unit: every discriminator that answers to a clause has
/// its declared phrase *inside* that clause. So a clause the registry publishes as decided on
/// the real path by one of that file's tests must contain at least one phrase the table
/// attributes a discriminator of that command to — otherwise the test that is named as
/// deciding the clause decides some other condition of the same cause, and the clause is
/// counted in `real_covered` on evidence about a different obligation.
///
/// Round 1's F4 finding was that `IssueAuthorizationCode` and `RedeemAuthorizationCode` each
/// enumerate two conditions in one clause and are counted `real_covered` on a single
/// `ExpiryUnbounded` discriminator, leaving "authority narrowing" and "atomic issuance" driven
/// by nothing. Round 1 split both. This case decides whether the split put the deferral on the
/// half the discriminator does not decide.
#[test]
fn every_sts_clause_a_precedent_test_covers_contains_a_phrase_that_table_attributes() {
    let attributed = precedent();
    let document: Value = serde_json::from_str(
        &fs::read_to_string(repo().join("contracts/obligations/sts.json")).expect("sts.json"),
    )
    .expect("valid JSON");
    let mut unattributed: Vec<String> = Vec::new();
    for entry in rows(&document["commands"]) {
        if entry["status"] != "implemented" {
            continue;
        }
        let command = entry["command"].as_str().expect("a command");
        for clause in rows(&entry["clauses"]) {
            let text = clause["clause"].as_str().expect("a clause");
            let covering: Vec<&str> = rows(&clause["tests"])
                .iter()
                .filter(|row| row["kind"] == "denial" && row["path"] == "real")
                .filter_map(|row| row["id"].as_str())
                .filter(|id| id.contains("declared_denials"))
                .collect();
            if covering.is_empty() {
                continue;
            }
            if !attributed
                .iter()
                .any(|(named, phrase)| named == command && text.contains(phrase.as_str()))
            {
                unattributed.push(format!(
                    "{command}: the clause {text:?} is real_covered by {}, and the precedent \
                     table attributes no discriminator to any phrase inside it",
                    covering.join(", ")
                ));
            }
        }
    }
    assert!(
        unattributed.is_empty(),
        "every clause a precedent test covers holds a phrase that table attributes:\n{}",
        unattributed.join("\n")
    );
}

/// `contracts/obligations/README.md`, *Why a clause and not a command*:
///
/// > A command whose `denied` outcome names six conditions and whose only test drives one of
/// > them is `implemented` in the coverage manifest and always will be. Splitting the declared
/// > cause into its clauses is what makes the other five countable, and **a count is the only
/// > thing that can fall**.
///
/// and, *A test row*, on the split round 1 introduced:
///
/// > where two conditions of one clause have different deciders, the clause is split into
/// > those conditions, each still a verbatim substring and **the set still tiling the cause**.
///
/// Nothing reads the second sentence. The step decides each clause is *a* substring of the
/// cause (`obligations_registry.rs:656`) and that the same text is not stated twice; it never
/// decides that the clauses together account for the cause. So a condition the author cannot
/// bind is removable: the clause vanishes from `clauses` and from `deferred`, the report is
/// regenerated by the documented `--write`, and the step exits 0 on a registry that no longer
/// publishes the obligation at all. That is the count falling by deletion rather than by work,
/// which is the one move the document says this file exists to prevent.
#[test]
fn a_clause_dropped_from_a_commands_clause_list_is_refused() {
    let root = fixture("clause-dropped");
    let before = report(&root);
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RegisterResource");
    let clauses = document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses");
    let dropped = clauses
        .iter()
        .position(|clause| {
            clause["clause"] == "Caller lacks resource registration/ownership authority"
        })
        .expect("the unbound caller-authority clause");
    clauses.remove(dropped);
    write_document(&root, "graph", &document);

    let outcome = run_after_write(&root);
    let after = report(&root);
    assert_eq!(
        after["totals"]["clauses"].as_u64().expect("a count") + 1,
        before["totals"]["clauses"].as_u64().expect("a count"),
        "the deletion moved the published clause count"
    );
    let error = match outcome {
        Ok(table) => panic!(
            "the registry dropped the clause \"Caller lacks resource registration/ownership \
             authority\" of mandate.graph.RegisterResource, which its declared cause still \
             names, and the step accepted it:\n{table}"
        ),
        Err(error) => error,
    };
    assert!(
        error.contains("Caller lacks resource registration/ownership authority"),
        "the refusal names the condition the clause list no longer accounts for:\n{error}"
    );
}

/// The same rule from the other side. A clause need only be *a* substring of the cause, so one
/// that lies inside another clause of the same command is admitted: the cause is counted twice
/// over the overlap, and binding the overlap to a test the wider clause already names raises
/// both `clauses` and `real_covered` without a single new condition being decided.
///
/// A tiling has one clause per position of the cause. This one has two, and the report says
/// the registry covers more than it did.
#[test]
fn a_clause_that_lies_inside_another_clause_of_the_same_command_is_refused() {
    let root = fixture("clause-overlapping");
    let before = report(&root);
    let mut document = document(&root, "graph");
    let at = command_at(&document, "mandate.graph.RegisterResource");
    let covering = rows(&document["commands"][at]["clauses"])
        .iter()
        .find(|clause| clause["clause"] == "belongs to another organization")
        .expect("the tenant-half clause")
        .clone();
    // "another organization" is a verbatim substring of the declared cause and of the clause
    // above, and it is bound to that clause's own real-path row.
    document["commands"][at]["clauses"]
        .as_array_mut()
        .expect("clauses")
        .push(json!({
            "clause": "another organization",
            "tests": covering["tests"].clone(),
        }));
    write_document(&root, "graph", &document);

    let outcome = run_after_write(&root);
    let after = report(&root);
    assert_eq!(
        after["totals"]["real_covered"].as_u64().expect("a count"),
        before["totals"]["real_covered"].as_u64().expect("a count") + 1,
        "the overlapping clause raised the published real_covered total"
    );
    let error = match outcome {
        Ok(table) => panic!(
            "mandate.graph.RegisterResource states the clause \"another organization\", which \
             lies inside its own clause \"belongs to another organization\" and is decided by \
             that clause's row, and the step accepted it:\n{table}"
        ),
        Err(error) => error,
    };
    assert!(
        error.contains("another organization"),
        "the refusal names the overlapping clause:\n{error}"
    );
}

/// `contracts/obligations/README.md`, *`blocked_on`*:
///
/// > Where the shipped path *cannot* produce the declared denial at all, the deferral names
/// > the story that owns that path instead: **no test the binding story could write would bind
/// > the clause until the path answers with a denial**. "parent is unresolved" defers to
/// > `story:graph-policy-adapter` for that reason.
///
/// and, *A test row*:
///
/// > `double` is a stand-in **for the deciding code itself** … whose refusals are the double's
/// > own and not the adapter's.
///
/// The two together decide every `double_only` clause. A clause whose only evidence is a
/// double is one whose deciding code is not shipped — that is what `double` is defined to
/// mean — so no test `story:obligations-<crate>` could write binds it, and its deferral names
/// the story that owns the path. Round 1 applied that to one clause by hand. The rule it was
/// applied from has no reader, so the other double-backed clauses of the same two crates still
/// defer to the binding story, and the registry publishes seven obligations as waiting on a
/// story that cannot discharge them.
///
/// Measured against the workspace rather than asserted: the only non-test implementor of
/// `mandate_graph::topology::ResourceRegistry` and of `mandate_policy::port::PolicyAdministration`
/// is each crate's own `double`.
#[test]
fn a_double_only_clause_does_not_defer_to_the_crates_binding_story() {
    let directory = repo().join("contracts/obligations");
    let mut misdeferred: Vec<String> = Vec::new();
    let mut documents = 0_usize;
    for entry in fs::read_dir(&directory).expect("the registry directory") {
        let entry = entry.expect("a registry entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        documents += 1;
        let document: Value =
            serde_json::from_str(&fs::read_to_string(entry.path()).expect("a document"))
                .expect("valid JSON");
        let binding = format!("story:obligations-{stem}");
        for command in rows(&document["commands"]) {
            if command["status"] != "implemented" {
                continue;
            }
            for clause in rows(&command["clauses"]) {
                let covered_real = rows(&clause["tests"])
                    .iter()
                    .any(|row| row["kind"] == "denial" && row["path"] == "real");
                let double_only = !covered_real
                    && rows(&clause["tests"])
                        .iter()
                        .any(|row| row["path"] == "double");
                if double_only && clause["blocked_on"].as_str() == Some(binding.as_str()) {
                    misdeferred.push(format!(
                        "{}: the clause {} has no shipped decider — its only evidence is a \
                         double — and defers to {binding}, which owns a test file",
                        command["command"].as_str().unwrap_or_default(),
                        clause["clause"]
                    ));
                }
            }
        }
    }
    assert_eq!(documents, 7, "seven documents");
    assert!(
        misdeferred.is_empty(),
        "a double-backed clause defers to the story that owns the shipped path:\n{}",
        misdeferred.join("\n")
    );
}
