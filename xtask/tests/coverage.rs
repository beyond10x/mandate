//! The coverage step's cases, decided against the committed manifest and doctored copies of
//! it.
//!
//! The green case drives [`coverage::coverage`] over this checkout, so what is proved here is
//! proved about the same manifest, the same compiled model and the same planning store the
//! gate reads. Every red case copies the two files the step reads from a root —
//! `contracts/coverage.json` and `generated/ir/system.json` — into a scratch root under
//! `target/`, changes exactly one thing, and drives the same entry point at that root. The
//! store and the compiled test-id set are always this workspace's own: a copy cannot answer
//! for itself, which is the rule `xtask/src/documents.rs` already applies to the documents it
//! reads.
//!
//! The scratch root is what `Action::Coverage { root }` exists for, and it is how
//! `story:mutation-controls` drives its data mutants at this step.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/coverage.rs"]
mod coverage;
#[path = "../src/receipt.rs"]
mod receipt;

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

/// A root holding exactly what the step reads from one: the manifest and the compiled model.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-coverage-cases").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(root.join("contracts")).expect("fixture contracts");
    fs::create_dir_all(root.join("generated/ir")).expect("fixture model");
    fs::copy(
        repo().join("contracts/coverage.json"),
        root.join("contracts/coverage.json"),
    )
    .expect("copy the manifest");
    fs::copy(
        repo().join("generated/ir/system.json"),
        root.join("generated/ir/system.json"),
    )
    .expect("copy the compiled model");
    root
}

fn manifest(root: &Path) -> String {
    fs::read_to_string(root.join("contracts/coverage.json")).expect("the fixture manifest")
}

fn write_manifest(root: &Path, body: &str) {
    fs::write(root.join("contracts/coverage.json"), body).expect("write the fixture manifest");
}

/// The one line of the manifest whose entry names `element`.
fn line(body: &str, element: &str) -> String {
    let needle = format!("{{\"element\":\"{element}\",");
    let found: Vec<&str> = body
        .lines()
        .filter(|line| line.starts_with(&needle))
        .collect();
    assert_eq!(found.len(), 1, "{element}: one entry in the manifest");
    found[0].to_owned()
}

fn failure(root: &Path) -> String {
    match coverage::coverage(root) {
        Ok(report) => panic!("the doctored manifest was accepted:\n{report}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn the_committed_manifest_agrees_with_the_compiled_contract_the_store_and_the_test_binaries() {
    let report = coverage::coverage(&repo()).expect("the committed manifest is covered");
    // The acceptance statement ends "and the per-kind table is printed", and the step's own
    // caller — `Action::Coverage { root }` — is wired by the coordinator at integration. Until
    // then this is the only place the table any reader of coverage sees is produced, so it is
    // put on stdout rather than asserted about and discarded.
    println!("{report}");
    for kind in ["command", "event", "entity", "error", "type"] {
        assert!(report.contains(kind), "the table states {kind}:\n{report}");
    }
    assert!(
        report.contains("292"),
        "the table states the element total:\n{report}"
    );
}

/// A crate an `implemented` entry may name, whose per-crate case is not among the compiled
/// tests, is the one failure the list of accounting crates exists to make impossible.
///
/// The list is hand-written and the cases are not, so the list is what can rot. This drives
/// [`coverage::decide`] with a compiled set the case ids have been taken out of — the shape
/// the tree would have if a crate quietly stopped running its case — and the step refuses.
#[test]
fn a_crate_whose_manifest_case_no_binary_lists_fails() {
    let workspace = repo();
    let blocked = documents::store_blocked(&workspace).expect("the store answers");
    let whole = coverage::compiled(&workspace).expect("the workspace test set");
    let without = coverage::Compiled {
        tests: whole
            .tests
            .iter()
            .filter(|id| !id.starts_with("mandate-policy::"))
            .cloned()
            .collect(),
        crates: whole.crates.clone(),
        packages: whole.packages.clone(),
    };
    let error = coverage::decide(&workspace, &workspace, &blocked, &without)
        .expect_err("a crate that runs no manifest case is refused")
        .to_string();
    assert!(
        error.contains("mandate-policy"),
        "the failure names the crate whose case nothing lists: {error}"
    );
}

#[test]
fn an_element_the_manifest_does_not_name_fails() {
    let root = fixture("missing-element");
    let body = manifest(&root);
    let dropped = line(&body, "mandate.graph.Grant");
    // The dropped entry is not the last one, so the line before it still carries its comma
    // and the manifest stays well-formed JSON: what fails is the account, not the parse.
    write_manifest(
        &root,
        &format!(
            "{}\n",
            body.lines()
                .filter(|line| *line != dropped)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.Grant"),
        "the failure names the element the manifest dropped: {error}"
    );
}

#[test]
fn an_entry_naming_an_element_the_contract_does_not_declare_fails() {
    let root = fixture("orphan-entry");
    let body = manifest(&root);
    let renamed = line(&body, "mandate.graph.Grant").replace(
        "\"element\":\"mandate.graph.Grant\"",
        "\"element\":\"mandate.graph.Grantt\"",
    );
    write_manifest(
        &root,
        &body.replace(&line(&body, "mandate.graph.Grant"), &renamed),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.Grantt"),
        "the failure names the element nothing declares: {error}"
    );
}

#[test]
fn a_new_event_the_manifest_has_no_entry_for_fails() {
    let root = fixture("new-event");
    let model = fs::read_to_string(root.join("generated/ir/system.json")).expect("the model");
    let mut parsed: serde_json::Value = serde_json::from_str(&model).expect("the model is JSON");
    let declared = parsed["events"]["mandate.graph.GrantRevoked"].clone();
    parsed["events"]["mandate.graph.GrantWidened"] = declared;
    fs::write(
        root.join("generated/ir/system.json"),
        serde_json::to_string(&parsed).expect("re-encode the model"),
    )
    .expect("write the doctored model");
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.GrantWidened"),
        "the failure names the event added to the contract: {error}"
    );
}

#[test]
fn an_implemented_entry_naming_a_symbol_of_no_crate_of_this_workspace_fails() {
    let root = fixture("absent-symbol");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace(
                "\"impl\":[\"crate::record::Grant\"]",
                "\"impl\":[\"mandate_absent::record::Grant\"]",
            ),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate_absent::record::Grant"),
        "the failure names the symbol nothing in the workspace declares: {error}"
    );
}

#[test]
fn an_implemented_entry_naming_no_symbol_at_all_fails() {
    let root = fixture("no-symbol");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace("\"impl\":[\"crate::record::Grant\"]", "\"impl\":[]"),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.Grant"),
        "the failure names the entry that claims an implementation and names none: {error}"
    );
}

/// `mandate-proto` is the crate this case moves an entry to, and it is chosen rather than
/// invented: it is a real member of this workspace that runs no `tests/contract_agreement.rs`
/// and reconciles no coverage entry. `mandate-token` stood here until wave D's correction
/// round — it ran an agreement suite all along, which is exactly why it stopped being an
/// example of a crate that reconciles nothing and became an accounting crate.
#[test]
fn an_implemented_entry_naming_a_crate_that_runs_no_manifest_case_fails() {
    let root = fixture("unaccounted-crate");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace("\"crate\":\"mandate-graph\"", "\"crate\":\"mandate-proto\""),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate-proto"),
        "the failure names the crate that reconciles nothing: {error}"
    );
}

#[test]
fn an_implemented_entry_naming_a_test_that_does_not_exist_fails() {
    let root = fixture("absent-test");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace(
                "mandate-graph::contract_agreement::every_realized_element_is_one_the_contract_declares",
                "mandate-graph::contract_agreement::a_case_nobody_wrote",
            ),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("a_case_nobody_wrote"),
        "the failure names the test id no compiled binary lists: {error}"
    );
}

#[test]
fn a_declared_entry_relabelled_implemented_fails() {
    let root = fixture("relabelled");
    let body = manifest(&root);
    let entry = line(&body, "mandate.authorization.DecisionRecorded");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace("\"status\":\"declared\"", "\"status\":\"implemented\""),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate.authorization.DecisionRecorded"),
        "the failure names the entry relabelled as implemented: {error}"
    );
}

#[test]
fn two_entries_for_one_element_fail() {
    let root = fixture("duplicate-realizer");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    // The line already carries the comma that separates it from the next entry, so the copy
    // goes below it and the manifest stays well-formed JSON.
    let duplicate = entry.replace("\"crate\":\"mandate-graph\"", "\"crate\":\"mandate-model\"");
    write_manifest(
        &root,
        &body.replace(&entry, &format!("{entry}\n{duplicate}")),
    );
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.Grant"),
        "the failure names the element two entries claim: {error}"
    );
}

#[test]
fn a_deferred_entry_whose_blocker_the_store_does_not_report_open_fails() {
    let root = fixture("absent-blocker");
    let body = manifest(&root);
    let entry = line(&body, "mandate.audit.AuditEvent");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace(
                "\"blocker\":\"decision-blocker:audit-routing\"",
                "\"blocker\":\"decision-blocker:nothing-holds-this\"",
            ),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("decision-blocker:nothing-holds-this"),
        "the failure names the blocker the store does not report: {error}"
    );
}

#[test]
fn a_deferred_entry_whose_blocker_holds_another_story_fails() {
    let root = fixture("wrong-blocker");
    let body = manifest(&root);
    let entry = line(&body, "mandate.audit.AuditEvent");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace(
                "\"blocker\":\"decision-blocker:audit-routing\"",
                "\"blocker\":\"decision-blocker:epoch\"",
            ),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("decision-blocker:epoch"),
        "the failure names the blocker that holds another story: {error}"
    );
}

#[test]
fn an_entry_naming_a_story_the_planning_store_does_not_hold_fails() {
    let root = fixture("absent-story");
    let body = manifest(&root);
    let entry = line(&body, "mandate.tenancy.CreateOrganization");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace(
                "\"story\":\"story:tenancy-topology\"",
                "\"story\":\"story:nobody-wrote-this\"",
            ),
        ),
    );
    let error = failure(&root);
    assert!(
        error.contains("story:nobody-wrote-this"),
        "the failure names the story the store does not hold: {error}"
    );
}

#[test]
fn a_manifest_that_is_not_one_entry_to_a_line_fails() {
    let root = fixture("reflowed");
    let parsed: serde_json::Value =
        serde_json::from_str(&manifest(&root)).expect("the manifest is JSON");
    write_manifest(
        &root,
        &serde_json::to_string_pretty(&parsed).expect("re-encode the manifest"),
    );
    let error = failure(&root);
    assert!(
        error.contains("one entry to a line"),
        "the failure states the form the three crates without a JSON reader read: {error}"
    );
}

#[test]
fn the_receipt_is_byte_identical_across_two_runs() {
    let root = repo().join("target/xtask-coverage-cases/receipt");
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the receipt fixture");
    }
    for directory in [
        "contracts",
        "generated/ir",
        "generated/rust/mandate-contract/src",
        "systems/mandate",
    ] {
        fs::create_dir_all(root.join(directory)).expect("receipt fixture tree");
    }
    fs::copy(
        repo().join("contracts/coverage.json"),
        root.join("contracts/coverage.json"),
    )
    .expect("copy the manifest");
    fs::copy(
        repo().join("generated/ir/system.json"),
        root.join("generated/ir/system.json"),
    )
    .expect("copy the compiled model");
    copy_tree(
        &repo().join("generated/rust/mandate-contract/src"),
        &root.join("generated/rust/mandate-contract/src"),
    );
    copy_tree(
        &repo().join("systems/mandate"),
        &root.join("systems/mandate"),
    );

    receipt::receipt(&root, &root.join("generated")).expect("the receipt is written");
    let first = fs::read(root.join("generated/coverage/receipt.json")).expect("the receipt");
    receipt::receipt(&root, &root.join("generated")).expect("the receipt is written again");
    let second = fs::read(root.join("generated/coverage/receipt.json")).expect("the receipt");
    assert_eq!(
        first, second,
        "the receipt is not byte-identical across two runs, so `cargo xtask contracts` would \
         report drift the contract does not have"
    );

    let parsed: serde_json::Value = serde_json::from_slice(&first).expect("the receipt is JSON");
    assert_eq!(parsed["format"], "mandate-coverage-receipt/1");
    for digest in [
        "source_digest",
        "ir_digest",
        "contract_crate_digest",
        "manifest_digest",
    ] {
        let value = parsed[digest].as_str().unwrap_or_default();
        assert_eq!(value.len(), 64, "{digest} is not a SHA-256 digest: {value}");
    }
    assert_eq!(
        parsed["counts"]["type"]["implemented"], 93,
        "the receipt states the per-kind counts; 93 and not the 108 this pin first carried, \
         because wave D's correction round refused a generated contract shape as an \
         implementation and the 23 derived `.State` entries that named one now follow their \
         records — six to mandate-model's own enums, two to mandate-token's authored types, \
         and seventeen to declared or deferred"
    );
    // The receipt binds digests and counts and nothing else: test ids are the step's live
    // check, so `generate()` nests no cargo test build (the wave D ruling). A test id is the
    // one thing in the manifest that carries `::`, so its absence is checkable here.
    assert!(
        !String::from_utf8_lossy(&first).contains("::"),
        "the receipt carries a test id, which is the step's live check and not a digest"
    );
}

#[test]
fn the_receipt_moves_when_the_manifest_does() {
    let root = fixture("receipt-drift");
    fs::create_dir_all(root.join("generated/rust/mandate-contract/src")).expect("fixture tree");
    copy_tree(
        &repo().join("generated/rust/mandate-contract/src"),
        &root.join("generated/rust/mandate-contract/src"),
    );
    copy_tree(
        &repo().join("systems/mandate"),
        &root.join("systems/mandate"),
    );

    receipt::receipt(&root, &root.join("generated")).expect("the receipt is written");
    let before = fs::read_to_string(root.join("generated/coverage/receipt.json")).expect("receipt");

    let body = manifest(&root);
    let entry = line(&body, "mandate.authorization.DecisionRecorded");
    write_manifest(
        &root,
        &body.replace(
            &entry,
            &entry.replace("\"status\":\"declared\"", "\"status\":\"deferred\""),
        ),
    );
    receipt::receipt(&root, &root.join("generated")).expect("the receipt is written again");
    let after = fs::read_to_string(root.join("generated/coverage/receipt.json")).expect("receipt");

    assert_ne!(
        before, after,
        "the receipt did not move when the manifest did, so a committed receipt would not \
         bind the manifest it was written from"
    );
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("destination");
    for entry in fs::read_dir(from).expect("source directory") {
        let path = entry.expect("entry").path();
        let name = path.file_name().expect("file name");
        if path.is_dir() {
            copy_tree(&path, &to.join(name));
        } else {
            fs::copy(&path, to.join(name)).expect("copy file");
        }
    }
}

/// [`coverage::Compiled::crates`] is the set of **workspace members**, which is what the
/// symbol check at [`coverage::decide`] reads when it decides whether a path root names a
/// crate of this workspace.
///
/// It was built from every `package_id` the `cargo test --message-format=json` stream
/// mentions, which is every resolved third-party dependency as well, so `serde_json::Value`
/// passed a check whose whole content is "this is one of ours". The stream is not an answer
/// to that question; `cargo metadata --no-deps` is.
#[test]
fn the_workspace_crate_set_is_the_members_and_not_every_package_cargo_mentioned() {
    let compiled = coverage::compiled(&repo()).expect("the workspace test set");
    for member in [
        "mandate_types",
        "mandate_token",
        "mandate_contract",
        "xtask",
    ] {
        assert!(
            compiled.crates.contains(member),
            "{member} is a member of this workspace and the crate set does not hold it: \
             {:?}",
            compiled.crates
        );
    }
    for dependency in ["serde_json", "serde", "sha2"] {
        assert!(
            !compiled.crates.contains(dependency),
            "{dependency} is a third-party dependency and the crate set holds it, so a \
             symbol rooted in it passes the check that its root is a crate of this workspace"
        );
    }
}

/// A generated contract shape is the contract re-emitted, not an implementation of it.
///
/// `mandate_contract` is a member of this workspace, so the "root is a crate of this
/// workspace" check admits it by name. What it cannot admit is the claim: an entry whose
/// only symbol is `mandate_contract::entities::…` says the element is implemented by the
/// projection of its own declaration, which every element has and which decides nothing.
#[test]
fn an_implemented_entry_naming_a_generated_contract_symbol_fails() {
    let root = fixture("generated-symbol");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    let doctored = entry.replace(
        "\"impl\":[\"crate::record::Grant\"]",
        "\"impl\":[\"mandate_contract::entities::MandateGraphGrant\"]",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));
    let error = failure(&root);
    assert!(
        error.contains("mandate_contract"),
        "the failure names the generated shape claimed as an implementation: {error}"
    );
}

/// The committed manifest names no generated contract shape as an implementation.
///
/// The case above decides the rule; this one decides the file the gate reads, because the
/// rule arrived after the manifest did. It is the whole class in one assertion rather than
/// the 23 derived `.State` entries the adversary's measurement found.
#[test]
fn no_entry_of_the_committed_manifest_names_a_generated_contract_symbol() {
    let text = fs::read_to_string(repo().join("contracts/coverage.json")).expect("the manifest");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("the manifest is JSON");
    let entries = parsed["entries"]
        .as_array()
        .expect("the manifest's entries");
    assert_eq!(entries.len(), 292, "the manifest's element count");
    let mut claimed = Vec::new();
    for entry in entries {
        for symbol in entry["impl"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let symbol = symbol.as_str().unwrap_or_default();
            if symbol.split("::").next() == Some("mandate_contract") {
                claimed.push(format!(
                    "  {}: {symbol}",
                    entry["element"].as_str().unwrap_or_default()
                ));
            }
        }
    }
    assert!(
        claimed.is_empty(),
        "{} entries of the committed manifest name a generated contract shape as the \
         implementation of the element the shape was generated from:\n{}",
        claimed.len(),
        claimed.join("\n")
    );
}

/// An `implemented` entry names at least one test of the crate that implements it.
///
/// Existence alone makes every id in the workspace satisfy every element: the column says
/// "the checks that decide it", and a case of another package decides another crate's
/// claim. The per-crate manifest case reconciles `element` and `impl` and never reads this
/// column, so nothing else in the tree can see it.
#[test]
fn an_implemented_entry_whose_tests_all_belong_to_another_crate_fails() {
    let root = fixture("foreign-tests");
    let body = manifest(&root);
    let entry = line(&body, "mandate.graph.Grant");
    let (_, rest) = entry
        .split_once("\"tests\":[")
        .expect("the entry states its tests");
    let (list, _) = rest.split_once(']').expect("the tests list closes");
    let doctored = entry.replace(
        &format!("\"tests\":[{list}]"),
        "\"tests\":[\"mandate-model::contract_agreement::the_coverage_manifest_names_exactly_what_this_crate_realizes\"]",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));
    let error = failure(&root);
    assert!(
        error.contains("mandate.graph.Grant"),
        "the failure names the element whose checks belong to another crate: {error}"
    );
}

/// An `#[ignore]`d case is listed by `--list` exactly as a running one and is never run, so
/// it proves nothing and is not in the proven set.
///
/// The guard is the second assertion: a running case of the **same binary** has to be in the
/// set, or the absence of the ignored one would be a parse that read nothing rather than a
/// subtraction.
#[test]
fn an_ignored_case_is_not_in_the_proven_test_set() {
    let compiled = coverage::compiled(&repo()).expect("the workspace test set");
    let running =
        "xtask::adversary_coverage_1::an_ignored_case_is_not_a_test_that_decides_an_element";
    assert!(
        compiled.tests.contains(running),
        "the proven set holds no case of the binary the ignored fixture lives in, so its \
         absence below would decide nothing"
    );
    let ignored = "xtask::adversary_coverage_1::adversary_ignored_fixture";
    assert!(
        !compiled.tests.contains(ignored),
        "{ignored} is `#[ignore]`d and `cargo test` never runs it, and the proven set counts \
         it as a check that decides an element"
    );
}

/// Every crate that runs an agreement suite reconciles its own coverage entries.
///
/// [`coverage::ACCOUNTING_CRATES`] is checked against the compiled test set in both
/// directions already, and both directions start from the list. This starts from the tree:
/// a crate whose `tests/contract_agreement.rs` exists and whose name is not on the list runs
/// a reconciliation no entry of the manifest answers to, which is the shape `mandate-token`
/// had while it round-tripped two authored types the manifest called blocked.
#[test]
fn every_crate_holding_a_contract_agreement_case_is_an_accounting_crate() {
    let compiled = coverage::compiled(&repo()).expect("the workspace test set");
    let holding = coverage::agreement_crates(compiled);
    assert!(
        holding.len() >= 8,
        "only {} workspace member(s) hold a tests/contract_agreement.rs, so this case read \
         almost nothing: {holding:?}",
        holding.len()
    );
    let allowed: Vec<&str> = coverage::AGREEMENT_ALLOWANCES
        .iter()
        .map(|(package, _)| *package)
        .collect();
    let unreconciled: Vec<&str> = holding
        .iter()
        .copied()
        .filter(|package| {
            !coverage::ACCOUNTING_CRATES.contains(package) && !allowed.contains(package)
        })
        .collect();
    assert!(
        unreconciled.is_empty(),
        "{unreconciled:?} run a contract agreement suite and reconcile no coverage entry, \
         and are named in no allowance"
    );
}

/// A `declared` entry names a story the store has not already closed.
///
/// Existence alone is satisfied by a closed story forever; the frontmatter `status:` is what
/// says whether anybody will pick the work up. `story:tenancy-topology` is `implemented`.
#[test]
fn a_declared_entry_on_a_story_at_a_terminal_rung_fails() {
    let root = fixture("terminal-story");
    let body = manifest(&root);
    let entry = line(&body, "mandate.authorization.DecisionRecorded");
    let doctored = entry.replace(
        "\"story\":\"story:declared-writers\"",
        "\"story\":\"story:tenancy-topology\"",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));
    let error = failure(&root);
    assert!(
        error.contains("terminal rung") && error.contains("story:tenancy-topology"),
        "the failure names the closed story and the rung: {error}"
    );
}

/// A `.State` whose record is not `implemented` carries the record's status, story and
/// blocker — the first branch of the rule.
#[test]
fn a_state_entry_that_leaves_its_records_story_fails() {
    let root = fixture("state-follows-record");
    let body = manifest(&root);
    let entry = line(&body, "mandate.identity.RefreshCredential.State");
    let doctored = entry.replace(
        "\"story\":\"story:declared-writers\"",
        "\"story\":\"story:graph-policy-adapter\"",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));
    let error = failure(&root);
    assert!(
        error.contains("mandate.identity.RefreshCredential.State")
            && error.contains("against its record's"),
        "the failure names the .State that left its record: {error}"
    );
}

/// A `.State` whose record is `implemented` and whose enum no crate registers is `declared`
/// with no blocker — the second branch of the rule.
#[test]
fn a_state_entry_of_an_implemented_record_is_declared_and_not_deferred() {
    let root = fixture("state-of-implemented-record");
    let body = manifest(&root);
    let entry = line(&body, "mandate.identity.SecurityEpochSnapshot.State");
    let doctored = entry
        .replace("\"status\":\"declared\"", "\"status\":\"deferred\"")
        .replace(
            "\"reason\":",
            "\"blocker\":\"decision-blocker:epoch\",\"reason\":",
        );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));
    let error = failure(&root);
    assert!(
        error.contains("mandate.identity.SecurityEpochSnapshot.State")
            && error.contains("its record is implemented"),
        "the failure names the second branch of the .State rule: {error}"
    );
}
