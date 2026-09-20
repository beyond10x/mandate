//! Named **data** mutants of the coverage account: one fault to a case, each driven at the
//! step it targets and each stating which check kills it.
//!
//! `tests/mutants/` holds the mutants that are a patch to the *source*: a copy of the tree,
//! `git apply`, and the named test run against it. A manifest is not source — nothing compiles
//! differently when an entry is relabelled — so the same control for the coverage account is
//! cheaper and sharper as ordinary cases here: copy the files the step reads into a scratch
//! root under `target/`, change exactly one thing, and drive `coverage::coverage(&root)` at it.
//! That is what `Action::Coverage { root }` exists for, and `xtask/tests/coverage.rs` already
//! reads a doctored root this way.
//!
//! # Why this is a second file beside `coverage.rs`
//!
//! `xtask/tests/coverage.rs` decides the step's rules: each of its cases states a rule and
//! shows the step applying it. This file decides something the step cannot state about
//! itself — **which** check kills each fault, and therefore which faults this step does not
//! kill at all. Four of the ten mutants below are accepted by the coverage step and refused
//! elsewhere, and a suite that only ever asserts refusals cannot say so: an escaping mutant
//! would look exactly like a mutant nobody wrote.
//!
//! The four do not partition by one killer each, and an earlier revision of this comment said
//! they did:
//!
//! * the **two relabels** are killed twice over — by the per-crate registry-equality case,
//!   which is the detector of the *claim* (`ESS_REALIZATIONS` does not name the element), and
//!   by the regeneration byte-compare of `cargo xtask contracts`, which is the detector of the
//!   *edit*. `generated/coverage/receipt.json` binds `contracts/coverage.json` by
//!   `manifest_digest` and by the per-kind counts, so **every** byte-level change to the
//!   manifest is projection drift, a relabel included;
//! * the **two receipt mutations** are killed by the byte-compare alone. Nothing else reads
//!   the receipt: not this step, and not a per-crate case, which reconciles a registry against
//!   the manifest and never against the receipt.
//!
//! So the byte-compare is the broader net and the registry case is the specific one, and the
//! interesting fact about a relabel is not that something catches it but that the *account* is
//! what catches the claim. Each case names its killer in its own name and asserts it; the
//! relabel's second killer is asserted by
//! [`a_relabel_moves_the_receipt_so_the_regeneration_byte_compare_kills_it_too`], because a
//! statement about which check kills what belongs in a case and not in this comment.
//!
//! # What the step reads, and what it is blind to
//!
//! `coverage::coverage(root)` reads `root/contracts/coverage.json` and
//! `root/generated/ir/system.json`, and nothing else from `root`: the planning store and the
//! compiled test binaries are always this workspace's own, so a copy cannot answer for
//! itself. In particular it never reads `generated/coverage/receipt.json`. The receipt is
//! bound by regeneration and byte-compare — `cargo xtask contracts` — so the two receipt
//! mutants below are driven at `receipt::receipt` and the comparison that step makes, not at
//! this one. `main.rs`'s `files()` is private to the binary, so the comparison is reproduced
//! here over the one projection these mutations touch.
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
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// The per-crate case that reconciles `mandate-authz`'s registry with the manifest: the run
/// that kills both relabels this step lets through.
const AUTHZ_REGISTRY_CASE: &str = "mandate-authz::contract_agreement::the_coverage_manifest_names_exactly_what_this_crate_realizes";

/// The mutant record that carries the first of those two into the patch catalogue.
const RELABEL_RECORD: &str = "tests/mutants/manifest-relabel.json";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// A root holding exactly what the step reads from one: the manifest and the compiled model.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-coverage-mutants").join(name);
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

/// Write `body` with the entry for `element` replaced by `doctored`, refusing a mutation that
/// changed nothing: a fixture that mutates nothing proves the step accepts the committed
/// manifest, which is another case's job.
fn mutate(root: &Path, element: &str, doctored: &str) {
    let body = manifest(root);
    let entry = line(&body, element);
    assert_ne!(entry, doctored, "{element}: the mutation changed nothing");
    write_manifest(root, &body.replace(&entry, doctored));
}

/// The rung the planning store reports for a story, when it is a terminal one.
///
/// The same reading [`coverage::decide`] takes — the frontmatter between the first two `---`
/// lines, and a `status:` in the body is prose — because a precondition of a case here is
/// only worth asserting if it is the fact the step acts on. The step's own `terminal_rung` is
/// private to the module, so the reading is repeated rather than reached for.
fn terminal_rung(story: &str) -> Option<String> {
    const TERMINAL: [&str; 3] = ["implemented", "archived", "rejected"];
    let name = story.strip_prefix("story:").unwrap_or(story);
    let path = repo().join(format!(".engineering/planning/story/{name}.md"));
    let text =
        fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
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

/// The step's refusal of a doctored root.
fn failure(root: &Path) -> String {
    match coverage::coverage(root) {
        Ok(report) => panic!("the doctored root was accepted:\n{report}"),
        Err(error) => error.to_string(),
    }
}

/// The step's acceptance of a doctored root: a mutation this step is blind to.
fn accepted(root: &Path) -> String {
    coverage::coverage(root).unwrap_or_else(|error| {
        panic!("the doctored root was refused by this step, which is not the killer this case names:\n{error}")
    })
}

// ---------------------------------------------------------------------------------------
// The two relabels: accepted here, killed by the per-crate registry case and by the
// regeneration byte-compare.
// ---------------------------------------------------------------------------------------

/// A `deferred` entry relabelled `implemented`, with a real symbol of a real accounting crate
/// and a real case of that same crate.
///
/// This is `tests/mutants/manifest-relabel.patch` as a data mutation. Every rule this step
/// has about an `implemented` entry is satisfied by the relabel — `mandate-authz` runs a
/// manifest case, `crate::decision::Taken` is a path rooted in a workspace member, and the
/// named test is one a compiled binary lists and belongs to that crate — so the step accepts
/// it, and nothing here can see that `mandate_authz::ESS_REALIZATIONS` never names the
/// element. The registry is the fact that contradicts the *claim*, and it is compiled into
/// the crate rather than readable from a root, so that kill belongs to the crate's own case.
///
/// It is not the only kill, and the catalogue's record names it because it is the one that
/// decides the claim rather than the edit: the relabel also moves `manifest_digest` and the
/// per-kind counts of the receipt, so `cargo xtask contracts` refuses it as projection drift
/// like any other change to the manifest — asserted by
/// [`a_relabel_moves_the_receipt_so_the_regeneration_byte_compare_kills_it_too`].
#[test]
fn a_deferred_entry_relabelled_implemented_escapes_this_step_and_is_killed_by_the_registry_case() {
    let root = fixture("deferred-relabelled-implemented");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let head = entry
        .split_once("\"impl\":[")
        .expect("the entry states an impl list")
        .0;
    let doctored = format!(
        "{head}\"crate\":\"mandate-authz\",\"impl\":[\"crate::decision::Taken\"],\"tests\":[\"{AUTHZ_REGISTRY_CASE}\"]}},"
    )
    .replace("\"status\":\"deferred\"", "\"status\":\"implemented\"");
    mutate(&root, "mandate.delegation.DelegationCreated", &doctored);

    let report = accepted(&root);
    assert!(
        report.contains("292 contract elements mapped"),
        "the step read the doctored manifest whole: {report}"
    );
}

/// The same relabel the other way round, onto a story that is live and unblocked.
///
/// The escape is **not** the status change on its own. `mandate.authorization.Denied` sits on
/// `story:check-api`, which the store reports `implemented`, and a `declared` entry on a
/// story at a terminal rung is refused by this step by that rule alone — asserted below
/// before the escaping form is built, so the difference between the two is decided here and
/// not described. What escapes is the demotion that *also* repoints the entry at a live
/// story: the entry then carries no crate, no symbol and no test, states a reason, and names
/// a story that is neither terminal nor held by an open blocker, so every rule this step has
/// is satisfied. What it contradicts is `mandate_authz::ESS_REALIZATIONS`, which still names
/// the element — so the crate's own case is again the killer of the claim, and this is the
/// direction of the fault the patch catalogue carries no record for.
///
/// `story:declared-writers` being off a terminal rung is a fact about the store, not about
/// this file, so it is read the way [`coverage::decide`] reads it — the frontmatter between
/// the first two `---` lines — and asserted. The day that story closes, this case fails
/// naming it rather than silently becoming a case about a refusal.
#[test]
fn an_implemented_entry_relabelled_declared_onto_a_live_story_escapes_this_step() {
    let live = "story:declared-writers";
    if let Some(rung) = terminal_rung(live) {
        panic!(
            "{live}: the store now reports `{rung}`, a terminal rung. This case needs it off \
             one — the step refuses any non-implemented entry whose story is at a terminal \
             rung, so the demotion below would be refused by that rule and would stop being \
             the escape this case is about. Repoint it at a live, unblocked story."
        );
    }

    // The status change alone, with the entry left on its own finished story: refused here.
    let closed = fixture("implemented-relabelled-declared-on-a-finished-story");
    let body = manifest(&closed);
    let entry = line(&body, "mandate.authorization.Denied");
    let head = entry
        .split_once("\"crate\":\"")
        .expect("the entry names a crate")
        .0;
    let status_only = format!(
        "{head}\"impl\":[],\"tests\":[],\"reason\":\"the decision point returns the refusal to \
         its caller\"}},"
    )
    .replace("\"status\":\"implemented\"", "\"status\":\"declared\"");
    mutate(&closed, "mandate.authorization.Denied", &status_only);
    let error = failure(&closed);
    assert!(
        error.contains("story:check-api") && error.contains("terminal rung"),
        "a status-only demotion is refused on the rung of the story it keeps: {error}"
    );

    let root = fixture("implemented-relabelled-declared");
    let body = manifest(&root);
    let entry = line(&body, "mandate.authorization.Denied");
    let head = entry
        .split_once("\"crate\":\"")
        .expect("the entry names a crate")
        .0;
    let doctored = format!(
        "{head}\"impl\":[],\"tests\":[],\"reason\":\"the decision point returns the refusal to \
         its caller; story:declared-writers decides the writer\"}},"
    )
    .replace("\"status\":\"implemented\"", "\"status\":\"declared\"")
    .replace(
        "\"story\":\"story:check-api\"",
        "\"story\":\"story:declared-writers\"",
    );
    mutate(&root, "mandate.authorization.Denied", &doctored);

    let report = accepted(&root);
    assert!(
        report.contains("292 contract elements mapped"),
        "the step read the doctored manifest whole: {report}"
    );
}

/// The run that kills both relabels is one this workspace makes, and the catalogue names it.
///
/// The two cases above assert that this step is blind to a relabel; on their own that is a
/// pair of green cases recording a hole. This is what makes them evidence: the killer they
/// name is a case a compiled binary lists and runs, and `tests/mutants/manifest-relabel.json`
/// declares exactly that run as the kill for the patch form of the first one.
#[test]
fn the_registry_case_that_kills_the_relabels_is_run_and_is_what_the_relabel_record_names() {
    let compiled = coverage::compiled(&repo()).expect("the workspace test set");
    assert!(
        compiled.tests.contains(AUTHZ_REGISTRY_CASE),
        "{AUTHZ_REGISTRY_CASE} is the killer the two relabel cases name and no compiled test \
         binary lists and runs it"
    );

    let path = repo().join(RELABEL_RECORD);
    let record: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let (package, target, case) = (
        record["crate"].as_str().unwrap_or_default(),
        record["test_target"].as_str().unwrap_or_default(),
        record["test"].as_str().unwrap_or_default(),
    );
    assert_eq!(
        format!("{package}::{target}::{case}"),
        AUTHZ_REGISTRY_CASE,
        "{RELABEL_RECORD} names a run other than the one that kills the relabel"
    );
    assert_eq!(
        record["kill"], "test-fails",
        "{RELABEL_RECORD}: the registry case is a test that fails, not a step that refuses"
    );
}

/// A relabel is refused by the regeneration byte-compare as well as by the registry case.
///
/// The receipt binds the manifest by `manifest_digest` and by the per-kind counts, so a
/// relabel — which changes both — is projection drift, exactly as the two receipt mutations
/// below are. This case is what stops the file's account of the killers being prose: the
/// earlier revision of the module comment gave the relabels the registry case and the
/// byte-compare the two receipt mutants, as though each fault had one killer, and nothing in
/// the tree compared that claim against the code.
///
/// The two killers are not interchangeable, which is why the catalogue's record names the
/// registry one. The byte-compare refuses the **edit**: it would refuse a corrected manifest
/// just the same, and a regenerated receipt makes it green again while the false claim
/// stands. The registry case refuses the **claim**, and no regeneration quiets it.
#[test]
fn a_relabel_moves_the_receipt_so_the_regeneration_byte_compare_kills_it_too() {
    let root = receipt_fixture("relabel-against-the-receipt");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let head = entry
        .split_once("\"impl\":[")
        .expect("the entry states an impl list")
        .0;
    let doctored = format!(
        "{head}\"crate\":\"mandate-authz\",\"impl\":[\"crate::decision::Taken\"],\"tests\":[\"{AUTHZ_REGISTRY_CASE}\"]}},"
    )
    .replace("\"status\":\"deferred\"", "\"status\":\"implemented\"");
    mutate(&root, "mandate.delegation.DelegationCreated", &doctored);

    let (committed, fresh) = regenerated(&root);
    assert_ne!(
        committed, fresh,
        "a relabelled manifest regenerates the same receipt, so `cargo xtask contracts` would \
         not refuse it and the receipt binds bytes it does not bind"
    );
    let written = String::from_utf8_lossy(
        fresh
            .get(Path::new("receipt.json"))
            .expect("the regeneration writes a receipt"),
    )
    .into_owned();
    let held = String::from_utf8_lossy(
        committed
            .get(Path::new("receipt.json"))
            .expect("the fixture holds the committed receipt"),
    )
    .into_owned();
    let digest = |text: &str| -> String {
        text.lines()
            .find(|line| line.contains("manifest_digest"))
            .expect("the receipt states a manifest digest")
            .trim()
            .to_owned()
    };
    assert_ne!(
        digest(&held),
        digest(&written),
        "the relabel left manifest_digest where it was, so the digest does not bind the \
         entries of the manifest"
    );

    // And the coverage step still accepts it: the two killers are elsewhere, which is the
    // whole point of the pair of escape cases above.
    accepted(&root);
}

// ---------------------------------------------------------------------------------------
// The mutations this step kills.
//
// The first two restate rules `xtask/tests/coverage.rs` already decides — an element the
// manifest does not name, and two entries for one element. They are kept here rather than
// pointed at, because this file's subject is the killer of each fault and an account with
// holes in it where another file happens to cover the same ground is not an account. Where
// they overlap they use a different element from that file's cases, so a fixture that stopped
// mutating anything would show up as one of the two going green for the wrong reason.
// ---------------------------------------------------------------------------------------

/// An entry deleted: the element goes on being declared by the compiled model and the map
/// stops answering for it.
#[test]
fn an_entry_deleted_leaves_an_element_the_model_declares_unmapped() {
    let root = fixture("entry-deleted");
    let body = manifest(&root);
    let dropped = line(&body, "mandate.delegation.DelegationCreated");
    // Not the last entry, so the line before it keeps its comma and the manifest stays
    // well-formed JSON: what fails is the account, not the parse.
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
        error.contains("mandate.delegation.DelegationCreated") && error.contains("no entry for it"),
        "the failure names the element the manifest dropped: {error}"
    );
}

/// An entry duplicated: one declared element with two realizers, which is two answers to
/// "who implements this".
#[test]
fn an_entry_duplicated_gives_one_element_two_realizers() {
    let root = fixture("entry-duplicated");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    // The line already carries the comma that separates it from the next entry, so the copy
    // goes below it and the manifest stays well-formed JSON.
    write_manifest(&root, &body.replace(&entry, &format!("{entry}\n{entry}")));
    let error = failure(&root);
    assert!(
        error.contains("mandate.delegation.DelegationCreated") && error.contains("2 entries"),
        "the failure names the element two entries claim: {error}"
    );
}

/// An element renamed: the entry answers for nothing and the element it was written for is
/// unanswered. Both halves of the set comparison have to fire, or a rename would be a way of
/// dropping an element while the entry count stayed put.
#[test]
fn an_element_renamed_to_one_the_model_does_not_declare_fails_both_ways() {
    let root = fixture("element-renamed");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let doctored = entry.replace(
        "\"element\":\"mandate.delegation.DelegationCreated\"",
        "\"element\":\"mandate.delegation.DelegationsCreated\"",
    );
    mutate(&root, "mandate.delegation.DelegationCreated", &doctored);
    let error = failure(&root);
    assert!(
        error.contains("mandate.delegation.DelegationsCreated")
            && error.contains("does not declare"),
        "the failure names the element nothing declares: {error}"
    );
    assert!(
        error.contains("mandate.delegation.DelegationCreated: the compiled model declares it"),
        "the failure names the element left unmapped by the rename: {error}"
    );
}

/// A `deferred` entry whose blocker the store has **cleared**.
///
/// `decision-blocker:algorithm-policy` is a real blocker of this store and its status is
/// `cleared`, so `aep plan artifact blocked` no longer reports it. That is the shape this
/// fault has in life — the decision was taken and the entry stayed deferred — and an
/// invented blocker id is the easier half of it.
#[test]
fn a_deferred_entry_whose_blocker_the_store_has_cleared_fails() {
    let root = fixture("blocker-cleared");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let doctored = entry.replace(
        "\"blocker\":\"decision-blocker:identity-uniqueness\"",
        "\"blocker\":\"decision-blocker:algorithm-policy\"",
    );
    mutate(&root, "mandate.delegation.DelegationCreated", &doctored);
    let error = failure(&root);
    assert!(
        error.contains("decision-blocker:algorithm-policy") && error.contains("does not report"),
        "the failure names the blocker the store has cleared: {error}"
    );
}

/// An entry moved onto a story the store reports `implemented`: a map that answers "who
/// implements this" with work that is over.
#[test]
fn a_deferred_entry_moved_onto_a_story_the_store_reports_implemented_fails() {
    let root = fixture("story-finished");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let doctored = entry.replace(
        "\"story\":\"story:agent-authority-kernel\"",
        "\"story\":\"story:tenancy-topology\"",
    );
    mutate(&root, "mandate.delegation.DelegationCreated", &doctored);
    let error = failure(&root);
    assert!(
        error.contains("story:tenancy-topology") && error.contains("terminal rung"),
        "the failure names the finished story the entry was moved onto: {error}"
    );
}

/// A `.State` entry moved off its record: the lifecycle enum of a record carries that
/// record's account, and a `.State` on another story is a second answer for one element.
#[test]
fn a_state_entry_moved_off_its_records_story_fails() {
    let root = fixture("state-moved");
    let body = manifest(&root);
    let entry = line(&body, "mandate.delegation.Agent.State");
    let doctored = entry.replace(
        "\"story\":\"story:declared-writers\"",
        "\"story\":\"story:mutation-controls\"",
    );
    mutate(&root, "mandate.delegation.Agent.State", &doctored);
    let error = failure(&root);
    assert!(
        error.contains("mandate.delegation.Agent.State") && error.contains("against its record's"),
        "the failure names the .State that left its record: {error}"
    );
}

// ---------------------------------------------------------------------------------------
// The receipt: mutations of a generated artifact the coverage step does not read.
// ---------------------------------------------------------------------------------------

/// A root holding everything `receipt::receipt` reads, with the committed receipt in place.
fn receipt_fixture(name: &str) -> PathBuf {
    let root = fixture(name);
    for directory in ["generated/rust/mandate-contract/src", "systems/mandate"] {
        fs::create_dir_all(root.join(directory)).expect("receipt fixture tree");
    }
    copy_tree(
        &repo().join("generated/rust/mandate-contract/src"),
        &root.join("generated/rust/mandate-contract/src"),
    );
    copy_tree(
        &repo().join("systems/mandate"),
        &root.join("systems/mandate"),
    );
    fs::create_dir_all(root.join("generated/coverage")).expect("receipt directory");
    fs::copy(
        repo().join("generated/coverage/receipt.json"),
        root.join("generated/coverage/receipt.json"),
    )
    .expect("copy the committed receipt");
    root
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

/// Every file of a projection directory, as `cargo xtask contracts` compares them.
///
/// That step's own `files()` walks the whole of `generated/` and is private to the binary
/// crate; this is the same comparison over the one projection these two mutations touch, so
/// what is decided here is the comparison and not a reimplementation of the walk.
fn projection(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return files;
    };
    for entry in entries {
        let path = entry.expect("entry").path();
        let name = PathBuf::from(path.file_name().expect("file name"));
        files.insert(name, fs::read(&path).expect("projection file"));
    }
    files
}

/// The committed receipt, a fresh one written from the same root, and the coverage step's
/// answer about that root.
fn regenerated(root: &Path) -> (BTreeMap<PathBuf, Vec<u8>>, BTreeMap<PathBuf, Vec<u8>>) {
    let committed = projection(&root.join("generated/coverage"));
    let fresh = root.join("target/regeneration");
    if fresh.exists() {
        fs::remove_dir_all(&fresh).expect("clear the regeneration");
    }
    receipt::receipt(root, &fresh).expect("the receipt is written");
    (committed, projection(&fresh.join("coverage")))
}

/// A digest of the receipt altered by hand: the manifest it binds is no longer the manifest
/// it was written from, and nothing about it is refused by the coverage step.
#[test]
fn the_receipts_manifest_digest_altered_is_refused_by_regeneration_and_not_by_the_coverage_step() {
    let root = receipt_fixture("receipt-digest-altered");
    let path = root.join("generated/coverage/receipt.json");
    let body = fs::read_to_string(&path).expect("the committed receipt");
    let mut parsed: serde_json::Value = serde_json::from_str(&body).expect("the receipt is JSON");
    let digest = parsed["manifest_digest"]
        .as_str()
        .expect("the receipt states a manifest digest")
        .to_owned();
    let altered = format!("0{}", &digest[1..]);
    assert_ne!(digest, altered, "the mutation changed nothing");
    parsed["manifest_digest"] = serde_json::Value::from(altered.clone());
    fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&parsed).expect("re-encode the receipt")
        ),
    )
    .expect("write the doctored receipt");

    // The step that binds the receipt is `cargo xtask contracts`: it writes a fresh one from
    // the same inputs and byte-compares.
    let (committed, fresh) = regenerated(&root);
    assert_ne!(
        committed, fresh,
        "the doctored receipt survived regeneration, so the digest that binds the manifest \
         binds nothing"
    );
    let written = String::from_utf8_lossy(
        fresh
            .get(Path::new("receipt.json"))
            .expect("the regeneration writes a receipt"),
    )
    .into_owned();
    assert!(
        written.contains(&digest) && !written.contains(&altered),
        "the fresh receipt states the digest of the manifest it was written from: {written}"
    );

    // And the coverage step is blind to it: the manifest and the compiled model are what it
    // reads from a root, so a receipt that contradicts them is not its failure to find.
    accepted(&root);
}

/// The receipt deleted: the projection the gate compares is simply absent, and again the
/// coverage step has nothing to say about it.
#[test]
fn the_receipt_deleted_is_refused_by_regeneration_and_not_by_the_coverage_step() {
    let root = receipt_fixture("receipt-deleted");
    fs::remove_file(root.join("generated/coverage/receipt.json")).expect("delete the receipt");

    let (committed, fresh) = regenerated(&root);
    assert!(
        committed.is_empty(),
        "the fixture did not delete the receipt"
    );
    assert_ne!(
        committed, fresh,
        "a generated projection the tree no longer holds compares equal to a fresh one, so \
         deleting it is a mutation nothing sees"
    );
    assert!(
        fresh.contains_key(Path::new("receipt.json")),
        "the regeneration writes the receipt the tree is missing"
    );

    accepted(&root);
}
