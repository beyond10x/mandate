//! Adversary pass 3 against round 2 of `story:mutation-controls`: the unit's own new
//! documents, driven against the code the same unit wrote.
//!
//! `xtask/tests/coverage_mutants.rs` states, in prose, which check kills each of its ten data
//! faults — that is the file's declared purpose (`coverage_mutants.rs:14-21`: "This file
//! decides something the step cannot state about itself — **which** check kills each fault").
//! Nothing in the tree compares that account against the code, because the account is a doc
//! comment and the cases that carry it assert only that `coverage::coverage` accepts the
//! doctored root. The cases here read the account as the specification it claims to be.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/coverage.rs"]
mod coverage;
#[path = "../src/mutants.rs"]
mod mutants;
#[path = "../src/receipt.rs"]
mod receipt;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// A directory of this case's own, under `target/`, emptied first.
fn scratch(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-mutants-3").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the scratch directory");
    }
    fs::create_dir_all(&root).expect("scratch directory");
    root
}

fn manifest_text() -> String {
    fs::read_to_string(repo().join("contracts/coverage.json")).expect("the committed manifest")
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

/// A `deferred` entry relabelled `implemented` onto `package`, by the recipe
/// `coverage_mutants.rs:147-156` uses for the mutant `tests/mutants/manifest-relabel.patch`
/// carries.
fn relabelled(entry: &str, package: &str, symbol: &str, test: &str) -> String {
    let head = entry
        .split_once("\"impl\":[")
        .expect("the entry states an impl list")
        .0;
    format!("{head}\"crate\":\"{package}\",\"impl\":[\"{symbol}\"],\"tests\":[\"{test}\"]}},")
        .replace("\"status\":\"deferred\"", "\"status\":\"implemented\"")
}

/// An `implemented` entry demoted to `declared` onto a live story, by the recipe
/// `coverage_mutants.rs:177-190` uses — the second relabel, the one the committed catalogue
/// carries no patch for.
fn demoted(entry: &str) -> String {
    let head = entry
        .split_once("\"crate\":\"")
        .expect("the entry names a crate")
        .0;
    format!(
        "{head}\"impl\":[],\"tests\":[],\"reason\":\"the decision point returns the refusal to \
         its caller; story:declared-writers decides the writer\"}},"
    )
    .replace("\"status\":\"implemented\"", "\"status\":\"declared\"")
    .replace(
        "\"story\":\"story:check-api\"",
        "\"story\":\"story:declared-writers\"",
    )
}

// ---------------------------------------------------------------------------------------
// 1. The account of which check kills a relabel.
// ---------------------------------------------------------------------------------------

/// Every file of a projection directory, as `main.rs`'s `contracts()` compares them.
fn projection(directory: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let Ok(entries) = fs::read_dir(directory) else {
        return files;
    };
    for entry in entries {
        let path = entry.expect("entry").path();
        files.insert(
            PathBuf::from(path.file_name().expect("file name")),
            fs::read(&path).expect("projection file"),
        );
    }
    files
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

/// A root holding everything `receipt::receipt` reads plus the committed receipt: the fixture
/// `coverage_mutants.rs:374-394` builds for its two receipt mutants.
fn receipt_fixture(name: &str) -> PathBuf {
    let root = scratch(name);
    fs::create_dir_all(root.join("contracts")).expect("fixture contracts");
    fs::create_dir_all(root.join("generated/ir")).expect("fixture model");
    fs::create_dir_all(root.join("generated/coverage")).expect("receipt directory");
    for (from, to) in [
        ("contracts/coverage.json", "contracts/coverage.json"),
        ("generated/ir/system.json", "generated/ir/system.json"),
        (
            "generated/coverage/receipt.json",
            "generated/coverage/receipt.json",
        ),
    ] {
        fs::copy(repo().join(from), root.join(to)).expect("copy an input");
    }
    copy_tree(
        &repo().join("generated/rust/mandate-contract/src"),
        &root.join("generated/rust/mandate-contract/src"),
    );
    copy_tree(
        &repo().join("systems/mandate"),
        &root.join("systems/mandate"),
    );
    root
}

/// The committed coverage projection of `root` and a fresh one written from the same root.
fn regenerated(root: &Path) -> (BTreeMap<PathBuf, Vec<u8>>, BTreeMap<PathBuf, Vec<u8>>) {
    let committed = projection(&root.join("generated/coverage"));
    let fresh = root.join("target/regeneration");
    if fresh.exists() {
        fs::remove_dir_all(&fresh).expect("clear the regeneration");
    }
    receipt::receipt(root, &fresh).expect("the receipt is written");
    (committed, projection(&fresh.join("coverage")))
}

/// `coverage_mutants.rs:17-21` partitions the four escaping mutants by killer: "two relabels
/// the per-crate registry case kills, and two receipt mutations the regeneration byte-compare
/// kills", and "each escape asserts the run that does kill it". `:140-142` states it again for
/// the first relabel — "the registry is the fact that contradicts the claim … so **the kill
/// belongs to the crate's own case**".
///
/// This case asserts that partition where it is cheapest to decide: the relabel is applied to
/// a root holding the committed receipt, the receipt is regenerated from that root, and the
/// two are compared the way `main.rs`'s `contracts()` compares them. If the byte-compare is
/// the killer of the two receipt mutants and not of the relabels, a relabelled manifest leaves
/// the coverage projection unchanged.
#[test]
fn the_regeneration_byte_compare_the_file_assigns_to_the_receipt_mutants_says_nothing_of_a_relabel()
{
    let root = receipt_fixture("relabel-against-the-receipt");
    let path = root.join("contracts/coverage.json");
    let body = fs::read_to_string(&path).expect("the fixture manifest");
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let doctored = relabelled(
        &entry,
        "mandate-authz",
        "crate::decision::Taken",
        "mandate-authz::contract_agreement::the_coverage_manifest_names_exactly_what_this_crate_realizes",
    );
    assert_ne!(entry, doctored, "the mutation changed nothing");
    fs::write(&path, body.replace(&entry, &doctored)).expect("write the relabelled manifest");

    let (committed, fresh) = regenerated(&root);
    let read = |files: &BTreeMap<PathBuf, Vec<u8>>| -> String {
        String::from_utf8_lossy(
            files
                .get(Path::new("receipt.json"))
                .expect("a receipt is present"),
        )
        .lines()
        .find(|line| line.contains("manifest_digest"))
        .expect("the receipt states a manifest digest")
        .trim()
        .to_owned()
    };
    assert_eq!(
        committed,
        fresh,
        "the relabel `tests/mutants/manifest-relabel.patch` carries changes the bytes of \
         contracts/coverage.json, and `generated/coverage/receipt.json` binds those bytes by \
         digest, so `cargo xtask contracts` refuses this mutant by regeneration exactly as it \
         refuses the two receipt mutants — committed {}, fresh {}. The file's account of which \
         check kills which fault (coverage_mutants.rs:17-21, :140-142) gives the relabels one \
         killer and the byte-compare only the two receipt mutations",
        read(&committed),
        read(&fresh)
    );
}

/// The committed patch and the data case are said to be one mutation in two forms
/// (`coverage_mutants.rs:136` — "This is `tests/mutants/manifest-relabel.patch` as a data
/// mutation"), and nothing compares them: the data case builds its entry by hand and the
/// registry case that proves the patch reads only the record beside it.
#[test]
fn the_committed_relabel_patch_writes_the_entry_the_data_case_writes() {
    let patch = fs::read_to_string(repo().join("tests/mutants/manifest-relabel.patch"))
        .expect("the committed patch");
    let written: Vec<&str> = patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .map(|line| &line[1..])
        .collect();
    assert_eq!(written.len(), 1, "the patch rewrites one entry");

    let body = manifest_text();
    let entry = line(&body, "mandate.delegation.DelegationCreated");
    let doctored = relabelled(
        &entry,
        "mandate-authz",
        "crate::decision::Taken",
        "mandate-authz::contract_agreement::the_coverage_manifest_names_exactly_what_this_crate_realizes",
    );
    assert_eq!(
        written[0], doctored,
        "the patch in tests/mutants/ and the data case in xtask/tests/coverage_mutants.rs are \
         said to be one mutation in two forms and write different entries"
    );
}

// ---------------------------------------------------------------------------------------
// 2. The kill, in the crates the catalogue does not name.
// ---------------------------------------------------------------------------------------

/// A unified diff rewriting `old` to `new` in `path`, with three lines of context, and the
/// 1-based number of the line it rewrites.
fn unified(path: &str, body: &str, old: &str, new: &str) -> (String, usize) {
    let lines: Vec<&str> = body.lines().collect();
    let index = lines
        .iter()
        .position(|line| *line == old)
        .unwrap_or_else(|| panic!("{path}: the line to rewrite"));
    let start = index.saturating_sub(3);
    let end = (index + 4).min(lines.len());
    let count = end - start;
    let mut patch = format!(
        "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -{0},{1} +{0},{1} @@\n",
        start + 1,
        count
    );
    for (offset, line) in lines[start..end].iter().enumerate() {
        if start + offset == index {
            patch.push_str(&format!("-{line}\n+{new}\n"));
        } else {
            patch.push_str(&format!(" {line}\n"));
        }
    }
    (patch, index + 1)
}

fn record(package: &str, target: &str, test: &str, anchor: &str) -> String {
    format!(
        "{{\"crate\": \"{package}\", \"test_target\": \"{target}\", \"test\": \"{test}\", \
         \"kill\": \"test-fails\", \"anchor\": \"{anchor}\"}}\n"
    )
}

/// The relabel `tests/mutants/manifest-relabel` carries is one crate's: it relabels an element
/// onto `mandate-authz` and is killed by that crate's manifest case. Eight other crates may be
/// named by an `implemented` entry (`coverage::ACCOUNTING_CRATES`), three of them read the
/// manifest as **lines** rather than as JSON because no `serde_json` is reachable from them,
/// and one — `mandate-types` — reconciles against a conformance account rather than a
/// `realizes!` registry. The catalogue proves the kill for `mandate-authz` and the story
/// reports the registry equality as "the real detector"; that a relabel dies in the other
/// accounting crates is a claim no run makes.
///
/// So: four mutants of this case's own, driven through the committed step with its own
/// scratch tree and build directory — a relabel onto `mandate-graph` and onto `mandate-policy`
/// (the line readers), one onto `mandate-types` (the conformance account), and the demotion
/// `coverage_mutants.rs:174` calls an escape and names no patch for, which is the one direction
/// of the fault the catalogue does not carry.
#[test]
fn a_relabel_dies_in_every_accounting_crate_it_names_and_not_only_in_mandate_authz() {
    let body = manifest_text();
    let directory = scratch("nine-crates/catalogue");
    let work = scratch("nine-crates/work");

    let mut named: Vec<(&str, String, String)> = Vec::new();
    for (name, element, package, target, case, symbol) in [
        (
            "relabel-graph",
            "mandate.graph.GrantRevoked",
            "mandate-graph",
            "contract_agreement",
            "the_coverage_manifest_names_exactly_what_this_crate_realizes",
            "crate::port::GraphError",
        ),
        (
            "relabel-policy",
            "mandate.policy.PolicySuperseded",
            "mandate-policy",
            "contract_agreement",
            "the_coverage_manifest_names_exactly_what_this_crate_realizes",
            "crate::record::AuthorizationModel",
        ),
        (
            "relabel-types",
            "mandate.graph.RelationshipWritten",
            "mandate-types",
            "inventory",
            "the_coverage_manifest_names_exactly_what_this_crate_accounts_for",
            "mandate_types::AccessCredentialId",
        ),
    ] {
        let entry = line(&body, element);
        let test = format!("{package}::{target}::{case}");
        let (patch, anchored) = unified(
            "contracts/coverage.json",
            &body,
            &entry,
            &relabelled(&entry, package, symbol, &test),
        );
        named.push((
            name,
            patch,
            record(
                package,
                target,
                case,
                &format!("contracts/coverage.json:{anchored}"),
            ),
        ));
    }
    let entry = line(&body, "mandate.authorization.Denied");
    let (patch, anchored) = unified("contracts/coverage.json", &body, &entry, &demoted(&entry));
    named.push((
        "demote-authz",
        patch,
        record(
            "mandate-authz",
            "contract_agreement",
            "the_coverage_manifest_names_exactly_what_this_crate_realizes",
            &format!("contracts/coverage.json:{anchored}"),
        ),
    ));

    for (name, patch, json) in &named {
        fs::write(directory.join(format!("{name}.patch")), patch).expect("fixture patch");
        fs::write(directory.join(format!("{name}.json")), json).expect("fixture record");
    }

    let table = mutants::bounded(&repo(), &directory, &work, Duration::from_secs(900))
        .unwrap_or_else(|error| {
            panic!(
                "a relabel of the coverage manifest survives in a crate the catalogue does not \
                 name, or the step cannot state the kill:\n{error}"
            )
        });
    for (name, _, _) in &named {
        assert!(
            table.contains(&format!("| `{name}` |")),
            "{name} is missing from the table the step printed:\n{table}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// 3. What the copy says when the tree it is told to copy is not the tree on disk.
// ---------------------------------------------------------------------------------------

fn git(directory: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        directory.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The round-2 result records, for the coordinator, that "`mutants::copy` fails with a bare
/// \"No such file or directory\" when `git ls-files` lists an intent-to-add path absent from
/// disk". A copy failure that names no path is a gate failure nobody can act on, and CI reaches
/// this state whenever an index records a path the checkout does not hold — so the claim is
/// worth deciding rather than recording.
#[test]
fn the_copy_names_the_path_it_cannot_read() {
    let source = scratch("intent-to-add/source");
    fs::write(
        source.join("letters.txt"),
        "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n",
    )
    .expect("the tracked file");
    git(&source, &["init", "-q"]);
    git(&source, &["add", "-A"]);
    fs::write(source.join("ghost.txt"), "ghost\n").expect("the intent-to-add file");
    git(&source, &["add", "-N", "ghost.txt"]);
    fs::remove_file(source.join("ghost.txt")).expect("take it off disk again");

    let directory = scratch("intent-to-add/catalogue");
    let (patch, anchored) = unified(
        "letters.txt",
        "alpha\nbeta\ngamma\ndelta\nepsilon\nzeta\n",
        "delta",
        "DELTA",
    );
    fs::write(directory.join("ghost.patch"), &patch).expect("fixture patch");
    fs::write(
        directory.join("ghost.json"),
        record(
            "a-package-no-workspace-here-resolves",
            "letters",
            "letters",
            &format!("letters.txt:{anchored}"),
        ),
    )
    .expect("fixture record");

    let refused = mutants::bounded(
        &source,
        &directory,
        &scratch("intent-to-add/work"),
        Duration::from_secs(60),
    )
    .expect_err("a tracked path the checkout does not hold fails the copy");

    assert!(
        refused.to_string().contains("ghost.txt"),
        "the step could not copy a path `git ls-files` named and its refusal does not say \
         which: {refused}"
    );
}
