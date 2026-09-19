//! Adversary pass 2 against `story:coverage-map`, after correction round 1.
//!
//! Every case here drives the **unit's own documents** against the unit's own data:
//!
//! * `xtask/src/coverage.rs:53-55` states the rule a `.State` entry follows. The manifest is
//!   the data that rule is about, and nothing in the tree compares the two.
//! * `.engineering/planning/story/coverage-map.md` (Scope, "Generated") states that
//!   `generated/coverage/receipt.json` is "written only by `generate()`" and byte-compared by
//!   `contracts()`. `xtask/src/receipt.rs` is the writer that wiring has to call.
//! * The manifest's `story` column is the routing a reader of the map follows for an element
//!   nothing implements.
//!
//! No implementation file is touched by this file; every fixture is built under `target/`.
#![allow(dead_code)]
#[path = "../src/documents.rs"]
mod documents;
#[path = "../src/emit.rs"]
mod emit;

#[path = "../src/coverage.rs"]
mod coverage;
#[path = "../src/receipt.rs"]
mod receipt;

use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}

/// Every entry of the committed manifest, by element.
fn entries() -> BTreeMap<String, Value> {
    let path = repo().join("contracts/coverage.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let manifest: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let listed = manifest["entries"]
        .as_array()
        .expect("the manifest states entries");
    let mut by_element = BTreeMap::new();
    for entry in listed {
        by_element.insert(
            entry["element"]
                .as_str()
                .expect("an entry names an element")
                .to_owned(),
            entry.clone(),
        );
    }
    assert_eq!(
        by_element.len(),
        listed.len(),
        "two entries name one element, so this case reads only one of them"
    );
    by_element
}

fn text_of(entry: &Value, key: &str) -> String {
    entry[key].as_str().unwrap_or_default().to_owned()
}

/// The `.State` rule, as ruled at adversary pass 2 (coordinator amendment):
///
/// > A `.State` element follows its record. Where the record is not `implemented`, the
/// > `.State` carries the record's status, story and blocker. Where the record is
/// > `implemented` but no crate registers its own lifecycle enum for it, the `.State` is
/// > `declared` on the live story that will register it.
///
/// Pass 2 found the unit's own rule (`xtask/src/coverage.rs:53-55`) had no satisfiable answer
/// for the four identity epoch `.State` entries whose records are `implemented` on a closed
/// story; the ruling adds the second branch. `decide()` checks both branches; this case is
/// its independent control over the committed manifest.
#[test]
fn every_unimplemented_state_entry_follows_its_record() {
    let by_element = entries();
    let mut derived = 0_usize;
    let mut divergent = Vec::new();
    for (element, entry) in &by_element {
        let Some(record) = element.strip_suffix(".State") else {
            continue;
        };
        derived += 1;
        if text_of(entry, "status") == "implemented" {
            // The registering crate's own equality case decides this branch.
            continue;
        }
        let held = by_element
            .get(record)
            .unwrap_or_else(|| panic!("{element}: the manifest has no entry for {record}"));
        if text_of(held, "status") == "implemented" {
            // Second branch: declared on a live story, no blocker.
            if text_of(entry, "status") != "declared"
                || text_of(entry, "story").is_empty()
                || !text_of(entry, "blocker").is_empty()
            {
                divergent.push(format!(
                    "  {element}: record implemented, so the .State is `declared` on a story \
                     with no blocker; carries status {:?}, story {:?}, blocker {:?}",
                    text_of(entry, "status"),
                    text_of(entry, "story"),
                    text_of(entry, "blocker")
                ));
            }
            continue;
        }
        let mut differs = Vec::new();
        for key in ["status", "story", "blocker"] {
            let (mine, its) = (text_of(entry, key), text_of(held, key));
            if mine != its {
                differs.push(format!("{key} {mine:?} against the record's {its:?}"));
            }
        }
        if !differs.is_empty() {
            divergent.push(format!("  {element}: carries {}", differs.join("; ")));
        }
    }
    assert!(
        derived >= 36,
        "this case found {derived} derived `.State` elements and the manifest holds 36, so it \
         is reading less than the set the rule is about"
    );
    assert!(
        divergent.is_empty(),
        "a `.State` element that is not `implemented` follows its record; {} of the {derived} \
         derived entries do not:\n{}",
        divergent.len(),
        divergent.join("\n")
    );
}

/// The status frontmatter of a planning-store story, as the store writes it.
fn story_status(id: &str) -> String {
    let name = id
        .strip_prefix("story:")
        .unwrap_or_else(|| panic!("{id} is no story id"));
    let path = repo()
        .join(".engineering/planning/story")
        .join(format!("{name}.md"));
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .skip(1)
        .take_while(|line| line.trim_end() != "---")
        .find_map(|line| line.strip_prefix("status:"))
        .unwrap_or_else(|| panic!("{}: states no status", path.display()))
        .trim()
        .to_owned()
}

/// A `declared` entry is the map's answer to "nothing implements this element; who will".
///
/// `decide()` asks only whether the story **file exists** (`xtask/src/coverage.rs:431-437`),
/// which every closed story's file does forever. The step already treats a `declared` entry's
/// story's live store state as load-bearing in the other direction — check 5 refuses a
/// `declared` entry whose story an open blocker holds — so reading the store and not reading
/// the one field that says the work is over is the asymmetry this case closes. An element
/// routed at a story the store reports `implemented` is routed at work that is finished, and
/// no later reader of the map is told that nothing is coming.
#[test]
fn every_declared_entry_names_a_story_the_store_has_not_already_closed() {
    let by_element = entries();
    let terminal = ["implemented", "archived", "rejected", "superseded"];
    let mut declared = 0_usize;
    let mut dead = Vec::new();
    for (element, entry) in &by_element {
        if text_of(entry, "status") != "declared" {
            continue;
        }
        declared += 1;
        let story = text_of(entry, "story");
        let status = story_status(&story);
        if terminal.contains(&status.as_str()) {
            dead.push(format!(
                "  {element}: declared, routed at {story} ({status})"
            ));
        }
    }
    // Coordinator amendment (correction 2): eleven tenancy elements moved to `implemented`.
    assert!(
        declared >= 29,
        "this case found {declared} declared entries and the manifest holds 29"
    );
    assert!(
        dead.is_empty(),
        "{} of the {declared} `declared` entries route at a story the planning store has \
         already closed, so the map answers \"who will implement this\" with work that is \
         over:\n{}",
        dead.len(),
        dead.join("\n")
    );
}

fn scratch(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-2").join(name);
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear the fixture");
    }
    fs::create_dir_all(&root).expect("the fixture root");
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

/// `story:coverage-map`'s Scope names one writer and one check for the receipt:
///
/// > **Generated:** `generated/coverage/receipt.json`, written only by `generate()`
/// > (`xtask/src/main.rs:77-99`) and byte-compared for free: `files()` (`:58-76`) walks the
/// > whole tree and `contracts()` (`:130-142`) diffs it against the regeneration.
///
/// and the Acceptance turns on it: "the receipt `generated/coverage/receipt.json` is
/// byte-identical to what `cargo xtask generate` wrote".
///
/// `generate(root)` is given the **generated-output** root and never the repository:
/// `Action::Generate => generate(Path::new("generated"))` (`xtask/src/main.rs:424`), and
/// `contracts()` calls `generate(&PathBuf::from("target/xtask-contract-regeneration"))`
/// (`:136`) and then diffs `files(<that root>)` against `files("generated")` (`:137`). Every
/// other kind obeys that convention — `ir(root)` writes `<root>/ir/system.json` and
/// `emit::emit(root)` writes `<root>/rust/mandate-contract/src` — so a receipt the
/// byte-compare covers has to be written at `<root>/coverage/receipt.json` by the call
/// `generate()` makes.
///
/// Coordinator amendment (pass 2 ruling on F3): the writer takes two roots, the repository
/// the inputs are read from and the output root the receipt is written under, so the call in
/// `generate(root)` is `receipt::receipt(Path::new("."), root)`.
///
/// Before the ruling, `receipt::receipt(root)` read `root/contracts/coverage.json`, `root/systems/mandate`,
/// `root/generated/ir/system.json` and `root/generated/rust/mandate-contract/src`, and writes
/// `root/generated/coverage/receipt.json`. Its `root` is the repository. The two conventions
/// are the same parameter, so the wiring the Scope names cannot be written.
///
/// The control below proves the writer itself works and that its root is the repository, so
/// what the second half reports is the convention and not a fixture this case forgot.
#[test]
fn the_receipt_writer_accepts_the_root_generate_is_given() {
    // Control: a repository-shaped root. This is the shape `xtask/tests/coverage.rs:401`
    // builds, and it succeeds.
    let repository = scratch("receipt-repository-root");
    for directory in ["contracts", "generated/ir"] {
        fs::create_dir_all(repository.join(directory)).expect("the fixture tree");
    }
    fs::copy(
        repo().join("contracts/coverage.json"),
        repository.join("contracts/coverage.json"),
    )
    .expect("copy the manifest");
    fs::copy(
        repo().join("generated/ir/system.json"),
        repository.join("generated/ir/system.json"),
    )
    .expect("copy the compiled model");
    copy_tree(
        &repo().join("generated/rust/mandate-contract/src"),
        &repository.join("generated/rust/mandate-contract/src"),
    );
    copy_tree(
        &repo().join("systems/mandate"),
        &repository.join("systems/mandate"),
    );
    receipt::receipt(&repository, &repository.join("generated"))
        .expect("the writer takes a source root and an output root");
    assert!(
        repository.join("generated/coverage/receipt.json").is_file(),
        "the control did not write a receipt, so the rest of this case decides nothing"
    );

    // The subject: the root `generate()` is given, holding everything `generate()` puts
    // there — the whole committed `generated/` tree.
    let generated = scratch("receipt-generated-root");
    copy_tree(&repo().join("generated"), &generated);
    assert!(
        generated.join("ir/system.json").is_file(),
        "the fixture is not the root generate() is given"
    );
    let written = receipt::receipt(&repository, &generated);
    assert!(
        written.is_ok(),
        "generate() is given the generated-output root and `receipt::receipt` refuses it, so \
         the receipt cannot be written by the call story:coverage-map's Scope names as its \
         only writer: {}",
        written
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default()
    );
    assert!(
        generated.join("coverage/receipt.json").is_file(),
        "the receipt is not at <root>/coverage/receipt.json, so contracts()' byte-compare of \
         files(<regeneration root>) against files(\"generated\") never covers it"
    );
}

/// A crate can register elements it does not realize and never compare that registry with the
/// manifest, and every gate step passes.
///
/// Six of the twenty-two workspace members declare `ESS_UNREALIZED` today and all six call
/// `no_unrealized_element_contradicts_the_coverage_manifest`; `mandate-model` and
/// `mandate-token` run an agreement suite and declare no such registry. Nothing holds that
/// coincidence in place. `decide()`'s check 8 (`xtask/src/coverage.rs:551-586`) asks one
/// question of a member's directory — does it hold a `tests/contract_agreement.rs` — and
/// `agreement_crates` (`:535-542`) already walks [`coverage::Compiled::packages`] to ask it,
/// so the second question costs the same walk: a member whose `src/lib.rs` declares
/// `ESS_UNREALIZED` and whose agreement suite does not name the clause is a registry the
/// manifest is never reconciled against. That is the state the correction round closed for
/// six crates by hand and left open for the seventh.
///
/// The probe is a fixture, not an edit: the committed tree is untouched and the broken shape
/// is handed to [`coverage::decide`] as a doctored [`coverage::Compiled`], whose `packages`
/// points one accounting crate at a directory holding exactly that shape.
#[test]
fn a_crate_registering_unrealized_elements_its_agreement_suite_never_reconciles_is_refused() {
    let seventh = scratch("seventh-crate");
    fs::create_dir_all(seventh.join("src")).expect("the fixture crate root");
    fs::create_dir_all(seventh.join("tests")).expect("the fixture crate tests");
    fs::write(
        seventh.join("src/lib.rs"),
        "pub const ESS_UNREALIZED: &[(&str, &str)] =\n    \
         &[(\"mandate.core.Audience\", \"nothing in this crate realizes it\")];\n",
    )
    .expect("the fixture registry");
    fs::write(
        seventh.join("tests/contract_agreement.rs"),
        "#[test]\nfn the_coverage_manifest_names_exactly_what_this_crate_realizes() {}\n",
    )
    .expect("the fixture agreement suite");

    let real = coverage::compiled(&repo()).expect("the workspace test set");
    let mut packages = real.packages.clone();
    let repointed = "mandate-token";
    assert!(
        packages
            .insert(repointed.to_owned(), seventh.clone())
            .is_some(),
        "{repointed} is no member of this workspace, so this probe repoints nothing"
    );
    let doctored = coverage::Compiled {
        tests: real.tests.clone(),
        crates: real.crates.clone(),
        packages,
    };
    assert!(
        coverage::agreement_crates(&doctored).contains(repointed),
        "the fixture is not seen as a crate holding an agreement suite, so this probe decides \
         nothing"
    );

    let blocked = documents::store_blocked(&repo()).expect("the planning store's blockers");
    let decided = coverage::decide(&repo(), &repo(), &blocked, &doctored);
    let reported = decided
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        reported.contains("ESS_UNREALIZED") || reported.contains("unrealized"),
        "{repointed} declares ESS_UNREALIZED and its agreement suite never compares that \
         registry with the manifest, and the step reports nothing: a crate's statement that it \
         realizes none of an element is then a second account of the contract that no gate \
         reads. decide() said: {}",
        if reported.is_empty() {
            "the manifest agrees with everything".to_owned()
        } else {
            reported
        }
    );
}
