//! Adversarial cases against `story:coverage-map`: the authored manifest read as the
//! specification it claims to be, and driven against the code the same unit wrote.
//!
//! `contracts/coverage.json` is a **second** account of which symbol realizes which element.
//! The first is each crate's own `mandate_types::realizes!` registry together with the
//! `ESS_UNREALIZED` list beside it, which `crates/*/src/lib.rs` documents as "every declared
//! element this crate does **not** realize". `xtask/src/coverage.rs` reads only the manifest,
//! and each crate's per-crate case reads only its own `ESS_REALIZATIONS` — so nothing in the
//! tree compares an `ESS_UNREALIZED` entry against the manifest's claim about the same
//! element. The first two cases here do exactly that.
//!
//! The remaining cases drive the step over doctored copies of the two files it reads from a
//! root, the way `xtask/tests/coverage.rs` does, and ask what an `implemented` entry can get
//! past it.
#![allow(dead_code)] // the binary target uses the whole of each module; a case here uses part.
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

fn manifest_text() -> String {
    fs::read_to_string(repo().join("contracts/coverage.json")).expect("the coverage manifest")
}

/// Every entry of the committed manifest, by element.
fn entries() -> BTreeMap<String, Value> {
    let manifest: Value = serde_json::from_str(&manifest_text()).expect("the manifest is JSON");
    let entries = manifest["entries"]
        .as_array()
        .expect("the manifest states its entries")
        .clone();
    assert_eq!(entries.len(), 292, "the manifest's element count");
    entries
        .into_iter()
        .map(|entry| {
            (
                entry["element"]
                    .as_str()
                    .expect("an entry states an element")
                    .to_owned(),
                entry,
            )
        })
        .collect()
}

/// Every crate that keeps an `ESS_UNREALIZED` registry, and where it keeps it.
const REGISTRARS: [(&str, &str); 6] = [
    ("mandate-authz", "crates/mandate-authz/src/lib.rs"),
    ("mandate-federation", "crates/mandate-federation/src/lib.rs"),
    ("mandate-graph", "crates/mandate-graph/src/lib.rs"),
    ("mandate-identity", "crates/mandate-identity/src/lib.rs"),
    ("mandate-policy", "crates/mandate-policy/src/lib.rs"),
    ("mandate-sts", "services/sts/src/lib.rs"),
];

/// `(registrar, element, reason)` for every entry of every `ESS_UNREALIZED` registry.
///
/// Read as source text for the same reason the step reads the manifest as lines: `xtask`
/// depends on no crate of this workspace, and `dependency-boundaries.json` would refuse the
/// edge. The total is asserted so that a parser which selected nothing cannot pass.
fn unrealized() -> Vec<(&'static str, String, String)> {
    let mut all = Vec::new();
    for (registrar, path) in REGISTRARS {
        let text =
            fs::read_to_string(repo().join(path)).unwrap_or_else(|error| panic!("{path}: {error}"));
        let start = text
            .find("pub const ESS_UNREALIZED")
            .unwrap_or_else(|| panic!("{path}: declares no ESS_UNREALIZED"));
        let block = &text[start..];
        let end = block
            .find("];")
            .unwrap_or_else(|| panic!("{path}: ESS_UNREALIZED does not close"));
        let block = &block[..end];
        let marks: Vec<usize> = block
            .match_indices("\"mandate.")
            .map(|(at, _)| at)
            .collect();
        assert!(
            !marks.is_empty(),
            "{path}: ESS_UNREALIZED names no element, so this case reads nothing"
        );
        for (index, at) in marks.iter().enumerate() {
            let rest = &block[at + 1..];
            let element = rest
                .split('"')
                .next()
                .expect("an element literal closes")
                .to_owned();
            let until = marks.get(index + 1).copied().unwrap_or(block.len());
            let reason = block[at + 1 + element.len()..until].to_owned();
            all.push((registrar, element, reason));
        }
    }
    assert_eq!(
        all.len(),
        24,
        "every ESS_UNREALIZED entry of the workspace: authz 1, federation 1, graph 7, \
         identity 10, policy 2, sts 3"
    );
    all
}

/// An element a crate registers as one it does **not** realize is not an element the coverage
/// manifest reports as implemented by the generated contract shape.
///
/// `mandate-types`' 91 entries are the residue: every declared type no registrar claims,
/// paired with `mandate_contract::entities::<Entity>State` for the derived half. The pairing
/// is a derivation over `DERIVED_STATE_ENUMS`, which ESS emits for **every** declared entity
/// whether anything folds it or not — so the residue silently absorbs the state enum of an
/// entity the owning crate has already said, in its own registry, that it does not project.
/// The result is a coverage report that calls an element implemented in the same commit in
/// which the crate that owns its domain calls it unrealized. Nothing compares the two: the
/// step reads only the manifest, and each per-crate case reads only its own
/// `ESS_REALIZATIONS`.
#[test]
fn no_element_a_crate_registers_as_unrealized_is_implemented_by_mandate_types() {
    let entries = entries();
    let mut contradictions = Vec::new();
    for (registrar, element, _) in unrealized() {
        let entry = entries
            .get(&element)
            .unwrap_or_else(|| panic!("{element}: the coverage manifest has no entry"));
        if entry["status"] == "implemented" && entry["crate"] == "mandate-types" {
            contradictions.push(format!(
                "  {element}: {registrar}::ESS_UNREALIZED names it as an element that crate \
                 does not realize, and contracts/coverage.json reports it implemented by \
                 mandate-types as {}",
                entry["impl"]
            ));
        }
    }
    assert!(
        contradictions.is_empty(),
        "the coverage manifest reports {} element(s) as implemented that their own domain's \
         crate registers as unrealized:\n{}",
        contradictions.len(),
        contradictions.join("\n")
    );
}

/// Where an `ESS_UNREALIZED` reason names the symbol that realizes the element instead, the
/// manifest names that same symbol.
///
/// This is the wave D ruling "one declared element has one realizer" read across the two
/// documents rather than within one of them. `cargo xtask coverage` asserts it over the
/// manifest alone, which cannot see a second realizer named in a crate's registry, and the
/// registry's own case cannot see the manifest's.
#[test]
fn the_manifest_names_the_realizer_every_unrealized_reason_names() {
    let entries = entries();
    let mut checked = 0_usize;
    let mut disagreements = Vec::new();
    for (registrar, element, reason) in unrealized() {
        let Some((_, named)) = reason.split_once("realized by ") else {
            continue;
        };
        let claimed: String = named
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || *character == '_' || *character == ':'
            })
            .collect();
        if claimed.is_empty() {
            continue;
        }
        checked += 1;
        let entry = entries
            .get(&element)
            .unwrap_or_else(|| panic!("{element}: the coverage manifest has no entry"));
        let holder = entry["crate"]
            .as_str()
            .unwrap_or_default()
            .replace('-', "_");
        let symbol = entry["impl"][0].as_str().unwrap_or_default();
        let resolved = match symbol.strip_prefix("crate::") {
            Some(tail) => format!("{holder}::{tail}"),
            None => symbol.to_owned(),
        };
        if resolved != claimed {
            disagreements.push(format!(
                "  {element}: {registrar}::ESS_UNREALIZED says it is realized by {claimed}, \
                 contracts/coverage.json says {resolved}"
            ));
        }
    }
    assert!(
        checked >= 4,
        "no ESS_UNREALIZED reason named a realizer, so this case decided nothing"
    );
    assert!(
        disagreements.is_empty(),
        "the coverage manifest and a crate's own registry name two different realizers for \
         one element:\n{}",
        disagreements.join("\n")
    );
}

/// A root holding exactly what the step reads from one: the manifest and the compiled model.
fn fixture(name: &str) -> PathBuf {
    let root = repo().join("target/xtask-adversary-coverage-1").join(name);
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

fn write_manifest(root: &Path, body: &str) {
    fs::write(root.join("contracts/coverage.json"), body).expect("write the fixture manifest");
}

/// The entry's `"<key>":[…]` list, verbatim, brackets included.
fn list(line: &str, key: &str) -> String {
    let opener = format!("\"{key}\":[");
    let (_, rest) = line
        .split_once(&opener)
        .unwrap_or_else(|| panic!("the entry states no {key} list: {line}"));
    let (body, _) = rest
        .split_once(']')
        .unwrap_or_else(|| panic!("the entry's {key} list does not close: {line}"));
    format!("{opener}{body}]")
}

/// The step's symbol check is "the path root is a crate of this workspace"
/// (`xtask/src/coverage.rs:411`), and [`coverage::Compiled::crates`] is documented as "every
/// workspace package". It is not: it is every package `cargo test --workspace
/// --message-format=json` mentioned, which is every third-party dependency too. So a symbol
/// rooted in `serde_json` passes the check the doc comment says only a workspace crate
/// passes.
///
/// This matters for `Action::Coverage { root }`, which `story:mutation-controls` drives over
/// a scratch root where no per-crate case runs — the step is the only reader there.
#[test]
fn an_implemented_entry_naming_a_symbol_of_a_third_party_crate_fails() {
    let root = fixture("third-party-symbol");
    let body = fs::read_to_string(root.join("contracts/coverage.json")).expect("the manifest");
    let entry = line(&body, "mandate.graph.Grant");
    let doctored = entry.replace(
        "\"impl\":[\"crate::record::Grant\"]",
        "\"impl\":[\"serde_json::Value\"]",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));

    match coverage::coverage(&root) {
        Ok(report) => panic!(
            "the step accepted serde_json::Value — a crate of no workspace member — as the \
             implementation of mandate.graph.Grant:\n{report}"
        ),
        Err(error) => assert!(
            error.to_string().contains("serde_json"),
            "the failure names the third-party symbol: {error}"
        ),
    }
}

/// The `tests` column is the "checks that decide it" half of the manifest
/// (`xtask/src/coverage.rs:2`, and the message at `:422` reads "names no test that decides
/// it"). Only existence is decided: any id a compiled binary lists satisfies any element,
/// and no per-crate case reads the column at all — `manifest_entries` in every registrar's
/// `contract_agreement.rs` and `the_coverage_manifest_names_exactly_what_this_crate_accounts_for`
/// in `crates/mandate-types/tests/inventory.rs` both read `element` and `impl` only.
#[test]
fn an_implemented_entry_naming_a_test_of_an_unrelated_crate_fails() {
    let root = fixture("unrelated-test");
    let body = fs::read_to_string(root.join("contracts/coverage.json")).expect("the manifest");
    let entry = line(&body, "mandate.graph.Grant");
    let tests = list(&entry, "tests");
    let doctored = entry.replace(
        &tests,
        "\"tests\":[\"xtask::coverage::a_manifest_that_is_not_one_entry_to_a_line_fails\"]",
    );
    assert_ne!(entry, doctored, "the fixture changed nothing");
    write_manifest(&root, &body.replace(&entry, &doctored));

    match coverage::coverage(&root) {
        Ok(report) => panic!(
            "the step accepted a case of `xtask` that never mentions mandate.graph.Grant as \
             the check that decides it:\n{report}"
        ),
        Err(error) => assert!(
            error.to_string().contains("mandate.graph.Grant"),
            "the failure names the element whose tests decide nothing: {error}"
        ),
    }
}

/// A fixture, not a check: this case is never run, and exists only so the workspace holds
/// one `#[ignore]`d case for [`an_ignored_case_is_not_a_test_that_decides_an_element`] to ask
/// the step about. It is written to fail, so a run that executes it says the fixture is wrong
/// rather than passing quietly.
#[test]
#[ignore = "a fixture for an_ignored_case_is_not_a_test_that_decides_an_element"]
fn adversary_ignored_fixture() {
    panic!("this case is a fixture for the case below and is never meant to run");
}

/// `cargo test -- --list` lists an `#[ignore]`d case exactly as it lists a running one, so
/// the step's proof that a named test exists is not a proof that it ever decides anything.
/// The acceptance statement says the tests are proven "by `cargo test -- --list`", which is
/// literally what happens; what the manifest's column claims is that the id names a check
/// that decides the element.
#[test]
fn an_ignored_case_is_not_a_test_that_decides_an_element() {
    let compiled = coverage::compiled(&repo()).expect("the workspace test set");
    let id = "xtask::adversary_coverage_1::adversary_ignored_fixture";
    assert!(
        !compiled.tests.contains(id),
        "the step counts {id} as a compiled, listed test, and `cargo test` never runs it: an \
         `implemented` entry naming only ignored cases is proven by nothing"
    );
}
