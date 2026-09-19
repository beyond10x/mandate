//! The lock-wide license fold, decided against constructed metadata documents.
//!
//! The step exists because `cargo deny check licenses` does not see the whole lock: a crate
//! reachable only through a dev-dependency is written to `Cargo.lock` and is absent from
//! cargo-deny's graph. Twelve crates in this workspace's resolved graph are invisible to it,
//! so a refused license could ship behind a green `licenses ok`. The cases here drive the
//! fold with documents shaped like `cargo metadata`'s, and one drives it with the real one.
#[allow(dead_code)] // the binary target uses the whole module; a case here uses part of it.
#[path = "../src/licenses.rs"]
mod licenses;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_owned()
}
/// A document shaped like `cargo metadata --format-version 1`: every crate named in
/// `crates` is both a package and a node of the resolved graph, which is the shape a
/// dev-only dependency has — `cargo metadata` carries the dev edges that cargo-deny drops.
fn metadata(crates: &[(&str, &str, Option<&str>)]) -> Value {
    let id =
        |name: &str, version: &str| format!("registry+https://example.invalid#{name}@{version}");
    json!({
        "packages": crates
            .iter()
            .map(|(name, version, license)| json!({
                "id": id(name, version),
                "name": name,
                "version": version,
                "license": license,
            }))
            .collect::<Vec<Value>>(),
        "resolve": {
            "nodes": crates
                .iter()
                .map(|(name, version, _)| json!({ "id": id(name, version) }))
                .collect::<Vec<Value>>(),
        },
    })
}
fn allowlist(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[test]
fn a_dev_only_crate_with_a_refused_license_is_named_with_its_license() {
    let document = metadata(&[
        ("mandate-token", "0.2.0", Some("Apache-2.0")),
        ("doctored-dev-only", "1.0.0", Some("BSD-2-Clause")),
    ]);

    let refusal = licenses::audit(&document, &allowlist(&["Apache-2.0", "MIT"]))
        .expect_err("a BSD-2-Clause crate is not allowed");
    let text = refusal.to_string();

    assert!(text.contains("doctored-dev-only"), "{text}");
    assert!(text.contains("BSD-2-Clause"), "{text}");
}

#[test]
fn a_crate_outside_the_resolved_graph_is_not_read_at_all() {
    let mut document = metadata(&[("kept", "1.0.0", Some("Apache-2.0"))]);
    document["packages"]
        .as_array_mut()
        .expect("packages")
        .push(json!({
            "id": "registry+https://example.invalid#unresolved@9.9.9",
            "name": "unresolved",
            "version": "9.9.9",
            "license": "BSD-2-Clause",
        }));

    assert_eq!(
        licenses::audit(&document, &allowlist(&["Apache-2.0"])).expect("only the graph is read"),
        1
    );
}

#[test]
fn a_crate_declaring_no_license_is_refused_rather_than_skipped() {
    let document = metadata(&[("silent", "1.0.0", None)]);

    let refusal = licenses::audit(&document, &allowlist(&["Apache-2.0"]))
        .expect_err("an undeclared license is not an allowed one");

    assert!(refusal.to_string().contains("silent"), "{refusal}");
}

#[test]
fn an_expression_is_satisfied_by_any_one_of_its_alternatives() {
    let allowed = allowlist(&["Apache-2.0"]);

    for expression in ["MIT OR Apache-2.0", "MIT/Apache-2.0", "(MIT OR Apache-2.0)"] {
        let document = metadata(&[("dual", "1.0.0", Some(expression))]);

        assert_eq!(licenses::audit(&document, &allowed).expect(expression), 1);
    }
}

#[test]
fn a_conjunction_is_satisfied_only_when_every_term_is_allowed() {
    let document = metadata(&[("both", "1.0.0", Some("Apache-2.0 AND ISC"))]);

    assert!(licenses::audit(&document, &allowlist(&["Apache-2.0"])).is_err());
    assert_eq!(
        licenses::audit(&document, &allowlist(&["Apache-2.0", "ISC"])).expect("both allowed"),
        1
    );
}

#[test]
fn the_allowlist_is_read_from_deny_toml_rather_than_restated() {
    // The expectation is derived from the file, never from a license named here. A case that
    // asserted a particular license present or absent would be a second copy of the allowlist,
    // which is the duplication this whole step exists to avoid — and it would go red on a
    // legitimate allowlist change rather than on a defect. This one went red exactly that way
    // when `ISC` was admitted, which is how it earned its present shape.
    let policy = std::fs::read_to_string(repo().join("deny.toml")).expect("deny.toml");
    let declared: BTreeSet<String> = policy
        .lines()
        .find(|line| line.trim_start().starts_with("allow = ["))
        .expect("deny.toml declares an allowlist")
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();

    let allowed = licenses::allowed(&policy).expect("deny.toml declares an allowlist");

    assert_eq!(allowed, declared);
    assert!(!allowed.is_empty());
}

#[test]
fn an_allowlist_that_declares_nothing_is_refused_rather_than_read_as_empty() {
    assert!(licenses::allowed("[licenses]\n").is_err());
    assert!(licenses::allowed("[licenses]\nallow = []\n").is_err());
}

#[test]
fn the_workspace_as_it_stands_satisfies_its_own_allowlist() {
    let policy = std::fs::read_to_string(repo().join("deny.toml")).expect("deny.toml");
    let allowed = licenses::allowed(&policy).expect("allowlist");
    let emitted = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(repo())
        .output()
        .expect("cargo metadata");
    assert!(emitted.status.success(), "cargo metadata failed");
    let document: Value = serde_json::from_slice(&emitted.stdout).expect("metadata json");

    let counted = licenses::audit(&document, &allowed).expect("the tree satisfies its allowlist");

    assert!(counted > 200, "only {counted} crates read");
}
