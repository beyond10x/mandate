//! The accepted-type and exclusion account, decided against the ESS projection.
//!
//! `generated/schema/types` is the compiled model's own type index; `cargo xtask
//! contracts` byte-compares it against a fresh `ess generate`. Reading it here means
//! the account cannot drift from the contract without this suite failing.

use mandate_types::inventory::{ACCEPTED, EXCLUDED_ENTITIES, EXCLUDED_SEMANTICS, Kind, Owner};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

fn schema_names(directory: &str) -> BTreeSet<String> {
    let path = format!("{SCHEMA}/{directory}");
    std::fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("{path}: {error}"))
        .map(|entry| entry.expect("directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter_map(|name| name.strip_suffix(".schema.json").map(str::to_owned))
        .collect()
}

fn schema_kind(ess_name: &str) -> String {
    let path = format!("{SCHEMA}/types/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name]["x-ess-kind"]
        .as_str()
        .expect("declared ESS kind")
        .to_owned()
}

#[test]
fn the_compiled_type_index_splits_into_authored_types_and_derived_state_enums() {
    let names = schema_names("types");
    assert_eq!(names.len(), 110, "compiled type entries");
    let authored: BTreeSet<&String> = names
        .iter()
        .filter(|name| name.starts_with("mandate.core."))
        .collect();
    assert_eq!(authored.len(), 74, "authored model types");
    for name in &names {
        if !name.starts_with("mandate.core.") {
            assert!(name.ends_with(".State"), "unaccounted type entry {name}");
        }
    }
    assert_eq!(names.len() - authored.len(), 36, "derived state enums");
}

#[test]
fn the_accepted_account_is_exactly_the_authored_type_set() {
    let authored: BTreeSet<String> = schema_names("types")
        .into_iter()
        .filter(|name| name.starts_with("mandate.core."))
        .collect();
    let accepted: BTreeSet<String> = ACCEPTED
        .iter()
        .map(|entry| entry.ess_name.to_owned())
        .collect();
    assert_eq!(
        accepted.len(),
        ACCEPTED.len(),
        "the account holds no duplicate"
    );
    assert_eq!(accepted, authored);
}

#[test]
fn no_derived_state_enum_is_accepted() {
    for entry in ACCEPTED {
        assert!(
            !entry.ess_name.ends_with(".State"),
            "derived state enum accepted: {}",
            entry.ess_name
        );
    }
}

#[test]
fn the_accepted_account_agrees_with_the_projected_kind_of_every_type() {
    let mut breakdown: BTreeMap<Kind, usize> = BTreeMap::new();
    for entry in ACCEPTED {
        let declared = schema_kind(entry.ess_name);
        assert_eq!(entry.kind.as_ess_kind(), declared, "{}", entry.ess_name);
        *breakdown.entry(entry.kind).or_default() += 1;
    }
    assert_eq!(breakdown[&Kind::Newtype], 55);
    assert_eq!(breakdown[&Kind::Enum], 8);
    assert_eq!(breakdown[&Kind::Struct], 9);
    assert_eq!(breakdown[&Kind::Union], 2);
}

#[test]
fn every_accepted_type_has_exactly_one_owning_crate() {
    let mut breakdown: BTreeMap<Owner, usize> = BTreeMap::new();
    for entry in ACCEPTED {
        *breakdown.entry(entry.owner).or_default() += 1;
    }
    assert_eq!(breakdown.values().sum::<usize>(), 74);
    assert_eq!(
        breakdown.get(&Owner::Types).copied().unwrap_or_default(),
        68
    );
    assert_eq!(breakdown.get(&Owner::Model).copied().unwrap_or_default(), 4);
    assert_eq!(breakdown.get(&Owner::Token).copied().unwrap_or_default(), 2);
    assert_eq!(breakdown.get(&Owner::Proto).copied().unwrap_or_default(), 0);
}

#[test]
fn the_excluded_epoch_entities_are_entities_and_are_not_realized() {
    let entities = schema_names("entities");
    assert_eq!(entities.len(), 36, "compiled entities");
    let accepted: BTreeSet<&str> = ACCEPTED.iter().map(|entry| entry.ess_name).collect();
    assert_eq!(EXCLUDED_ENTITIES.len(), 4);
    for excluded in EXCLUDED_ENTITIES {
        assert!(
            entities.contains(excluded.ess_name),
            "{} is not an entity in the compiled model",
            excluded.ess_name
        );
        assert!(
            !accepted.contains(excluded.ess_name),
            "{} was accepted",
            excluded.ess_name
        );
        assert!(
            !excluded.reason.trim().is_empty(),
            "{} has no reason",
            excluded.ess_name
        );
    }
}

#[test]
fn the_three_generation_records_carry_exactly_the_declared_generation() {
    for name in [
        "mandate.identity.PrincipalSecurityEpoch",
        "mandate.identity.OrganizationSecurityEpoch",
        "mandate.identity.FederationSecurityEpoch",
    ] {
        let path = format!("{SCHEMA}/entities/{name}.schema.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
        let properties: BTreeSet<&str> = document["properties"]
            .as_object()
            .expect("entity properties")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            properties,
            BTreeSet::from(["id", "state", "generation"]),
            "{name} no longer declares exactly the generation the contract records; \
             the exclusion account must be revisited"
        );
    }
}

#[test]
fn the_excluded_semantics_are_named_rather_than_implied() {
    assert!(EXCLUDED_SEMANTICS.len() >= 6);
    for reason in EXCLUDED_SEMANTICS {
        assert!(!reason.trim().is_empty());
    }
}

#[test]
fn the_projection_declares_no_pattern_the_conformance_suite_does_not_enforce() {
    /// A `pattern` can be declared at any depth: on a type, on a property of a struct, or
    /// inside a union arm. Reading only the top-level node would let one appear below it
    /// with nothing enforcing it, so this descends the whole document.
    fn collect_patterns(node: &serde_json::Value, found: &mut BTreeSet<String>) {
        match node {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    if key == "pattern"
                        && let Some(pattern) = value.as_str()
                    {
                        found.insert(pattern.to_owned());
                    }
                    collect_patterns(value, found);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_patterns(item, found);
                }
            }
            _ => {}
        }
    }

    let mut patterns: BTreeSet<String> = BTreeSet::new();
    for entry in ACCEPTED {
        let path = format!("{SCHEMA}/types/{}.schema.json", entry.ess_name);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
        collect_patterns(&document, &mut patterns);
    }
    assert_eq!(
        patterns,
        BTreeSet::from([
            "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$".to_owned(),
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
                .to_owned(),
        ]),
        "a declared pattern with no enforcing case in tests/conformance.rs"
    );
}

#[test]
fn no_persisted_projection_carries_a_transient_credential_value() {
    for directory in ["entities", "events"] {
        for name in schema_names(directory) {
            let path = format!("{SCHEMA}/{directory}/{name}.schema.json");
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
            for transient in [
                "mandate.core.CredentialSecret",
                "mandate.core.CredentialProof",
            ] {
                assert!(
                    !text.contains(transient),
                    "{directory}/{name} references the transient type {transient}"
                );
            }
        }
    }
}
