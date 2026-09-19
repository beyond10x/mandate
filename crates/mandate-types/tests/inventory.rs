//! The accepted-type and exclusion account, decided against the ESS projection.
//!
//! `generated/schema/types` is the compiled model's own type index; `cargo xtask
//! contracts` byte-compares it against a fresh `ess generate`. Reading it here means
//! the account cannot drift from the contract without this suite failing.

use mandate_types::inventory::{
    ACCEPTED, DERIVED_STATE_ENUMS, EXCLUDED_ENTITIES, EXCLUDED_SEMANTICS, Kind, Owner,
};
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

/// The derived half of the compiled index is accounted for, name for name.
///
/// `DERIVED_STATE_ENUMS` is the list `tests/conformance.rs` pairs with the generated
/// `mandate_contract` shape that realizes each one, so the two halves of the account
/// cannot drift: a `.State` enum the contract adds is absent here until it is listed, and
/// a name listed here without a case in the conformance account fails there.
#[test]
fn the_derived_state_enum_account_is_exactly_the_derived_half_of_the_compiled_index() {
    let derived: BTreeSet<String> = schema_names("types")
        .into_iter()
        .filter(|name| name.ends_with(".State"))
        .collect();
    let accounted: BTreeSet<String> = DERIVED_STATE_ENUMS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(
        accounted.len(),
        DERIVED_STATE_ENUMS.len(),
        "the account holds no duplicate"
    );
    assert_eq!(accounted, derived);
    assert_eq!(derived.len(), 36, "derived state enums");
    for name in DERIVED_STATE_ENUMS {
        assert_eq!(schema_kind(name), "enum", "{name}");
    }
}

#[test]
fn the_excluded_semantics_are_named_rather_than_implied() {
    assert!(EXCLUDED_SEMANTICS.len() >= 6);
    for reason in EXCLUDED_SEMANTICS {
        assert!(!reason.trim().is_empty());
    }
    // The derived state enums are decided, per declared variant, in tests/conformance.rs,
    // so no exclusion may still claim them. The check is over the list rather than over
    // the one sentence that used to be there: any future wording that excludes a `.State`
    // enum fails here.
    for reason in EXCLUDED_SEMANTICS {
        assert!(
            !reason.contains(".State"),
            "an exclusion still claims the derived state enums, which the account covers: {reason}"
        );
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

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/coverage.json");

/// The coverage manifest's account of this crate is exactly the account this crate keeps.
///
/// `contracts/coverage.json` maps all 110 compiled type declarations, and the eight registrar
/// crates reconcile their own entries against a `mandate_types::realizes!` registry the
/// compiler touches. This crate has no such registry and is not given one: the ruling for
/// `story:coverage-map` is that the authored types are accounted here through the conformance
/// account, not through a registry. This is the case that makes that account answerable, and
/// it decides three things.
///
/// **The authored half.** Every entry of [`ACCEPTED`] this crate owns is implemented by this
/// crate in the manifest, paired with `mandate_types::<Name>`. The pairing is a derivation and
/// not a list: every declaration form in `crates/mandate-types/src/macros.rs` writes
/// `ESS_NAME` as `concat!("mandate.core.", stringify!($name))`, so the Rust identifier of an
/// accepted type *is* the local part of its element name, and a type that stopped agreeing
/// with that would fail `the_realized_set_is_exactly_the_share_this_crate_owns` first.
///
/// **The derived half, which this crate claims none of.** `tests/conformance.rs` puts every
/// one of the 36 `.State` enums of [`DERIVED_STATE_ENUMS`] through the same schema account the
/// authored types go through, against the generated `mandate_contract::entities::<Entity>State`
/// shape its name derives to. That is a *check*, and wave D's correction round settled that it
/// is not an *implementation*: ESS emits one such shape for every declared entity whether any
/// crate folds the record or not, so a manifest entry naming it says nothing that
/// distinguishes a realized lifecycle from an unrealized one. Twenty-three entries said
/// exactly that, six of them while the crate owning the domain registered the element as one
/// it does not realize. So the manifest's account of each `.State` is the crate that folds the
/// record — registering its own enum, reconciled by that crate's own case — or no crate at
/// all, and this case decides that none of them is parked here.
///
/// **Nothing else.** An entry naming this crate that is not an accepted type this crate owns
/// fails, and so does one claiming a `mandate.core` record `mandate-model` or `mandate-token`
/// declares: those carry their own conformance registries, and claiming them here would be
/// this crate answering for a type it cannot construct.
#[test]
fn the_coverage_manifest_names_exactly_what_this_crate_accounts_for() {
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_else(|error| {
        panic!("{MANIFEST}: {error}");
    });
    let manifest: serde_json::Value =
        serde_json::from_str(&text).expect("the coverage manifest is JSON");
    assert_eq!(
        manifest["format"], "mandate-coverage/1",
        "unknown coverage manifest format"
    );

    let mut entries: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
    for entry in manifest["entries"]
        .as_array()
        .expect("the coverage manifest states its entries")
    {
        let element = entry["element"]
            .as_str()
            .expect("an entry states an element");
        assert!(
            entries.insert(element, entry).is_none(),
            "{element}: two entries name this element"
        );
    }
    assert_eq!(entries.len(), 292, "the coverage manifest's element count");

    let mut claimed: BTreeMap<String, String> = BTreeMap::new();
    for (element, entry) in &entries {
        if entry["crate"].as_str() != Some("mandate-types") {
            continue;
        }
        assert_eq!(
            entry["status"], "implemented",
            "{element}: an entry names this crate and is not implemented"
        );
        let symbols = entry["impl"]
            .as_array()
            .unwrap_or_else(|| panic!("{element}: the entry states no impl list"));
        assert_eq!(
            symbols.len(),
            1,
            "{element}: one element has one realizer, and one realizer names one symbol"
        );
        claimed.insert(
            (*element).to_owned(),
            symbols[0]
                .as_str()
                .unwrap_or_else(|| panic!("{element}: the symbol is no path"))
                .to_owned(),
        );
    }

    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    for accepted in ACCEPTED.iter().filter(|entry| entry.owner == Owner::Types) {
        let local = accepted
            .ess_name
            .strip_prefix("mandate.core.")
            .unwrap_or_else(|| panic!("{}: an authored type of another domain", accepted.ess_name));
        expected.insert(
            accepted.ess_name.to_owned(),
            format!("mandate_types::{local}"),
        );
    }
    assert_eq!(
        expected.len(),
        68,
        "the share of the authored types this crate owns"
    );
    assert_eq!(
        claimed, expected,
        "the coverage manifest's entries for this crate are not the account it keeps"
    );
    for accepted in ACCEPTED.iter().filter(|entry| entry.owner != Owner::Types) {
        assert!(
            !claimed.contains_key(accepted.ess_name),
            "{}: declared in another crate and claimed by this one",
            accepted.ess_name
        );
    }

    let mut folded = 0_usize;
    for name in DERIVED_STATE_ENUMS {
        let entry = entries
            .get(name)
            .unwrap_or_else(|| panic!("{name}: the coverage manifest has no entry"));
        let holding = entry["crate"].as_str().unwrap_or_default();
        assert_ne!(
            holding, "mandate-types",
            "{name}: this crate declares no Rust representation of a derived state enum, and \
             the generated shape it is paired with in tests/conformance.rs is the contract \
             re-emitted rather than an implementation of it"
        );
        if entry["status"] == "implemented" {
            let symbol = entry["impl"][0].as_str().unwrap_or_default();
            assert!(
                !symbol.starts_with("mandate_contract::"),
                "{name}: implemented by {holding} as the generated shape {symbol}, which ESS \
                 emits for every declared entity"
            );
            folded += 1;
        }
    }
    assert_eq!(
        folded, 19,
        "the derived state enums a crate of this workspace folds and registers: six in \
         mandate-model, four in the STS, three in mandate-federation, two each in \
         mandate-identity, mandate-graph and mandate-policy. The other seventeen have no \
         hand-written enum anywhere in this workspace and carry their record's status; the \
         count moved from 36 when wave D's correction round refused the generated contract \
         shape as an implementation"
    );
}
