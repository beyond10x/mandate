//! Adversary pass 1 against `story:model-agreement`, `types` unit.
//!
//! `crates/mandate-types/tests/conformance.rs:10-28` is the document this unit wrote about
//! its own state account. Two of its sentences are put to a program here.
//!
//! * ":17-19 — each of the 36 compiled declarations is paired with the generated enum that
//!   realizes it and decided through it." The pairing is a hand-written literal table
//!   (`state_enums!`, conformance.rs:461-497) and the procedure that reads it carries no
//!   evidence of the pairing: it reads the declared variants out of the schema file named
//!   by the *left* side and pushes them through the type named by the *right* side. Where
//!   two declarations have the same variant list — and 22 of the 36 do — the right side
//!   can name another element's enum and every assertion still passes.
//!
//! * ":22-24 — the six that also have a domain enum, `OrganizationState` and its siblings."
//!   `mandate-federation` declares five more, each documented with the `.State` element it
//!   realizes, and nothing in this repository decides any of them against the contract.
//!
//! The independent rebuild of `DERIVED_STATE_ENUMS` from the compiled index, and the
//! case-sensitivity boundary, are here too; both hold.

use std::collections::{BTreeMap, BTreeSet};

use mandate_contract::entities;
use mandate_types::inventory::DERIVED_STATE_ENUMS;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn state_schema_files() -> BTreeSet<String> {
    let path = format!("{ROOT}/generated/schema/types");
    std::fs::read_dir(&path)
        .unwrap_or_else(|error| panic!("{path}: {error}"))
        .map(|entry| entry.expect("directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter_map(|name| name.strip_suffix(".schema.json").map(str::to_owned))
        .filter(|name| name.ends_with(".State"))
        .collect()
}

fn declared_variants(ess_name: &str) -> Vec<String> {
    let path = format!("{ROOT}/generated/schema/types/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("{ess_name}: no declared variants"))
        .iter()
        .map(|variant| {
            variant
                .as_str()
                .unwrap_or_else(|| panic!("{ess_name}: a declared variant is not a string"))
                .to_owned()
        })
        .collect()
}

/// `conformance.rs::through_generated_shape`, re-stated so the procedure is the same one.
fn through_generated_shape<T: serde::Serialize + serde::de::DeserializeOwned>(
    variant: &str,
) -> Option<String> {
    let wire = serde_json::to_string(variant).expect("a variant name encodes as a JSON string");
    let decoded: T = serde_json::from_str(&wire).ok()?;
    Some(serde_json::to_string(&decoded).expect("the generated shape encodes"))
}

/// ESS's `declaration_name`: split on every non-alphanumeric, capitalize each part, join — the
/// rule `xtask/src/emit.rs` reproduces and the account's pairing evidence rests on.
fn declaration_name(ess_name: &str) -> String {
    ess_name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// The whole per-element procedure of `every_derived_state_enum_joins_the_per_type_schema_account`,
/// including the pairing evidence the coordinator ruled after adversary pass 1: the generated
/// enum on the right must be the one the element name on the left derives to.
fn account_procedure_passes<T: serde::Serialize + serde::de::DeserializeOwned>(
    ess_name: &str,
) -> bool {
    let expected = declaration_name(ess_name);
    let actual = std::any::type_name::<T>();
    if !actual.ends_with(&expected) {
        return false;
    }
    let declared = declared_variants(ess_name);
    if declared.is_empty() {
        return false;
    }
    for variant in &declared {
        match through_generated_shape::<T>(variant) {
            Some(encoded) if encoded == format!("\"{variant}\"") => {}
            _ => return false,
        }
    }
    through_generated_shape::<T>("MandateUndeclaredVariant").is_none()
}

/// The account list is exactly the `.State` half of the compiled index, rebuilt from the files.
#[test]
fn the_state_account_rebuilt_from_the_compiled_index_is_the_account_the_crate_declares() {
    let from_files = state_schema_files();
    let declared: BTreeSet<String> = DERIVED_STATE_ENUMS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(declared, from_files);
    assert_eq!(from_files.len(), 36, "derived state enums");
    let variants: usize = from_files
        .iter()
        .map(|name| declared_variants(name).len())
        .sum();
    assert_eq!(variants, 70, "declared variants across the derived half");
}

/// A declared element is decided through the generated enum that realizes it and no other.
#[test]
fn the_state_account_procedure_refuses_another_elements_generated_enum() {
    // Two pairings the account's own procedure would accept, from two different variant
    // classes. Each names an element on the left and the enum of a *different* element on
    // the right; neither pairing appears in `state_enums!`.
    let mut accepted: Vec<String> = Vec::new();
    if account_procedure_passes::<entities::MandateIdentitySessionState>(
        "mandate.graph.Grant.State",
    ) {
        accepted.push(
            "mandate.graph.Grant.State passes the whole procedure through \
             MandateIdentitySessionState"
                .to_owned(),
        );
    }
    if account_procedure_passes::<entities::MandateDelegationAgentState>(
        "mandate.tenancy.Team.State",
    ) {
        accepted.push(
            "mandate.tenancy.Team.State passes the whole procedure through \
             MandateDelegationAgentState"
                .to_owned(),
        );
    }

    // How large the blind spot is, read off the compiled index alone: ordered pairs of
    // distinct `.State` declarations whose declared variant lists are equal.
    let mut by_variants: BTreeMap<Vec<String>, Vec<String>> = BTreeMap::new();
    for name in state_schema_files() {
        let mut variants = declared_variants(&name);
        variants.sort();
        by_variants.entry(variants).or_default().push(name);
    }
    let interchangeable: usize = by_variants
        .values()
        .map(|group| group.len() * group.len().saturating_sub(1))
        .sum();

    assert!(
        accepted.is_empty(),
        "conformance.rs:17-19 states each declaration is decided through the generated enum \
         that realizes it; the procedure carries no evidence of the pairing, and {} of the \
         1260 ordered cross-pairings pass it unchanged:\n{}",
        interchangeable,
        accepted.join("\n")
    );
}

/// Every domain enum outside `mandate-model` that names a derived `.State` element is named in
/// the account, with the story that decides it.
///
/// Coordinator ruling after adversary pass 1 (A1-4): the original case asserted no such enum
/// exists; ten do, and the account now states its coverage and routes each of them. The
/// property that holds is that none of them is unaccounted for.
#[test]
fn every_domain_state_enum_outside_mandate_model_is_named_in_the_account() {
    fn rust_sources(directory: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_sources(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    let elements = state_schema_files();
    let crates = std::path::Path::new(ROOT).join("crates");
    let mut sources: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("the crates directory") {
        let path = entry.expect("directory entry").path();
        if path.file_name().is_some_and(|name| name == "mandate-model") {
            continue;
        }
        rust_sources(&path.join("src"), &mut sources);
    }
    assert!(sources.len() > 20, "sources scanned: {}", sources.len());

    let mut claims: Vec<String> = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("a source file");
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let Some(name) = line.trim().strip_prefix("pub enum ") else {
                continue;
            };
            let name = name.trim_end_matches(" {").trim();
            let window = &lines[index.saturating_sub(8)..index];
            for above in window {
                if !above.trim_start().starts_with("///") {
                    continue;
                }
                if let Some(element) = elements.iter().find(|element| above.contains(*element)) {
                    let relative = path
                        .strip_prefix(ROOT)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .into_owned();
                    claims.push(format!("{relative}:{}: {name} => {element}", index + 1));
                    break;
                }
            }
        }
    }

    assert!(
        !claims.is_empty(),
        "the scan found no domain enum naming a derived state element outside mandate-model; \
         the account's routing has nothing to cover"
    );
    let account = std::fs::read_to_string(
        std::path::Path::new(ROOT).join("crates/mandate-types/tests/conformance.rs"),
    )
    .expect("the per-type schema account");
    let unaccounted: Vec<&String> = claims
        .iter()
        .filter(|claim| {
            let element = claim.rsplit(" => ").next().unwrap_or("");
            !account.contains(element)
        })
        .collect();
    assert!(
        unaccounted.is_empty(),
        "domain enums outside mandate-model whose element the account never names:\n{}",
        unaccounted
            .iter()
            .map(|claim| claim.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A variant string in another case, or with surrounding space, is refused by the generated shape.
#[test]
fn a_variant_string_the_declaration_does_not_carry_verbatim_is_refused() {
    for undeclared in ["active", "ACTIVE", "Active ", " Active", "", "Revoked\n"] {
        assert!(
            through_generated_shape::<entities::MandateIdentitySessionState>(undeclared).is_none(),
            "the generated shape accepted {undeclared:?}"
        );
    }
    for declared in ["Active", "Revoked"] {
        assert_eq!(
            through_generated_shape::<entities::MandateIdentitySessionState>(declared),
            Some(format!("\"{declared}\"")),
        );
    }
}
