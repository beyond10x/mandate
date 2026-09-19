//! An adversarial case against `story:coverage-map`'s manifest, decided against the account
//! this crate already keeps.
//!
//! `mandate_types::inventory::ACCEPTED` is the 74 authored `mandate.core` types, each with
//! the crate that **declares its realization** — `tests/inventory.rs` decides that the set is
//! exactly the compiled authored type index and that every entry has exactly one owning
//! crate. An accepted type is therefore a type this workspace declares in Rust, in a named
//! crate, today.
//!
//! `contracts/coverage.json` is the other account, and it is the one a reader of coverage is
//! given. This case asks whether the two agree about which authored types are implemented.

use mandate_types::inventory::ACCEPTED;
use serde_json::Value;
use std::collections::BTreeMap;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts/coverage.json");

/// Every accepted authored type is an `implemented` entry of the coverage manifest.
///
/// `declared` and `deferred` both mean, in the step's own words, that "a {status} element
/// carries no implementation" (`xtask/src/coverage.rs:452`), and both are refused if they
/// name a crate, a symbol or a test. An accepted type carries all three — the crate is
/// `Accepted::owner`, the symbol is the Rust declaration that owner holds, and the check is
/// that owner's conformance registry — so an accepted type the manifest does not report as
/// implemented is a coverage report that understates the contract, in the one direction
/// `cargo xtask coverage` cannot see: every check it runs over a `deferred` entry passes
/// when the entry is false.
#[test]
fn every_accepted_authored_type_is_implemented_in_the_coverage_manifest() {
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_else(|error| {
        panic!("{MANIFEST}: {error}");
    });
    let manifest: Value = serde_json::from_str(&text).expect("the coverage manifest is JSON");
    assert_eq!(
        manifest["format"], "mandate-coverage/1",
        "unknown coverage manifest format"
    );
    let entries: BTreeMap<String, Value> = manifest["entries"]
        .as_array()
        .expect("the coverage manifest states its entries")
        .iter()
        .map(|entry| {
            (
                entry["element"]
                    .as_str()
                    .expect("an entry states an element")
                    .to_owned(),
                entry.clone(),
            )
        })
        .collect();
    assert_eq!(ACCEPTED.len(), 74, "the authored type account");

    let mut understated = Vec::new();
    for accepted in ACCEPTED {
        let entry = entries
            .get(accepted.ess_name)
            .unwrap_or_else(|| panic!("{}: the coverage manifest has no entry", accepted.ess_name));
        if entry["status"] != "implemented" {
            understated.push(format!(
                "  {}: declared in this workspace by {:?} (mandate_types::inventory::ACCEPTED), \
                 and the coverage manifest reports it {} on {} with impl {} and tests {}",
                accepted.ess_name,
                accepted.owner,
                entry["status"],
                entry["blocker"],
                entry["impl"],
                entry["tests"]
            ));
        }
    }
    assert!(
        understated.is_empty(),
        "the coverage manifest reports {} authored type(s) as carrying no implementation, and \
         this crate's own account names the crate that declares each one:\n{}",
        understated.len(),
        understated.join("\n")
    );
}
