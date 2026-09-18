//! Adversarial cases for `story:canonical-types`, driven from the documents this unit
//! wrote about itself and from the ESS projection it claims to realize.
//!
//! Nothing here is an opinion; each case asserts a sentence the unit's own source or the
//! projection states, against the code the same unit shipped.

use std::collections::BTreeSet;

use mandate_proto::{WIRE_CONTRACTS, WireContract};
use mandate_types::inventory::ACCEPTED;
use mandate_types::{OrganizationId, PrincipalId};

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

/// `crates/mandate-proto/src/lib.rs:20`: "A wire form decoded into the wrong identifier
/// is a refusal, not a coercion". `crates/mandate-proto/src/lib.rs:42`, on
/// `WireError::Decode`: "Decoding refuses; it never coerces one identifier into another."
///
/// The unit's acceptance statement requires proving `PrincipalId` cannot substitute
/// `OrganizationId`. `from_wire` is the public surface this crate added for crossing the
/// wire, and it is documented as refusing that substitution.
#[test]
fn a_wire_form_decoded_into_the_wrong_identifier_is_refused() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    let wire = principal.to_wire().expect("encode");
    let coerced = OrganizationId::from_wire(&wire);
    assert!(
        coerced.is_err(),
        "a PrincipalId wire form decoded into an OrganizationId: {coerced:?}"
    );
}

/// Control for the `compile_fail` doctest at `crates/mandate-proto/src/lib.rs:23`, which
/// is introduced as proving that "the identifier types themselves do not convert".
///
/// Its body is `let organization: OrganizationId = principal.to_wire().unwrap();`.
/// `to_wire` returns `Result<String, WireError>`, so the annotation is compared against
/// `String`. This control is that body with the annotation changed to `String` and
/// nothing else changed; because it compiles, the doctest's failure is that mismatch.
/// Naming `PrincipalId` — the identifier the value already has — in place of
/// `OrganizationId` leaves the doctest failing exactly as it does now, so the case
/// cannot distinguish the two identifiers and proves nothing about them.
#[test]
fn the_identifier_compile_fail_body_is_a_string_mismatch_not_an_identifier_one() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    let organization: String = principal.to_wire().expect("encode");
    assert_eq!(organization, format!("\"{SAMPLE_UUID}\""));
}

/// Every `mandate.core.X` token a schema file names, matched on a token boundary rather
/// than as a substring: `mandate.core.Decision` must not be found in a file that only
/// names `mandate.core.DecisionId`.
fn core_references(text: &str) -> BTreeSet<String> {
    const PREFIX: &str = "mandate.core.";
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(start) = rest.find(PREFIX) {
        let tail = &rest[start + PREFIX.len()..];
        let end = tail
            .find(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(tail.len());
        found.insert(format!("{PREFIX}{}", &tail[..end]));
        rest = &tail[end..];
    }
    found
}

/// The projection puts a type on the wire by naming it from a command, response or event
/// schema. `crates/mandate-proto/src/lib.rs:1` declares this crate to be "Wire contracts
/// and explicit conversions", and `WIRE_CONTRACTS` is documented as "Every ESS model name
/// this crate carries a wire contract for".
///
/// `crates/mandate-types/src/inventory.rs:50` states the unit's position: "No authored
/// `mandate.core` type is a wire-only contract, so this crate declares none of the 74. It
/// carries the wire contract over the types it can reach, which the dependency policy
/// limits to `mandate-types`." This case decides that position against the projection.
#[test]
fn every_accepted_type_the_projection_puts_on_the_wire_carries_a_wire_contract() {
    let accepted: BTreeSet<&str> = ACCEPTED.iter().map(|entry| entry.ess_name).collect();
    let wired: BTreeSet<&str> = WIRE_CONTRACTS.iter().copied().collect();

    let mut on_the_wire: BTreeSet<String> = BTreeSet::new();
    for directory in ["commands", "responses", "events"] {
        let path = format!("{SCHEMA}/{directory}");
        for entry in std::fs::read_dir(&path).unwrap_or_else(|error| panic!("{path}: {error}")) {
            let entry = entry.expect("directory entry");
            let text = std::fs::read_to_string(entry.path()).expect("schema text");
            for name in core_references(&text) {
                if accepted.contains(name.as_str()) {
                    on_the_wire.insert(name);
                }
            }
        }
    }
    assert!(
        !on_the_wire.is_empty(),
        "the projection named no accepted type"
    );

    let uncovered: Vec<&str> = on_the_wire
        .iter()
        .map(String::as_str)
        .filter(|name| !wired.contains(name))
        .collect();
    assert!(
        uncovered.is_empty(),
        "accepted types the projection puts on the wire with no WireContract: {uncovered:?}"
    );
}
