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

/// Retired by the wave coordinator on 2026-09-18 and rewritten to assert what was
/// decided, under `review-result:wave1-canonical-types-adversary-2`.
///
/// This case previously required `OrganizationId::from_wire` to refuse a `PrincipalId`
/// wire form. That is unsatisfiable against the contract, and three parties established
/// it separately: the implementor, adversary pass 2, and the coordinator reading the
/// projection directly. `generated/schema/types/mandate.core.PrincipalId.schema.json` and
/// `…OrganizationId.schema.json` declare `$defs` nodes that are byte-identical apart from
/// `title` and `x-ess-name`. `from_wire` takes only `&str`, so returning `Ok` for one and
/// `Err` for the other on the same string is a contradiction, not a defect.
///
/// The alternatives were ruled out rather than overlooked. A tagged envelope inside
/// `to_wire` breaks `mandate-types/tests/conformance.rs`, which validates the encoded form
/// against a `$defs` node of `{"type":"string"}`. A context argument moves the
/// discriminating information into the caller's own parameter, which makes the refusal a
/// tautology about the caller rather than a property of the wire form. A `parse`/`from_wire`
/// split changes nothing, because both are functions of the string alone.
///
/// Identifier separation in this unit is therefore type-level, and the acceptance
/// requirement that `PrincipalId` cannot substitute `OrganizationId` is discharged by the
/// `compile_fail` pair at `crates/mandate-proto/src/lib.rs`, which fails with exactly
/// `E0308` and nothing else.
///
/// So this case now asserts the decision: the two identifiers share one declared wire form,
/// and any decoder reading that form accepts either. It fails if the projection stops
/// declaring them identically, or if a decoder starts discriminating without the contract
/// changing first — which is the state that would make the original requirement meaningful.
#[test]
fn the_two_identifiers_share_one_declared_wire_form_no_decoder_can_discriminate() {
    let principal_node = declared_node("mandate.core.PrincipalId");
    let organization_node = declared_node("mandate.core.OrganizationId");
    assert_eq!(
        principal_node, organization_node,
        "the projection no longer declares one form for both identifiers, so the retirement \
         reason for this case no longer holds and wire-level separation must be reconsidered"
    );

    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    let wire = principal.to_wire().expect("encode");
    let organization = OrganizationId::parse(SAMPLE_UUID).expect("organization");
    assert_eq!(
        wire,
        organization.to_wire().expect("encode"),
        "the two identifiers no longer encode to the same string"
    );
    assert!(
        OrganizationId::from_wire(&wire).is_ok(),
        "a decoder refused a string the contract declares valid for its own type"
    );
}

/// The declared value node for `name`, with the two labelling keys dropped. Those are the
/// only keys that may differ between two types sharing a form.
fn declared_node(name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA}/types/{name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema json");
    let mut node = document["$defs"][name].clone();
    let object = node.as_object_mut().expect("declared node is an object");
    object.remove("title");
    object.remove("x-ess-name");
    node
}

/// Control for the `compile_fail` doctest at `crates/mandate-proto/src/lib.rs:23`, which
/// is introduced as proving that "the identifier types themselves do not convert".
///
/// That body was replaced during correction round 1 and now reads
/// `fn tenant(_: OrganizationId){} tenant(PrincipalId::parse(..).unwrap())`, which does
/// fail for the identifier. This control documents the defect that was found and keeps
/// its assertion, which is still true: `to_wire` returns a `String`.
/// The original body was `let organization: OrganizationId = principal.to_wire().unwrap();`.
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
