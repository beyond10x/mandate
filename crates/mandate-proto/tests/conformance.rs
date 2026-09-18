//! The wire contract: explicit conversions, and the set of types that carry one.

use mandate_proto::{WIRE_CONTRACTS, WireContract, WireError};
use mandate_types::inventory::{ACCEPTED, Owner};
use mandate_types::{AuthoritySubject, OrganizationId, PrincipalId};

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

#[test]
fn every_accepted_type_carries_a_wire_contract() {
    let mut wired: Vec<&str> = WIRE_CONTRACTS.to_vec();
    wired.sort_unstable();
    let mut accepted: Vec<&str> = ACCEPTED.iter().map(|entry| entry.ess_name).collect();
    accepted.sort_unstable();
    assert_eq!(wired, accepted, "an accepted type with no wire contract");
    assert_eq!(wired.len(), 74);
}

/// The six records `mandate-model` and `mandate-token` declare are on the wire by the
/// projection's own reckoning: it names them from commands, responses and events. They
/// reach this crate through the `mandate-proto -> mandate-model` and
/// `mandate-proto -> mandate-token` entries in `dependency-boundaries.json`, which are new
/// edges rather than reversals: nothing in that policy has either crate depending on this
/// one.
#[test]
fn the_records_owned_by_other_crates_cross_the_wire_through_this_one() {
    let wired: Vec<&str> = WIRE_CONTRACTS.to_vec();
    let mut covered = 0;
    for entry in ACCEPTED {
        if matches!(entry.owner, Owner::Model | Owner::Token) {
            assert!(
                wired.contains(&entry.ess_name),
                "{} has no wire contract",
                entry.ess_name
            );
            covered += 1;
        }
    }
    assert_eq!(covered, 6);

    let record = mandate_model::TenantResolutionRule {
        configured_organization: OrganizationId::parse(SAMPLE_UUID).expect("organization"),
        verified_claim_name: None,
        verified_claim_value: None,
    };
    let wire = record.to_wire().expect("encode");
    assert_eq!(
        wire,
        format!("{{\"configured_organization\":\"{SAMPLE_UUID}\"}}")
    );
    assert_eq!(
        mandate_model::TenantResolutionRule::from_wire(&wire).expect("decode"),
        record
    );
}

#[test]
fn every_wire_contract_round_trips_through_its_explicit_conversion() {
    let failures = mandate_proto::conformance::run();
    assert!(failures.is_empty(), "wire round trips failed: {failures:?}");
}

#[test]
fn the_wire_form_is_the_canonical_serialization_and_nothing_else() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    assert_eq!(
        principal.to_wire().expect("encode"),
        format!("\"{SAMPLE_UUID}\"")
    );
    assert_eq!(
        PrincipalId::from_wire(&principal.to_wire().expect("encode")).expect("decode"),
        principal
    );
    let subject = AuthoritySubject::Team(mandate_types::TeamId::parse(SAMPLE_UUID).expect("team"));
    assert_eq!(
        subject.to_wire().expect("encode"),
        format!("{{\"kind\":\"team\",\"value\":\"{SAMPLE_UUID}\"}}")
    );
}

#[test]
fn a_malformed_wire_form_is_refused_rather_than_coerced() {
    let error = PrincipalId::from_wire("\"not-a-uuid\"").expect_err("must refuse");
    assert!(matches!(error, WireError::Decode(_)));
    assert!(!format!("{error}").is_empty());
    assert!(OrganizationId::from_wire("{}").is_err());
}

/// `generated/schema/types/mandate.core.PrincipalId.schema.json` and
/// `…OrganizationId.schema.json` declare the same node apart from `title` and
/// `x-ess-name`. One identifier's wire form is therefore a valid wire form of the other,
/// and no decoder that honours the projection can refuse it. Separation is type-level;
/// the compile_fail pair in lib.rs is where it is proved.
#[test]
fn the_two_identifiers_share_a_declared_wire_form_no_decoder_can_tell_apart() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    let organization = OrganizationId::parse(SAMPLE_UUID).expect("organization");
    assert_eq!(
        principal.to_wire().expect("encode"),
        organization.to_wire().expect("encode")
    );

    let declared = |name: &str| -> serde_json::Value {
        let path = format!("{SCHEMA_TYPES}/{name}.schema.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
        let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
        let mut node = document["$defs"][name].clone();
        let object = node.as_object_mut().expect("schema node");
        object.remove("title");
        object.remove("x-ess-name");
        node
    };
    assert_eq!(
        declared("mandate.core.PrincipalId"),
        declared("mandate.core.OrganizationId"),
        "the projection declares two distinguishable wire forms after all"
    );
}

/// Why `tests/adversary.rs::a_wire_form_decoded_into_the_wrong_identifier_is_refused`
/// cannot be satisfied, stated so a reader can run it rather than take my word.
///
/// That case requires `OrganizationId::from_wire(w).is_err()` for `w` produced by
/// `PrincipalId::to_wire`. This shows `w` is byte-identical to the wire form a valid
/// `OrganizationId` produces, and that `from_wire` accepts that form — as the wire
/// contract requires, and as `every_wire_contract_round_trips_through_its_explicit_conversion`
/// asserts for all 74 types. `from_wire` is a function of the string alone, so it cannot
/// return `Ok` and `Err` for the same string: the requirement is a contradiction, not a
/// defect in the implementation.
///
/// The case is left standing and red. Making it pass would require tagging the wire form
/// with the type name, which contradicts both the projection and the adversary's own
/// `the_identifier_compile_fail_body_is_a_string_mismatch_not_an_identifier_one`, which
/// pins `to_wire` to the bare JSON string.
#[test]
fn the_wire_form_the_adversary_requires_refused_is_a_valid_organization_wire_form() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal");
    let organization = OrganizationId::parse(SAMPLE_UUID).expect("organization");

    let demanded_refusal = principal.to_wire().expect("encode");
    let required_acceptance = organization.to_wire().expect("encode");
    assert_eq!(demanded_refusal, required_acceptance);

    assert_eq!(
        OrganizationId::from_wire(&required_acceptance).expect("a wire contract must accept it"),
        organization
    );
}
