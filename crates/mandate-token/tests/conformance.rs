//! Round-trip conformance for the accepted credential-format types.

use mandate_token::conformance;
use mandate_token::{CredentialDescriptor, CredentialProfile};
use mandate_types::inventory::{ACCEPTED, Owner};
use mandate_types::{
    Audience, AuthorityScope, CredentialKind, Duration, OrganizationId, PrincipalId,
    RevocationGuarantee, Timestamp,
};

const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

fn schema_node(ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_TYPES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name].clone()
}

#[test]
fn every_realized_credential_format_type_round_trips_and_matches_its_projection() {
    let cases = conformance::cases();
    assert!(!cases.is_empty(), "the conformance suite executed no case");
    for case in &cases {
        let node = schema_node(case.ess_name);
        assert_eq!(
            node["additionalProperties"],
            serde_json::Value::Bool(false),
            "{}",
            case.ess_name
        );
        let properties = node["properties"].as_object().expect("declared properties");
        for encoded in &case.encoded {
            let value: serde_json::Value = serde_json::from_str(encoded).expect("encoded is JSON");
            let object = value.as_object().expect("encodes as a JSON object");
            for key in object.keys() {
                assert!(
                    properties.contains_key(key),
                    "{}: undeclared field {key}",
                    case.ess_name
                );
            }
            for required in node["required"].as_array().expect("required list") {
                let required = required.as_str().expect("required name");
                assert!(
                    object.contains_key(required),
                    "{}: missing {required}",
                    case.ess_name
                );
            }
        }
    }
}

#[test]
fn the_realized_set_is_exactly_the_share_this_crate_owns() {
    let mut realized: Vec<&str> = conformance::cases()
        .iter()
        .map(|case| case.ess_name)
        .collect();
    realized.sort_unstable();
    let mut owned: Vec<&str> = ACCEPTED
        .iter()
        .filter(|accepted| accepted.owner == Owner::Token)
        .map(|accepted| accepted.ess_name)
        .collect();
    owned.sort_unstable();
    assert_eq!(realized, owned);
    assert_eq!(realized.len(), 2);
}

#[test]
fn a_credential_descriptor_describes_authority_and_carries_no_secret() {
    let descriptor = CredentialDescriptor {
        kind: CredentialKind::SelfContained,
        subject: PrincipalId::parse(SAMPLE_UUID).expect("subject"),
        actor: None,
        organization: OrganizationId::parse(SAMPLE_UUID).expect("organization"),
        audience: Audience::new("mandate"),
        scope: AuthorityScope {
            actions: Vec::new(),
            resources: Vec::new(),
            space: None,
        },
        delegation: None,
        execution: None,
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
    };
    let encoded = serde_json::to_string(&descriptor).expect("encode");
    assert_eq!(
        serde_json::from_str::<CredentialDescriptor>(&encoded).expect("decode"),
        descriptor
    );
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    for field in ["secret", "proof", "credential_secret", "credential_proof"] {
        assert!(
            value.get(field).is_none(),
            "{field} is not a descriptor field"
        );
    }
}

#[test]
fn a_credential_profile_keeps_its_declared_durations_lexical() {
    let profile = CredentialProfile {
        name: "default".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    };
    let encoded = serde_json::to_string(&profile).expect("encode");
    assert_eq!(
        serde_json::from_str::<CredentialProfile>(&encoded).expect("decode"),
        profile
    );
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(value["max_ttl"], "PT1H");
    assert!(value["requires_online_authorization"].is_boolean());
}
