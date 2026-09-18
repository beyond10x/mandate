//! Round-trip conformance for every `mandate.core` type realized in `mandate-types`.
//!
//! Every case is decided against `generated/schema/types`, the ESS projection that
//! `cargo xtask contracts` byte-compares. Nothing here asserts runtime enforcement.

use mandate_types::conformance::{self, Canonical, Case};
use mandate_types::inventory::{ACCEPTED, Owner};
use mandate_types::{
    Audience, AuthoritySubject, CorrelationId, CredentialId, CredentialProof, CredentialSecret,
    EpochSnapshotRef, OrganizationId, PrincipalId, SecurityEpochTarget, VerifiedContext,
};

const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

const UUID_PATTERN: &str =
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
const BASE64_PATTERN: &str = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

fn schema_node(ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_TYPES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name].clone()
}

fn assert_uuid_lexical_form(text: &str) {
    assert_eq!(text.len(), 36, "uuid lexical form length: {text}");
    for (index, byte) in text.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-', "uuid separator at {index}: {text}");
        } else {
            assert!(
                byte.is_ascii_hexdigit(),
                "uuid hex digit at {index}: {text}"
            );
        }
    }
}

fn assert_base64_lexical_form(text: &str) {
    assert_eq!(text.len() % 4, 0, "base64 quantum: {text}");
    let padding = text.bytes().rev().take_while(|byte| *byte == b'=').count();
    assert!(padding <= 2, "base64 padding: {text}");
    for byte in text.bytes().take(text.len() - padding) {
        assert!(
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/',
            "base64 alphabet: {text}"
        );
    }
}

/// Every `pattern` the projection declares is enforced here. A pattern this suite
/// does not know about is a failure, not a silent pass.
fn assert_pattern(pattern: &str, text: &str) {
    match pattern {
        UUID_PATTERN => assert_uuid_lexical_form(text),
        BASE64_PATTERN => assert_base64_lexical_form(text),
        other => panic!("no conformance check for declared pattern {other}"),
    }
}

fn assert_encoding_matches_schema(ess_name: &str, encoded: &str) {
    let node = schema_node(ess_name);
    let value: serde_json::Value = serde_json::from_str(encoded).expect("encoded form is JSON");

    if let Some(one_of) = node.get("oneOf") {
        let tag = node["x-ess-union-tag"]
            .as_str()
            .expect("declared union tag");
        let object = value.as_object().expect("union encodes as an object");
        assert_eq!(
            object.keys().collect::<Vec<_>>(),
            vec![tag, "value"],
            "{ess_name}: union wire shape"
        );
        let selected = object[tag].as_str().expect("union tag is a string");
        let titles: Vec<&str> = one_of
            .as_array()
            .expect("oneOf list")
            .iter()
            .map(|variant| variant["title"].as_str().expect("variant title"))
            .collect();
        assert!(
            titles.contains(&selected),
            "{ess_name}: unknown tag {selected}"
        );
        return;
    }

    match node["type"].as_str().expect("declared JSON type") {
        "string" => {
            let text = value.as_str().expect("encodes as a JSON string");
            if let Some(members) = node.get("enum") {
                let members = members.as_array().expect("enum list");
                assert!(
                    members.contains(&value),
                    "{ess_name}: {text} is not a declared variant"
                );
            }
            if let Some(pattern) = node.get("pattern") {
                assert_pattern(pattern.as_str().expect("pattern is a string"), text);
            }
        }
        "object" => {
            assert_eq!(
                node["additionalProperties"],
                serde_json::Value::Bool(false),
                "{ess_name}: closed record"
            );
            let object = value.as_object().expect("encodes as a JSON object");
            let properties = node["properties"].as_object().expect("declared properties");
            for key in object.keys() {
                assert!(
                    properties.contains_key(key),
                    "{ess_name}: undeclared field {key}"
                );
            }
            for required in node["required"].as_array().expect("required list") {
                let required = required.as_str().expect("required name");
                assert!(
                    object.contains_key(required),
                    "{ess_name}: missing {required}"
                );
            }
        }
        other => panic!("{ess_name}: unexpected declared JSON type {other}"),
    }
}

#[test]
fn every_realized_type_round_trips_and_matches_its_projection() {
    let cases: Vec<Case> = conformance::cases();
    assert!(!cases.is_empty(), "the conformance suite executed no case");
    for case in &cases {
        assert!(
            !case.encoded.is_empty(),
            "{}: no sample encoded",
            case.ess_name
        );
        for encoded in &case.encoded {
            assert_encoding_matches_schema(case.ess_name, encoded);
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
        .filter(|accepted| accepted.owner == Owner::Types)
        .map(|accepted| accepted.ess_name)
        .collect();
    owned.sort_unstable();
    assert_eq!(realized, owned);
}

#[test]
fn identifiers_share_a_wire_form_without_sharing_a_type() {
    let principal = PrincipalId::parse(SAMPLE_UUID).expect("principal identifier");
    let organization = OrganizationId::parse(SAMPLE_UUID).expect("organization identifier");
    assert_eq!(
        serde_json::to_string(&principal).expect("encode"),
        serde_json::to_string(&organization).expect("encode"),
        "the declared wire form is shared"
    );
    // The type-level half of this observation is the compile_fail doctest pair in lib.rs.
    assert_eq!(principal.to_string(), SAMPLE_UUID);
    assert_eq!(organization.to_string(), SAMPLE_UUID);
}

#[test]
fn identifier_parsing_rejects_a_form_the_contract_does_not_declare() {
    assert!(PrincipalId::parse("not-a-uuid").is_err());
    assert!(PrincipalId::parse("").is_err());
    assert!(serde_json::from_str::<PrincipalId>("\"not-a-uuid\"").is_err());
    assert!(serde_json::from_str::<PrincipalId>("0").is_err());
}

#[test]
fn identifiers_serialize_in_the_canonical_lower_case_form() {
    let upper = "1B4E28BA-2FA1-4D8E-B1B0-8C1D4E5F6A7B";
    let parsed = PrincipalId::parse(upper).expect("uppercase input is accepted");
    assert_eq!(
        serde_json::to_string(&parsed).expect("encode"),
        format!("\"{SAMPLE_UUID}\""),
        "serialization is canonical, not input-shaped"
    );
}

#[test]
fn transient_credential_values_never_render_their_bytes() {
    let secret = CredentialSecret::from_bytes(b"top-secret-material".to_vec());
    let proof = CredentialProof::from_bytes(b"top-secret-material".to_vec());
    for rendered in [format!("{secret:?}"), format!("{proof:?}")] {
        assert!(
            !rendered.contains("top-secret"),
            "debug output leaked: {rendered}"
        );
        assert!(
            !rendered.contains("dG9wLXNlY3JldA"),
            "debug output leaked: {rendered}"
        );
        assert!(
            rendered.contains("redacted"),
            "debug output is not marked: {rendered}"
        );
    }
}

#[test]
fn transient_credential_values_cross_the_boundary_only_through_a_named_call() {
    let secret = CredentialSecret::from_bytes(b"abc".to_vec());

    // Ambient serialization is reachable by every container that derives `Serialize`,
    // including one declared outside this crate, so it never carries the material.
    assert_eq!(
        serde_json::to_string(&secret).expect("encode"),
        format!("\"{}\"", mandate_types::REDACTED)
    );
    assert!(
        serde_json::from_str::<CredentialSecret>(&format!("\"{}\"", mandate_types::REDACTED))
            .is_err(),
        "the redaction marker must not decode back into a credential"
    );

    // The declared base64 form is reachable through the named call, and round trips.
    let encoded = Canonical::encode(&secret).expect("encode");
    assert_eq!(encoded, "\"YWJj\"");
    assert_eq!(CredentialSecret::decode(&encoded).expect("decode"), secret);
    assert!(CredentialSecret::decode("\"not base64!\"").is_err());
}

/// The class the wrapper case belongs to: `mandate-model`'s adversary suite shows a
/// downstream crate can launder a transient type past `canonical_record!` inside its own
/// generic wrapper, because the orphan rule permits `impl PersistedValue for
/// Envelope<CredentialSecret>`. Whatever container reaches `Serialize`, the material does
/// not follow.
#[test]
fn no_container_puts_transient_credential_material_on_the_wire() {
    #[derive(serde::Serialize)]
    struct Envelope<T>(T);

    #[derive(serde::Serialize)]
    struct Nested<T> {
        held: Vec<Option<T>>,
    }

    let secret = CredentialSecret::from_bytes(b"abc".to_vec());
    let proof = CredentialProof::from_bytes(b"abc".to_vec());
    let forms = [
        serde_json::to_string(&Envelope(&secret)).expect("encode"),
        serde_json::to_string(&Envelope(&proof)).expect("encode"),
        serde_json::to_string(&Nested {
            held: vec![Some(&secret)],
        })
        .expect("encode"),
        serde_json::to_string(&vec![&secret]).expect("encode"),
        serde_json::to_string(&Some(&proof)).expect("encode"),
    ];
    for form in forms {
        assert!(
            !form.contains("YWJj"),
            "credential material reached a wire form through a container: {form}"
        );
        assert!(
            form.contains(mandate_types::REDACTED),
            "not redacted: {form}"
        );
    }
}

#[test]
fn an_absent_optional_field_stays_absent_across_a_round_trip() {
    let context = VerifiedContext {
        subject: PrincipalId::parse(SAMPLE_UUID).expect("subject"),
        actor: None,
        organization: OrganizationId::parse(SAMPLE_UUID).expect("organization"),
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(SAMPLE_UUID).expect("credential"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    };
    let encoded = serde_json::to_string(&context).expect("encode");
    assert!(
        !encoded.contains("actor"),
        "an absent actor must not be written: {encoded}"
    );
    let decoded: VerifiedContext = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, context);

    let mut present = context.clone();
    present.actor = Some(PrincipalId::parse(SAMPLE_UUID).expect("actor"));
    let encoded = serde_json::to_string(&present).expect("encode");
    assert!(
        encoded.contains("\"actor\""),
        "a present actor must be written: {encoded}"
    );
    let decoded: VerifiedContext = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded.actor, present.actor);
}

#[test]
fn a_closed_record_rejects_a_field_the_contract_does_not_declare() {
    let encoded = "{\"resource_type\":\"document\",\"resource_id\":\"1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b\",\"tenant\":\"x\"}";
    assert!(serde_json::from_str::<mandate_types::ResourceRef>(encoded).is_err());
}

#[test]
fn a_union_uses_the_declared_tag_and_carries_no_numeric_content() {
    let subject = AuthoritySubject::Principal(PrincipalId::parse(SAMPLE_UUID).expect("principal"));
    assert_eq!(
        serde_json::to_string(&subject).expect("encode"),
        format!("{{\"kind\":\"principal\",\"value\":\"{SAMPLE_UUID}\"}}")
    );
    let target =
        SecurityEpochTarget::Organization(OrganizationId::parse(SAMPLE_UUID).expect("target"));
    let encoded = serde_json::to_string(&target).expect("encode");
    assert_eq!(
        encoded,
        format!("{{\"kind\":\"organization\",\"value\":\"{SAMPLE_UUID}\"}}")
    );
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    assert!(
        value["value"].is_string(),
        "a security epoch target carries a reference, never a generation number"
    );
    assert!(
        serde_json::from_str::<SecurityEpochTarget>("{\"kind\":\"generation\",\"value\":7}")
            .is_err()
    );
}

#[test]
fn an_epoch_snapshot_reference_stays_an_opaque_record_handle() {
    let handle = EpochSnapshotRef::parse(SAMPLE_UUID).expect("snapshot handle");
    assert_eq!(
        serde_json::to_string(&handle).expect("encode"),
        format!("\"{SAMPLE_UUID}\"")
    );
    assert!(serde_json::from_str::<EpochSnapshotRef>("1").is_err());
    // The absence of arithmetic is proved by the compile_fail doctest in lib.rs.
}
