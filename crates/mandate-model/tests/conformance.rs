//! Round-trip conformance for the accepted domain records realized in `mandate-model`.

use mandate_model::conformance;
use mandate_model::{AuditRecord, Decision, DecisionChallenge, TenantResolutionRule};
use mandate_types::inventory::{ACCEPTED, Owner};
use mandate_types::{
    Action, AuditAction, AuditOutcome, AuthorityScope, CorrelationId, DecisionId, DecisionReason,
    OrganizationId, PolicyId, PrincipalId, ResourceRef, ResourceType, Timestamp,
};

const SCHEMA_TYPES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/types");

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

fn schema_node(ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA_TYPES}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: serde_json::Value = serde_json::from_str(&text).expect("schema is JSON");
    document["$defs"][ess_name].clone()
}

fn assert_encoding_matches_schema(ess_name: &str, encoded: &str) {
    let node = schema_node(ess_name);
    assert_eq!(node["x-ess-kind"], "struct", "{ess_name}");
    assert_eq!(
        node["additionalProperties"],
        serde_json::Value::Bool(false),
        "{ess_name}"
    );
    let value: serde_json::Value = serde_json::from_str(encoded).expect("encoded form is JSON");
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

#[test]
fn every_realized_record_round_trips_and_matches_its_projection() {
    let cases = conformance::cases();
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
        .filter(|accepted| accepted.owner == Owner::Model)
        .map(|accepted| accepted.ess_name)
        .collect();
    owned.sort_unstable();
    assert_eq!(realized, owned);
    assert_eq!(realized.len(), 4);
}

fn audit_record() -> AuditRecord {
    AuditRecord {
        subject: Some(PrincipalId::parse(SAMPLE_UUID).expect("subject")),
        actor: None,
        organization_id: Some(OrganizationId::parse(SAMPLE_UUID).expect("organization")),
        event_type: AuditAction::new("mandate.credential.IssueSelfContainedCredential"),
        correlation: CorrelationId::new("correlation"),
        decision_id: None,
        requested_audience: None,
        issued_audience: None,
        requested_scope: Some(AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![ResourceRef {
                resource_type: ResourceType::new("document"),
                resource_id: mandate_types::ResourceId::parse(SAMPLE_UUID).expect("resource"),
            }],
            space: None,
        }),
        credential_kind: None,
        delegation_id: None,
        execution_id: None,
        result: AuditOutcome::new("allowed"),
        occurred_at: Timestamp::new("2026-09-18T00:00:00Z"),
        policy_version: None,
        model_version: None,
        authz_revision: None,
        source_credential_kind: None,
        source_credential_id: None,
        issued_credential_id: None,
        issued_scope: None,
    }
}

#[test]
fn an_optional_actor_is_preserved_in_both_states() {
    let mut record = audit_record();
    let encoded = serde_json::to_string(&record).expect("encode");
    assert!(
        !encoded.contains("\"actor\""),
        "an absent actor must not be written: {encoded}"
    );
    assert_eq!(
        serde_json::from_str::<AuditRecord>(&encoded).expect("decode"),
        record
    );

    record.actor = Some(PrincipalId::parse(SAMPLE_UUID).expect("actor"));
    let encoded = serde_json::to_string(&record).expect("encode");
    assert!(
        encoded.contains("\"actor\""),
        "a present actor must be written: {encoded}"
    );
    let decoded: AuditRecord = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded.actor, record.actor);
    assert_eq!(decoded, record);
}

#[test]
fn a_domain_record_rejects_a_field_the_contract_does_not_declare() {
    let mut value: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&audit_record()).expect("encode"))
            .expect("decode");
    value["credential_secret"] = serde_json::Value::String("YWJj".to_owned());
    assert!(serde_json::from_str::<AuditRecord>(&value.to_string()).is_err());
}

#[test]
fn a_decision_carries_its_challenge_without_a_numeric_epoch() {
    let decision = Decision {
        allowed: false,
        reason: DecisionReason::ApprovalRequired,
        decision_id: DecisionId::parse(SAMPLE_UUID).expect("decision"),
        revision: None,
        challenge: Some(DecisionChallenge {
            action: Action::new("approve"),
            resource: ResourceRef {
                resource_type: ResourceType::new("document"),
                resource_id: mandate_types::ResourceId::parse(SAMPLE_UUID).expect("resource"),
            },
            approver_policy: PolicyId::parse(SAMPLE_UUID).expect("policy"),
            expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        }),
        policy_version: None,
        model_version: None,
    };
    let encoded = serde_json::to_string(&decision).expect("encode");
    assert_eq!(
        serde_json::from_str::<Decision>(&encoded).expect("decode"),
        decision
    );
    let value: serde_json::Value = serde_json::from_str(&encoded).expect("decode");
    assert!(value["challenge"]["expires_at"].is_string());
    assert!(value.get("epoch").is_none(), "no numeric epoch is realized");
}

#[test]
fn a_tenant_rule_keeps_its_configured_organization_required() {
    let rule = TenantResolutionRule {
        configured_organization: OrganizationId::parse(SAMPLE_UUID).expect("organization"),
        verified_claim_name: None,
        verified_claim_value: None,
    };
    let encoded = serde_json::to_string(&rule).expect("encode");
    assert_eq!(
        encoded,
        format!("{{\"configured_organization\":\"{SAMPLE_UUID}\"}}")
    );
    assert!(serde_json::from_str::<TenantResolutionRule>("{}").is_err());
}
