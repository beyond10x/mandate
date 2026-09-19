//! Adversary pass 1 over `story:contract-shapes`: what the generated shapes do with documents
//! the ESS JSON Schema projection of the same model accepts.
//!
//! Every fixture below was produced from `generated/schema/{events,entities}/<name>.schema.json`
//! and validated against that schema with `jsonschema` 4.26.0 before it was written here, so the
//! oracle is ESS's own projection and not this file's opinion.

use mandate_contract::{entities, events, types::Presence};
use serde_json::{Value, json};

/// Absence has no JSON spelling outside a skipping field position, so an absent value refuses
/// to serialize on its own and `null` refuses to deserialize; neither side invents `null`.
///
/// Coordinator ruling after adversary pass 1 (finding A1-2): the original case asserted
/// `from(to(Absent)) == Absent`, which no JSON spelling can satisfy without admitting `null`,
/// which the schemas do not; the property that holds is that both directions refuse loudly.
#[test]
fn presence_absent_refuses_to_serialize_and_null_refuses_to_deserialize() {
    let absent: Presence<String> = Presence::Absent;
    let error = serde_json::to_value(&absent).expect_err("an absent value has no JSON spelling");
    assert!(
        error.to_string().contains("Absent"),
        "the refusal names the rule, got: {error}"
    );
    serde_json::from_value::<Presence<String>>(Value::Null)
        .expect_err("null is not absence: omit the key instead");
}

/// A document the JSON Schema projection accepts is a value of the generated shape, unchanged.
#[test]
fn ten_events_and_five_entities_round_trip_from_a_schema_valid_document() {
    macro_rules! round_trip {
        ($ty:ty, $json:expr) => {{
            let wire: Value = serde_json::from_str($json).expect("the fixture parses");
            let value: $ty = serde_json::from_value(wire.clone()).unwrap_or_else(|e| {
                panic!(
                    "{} refuses a document its schema accepts: {e}\n{}",
                    stringify!($ty),
                    $json
                )
            });
            let back = serde_json::to_value(&value).expect("the shape serializes");
            assert_eq!(back, wire, "{} does not round-trip", stringify!($ty));
        }};
    }

    // mandate.identity.SecurityEpochRecorded
    round_trip!(
        events::MandateIdentitySecurityEpochRecorded,
        r#"{"target": {"kind": "federation", "value": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "generation": 7}"#
    );
    // mandate.audit.AuditEventRecorded
    round_trip!(
        events::MandateAuditAuditEventRecorded,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "record": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "event_type": "value-1", "correlation": "value-1", "decision_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "requested_audience": "value-1", "issued_audience": "value-1", "requested_scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "credential_kind": "SelfContained", "delegation_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "result": "value-1", "occurred_at": "2026-09-19T10:11:12Z", "policy_version": "value-1", "model_version": "value-1", "authz_revision": "value-1", "source_credential_kind": "SelfContained", "source_credential_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "issued_credential_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "issued_scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}}}"#
    );
    // mandate.credential.ResourceServerRegistered
    round_trip!(
        events::MandateCredentialResourceServerRegistered,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential_profile": {"name": "value-1", "kind": "SelfContained", "revocation": "ImmediateOnline", "max_ttl": "PT1H", "positive_cache_ttl": "PT1H", "requires_online_authorization": true}, "allowed_exchange_sources": ["3f2504e0-4f89-41d3-9a0c-0305e82c3301"]}"#
    );
    // mandate.delegation.DelegationCreated
    round_trip!(
        events::MandateDelegationDelegationCreated,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegator": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegate": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "audience": "value-1", "not_before": "2026-09-19T10:11:12Z", "expires_at": "2026-09-19T10:11:12Z", "execution_binding": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "created_at": "2026-09-19T10:11:12Z"}"#
    );
    round_trip!(
        events::MandateDelegationDelegationCreated,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegator": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegate": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "audience": "value-1", "expires_at": "2026-09-19T10:11:12Z", "created_at": "2026-09-19T10:11:12Z"}"#
    );
    // mandate.directory.DirectoryGroupTeamMappingCreated
    round_trip!(
        events::MandateDirectoryDirectoryGroupTeamMappingCreated,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "mapping_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "group_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "team_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "created_by": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "created_at": "2026-09-19T10:11:12Z", "contributions": ["3f2504e0-4f89-41d3-9a0c-0305e82c3301"]}"#
    );
    // mandate.graph.ResourceRegistered
    round_trip!(
        events::MandateGraphResourceRegistered,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "resource": {"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "parent": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}"#
    );
    round_trip!(
        events::MandateGraphResourceRegistered,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "resource": {"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}}"#
    );
    // mandate.identity.SessionOpened
    round_trip!(
        events::MandateIdentitySessionOpened,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "principal_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "connection_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "epochs": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "expires_at": "2026-09-19T10:11:12Z"}"#
    );
    round_trip!(
        events::MandateIdentitySessionOpened,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "principal_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "epochs": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "expires_at": "2026-09-19T10:11:12Z"}"#
    );
    // mandate.identity.SessionRevoked
    round_trip!(
        events::MandateIdentitySessionRevoked,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}"#
    );
    // mandate.credential.CredentialIntrospected
    round_trip!(
        events::MandateCredentialCredentialIntrospected,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}, "descriptor": {"kind": "SelfContained", "subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "expires_at": "2026-09-19T10:11:12Z"}}"#
    );
    round_trip!(
        events::MandateCredentialCredentialIntrospected,
        r#"{"context": {"subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "credential": "00000000-0000-4000-8000-000000000001", "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "correlation": "value-1"}}"#
    );
    // mandate.directory.MembershipContributionRecorded
    round_trip!(
        events::MandateDirectoryMembershipContributionRecorded,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "team_membership_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "source": "Manual", "mapping_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "created_by": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}"#
    );
    round_trip!(
        events::MandateDirectoryMembershipContributionRecorded,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "team_membership_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "source": "Manual", "created_by": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}"#
    );
    // mandate.audit.AuditEvent
    round_trip!(
        entities::MandateAuditAuditEvent,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "event_type": "value-1", "correlation": "value-1", "decision_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "requested_audience": "value-1", "issued_audience": "value-1", "requested_scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "credential_kind": "SelfContained", "delegation_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "result": "value-1", "occurred_at": "2026-09-19T10:11:12Z", "policy_version": "value-1", "model_version": "value-1", "authz_revision": "value-1", "source_credential_kind": "SelfContained", "source_credential_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "issued_credential_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "issued_scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "state": "Recorded"}"#
    );
    round_trip!(
        entities::MandateAuditAuditEvent,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "event_type": "value-1", "correlation": "value-1", "result": "value-1", "occurred_at": "2026-09-19T10:11:12Z", "state": "Recorded"}"#
    );
    // mandate.identity.Principal
    round_trip!(
        entities::MandateIdentityPrincipal,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "kind": "User", "display_name": "value-1", "state": "Active"}"#
    );
    // mandate.delegation.Delegation
    round_trip!(
        entities::MandateDelegationDelegation,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegator": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegate": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "audience": "value-1", "not_before": "2026-09-19T10:11:12Z", "expires_at": "2026-09-19T10:11:12Z", "execution_binding": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "transitive": true, "created_at": "2026-09-19T10:11:12Z", "state": "Active"}"#
    );
    round_trip!(
        entities::MandateDelegationDelegation,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegator": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "delegate": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "audience": "value-1", "expires_at": "2026-09-19T10:11:12Z", "transitive": true, "created_at": "2026-09-19T10:11:12Z", "state": "Active"}"#
    );
    // mandate.credential.AccessCredential
    round_trip!(
        entities::MandateCredentialAccessCredential,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "descriptor": {"kind": "SelfContained", "subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "expires_at": "2026-09-19T10:11:12Z"}, "reference_verifier": "value-1", "epochs": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "issued_at": "2026-09-19T10:11:12Z", "state": "Active"}"#
    );
    round_trip!(
        entities::MandateCredentialAccessCredential,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "descriptor": {"kind": "SelfContained", "subject": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "actor": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "organization": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "audience": "value-1", "scope": {"actions": ["value-1"], "resources": [{"resource_type": "value-1", "resource_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}], "space": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}, "delegation": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "execution": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "expires_at": "2026-09-19T10:11:12Z"}, "issued_at": "2026-09-19T10:11:12Z", "state": "Active"}"#
    );
    // mandate.identity.PrincipalSecurityEpoch
    round_trip!(
        entities::MandateIdentityPrincipalSecurityEpoch,
        r#"{"id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "generation": 7, "state": "Recorded"}"#
    );
}

/// Every number the schema calls an `integer` is a value of the shape it projects.
///
/// `{"type": "integer"}` in JSON Schema 2020-12 is *any number with a zero fractional part*, and
/// the projection of `mandate.identity.SecurityEpochRecorded.generation` carries no `minimum` or
/// `maximum`. Both documents below were validated against
/// `generated/schema/events/mandate.identity.SecurityEpochRecorded.schema.json`.
#[test]
fn an_integer_the_schema_admits_is_a_value_of_the_emitted_shape() {
    let target = json!({"kind": "federation", "value": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"});
    for generation in ["1.0", "9223372036854775808"] {
        let document = format!("{{\"target\": {target}, \"generation\": {generation}}}");
        serde_json::from_str::<events::MandateIdentitySecurityEpochRecorded>(&document)
            .unwrap_or_else(|e| {
                panic!("the shape refuses a schema-valid generation {generation}: {e}")
            });
    }
}

/// An entity record states the lifecycle its declaration admits, and nothing else.
#[test]
fn an_entity_refuses_a_state_its_lifecycle_does_not_declare() {
    let wire = json!({
        "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "kind": "Service",
        "display_name": "Ada",
        "state": "Retired"
    });
    serde_json::from_value::<entities::MandateIdentityPrincipal>(wire)
        .expect_err("a state the lifecycle does not declare is refused");
}
