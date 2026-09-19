//! Adversary pass 1 over the event-validation harness.
//!
//! Every case drives `mandate_testkit::contract` against one of the two generated
//! projections read as the specification it claims to be: `generated/ir/system.json`
//! and `generated/schema/events/*.schema.json`. A case that fails here is a place where
//! the harness and the contract disagree; a case that passes is a property the harness
//! already holds.
//!
//! Nothing in this file edits the implementation or the implementor's own cases.

use mandate_testkit::contract::{
    check_event_conforms, check_payload_sources, check_single_emission,
};
use serde_json::{Value, json};

const ORGANIZATION_CREATED: &str = "mandate.tenancy.OrganizationCreated";
const REVOKE_SESSION: &str = "mandate.identity.RevokeSession";
const SESSION_REVOKED: &str = "mandate.identity.SessionRevoked";
const REGISTER_RESOURCE: &str = "mandate.graph.RegisterResource";
const RESOURCE_REGISTERED: &str = "mandate.graph.ResourceRegistered";
const PROVISION_EXTERNAL_PRINCIPAL: &str = "mandate.federation.ProvisionExternalPrincipal";
const EXTERNAL_PRINCIPAL_PROVISIONED: &str = "mandate.federation.ExternalPrincipalProvisioned";
const SECURITY_EPOCH_INCREMENTED: &str = "mandate.identity.SecurityEpochIncremented";
const SECURITY_EPOCH_RECORDED: &str = "mandate.identity.SecurityEpochRecorded";
const FEDERATION_CONNECTION_DISABLED: &str = "mandate.federation.FederationConnectionDisabled";
const RESOURCE_SERVER_REGISTERED: &str = "mandate.credential.ResourceServerRegistered";
const AUDIT_EVENT_RECORDED: &str = "mandate.audit.AuditEventRecorded";

const ORGANIZATION: &str = "01010101-0101-0101-0101-010101010101";
const PRINCIPAL: &str = "02020202-0202-0202-0202-020202020202";
const SESSION: &str = "03030303-0303-0303-0303-030303030303";
const CONNECTION: &str = "05050505-0505-0505-0505-050505050505";
const EXTERNAL_PRINCIPAL: &str = "06060606-0606-0606-0606-060606060606";
const CREDENTIAL: &str = "07070707-0707-0707-0707-070707070707";
const RESOURCE: &str = "0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a";
const RESOURCE_SERVER: &str = "0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b";
const AUDIT_EVENT: &str = "0c0c0c0c-0c0c-0c0c-0c0c-0c0c0c0c0c0c";

/// The declared `VerifiedContext`, carrying every required field and no optional one.
fn context() -> Value {
    json!({
        "subject": PRINCIPAL,
        "organization": ORGANIZATION,
        "audience": "mandate",
        "credential": CREDENTIAL,
        "correlation": "correlation",
    })
}

fn session_revoked() -> Value {
    json!({ "context": context(), "id": SESSION })
}

fn organization_created() -> Value {
    json!({
        "context": context(),
        "organization_id": ORGANIZATION,
        "display_name": "Acme",
    })
}

/// A `ResourceRef` as the contract declares it.
fn resource_ref() -> Value {
    json!({ "resource_type": "space", "resource_id": RESOURCE })
}

/// The input, response and emitted payload of `ProvisionExternalPrincipal`, built from
/// the mapping `generated/ir/system.json` declares for it.
fn provisioned() -> (Value, Value, Value) {
    let input = json!({
        "connection_id": CONNECTION,
        "proof": {"issuer": "https://issuer.example", "verifier": "jwks"},
    });
    let response = json!({
        "principal_id": PRINCIPAL,
        "external_principal_id": EXTERNAL_PRINCIPAL,
        "subject": "external-subject",
    });
    let event = json!({
        "organization_id": ORGANIZATION,
        "correlation": "correlation",
        "connection_id": CONNECTION,
        "principal_id": PRINCIPAL,
        "kind": "User",
        "display_name": "External User",
        "external_principal_id": EXTERNAL_PRINCIPAL,
        "subject": "external-subject",
        "link_method": "ConfiguredFederation",
        "linked_at": "2026-09-19T00:00:00Z",
    });
    (input, response, event)
}

/// A `ResourceServerRegistered` payload; `max_ttl` and `positive_cache_ttl` are the two
/// `format: duration` strings the whole contract has.
fn resource_server_registered(max_ttl: &str) -> Value {
    json!({
        "context": context(),
        "id": RESOURCE_SERVER,
        "audience": "mandate",
        "credential_profile": {
            "name": "default",
            "kind": "Reference",
            "revocation": "ImmediateOnline",
            "max_ttl": max_ttl,
            "positive_cache_ttl": "PT30S",
            "requires_online_authorization": true,
        },
        "allowed_exchange_sources": [],
    })
}

/// An `AuditEventRecorded` payload; `record.occurred_at` is a `format: date-time` that
/// lives inside `$defs`, not at the top level of the event.
fn audit_event_recorded(occurred_at: &str) -> Value {
    json!({
        "id": AUDIT_EVENT,
        "record": {
            "event_type": "mandate.audit.RecordAuditEvent",
            "correlation": "correlation",
            "result": "allowed",
            "occurred_at": occurred_at,
        },
    })
}

/// An optional input the contract permits to be absent is not a source disagreement.
#[test]
fn an_absent_optional_input_is_not_a_source_failure() {
    // Aligned at regeneration: the compiled contract sources `resource_id` from the
    // `RegisterResource` response, so the root-resource payload carries it; `parent`
    // stays the absent optional this case is about.
    let resource_id = resource_ref()["resource_id"].clone();
    let input = json!({ "context": context(), "resource": resource_ref() });
    let response = json!({ "resource_id": resource_id });
    let event = json!({
        "context": context(),
        "resource_id": resource_id,
        "resource": resource_ref(),
    });
    check_event_conforms(RESOURCE_REGISTERED, &event)
        .expect("`parent` is outside `required`, so a root resource is a conforming event");
    check_payload_sources(
        REGISTER_RESOURCE,
        &input,
        Some(&response),
        RESOURCE_REGISTERED,
        &event,
    )
    .expect("an absent optional input and an absent optional event field agree with each other");
}

/// A field the contract declares no source for is a field the command was not given.
#[test]
fn an_event_field_with_no_declared_source_is_refused() {
    let input = json!({ "id": SESSION, "context": context() });
    let mut event = session_revoked();
    event["surprise"] = json!("fabricated");
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("the event carries a field the contract did not declare");
    assert!(message.contains("surprise"), "{message}");
}

/// `null` is not a value a generated field may carry; absence is spelled by omission.
#[test]
fn a_generated_field_that_is_null_is_refused() {
    let (input, response, mut event) = provisioned();
    event["linked_at"] = Value::Null;
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("`null` is not how the contract spells a generated value");
    assert!(message.contains("linked_at"), "{message}");
}

/// An `ess_name` that escapes `generated/schema/events` is not a declared event.
#[test]
fn an_event_name_that_escapes_the_events_directory_is_refused() {
    let escaping = format!("../events/{ORGANIZATION_CREATED}");
    let message = check_event_conforms(&escaping, &organization_created())
        .expect_err("the contract declares no event under that name");
    // Coordinator amendment after adversary pass 2 (A2-8): the refusal must say the name is
    // undeclared and must not mention a file, a directory or an os error.
    assert!(message.contains("declares no such event"), "{message}");
    assert!(
        !message.contains("No such file")
            && !message.contains("os error")
            && !message.contains("generated/schema/events/"),
        "the refusal leaks a filesystem detail: {message}"
    );
}

/// The live drift `IdentityEvent::SecurityEpochIncremented { target }` is refused by name.
#[test]
fn the_domain_shape_of_security_epoch_incremented_is_refused_naming_context() {
    let event = json!({ "target": {"kind": "principal", "value": PRINCIPAL} });
    let message = check_event_conforms(SECURITY_EPOCH_INCREMENTED, &event)
        .expect_err("the contract declares `context` on this event and the domain omits it");
    assert!(
        message.contains("\"context\" is a required property"),
        "{message}"
    );
}

/// The live drift `FederationConnectionDisabled { context, connection_id }` is refused
/// naming both the field the contract wants and the one the domain carries.
#[test]
fn the_domain_shape_of_federation_connection_disabled_is_refused_naming_both_names() {
    let event = json!({ "context": context(), "connection_id": CONNECTION });
    let message = check_event_conforms(FEDERATION_CONNECTION_DISABLED, &event)
        .expect_err("the contract declares `id`, the domain carries `connection_id`");
    assert!(
        message.contains("\"id\" is a required property"),
        "{message}"
    );
    assert!(message.contains("connection_id"), "{message}");
}

/// `additionalProperties: false` closes a `$defs` object, not only the event's top level.
#[test]
fn an_extra_key_inside_a_defs_object_is_refused() {
    let mut event = session_revoked();
    event["context"]["tenant"] = json!("acme");
    let message = check_event_conforms(SESSION_REVOKED, &event)
        .expect_err("`VerifiedContext` declares `additionalProperties: false`");
    assert!(message.contains("/context"), "{message}");
    assert!(message.contains("tenant"), "{message}");
}

/// A declared `pattern` is enforced on a nested id, and the failure names its path.
#[test]
fn a_malformed_nested_id_is_refused_naming_its_instance_path() {
    let mut event = session_revoked();
    event["context"]["subject"] = json!("principal-2");
    let message = check_event_conforms(SESSION_REVOKED, &event)
        .expect_err("`PrincipalId` declares the UUID lexical form");
    assert!(message.contains("/context/subject"), "{message}");
}

/// `type: integer` refuses the same number spelled as a string.
#[test]
fn an_integer_given_as_a_string_is_refused() {
    let event = json!({
        "target": {"kind": "organization", "value": ORGANIZATION},
        "generation": "7",
    });
    let message = check_event_conforms(SECURITY_EPOCH_RECORDED, &event)
        .expect_err("`generation` is declared `type: integer`");
    assert!(message.contains("/generation"), "{message}");
}

/// `format: duration` is asserted on the two duration strings the contract declares.
#[test]
fn a_non_duration_string_is_refused_naming_the_format() {
    check_event_conforms(
        RESOURCE_SERVER_REGISTERED,
        &resource_server_registered("PT5M"),
    )
    .expect("an ISO 8601 duration conforms");
    let message = check_event_conforms(
        RESOURCE_SERVER_REGISTERED,
        &resource_server_registered("5 minutes"),
    )
    .expect_err("`max_ttl` is declared `format: duration` and carries no pattern");
    assert!(message.contains("/credential_profile/max_ttl"), "{message}");
    assert!(message.contains("duration"), "{message}");
}

/// `format: date-time` is asserted inside `$defs`, on a date that does not exist.
#[test]
fn an_impossible_date_in_a_nested_field_is_refused_naming_the_format() {
    check_event_conforms(
        AUDIT_EVENT_RECORDED,
        &audit_event_recorded("2026-09-19T00:00:00Z"),
    )
    .expect("an RFC 3339 timestamp conforms");
    let message = check_event_conforms(
        AUDIT_EVENT_RECORDED,
        &audit_event_recorded("2026-02-30T00:00:00Z"),
    )
    .expect_err("February 30th is not a date-time");
    assert!(message.contains("/record/occurred_at"), "{message}");
    assert!(message.contains("date-time"), "{message}");
}

/// Declared names are matched exactly: a different case is a different name.
#[test]
fn a_declared_name_in_a_different_case_is_refused() {
    let payload = session_revoked();
    check_event_conforms("mandate.identity.sessionrevoked", &payload)
        .expect_err("the event name is matched exactly");
    check_single_emission(REVOKE_SESSION, "Accepted", &[(SESSION_REVOKED, &payload)])
        .expect_err("the outcome name is matched exactly");
    check_single_emission(
        "mandate.identity.revokesession",
        "accepted",
        &[(SESSION_REVOKED, &payload)],
    )
    .expect_err("the command name is matched exactly");
}

/// An accepted outcome that emitted nothing is a wrong number of events.
#[test]
fn an_accepted_outcome_that_emitted_nothing_is_refused() {
    let message = check_single_emission(REVOKE_SESSION, "accepted", &[])
        .expect_err("the contract declares one emission for this outcome");
    assert!(message.contains(SESSION_REVOKED), "{message}");
}
