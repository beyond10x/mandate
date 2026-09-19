//! The event-validation harness's own cases.
//!
//! Every refusal is asserted to *name* what broke — the field, the command, the
//! outcome or the event. A check whose message does not say that is not usable by the
//! test that called it, so the message is part of the behaviour under test.
//!
//! Several cases sweep the whole contract rather than one example: every declared event
//! schema, every declared outcome, every declared payload source kind, and every mapping
//! decided against its own `target_type`. A harness that only reads
//! `mandate.tenancy.OrganizationCreated` is a harness that stops working the first time
//! the contract grows a shape it has not seen, and a rule held up by two hand-written
//! fixtures is a rule that holds only for the mappings someone thought of.

use mandate_testkit::contract::{
    assert_event_conforms, assert_payload_sources, assert_single_emission, check_event_conforms,
    check_payload_sources, check_single_emission, declaring_outcome_in,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DelegationId, EpochSnapshotRef, ExecutionId,
    ExternalPrincipalId, FederationConnectionId, OrganizationId, PrincipalId, ResourceId,
    SessionId, Timestamp, Uuid, VerifiedContext,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

const SYSTEM_IR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/ir/system.json"
);

const ORGANIZATION_CREATED: &str = "mandate.tenancy.OrganizationCreated";
const SESSION_OPENED: &str = "mandate.identity.SessionOpened";
const SESSION_REVOKED: &str = "mandate.identity.SessionRevoked";
const REVOKE_SESSION: &str = "mandate.identity.RevokeSession";
const PROVISION_EXTERNAL_PRINCIPAL: &str = "mandate.federation.ProvisionExternalPrincipal";
const EXTERNAL_PRINCIPAL_PROVISIONED: &str = "mandate.federation.ExternalPrincipalProvisioned";
const REGISTER_RESOURCE: &str = "mandate.graph.RegisterResource";
const RESOURCE_REGISTERED: &str = "mandate.graph.ResourceRegistered";
const CREATE_DELEGATION: &str = "mandate.delegation.CreateDelegation";
const DELEGATION_CREATED: &str = "mandate.delegation.DelegationCreated";
const INTROSPECT_CREDENTIAL: &str = "mandate.credential.IntrospectCredential";
const CREDENTIAL_INTROSPECTED: &str = "mandate.credential.CredentialIntrospected";

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn encoded<T: Serialize>(item: &T) -> Value {
    serde_json::to_value(item).expect("a declared type encodes as JSON")
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(2)),
        actor: None,
        organization: OrganizationId::new(uuid(1)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// A payload the contract declares in full, built from realized types.
fn organization_created() -> Value {
    json!({
        "context": encoded(&context()),
        "organization_id": encoded(&OrganizationId::new(uuid(1))),
        "display_name": "Acme",
    })
}

/// A payload whose optional `connection_id` is absent, as the contract spells absence.
fn session_opened() -> Value {
    json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "principal_id": encoded(&PrincipalId::new(uuid(2))),
        "organization_id": encoded(&OrganizationId::new(uuid(1))),
        "epochs": encoded(&EpochSnapshotRef::new(uuid(4))),
        "expires_at": encoded(&Timestamp::new("2026-09-19T00:00:00Z")),
    })
}

fn session_revoked() -> Value {
    json!({
        "context": encoded(&context()),
        "id": encoded(&SessionId::new(uuid(3))),
    })
}

fn system_ir() -> Value {
    let text = std::fs::read_to_string(SYSTEM_IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

fn strings(node: &Value, key: &str) -> Vec<String> {
    node[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("a name is a string").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_declared_payload_conforms() {
    assert_event_conforms(ORGANIZATION_CREATED, &organization_created());
    assert_event_conforms(SESSION_OPENED, &session_opened());
    check_event_conforms(SESSION_REVOKED, &session_revoked()).expect("a declared payload conforms");
}

#[test]
fn an_obsolete_field_fails_naming_it() {
    let mut payload = organization_created();
    payload["legacy_display_name"] = json!("Acme");
    let message = check_event_conforms(ORGANIZATION_CREATED, &payload)
        .expect_err("an undeclared field is refused");
    assert!(message.contains("legacy_display_name"), "{message}");
}

#[test]
fn a_missing_required_field_fails_naming_it() {
    let mut payload = organization_created();
    payload
        .as_object_mut()
        .expect("the payload is an object")
        .remove("display_name");
    let message = check_event_conforms(ORGANIZATION_CREATED, &payload)
        .expect_err("a missing required field is refused");
    assert!(
        message.contains("\"display_name\" is a required property"),
        "{message}"
    );
}

#[test]
fn a_null_for_an_absent_optional_fails_naming_it() {
    let mut payload = session_opened();
    payload["connection_id"] = Value::Null;
    let message = check_event_conforms(SESSION_OPENED, &payload)
        .expect_err("`null` is not how the contract spells an absent optional");
    assert!(message.contains("/connection_id"), "{message}");
}

#[test]
fn a_pattern_violation_fails_naming_the_pattern() {
    let mut payload = session_revoked();
    payload["id"] = json!("session-3");
    let message = check_event_conforms(SESSION_REVOKED, &payload)
        .expect_err("the declared pattern is closed");
    assert!(message.contains("/id"), "{message}");
    assert!(message.contains("[0-9a-fA-F]{8}"), "{message}");
}

#[test]
fn a_format_violation_fails_naming_the_format() {
    let mut payload = session_opened();
    payload["expires_at"] = json!("yesterday");
    let message = check_event_conforms(SESSION_OPENED, &payload)
        .expect_err("`expires_at` declares `format: date-time` and no pattern");
    assert!(message.contains("/expires_at"), "{message}");
    assert!(message.contains("date-time"), "{message}");
}

#[test]
fn an_undeclared_event_name_is_refused_by_name() {
    let message = check_event_conforms("mandate.tenancy.OrganizationRenamed", &json!({}))
        .expect_err("the contract declares no such event");
    assert!(
        message.contains("mandate.tenancy.OrganizationRenamed"),
        "{message}"
    );
}

#[test]
#[should_panic(expected = "legacy_display_name")]
fn the_assert_form_panics_naming_the_offending_field() {
    let mut payload = organization_created();
    payload["legacy_display_name"] = json!("Acme");
    assert_event_conforms(ORGANIZATION_CREATED, &payload);
}

#[test]
fn the_declared_single_emission_passes() {
    let payload = session_revoked();
    assert_single_emission(REVOKE_SESSION, "accepted", &[(SESSION_REVOKED, &payload)]);
}

#[test]
fn two_emissions_for_an_accepted_outcome_fail() {
    let payload = session_revoked();
    let message = check_single_emission(
        REVOKE_SESSION,
        "accepted",
        &[(SESSION_REVOKED, &payload), (SESSION_REVOKED, &payload)],
    )
    .expect_err("an accepted outcome emits exactly one event");
    assert!(message.contains(REVOKE_SESSION), "{message}");
    assert!(message.contains(SESSION_REVOKED), "{message}");
}

#[test]
fn an_emission_for_a_denied_outcome_fails() {
    let payload = session_revoked();
    let message = check_single_emission(REVOKE_SESSION, "denied", &[(SESSION_REVOKED, &payload)])
        .expect_err("a denied outcome emits nothing");
    assert!(message.contains("/denied:"), "{message}");
    assert!(message.contains(SESSION_REVOKED), "{message}");
}

#[test]
fn the_wrong_event_for_an_accepted_outcome_fails_naming_both() {
    let payload = session_revoked();
    let message = check_single_emission(REVOKE_SESSION, "accepted", &[(SESSION_OPENED, &payload)])
        .expect_err("the emitted event is not the declared one");
    assert!(message.contains(SESSION_OPENED), "{message}");
    assert!(message.contains(SESSION_REVOKED), "{message}");
}

#[test]
fn an_unknown_command_or_outcome_is_refused_by_name() {
    let message = check_single_emission("mandate.identity.CloseSession", "accepted", &[])
        .expect_err("the contract declares no such command");
    assert!(
        message.contains("mandate.identity.CloseSession"),
        "{message}"
    );

    let message = check_single_emission(REVOKE_SESSION, "rejected", &[])
        .expect_err("the command declares no such outcome");
    assert!(message.contains(REVOKE_SESSION), "{message}");
    assert!(message.contains("no outcome `rejected`"), "{message}");
}

#[test]
fn a_payload_agreeing_with_the_input_passes() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    assert_payload_sources(
        REVOKE_SESSION,
        &input,
        None,
        SESSION_REVOKED,
        &session_revoked(),
    );
}

#[test]
fn an_input_sourced_field_that_disagrees_fails_naming_it() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    let mut event = session_revoked();
    event["id"] = encoded(&SessionId::new(uuid(9)));
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("the event carries a session the command was not given");
    assert!(message.contains("field `id`:"), "{message}");
    assert!(
        message.contains("09090909-0909-0909-0909-090909090909"),
        "{message}"
    );
}

#[test]
fn an_input_sourced_field_that_is_absent_fails_naming_it() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    let mut event = session_revoked();
    event
        .as_object_mut()
        .expect("the event is an object")
        .remove("context");
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("a mapped field that is absent is a source failure");
    assert!(message.contains("field `context`:"), "{message}");
}

#[test]
fn a_response_sourced_field_without_a_response_fails_naming_it() {
    let (input, _response, event) = provisioned();
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        None,
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("a response-sourced field cannot be checked without a response");
    assert!(message.contains("field `principal_id`:"), "{message}");
}

#[test]
fn a_response_sourced_field_that_disagrees_fails_naming_it() {
    let (input, response, mut event) = provisioned();
    event["external_principal_id"] = encoded(&ExternalPrincipalId::new(uuid(8)));
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("the event carries an identifier the response did not return");
    assert!(
        message.contains("field `external_principal_id`:"),
        "{message}"
    );
}

#[test]
fn a_literal_field_that_disagrees_fails_naming_it() {
    let (input, response, mut event) = provisioned();
    event["link_method"] = json!("SelfService");
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("the contract declares this field a literal");
    assert!(message.contains("field `link_method`:"), "{message}");
    assert!(message.contains("ConfiguredFederation"), "{message}");
}

#[test]
fn a_generated_field_is_checked_for_presence_only() {
    let (input, response, mut event) = provisioned();
    event["linked_at"] = json!("any lexical form the runtime produced");
    check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect("a generated field is checked for presence, not value");

    event
        .as_object_mut()
        .expect("the event is an object")
        .remove("linked_at");
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("a generated field must still be present");
    assert!(message.contains("field `linked_at`:"), "{message}");
}

/// An optional target agrees with a source that carries no value. The named mappings
/// here are hand-built fixtures; the count is never written down, because
/// `every_declared_mapping_decides_absence_by_its_declared_target_type` derives the
/// whole set from the IR and would cover a fifth one the day the contract grows it.
#[test]
fn an_absent_optional_source_agrees_with_an_absent_target() {
    let (input, event) = registered_root_resource();
    assert_payload_sources(REGISTER_RESOURCE, &input, None, RESOURCE_REGISTERED, &event);

    let (input, response, event) = created_delegation();
    assert_payload_sources(
        CREATE_DELEGATION,
        &input,
        Some(&response),
        DELEGATION_CREATED,
        &event,
    );
}

/// The one optional target the contract sources from a *response* rather than an input:
/// `descriptor` on `CredentialIntrospected`, absent from a response that returned none.
#[test]
fn an_absent_optional_response_source_agrees_with_an_absent_target() {
    let (response, event) = introspected_without_a_descriptor();
    assert_payload_sources(
        INTROSPECT_CREDENTIAL,
        &json!({}),
        Some(&response),
        CREDENTIAL_INTROSPECTED,
        &event,
    );
}

/// The same optional response source the other way round: a response that returned no
/// descriptor and an event that carries one is a field the command was not given.
#[test]
fn an_absent_optional_response_source_with_a_carried_target_fails_naming_it() {
    let (response, mut event) = introspected_without_a_descriptor();
    event["descriptor"] = json!({"kind": "Reference"});
    let message = check_payload_sources(
        INTROSPECT_CREDENTIAL,
        &json!({}),
        Some(&response),
        CREDENTIAL_INTROSPECTED,
        &event,
    )
    .expect_err("the event carries a descriptor the response did not return");
    assert!(message.contains("field `descriptor`:"), "{message}");
}

/// The hand-built mappings the other way round: an input that carries no value and an
/// event that carries one is a field the command was not given.
#[test]
fn an_absent_optional_source_with_a_carried_target_fails_naming_it() {
    let (input, mut event) = registered_root_resource();
    event["parent"] = encoded(&ResourceId::new(uuid(13)));
    let message =
        check_payload_sources(REGISTER_RESOURCE, &input, None, RESOURCE_REGISTERED, &event)
            .expect_err("the event carries a parent the command was not given");
    assert!(message.contains("field `parent`:"), "{message}");

    let (input, response, mut event) = created_delegation();
    event["not_before"] = encoded(&Timestamp::new("2026-09-19T12:00:00Z"));
    event["execution_binding"] = encoded(&ExecutionId::new(uuid(14)));
    let message = check_payload_sources(
        CREATE_DELEGATION,
        &input,
        Some(&response),
        DELEGATION_CREATED,
        &event,
    )
    .expect_err("the event carries two bindings the command was not given");
    assert!(message.contains("field `not_before`:"), "{message}");
    assert!(message.contains("field `execution_binding`:"), "{message}");
}

/// `null` is not a value on either side: an input `null` is an absent source and an
/// event `null` is an absent target, so the two agree and neither is read as a value.
#[test]
fn a_null_is_read_as_absence_on_both_sides() {
    let (mut input, mut event) = registered_root_resource();
    input["parent"] = Value::Null;
    event["parent"] = Value::Null;
    assert_payload_sources(REGISTER_RESOURCE, &input, None, RESOURCE_REGISTERED, &event);
}

/// `null` is absence at the mapped field level only. A `null` nested inside a mapped
/// object is part of the value the source check compares — so an event carrying one
/// disagrees with an input that does not — and the schema check refuses it by its
/// instance path, because the contract declares no nullable type.
#[test]
fn a_null_nested_inside_a_mapped_object_is_a_value_not_an_absence() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    let mut event = session_revoked();
    event["context"]["actor"] = Value::Null;
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("the nested `null` is part of the value this check compares");
    assert!(message.contains("field `context`:"), "{message}");

    let message = check_event_conforms(SESSION_REVOKED, &event)
        .expect_err("the contract declares no nullable type");
    assert!(message.contains("/context/actor"), "{message}");
}

/// A `generated` target whose value is `null` is absent, not present: the contract
/// spells a generated value by carrying one.
#[test]
fn a_generated_field_that_is_null_fails_naming_it() {
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
    assert!(message.contains("field `linked_at`:"), "{message}");
}

/// The declared targets are the whole of what an emitted payload may carry, so a key
/// with no declared source is refused whatever its value — including `null`.
#[test]
fn event_keys_with_no_declared_source_are_refused_by_name() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    let mut event = session_revoked();
    event["tenant"] = json!("acme");
    event["shadow"] = Value::Null;
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("the contract declares a source for neither key");
    assert!(message.contains("`tenant`"), "{message}");
    assert!(message.contains("`shadow`"), "{message}");
}

/// An event name is decided against the IR's own event list, so a name that is not
/// declared is refused as undeclared and never as a missing file — and nothing a
/// caller supplies is ever joined into a path.
#[test]
fn an_event_name_is_decided_against_the_contract_not_the_filesystem() {
    for name in [
        "mandate.tenancy.OrganizationRenamed",
        "mandate.identity.sessionrevoked",
        "../types/mandate.core.VerifiedContext",
        "",
    ] {
        let message = check_event_conforms(name, &organization_created())
            .expect_err("the contract declares no event under that name");
        assert!(
            message.contains("declares no such event"),
            "{name}: {message}"
        );
        assert!(!message.contains("No such file"), "{name}: {message}");
    }
}

/// The panicking forms carry the same message, naming the outcome and the field.
#[test]
#[should_panic(expected = "/denied:")]
fn the_assert_form_of_single_emission_panics_naming_the_outcome() {
    let payload = session_revoked();
    assert_single_emission(REVOKE_SESSION, "denied", &[(SESSION_REVOKED, &payload)]);
}

#[test]
#[should_panic(expected = "field `id`:")]
fn the_assert_form_of_payload_sources_panics_naming_the_field() {
    let input = json!({
        "id": encoded(&SessionId::new(uuid(3))),
        "context": encoded(&context()),
    });
    let mut event = session_revoked();
    event["id"] = encoded(&SessionId::new(uuid(9)));
    assert_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event);
}

#[test]
fn an_unknown_command_or_event_is_refused_by_name_for_sources() {
    let message = check_payload_sources(
        "mandate.identity.CloseSession",
        &json!({}),
        None,
        SESSION_REVOKED,
        &json!({}),
    )
    .expect_err("the contract declares no such command");
    assert!(
        message.contains("mandate.identity.CloseSession"),
        "{message}"
    );

    let message =
        check_payload_sources(REVOKE_SESSION, &json!({}), None, SESSION_OPENED, &json!({}))
            .expect_err("the command declares no payload for that event");
    assert!(message.contains(REVOKE_SESSION), "{message}");
    assert!(message.contains(SESSION_OPENED), "{message}");
}

/// Every event the contract declares is validated, not only the ones with a case above:
/// each schema compiles under the pinned validator and refuses an empty payload by
/// naming a required property.
#[test]
fn every_declared_event_schema_compiles_and_refuses_an_empty_payload() {
    let ir = system_ir();
    let events = ir["events"].as_object().expect("the IR lists events");
    assert!(!events.is_empty(), "the IR lists no events");
    for name in events.keys() {
        let message = check_event_conforms(name, &json!({}))
            .expect_err("an empty payload satisfies no declared event");
        assert!(
            message.contains("is a required property"),
            "{name}: {message}"
        );
    }
}

/// Every outcome the contract declares is read by the emission check, and its own
/// declared emissions are what the check accepts.
#[test]
fn every_declared_outcome_accepts_exactly_its_own_emissions() {
    let ir = system_ir();
    let commands = ir["commands"].as_object().expect("the IR lists commands");
    assert!(!commands.is_empty(), "the IR lists no commands");
    let payload = json!({});
    for (command, node) in commands {
        for outcome in node["outcomes"].as_array().expect("outcomes are a list") {
            let name = outcome["name"].as_str().expect("an outcome has a name");
            let emits = strings(outcome, "emits");
            let emitted: Vec<(&str, &Value)> = emits
                .iter()
                .map(|event| (event.as_str(), &payload))
                .collect();
            check_single_emission(command, name, &emitted)
                .unwrap_or_else(|message| panic!("{command}/{name}: {message}"));
        }
    }
}

/// Every payload source kind the contract uses is one the harness checks. A kind it
/// does not know cannot be satisfied by an event built exactly as the IR declares it,
/// so this case fails the day the contract grows a fifth kind.
#[test]
fn every_declared_payload_source_is_satisfied_by_the_declared_shape() {
    let ir = system_ir();
    let commands = ir["commands"].as_object().expect("the IR lists commands");
    let mut checked = 0usize;
    for (command, node) in commands {
        for outcome in node["outcomes"].as_array().expect("outcomes are a list") {
            let Some(entries) = outcome["payload"].as_array() else {
                continue;
            };
            for entry in entries {
                let event_name = entry["event"].as_str().expect("a payload names its event");
                let fields = entry["fields"].as_array().expect("fields are a list");
                let (input, response, event) = declared_shape(command, event_name, fields);
                checked += fields.len();
                check_payload_sources(command, &input, Some(&response), event_name, &event)
                    .unwrap_or_else(|message| panic!("{command}/{event_name}: {message}"));
            }
        }
    }
    assert!(checked > 0, "the IR declares no payload sources");
}

/// The absence branch of the same sweep, over every value-sourced mapping the contract
/// declares: drop the source field and its target together, and the contract's own
/// `target_type` decides. An `optional` target passes; every other target is refused,
/// because its schema declares it required and an absent source cannot excuse it.
///
/// Two hand-written fixtures cannot hold this rule up — they cover the mappings someone
/// thought of. This walks all of them, so a mapping added or changed to optional is
/// decided by the IR and not by this file.
#[test]
fn every_declared_mapping_decides_absence_by_its_declared_target_type() {
    let ir = system_ir();
    let commands = ir["commands"].as_object().expect("the IR lists commands");
    let mut optional = 0usize;
    let mut required = 0usize;
    let mut wrong: Vec<String> = Vec::new();
    for (command, node) in commands {
        for outcome in node["outcomes"].as_array().expect("outcomes are a list") {
            let Some(entries) = outcome["payload"].as_array() else {
                continue;
            };
            for entry in entries {
                let event_name = entry["event"].as_str().expect("a payload names its event");
                let fields = entry["fields"].as_array().expect("fields are a list");
                let (input, response, event) = declared_shape(command, event_name, fields);
                for field in fields {
                    let target = field["target"].as_str().expect("a field has a target");
                    let Some(from) = field["value"]["field"].as_str() else {
                        continue;
                    };
                    let is_optional = field["target_type"]["kind"].as_str() == Some("optional");
                    let mut input = input.clone();
                    let mut response = response.clone();
                    let mut event = event.clone();
                    let supplied = if field["value"]["kind"] == json!("input_field") {
                        &mut input
                    } else {
                        &mut response
                    };
                    supplied
                        .as_object_mut()
                        .expect("the supplied side is an object")
                        .remove(from);
                    event
                        .as_object_mut()
                        .expect("the event is an object")
                        .remove(target);
                    if is_optional {
                        optional += 1;
                    } else {
                        required += 1;
                    }
                    let decided =
                        check_payload_sources(command, &input, Some(&response), event_name, &event);
                    let named = format!("{command}/{event_name} `{target}` from `{from}`");
                    match (is_optional, decided) {
                        (true, Ok(())) => {}
                        (false, Err(message)) => assert!(
                            message.contains(&format!("field `{target}`:")),
                            "{named}: the refusal does not name the target: {message}"
                        ),
                        (true, Err(message)) => {
                            wrong.push(format!("{named}: declared optional, refused: {message}"));
                        }
                        (false, Ok(())) => {
                            wrong.push(format!("{named}: declared required, accepted"));
                        }
                    }
                }
            }
        }
    }
    // The substantive assertion runs before the guards: a guard that fires first reports
    // that the sweep found nothing and hides what the sweep actually found.
    assert!(
        wrong.is_empty(),
        "{} of {} value-sourced targets are decided against their declared target_type: {}",
        wrong.len(),
        optional + required,
        wrong.join("; ")
    );
    assert!(
        optional > 0,
        "the IR declares no optional value-sourced target"
    );
    assert!(
        required > 0,
        "the IR declares no required value-sourced target"
    );
}

/// An event two outcomes of one command both declare has no mapping the harness may
/// pick: the IR as generated declares every mapping on a distinct event, so the case is
/// built in memory and driven through the `declaring_outcome_in` seam.
#[test]
fn an_event_declared_on_two_outcomes_is_refused_naming_both() {
    let ir = json!({
        "commands": {
            "mandate.example.DoThing": {
                "outcomes": [
                    {"name": "accepted", "payload": [{"event": "mandate.example.ThingDone", "fields": []}]},
                    {"name": "repaired", "payload": [{"event": "mandate.example.ThingDone", "fields": []}]},
                ],
            },
        },
    });
    let message = declaring_outcome_in(&ir, "mandate.example.DoThing", "mandate.example.ThingDone")
        .expect_err("two outcomes declare the same event, so the outcome decides");
    assert!(message.contains("accepted"), "{message}");
    assert!(message.contains("repaired"), "{message}");
    assert!(message.contains("2 outcomes"), "{message}");

    let sole = json!({
        "commands": {
            "mandate.example.DoThing": {
                "outcomes": [
                    {"name": "accepted", "payload": [{"event": "mandate.example.ThingDone", "fields": []}]},
                    {"name": "denied", "emits": [], "error": "mandate.example.Denied"},
                ],
            },
        },
    });
    let outcome = declaring_outcome_in(
        &sole,
        "mandate.example.DoThing",
        "mandate.example.ThingDone",
    )
    .expect("one outcome declares the event");
    assert_eq!(outcome, "accepted");

    let message =
        declaring_outcome_in(&sole, "mandate.example.Absent", "mandate.example.ThingDone")
            .expect_err("the supplied IR declares no such command");
    assert!(message.contains("mandate.example.Absent"), "{message}");
    assert!(message.contains("mandate.example.ThingDone"), "{message}");
}

/// The input, response and event one declared mapping describes, every field carrying
/// a probe value: exactly the shape the contract says the runtime produces. A source
/// kind the harness does not read cannot be built this way, so the sweeps that use it
/// fail the day the contract grows a fifth one.
fn declared_shape(command: &str, event_name: &str, fields: &[Value]) -> (Value, Value, Value) {
    let mut input = Map::new();
    let mut response = Map::new();
    let mut event = Map::new();
    for field in fields {
        let target = field["target"].as_str().expect("a field has a target");
        let source = &field["value"];
        match source["kind"].as_str().expect("a source has a kind") {
            "input_field" => {
                let from = source["field"].as_str().expect("a named input field");
                let probe = json!({ "from_input": from });
                input.insert(from.to_owned(), probe.clone());
                event.insert(target.to_owned(), probe);
            }
            "response_field" => {
                let from = source["field"].as_str().expect("a named response field");
                let probe = json!({ "from_response": from });
                response.insert(from.to_owned(), probe.clone());
                event.insert(target.to_owned(), probe);
            }
            "literal" => {
                event.insert(target.to_owned(), source["value"].clone());
            }
            "generated" => {
                event.insert(target.to_owned(), json!("generated at runtime"));
            }
            other => panic!("{command}/{event_name}: unread source kind {other}"),
        }
    }
    (
        Value::Object(input),
        Value::Object(response),
        Value::Object(event),
    )
}

/// The input and emitted payload of `RegisterResource` — whose `parent` the IR
/// declares `target_type.kind: optional` — with `parent` absent from both sides, as a
/// root resource is registered.
fn registered_root_resource() -> (Value, Value) {
    let resource = json!({
        "resource_type": "space",
        "resource_id": encoded(&ResourceId::new(uuid(10))),
    });
    let input = json!({ "context": encoded(&context()), "resource": resource });
    let event = json!({ "context": encoded(&context()), "resource": resource });
    (input, event)
}

/// The input, response and emitted payload of `CreateDelegation`, whose mapping carries
/// two more targets the IR declares optional — `not_before` and `execution_binding` —
/// both absent from the input and from the event.
fn created_delegation() -> (Value, Value, Value) {
    let input = json!({
        "context": encoded(&context()),
        "delegate": encoded(&PrincipalId::new(uuid(11))),
        "scope": {"actions": ["read"], "resources": []},
        "audience": encoded(&Audience::new("mandate")),
        "expires_at": encoded(&Timestamp::new("2026-09-20T00:00:00Z")),
    });
    let response = json!({ "delegation_id": encoded(&DelegationId::new(uuid(12))) });
    let event = json!({
        "context": encoded(&context()),
        "id": encoded(&DelegationId::new(uuid(12))),
        "delegator": encoded(&PrincipalId::new(uuid(2))),
        "delegate": encoded(&PrincipalId::new(uuid(11))),
        "scope": {"actions": ["read"], "resources": []},
        "audience": encoded(&Audience::new("mandate")),
        "expires_at": encoded(&Timestamp::new("2026-09-20T00:00:00Z")),
        "created_at": encoded(&Timestamp::new("2026-09-19T00:00:00Z")),
    });
    (input, response, event)
}

/// The response and emitted payload of `IntrospectCredential` with the optional
/// `descriptor` — the contract's one optional `response_field` target — absent from
/// both, as an introspection that resolved no descriptor returns.
fn introspected_without_a_descriptor() -> (Value, Value) {
    let response = json!({ "active": true });
    let event = json!({ "context": encoded(&context()) });
    (response, event)
}

/// The input, response and emitted payload of the one command whose mapping uses all
/// four source kinds the contract has: `input_field`, `response_field`, `literal` and
/// `generated`.
fn provisioned() -> (Value, Value, Value) {
    let input = json!({
        "connection_id": encoded(&FederationConnectionId::new(uuid(5))),
        "proof": {"issuer": "https://issuer.example", "verifier": "jwks"},
    });
    let response = json!({
        "principal_id": encoded(&PrincipalId::new(uuid(2))),
        "external_principal_id": encoded(&ExternalPrincipalId::new(uuid(6))),
        "subject": "external-subject",
    });
    let event = json!({
        "organization_id": encoded(&OrganizationId::new(uuid(1))),
        "correlation": "correlation",
        "connection_id": encoded(&FederationConnectionId::new(uuid(5))),
        "principal_id": encoded(&PrincipalId::new(uuid(2))),
        "kind": "User",
        "display_name": "External User",
        "external_principal_id": encoded(&ExternalPrincipalId::new(uuid(6))),
        "subject": "external-subject",
        "link_method": "ConfiguredFederation",
        "linked_at": encoded(&Timestamp::new("2026-09-19T00:00:00Z")),
    });
    (input, response, event)
}
