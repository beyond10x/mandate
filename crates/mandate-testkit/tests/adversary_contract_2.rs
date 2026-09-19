//! Adversary pass 2 over the event-validation harness, after correction round 1.
//!
//! Every case drives `mandate_testkit::contract` against one of the two generated
//! projections read as the specification it claims to be — `generated/ir/system.json`
//! and `generated/schema/events/*.schema.json` — or against the harness's own doc
//! comments read as the contract they claim to be. The IR carries `target_type` on
//! every payload field, so the contract itself says which targets are optional; a case
//! that reads that and disagrees with the code is the contract disagreeing with the
//! code, not an adversary's opinion.
//!
//! Nothing in this file edits the implementation or any existing case.

use mandate_testkit::contract::{
    check_event_conforms, check_payload_sources, check_single_emission,
};
use serde_json::{Map, Value, json};

const SYSTEM_IR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../generated/ir/system.json"
);
const EVENT_SCHEMAS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/events");

const REVOKE_SESSION: &str = "mandate.identity.RevokeSession";
const SESSION_REVOKED: &str = "mandate.identity.SessionRevoked";
const INTROSPECT_CREDENTIAL: &str = "mandate.credential.IntrospectCredential";
const CREDENTIAL_INTROSPECTED: &str = "mandate.credential.CredentialIntrospected";
const PROVISION_EXTERNAL_PRINCIPAL: &str = "mandate.federation.ProvisionExternalPrincipal";
const EXTERNAL_PRINCIPAL_PROVISIONED: &str = "mandate.federation.ExternalPrincipalProvisioned";

const ORGANIZATION: &str = "01010101-0101-0101-0101-010101010101";
const PRINCIPAL: &str = "02020202-0202-0202-0202-020202020202";
const SESSION: &str = "03030303-0303-0303-0303-030303030303";
const CONNECTION: &str = "05050505-0505-0505-0505-050505050505";
const EXTERNAL_PRINCIPAL: &str = "06060606-0606-0606-0606-060606060606";
const CREDENTIAL: &str = "07070707-0707-0707-0707-070707070707";

const SAMPLE_UUID: &str = "11111111-2222-4333-8444-555555555555";
const SAMPLE_DATE_TIME: &str = "2026-09-19T00:00:00Z";
const SAMPLE_DURATION: &str = "PT30S";

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

/// A `CredentialDescriptor` carrying every required field the contract declares.
fn descriptor() -> Value {
    json!({
        "kind": "Reference",
        "subject": PRINCIPAL,
        "organization": ORGANIZATION,
        "audience": "mandate",
        "scope": {"actions": ["read"], "resources": []},
        "expires_at": SAMPLE_DATE_TIME,
    })
}

/// The input, response and emitted payload of the one command whose mapping uses all
/// four source kinds, built from the mapping `generated/ir/system.json` declares.
fn provisioned() -> (Value, Value, Value) {
    let input = json!({
        "connection_id": CONNECTION,
        "proof": {"issuer": "https://issuer.example", "verifier": "jwks"},
    });
    let response = json!({
        "principal_id": PRINCIPAL,
        "external_principal_id": EXTERNAL_PRINCIPAL,
        "subject": "external-subject",
        "organization_id": ORGANIZATION,
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
        "linked_at": SAMPLE_DATE_TIME,
    });
    (input, response, event)
}

fn system_ir() -> Value {
    let text = std::fs::read_to_string(SYSTEM_IR).expect("the generated IR is readable");
    serde_json::from_str(&text).expect("the generated IR is JSON")
}

fn event_schema(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{EVENT_SCHEMAS}/{name}.schema.json"))
        .expect("the generated event schema is readable");
    serde_json::from_str(&text).expect("the generated event schema is JSON")
}

/// One declared payload mapping, keyed on the triple the IR keys it on.
struct Mapping {
    command: String,
    outcome: String,
    event: String,
    fields: Vec<Value>,
}

/// Every payload mapping the contract declares, in IR order.
fn mappings(ir: &Value) -> Vec<Mapping> {
    let mut declared = Vec::new();
    let commands = ir["commands"].as_object().expect("the IR lists commands");
    for (command, node) in commands {
        for outcome in node["outcomes"].as_array().expect("outcomes are a list") {
            let Some(entries) = outcome["payload"].as_array() else {
                continue;
            };
            let name = outcome["name"].as_str().expect("an outcome has a name");
            for entry in entries {
                declared.push(Mapping {
                    command: command.clone(),
                    outcome: name.to_owned(),
                    event: entry["event"]
                        .as_str()
                        .expect("a payload names its event")
                        .to_owned(),
                    fields: entry["fields"]
                        .as_array()
                        .expect("fields are a list")
                        .clone(),
                });
            }
        }
    }
    declared
}

/// The input, response and event a mapping declares, every field carrying a probe
/// value, so the source check sees exactly the shape the contract describes.
fn declared_shape(mapping: &Mapping) -> (Value, Value, Value) {
    let mut input = Map::new();
    let mut response = Map::new();
    let mut event = Map::new();
    for field in &mapping.fields {
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
            other => panic!(
                "{}/{}: unread source kind {other}",
                mapping.command, mapping.event
            ),
        }
    }
    (
        Value::Object(input),
        Value::Object(response),
        Value::Object(event),
    )
}

/// An instance built from a schema node: every required property, `$ref` resolved
/// against the file's own `$defs`, and a sample value for each declared lexical form.
fn synthesized(node: &Value, defs: &Value, depth: usize) -> Value {
    assert!(
        depth < 16,
        "this case does not follow a schema this deep: {node}"
    );
    if let Some(reference) = node["$ref"].as_str() {
        let name = reference
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("a `$ref` outside the file's own `$defs`: {reference}"));
        return synthesized(&defs[name], defs, depth + 1);
    }
    if let Some(branch) = node["oneOf"]
        .as_array()
        .and_then(|branches| branches.first())
    {
        return synthesized(branch, defs, depth + 1);
    }
    if let Some(constant) = node.get("const") {
        return constant.clone();
    }
    if let Some(first) = node["enum"].as_array().and_then(|values| values.first()) {
        return first.clone();
    }
    match node["type"].as_str() {
        Some("object") => {
            let mut instance = Map::new();
            for key in node["required"].as_array().map_or(&[][..], Vec::as_slice) {
                let key = key.as_str().expect("a required entry is a property name");
                instance.insert(
                    key.to_owned(),
                    synthesized(&node["properties"][key], defs, depth + 1),
                );
            }
            Value::Object(instance)
        }
        Some("array") => json!([]),
        Some("integer") => json!(1),
        Some("boolean") => json!(true),
        Some("string") => match node["format"].as_str() {
            Some("uuid") => json!(SAMPLE_UUID),
            Some("date-time") => json!(SAMPLE_DATE_TIME),
            Some("duration") => json!(SAMPLE_DURATION),
            Some(other) => panic!("this case carries no sample for `format: {other}`"),
            None => {
                assert!(
                    node.get("pattern").is_none(),
                    "this case carries no sample for the pattern {}",
                    node["pattern"]
                );
                json!("sample")
            }
        },
        other => panic!("this case does not synthesize `type: {other:?}`: {node}"),
    }
}

/// A required target absent from the event is refused even when the supplied input is
/// missing the field the contract sources it from.
#[test]
fn a_required_target_absent_from_both_sides_is_refused() {
    let message = check_payload_sources(
        REVOKE_SESSION,
        &json!({}),
        None,
        SESSION_REVOKED,
        &json!({}),
    )
    .expect_err("`context` and `id` are declared required targets and the event carries neither");
    assert!(message.contains("field `context`:"), "{message}");
    assert!(message.contains("field `id`:"), "{message}");
}

/// For every target the IR declares non-optional, an absent source and an absent
/// target disagree: the contract carries the distinction in `target_type`.
#[test]
fn every_required_target_refuses_a_source_and_a_target_that_are_both_absent() {
    let ir = system_ir();
    let mut accepted: Vec<String> = Vec::new();
    let mut examined = 0usize;
    for mapping in mappings(&ir) {
        let (input, response, event) = declared_shape(&mapping);
        for field in &mapping.fields {
            if field["target_type"]["kind"].as_str() == Some("optional") {
                continue;
            }
            let target = field["target"].as_str().expect("a field has a target");
            let kind = field["value"]["kind"]
                .as_str()
                .expect("a source has a kind")
                .to_owned();
            let Some(from) = field["value"]["field"].as_str() else {
                continue;
            };
            let mut input = input.clone();
            let mut response = response.clone();
            let mut event = event.clone();
            let side = if kind == "input_field" {
                &mut input
            } else {
                &mut response
            };
            side.as_object_mut()
                .expect("the probe side is an object")
                .remove(from);
            event
                .as_object_mut()
                .expect("the probe event is an object")
                .remove(target);
            examined += 1;
            if check_payload_sources(
                &mapping.command,
                &input,
                Some(&response),
                &mapping.event,
                &event,
            )
            .is_ok()
            {
                accepted.push(format!(
                    "{}/{}/{} `{target}` (declared {kind} `{from}`)",
                    mapping.command, mapping.outcome, mapping.event
                ));
            }
        }
    }
    assert!(
        examined > 0,
        "the IR declares no required value-sourced target"
    );
    assert!(
        accepted.is_empty(),
        "{} of {examined} required targets are accepted while the event omits them, because the source the caller supplied omits them too; the IR declares every one of them `target_type.kind: declared`: {}",
        accepted.len(),
        accepted
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<String>>()
            .join("; ")
    );
}

/// The optional-to-optional mappings the harness's cases exercise are declared by the IR.
///
/// Aligned at regeneration: the harness no longer documents a count (correction round 2),
/// and `story:contract-creates` widened the set beyond the four this pass found, so the
/// case asserts the four it exercises are among what the IR declares.
#[test]
fn the_documented_count_of_optional_to_optional_mappings_matches_the_ir() {
    let ir = system_ir();
    let mut optional = Vec::new();
    for mapping in mappings(&ir) {
        for field in &mapping.fields {
            if field["target_type"]["kind"].as_str() == Some("optional") {
                optional.push(format!(
                    "`{}` on {} (source kind {})",
                    field["target"].as_str().unwrap_or("<unnamed>"),
                    mapping.event,
                    field["value"]["kind"].as_str().unwrap_or("<none>")
                ));
            }
        }
    }
    for expected in [
        "`descriptor` on mandate.credential.CredentialIntrospected",
        "`not_before` on mandate.delegation.DelegationCreated",
        "`execution_binding` on mandate.delegation.DelegationCreated",
        "`parent` on mandate.graph.ResourceRegistered",
    ] {
        assert!(
            optional.iter().any(|row| row.starts_with(expected)),
            "the IR no longer declares {expected}; it declares {}: {}",
            optional.len(),
            optional.join("; ")
        );
    }
}

/// A `null` is absence at the mapped field level only, as `src/contract.rs` says after
/// correction round 2: a `null` nested inside a `$defs` object is part of the value the
/// mapping compares as a whole, so the source check refuses it and the schema check
/// refuses it by its instance path.
#[test]
fn a_null_nested_in_an_object_is_a_value_the_mapping_compares() {
    let input = json!({ "context": context(), "id": SESSION });
    let mut event = session_revoked();
    event["context"]["actor"] = Value::Null;
    let message = check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect_err("the nested `null` is part of the value the mapping compares");
    assert!(message.contains("field `context`:"), "{message}");
    let message = check_event_conforms(SESSION_REVOKED, &event)
        .expect_err("the contract declares no nullable type");
    assert!(message.contains("/context/actor"), "{message}");
}

/// A refusal names the outcome and the event the caller supplied, as the `# Errors`
/// clauses at `src/contract.rs:111` and `src/contract.rs:190` promise.
#[test]
fn a_refusal_names_the_outcome_and_the_event_the_caller_supplied() {
    let mut silent = Vec::new();
    let message = check_single_emission("mandate.identity.CloseSession", "accepted", &[])
        .expect_err("the contract declares no such command");
    if !message.contains("accepted") {
        silent.push(format!(
            "check_single_emission on an undeclared command does not name the outcome `accepted`: {message}"
        ));
    }
    let message = check_payload_sources(
        "mandate.identity.CloseSession",
        &json!({}),
        None,
        SESSION_REVOKED,
        &json!({}),
    )
    .expect_err("the contract declares no such command");
    if !message.contains(SESSION_REVOKED) {
        silent.push(format!(
            "check_payload_sources on an undeclared command does not name the event `{SESSION_REVOKED}`: {message}"
        ));
    }
    assert!(silent.is_empty(), "{}", silent.join("; "));
}

/// Absence is symmetric through `response_field` too: the contract's one optional
/// response-sourced target agrees with a response that omits it and disagrees with an
/// event that carries one.
#[test]
fn absence_symmetry_holds_through_the_response_for_an_optional_response_source() {
    let response = json!({});
    let event = json!({ "context": context() });
    check_event_conforms(CREDENTIAL_INTROSPECTED, &event)
        .expect("`descriptor` is outside `required`, so an introspection without one conforms");
    check_payload_sources(
        INTROSPECT_CREDENTIAL,
        &json!({}),
        Some(&response),
        CREDENTIAL_INTROSPECTED,
        &event,
    )
    .expect("a response that omits the optional `descriptor` agrees with an event that omits it");

    let mut carried = event.clone();
    carried["descriptor"] = descriptor();
    let message = check_payload_sources(
        INTROSPECT_CREDENTIAL,
        &json!({}),
        Some(&response),
        CREDENTIAL_INTROSPECTED,
        &carried,
    )
    .expect_err("the event carries a descriptor the response did not return");
    assert!(message.contains("field `descriptor`:"), "{message}");
}

/// A `literal` target carrying `null` is absent, and absence disagrees with a literal.
#[test]
fn a_literal_target_that_carries_null_is_refused_naming_the_literal() {
    let (input, response, mut event) = provisioned();
    event["kind"] = Value::Null;
    let message = check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect_err("`null` is not how the contract spells a declared literal");
    assert!(message.contains("field `kind`:"), "{message}");
    assert!(message.contains("User"), "{message}");
}

/// An emitted payload that is not a JSON object is refused naming its shape, whatever
/// the supplied input carries.
#[test]
fn an_event_that_is_not_a_json_object_is_refused_naming_its_shape() {
    for event in [
        json!([]),
        json!("mandate.identity.SessionRevoked"),
        json!(7),
    ] {
        let message =
            check_payload_sources(REVOKE_SESSION, &json!({}), None, SESSION_REVOKED, &event)
                .expect_err("an emitted payload is a JSON object");
        assert!(message.contains("not a JSON object"), "{event}: {message}");
    }
}

/// A `generated` target carrying the empty string is present, not absent: the source
/// check passes it and the schema decides its lexical form.
#[test]
fn a_generated_target_that_is_an_empty_string_is_present_not_absent() {
    let (input, response, mut event) = provisioned();
    event["linked_at"] = json!("");
    check_payload_sources(
        PROVISION_EXTERNAL_PRINCIPAL,
        &input,
        Some(&response),
        EXTERNAL_PRINCIPAL_PROVISIONED,
        &event,
    )
    .expect("an empty string is a value the runtime produced, so the source check passes it on");
    let message = check_event_conforms(EXTERNAL_PRINCIPAL_PROVISIONED, &event)
        .expect_err("`linked_at` is declared `format: date-time`");
    assert!(message.contains("/linked_at"), "{message}");
}

/// A `null` for a required field inside a `$defs` object is refused by its instance
/// path, and the source check reads the object as a whole without failing on it.
#[test]
fn a_null_for_a_required_field_inside_a_defs_object_is_refused_by_instance_path() {
    let mut event = session_revoked();
    event["context"]["subject"] = Value::Null;
    let message = check_event_conforms(SESSION_REVOKED, &event)
        .expect_err("`subject` is required and the contract declares no nullable type");
    assert!(message.contains("/context/subject"), "{message}");
    let input = json!({ "context": event["context"].clone(), "id": SESSION });
    check_payload_sources(REVOKE_SESSION, &input, None, SESSION_REVOKED, &event)
        .expect("the source check compares the mapped object by value and does not read inside it");
}

/// No event name reaches the filesystem, whatever shape it is given: each is refused
/// as undeclared, and no refusal carries an OS error or an absolute path.
#[test]
fn no_event_name_reaches_the_filesystem_whatever_shape_it_takes() {
    for name in [
        "/etc/passwd",
        "../../ir/system",
        "mandate.identity.SessionRevoked.schema.json",
        "mandate.core.VerifiedContext",
        "generated/schema/events/mandate.identity.SessionRevoked",
        ".",
    ] {
        let message = check_event_conforms(name, &session_revoked())
            .expect_err("the contract declares no event under that name");
        assert!(
            message.contains("declares no such event"),
            "{name}: {message}"
        );
        assert!(!message.contains("os error"), "{name}: {message}");
        assert!(
            !message.contains(env!("CARGO_MANIFEST_DIR")),
            "{name}: {message}"
        );
    }
}

/// Every declared event schema accepts an instance synthesized from its own required
/// properties, with `$ref` resolved recursively against its own `$defs`.
#[test]
fn every_declared_event_schema_accepts_a_synthesized_required_instance() {
    let ir = system_ir();
    let events = ir["events"].as_object().expect("the IR lists events");
    assert!(!events.is_empty(), "the IR lists no events");
    let mut refused = Vec::new();
    for name in events.keys() {
        let schema = event_schema(name);
        let instance = synthesized(&schema, &schema["$defs"], 0);
        if let Err(message) = check_event_conforms(name, &instance) {
            refused.push(format!("{message} (synthesized {instance})"));
        }
    }
    assert!(
        refused.is_empty(),
        "{} of {} declared event schemas refuse an instance built from their own required properties: {}",
        refused.len(),
        events.len(),
        refused.join("; ")
    );
}

/// The two projections agree on the declared shape: an event built from the IR mapping
/// with schema-conforming values passes the schema check and the source check at once.
#[test]
fn every_declared_mapping_conforms_and_passes_its_sources_together() {
    let ir = system_ir();
    let mut disagreements = Vec::new();
    let mut checked = 0usize;
    for mapping in mappings(&ir) {
        let schema = event_schema(&mapping.event);
        let defs = schema["$defs"].clone();
        let mut input = Map::new();
        let mut response = Map::new();
        let mut event = Map::new();
        for field in &mapping.fields {
            let target = field["target"].as_str().expect("a field has a target");
            let source = &field["value"];
            let kind = source["kind"].as_str().expect("a source has a kind");
            let value = if kind == "literal" {
                source["value"].clone()
            } else {
                synthesized(&schema["properties"][target], &defs, 0)
            };
            if kind == "input_field" {
                let from = source["field"].as_str().expect("a named input field");
                input.insert(from.to_owned(), value.clone());
            } else if kind == "response_field" {
                let from = source["field"].as_str().expect("a named response field");
                response.insert(from.to_owned(), value.clone());
            }
            event.insert(target.to_owned(), value);
        }
        let event = Value::Object(event);
        checked += 1;
        if let Err(message) = check_event_conforms(&mapping.event, &event) {
            disagreements.push(format!("{}: conforms refused: {message}", mapping.command));
        }
        if let Err(message) = check_payload_sources(
            &mapping.command,
            &Value::Object(input),
            Some(&Value::Object(response)),
            &mapping.event,
            &event,
        ) {
            disagreements.push(format!("sources refused: {message}"));
        }
    }
    assert!(checked > 0, "the IR declares no payload mapping");
    assert!(
        disagreements.is_empty(),
        "{} of {checked} declared mappings are refused by one of the two checks: {}",
        disagreements.len(),
        disagreements.join("; ")
    );
}
