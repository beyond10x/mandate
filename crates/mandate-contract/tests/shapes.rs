//! What the generated shapes refuse, decided against JSON rather than against Rust.
//!
//! The crate's whole claim is that a document which does not match an ESS declaration cannot
//! become a value of the declaration's Rust shape. Every case here therefore starts from a
//! `serde_json::Value` — the wire — and asks the shape to accept it, because a case written in
//! Rust constructors can only ever build what the shape already admits.

use mandate_contract::{
    commands, entities, events,
    types::{self, Presence},
};
use serde_json::{Value, json};

fn principal(id: &str) -> types::MandateCorePrincipalId {
    types::MandateCorePrincipalId(id.to_owned())
}

/// The smallest context the declaration admits: every optional key absent.
fn context() -> types::MandateCoreVerifiedContext {
    types::MandateCoreVerifiedContext {
        subject: principal("principal-1"),
        actor: Presence::Absent,
        organization: types::MandateCoreOrganizationId("organization-1".to_owned()),
        audience: types::MandateCoreAudience("https://api.example".to_owned()),
        credential: types::MandateCoreCredentialId("credential-1".to_owned()),
        delegation: Presence::Absent,
        execution: Presence::Absent,
        correlation: types::MandateCoreCorrelationId("correlation-1".to_owned()),
    }
}

fn context_json() -> Value {
    json!({
        "subject": "principal-1",
        "organization": "organization-1",
        "audience": "https://api.example",
        "credential": "credential-1",
        "correlation": "correlation-1"
    })
}

fn session_revoked() -> Value {
    json!({"context": context_json(), "id": "session-1"})
}

/// The acceptance statement's own case: a representation carrying a key the declaration does
/// not, fed to the generated shape, fails on that key.
///
/// `SessionRevoked` declares `context` and `id`. A Rust event that still carried a `session`
/// it once had is exactly the drift no check caught before this crate existed, and
/// `deny_unknown_fields` is what turns it into a refusal instead of a silently dropped key.
#[test]
fn a_key_the_declaration_does_not_carry_is_refused() {
    let mut drifted = session_revoked();
    drifted["session"] = json!("session-1");
    let refusal = serde_json::from_value::<events::MandateIdentitySessionRevoked>(drifted)
        .expect_err("an unknown key is refused");
    assert!(refusal.to_string().contains("session"), "{refusal}");
    serde_json::from_value::<events::MandateIdentitySessionRevoked>(session_revoked())
        .expect("the declared document is accepted");
}

#[test]
fn a_missing_declared_key_is_refused() {
    let mut missing = session_revoked();
    missing
        .as_object_mut()
        .expect("an object")
        .remove("id")
        .expect("id was there");
    let refusal = serde_json::from_value::<events::MandateIdentitySessionRevoked>(missing)
        .expect_err("a missing declared key is refused");
    assert!(
        refusal.to_string().contains("missing field `id`"),
        "{refusal}"
    );
}

/// An absent optional is a key that is not there, on both sides of the wire.
#[test]
fn an_absent_optional_serializes_to_no_key_at_all() {
    let serialized = serde_json::to_value(context()).expect("serialize");
    let keys = serialized.as_object().expect("an object");
    for absent in ["actor", "delegation", "execution"] {
        assert!(!keys.contains_key(absent), "{absent} was written as a key");
    }
    assert_eq!(serialized, context_json());
}

/// `null` is not absence. ESS `optional` admits a missing key, not a null value.
#[test]
fn null_is_not_an_absent_optional() {
    let mut nulled = context_json();
    nulled["actor"] = Value::Null;
    let refusal = serde_json::from_value::<types::MandateCoreVerifiedContext>(nulled)
        .expect_err("null is refused");
    assert!(
        refusal.to_string().contains("null is not absence"),
        "{refusal}"
    );
}

/// A fully populated value survives the wire unchanged, optionals and union included.
#[test]
fn a_fully_populated_value_round_trips() {
    let populated = types::MandateCoreVerifiedContext {
        actor: Presence::Present(principal("principal-2")),
        delegation: Presence::Present(types::MandateCoreDelegationId("delegation-1".to_owned())),
        execution: Presence::Present(types::MandateCoreExecutionId("execution-1".to_owned())),
        ..context()
    };
    let wire = serde_json::to_value(&populated).expect("serialize");
    assert_eq!(wire["actor"], json!("principal-2"));
    let returned: types::MandateCoreVerifiedContext =
        serde_json::from_value(wire).expect("deserialize");
    assert_eq!(returned, populated);
}

/// A union is adjacently tagged, and the tag and content keys are the declaration's.
#[test]
fn a_union_carries_its_declared_tag_and_content() {
    let target = types::MandateCoreSecurityEpochTarget::Principal(principal("principal-1"));
    let wire = serde_json::to_value(&target).expect("serialize");
    assert_eq!(wire, json!({"kind": "principal", "value": "principal-1"}));
    assert_eq!(
        serde_json::from_value::<types::MandateCoreSecurityEpochTarget>(wire).expect("round trip"),
        target
    );
    serde_json::from_value::<types::MandateCoreSecurityEpochTarget>(
        json!({"kind": "principal", "value": "principal-1", "extra": 1}),
    )
    .expect_err("a union refuses a key it does not declare");
}

/// An entity record carries its identity, its fields and its lifecycle state.
#[test]
fn an_entity_carries_its_identity_and_its_lifecycle_state() {
    let wire = json!({
        "id": "principal-1",
        "kind": "Service",
        "display_name": "Ada",
        "state": "Active"
    });
    let principal: entities::MandateIdentityPrincipal =
        serde_json::from_value(wire.clone()).expect("deserialize");
    assert_eq!(
        principal.state,
        entities::MandateIdentityPrincipalState::Active
    );
    assert_eq!(serde_json::to_value(&principal).expect("serialize"), wire);
    let mut stateless = wire;
    stateless
        .as_object_mut()
        .expect("an object")
        .remove("state");
    serde_json::from_value::<entities::MandateIdentityPrincipal>(stateless)
        .expect_err("an entity without its lifecycle state is refused");
}

/// A command input may carry credential material, and its shape says so.
#[test]
fn a_command_input_carries_the_credential_it_verifies() {
    let wire = json!({"caller_proof": "Y2FsbGVy", "credential_proof": "Y3JlZA=="});
    let input: commands::MandateCredentialIntrospectCredentialInput =
        serde_json::from_value(wire.clone()).expect("deserialize");
    assert_eq!(
        input.credential_proof,
        types::MandateCoreCredentialProof("Y3JlZA==".to_owned())
    );
    assert_eq!(serde_json::to_value(&input).expect("serialize"), wire);
}

/// Today's drift, demonstrated: the domain's own event shape, fed to the declaration.
///
/// `crates/mandate-identity/src/port.rs` declares `IdentityEvent::SecurityEpochIncremented`
/// with a `target` and nothing else, while `mandate.identity.SecurityEpochIncremented` declares
/// a `context` beside it. Nothing in the workspace binds the two, so the divergence is live and
/// silent. This is the class of defect the crate exists to catch, and it is caught here as a
/// refusal naming the key the representation dropped.
#[test]
fn the_drifted_domain_event_fails_on_the_key_it_dropped() {
    #[derive(::serde::Serialize)]
    struct SecurityEpochIncremented {
        target: types::MandateCoreSecurityEpochTarget,
    }

    let drifted = serde_json::to_value(SecurityEpochIncremented {
        target: types::MandateCoreSecurityEpochTarget::Principal(principal("principal-1")),
    })
    .expect("serialize");
    let refusal =
        serde_json::from_value::<events::MandateIdentitySecurityEpochIncremented>(drifted)
            .expect_err("a representation missing a declared key is refused");
    assert!(
        refusal.to_string().contains("missing field `context`"),
        "{refusal}"
    );
}

/// A declared list is a `Vec`, and it round-trips with its order and its emptiness intact.
///
/// Order is part of the document: a list the shape reordered would make a byte-compare of two
/// equal records fail, and an empty list is not an absent key — `resources: []` is a document
/// the schema admits and `AuthorityScope` carries it as such.
#[test]
fn a_declared_list_round_trips_in_order() {
    let wire = json!({
        "actions": ["read", "write", "admin"],
        "resources": [
            {"resource_type": "repository", "resource_id": "repository-1"},
            {"resource_type": "space", "resource_id": "space-1"}
        ]
    });
    let scope: types::MandateCoreAuthorityScope =
        serde_json::from_value(wire.clone()).expect("deserialize");
    assert_eq!(
        scope.actions,
        ["read", "write", "admin"].map(|a| types::MandateCoreAction(a.to_owned()))
    );
    assert_eq!(scope.space, Presence::Absent);
    assert_eq!(serde_json::to_value(&scope).expect("serialize"), wire);

    let empty = json!({"actions": [], "resources": []});
    let none: types::MandateCoreAuthorityScope =
        serde_json::from_value(empty.clone()).expect("an empty list is not an absent key");
    assert!(none.actions.is_empty());
    assert_eq!(serde_json::to_value(&none).expect("serialize"), empty);
}

/// An `integer` carries every number its schema admits, exactly.
#[test]
fn an_integer_field_carries_what_the_schema_admits() {
    for generation in ["7", "1.0", "9223372036854775808"] {
        let document =
            format!(r#"{{"id": "epoch-1", "generation": {generation}, "state": "Recorded"}}"#);
        let epoch: entities::MandateIdentityPrincipalSecurityEpoch =
            serde_json::from_str(&document).unwrap_or_else(|e| {
                panic!("the shape refuses a schema-valid generation {generation}: {e}")
            });
        assert_eq!(epoch.generation.to_string(), generation);
    }
}

/// An absent value has no JSON spelling of its own, in either direction.
#[test]
fn an_absent_value_refuses_to_serialize_on_its_own() {
    let absent: Presence<types::MandateCorePrincipalId> = Presence::Absent;
    let refusal = serde_json::to_value(&absent).expect_err("absence is not a JSON value");
    assert!(
        refusal.to_string().contains("Presence::Absent"),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("omit the key"), "{refusal}");
}
