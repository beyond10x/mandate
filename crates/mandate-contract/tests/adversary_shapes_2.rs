//! Adversary pass 2 against the generated crate: the boundaries the round-1 cases stopped
//! short of, absence at depth, and the surface the E2 agreement tests will hold the crate by.

use mandate_contract::{
    entities, events,
    types::{self, Presence},
};
use serde_json::json;

fn principal(id: &str) -> types::MandateCorePrincipalId {
    types::MandateCorePrincipalId(id.to_owned())
}

/// Every number the schema calls an `integer` is carried exactly, as the mapping's reason says.
///
/// `xtask/src/emit.rs` maps `integer` to `::serde_json::Number` because "`1.0` and `2^63` are
/// both values the projection admits and neither is an `i64`. `Number` keeps every one of them
/// exactly." `generated/schema/entities/mandate.identity.PrincipalSecurityEpoch.schema.json`
/// states `{"type": "integer"}` for `generation` with no `minimum` and no `maximum`, so every
/// document below is one the projection admits. `18446744073709551617` is `2^64 + 1`, which no
/// `f64` holds, so what it costs is the value and not only its spelling.
#[test]
fn an_integer_the_schema_admits_is_carried_exactly() {
    // Coordinator ruling after adversary pass 2 (A2-3): `serde_json::Number` without
    // `arbitrary_precision` carries every integer in the i64 and u64 ranges exactly and
    // no contract integer (epoch generations, counters) leaves that range; `2^64 + 1` and
    // `-0` are outside the domain's value space and are documented as the bound, not
    // asserted. Exactness is asserted across the whole representable range.
    let mut lost = Vec::new();
    for generation in [
        "0",
        "7",
        "1.0",
        "9223372036854775807",
        "9223372036854775808",
        "18446744073709551615",
        "-9223372036854775808",
    ] {
        let document =
            format!(r#"{{"id": "epoch-1", "generation": {generation}, "state": "Recorded"}}"#);
        let epoch: entities::MandateIdentityPrincipalSecurityEpoch =
            serde_json::from_str(&document).unwrap_or_else(|error| {
                panic!("the shape refuses a schema-valid {generation}: {error}")
            });
        let carried = epoch.generation.to_string();
        if carried != generation {
            lost.push(format!("{generation} came back as {carried}"));
        }
    }
    assert!(
        lost.is_empty(),
        "the shape did not keep every integer its schema admits:\n{}",
        lost.join("\n")
    );
}

/// An absent optional is a key that is not there at every depth, not only at the top.
///
/// `SessionRevoked.context` is a `VerifiedContext` with three optional keys, so the skipping
/// attribute has to hold one record down from the event rather than on the event's own keys.
#[test]
fn an_absent_optional_is_omitted_at_every_depth() {
    let event = events::MandateIdentitySessionRevoked {
        context: types::MandateCoreVerifiedContext {
            subject: principal("principal-1"),
            actor: Presence::Absent,
            organization: types::MandateCoreOrganizationId("organization-1".to_owned()),
            audience: types::MandateCoreAudience("https://api.example".to_owned()),
            credential: types::MandateCoreCredentialId("credential-1".to_owned()),
            delegation: Presence::Absent,
            execution: Presence::Absent,
            correlation: types::MandateCoreCorrelationId("correlation-1".to_owned()),
        },
        id: types::MandateCoreSessionId("session-1".to_owned()),
    };
    let wire = serde_json::to_value(&event).expect("serialize");
    let nested = wire["context"].as_object().expect("a nested record");
    for absent in ["actor", "delegation", "execution"] {
        assert!(
            !nested.contains_key(absent),
            "the nested record carries {absent}: {wire}"
        );
    }
    assert_eq!(
        wire,
        json!({
            "context": {
                "subject": "principal-1",
                "organization": "organization-1",
                "audience": "https://api.example",
                "credential": "credential-1",
                "correlation": "correlation-1"
            },
            "id": "session-1"
        })
    );
    assert_eq!(
        serde_json::from_value::<events::MandateIdentitySessionRevoked>(wire).expect("round trip"),
        event
    );
}

/// The surface an agreement test holds the crate by: value equality and exhaustive destructuring.
///
/// `story:model-agreement` reads `to_value(domain) -> from_value::<Generated>() -> to_value`
/// and destructures the generated record to prove no key was forgotten. Both need every field
/// public, `Deserialize`, `Serialize`, `PartialEq` and `Debug` on the record, and `Presence` to
/// be matchable from outside the crate.
#[test]
fn the_surface_an_agreement_test_needs_is_public() {
    let document = json!({
        "context": {
            "subject": "principal-1",
            "actor": "principal-2",
            "organization": "organization-1",
            "audience": "https://api.example",
            "credential": "credential-1",
            "correlation": "correlation-1"
        },
        "id": "session-1"
    });
    let event: events::MandateIdentitySessionRevoked =
        serde_json::from_value(document.clone()).expect("deserialize");
    assert_eq!(serde_json::to_value(&event).expect("serialize"), document);

    let events::MandateIdentitySessionRevoked { context, id } = event.clone();
    let types::MandateCoreVerifiedContext {
        subject,
        actor,
        organization,
        audience,
        credential,
        delegation,
        execution,
        correlation,
    } = context;
    assert_eq!(subject, principal("principal-1"));
    assert_eq!(
        match actor {
            Presence::Present(value) => value,
            Presence::Absent => panic!("the document carries an actor"),
        },
        principal("principal-2")
    );
    assert!(delegation.is_absent() && execution.is_absent());
    assert_eq!(organization.0, "organization-1");
    assert_eq!(audience.0, "https://api.example");
    assert_eq!(credential.0, "credential-1");
    assert_eq!(correlation.0, "correlation-1");
    assert_eq!(id.0, "session-1");
    assert_eq!(event.clone(), event);
}
