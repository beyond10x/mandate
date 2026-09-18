//! Adversarial cases for `story:canonical-types`, driven from the ESS projection this
//! unit claims to realize.

use mandate_types::AuthorityScope;

/// Positive controls for the `compile_fail` doctests in `crates/mandate-types/src/lib.rs`.
///
/// A `compile_fail` doctest passes when its snippet fails to compile for *any* reason,
/// including a typo, a missing import or a private path. Each control below is the
/// corresponding doctest body with exactly one token changed, so that the rule the
/// doctest claims to prove is no longer violated and nothing else differs. Because this
/// file compiles, each of those doctests fails for the rule and not for an accident.
mod compile_fail_controls {
    use mandate_types::{CorrelationId, CredentialId, OrganizationId, PersistedValue, PrincipalId};

    const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

    /// `lib.rs:22` calls `tenant_of(PrincipalId::parse(..).unwrap())` where `tenant_of`
    /// takes an `OrganizationId`. Control: the parameter type, and nothing else, is the
    /// identifier the argument already has.
    fn tenant_of(_: PrincipalId) {}

    /// `lib.rs:52` calls `persistable::<CredentialSecret>()`. Control: the type argument,
    /// and nothing else, is a type the boundary admits.
    fn persistable<T: PersistedValue>() {}

    /// `lib.rs:98` declares a record whose `secret` field is a `CredentialSecret` and
    /// passes it to `canonical_record!`. Control: the field type, and nothing else, is a
    /// type the boundary admits. The field name, the field order, the derives and the
    /// macro invocation are byte-for-byte the doctest's.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub struct Trace {
        pub secret: CredentialId,
        pub correlation: CorrelationId,
    }

    mandate_types::canonical_record!(Trace { secret, correlation }, samples: vec![Trace {
        secret: CredentialId::parse(SAMPLE_UUID).unwrap(),
        correlation: CorrelationId::new("correlation"),
    }]);

    #[test]
    fn each_compile_fail_body_compiles_once_its_one_offending_token_is_changed() {
        tenant_of(PrincipalId::parse(SAMPLE_UUID).expect("principal"));
        persistable::<OrganizationId>();
        let trace = Trace {
            secret: CredentialId::parse(SAMPLE_UUID).expect("credential"),
            correlation: CorrelationId::new("correlation"),
        };
        assert_eq!(
            serde_json::to_string(&trace).expect("encode"),
            format!("{{\"secret\":\"{SAMPLE_UUID}\",\"correlation\":\"correlation\"}}")
        );
    }
}

/// `generated/schema/types/mandate.core.AuthorityScope.schema.json` declares
/// `properties.space` as `{"$ref": "#/$defs/mandate.core.SpaceId"}`, and
/// `mandate.core.SpaceId` as `{"type": "string", "format": "uuid", "pattern": ...}`.
/// JSON `null` is therefore not a form the projection declares for `space`.
///
/// `crates/mandate-types/src/conformance.rs:15` states the rule this case applies: the
/// suite carries "Wire forms the contract does not declare, which decoding must refuse."
///
/// The unit's own optional-field case
/// (`crates/mandate-types/tests/conformance.rs:228`) covers two of the three wire states
/// an optional field has — omitted and present. This is the third.
#[test]
fn an_optional_field_refuses_the_json_null_the_projection_does_not_declare() {
    let wire = r#"{"actions":[],"resources":[],"space":null}"#;
    let decoded = serde_json::from_str::<AuthorityScope>(wire);
    assert!(
        decoded.is_err(),
        "decoded an undeclared wire form {wire} into {decoded:?}"
    );
}
