//! Adversarial cases for `story:canonical-types`: the transient credential boundary,
//! attacked from a crate that is not `mandate-types`.

use mandate_types::{CorrelationId, CredentialSecret, PersistedValue};
use serde::{Deserialize, Serialize};

/// A container declared outside `mandate-types`.
///
/// `crates/mandate-types/src/marker.rs:7` states the guarantee this case attacks:
/// "Neither trait can be implemented for [`CredentialSecret`] or [`CredentialProof`]
/// outside this crate: both the trait and the types are foreign to every other crate, so
/// the orphan rule refuses the impl. The guarantee is therefore the absence of an impl
/// here, not a convention anywhere else."
///
/// The orphan rule does not refuse the impl below: `Envelope` is local to this crate, so
/// `Envelope<CredentialSecret>` is a local type and `PersistedValue` may be implemented
/// for it. If this file compiles, the guarantee quoted above does not hold as stated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Envelope<T>(T);

impl PersistedValue for Envelope<CredentialSecret> {}

/// A record declared through the macro whose doc
/// (`crates/mandate-types/src/macros.rs:152`) promises that a transient credential type
/// "does not implement [`PersistedValue`], so no record declared through
/// [`canonical_record`] can hold one, in any wrapper".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LaunderedRecord {
    correlation: CorrelationId,
    secret: Envelope<CredentialSecret>,
}

mandate_types::canonical_record!(
    LaunderedRecord { correlation, secret },
    samples: vec![LaunderedRecord {
        correlation: CorrelationId::new("correlation"),
        secret: Envelope(CredentialSecret::from_bytes(b"abc".to_vec())),
    }]
);

/// Positive control for the `compile_fail` doctest at
/// `crates/mandate-model/src/lib.rs:23`.
///
/// That doctest declares `IssuanceRecord { correlation: CorrelationId, proof:
/// CredentialProof }` and passes it to `canonical_record!`. This control is the same
/// declaration with the `proof` field type, and nothing else, changed to a type the
/// boundary admits. Because it compiles, the doctest fails for the transient field and
/// not for a missing import, a private path or a typo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct IssuanceRecord {
    correlation: CorrelationId,
    proof: mandate_types::CredentialVerifier,
}

mandate_types::canonical_record!(
    IssuanceRecord { correlation, proof },
    samples: vec![IssuanceRecord {
        correlation: CorrelationId::new("correlation"),
        proof: mandate_types::CredentialVerifier::new("verifier"),
    }]
);

#[test]
fn the_compile_fail_body_compiles_once_its_transient_field_type_is_changed() {
    let record = IssuanceRecord {
        correlation: CorrelationId::new("correlation"),
        proof: mandate_types::CredentialVerifier::new("verifier"),
    };
    assert_eq!(
        serde_json::to_string(&record).expect("encode"),
        "{\"correlation\":\"correlation\",\"proof\":\"verifier\"}"
    );
}

/// `docs/architecture/combined.md`, quoted at `crates/mandate-types/src/marker.rs:3`:
/// "CredentialSecret and CredentialProof are transient boundary types, never persisted
/// entity fields or audit payloads."
#[test]
fn a_persisted_record_cannot_carry_a_transient_credential_in_any_wrapper() {
    let record = LaunderedRecord {
        correlation: CorrelationId::new("correlation"),
        secret: Envelope(CredentialSecret::from_bytes(b"abc".to_vec())),
    };
    let encoded = serde_json::to_string(&record).expect("encode");
    assert!(
        !encoded.contains("YWJj"),
        "credential material reached a persisted record's wire form: {encoded}"
    );
}
