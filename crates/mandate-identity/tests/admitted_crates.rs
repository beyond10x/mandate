//! The generated contract shape admitted to `mandate-identity` resolves and links.
//!
//! The identity fold opens a Session from the payload `mandate-federation` emits, so it reads
//! the generated shape rather than a hand-written copy of it. Naming the type here shows the
//! regular dependency resolves and keeps the direction `mandate-federation → mandate-identity`:
//! `mandate-contract` re-exports generated structure and can reach no Mandate domain crate.

//! `serde` and `serde_json` are admitted by `story:federation-identity-alignment`: the
//! event, command-input and entity shapes this crate holds carry the derive their
//! agreement with the contract is decided through, and the cases that decide it read the
//! JSON. A boundary entry and a manifest line are both satisfied by a crate that is merely
//! *named*; building a value of its types is what shows the pin resolves with the features
//! this crate selects.

#[test]
fn the_generated_federation_authenticated_payload_is_reachable_from_identity() {
    assert!(size_of::<mandate_contract::events::MandateFederationFederationAuthenticated>() > 0);
}

#[test]
fn serde_is_reachable_from_this_crate_and_derives_for_a_local_type() {
    #[derive(serde::Serialize)]
    struct Declared {
        session_id: mandate_types::SessionId,
    }

    let encoded = serde_json::to_value(Declared {
        session_id: mandate_types::SessionId::new(mandate_types::Uuid::from_bytes([20; 16])),
    })
    .expect("a declared shape encodes as JSON");

    assert_eq!(
        encoded,
        serde_json::json!({"session_id": "14141414-1414-1414-1414-141414141414"})
    );
}
