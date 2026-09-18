//! Positive control for the `compile_fail` doctest at
//! `crates/mandate-token/src/lib.rs:29`.
//!
//! That doctest declares `IssuedCredential { audience: Audience, secret: CredentialSecret }`
//! and passes it to `canonical_record!`. This control is the same declaration with the
//! `secret` field type, and nothing else, changed to a type the boundary admits. Because
//! this file compiles, the doctest fails for the transient field and not for a missing
//! import, a private path or a typo.

use mandate_types::{Audience, CredentialId};
use serde::{Deserialize, Serialize};

const SAMPLE_UUID: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct IssuedCredential {
    audience: Audience,
    secret: CredentialId,
}

mandate_types::canonical_record!(
    IssuedCredential { audience, secret },
    samples: vec![IssuedCredential {
        audience: Audience::new("mandate"),
        secret: CredentialId::parse(SAMPLE_UUID).unwrap(),
    }]
);

#[test]
fn the_compile_fail_body_compiles_once_its_transient_field_type_is_changed() {
    let credential = IssuedCredential {
        audience: Audience::new("mandate"),
        secret: CredentialId::parse(SAMPLE_UUID).expect("credential"),
    };
    assert_eq!(
        serde_json::to_string(&credential).expect("encode"),
        format!("{{\"audience\":\"mandate\",\"secret\":\"{SAMPLE_UUID}\"}}")
    );
}
