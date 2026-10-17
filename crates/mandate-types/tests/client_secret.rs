//! The keyed client-secret verifier (fork F2 A).
//!
//! A confidential client's secret is resolved at start, turned into a
//! `mandate.core.CredentialVerifier` under a deployment key, and only the verifier is
//! recorded. These cases decide the four properties the story names: the derivation is keyed
//! and deterministic, a presented secret is compared in constant time against every active
//! verifier, a configured secret under the entropy floor is refused, and no rendering of the
//! secret or the key carries a byte of either.

use mandate_types::{
    ClientSecretError, CredentialVerifier, OAuthClientSecret, VerifierKey, client_secret_presents,
};

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef-deployment-key";
const SECRET: &[u8] = b"Zr4qL9x2Tn8vB1mK7pW3sD6fH0jG5cYeQa";

fn key() -> VerifierKey {
    VerifierKey::from_bytes(KEY.to_vec()).expect("a 32-byte key is admitted")
}

fn configured(bytes: &[u8]) -> OAuthClientSecret {
    OAuthClientSecret::configured(bytes.to_vec()).expect("the test secret clears the floor")
}

#[test]
fn derivation_is_deterministic_and_keyed() {
    let one = configured(SECRET).verifier(&key());
    let again = configured(SECRET).verifier(&key());
    assert_eq!(one, again, "equal secret and key derive one verifier");

    let other_key = VerifierKey::from_bytes(b"fedcba9876543210fedcba9876543210-other".to_vec())
        .expect("admitted");
    assert_ne!(
        one,
        configured(SECRET).verifier(&other_key),
        "the key is an input: another deployment derives another verifier"
    );
    assert!(
        one.as_str().starts_with("hmac-sha256:"),
        "the verifier names its algorithm: {}",
        one.as_str()
    );
    assert_eq!(one.as_str().len(), "hmac-sha256:".len() + 64);
}

#[test]
fn verifier_carries_no_secret_byte() {
    let verifier = configured(SECRET).verifier(&key());
    let secret = std::str::from_utf8(SECRET).expect("ascii");
    assert!(!verifier.as_str().contains(secret));
    let hex: String = SECRET.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!verifier.as_str().contains(&hex[..16]));
}

#[test]
fn presented_secret_matches_any_active_verifier() {
    let first = configured(SECRET).verifier(&key());
    let second = configured(b"Nw2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xC").verifier(&key());
    let recorded = [first, second];

    assert!(client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(SECRET.to_vec())
    ));
    assert!(client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(b"Nw2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xC".to_vec())
    ));
    assert!(!client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(b"Nw2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xD".to_vec())
    ));
    assert!(!client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(Vec::new())
    ));
    assert!(
        !client_secret_presents(&key(), &[], &OAuthClientSecret::presented(SECRET.to_vec())),
        "a client with no verifier authenticates nothing"
    );
}

#[test]
fn a_verifier_under_another_key_does_not_match() {
    let other_key = VerifierKey::from_bytes(b"fedcba9876543210fedcba9876543210-other".to_vec())
        .expect("admitted");
    let recorded = [configured(SECRET).verifier(&other_key)];
    assert!(!client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(SECRET.to_vec())
    ));
}

#[test]
fn a_foreign_verifier_form_never_matches() {
    let recorded = [CredentialVerifier::new(SECRET_AS_STR)];
    assert!(!client_secret_presents(
        &key(),
        &recorded,
        &OAuthClientSecret::presented(SECRET.to_vec())
    ));
}

const SECRET_AS_STR: &str = "Zr4qL9x2Tn8vB1mK7pW3sD6fH0jG5cYeQa";

#[test]
fn configured_secret_under_the_entropy_floor_is_refused() {
    for weak in [
        &b""[..],
        b"secret",
        b"password1234",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"abababababababababababababababababababababababab",
        b"0123456789abcdef",
    ] {
        assert!(
            matches!(
                OAuthClientSecret::configured(weak.to_vec()),
                Err(ClientSecretError::BelowEntropyFloor { .. })
            ),
            "{:?} must be refused",
            String::from_utf8_lossy(weak)
        );
    }
    // `openssl rand -base64 32` and `openssl rand -hex 32` both clear it.
    assert!(
        OAuthClientSecret::configured(b"q3Zk8vN1pR6tW0yB4mD9fH2jL7sX5cA+gE/uKoIeT0s=".to_vec())
            .is_ok()
    );
    assert!(
        OAuthClientSecret::configured(
            b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_vec()
        )
        .is_ok()
    );
}

#[test]
fn a_short_key_is_refused() {
    assert!(matches!(
        VerifierKey::from_bytes(b"too-short".to_vec()),
        Err(ClientSecretError::KeyTooShort { .. })
    ));
}

#[test]
fn debug_renders_neither_secret_nor_key() {
    let secret = configured(SECRET);
    let presented = OAuthClientSecret::presented(SECRET.to_vec());
    let key = key();
    for rendered in [
        format!("{secret:?}"),
        format!("{secret:#?}"),
        format!("{presented:?}"),
        format!("{key:?}"),
        format!("{key:#?}"),
    ] {
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains(SECRET_AS_STR), "{rendered}");
        assert!(!rendered.contains("deployment-key"), "{rendered}");
        assert!(!rendered.contains("Zr4q"), "{rendered}");
    }
    let error = OAuthClientSecret::configured(b"password1234".to_vec()).expect_err("weak");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("password1234"), "{rendered}");
}
