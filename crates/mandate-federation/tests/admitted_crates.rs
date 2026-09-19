//! The external crates admitted to `mandate-federation` resolve, link and are usable.
//!
//! Before `story:signing-and-verification`, `dependency-boundaries.json` named no external
//! crate for this crate. A boundary entry and a manifest line are both satisfied by a crate
//! that is merely *named*: only building a value of its types shows the pin resolves and the
//! feature selection compiles. The cases here open no socket and read no file.
//!
//! The pre-landed [`mandate_federation::verifier_real`] module is checked from here too,
//! because a `pub mod` line is what lets `story:signing-and-verification`'s verifier unit
//! land without touching a crate root that belongs to another unit this wave.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, crypto};
use mandate_federation::verifier_real::JwksSource;
use mandate_types::Issuer;

#[test]
fn a_ureq_agent_is_built_from_defaults_and_sends_nothing() {
    let agent = ureq::Agent::new_with_defaults();

    // ureq 3's documented default redirect ceiling. Reading it back shows the agent is
    // fully constructed; no request is issued, so nothing leaves the process.
    assert_eq!(agent.config().max_redirects(), 10);
}

#[test]
fn a_ureq_config_is_built_through_the_admitted_major_s_own_builder() {
    // `config::Config::builder` is ureq 3's entry point. ureq 2 configured an agent through
    // `AgentBuilder`, which does not exist here, so this compiling fixes the major.
    let config = ureq::config::Config::builder().max_redirects(0).build();

    assert_eq!(config.max_redirects(), 0);
}

#[test]
fn serde_json_is_reachable_from_this_crate() {
    let jwks = serde_json::json!({ "keys": [] });

    assert_eq!(jwks["keys"].as_array().map(Vec::len), Some(0));
}

#[test]
fn rand_fills_a_buffer_the_case_owns() {
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut first);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut second);

    assert_ne!(first, second);
}

#[test]
fn the_pre_landed_jwks_source_port_is_reachable_from_outside_the_crate() {
    struct Empty;

    impl JwksSource for Empty {
        fn jwks(&self, _issuer: &Issuer) -> Option<serde_json::Value> {
            None
        }
    }

    assert!(Empty.jwks(&Issuer::new("https://idp.example")).is_none());
}

#[test]
fn the_admitted_allowlist_is_rs256_and_es256_and_holds_no_hmac() {
    let admitted = [Algorithm::RS256, Algorithm::ES256];

    assert_eq!(admitted.len(), 2);
    assert!(!admitted.contains(&Algorithm::HS256));
}

#[test]
fn a_defaulted_algorithm_is_the_one_family_the_policy_refuses() {
    // `Algorithm` derives `Default` with `HS256` as the default variant, so an allowlist that
    // was defaulted rather than deployment-configured admits exactly the shared-secret family
    // `decision-blocker:algorithm-policy` refuses. Nothing may reach the allowlist by default.
    assert_eq!(Algorithm::default(), Algorithm::HS256);
}

#[test]
fn a_validation_is_built_for_each_admitted_algorithm_and_carries_no_other() {
    let built: Vec<Vec<Algorithm>> = [Algorithm::RS256, Algorithm::ES256]
        .into_iter()
        .map(|admitted| Validation::new(admitted).algorithms)
        .collect();

    assert_eq!(built, vec![vec![Algorithm::RS256], vec![Algorithm::ES256]]);
}

#[test]
fn the_backend_carries_a_verifier_for_both_admitted_families() {
    // `Ok(false)` is "this verifier exists and refused the signature"; a family the pinned
    // backend cannot compute answers `Err` from the provider's factory instead, before any
    // signature is read. RS256 answering `Err` here is what an ES256-only build looks like,
    // and a customer IdP signing RS256 would be unverifiable behind a green suite.
    let rsa = DecodingKey::from_rsa_raw_components(&[0xC5; 256], &[0x01, 0x00, 0x01]);
    let ec = DecodingKey::from_ec_components(
        "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
        "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
    )
    .expect("well-formed EC components");

    assert_eq!(
        crypto::verify("AAAA", b"message", &rsa, Algorithm::RS256).ok(),
        Some(false)
    );
    assert_eq!(
        crypto::verify("AAAA", b"message", &ec, Algorithm::ES256).ok(),
        Some(false)
    );
}

#[test]
fn the_backend_would_verify_hs256_too_so_refusing_it_is_the_allowlist_s_work() {
    // The pinned backend carries an HMAC verifier: it answers `Ok(false)` rather than `Err`.
    // So `none` and the shared-secret family are not refused by what the build can compute,
    // and a verifier that inferred refusal from the backend would admit every one of them.
    // Refusal is the configured allowlist's, checked before a key is ever selected.
    let secret = DecodingKey::from_secret(b"not a key this system would ever hold");

    assert_eq!(
        crypto::verify("AAAA", b"message", &secret, Algorithm::HS256).ok(),
        Some(false)
    );
}
