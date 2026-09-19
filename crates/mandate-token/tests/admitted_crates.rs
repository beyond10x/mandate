//! The crates admitted to `mandate-token` resolve, link and are usable.
//!
//! `dependency-boundaries.json` named no external crate for this crate beyond `serde` and
//! `serde_json` before `story:signing-and-verification`. A manifest line alone does not show
//! a pin resolves; building a value out of the crate does.
//!
//! The pre-landed [`mandate_token::signing_real`] module is checked from here, because its
//! `pub mod` line is what lets the signing unit land without touching this crate's root.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, crypto};

#[test]
fn rand_fills_a_buffer_the_case_owns() {
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut first);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut second);

    assert_ne!(first, second);
}

#[test]
fn the_pre_landed_signing_module_is_reachable_from_outside_the_crate() {
    // The module is empty by design: `mandate-token` declares no signing port trait, and
    // this pre-land adds none. Resolving its path from another crate is the entire claim a
    // `pub mod` line makes, so the import having nothing to bind is the case, not a defect —
    // `mod signing_real;` without `pub` compiles the crate and fails right here.
    #[allow(unused_imports)]
    use mandate_token::signing_real;
}

#[test]
fn the_admitted_signing_allowlist_is_rs256_and_es256_and_holds_no_hmac() {
    let admitted = [Algorithm::RS256, Algorithm::ES256];

    assert_eq!(admitted.len(), 2);
    assert!(!admitted.contains(&Algorithm::HS256));
    // `Algorithm`'s `Default` is `HS256`, so a signer that took the default would issue under
    // the family issuance refuses. Nothing reaches the allowlist by default.
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
fn the_backend_carries_a_signer_side_verifier_for_both_admitted_families() {
    // Issuance refuses the names validation refuses, so this crate needs both admitted
    // families computable. `Ok(false)` is "the verifier exists and refused the signature";
    // a family the pinned backend cannot compute answers `Err` before any signature is read.
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
