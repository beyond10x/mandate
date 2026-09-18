//! The PKCE digest port, challenge well-formedness and the challenge/verifier predicate.
//!
//! The corpus cases this file underwrites are `story:oauth-integration`'s and are named
//! per test: `pkce-wrong` (`tests/security/cases.json:349`), `pkce-missing` (`:363`) and
//! `pkce-plain` (`:377`). None is owned here; what is executed is the predicate half of
//! each, with no code record consumed and no credential created.
//!
//! The presented code verifier is `mandate.core.CredentialProof`, the transient type
//! `mandate.credential.RedeemAuthorizationCode` declares for `pkce_verifier`
//! (`systems/mandate/domains/credential.yaml:205-206`), not the persisted
//! `CredentialVerifier` — which that domain's record uses for the non-reversible verifier
//! of the code itself (`:118`, `:393`). The verifiers below are synthetic markers built to
//! the declared form, never credential material: `AGENTS.md` forbids a raw credential in a
//! fixture.

use mandate_federation::DenialClause;
use mandate_federation::pkce::{
    PkceDigest, StandInDigest, challenge_is_well_formed, verifier_is_well_formed, verify_pkce,
};
use mandate_types::{CredentialProof, DenialReason, PkceChallenge, PkceMethod, REDACTED};

/// A verifier in the declared form: 43-128 characters of the unreserved set
/// (RFC 7636 section 4.1), padded to the minimum length so the form is evident.
fn verifier(name: &str) -> CredentialProof {
    let mut text = format!("mandate-test-verifier-{name}");
    while text.len() < 43 {
        text.push('~');
    }
    CredentialProof::from_bytes(text.into_bytes())
}

/// The challenge a real S256 digest would record for this verifier.
fn challenge_of(name: &str) -> PkceChallenge {
    StandInDigest.challenge(&verifier(name))
}

#[test]
fn the_matching_verifier_is_admitted_against_the_recorded_challenge() {
    let admitted = verify_pkce(
        &challenge_of("one"),
        PkceMethod::S256,
        Some(&verifier("one")),
        &StandInDigest,
    );

    assert_eq!(admitted, Ok(()));
}

/// `pkce-wrong` (`tests/security/cases.json:349`): "Wrong verifier" denies.
#[test]
fn a_wrong_verifier_is_refused() {
    let denied = verify_pkce(
        &challenge_of("one"),
        PkceMethod::S256,
        Some(&verifier("two")),
        &StandInDigest,
    )
    .expect_err("a verifier that does not digest to the recorded challenge is refused");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::VerifierMismatch);
}

/// `pkce-missing` (`tests/security/cases.json:363`): "Public client omits verifier".
#[test]
fn a_missing_verifier_is_refused() {
    let denied = verify_pkce(&challenge_of("one"), PkceMethod::S256, None, &StandInDigest)
        .expect_err("an omitted verifier is refused, never treated as a match");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::VerifierMissing);
}

/// `pkce-plain` (`tests/security/cases.json:377`): "Challenge method plain" denies as an
/// unsupported method. `mandate.core.PkceMethod` declares exactly one variant
/// (`crates/mandate-types/src/enumeration.rs:10`), so `plain` is unrepresentable: it
/// cannot be constructed, passed or folded, and the match in `verify_pkce` is exhaustive
/// without a wildcard, so a second declared method would fail to compile rather than
/// fall through to the S256 branch.
#[test]
fn plain_is_unrepresentable_because_the_contract_declares_one_method() {
    assert_eq!(PkceMethod::VARIANTS, &[PkceMethod::S256]);

    let named = match PkceMethod::S256 {
        PkceMethod::S256 => "S256",
    };
    assert_eq!(named, "S256");
}

/// "S256 challenge is absent/invalid" (`federation.yaml:299`): a challenge that is not
/// 43 characters of the base64url alphabet is refused before any verifier is read.
#[test]
fn a_challenge_outside_the_declared_form_is_refused() {
    for malformed in [
        PkceChallenge::new(""),
        PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"),
        PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM="),
        PkceChallenge::new("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"),
    ] {
        assert!(!challenge_is_well_formed(&malformed));
        let denied = verify_pkce(
            &malformed,
            PkceMethod::S256,
            Some(&verifier("one")),
            &StandInDigest,
        )
        .expect_err("a challenge outside the declared form is refused");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::ChallengeMalformed);
    }
}

/// A presented verifier outside RFC 7636's declared form is refused for its form, not
/// digested and compared: a one-character verifier that happened to collide would
/// otherwise be admitted.
#[test]
fn a_verifier_outside_the_declared_form_is_refused() {
    for malformed in [
        CredentialProof::from_bytes(Vec::new()),
        CredentialProof::from_bytes(b"too-short".to_vec()),
        CredentialProof::from_bytes(vec![b'~'; 129]),
        CredentialProof::from_bytes(format!("{}space here", "~".repeat(34)).into_bytes()),
    ] {
        assert!(!verifier_is_well_formed(&malformed));
        let denied = verify_pkce(
            &challenge_of("one"),
            PkceMethod::S256,
            Some(&malformed),
            &StandInDigest,
        )
        .expect_err("a verifier outside the declared form is refused");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::VerifierMalformed);
    }
}

#[test]
fn every_challenge_the_port_produces_is_in_the_declared_form() {
    for name in ["one", "two", "three", "four"] {
        let challenge = challenge_of(name);
        assert!(
            challenge_is_well_formed(&challenge),
            "the port answers a well-formed challenge: {challenge}"
        );
    }
}

#[test]
fn the_stand_in_digest_is_deterministic_and_separates_distinct_verifiers() {
    assert_eq!(challenge_of("one"), challenge_of("one"));
    assert_ne!(challenge_of("one"), challenge_of("two"));
}

/// A refusal names the condition that fired and carries no verifier material.
#[test]
fn a_refusal_carries_no_verifier_material() {
    let presented = verifier("secret-marker");

    let denied = verify_pkce(
        &challenge_of("one"),
        PkceMethod::S256,
        Some(&presented),
        &StandInDigest,
    )
    .expect_err("a verifier that does not match is refused");

    let rendering = format!("{denied:?} {denied}");
    assert!(
        !rendering.contains("secret-marker"),
        "a denial renders no verifier material: {rendering}"
    );
    assert!(
        format!("{presented:?}").contains(REDACTED),
        "the presented verifier itself renders redacted"
    );
}

/// A 43-character base64url string is not an S256 challenge unless it is the encoding of
/// 32 bytes. RFC 4648 section 3.5: the two pad bits of the final quantum are zero, so of
/// the 64 characters that may end one, only the 16 whose alphabet index is a multiple of
/// four leave them zero. The value below is a well-formed challenge with its last
/// character moved one place along the alphabet — still 43 characters, still base64url,
/// and now the encoding of nothing, which makes it the S256 challenge of no verifier that
/// exists.
#[test]
fn a_forty_three_character_challenge_carrying_pad_bits_is_refused_as_malformed() {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let well_formed = challenge_of("one");
    let (prefix, last) = well_formed.as_str().split_at(42);
    let index = ALPHABET
        .iter()
        .position(|entry| *entry == last.as_bytes()[0])
        .expect("the port answers base64url");

    assert!(challenge_is_well_formed(&well_formed));
    assert_eq!(
        index % 4,
        0,
        "the premise: {well_formed} decodes to 32 bytes"
    );

    for shift in 1..4_usize {
        let carrying = PkceChallenge::new(format!(
            "{prefix}{}",
            char::from(ALPHABET[(index + shift) % ALPHABET.len()])
        ));

        assert_eq!(carrying.as_str().len(), 43);
        assert!(
            !challenge_is_well_formed(&carrying),
            "a value carrying pad bits is the encoding of nothing: {carrying}"
        );

        let denied = verify_pkce(
            &carrying,
            PkceMethod::S256,
            Some(&verifier("one")),
            &StandInDigest,
        )
        .expect_err("a challenge that decodes to no digest is absent/invalid");

        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::ChallengeMalformed);
    }
}
