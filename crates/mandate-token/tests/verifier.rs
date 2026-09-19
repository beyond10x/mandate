//! The non-reversible reference verifier: what a record holds instead of a secret.
//!
//! The digest itself is the caller's — `mandate-token` has no `sha2`
//! (`dependency-boundaries.json`) — so the port is what this crate declares and the cases
//! here drive it with a digest they own. What is decided here is the part that is this
//! crate's: a verifier is derived from material and never the material, equal material
//! derives equal verifiers, and the comparison does not stop at the first differing byte.

use std::collections::BTreeSet;

use mandate_token::verifier::{
    CredentialDigest, CredentialDomain, constant_time_eq, matches, presents, presents_in,
    verifier_for, verifier_in,
};
use mandate_types::{CredentialProof, CredentialSecret, CredentialVerifier};

/// A digest this case owns: the FNV-1a of the material, rendered hexadecimal.
///
/// Not a cryptographic hash and not proposed as one — a deployment supplies SHA-256
/// through the same port. What it has to be for these cases is a *function*: equal
/// material in, equal text out, and no way to read the material back out of the text of
/// the length it produces.
struct Fnv;

impl CredentialDigest for Fnv {
    fn digest(&self, material: &[u8]) -> CredentialVerifier {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in material {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        CredentialVerifier::new(format!("{hash:016x}"))
    }
}

fn secret(material: &[u8]) -> CredentialSecret {
    CredentialSecret::from_bytes(material.to_vec())
}

fn proof(material: &[u8]) -> CredentialProof {
    CredentialProof::from_bytes(material.to_vec())
}

#[test]
fn the_verifier_a_secret_derives_carries_none_of_the_secret() {
    let material = b"the-raw-secret-returned-once";

    let verifier = verifier_for(&Fnv, &secret(material));

    assert!(
        !verifier.as_str().contains("the-raw-secret"),
        "the verifier is derived from the secret and is not a rendering of it"
    );
    assert_ne!(verifier.as_str().as_bytes(), material);
}

#[test]
fn one_secret_derives_one_verifier_and_two_secrets_derive_two() {
    assert_eq!(
        verifier_for(&Fnv, &secret(b"one")),
        verifier_for(&Fnv, &secret(b"one"))
    );
    assert_ne!(
        verifier_for(&Fnv, &secret(b"one")),
        verifier_for(&Fnv, &secret(b"two"))
    );
}

/// The two transient types are one boundary: the secret an issuance returns and the proof
/// the holder presents back carry the same material, so the verifier a record holds is
/// derived through one port for both.
#[test]
fn the_proof_a_holder_presents_derives_the_verifier_the_record_holds() {
    let recorded = verifier_for(&Fnv, &secret(b"the-raw-secret-returned-once"));

    assert!(presents(
        &Fnv,
        &recorded,
        &proof(b"the-raw-secret-returned-once")
    ));
    assert!(!presents(&Fnv, &recorded, &proof(b"another-secret")));
}

#[test]
fn a_recorded_verifier_matches_only_itself() {
    let recorded = CredentialVerifier::new("0123456789abcdef");

    assert!(matches(
        &recorded,
        &CredentialVerifier::new("0123456789abcdef")
    ));
    assert!(!matches(
        &recorded,
        &CredentialVerifier::new("0123456789abcdee")
    ));
    assert!(!matches(
        &recorded,
        &CredentialVerifier::new("0123456789abcde")
    ));
    assert!(!matches(
        &recorded,
        &CredentialVerifier::new("0123456789abcdef0")
    ));
    assert!(!matches(&recorded, &CredentialVerifier::new("")));
}

/// A comparison that returned at the first differing byte would answer sooner for a
/// presented value that shares a longer prefix with the recorded one, which is how a
/// verifier is recovered a byte at a time. The property a case can decide is the one
/// below: every difference reaches the answer, whatever its position and whatever the two
/// lengths are.
#[test]
fn every_difference_is_folded_in_whatever_its_position() {
    let recorded = [0_u8; 32];

    for index in 0..recorded.len() {
        let mut presented = recorded;
        presented[index] ^= 0x01;
        assert!(
            !constant_time_eq(&recorded, &presented),
            "a difference at byte {index} is not seen"
        );
    }
    assert!(constant_time_eq(&recorded, &[0_u8; 32]));
}

#[test]
fn a_length_difference_is_a_difference_and_no_prefix_matches() {
    assert!(!constant_time_eq(b"abcdef", b"abcde"));
    assert!(!constant_time_eq(b"abcde", b"abcdef"));
    assert!(!constant_time_eq(b"", b"a"));
    assert!(!constant_time_eq(b"a", b""));
    assert!(constant_time_eq(b"", b""));
    // A shorter value padded with the zero byte the comparison reads past the end is not
    // the longer one: the length difference alone decides it.
    assert!(!constant_time_eq(b"ab\0", b"ab"));
}

/// **One piece of material, three domains, three verifiers.**
///
/// The property the separation exists for: a value of one kind cannot resolve to a record of
/// another. A deployment holds reference secrets, self-contained tokens and
/// authorization-code verifiers in one index — `services/sts` stores the third
/// (`services/sts/src/store.rs`) — and an authorization code presented where a credential
/// proof is expected must resolve to nothing.
#[test]
fn one_material_derives_a_different_verifier_in_every_domain() {
    let material = secret(b"the-same-bytes");
    let derived: Vec<CredentialVerifier> = [
        CredentialDomain::ReferenceSecret,
        CredentialDomain::SelfContainedToken,
        CredentialDomain::AuthorizationCodeVerifier,
    ]
    .into_iter()
    .map(|domain| verifier_in(&Fnv, domain, &material))
    .collect();

    let distinct: BTreeSet<&str> = derived.iter().map(CredentialVerifier::as_str).collect();
    assert_eq!(
        distinct.len(),
        3,
        "two domains derived one verifier: {derived:?}"
    );
    // And the 2-ary form is the reference family's, which is what every reference record and
    // every case that resolves one is written against.
    assert_eq!(verifier_for(&Fnv, &material), derived[0]);
    assert!(!presents_in(
        &Fnv,
        CredentialDomain::SelfContainedToken,
        &derived[0],
        &material
    ));
}

/// The tags are distinct and carry no separator of their own, which is what makes the
/// encoding unambiguous: `tag(a) ‖ 0 ‖ x` and `tag(b) ‖ 0 ‖ y` are equal only when both
/// halves are.
#[test]
fn the_domain_tags_are_distinct_and_contain_no_separator() {
    let tags: Vec<&str> = [
        CredentialDomain::ReferenceSecret,
        CredentialDomain::SelfContainedToken,
        CredentialDomain::AuthorizationCodeVerifier,
    ]
    .into_iter()
    .map(CredentialDomain::tag)
    .collect();

    assert_eq!(tags.iter().collect::<BTreeSet<_>>().len(), 3);
    for tag in tags {
        assert!(!tag.as_bytes().contains(&0), "{tag} carries the separator");
        assert!(
            tag.starts_with("mandate.credential."),
            "{tag} is not a qualified name"
        );
    }
}

/// A prefix-free encoding, reached the way an attacker would: material chosen to look like
/// another domain's tagged input.
#[test]
fn material_shaped_like_another_domains_tagged_input_does_not_collide() {
    let token_tag = CredentialDomain::SelfContainedToken.tag();
    // A "reference secret" whose bytes are the self-contained domain's tagged input.
    let mut forged = token_tag.as_bytes().to_vec();
    forged.push(0);
    forged.extend_from_slice(b"the-token");

    assert_ne!(
        verifier_in(&Fnv, CredentialDomain::ReferenceSecret, &secret(&forged)),
        verifier_in(
            &Fnv,
            CredentialDomain::SelfContainedToken,
            &secret(b"the-token")
        )
    );
}
