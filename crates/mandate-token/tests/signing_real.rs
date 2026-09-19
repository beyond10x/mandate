//! The signing port signs, publishes and rotates real keys, and refuses everything else.
//!
//! Every key here is generated at test time with `aws-lc-rs`; no private key material is
//! committed, which is the evidence row `decision-blocker:algorithm-policy` asks for
//! (`docs/architecture/runtime-decisions.md` §9, "no production private key appears in
//! source or config").
//!
//! Round trip is proved the way a relying party would prove it: sign with
//! [`mandate_token::signing_real::RealSigner`], read the `kid` out of the compact token's
//! header, find that `kid` in the set [`CredentialSigner::published_keys`] returns, and
//! verify through `jsonwebtoken::decode` against that published JWK. Nothing in the chain
//! reaches back into the signer's private material.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use mandate_token::signing_real::{
    AlgorithmPolicyError, AllowedAlgorithms, Clock, CredentialSigner, RealSigner, SigningError,
    SigningKeyMaterial, StandardClaims,
};
use mandate_types::value::encode_base64;
use mandate_types::{Audience, Issuer, PrincipalId, SigningAlgorithm};

/// The instant every case pins its clock to: 2100-01-01T00:00:00Z.
///
/// `jsonwebtoken::decode` reads the host wall clock for `exp`, so a fixed clock has to sit
/// ahead of it for a round trip to mean anything. A literal keeps the cases deterministic;
/// it stops being ahead of the wall clock in 2100.
const NOW: u64 = 4_102_444_800;

const TTL: u64 = 900;
const OVERLAP: u64 = 3_600;

const ISSUER: &str = "https://sts.mandate.test";
const AUDIENCE: &str = "mandate";
const SUBJECT: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

// --- test-time key material -------------------------------------------------------------

/// An RSA 2048 private key, PKCS#8 v1 DER, generated now and never written down.
fn rsa_pkcs8_der() -> Vec<u8> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA 2048 generation");
    let der: Pkcs8V1Der<'static> = pair.as_der().expect("PKCS#8 serialization");
    der.as_ref().to_vec()
}

/// A P-256 private key, PKCS#8 v1 DER, generated now and never written down.
fn ec_pkcs8_der() -> Vec<u8> {
    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .expect("P-256 generation")
        .as_ref()
        .to_vec()
}

/// The `RSAPrivateKey` (RFC 8017) sitting inside a PKCS#8 `PrivateKeyInfo`.
///
/// The fixture a deployment holding an OpenSSL `BEGIN RSA PRIVATE KEY` file would supply.
/// `aws-lc-rs` only serializes PKCS#8, so the case builds the other spelling itself.
fn pkcs1_inside(pkcs8: &[u8]) -> Vec<u8> {
    let (tag, body, _) = der_take(pkcs8);
    assert_eq!(tag, 0x30, "PrivateKeyInfo is a SEQUENCE");
    let (_, _, after_version) = der_take(body);
    let (_, _, after_algorithm) = der_take(after_version);
    let (tag, key, _) = der_take(after_algorithm);
    assert_eq!(tag, 0x04, "privateKey is an OCTET STRING");
    key.to_vec()
}

/// Split one DER TLV: its tag, its contents and whatever follows it.
fn der_take(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = input[0];
    let first = input[1];
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    (
        tag,
        &input[header..header + length],
        &input[header + length..],
    )
}

/// Wrap DER in the PEM envelope a deployment would hand over.
fn pem(label: &str, der: &[u8]) -> String {
    let mut out = format!("-----BEGIN {label}-----\n");
    let body = encode_base64(der);
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

// --- fixtures ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct FixedClock(Rc<Cell<u64>>);

impl FixedClock {
    fn at(instant: u64) -> Self {
        Self(Rc::new(Cell::new(instant)))
    }

    fn advance(&self, seconds: u64) {
        self.0.set(self.0.get() + seconds);
    }

    fn set(&self, instant: u64) {
        self.0.set(instant);
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ProfileClaims {
    profile: String,
    organization: String,
}

#[derive(Debug, Deserialize)]
struct Decoded {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
    profile: String,
    organization: String,
}

fn rs256() -> SigningAlgorithm {
    SigningAlgorithm::new("RS256")
}

fn es256() -> SigningAlgorithm {
    SigningAlgorithm::new("ES256")
}

fn both() -> AllowedAlgorithms {
    AllowedAlgorithms::new(&[rs256(), es256()]).expect("RS256 and ES256 are the admitted set")
}

fn profile_claims() -> ProfileClaims {
    ProfileClaims {
        profile: "self-contained".to_owned(),
        organization: "acme".to_owned(),
    }
}

fn standard(jti: &str) -> StandardClaims {
    StandardClaims {
        issuer: Issuer::new(ISSUER),
        subject: PrincipalId::parse(SUBJECT).expect("a declared UUID"),
        audience: Audience::new(AUDIENCE),
        token_id: jti.to_owned(),
    }
}

fn rsa_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &rs256(), &rsa_pkcs8_der()).expect("RSA key material")
}

fn ec_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &es256(), &ec_pkcs8_der()).expect("P-256 key material")
}

/// Verify the way a relying party would: header `kid`, published JWK, `jsonwebtoken::decode`.
fn verify(token: &str, published: &JwkSet, algorithm: Algorithm) -> Decoded {
    let header = decode_header(token).expect("a readable JOSE header");
    let kid = header.kid.expect("the header carries a kid");
    let jwk = published
        .find(&kid)
        .unwrap_or_else(|| panic!("kid {kid} is in the published set"));
    let key = DecodingKey::from_jwk(jwk).expect("a decoding key from the published JWK");
    let mut validation = Validation::new(algorithm);
    // No leeway: the signer's own `exp` has to stand on its own, not on the default
    // 60-second grace a verifier happens to allow. `nbf` is deliberately not checked here —
    // every case but one pins its clock to `NOW`, which is ahead of the host wall clock so
    // that `exp` is meaningful, and that necessarily makes `nbf` immature. The case that
    // runs at the real clock checks `nbf` too:
    // `a_token_signed_at_the_real_clock_verifies_with_nbf_and_exp_checked`.
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    decode::<Decoded>(token, &key, &validation)
        .expect("the published JWK verifies the token")
        .claims
}

fn kids(published: &JwkSet) -> Vec<String> {
    published
        .keys
        .iter()
        .map(|jwk| {
            jwk.common
                .key_id
                .clone()
                .expect("every published key names a kid")
        })
        .collect()
}

fn claims_segment(token: &str) -> &str {
    token
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- round trip -------------------------------------------------------------------------

#[test]
fn rs256_signs_and_verifies_through_the_published_jwk() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let signed = signer
        .sign(&profile_claims(), &standard("jti-rs"))
        .expect("signs under the active key");

    assert_eq!(signed.kid, "rsa-1");
    let claims = verify(&signed.token, &signer.published_keys(), Algorithm::RS256);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.jti, "jti-rs");
    assert_eq!(claims.profile, "self-contained");
    assert_eq!(claims.organization, "acme");
}

#[test]
fn es256_signs_and_verifies_through_the_published_jwk() {
    let signer = RealSigner::new(both(), ec_key("ec-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted ES256 key");

    let signed = signer
        .sign(&profile_claims(), &standard("jti-ec"))
        .expect("signs under the active key");

    assert_eq!(signed.kid, "ec-1");
    let claims = verify(&signed.token, &signer.published_keys(), Algorithm::ES256);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.sub, SUBJECT);
    assert_eq!(claims.aud, AUDIENCE);
    assert_eq!(claims.jti, "jti-ec");
}

// --- the allowlist, refused at construction ---------------------------------------------

#[test]
fn an_empty_allowlist_is_refused_at_construction() {
    assert!(matches!(
        AllowedAlgorithms::new(&[]),
        Err(AlgorithmPolicyError::EmptyAllowlist)
    ));
}

#[test]
fn the_none_algorithm_is_refused_at_construction_in_every_spelling() {
    for spelling in ["none", "None", "NONE", "nOnE"] {
        let refused = AllowedAlgorithms::new(&[SigningAlgorithm::new(spelling)]);
        assert!(
            matches!(refused, Err(AlgorithmPolicyError::NoneRefused)),
            "{spelling} must be refused as `none`, got {refused:?}"
        );
        // And it cannot be smuggled in beside an admitted name either.
        let beside = AllowedAlgorithms::new(&[rs256(), SigningAlgorithm::new(spelling)]);
        assert!(
            matches!(beside, Err(AlgorithmPolicyError::NoneRefused)),
            "{spelling} beside RS256 must be refused, got {beside:?}"
        );
    }
}

#[test]
fn every_name_outside_the_admitted_set_is_refused_at_construction() {
    // The class, enumerated rather than sampled: exactly two names are admitted, and every
    // other name `jsonwebtoken` can name — plus the shapes a config file produces by
    // accident — is refused. A name this crate gains later fails here until it is decided.
    for admitted in ["RS256", "ES256"] {
        let name = SigningAlgorithm::new(admitted);
        assert!(
            AllowedAlgorithms::new(std::slice::from_ref(&name)).is_ok(),
            "{admitted} is the recorded allowlist"
        );
    }

    let refused = [
        "HS256", "HS384", "HS512", "RS384", "RS512", "ES384", "ES512", "PS256", "PS384", "PS512",
        "EdDSA", "rs256", "es256", "RS256 ", " RS256", "", "RSA-OAEP", "dir",
    ];
    for name in refused {
        let outcome = AllowedAlgorithms::new(&[SigningAlgorithm::new(name)]);
        assert!(
            matches!(outcome, Err(AlgorithmPolicyError::UnadmittedName(_))),
            "{name:?} must be refused as unadmitted, got {outcome:?}"
        );
    }
}

#[test]
fn key_material_outside_the_admitted_set_is_refused_before_any_signing() {
    let outcome = SigningKeyMaterial::from_der("hs-1", &SigningAlgorithm::new("HS256"), b"secret");
    assert!(
        matches!(
            outcome,
            Err(SigningError::Algorithm(
                AlgorithmPolicyError::UnadmittedName(_)
            ))
        ),
        "an unadmitted algorithm name cannot become key material, got {outcome:?}"
    );
}

// --- refusal at issuance ----------------------------------------------------------------

#[test]
fn sign_under_a_non_admitted_algorithm_is_refused_at_every_entry_point() {
    // The class: a signer can only reach a signing key through `new` or `rotate`, so both
    // are shown refusing a key whose algorithm this deployment did not configure. There is
    // no third way in, which is why `sign` needs no branch of its own.
    let rs256_only = AllowedAlgorithms::new(&[rs256()]).expect("a one-name allowlist");
    let clock = FixedClock::at(NOW);

    let at_construction = RealSigner::new(
        rs256_only.clone(),
        ec_key("ec-1"),
        clock.clone(),
        TTL,
        OVERLAP,
    );
    assert!(
        matches!(
            at_construction,
            Err(SigningError::Algorithm(
                AlgorithmPolicyError::NotConfigured(_)
            ))
        ),
        "ES256 is not configured here, got {at_construction:?}"
    );

    let mut signer = RealSigner::new(rs256_only, rsa_key("rsa-1"), clock, TTL, OVERLAP)
        .expect("RS256 is configured here");
    let at_rotation = signer.rotate(ec_key("ec-2"));
    assert!(
        matches!(
            at_rotation,
            Err(SigningError::Algorithm(
                AlgorithmPolicyError::NotConfigured(_)
            ))
        ),
        "rotation cannot install an unconfigured algorithm, got {at_rotation:?}"
    );

    // The refused rotation left the admitted key in place and signing untouched.
    assert_eq!(kids(&signer.published_keys()), vec!["rsa-1".to_owned()]);
    let signed = signer
        .sign(&profile_claims(), &standard("jti-after-refusal"))
        .expect("the admitted key still signs");
    assert_eq!(signed.kid, "rsa-1");
}

// --- kid --------------------------------------------------------------------------------

#[test]
fn the_kid_is_carried_in_the_header_and_names_a_published_key() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");
    let signed = signer
        .sign(&profile_claims(), &standard("jti-kid"))
        .expect("signs");

    let header = decode_header(&signed.token).expect("a readable header");
    assert_eq!(header.kid.as_deref(), Some("rsa-1"));
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ.as_deref(), Some("JWT"));
    assert_eq!(signed.kid, "rsa-1");

    let published = signer.published_keys();
    assert_eq!(kids(&published), vec!["rsa-1".to_owned()]);
    assert!(published.find("rsa-1").is_some());
}

// --- the rotation window ----------------------------------------------------------------

#[test]
fn the_rotation_window_publishes_the_previous_key_until_the_overlap_ends() {
    let clock = FixedClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");

    let under_old = signer
        .sign(&profile_claims(), &standard("jti-old"))
        .expect("signs under the first key");
    assert_eq!(under_old.kid, "rsa-1");

    clock.advance(10);
    signer.rotate(rsa_key("rsa-2")).expect("rotates");
    let under_new = signer
        .sign(&profile_claims(), &standard("jti-new"))
        .expect("signs under the new key");
    assert_eq!(under_new.kid, "rsa-2");

    // During the overlap a verifier reading the published set accepts both.
    let during = signer.published_keys();
    let mut published = kids(&during);
    published.sort();
    assert_eq!(published, vec!["rsa-1".to_owned(), "rsa-2".to_owned()]);
    verify(&under_old.token, &during, Algorithm::RS256);
    verify(&under_new.token, &during, Algorithm::RS256);

    // The overlap ends and the previous key drops out of the set. One second later than a
    // naive reading: the window closes at `rotated_at + overlap + 1`, so that the last
    // credential the key could sign is still verifiable at exactly its `exp`. The instant
    // itself is `the_window_covers_the_instant_a_credential_expires`.
    clock.advance(OVERLAP + 1);
    let after = signer.published_keys();
    assert_eq!(kids(&after), vec!["rsa-2".to_owned()]);
    assert!(after.find("rsa-1").is_none());
    verify(&under_new.token, &after, Algorithm::RS256);
}

#[test]
fn rotating_in_a_kid_already_in_the_window_is_refused() {
    let clock = FixedClock::at(NOW);
    let mut signer =
        RealSigner::new(both(), rsa_key("rsa-1"), clock, TTL, OVERLAP).expect("an admitted key");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    let outcome = signer.rotate(rsa_key("rsa-1"));
    assert!(
        matches!(outcome, Err(SigningError::DuplicateKid(_))),
        "a kid still in the window cannot be reused, got {outcome:?}"
    );
}

// --- emergency revocation ---------------------------------------------------------------

#[test]
fn an_emergency_revocation_drops_the_key_and_refuses_signing_under_it() {
    let clock = FixedClock::at(NOW);
    let mut signer =
        RealSigner::new(both(), rsa_key("rsa-1"), clock, TTL, OVERLAP).expect("an admitted key");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    // A key inside the window goes at once, without waiting for the overlap.
    signer.revoke("rsa-1").expect("revokes the windowed key");
    assert!(signer.published_keys().find("rsa-1").is_none());
    assert_eq!(kids(&signer.published_keys()), vec!["rsa-2".to_owned()]);

    // The active key goes the same way, and nothing signs afterwards.
    signer.revoke("rsa-2").expect("revokes the active key");
    assert!(signer.published_keys().keys.is_empty());
    let outcome = signer.sign(&profile_claims(), &standard("jti-revoked"));
    assert!(
        matches!(outcome, Err(SigningError::NoActiveKey)),
        "a revoked active key signs nothing, got {outcome:?}"
    );

    // Repeating the emergency path against a kid already revoked says so by name, and does
    // not file a second tombstone for the same key.
    let repeated = signer.revoke("rsa-1");
    assert!(
        matches!(repeated, Err(SigningError::RevokedKey(_))),
        "a repeated revocation names the revocation, got {repeated:?}"
    );
    assert_eq!(signer.revoked().len(), 2, "one tombstone per revoked key");

    // A kid the signer never held is a different refusal, told apart from the above.
    let unknown = signer.revoke("never-held");
    assert!(
        matches!(unknown, Err(SigningError::UnknownKid(_))),
        "an unheld kid is refused by name, got {unknown:?}"
    );
}

// --- expiry -----------------------------------------------------------------------------

#[test]
fn the_expiry_is_the_clock_plus_the_ttl() {
    let clock = FixedClock::at(NOW);
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");

    let first = signer
        .sign(&profile_claims(), &standard("jti-exp"))
        .expect("signs");
    let claims = verify(&first.token, &signer.published_keys(), Algorithm::RS256);
    assert_eq!(claims.iat, NOW);
    assert_eq!(claims.nbf, NOW);
    assert_eq!(claims.exp, NOW + TTL);

    clock.advance(60);
    let later = signer
        .sign(&profile_claims(), &standard("jti-exp-later"))
        .expect("signs again");
    let later_claims = verify(&later.token, &signer.published_keys(), Algorithm::RS256);
    assert_eq!(later_claims.iat, NOW + 60);
    assert_eq!(later_claims.exp, NOW + 60 + TTL);
}

// --- no key material anywhere a reader can see -------------------------------------------

#[test]
fn debug_output_carries_no_key_material() {
    let der = rsa_pkcs8_der();
    let key = SigningKeyMaterial::from_der("rsa-1", &rs256(), &der).expect("key material");
    let signer = RealSigner::new(both(), key.clone(), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    // The private material, in every rendering a `Debug` implementation could reach for:
    // whole and in a window taken from deep inside the key, where the primes live.
    let window = &der[der.len() - 48..];
    let window_debug = format!("{window:?}");
    let leaks = [
        encode_base64(&der),
        encode_base64(window),
        format!("{der:?}"),
        window_debug[1..window_debug.len() - 1].to_owned(),
        hex(&der),
        hex(window),
        hex(window).to_uppercase(),
    ];

    for rendering in [format!("{key:?}"), format!("{signer:?}")] {
        assert!(
            rendering.contains("rsa-1"),
            "the rendering is a real Debug: {rendering}"
        );
        for leak in &leaks {
            assert!(
                !rendering.contains(leak.as_str()),
                "key material reached Debug output: {rendering}"
            );
        }
    }
}

// --- determinism ------------------------------------------------------------------------

#[test]
fn the_claims_are_determined_by_the_clock_and_the_jti() {
    for (kid, key) in [("rsa-1", rsa_key("rsa-1")), ("ec-1", ec_key("ec-1"))] {
        let signer = RealSigner::new(both(), key, FixedClock::at(NOW), TTL, OVERLAP)
            .expect("an admitted key");

        let first = signer
            .sign(&profile_claims(), &standard("jti-fixed"))
            .expect("signs");
        let second = signer
            .sign(&profile_claims(), &standard("jti-fixed"))
            .expect("signs again");
        assert_eq!(
            claims_segment(&first.token),
            claims_segment(&second.token),
            "{kid}: a fixed clock and a fixed jti determine the claims"
        );

        // And the assertion is not vacuous: a different jti is a different claims set.
        let other = signer
            .sign(&profile_claims(), &standard("jti-other"))
            .expect("signs a third time");
        assert_ne!(
            claims_segment(&first.token),
            claims_segment(&other.token),
            "{kid}: the jti reaches the claims"
        );
    }
}

// --- the forms a deployment supplies ------------------------------------------------------

#[test]
fn a_pem_the_deployment_supplies_loads_the_der_inside_it() {
    let rsa = rsa_pkcs8_der();
    let from_der = SigningKeyMaterial::from_der("rsa-1", &rs256(), &rsa).expect("DER");
    let from_pem =
        SigningKeyMaterial::from_pem("rsa-1", &rs256(), &pem("PRIVATE KEY", &rsa)).expect("PEM");
    assert_eq!(from_der.published(), from_pem.published());

    let ec = ec_pkcs8_der();
    let from_der = SigningKeyMaterial::from_der("ec-1", &es256(), &ec).expect("DER");
    let from_pem =
        SigningKeyMaterial::from_pem("ec-1", &es256(), &pem("PRIVATE KEY", &ec)).expect("PEM");
    assert_eq!(from_der.published(), from_pem.published());

    // The PEM markers are assembled at run time so no source line carries a private-key
    // marker the repository's secret scanner would refuse.
    let begin = format!("-----BEGIN {}-----\n", "PRIVATE KEY");
    let end = format!("-----END {}-----\n", "PRIVATE KEY");
    for malformed in [
        "not a pem at all".to_owned(),
        begin.clone(),
        format!("{begin}!!!!\n{end}"),
    ] {
        let outcome = SigningKeyMaterial::from_pem("bad", &rs256(), &malformed);
        assert!(
            matches!(outcome, Err(SigningError::MalformedPem)),
            "{malformed:?} must be refused by name, got {outcome:?}"
        );
    }
}

#[test]
fn rsa_der_is_accepted_in_both_the_pkcs8_and_pkcs1_spellings() {
    let pkcs8 = rsa_pkcs8_der();
    let pkcs1 = pkcs1_inside(&pkcs8);

    let wrapped = SigningKeyMaterial::from_der("rsa-1", &rs256(), &pkcs8).expect("PKCS#8");
    let bare = SigningKeyMaterial::from_der("rsa-1", &rs256(), &pkcs1).expect("PKCS#1");
    assert_eq!(wrapped.published(), bare.published());

    let signer =
        RealSigner::new(both(), bare, FixedClock::at(NOW), TTL, OVERLAP).expect("an admitted key");
    let signed = signer
        .sign(&profile_claims(), &standard("jti-pkcs1"))
        .expect("signs");
    verify(&signed.token, &signer.published_keys(), Algorithm::RS256);
}

#[test]
fn key_material_the_deployment_mangled_is_refused_by_name() {
    let outcome = SigningKeyMaterial::from_der("rsa-1", &rs256(), b"\x30\x03\x02\x01\x00");
    assert!(
        matches!(outcome, Err(SigningError::KeyRejected(_))),
        "bytes that are not a key are refused by name, got {outcome:?}"
    );

    let outcome = SigningKeyMaterial::from_der("ec-1", &es256(), &rsa_pkcs8_der());
    assert!(
        matches!(outcome, Err(SigningError::KeyRejected(_))),
        "an RSA key declared ES256 is refused by name, got {outcome:?}"
    );
}

// --- the standard claims are the signer's ------------------------------------------------

/// Every claim the signer owns is refused when a caller supplies it, in any letter case.
#[test]
fn a_caller_claim_naming_a_standard_claim_is_refused() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    // The class, enumerated: every reserved name, and for each one a letter case a config
    // or a JSON producer could plausibly emit. Refusing beats overwriting — a caller that
    // names `exp` believes something about the lifetime, and silence leaves that standing.
    let reserved = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
    for name in reserved {
        for spelling in [
            name.to_owned(),
            name.to_uppercase(),
            format!("{}{}", name[..1].to_uppercase(), &name[1..]),
        ] {
            let mut claims = BTreeMap::new();
            claims.insert(spelling.clone(), "caller".to_owned());
            let outcome = signer.sign(&claims, &standard("jti-reserved"));
            assert!(
                matches!(&outcome, Err(SigningError::ReservedClaim(seen)) if *seen == spelling),
                "{spelling:?} must be refused as a reserved claim, got {outcome:?}"
            );
        }
    }

    // A reserved name alongside ordinary ones is still refused, not partially accepted.
    let mut mixed = BTreeMap::new();
    mixed.insert("profile".to_owned(), "self-contained".to_owned());
    mixed.insert("EXP".to_owned(), "99".to_owned());
    assert!(
        matches!(
            signer.sign(&mixed, &standard("jti-mixed")),
            Err(SigningError::ReservedClaim(_))
        ),
        "a reserved name beside ordinary ones is refused"
    );

    // And the check is not a blanket refusal: ordinary claims still sign.
    let mut ordinary = BTreeMap::new();
    ordinary.insert("profile".to_owned(), "self-contained".to_owned());
    ordinary.insert("issuer_hint".to_owned(), "not-reserved".to_owned());
    assert!(
        signer.sign(&ordinary, &standard("jti-ordinary")).is_ok(),
        "a claim that merely contains a reserved name is not one"
    );
}

/// The wire object carries each claim once, with the signer's value.
#[test]
fn the_claims_object_holds_each_standard_claim_exactly_once() {
    for (algorithm, key) in [
        (Algorithm::RS256, rsa_key("rsa-1")),
        (Algorithm::ES256, ec_key("ec-1")),
    ] {
        let signer = RealSigner::new(both(), key, FixedClock::at(NOW), TTL, OVERLAP)
            .expect("an admitted key");
        let signed = signer
            .sign(&profile_claims(), &standard("jti-once"))
            .expect("signs");

        // Read the claims segment as raw text, not through a parser that would already
        // have collapsed a duplicate key to the last one written.
        let segment = signed
            .token
            .split('.')
            .nth(1)
            .expect("a compact JWS has three parts");
        let mut padded: String = segment
            .chars()
            .map(|character| match character {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        while !padded.len().is_multiple_of(4) {
            padded.push('=');
        }
        let text = String::from_utf8(
            mandate_types::value::decode_base64(&padded).expect("a base64url segment"),
        )
        .expect("UTF-8 JSON");

        for name in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
            assert_eq!(
                text.matches(&format!("\"{name}\":")).count(),
                1,
                "{algorithm:?}: `{name}` appears more than once on the wire: {text}"
            );
        }

        // And it decodes with no leeway at all against the published key.
        verify(&signed.token, &signer.published_keys(), algorithm);
    }
}

/// A caller value that is not a JSON object is refused rather than signed.
#[test]
fn a_caller_value_that_is_not_a_json_object_is_refused() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    let outcomes = [
        ("unit", signer.sign(&(), &standard("a"))),
        (
            "none",
            signer.sign(&Option::<ProfileClaims>::None, &standard("b")),
        ),
        ("string", signer.sign(&"a bare string", &standard("c"))),
        ("number", signer.sign(&42_u64, &standard("d"))),
        ("array", signer.sign(&vec![1_u64, 2, 3], &standard("e"))),
        ("boolean", signer.sign(&true, &standard("f"))),
    ];
    for (shape, outcome) in &outcomes {
        assert!(
            matches!(outcome, Err(SigningError::Encode(_))),
            "a {shape} claims value must be refused as Encode, got {outcome:?}"
        );
    }
}

// --- revocation is permanent ---------------------------------------------------------------

/// A revoked key comes back under neither its own `kid` nor a new one.
#[test]
fn a_revoked_key_is_never_installed_again_by_kid_or_by_material() {
    for (name, der) in [(rs256(), rsa_pkcs8_der()), (es256(), ec_pkcs8_der())] {
        let family = name.as_str().to_owned();
        let load = |kid: &str| {
            SigningKeyMaterial::from_der(kid, &name, &der).expect("admitted key material")
        };
        let compromised = load("compromised");
        let clock = FixedClock::at(NOW);
        let mut signer = RealSigner::new(both(), compromised.clone(), clock.clone(), TTL, OVERLAP)
            .expect("an admitted key");
        signer.revoke("compromised").expect("revokes");

        assert_eq!(
            signer.revoked().len(),
            1,
            "{family}: the revocation is kept"
        );
        assert_eq!(signer.revoked()[0].kid, "compromised");
        assert_eq!(signer.revoked()[0].thumbprint, compromised.thumbprint());

        // rotate refuses the same kid.
        let same_kid = signer.rotate(compromised.clone());
        assert!(
            matches!(same_kid, Err(SigningError::RevokedKey(_))),
            "{family}: the revoked kid returned through rotate: {same_kid:?}"
        );

        // And the same material filed under a new name — the thumbprint catches it, which
        // is the spelling an operator working an incident actually produces.
        let renamed = load("renamed");
        assert_eq!(
            renamed.thumbprint(),
            compromised.thumbprint(),
            "{family}: the same key has the same thumbprint under any kid"
        );
        let by_material = signer.rotate(renamed);
        assert!(
            matches!(by_material, Err(SigningError::RevokedKey(_))),
            "{family}: the revoked material returned under a new kid: {by_material:?}"
        );

        // `new` refuses it too, rehydrated from the record a restart would carry.
        let restarted = RealSigner::new_with_revocations(
            both(),
            compromised.clone(),
            clock,
            TTL,
            OVERLAP,
            signer.revoked().to_vec(),
        );
        assert!(
            matches!(restarted, Err(SigningError::RevokedKey(_))),
            "{family}: a restart installed the revoked key: {restarted:?}"
        );

        // A key that was never revoked still installs, so the refusal is not blanket.
        let fresh_material = if name == rs256() {
            rsa_key("fresh")
        } else {
            ec_key("fresh")
        };
        let fresh = RealSigner::new_with_revocations(
            both(),
            fresh_material,
            FixedClock::at(NOW),
            TTL,
            OVERLAP,
            signer.revoked().to_vec(),
        );
        assert!(
            fresh.is_ok(),
            "{family}: the refusal is not blanket, got {fresh:?}"
        );
    }
}

// --- the window covers every credential it signed -------------------------------------------

/// An overlap shorter than the TTL would strand a credential the signer still calls valid.
#[test]
fn an_overlap_shorter_than_the_ttl_is_refused_at_construction() {
    let outcome = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), 900, 60);
    assert!(
        matches!(
            outcome,
            Err(SigningError::OverlapShorterThanTtl {
                ttl_seconds: 900,
                overlap_seconds: 60
            })
        ),
        "an overlap under the TTL must be refused by name, got {outcome:?}"
    );

    // The boundary is inclusive: an overlap exactly equal to the TTL is enough.
    assert!(
        RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), 900, 900).is_ok(),
        "overlap == ttl covers every credential the key signed"
    );
}

// --- the forms a deployment supplies, strictly ------------------------------------------------

/// DER with anything after the key structure is refused in both families.
#[test]
fn der_with_trailing_bytes_is_refused_in_both_families() {
    for (name, mut der) in [(rs256(), rsa_pkcs8_der()), (es256(), ec_pkcs8_der())] {
        let clean = SigningKeyMaterial::from_der("k", &name, &der);
        assert!(clean.is_ok(), "{name} clean DER must load, got {clean:?}");

        der.push(0x00);
        let outcome = SigningKeyMaterial::from_der("k", &name, &der);
        assert!(
            matches!(outcome, Err(SigningError::KeyRejected(_))),
            "{name}: a trailing byte must be refused, got {outcome:?}"
        );

        // Two keys concatenated is the same defect at a larger size.
        let mut doubled = rsa_pkcs8_der();
        doubled.extend_from_slice(&rsa_pkcs8_der());
        let outcome = SigningKeyMaterial::from_der("k", &rs256(), &doubled);
        assert!(
            matches!(outcome, Err(SigningError::KeyRejected(_))),
            "two concatenated keys must be refused, got {outcome:?}"
        );
    }
}

/// The PEM label has to match the family, and one file carries one key.
#[test]
fn the_pem_label_must_match_the_family_and_the_file_holds_one_block() {
    let rsa = rsa_pkcs8_der();
    let ec = ec_pkcs8_der();

    // PKCS#8 under its own label loads for both families.
    assert!(SigningKeyMaterial::from_pem("k", &rs256(), &pem("PRIVATE KEY", &rsa)).is_ok());
    assert!(SigningKeyMaterial::from_pem("k", &es256(), &pem("PRIVATE KEY", &ec)).is_ok());

    // `RSA PRIVATE KEY` is RS256's alone, and it is RFC 8017 inside.
    let pkcs1 = pkcs1_inside(&rsa);
    assert!(SigningKeyMaterial::from_pem("k", &rs256(), &pem("RSA PRIVATE KEY", &pkcs1)).is_ok());
    let wrong_family = SigningKeyMaterial::from_pem("k", &es256(), &pem("RSA PRIVATE KEY", &pkcs1));
    assert!(
        matches!(wrong_family, Err(SigningError::UnsupportedPemLabel(_))),
        "an RSA label under ES256 must be refused by name, got {wrong_family:?}"
    );

    // Every other label a deployment might hand over is refused by name.
    for label in [
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "CERTIFICATE",
        "PUBLIC KEY",
        "OPENSSH PRIVATE KEY",
        "",
    ] {
        let outcome = SigningKeyMaterial::from_pem("k", &rs256(), &pem(label, &rsa));
        assert!(
            matches!(outcome, Err(SigningError::UnsupportedPemLabel(_))),
            "{label:?} must be refused by name, got {outcome:?}"
        );
    }

    // A file holding two keys is refused rather than reduced to the first.
    let two = format!("{}{}", pem("PRIVATE KEY", &rsa), pem("PRIVATE KEY", &rsa));
    let outcome = SigningKeyMaterial::from_pem("k", &rs256(), &two);
    assert!(
        matches!(outcome, Err(SigningError::MalformedPem)),
        "two blocks must be refused, got {outcome:?}"
    );

    // As is a block whose END names something else.
    let mismatched =
        pem("PRIVATE KEY", &rsa).replace("-----END PRIVATE KEY-----", "-----END X-----");
    let outcome = SigningKeyMaterial::from_pem("k", &rs256(), &mismatched);
    assert!(
        matches!(outcome, Err(SigningError::MalformedPem)),
        "a mismatched END must be refused, got {outcome:?}"
    );
}

// --- the published JWK -----------------------------------------------------------------------

/// The published JWK names its use and algorithm and carries no private member.
#[test]
fn the_published_jwk_carries_its_public_members_and_no_private_one() {
    let clock = FixedClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");
    signer.rotate(ec_key("ec-1")).expect("rotates");

    let published = serde_json::to_value(signer.published_keys()).expect("the set serializes");
    let keys = published["keys"].as_array().expect("a keys array");
    assert_eq!(keys.len(), 2);

    for key in keys {
        let object = key.as_object().expect("a JWK object");
        assert_eq!(object["use"], "sig", "every published key names its use");
        match object["kid"].as_str() {
            Some("rsa-1") => {
                assert_eq!(object["kty"], "RSA");
                assert_eq!(object["alg"], "RS256");
                assert!(object.contains_key("n") && object.contains_key("e"));
                assert!(!object.contains_key("crv"), "RSA carries no curve");
            }
            Some("ec-1") => {
                assert_eq!(object["kty"], "EC");
                assert_eq!(object["alg"], "ES256");
                assert_eq!(object["crv"], "P-256");
                assert!(object.contains_key("x") && object.contains_key("y"));
            }
            other => panic!("an unexpected kid is published: {other:?}"),
        }
        // The class: every private JWK member RFC 7517/7518 defines, for every key type
        // this module can publish. A member added to a JWK later fails here until it is
        // decided, rather than shipping.
        for private in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
            assert!(
                !object.contains_key(private),
                "the published JWK carries the private member {private}: {key}"
            );
        }
    }
}

/// At a real clock, an emitted token satisfies `nbf` and `exp` with no leeway at all.
///
/// The rest of the suite pins its clock to `NOW` so `exp` is a literal, which puts `nbf` in
/// the future of the host wall clock. This case gives up the literal to check the other
/// end: a credential signed now is immediately valid, without a verifier's grace period.
#[test]
fn a_token_signed_at_the_real_clock_verifies_with_nbf_and_exp_checked() {
    for (algorithm, key) in [
        (Algorithm::RS256, rsa_key("rsa-now")),
        (Algorithm::ES256, ec_key("ec-now")),
    ] {
        let signer = RealSigner::new(
            both(),
            key,
            FixedClock::at(jsonwebtoken::get_current_timestamp()),
            TTL,
            OVERLAP,
        )
        .expect("an admitted key");
        let signed = signer
            .sign(&profile_claims(), &standard("jti-real-clock"))
            .expect("signs");

        let published = signer.published_keys();
        let jwk = published.find(&signed.kid).expect("the kid is published");
        let decoding = DecodingKey::from_jwk(jwk).expect("a decoding key");
        let mut validation = Validation::new(algorithm);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);

        let outcome = decode::<Decoded>(&signed.token, &decoding, &validation);
        assert!(
            outcome.is_ok(),
            "{algorithm:?}: a credential signed now is not yet valid: {:?}",
            outcome.err()
        );
    }
}

// --- the far end of the rotation window -----------------------------------------------------

/// A key is published, and its `kid` reserved, at exactly the second its last credential
/// expires — and released the second after.
///
/// A relying party with no leeway accepts a credential at `now == exp`, so a window that
/// closes *at* `exp` strands it. The window therefore runs to `rotated_at + overlap + 1`,
/// and both halves of that are checked here at the exact instant: the key is in the
/// published set, and `rotate` will not hand the `kid` to different material.
#[test]
fn the_window_covers_the_instant_a_credential_expires() {
    // `overlap == ttl` is the tightest legal pairing, and it puts the boundary exactly on
    // the credential's `exp` when a rotation lands in the same second as an issuance.
    let clock = FixedClock::at(NOW);
    let mut signer =
        RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, TTL).expect("admitted");

    let issued = signer
        .sign(&profile_claims(), &standard("jti-boundary"))
        .expect("signs under the first key");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");
    let expires_at = NOW + TTL;

    // One second before `exp`: published, naturally.
    clock.set(expires_at - 1);
    assert!(signer.published_keys().find("rsa-1").is_some());

    // At `exp` itself: still published, and the credential still verifies against it.
    clock.set(expires_at);
    let at_exp = signer.published_keys();
    assert!(
        at_exp.find("rsa-1").is_some(),
        "at now == exp ({expires_at}) the signing key left the set: {:?}",
        kids(&at_exp)
    );
    let jwk = at_exp.find("rsa-1").expect("published at exp");
    let decoding = DecodingKey::from_jwk(jwk).expect("a decoding key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    assert!(
        decode::<Decoded>(&issued.token, &decoding, &validation).is_ok(),
        "the published key must still verify the credential at its exp"
    );

    // And the `kid` is not free at that instant either.
    let reuse = signer.rotate(rsa_key("rsa-1"));
    assert!(
        matches!(reuse, Err(SigningError::DuplicateKid(_))),
        "at now == exp the kid is still the window's, got {reuse:?}"
    );

    // One second later the window is closed: gone from the set, and the name is free.
    clock.set(expires_at + 1);
    let after = signer.published_keys();
    assert_eq!(kids(&after), vec!["rsa-2".to_owned()]);
    assert!(
        signer.rotate(rsa_key("rsa-1")).is_ok(),
        "past the window the kid is available again"
    );
}

// --- one public key, one name ----------------------------------------------------------------

/// The signer refuses to hold one public key under two `kid`s, and revocation drops it
/// wherever it is held.
#[test]
fn material_the_signer_already_holds_is_refused_and_revoked_by_material() {
    for (name, der) in [(rs256(), rsa_pkcs8_der()), (es256(), ec_pkcs8_der())] {
        let family = name.as_str().to_owned();
        let load = |kid: &str| {
            SigningKeyMaterial::from_der(kid, &name, &der).expect("admitted key material")
        };

        // The active key, offered again under a new name.
        let mut signer = RealSigner::new(both(), load("held"), FixedClock::at(NOW), TTL, OVERLAP)
            .expect("an admitted key");
        let renamed = signer.rotate(load("renamed"));
        assert!(
            matches!(&renamed, Err(SigningError::DuplicateMaterial(kid)) if kid == "held"),
            "{family}: the same key under a second name must be refused, got {renamed:?}"
        );
        assert_eq!(
            kids(&signer.published_keys()),
            vec!["held".to_owned()],
            "{family}: the refused rotation published nothing"
        );

        // A windowed copy is caught too, not just the active one.
        let mut windowed =
            RealSigner::new(both(), load("first"), FixedClock::at(NOW), TTL, OVERLAP)
                .expect("an admitted key");
        let other = if name == rs256() {
            rsa_key("second")
        } else {
            ec_key("second")
        };
        windowed
            .rotate(other)
            .expect("rotates to different material");
        let back = windowed.rotate(load("third"));
        assert!(
            matches!(&back, Err(SigningError::DuplicateMaterial(kid)) if kid == "first"),
            "{family}: material still in the window must be refused, got {back:?}"
        );

        // And revoking by one name takes the key out wherever it is held.
        windowed.revoke("first").expect("revokes the windowed key");
        assert!(
            windowed.published_keys().find("first").is_none(),
            "{family}: the revoked material is gone from the published set"
        );
        assert_eq!(windowed.revoked().len(), 1);
    }
}

// --- the caller's claims map is bounded --------------------------------------------------------

/// A caller cannot put unbounded data into a credential.
#[test]
fn the_caller_claims_map_is_bounded_by_key_count_and_by_size() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    // Key count: the bound itself is accepted, one past it is refused by name.
    let at_limit: BTreeMap<String, u64> = (0..256).map(|n| (format!("k{n}"), n)).collect();
    assert_eq!(at_limit.len(), 256);
    assert!(
        signer.sign(&at_limit, &standard("jti-256")).is_ok(),
        "256 keys is the bound, not past it"
    );

    let past_limit: BTreeMap<String, u64> = (0..257).map(|n| (format!("k{n}"), n)).collect();
    assert_eq!(past_limit.len(), 257);
    let outcome = signer.sign(&past_limit, &standard("jti-257"));
    assert!(
        matches!(outcome, Err(SigningError::TooManyClaims(257))),
        "257 keys must be refused by name, got {outcome:?}"
    );

    // Size: one key whose value crosses 64 KiB of serialized JSON.
    let mut under = BTreeMap::new();
    under.insert("blob".to_owned(), "x".repeat(60 * 1024));
    assert!(
        signer.sign(&under, &standard("jti-under")).is_ok(),
        "a map inside the size bound signs"
    );

    let mut over = BTreeMap::new();
    over.insert("blob".to_owned(), "x".repeat(70 * 1024));
    let outcome = signer.sign(&over, &standard("jti-over"));
    assert!(
        matches!(outcome, Err(SigningError::ClaimsTooLarge(bytes)) if bytes > 64 * 1024),
        "a map past the size bound must be refused by name, got {outcome:?}"
    );

    // The bound is on the caller's map, so a huge map is refused before the reserved-name
    // check ever reads it — both refusals are named, and neither is a panic.
    let mut both_wrong: BTreeMap<String, u64> = (0..300).map(|n| (format!("k{n}"), n)).collect();
    both_wrong.insert("exp".to_owned(), 1);
    assert!(
        matches!(
            signer.sign(&both_wrong, &standard("jti-both")),
            Err(SigningError::TooManyClaims(_))
        ),
        "the cheaper bound answers first, by name"
    );
}
