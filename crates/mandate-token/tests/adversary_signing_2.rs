//! Adversary pass 2 over the `token-signer` unit: the rotation-window boundary, what an
//! emergency revocation actually stops, the RFC 7638 thumbprint recomputed independently,
//! and the pass-1 refusal classes driven with shapes pass 1 did not send.
//!
//! Every case drives the implementation against a statement the unit wrote about itself —
//! the module documentation of `crates/mandate-token/src/signing_real.rs` and the
//! coordinator rulings recorded on `story:signing-and-verification` after adversary pass 1.
//! Every key is generated at test time; nothing is committed.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::{JwkSet, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, get_current_timestamp};
use serde::ser::{Error as _, SerializeMap as _};
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, RealSigner, RevokedKey, SigningError,
    SigningKeyMaterial, StandardClaims,
};
use mandate_types::value::decode_base64;
use mandate_types::{Audience, Issuer, PrincipalId, SigningAlgorithm};

/// The instant the deterministic cases pin their clock to: 2100-01-01T00:00:00Z, as both
/// existing files do, so a fixed `exp` sits ahead of the host wall clock.
const NOW: u64 = 4_102_444_800;

const TTL: u64 = 900;
const OVERLAP: u64 = 3_600;

const ISSUER: &str = "https://sts.mandate.test";
const AUDIENCE: &str = "mandate";
const SUBJECT: &str = "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

/// The claims the signer owns, in the spelling the module's `RESERVED_CLAIMS` uses.
const RESERVED: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

// --- test-time key material ---------------------------------------------------------------

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

fn rsa_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &rs256(), &rsa_pkcs8_der()).expect("admitted RSA material")
}

fn ec_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &es256(), &ec_pkcs8_der()).expect("admitted EC material")
}

// --- fixtures -------------------------------------------------------------------------------

/// A clock the case moves to any instant it wants to observe the signer at.
#[derive(Clone, Debug)]
struct TestClock(Rc<Cell<u64>>);

impl TestClock {
    fn at(instant: u64) -> Self {
        Self(Rc::new(Cell::new(instant)))
    }

    fn set(&self, instant: u64) {
        self.0.set(instant);
    }
}

impl Clock for TestClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProfileClaims {
    profile: String,
    organization: String,
}

/// A claims value whose `Serialize` fails part of the way through writing a map.
struct HalfSerialized;

impl Serialize for HalfSerialized {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("profile", "self-contained")?;
        Err(S::Error::custom("the caller's claims stopped serializing"))
    }
}

/// A claims value that writes the same key twice, which a JSON map cannot hold twice.
struct RepeatedKey;

impl Serialize for RepeatedKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("role", "viewer")?;
        map.serialize_entry("role", "administrator")?;
        map.end()
    }
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

fn kids(published: &JwkSet) -> Vec<String> {
    published
        .keys
        .iter()
        .map(|jwk| jwk.common.key_id.clone().unwrap_or_default())
        .collect()
}

/// Decode one base64url segment the way every JOSE reader does.
fn b64url_decode(segment: &str) -> Vec<u8> {
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
    decode_base64(&padded).expect("a base64url segment")
}

/// Base64url without padding, the form RFC 7638 §3 step 4 names for the digest.
fn b64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or_default());
        let third = u32::from(chunk.get(2).copied().unwrap_or_default());
        let packed = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[((packed >> 18) & 63) as usize]));
        encoded.push(char::from(ALPHABET[((packed >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            encoded.push(char::from(ALPHABET[((packed >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[(packed & 63) as usize]));
        }
    }
    encoded
}

/// The claims segment of a compact JWS, as the JSON text that goes on the wire.
fn payload_json(token: &str) -> String {
    let segment = token
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts");
    String::from_utf8(b64url_decode(segment)).expect("the claims segment is UTF-8 JSON")
}

/// The claims a relying party reads, under JSON object semantics.
fn effective_claims(token: &str) -> Value {
    serde_json::from_str(&payload_json(token)).expect("the claims segment is a JSON object")
}

fn claim_u64(token: &str, name: &str) -> u64 {
    effective_claims(token)
        .get(name)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("the credential carries a numeric `{name}`"))
}

/// A verification the way a relying party would do it: strictest possible, no leeway.
fn strict_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation
}

// --- the rotation window at its boundary -----------------------------------------------------

/// A relying party with no leeway still accepts a credential at the instant its `exp` names.
///
/// The premise the window cases rest on, measured rather than read off `jsonwebtoken`'s
/// source: `validate` refuses only when `exp < now`, so at `now == exp` the credential is
/// accepted. The signer's window has to cover that instant.
#[test]
fn a_relying_party_with_no_leeway_accepts_a_credential_at_the_instant_of_its_exp() {
    let material = rsa_key("rsa-at-exp");
    let decoding = DecodingKey::from_jwk(material.published()).expect("a decoding key");

    // `decode` reads the host wall clock, so the fixture puts `exp` exactly on it. An
    // attempt during which the host second ticked is discarded rather than asserted on.
    let mut measured = None;
    for _ in 0..16 {
        let host = get_current_timestamp();
        let signer = RealSigner::new(
            both(),
            material.clone(),
            TestClock::at(host - TTL),
            TTL,
            TTL,
        )
        .expect("an admitted key");
        let issued = signer
            .sign(&profile_claims(), &standard("jti-at-exp"))
            .expect("signs");
        let expires_at = claim_u64(&issued.token, "exp");
        let mut validation = strict_validation();
        validation.validate_nbf = true;
        let outcome = decode::<Value>(&issued.token, &decoding, &validation);
        if get_current_timestamp() == host {
            assert_eq!(expires_at, host, "the fixture puts `exp` on the host clock");
            measured = Some(outcome);
            break;
        }
    }

    let outcome = measured.expect("sixteen attempts without the host second ticking");
    assert!(
        outcome.is_ok(),
        "a relying party with no leeway must still accept a credential at `now == exp`, \
         which is the instant the signer's window has to cover: {outcome:?}"
    );
}

/// The published window covers a credential to the instant of its `exp`, not one short.
///
/// `RealSigner` documents the invariant at `signing_real.rs:684`: a key stays published
/// until every credential it signed has expired, which is why `new` refuses an overlap
/// under the TTL. At `overlap == ttl` — the minimum the module documents and the unit's own
/// suite blesses — a rotation in the same clock second as an issuance puts `drops_at`
/// exactly on the credential's `exp`, and `published_keys` drops the key at `drops_at`.
#[test]
fn the_published_window_covers_a_credential_to_the_instant_of_its_exp() {
    let clock = TestClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, TTL)
        .expect("overlap == ttl is the documented minimum");

    let issued = signer
        .sign(&profile_claims(), &standard("jti-edge"))
        .expect("signs under the first key");
    let expires_at = claim_u64(&issued.token, "exp");

    // `SystemClock` counts whole seconds, so a deployment that issues while it rotates
    // produces a rotation in the same second as an issuance.
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    clock.set(expires_at);
    let published = signer.published_keys();
    assert!(
        published.find(&issued.kid).is_some(),
        "at now == exp ({expires_at}) the key `{}` that signed the credential has left the \
         published set, while a relying party with no leeway still accepts the credential: \
         published={:?}",
        issued.kid,
        kids(&published)
    );
}

/// A `kid` is not handed to fresh material while a credential under it is still accepted.
///
/// The same boundary seen from the other side: `rotate` retires a windowed key at
/// `drops_at > now`, so at `now == drops_at` the `kid` is free again. A credential signed
/// under it is still accepted at that instant, and now resolves to material that did not
/// sign it.
#[test]
fn a_kid_is_not_reused_while_a_credential_it_signed_is_still_accepted() {
    let clock = TestClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, TTL)
        .expect("overlap == ttl is the documented minimum");

    let issued = signer
        .sign(&profile_claims(), &standard("jti-reuse"))
        .expect("signs under the first key");
    let expires_at = claim_u64(&issued.token, "exp");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    clock.set(expires_at);
    let reuse = signer.rotate(rsa_key("rsa-1"));
    let (verdict, still_verifies) = match &reuse {
        // The kid is still the window's: nothing to confuse a relying party with.
        Err(_) => ("refused".to_owned(), true),
        Ok(()) => {
            let published = signer.published_keys();
            let outcome = published.find(&issued.kid).map(|jwk| {
                let decoding = DecodingKey::from_jwk(jwk).expect("a decoding key");
                decode::<Value>(&issued.token, &decoding, &strict_validation())
            });
            (format!("{outcome:?}"), matches!(&outcome, Some(Ok(_))))
        }
    };

    assert!(
        still_verifies,
        "at now == exp ({expires_at}) the kid `{}` was handed to material that never signed \
         the credential, which a relying party with no leeway still accepts: {verdict}",
        issued.kid
    );
}

// --- what an emergency revocation actually stops ----------------------------------------------

/// The signer refuses to hold one public key under two `kid`s at once.
///
/// `rotate` already computes a thumbprint for the revocation check. Nothing compares it
/// with the keys the signer is holding, so the same key file supplied again under a new
/// name is installed: the published set carries one public key twice, and the rotation the
/// operator believes they performed moved nothing.
#[test]
fn rotate_refuses_material_the_signer_is_already_holding() {
    let der = rsa_pkcs8_der();
    let load = |kid: &str| {
        SigningKeyMaterial::from_der(kid, &rs256(), &der).expect("admitted RSA material")
    };
    let held = load("rsa-1");
    let renamed = load("rsa-2");
    assert_eq!(
        renamed.thumbprint(),
        held.thumbprint(),
        "the fixture is only meaningful if both names carry one key"
    );

    let mut signer =
        RealSigner::new(both(), held, TestClock::at(NOW), TTL, OVERLAP).expect("an admitted key");
    let outcome = signer.rotate(renamed);

    assert!(
        outcome.is_err(),
        "the signer installed material it was already holding, so the published set now \
         carries one public key under two kids and the rotation rotated nothing: \
         published={:?}",
        kids(&signer.published_keys())
    );
}

/// Revoking compromised material stops it signing under every `kid` that holds it.
///
/// `revoke` records the thumbprint, so no *future* install can bring the material back, but
/// it drops only the entry whose `kid` matches. A second holding of the same key keeps
/// signing and keeps being published after the emergency path has run against it.
#[test]
fn revoking_compromised_material_stops_it_signing_under_every_kid() {
    let der = rsa_pkcs8_der();
    let load = |kid: &str| {
        SigningKeyMaterial::from_der(kid, &rs256(), &der).expect("admitted RSA material")
    };
    let compromised = load("rsa-1");
    let fingerprint = compromised.thumbprint();

    let mut signer = RealSigner::new(both(), compromised, TestClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");
    // If the signer refuses a second holding, the emergency path has nothing to miss.
    let second_holding = signer.rotate(load("rsa-2")).is_ok();

    signer.revoke("rsa-1").expect("revokes the compromised kid");

    let signed_after = signer.sign(&profile_claims(), &standard("jti-after-revoke"));
    let published = signer.published_keys();
    let still_published: Vec<String> = published
        .keys
        .iter()
        .filter(|jwk| jwk.thumbprint(ThumbprintHash::SHA256) == fingerprint)
        .map(|jwk| jwk.common.key_id.clone().unwrap_or_default())
        .collect();

    assert!(
        signed_after.is_err() && still_published.is_empty(),
        "after revoking the compromised key the same material is still signing \
         (second holding installed: {second_holding}, sign={:?}) and is still published \
         under {still_published:?}",
        signed_after.map(|signed| signed.kid)
    );
}

/// Revoking the only key fails closed, and a repeated revocation is a named refusal.
#[test]
fn revoking_the_only_key_fails_closed_and_repeats_are_named() {
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), TestClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    signer.revoke("rsa-1").expect("revokes the active key");
    let signed = signer.sign(&profile_claims(), &standard("jti-none"));
    assert!(
        matches!(signed, Err(SigningError::NoActiveKey)),
        "a signer with no key must fail closed, got {signed:?}"
    );
    assert!(
        signer.published_keys().keys.is_empty(),
        "the revoked key is gone from the published set"
    );

    let again = signer.revoke("rsa-1");
    assert!(
        matches!(
            again,
            Err(SigningError::UnknownKid(_) | SigningError::RevokedKey(_))
        ),
        "a repeated revocation is a named refusal, not a panic or a silent success, \
         got {again:?}"
    );
    assert_eq!(
        signer.revoked().len(),
        1,
        "a repeated revocation does not duplicate the tombstone"
    );
}

/// Revoking a previous key leaves the active key publishing and signing.
#[test]
fn revoking_a_windowed_key_leaves_the_active_key_alone() {
    let clock = TestClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    signer.revoke("rsa-1").expect("revokes the previous key");

    let published = signer.published_keys();
    assert_eq!(
        kids(&published),
        vec!["rsa-2".to_owned()],
        "the revoked previous key is gone and the active key stays"
    );
    assert!(
        signer
            .sign(&profile_claims(), &standard("jti-after"))
            .is_ok(),
        "the active key keeps signing after a previous key is revoked"
    );
}

/// A rehydrated tombstone for a key this deployment never held changes nothing.
#[test]
fn rehydrated_tombstones_for_keys_never_held_are_inert() {
    let strangers = vec![
        RevokedKey {
            kid: "some-other-deployment".to_owned(),
            thumbprint: "not-a-thumbprint".to_owned(),
        },
        RevokedKey {
            kid: String::new(),
            thumbprint: String::new(),
        },
    ];

    let signer = RealSigner::new_with_revocations(
        both(),
        rsa_key("rsa-1"),
        TestClock::at(NOW),
        TTL,
        OVERLAP,
        strangers,
    )
    .expect("a tombstone naming nothing this signer holds is inert");

    assert!(
        signer
            .sign(&profile_claims(), &standard("jti-inert"))
            .is_ok(),
        "a malformed or foreign tombstone must not stop a clean key signing"
    );
}

// --- the thumbprint, recomputed independently --------------------------------------------------

/// The published thumbprint is the RFC 7638 SHA-256 over the required members alone.
#[test]
fn the_thumbprint_is_the_rfc_7638_digest_recomputed_from_the_jwk() {
    for key in [rsa_key("rsa-1"), ec_key("ec-1")] {
        let jwk = serde_json::to_value(key.published()).expect("the JWK serializes");
        let member = |name: &str| {
            jwk.get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("the JWK carries `{name}`"))
                .to_owned()
        };

        // RFC 7638 §3.3: the required members only, lexicographic, no whitespace.
        let canonical = match member("kty").as_str() {
            "RSA" => format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                member("e"),
                member("n")
            ),
            "EC" => format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                member("crv"),
                member("x"),
                member("y")
            ),
            other => panic!("an unexpected key type `{other}`"),
        };
        let expected = b64url_nopad(digest(&SHA256, canonical.as_bytes()).as_ref());

        assert_eq!(
            key.thumbprint(),
            expected,
            "the thumbprint of `{}` is not the RFC 7638 digest of {canonical}",
            key.kid()
        );
        assert!(
            !jwk.as_object()
                .expect("a JWK is an object")
                .keys()
                .any(|name| ["d", "p", "q", "dp", "dq", "qi"].contains(&name.as_str())),
            "the published JWK carries a private member"
        );
    }
}

// --- the reserved-claim refusal, as a class ----------------------------------------------------

/// Every letter case of a reserved name is refused, and no other key displaces the signer's.
///
/// The pass-1 blocker was a caller claim overriding a standard claim. The refusal is
/// ASCII-case-insensitive, so the class has two halves: a name that *is* one of the
/// signer's in some letter case must be refused, and a name that merely looks like one —
/// a non-ASCII homoglyph, an invisible neighbour, a nested object — must sign as an
/// ordinary claim without touching the standard claims on the wire.
#[test]
fn reserved_names_are_refused_and_look_alikes_never_displace_the_standard_claims() {
    let clock = TestClock::at(NOW);
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");

    for name in RESERVED {
        for spelling in [
            name.to_owned(),
            name.to_uppercase(),
            format!("{}{}", name[..1].to_uppercase(), &name[1..]),
            format!("{}{}", &name[..2], name[2..].to_uppercase()),
        ] {
            let mut claims = Map::new();
            claims.insert(spelling.clone(), Value::from("caller"));
            let outcome = signer.sign(&Value::Object(claims), &standard("jti-reserved"));
            assert!(
                matches!(&outcome, Err(SigningError::ReservedClaim(seen)) if *seen == spelling),
                "{spelling:?} must be refused as a reserved claim, got {outcome:?}"
            );
        }
    }

    // Keys that are not the signer's, however much they look like them. Each must sign,
    // and the wire's standard claims must still be the signer's alone.
    let look_alikes = [
        "\u{131}ss",      // a dotless i
        "\u{130}SS",      // a capital I with a dot above
        "\u{ff45}xp",     // a fullwidth e
        "exp\u{0}",       // a trailing NUL
        "\u{200b}exp",    // a leading zero-width space
        " exp",           // a leading space
        "exp ",           // a trailing space
        "e\u{301}xp",     // a combining accent
        "exp\u{200d}nbf", // a zero-width joiner
    ];
    for key in look_alikes {
        let mut claims = Map::new();
        claims.insert(key.to_owned(), Value::from(33_000_000_000_u64));
        let signed = signer
            .sign(&Value::Object(claims), &standard("jti-look-alike"))
            .unwrap_or_else(|error| panic!("{key:?} is not a reserved name: {error:?}"));
        assert_standard_claims_are_the_signers(&signed.token, "jti-look-alike", key);
    }

    // One level of nesting is a different key, and the nested object rides along untouched.
    let mut nested_inner = Map::new();
    nested_inner.insert("exp".to_owned(), Value::from(33_000_000_000_u64));
    nested_inner.insert("iss".to_owned(), Value::from("https://attacker.test"));
    let mut nested = Map::new();
    nested.insert("claims".to_owned(), Value::Object(nested_inner));
    let signed = signer
        .sign(&Value::Object(nested), &standard("jti-nested"))
        .expect("a nested object is not a reserved name");
    assert_standard_claims_are_the_signers(&signed.token, "jti-nested", "claims.exp");
    assert_eq!(
        effective_claims(&signed.token)["claims"]["exp"]
            .as_u64()
            .expect("the nested object rides along"),
        33_000_000_000,
        "the nested caller object is carried, unread"
    );

    // A caller whose serializer writes one key twice cannot put two of it on the wire.
    let signed = signer
        .sign(&RepeatedKey, &standard("jti-repeated"))
        .expect("a repeated ordinary key signs");
    let wire = payload_json(&signed.token);
    assert_eq!(
        wire.matches("\"role\"").count(),
        1,
        "a repeated caller key reached the wire twice: {wire}"
    );
    assert_standard_claims_are_the_signers(&signed.token, "jti-repeated", "role");
}

/// The wire's standard claims are the signer's own, whatever else the caller sent.
fn assert_standard_claims_are_the_signers(token: &str, jti: &str, sent: &str) {
    let claims = effective_claims(token);
    let mut wrong = Vec::new();
    for (name, expected) in [
        ("exp", Value::from(NOW + TTL)),
        ("nbf", Value::from(NOW)),
        ("iat", Value::from(NOW)),
        ("iss", Value::from(ISSUER)),
        ("sub", Value::from(SUBJECT)),
        ("aud", Value::from(AUDIENCE)),
        ("jti", Value::from(jti)),
    ] {
        let seen = claims.get(name);
        if seen != Some(&expected) {
            wrong.push(format!(
                "{name}: signer set {expected}, wire carries {seen:?}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the caller key {sent:?} displaced the signer's standard claims: {wrong:?}"
    );
}

// --- what the caller can hand over ---------------------------------------------------------------

/// A claims value that fails to serialize produces a named refusal and no token.
#[test]
fn a_claims_value_that_fails_to_serialize_produces_no_token() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), TestClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    let outcome = signer.sign(&HalfSerialized, &standard("jti-broken"));
    assert!(
        matches!(&outcome, Err(SigningError::Encode(reason))
            if reason.contains("stopped serializing")),
        "a failing serializer must be a named encode refusal carrying its reason, \
         got {outcome:?}"
    );

    // The signer is not left in a state that stops the next credential.
    assert!(
        signer
            .sign(&profile_claims(), &standard("jti-next"))
            .is_ok(),
        "a refused claims value must not disturb the next signature"
    );
}

/// A caller map at the signer's bound signs, and the signer's own claims survive it intact.
///
/// The ruling after this pass bounded the caller's map at 256 keys and 64 KiB serialized, so
/// the ten-thousand-key fixture this case used to carry is now a named refusal — and the
/// size bound alone would have refused it whatever the key count, since ten thousand
/// `c<n>: <n>` pairs serialize to roughly 120 KB. The case keeps its point by moving to the
/// largest map the signer accepts, and adds the refusal past it.
#[test]
fn a_caller_map_at_the_bound_does_not_displace_the_signers_own_claims() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), TestClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");

    let bulk: BTreeMap<String, u64> = (0..256).map(|index| (format!("c{index}"), index)).collect();
    let signed = signer
        .sign(&bulk, &standard("jti-bulk"))
        .expect("a caller map at the bound signs");
    assert_standard_claims_are_the_signers(
        &signed.token,
        "jti-bulk",
        "two hundred and fifty-six keys",
    );

    let published = signer.published_keys();
    let jwk = published.find(&signed.kid).expect("the kid is published");
    let decoding = DecodingKey::from_jwk(jwk).expect("a decoding key");
    let mut validation = strict_validation();
    validation.validate_exp = false;
    assert!(
        decode::<Value>(&signed.token, &decoding, &validation).is_ok(),
        "a large credential still verifies through the published key"
    );

    // Past the bound is a named refusal, in both dimensions, and neither is a panic.
    let too_many: BTreeMap<String, u64> = (0..10_000)
        .map(|index| (format!("c{index}"), index))
        .collect();
    let outcome = signer.sign(&too_many, &standard("jti-too-many"));
    assert!(
        matches!(outcome, Err(SigningError::TooManyClaims(10_000))),
        "ten thousand keys must be refused by name, got {outcome:?}"
    );

    let mut too_large = BTreeMap::new();
    too_large.insert("blob".to_owned(), "x".repeat(70 * 1024));
    let outcome = signer.sign(&too_large, &standard("jti-too-large"));
    assert!(
        matches!(outcome, Err(SigningError::ClaimsTooLarge(_))),
        "a map past the size bound must be refused by name, got {outcome:?}"
    );

    // And the refusals leave the signer able to issue the next credential.
    assert!(
        signer
            .sign(&profile_claims(), &standard("jti-after-bound"))
            .is_ok(),
        "a refused oversized map must not disturb the next signature"
    );
}

/// The clock and the TTL at their maximum saturate rather than wrapping or panicking.
#[test]
fn an_extreme_clock_and_ttl_saturate_rather_than_wrapping() {
    let clock = TestClock::at(u64::MAX - 1);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), u64::MAX, u64::MAX)
        .expect("overlap == ttl at the maximum is accepted");

    let signed = signer
        .sign(&profile_claims(), &standard("jti-max"))
        .expect("signs at the end of time");
    assert_eq!(
        claim_u64(&signed.token, "exp"),
        u64::MAX,
        "`exp` saturates rather than wrapping past the clock"
    );
    assert_eq!(claim_u64(&signed.token, "iat"), u64::MAX - 1);

    signer
        .rotate(rsa_key("rsa-2"))
        .expect("rotates at the end of time");
    assert!(
        signer.published_keys().find("rsa-1").is_some(),
        "the window's `drops_at` saturates rather than wrapping behind the clock"
    );
}
