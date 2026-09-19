//! Adversary pass 1 over the `token-signer` unit: the claims envelope, the header, the
//! allowlist, the rotation and revocation boundaries, the published key set and time.
//!
//! Every case here drives the implementation against a statement the unit wrote about
//! itself — the module documentation of `crates/mandate-token/src/signing_real.rs`, the
//! `## Acceptance` of `story:signing-and-verification`, and the clearance evidence
//! `docs/architecture/runtime-decisions.md` §9 lists. Every key is generated at test time;
//! nothing is committed.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    get_current_timestamp,
};
use serde::Serialize;
use serde_json::Value;

use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, RealSigner, SigningError, SigningKeyMaterial,
    StandardClaims,
};
use mandate_types::value::{decode_base64, encode_base64};
use mandate_types::{Audience, Issuer, PrincipalId, SigningAlgorithm};

/// The instant the cases pin their clock to: 2100-01-01T00:00:00Z, as the unit's own
/// suite does, so a fixed `exp` sits ahead of the host wall clock.
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

fn rsa_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &rs256(), &rsa_pkcs8_der()).expect("RSA key material")
}

fn ec_key(kid: &str) -> SigningKeyMaterial {
    SigningKeyMaterial::from_der(kid, &es256(), &ec_pkcs8_der()).expect("P-256 key material")
}

/// Wrap DER in a PEM envelope, under the label and the line ending a deployment supplies.
fn pem_with(label: &str, der: &[u8], newline: &str) -> String {
    let mut out = format!("-----BEGIN {label}-----{newline}");
    let body = encode_base64(der);
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push_str(newline);
    }
    out.push_str(&format!("-----END {label}-----{newline}"));
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
}

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Serialize)]
struct ProfileClaims {
    profile: String,
    organization: String,
}

/// The claims a caller supplies when it wants the standard claims to say something else.
#[derive(Clone, Debug, Serialize)]
struct OverridingClaims {
    exp: u64,
    nbf: u64,
    iat: u64,
    iss: &'static str,
    sub: &'static str,
    aud: &'static str,
    jti: &'static str,
}

fn overriding_claims() -> OverridingClaims {
    OverridingClaims {
        exp: 33_000_000_000,
        nbf: 0,
        iat: 0,
        iss: "https://attacker.test",
        sub: "00000000-0000-0000-0000-000000000000",
        aud: "internal-admin",
        jti: "forged",
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
    let mut standard: String = segment
        .chars()
        .map(|character| match character {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while !standard.len().is_multiple_of(4) {
        standard.push('=');
    }
    decode_base64(&standard).expect("a base64url segment")
}

/// The claims segment of a compact JWS, as the JSON text that goes on the wire.
fn payload_json(token: &str) -> String {
    let segment = token
        .split('.')
        .nth(1)
        .expect("a compact JWS has three parts");
    String::from_utf8(b64url_decode(segment)).expect("the claims segment is UTF-8 JSON")
}

/// The claims a relying party reads: JSON object semantics, where a repeated key is the
/// last one written — `serde_json`, `encoding/json`, `json.loads` and `JSON.parse` alike.
fn effective_claims(token: &str) -> Value {
    serde_json::from_str(&payload_json(token)).expect("the claims segment is a JSON object")
}

fn note_u64(wrong: &mut Vec<String>, claims: &Value, name: &str, expected: u64) {
    let seen = claims.get(name).and_then(Value::as_u64);
    if seen != Some(expected) {
        wrong.push(format!(
            "{name}: signer set {expected}, wire carries {seen:?}"
        ));
    }
}

fn note_str(wrong: &mut Vec<String>, claims: &Value, name: &str, expected: &str) {
    let seen = claims.get(name).and_then(Value::as_str);
    if seen != Some(expected) {
        wrong.push(format!(
            "{name}: signer set {expected:?}, wire carries {seen:?}"
        ));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- the claims envelope ------------------------------------------------------------------

/// A caller claim never displaces a standard claim the signer set.
///
/// The ruling after this pass made the attempt a refusal rather than a silent overwrite, so
/// the case asserts both halves: the bid is refused by name, and a caller that does not bid
/// gets the signer's own standard claims on the wire.
#[test]
fn caller_claims_do_not_override_the_standard_claims() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let bid = signer.sign(&overriding_claims(), &standard("jti-adv"));
    assert!(
        matches!(bid, Err(SigningError::ReservedClaim(_))),
        "a caller bid for the standard claims must be refused by name, got {bid:?}"
    );

    let signed = signer
        .sign(&profile_claims(), &standard("jti-adv"))
        .expect("signs under the active key");

    let claims = effective_claims(&signed.token);
    let mut wrong = Vec::new();
    note_u64(&mut wrong, &claims, "exp", NOW + TTL);
    note_u64(&mut wrong, &claims, "nbf", NOW);
    note_u64(&mut wrong, &claims, "iat", NOW);
    note_str(&mut wrong, &claims, "iss", ISSUER);
    note_str(&mut wrong, &claims, "sub", SUBJECT);
    note_str(&mut wrong, &claims, "aud", AUDIENCE);
    note_str(&mut wrong, &claims, "jti", "jti-adv");

    assert!(
        wrong.is_empty(),
        "caller claims reached the wire: {wrong:#?}\npayload: {}",
        payload_json(&signed.token)
    );
}

/// Every token `sign` produces verifies through the set `published_keys` returns.
#[test]
fn every_signed_token_verifies_through_the_published_key_set() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let signed = signer
        .sign(&profile_claims(), &standard("jti-roundtrip"))
        .expect("signs under the active key");

    let published = signer.published_keys();
    let jwk = published.find(&signed.kid).expect("the kid is published");
    let key = DecodingKey::from_jwk(jwk).expect("a decoding key from the published JWK");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);

    let outcome = decode::<Value>(&signed.token, &key, &validation);
    assert!(
        outcome.is_ok(),
        "the signer minted a token its own library cannot read: {:?}\npayload: {}",
        outcome.err(),
        payload_json(&signed.token)
    );
}

/// A caller value that is not a map is refused rather than signed.
#[test]
fn a_caller_value_that_is_not_a_map_is_refused() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let text = signer.sign(&"a bare string", &standard("jti-str"));
    let number = signer.sign(&42_u64, &standard("jti-num"));
    let list = signer.sign(&vec![1_u64, 2, 3], &standard("jti-seq"));
    let boolean = signer.sign(&true, &standard("jti-bool"));

    for (shape, outcome) in [
        ("string", &text),
        ("number", &number),
        ("sequence", &list),
        ("boolean", &boolean),
    ] {
        assert!(
            matches!(outcome, Err(SigningError::Encode(_))),
            "a {shape} claims value must be refused as Encode, got {outcome:?}"
        );
    }
}

/// A caller value that serializes to nothing is refused like every other non-map.
#[test]
fn a_unit_caller_value_is_refused_like_every_other_non_map() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let unit = signer.sign(&(), &standard("jti-unit"));
    let absent = signer.sign(&Option::<ProfileClaims>::None, &standard("jti-none"));

    assert!(
        matches!(unit, Err(SigningError::Encode(_))),
        "signing_real.rs:432 says a value that does not serialize as a map is refused; \
         `()` gave {unit:?}"
    );
    assert!(
        matches!(absent, Err(SigningError::Encode(_))),
        "signing_real.rs:432 says a value that does not serialize as a map is refused; \
         `None` gave {absent:?}"
    );
}

// --- header integrity ---------------------------------------------------------------------

/// The header names the active key, before and after a rotation, and carries nothing else.
#[test]
fn the_header_names_the_active_key_before_and_after_rotation() {
    let clock = FixedClock::at(NOW);
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, OVERLAP)
        .expect("an admitted RS256 key");

    let first = signer
        .sign(&profile_claims(), &standard("jti-header"))
        .expect("signs");
    let header = decode_header(&first.token).expect("a readable header");
    assert_eq!(header.kid.as_deref(), Some("rsa-1"));
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ.as_deref(), Some("JWT"));

    clock.advance(5);
    signer
        .rotate(ec_key("ec-2"))
        .expect("rotates to a P-256 key");
    let second = signer
        .sign(&profile_claims(), &standard("jti-header-2"))
        .expect("signs under the new key");
    let header = decode_header(&second.token).expect("a readable header");
    assert_eq!(
        header.kid.as_deref(),
        Some("ec-2"),
        "a token signed after rotation carries the new kid"
    );
    assert_eq!(
        header.alg,
        Algorithm::ES256,
        "the header algorithm is the active key's, not the previous one's"
    );
    assert_eq!(second.kid, "ec-2");
}

// --- the allowlist ------------------------------------------------------------------------

/// The admitted table matches by exact name and admits no look-alike of one.
#[test]
fn the_admitted_table_is_closed_under_lookalike_names() {
    let configured = both();
    let lookalikes = [
        "rs256",
        "Rs256",
        "rS256",
        "es256",
        "Es256",
        "RS256 ",
        " RS256",
        "\tRS256",
        "RS256\n",
        "RS256\r\n",
        "RS256\0",
        "RS256\u{200b}",
        "RS256\u{00a0}",
        "\u{feff}RS256",
        "\u{ff32}\u{ff33}256",
        "\u{ff32}\u{ff33}\u{ff12}\u{ff15}\u{ff16}",
        "R\u{0405}256",
        "\u{0415}S256",
        "RS\u{0455}256",
        "RS256;",
        "RS256,ES256",
        "RS-256",
        "RS_256",
        "RSA256",
        "RSASSA-PKCS1-v1_5",
        "rs 256",
        "",
        " ",
        "\u{0000}",
        "None",
        "no\u{0301}ne",
    ];

    let mut admitted = Vec::new();
    for name in lookalikes {
        let signing = SigningAlgorithm::new(name);
        if AllowedAlgorithms::new(std::slice::from_ref(&signing)).is_ok() {
            admitted.push(format!("{name:?} became an allowlist"));
        }
        if configured.admit(&signing).is_ok() {
            admitted.push(format!("{name:?} was admitted by a configured policy"));
        }
        if SigningKeyMaterial::from_der("k", &signing, &[0x30, 0x03, 0x02, 0x01, 0x00]).is_ok() {
            admitted.push(format!("{name:?} became key material"));
        }
    }

    assert!(
        admitted.is_empty(),
        "the admitted table is not closed: {admitted:#?}"
    );
}

/// A name configured twice collapses to one admitted algorithm.
#[test]
fn a_duplicated_configured_name_collapses_to_one_algorithm() {
    let twice =
        AllowedAlgorithms::new(&[rs256(), rs256()]).expect("a duplicated name is not fatal");
    assert_eq!(twice.configured(), &[Algorithm::RS256]);
    assert!(twice.admits(Algorithm::RS256));
    assert!(!twice.admits(Algorithm::ES256));

    let signer = RealSigner::new(twice, rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted RS256 key");
    assert_eq!(signer.allowed().configured(), &[Algorithm::RS256]);
}

// --- the published key set ------------------------------------------------------------------

/// The published set carries the public parameters of a signing key and nothing else.
#[test]
fn published_keys_carry_public_parameters_only() {
    let rsa_der = rsa_pkcs8_der();
    let ec_der = ec_pkcs8_der();
    let rsa = SigningKeyMaterial::from_der("rsa-1", &rs256(), &rsa_der).expect("RSA key material");
    let ec = SigningKeyMaterial::from_der("ec-1", &es256(), &ec_der).expect("P-256 key material");

    let clock = FixedClock::at(NOW);
    let mut signer =
        RealSigner::new(both(), rsa, clock.clone(), TTL, OVERLAP).expect("an admitted key");
    signer.rotate(ec).expect("rotates to the P-256 key");

    let published = signer.published_keys();
    let value = serde_json::to_value(&published).expect("the JWK set serializes");
    let text = serde_json::to_string(&published).expect("the JWK set renders");
    let keys = value["keys"].as_array().expect("a keys array");
    assert_eq!(keys.len(), 2, "both keys of the window are published");

    for key in keys {
        let object = key.as_object().expect("a JWK object");
        let kid = object
            .get("kid")
            .and_then(Value::as_str)
            .expect("every published key names a kid");
        let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
        names.sort_unstable();
        match kid {
            "rsa-1" => {
                assert_eq!(
                    names,
                    ["alg", "e", "kid", "kty", "n", "use"],
                    "an RSA JWK carries exactly the public RSA parameters"
                );
                assert_eq!(object["kty"], "RSA");
                assert_eq!(object["alg"], "RS256");
            }
            "ec-1" => {
                assert_eq!(
                    names,
                    ["alg", "crv", "kid", "kty", "use", "x", "y"],
                    "an EC JWK carries exactly the public EC parameters"
                );
                assert_eq!(object["kty"], "EC");
                assert_eq!(object["alg"], "ES256");
                assert_eq!(object["crv"], "P-256");
            }
            other => panic!("an unexpected kid is published: {other}"),
        }
        assert_eq!(object["use"], "sig", "every published key names its use");
        for private in ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] {
            assert!(
                !object.contains_key(private),
                "the published JWK for {kid} carries the private parameter {private}: {key}"
            );
        }
    }

    // And the private bytes themselves are in no rendering of the set.
    for der in [&rsa_der, &ec_der] {
        let tail = &der[der.len() - 48..];
        for leak in [encode_base64(der), encode_base64(tail), hex(der), hex(tail)] {
            assert!(
                !text.contains(leak.as_str()),
                "private key material reached the published set: {text}"
            );
        }
    }
}

/// No rendering of a signer or its key material, in any container, reaches the private bytes.
#[test]
fn no_debug_rendering_in_any_container_reaches_key_material() {
    #[derive(Debug)]
    #[allow(
        dead_code,
        reason = "every field exists to be rendered by the derived Debug"
    )]
    struct Holder {
        signer: RealSigner<FixedClock>,
        key: SigningKeyMaterial,
        spare: Option<SigningKeyMaterial>,
    }

    let der = rsa_pkcs8_der();
    let key = SigningKeyMaterial::from_der("rsa-1", &rs256(), &der).expect("RSA key material");
    let clock = FixedClock::at(NOW);
    let mut signer =
        RealSigner::new(both(), key.clone(), clock, TTL, OVERLAP).expect("an admitted key");
    signer.rotate(rsa_key("rsa-2")).expect("rotates");

    let holder = Holder {
        signer: signer.clone(),
        key: key.clone(),
        spare: Some(key.clone()),
    };
    let in_vec = vec![signer.clone()];
    let in_option = Some(&signer);
    let in_tuple = (&key, &signer);

    let renderings = [
        format!("{signer:?}"),
        format!("{signer:#?}"),
        format!("{key:?}"),
        format!("{key:#?}"),
        format!("{holder:?}"),
        format!("{holder:#?}"),
        format!("{in_vec:?}"),
        format!("{in_vec:#?}"),
        format!("{in_option:?}"),
        format!("{in_tuple:?}"),
        format!("{:?}", holder.spare),
    ];

    let windows: Vec<&[u8]> = vec![
        &der,
        &der[..32],
        &der[der.len() / 2..der.len() / 2 + 48],
        &der[der.len() - 48..],
    ];
    let mut leaks: Vec<String> = Vec::new();
    for window in windows {
        leaks.push(encode_base64(window));
        leaks.push(hex(window));
        leaks.push(hex(window).to_uppercase());
        let debug = format!("{window:?}");
        leaks.push(debug[1..debug.len() - 1].to_owned());
    }

    for rendering in &renderings {
        assert!(
            rendering.contains("rsa-1") || rendering.contains("rsa-2"),
            "the rendering is a real Debug: {rendering}"
        );
        for leak in &leaks {
            assert!(
                !rendering.contains(leak.as_str()),
                "key material reached a Debug rendering: {rendering}"
            );
        }
    }
}

// --- rotation and revocation boundaries -------------------------------------------------------

/// A kid the emergency path revoked is never installed again.
#[test]
fn a_revoked_kid_is_never_installed_again() {
    let clock = FixedClock::at(NOW);
    let compromised = rsa_key("rsa-1");
    let mut signer = RealSigner::new(both(), compromised.clone(), clock.clone(), TTL, OVERLAP)
        .expect("an admitted key");

    signer.revoke("rsa-1").expect("revokes the active key");
    let while_revoked = signer.sign(&profile_claims(), &standard("jti-revoked"));
    assert!(
        matches!(while_revoked, Err(SigningError::NoActiveKey)),
        "a revoked signer signs nothing, got {while_revoked:?}"
    );

    clock.advance(10);
    let reinstalled = signer.rotate(compromised.clone());
    let signs_again = signer
        .sign(&profile_claims(), &standard("jti-after-return"))
        .map(|signed| signed.kid);
    let published = kids(&signer.published_keys());

    assert!(
        reinstalled.is_err(),
        "the exact key material revoked on the emergency path was installed again: \
         rotate={reinstalled:?}, sign={signs_again:?}, published={published:?}"
    );
}

/// A rotated-out key stays published for as long as the credentials it signed stay valid.
///
/// The ruling after this pass made the signer refuse an overlap shorter than its TTL rather
/// than accept one and strand credentials, so the case asserts the refusal and then shows
/// the invariant holding at the shortest overlap the signer will accept.
#[test]
fn a_rotated_out_key_stays_published_while_its_credentials_live() {
    let clock = FixedClock::at(NOW);

    // An overlap under the TTL is the pairing that stranded a credential; it is refused.
    let stranding = RealSigner::new(both(), rsa_key("rsa-0"), clock.clone(), TTL, 60);
    assert!(
        matches!(stranding, Err(SigningError::OverlapShorterThanTtl { .. })),
        "an overlap under the TTL must be refused, got {stranding:?}"
    );

    // At the shortest overlap the signer accepts, the invariant holds.
    let mut signer = RealSigner::new(both(), rsa_key("rsa-1"), clock.clone(), TTL, TTL)
        .expect("an admitted key");

    let issued = signer
        .sign(&profile_claims(), &standard("jti-live"))
        .expect("signs under the first key");
    let expires_at = effective_claims(&issued.token)["exp"]
        .as_u64()
        .expect("the credential carries an exp");

    clock.advance(1);
    signer.rotate(rsa_key("rsa-2")).expect("rotates");
    clock.advance(100);

    let now = clock.now_unix();
    assert!(
        expires_at > now,
        "the fixture is only meaningful while the credential is unexpired"
    );
    let published = signer.published_keys();
    assert!(
        published.find(&issued.kid).is_some(),
        "an unexpired credential (exp {expires_at}, now {now}) lost the key that signed it: \
         published={:?}",
        kids(&published)
    );
}

// --- the forms a deployment supplies -----------------------------------------------------------

/// One way of building key material the case expects to be refused.
type KeyBuilder = Box<dyn Fn() -> Result<SigningKeyMaterial, SigningError>>;

/// Malformed key material is refused by name and never panics.
#[test]
fn malformed_key_material_is_refused_without_panicking() {
    let rsa = rsa_pkcs8_der();
    let ec = ec_pkcs8_der();

    let refused: Vec<(&str, KeyBuilder)> = vec![
        (
            "empty DER under RS256",
            Box::new(|| SigningKeyMaterial::from_der("k", &rs256(), &[])),
        ),
        (
            "empty DER under ES256",
            Box::new(|| SigningKeyMaterial::from_der("k", &es256(), &[])),
        ),
        ("one byte under RS256", {
            Box::new(|| SigningKeyMaterial::from_der("k", &rs256(), &[0x30]))
        }),
        ("truncated RSA PKCS#8", {
            let half = rsa[..rsa.len() / 2].to_vec();
            Box::new(move || SigningKeyMaterial::from_der("k", &rs256(), &half))
        }),
        ("truncated EC PKCS#8", {
            let half = ec[..ec.len() / 2].to_vec();
            Box::new(move || SigningKeyMaterial::from_der("k", &es256(), &half))
        }),
        ("a length header claiming more than it has", {
            Box::new(|| {
                SigningKeyMaterial::from_der("k", &rs256(), &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff])
            })
        }),
        ("an EC key declared RS256", {
            let ec = ec.clone();
            Box::new(move || SigningKeyMaterial::from_der("k", &rs256(), &ec))
        }),
        ("an empty PEM body", {
            Box::new(|| SigningKeyMaterial::from_pem("k", &rs256(), "-----BEGIN PRIVATE KEY-----"))
        }),
    ];

    for (label, build) in refused {
        let outcome = catch_unwind(AssertUnwindSafe(build));
        match outcome {
            Err(_) => panic!("{label} panicked instead of being refused"),
            Ok(Ok(key)) => panic!("{label} was accepted as key material: {key:?}"),
            Ok(Err(_)) => {}
        }
    }

    // A PEM a deployment supplies with CRLF line endings still loads.
    let crlf = SigningKeyMaterial::from_pem("k", &rs256(), &pem_with("PRIVATE KEY", &rsa, "\r\n"));
    assert!(crlf.is_ok(), "a CRLF PEM must load, got {crlf:?}");
}

/// DER carrying bytes after the key structure is refused rather than silently truncated.
#[test]
fn der_with_trailing_bytes_after_the_key_is_refused() {
    let mut rsa = rsa_pkcs8_der();
    rsa.push(0x00);
    let mut ec = ec_pkcs8_der();
    ec.push(0x00);

    let rsa_outcome = SigningKeyMaterial::from_der("rsa-1", &rs256(), &rsa);
    let ec_outcome = SigningKeyMaterial::from_der("ec-1", &es256(), &ec);

    assert!(
        rsa_outcome.is_err() && ec_outcome.is_err(),
        "trailing bytes after the key must be refused: RSA={rsa_outcome:?}, EC={ec_outcome:?}"
    );
}

// --- time ---------------------------------------------------------------------------------

/// A published key verifies a live credential and refuses an expired one with no leeway.
#[test]
fn the_published_key_refuses_an_expired_credential_with_no_leeway() {
    let live_clock = FixedClock::at(get_current_timestamp());
    let live_signer = RealSigner::new(both(), rsa_key("rsa-live"), live_clock, TTL, OVERLAP)
        .expect("an admitted key");
    let live = live_signer
        .sign(&profile_claims(), &standard("jti-live"))
        .expect("signs");

    let stale_clock = FixedClock::at(get_current_timestamp() - TTL - 300);
    let stale_signer = RealSigner::new(both(), rsa_key("rsa-stale"), stale_clock, TTL, OVERLAP)
        .expect("an admitted key");
    let stale = stale_signer
        .sign(&profile_claims(), &standard("jti-stale"))
        .expect("signs");

    for (label, signed, published, expected_ok) in [
        ("live", &live, live_signer.published_keys(), true),
        ("expired", &stale, stale_signer.published_keys(), false),
    ] {
        let jwk = published.find(&signed.kid).expect("the kid is published");
        let key = DecodingKey::from_jwk(jwk).expect("a decoding key");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        let outcome = decode::<Value>(&signed.token, &key, &validation);
        assert_eq!(
            outcome.is_ok(),
            expected_ok,
            "the {label} credential decoded as {outcome:?}"
        );
    }
}

/// The published public key cannot be turned into a forgery a pinned verifier accepts.
#[test]
fn a_forged_hs256_token_from_the_published_modulus_is_refused() {
    let signer = RealSigner::new(both(), rsa_key("rsa-1"), FixedClock::at(NOW), TTL, OVERLAP)
        .expect("an admitted key");
    let signed = signer
        .sign(&profile_claims(), &standard("jti-confusion"))
        .expect("signs");

    let published = signer.published_keys();
    let jwk = published.find("rsa-1").expect("the kid is published");
    let value = serde_json::to_value(jwk).expect("the JWK serializes");
    let modulus = b64url_decode(value["n"].as_str().expect("an RSA modulus"));

    // The classic algorithm-confusion attack: the attacker signs with the published public
    // material as an HMAC secret and hopes the verifier takes the algorithm from the header.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("rsa-1".to_owned());
    let claims = effective_claims(&signed.token);
    let forged = encode(&header, &claims, &EncodingKey::from_secret(&modulus))
        .expect("an HMAC token over the published modulus");

    let key = DecodingKey::from_jwk(jwk).expect("a decoding key from the published JWK");
    let mut pinned = Validation::new(Algorithm::RS256);
    pinned.set_issuer(&[ISSUER]);
    pinned.set_audience(&[AUDIENCE]);
    let refused = decode::<Value>(&forged, &key, &pinned);
    assert!(
        refused.is_err(),
        "a verifier pinned to RS256 accepted an HS256 forgery: {refused:?}"
    );

    let mut header_selected = Validation::new(Algorithm::HS256);
    header_selected.set_issuer(&[ISSUER]);
    header_selected.set_audience(&[AUDIENCE]);
    let also_refused = decode::<Value>(&forged, &key, &header_selected);
    assert!(
        also_refused.is_err(),
        "the published JWK served as an HMAC secret: {also_refused:?}"
    );
}
