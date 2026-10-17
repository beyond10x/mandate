//! The ID-token claim renderer: the claim set of OpenID Connect Core 3.1.3.6, the subject of
//! fork F1 and `at_hash`, signed by the real signer and read back the way a relying party
//! reads it.
//!
//! Every key is generated at test time with `aws-lc-rs`; no private key is committed. A token
//! is verified through `jsonwebtoken::decode` against the JWK the signer publishes under the
//! header's `kid`, so nothing reaches back into the signer's private material.

use std::cell::Cell;
use std::rc::Rc;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

use mandate_token::identity_token::{
    DEFAULT_ID_TOKEN_LIFETIME_SECONDS, IdentityTokenClaims, IdentityTokenRequest, ProfileScopes,
    RecordedProfile, SubjectError, at_hash, dex_compatible_subject, render_subject,
};
use mandate_token::signing_real::{
    AllowedAlgorithms, Clock, CredentialSigner, RealSigner, SigningError, SigningKeyMaterial,
};
use mandate_types::value::encode_base64;
use mandate_types::{
    DexConnectorId, ExternalSubject, IdTokenSigningAlgorithm, Issuer, OAuthClientId, PrincipalId,
    SigningAlgorithm, SubjectFormat,
};

/// 2100-01-01T00:00:00Z: ahead of the host wall clock, so `exp` is checked for real.
const NOW: u64 = 4_102_444_800;
const ISSUER: &str = "https://sts.mandate.test";
const CLIENT: &str = "0c0128ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const PRINCIPAL: &str = "a00128ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";
const ACCESS_TOKEN: &str = "mandate-access-token-presented-to-the-relying-party";

#[derive(Clone, Debug)]
struct FixedClock(Rc<Cell<u64>>);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

fn rsa_signer(kid: &str, overlap: u64) -> RealSigner<FixedClock> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA 2048 generation");
    let der: Pkcs8V1Der<'static> = pair.as_der().expect("PKCS#8 serialization");
    let algorithm = SigningAlgorithm::new("RS256");
    let key = SigningKeyMaterial::from_der(kid, &algorithm, der.as_ref()).expect("RSA key");
    let allowed = AllowedAlgorithms::new(&[algorithm]).expect("RS256 is admitted");
    RealSigner::new(
        allowed,
        key,
        FixedClock(Rc::new(Cell::new(NOW))),
        900,
        overlap,
    )
    .expect("a signer whose overlap covers its TTL")
}

fn client() -> OAuthClientId {
    OAuthClientId::parse(CLIENT).expect("a declared UUID")
}

fn principal() -> PrincipalId {
    PrincipalId::parse(PRINCIPAL).expect("a declared UUID")
}

fn profile() -> RecordedProfile {
    RecordedProfile {
        email: Some("person@example.test".to_owned()),
        email_verified: true,
        name: Some("A Person".to_owned()),
        groups: vec!["engineering".to_owned(), "on-call".to_owned()],
    }
}

fn all_scopes() -> ProfileScopes {
    ProfileScopes {
        email: true,
        profile: true,
        groups: true,
    }
}

fn request<'a>(
    issuer: &'a Issuer,
    client: &'a OAuthClientId,
    profile: &'a RecordedProfile,
    scopes: ProfileScopes,
) -> IdentityTokenRequest<'a> {
    IdentityTokenRequest {
        issuer,
        subject: PRINCIPAL.to_owned(),
        audience: client,
        token_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        auth_time: NOW - 30,
        nonce: Some("n-0S6_WzA2Mj".to_owned()),
        access_token: Some(ACCESS_TOKEN),
        scopes,
        profile,
    }
}

/// The claims object as a relying party decodes it, after the signature verified.
fn verified(token: &str, published: &JwkSet, algorithm: Algorithm) -> Value {
    let header = decode_header(token).expect("a readable JOSE header");
    assert_eq!(
        header.alg, algorithm,
        "the header names the signing algorithm"
    );
    let kid = header.kid.expect("the header carries a kid");
    let jwk = published.find(&kid).expect("the kid is published");
    let key = DecodingKey::from_jwk(jwk).expect("a decoding key from the published JWK");
    let mut validation = Validation::new(algorithm);
    validation.leeway = 0;
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
    decode::<Value>(token, &key, &validation)
        .expect("the published JWK verifies the ID token")
        .claims
}

// --- F1: the subject ----------------------------------------------------------------------

/// Dex's own output for its mock connector's user (`user_id` `0-385-28089-0`, connector
/// `mock`): `base64url(protobuf{user_id: 1, conn_id: 2})`, unpadded, byte for byte.
#[test]
fn dex_compatible_subject_matches_the_dex_golden_value() {
    assert_eq!(
        dex_compatible_subject("0-385-28089-0", "mock"),
        "Cg0wLTM4NS0yODA4OS0wEgRtb2Nr"
    );
}

/// The protobuf wire form, written out by hand from the encoding rules: field 1 and field 2,
/// wire type 2, each a varint length then the UTF-8 bytes. A length of 128 or more takes a
/// two-byte varint, which a one-byte length would silently truncate.
#[test]
fn dex_compatible_subject_encodes_long_fields_with_a_multi_byte_varint_length() {
    let user_id = "u".repeat(200);
    let mut wire = vec![0x0a, 0xc8, 0x01];
    wire.extend_from_slice(user_id.as_bytes());
    wire.extend_from_slice(&[0x12, 0x06]);
    wire.extend_from_slice(b"google");
    let expected = encode_base64(&wire)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned();

    assert_eq!(dex_compatible_subject(&user_id, "google"), expected);
}

/// proto3 omits a field holding its default value, so Dex's subject for an empty `user_id`
/// carries the connector field alone.
#[test]
fn dex_compatible_subject_omits_an_empty_field_as_proto3_does() {
    assert_eq!(dex_compatible_subject("", "mock"), "EgRtb2Nr");
}

#[test]
fn a_mandate_principal_connection_renders_the_principal_id() {
    let upstream = ExternalSubject::new("0-385-28089-0");
    assert_eq!(
        render_subject(
            SubjectFormat::MandatePrincipal,
            None,
            &principal(),
            &upstream
        ),
        Ok(PRINCIPAL.to_owned())
    );
}

#[test]
fn a_dex_compatible_connection_renders_the_dex_subject_of_the_upstream_subject() {
    let upstream = ExternalSubject::new("0-385-28089-0");
    let replaced = DexConnectorId::new("mock");
    assert_eq!(
        render_subject(
            SubjectFormat::DexCompatible,
            Some(&replaced),
            &principal(),
            &upstream
        ),
        Ok("Cg0wLTM4NS0yODA4OS0wEgRtb2Nr".to_owned())
    );
}

/// The registration refuses both mismatches (`RegisterFederationConnection`'s denial); the
/// renderer refuses them too rather than inventing a subject from a record that broke it.
#[test]
fn a_dex_compatible_connection_without_a_replaced_connector_renders_no_subject() {
    let upstream = ExternalSubject::new("0-385-28089-0");
    assert_eq!(
        render_subject(SubjectFormat::DexCompatible, None, &principal(), &upstream),
        Err(SubjectError::ReplacedConnectorMissing)
    );
}

#[test]
fn a_mandate_principal_connection_naming_a_replaced_connector_renders_no_subject() {
    let upstream = ExternalSubject::new("0-385-28089-0");
    let replaced = DexConnectorId::new("mock");
    assert_eq!(
        render_subject(
            SubjectFormat::MandatePrincipal,
            Some(&replaced),
            &principal(),
            &upstream
        ),
        Err(SubjectError::ReplacedConnectorUnexpected)
    );
}

// --- at_hash ------------------------------------------------------------------------------

/// OpenID Connect Core 3.1.3.6: the left-most half of the hash of the ASCII access token,
/// under the hash of the JOSE algorithm (SHA-256 for both RS256 and ES256), base64url.
#[test]
fn at_hash_is_the_left_half_of_the_sha256_of_the_access_token() {
    let full = digest(&SHA256, ACCESS_TOKEN.as_bytes());
    let expected = encode_base64(&full.as_ref()[..16])
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned();

    assert_eq!(
        at_hash(ACCESS_TOKEN, IdTokenSigningAlgorithm::RS256),
        expected
    );
    assert_eq!(
        at_hash(ACCESS_TOKEN, IdTokenSigningAlgorithm::ES256),
        expected
    );
    assert_eq!(
        expected.len(),
        22,
        "sixteen bytes are 22 unpadded base64url characters"
    );
}

// --- the claim set ------------------------------------------------------------------------

#[test]
fn the_default_id_token_lifetime_is_dex_s_twenty_four_hours() {
    assert_eq!(DEFAULT_ID_TOKEN_LIFETIME_SECONDS, 86_400);
}

#[test]
fn id_token_claims_carry_every_standard_claim_and_the_granted_profile() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let signer = rsa_signer("rsa-one", DEFAULT_ID_TOKEN_LIFETIME_SECONDS);
    let claims = IdentityTokenClaims::render(
        &request(&issuer, &client, &profile, all_scopes()),
        IdTokenSigningAlgorithm::RS256,
    );

    let signed = signer
        .sign_identity_token(&claims, DEFAULT_ID_TOKEN_LIFETIME_SECONDS)
        .expect("an RS256 signer signs an RS256 ID token");
    let decoded = verified(&signed.token, &signer.published_keys(), Algorithm::RS256);

    assert_eq!(decoded["iss"], ISSUER);
    assert_eq!(decoded["sub"], PRINCIPAL);
    assert_eq!(decoded["aud"], CLIENT);
    assert_eq!(decoded["iat"], NOW);
    assert_eq!(decoded["exp"], NOW + DEFAULT_ID_TOKEN_LIFETIME_SECONDS);
    assert_eq!(decoded["auth_time"], NOW - 30);
    assert_eq!(decoded["nonce"], "n-0S6_WzA2Mj");
    assert_eq!(
        decoded["at_hash"],
        at_hash(ACCESS_TOKEN, IdTokenSigningAlgorithm::RS256)
    );
    assert_eq!(decoded["jti"], "00000000-0000-4000-8000-000000000001");
    assert_eq!(decoded["email"], "person@example.test");
    assert_eq!(decoded["email_verified"], Value::Bool(true));
    assert_eq!(decoded["name"], "A Person");
    assert_eq!(
        decoded["groups"],
        serde_json::json!(["engineering", "on-call"])
    );
    assert_eq!(signed.kid, "rsa-one");
}

#[test]
fn without_the_email_scope_no_email_claim_is_rendered() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let claims = IdentityTokenClaims::render(
        &request(
            &issuer,
            &client,
            &profile,
            ProfileScopes {
                email: false,
                profile: true,
                groups: true,
            },
        ),
        IdTokenSigningAlgorithm::RS256,
    );
    let rendered = serde_json::to_value(&claims).expect("claims serialize");

    assert!(rendered.get("email").is_none());
    assert!(rendered.get("email_verified").is_none());
    assert_eq!(rendered["name"], "A Person");
}

#[test]
fn without_profile_or_groups_scopes_neither_name_nor_groups_is_rendered() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let claims = IdentityTokenClaims::render(
        &request(
            &issuer,
            &client,
            &profile,
            ProfileScopes {
                email: true,
                profile: false,
                groups: false,
            },
        ),
        IdTokenSigningAlgorithm::RS256,
    );
    let rendered = serde_json::to_value(&claims).expect("claims serialize");

    assert!(rendered.get("name").is_none());
    assert!(rendered.get("groups").is_none());
    assert_eq!(rendered["email"], "person@example.test");
}

#[test]
fn absent_nonce_access_token_and_profile_values_render_no_claim_and_no_null() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let empty = RecordedProfile::default();
    let mut bare = request(&issuer, &client, &empty, all_scopes());
    bare.nonce = None;
    bare.access_token = None;
    let rendered = serde_json::to_value(IdentityTokenClaims::render(
        &bare,
        IdTokenSigningAlgorithm::RS256,
    ))
    .expect("claims serialize");

    for absent in [
        "nonce",
        "at_hash",
        "email",
        "email_verified",
        "name",
        "groups",
    ] {
        assert!(rendered.get(absent).is_none(), "`{absent}` is not rendered");
    }
    let text = serde_json::to_string(&rendered).expect("claims serialize");
    assert!(
        !text.contains("null"),
        "no claim is rendered as null: {text}"
    );
}

#[test]
fn the_renderer_writes_no_iat_or_exp_and_the_signer_owns_both() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let rendered = serde_json::to_value(IdentityTokenClaims::render(
        &request(&issuer, &client, &profile, all_scopes()),
        IdTokenSigningAlgorithm::RS256,
    ))
    .expect("claims serialize");

    assert!(rendered.get("iat").is_none());
    assert!(rendered.get("exp").is_none());
}

/// A key must stay published until every token it signed has expired, so an ID token whose
/// lifetime outlasts the signer's rotation overlap is refused rather than stranded.
#[test]
fn an_id_token_lifetime_beyond_the_signer_overlap_is_refused() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let signer = rsa_signer("rsa-short", 3_600);
    let claims = IdentityTokenClaims::render(
        &request(&issuer, &client, &profile, all_scopes()),
        IdTokenSigningAlgorithm::RS256,
    );

    assert_eq!(
        signer.sign_identity_token(&claims, DEFAULT_ID_TOKEN_LIFETIME_SECONDS),
        Err(SigningError::OverlapShorterThanTtl {
            ttl_seconds: DEFAULT_ID_TOKEN_LIFETIME_SECONDS,
            overlap_seconds: 3_600,
        })
    );
}

#[test]
fn a_zero_id_token_lifetime_is_refused() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let signer = rsa_signer("rsa-zero", 3_600);
    let claims = IdentityTokenClaims::render(
        &request(&issuer, &client, &profile, all_scopes()),
        IdTokenSigningAlgorithm::RS256,
    );

    assert!(matches!(
        signer.sign_identity_token(&claims, 0),
        Err(SigningError::Encode(_))
    ));
}

#[test]
fn a_revoked_signer_signs_no_id_token() {
    let issuer = Issuer::new(ISSUER);
    let client = client();
    let profile = profile();
    let mut signer = rsa_signer("rsa-revoked", DEFAULT_ID_TOKEN_LIFETIME_SECONDS);
    signer
        .revoke("rsa-revoked")
        .expect("the active key revokes");
    let claims = IdentityTokenClaims::render(
        &request(&issuer, &client, &profile, all_scopes()),
        IdTokenSigningAlgorithm::RS256,
    );

    assert_eq!(
        signer.sign_identity_token(&claims, DEFAULT_ID_TOKEN_LIFETIME_SECONDS),
        Err(SigningError::NoActiveKey)
    );
}
