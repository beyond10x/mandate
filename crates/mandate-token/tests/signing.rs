//! Fork F8: an ID token is signed RS256 unless its client registered ES256
//! (`id_token_signed_response_alg`), and both algorithms are the ones a discovery document
//! lists.
//!
//! Keys are generated at test time with `aws-lc-rs`; nothing private is committed.

use std::cell::Cell;
use std::rc::Rc;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;

use mandate_token::identity_token::{
    IdentityTokenClaims, IdentityTokenRequest, ProfileScopes, RecordedProfile,
    algorithm_for_client, algorithm_name, jose_algorithm, signer_for, supported_algorithm_names,
};
use mandate_token::signing_real::{
    AlgorithmPolicyError, AllowedAlgorithms, Clock, CredentialSigner, RealSigner, SigningError,
    SigningKeyMaterial,
};
use mandate_types::{IdTokenSigningAlgorithm, Issuer, OAuthClientId, SigningAlgorithm};

const NOW: u64 = 4_102_444_800;
const LIFETIME: u64 = 86_400;
const ISSUER: &str = "https://sts.mandate.test";
const CLIENT: &str = "0c0128ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b";

#[derive(Clone, Debug)]
struct FixedClock(Rc<Cell<u64>>);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0.get()
    }
}

fn signer(kid: &str, name: &str, der: &[u8]) -> RealSigner<FixedClock> {
    let algorithm = SigningAlgorithm::new(name);
    let key = SigningKeyMaterial::from_der(kid, &algorithm, der).expect("key material");
    let allowed = AllowedAlgorithms::new(&[
        SigningAlgorithm::new("RS256"),
        SigningAlgorithm::new("ES256"),
    ])
    .expect("RS256 and ES256 are admitted");
    RealSigner::new(
        allowed,
        key,
        FixedClock(Rc::new(Cell::new(NOW))),
        900,
        LIFETIME,
    )
    .expect("a signer whose overlap covers the ID-token lifetime")
}

fn rsa() -> RealSigner<FixedClock> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("RSA 2048 generation");
    let der: Pkcs8V1Der<'static> = pair.as_der().expect("PKCS#8 serialization");
    signer("rsa-key", "RS256", der.as_ref())
}

fn ec() -> RealSigner<FixedClock> {
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
        .expect("P-256 generation");
    signer("ec-key", "ES256", der.as_ref())
}

fn claims(algorithm: IdTokenSigningAlgorithm) -> IdentityTokenClaims {
    let issuer = Issuer::new(ISSUER);
    let client = OAuthClientId::parse(CLIENT).expect("a declared UUID");
    let profile = RecordedProfile::default();
    IdentityTokenClaims::render(
        &IdentityTokenRequest {
            issuer: &issuer,
            subject: "a00128ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b".to_owned(),
            audience: &client,
            token_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            auth_time: NOW,
            nonce: None,
            access_token: Some("an-access-token"),
            scopes: ProfileScopes::default(),
            profile: &profile,
        },
        algorithm,
    )
}

/// Sign through the signer the client's choice selects, and verify against that signer's
/// published key the way a relying party would.
fn issued_under(
    choice: Option<IdTokenSigningAlgorithm>,
    signers: &[&RealSigner<FixedClock>],
) -> (Algorithm, String) {
    let algorithm = algorithm_for_client(choice);
    let chosen = signer_for(signers, algorithm).expect("a signer holds the chosen algorithm");
    let signed = chosen
        .sign_identity_token(&claims(algorithm), LIFETIME)
        .expect("the chosen signer signs");
    let header = decode_header(&signed.token).expect("a readable header");
    let published = chosen.published_keys();
    let jwk = published
        .find(header.kid.as_deref().expect("a kid"))
        .expect("the kid is published");
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT]);
    decode::<Value>(
        &signed.token,
        &DecodingKey::from_jwk(jwk).expect("a decoding key"),
        &validation,
    )
    .expect("the published key verifies the token");
    (header.alg, signed.kid)
}

#[test]
fn rs256_default_es256_per_client() {
    let rsa = rsa();
    let ec = ec();
    let signers = [&ec, &rsa];

    assert_eq!(algorithm_for_client(None), IdTokenSigningAlgorithm::RS256);
    assert_eq!(
        issued_under(None, &signers),
        (Algorithm::RS256, "rsa-key".to_owned())
    );
    assert_eq!(
        issued_under(Some(IdTokenSigningAlgorithm::RS256), &signers),
        (Algorithm::RS256, "rsa-key".to_owned())
    );
    assert_eq!(
        issued_under(Some(IdTokenSigningAlgorithm::ES256), &signers),
        (Algorithm::ES256, "ec-key".to_owned())
    );
    // The discovery document's `id_token_signing_alg_values_supported`, RS256 first because
    // OpenID Connect Core 15.1 requires it of every provider.
    assert_eq!(supported_algorithm_names(), ["RS256", "ES256"]);
}

#[test]
fn a_client_choice_no_signer_holds_is_refused_by_name() {
    let rsa = rsa();

    assert_eq!(
        signer_for(&[&rsa], IdTokenSigningAlgorithm::ES256).map(|_| ()),
        Err(SigningError::Algorithm(
            AlgorithmPolicyError::NotConfigured("ES256".to_owned())
        ))
    );
}

/// The claims carry the algorithm they were rendered for (`at_hash` depends on it), so a
/// signer whose active key is another algorithm refuses them instead of signing a token
/// whose header and `at_hash` disagree.
#[test]
fn a_signer_refuses_claims_rendered_for_another_algorithm() {
    let ec = ec();

    assert_eq!(
        ec.sign_identity_token(&claims(IdTokenSigningAlgorithm::RS256), LIFETIME),
        Err(SigningError::Algorithm(
            AlgorithmPolicyError::NotConfigured("RS256".to_owned())
        ))
    );
}

#[test]
fn the_wire_names_of_the_two_algorithms_are_the_jose_names() {
    assert_eq!(algorithm_name(IdTokenSigningAlgorithm::RS256), "RS256");
    assert_eq!(algorithm_name(IdTokenSigningAlgorithm::ES256), "ES256");
    assert_eq!(
        jose_algorithm(IdTokenSigningAlgorithm::RS256),
        Algorithm::RS256
    );
    assert_eq!(
        jose_algorithm(IdTokenSigningAlgorithm::ES256),
        Algorithm::ES256
    );
}

/// Discovery lists exactly the algorithms `mandate.core.IdTokenSigningAlgorithm` declares, in
/// declaration order, so a variant added to the contract cannot go unadvertised.
#[test]
fn discovery_lists_every_declared_algorithm() {
    let declared: Vec<&str> = IdTokenSigningAlgorithm::VARIANTS
        .iter()
        .copied()
        .map(algorithm_name)
        .collect();
    assert_eq!(supported_algorithm_names(), declared);
}
