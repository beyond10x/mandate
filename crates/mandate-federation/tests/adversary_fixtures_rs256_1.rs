//! Adversary pass 1 on `story:federation-fixtures-rs256`.
//!
//! The implementation's own justification for mapping `TenantClaimNotText` to
//! `TenantZero` (`src/verifier_real.rs`, `refused`) is that it is "what
//! `authenticate_federation` would have answered had the claim been skipped". These cases
//! drive that sentence: each builds a proof the base commit skipped the claim of and then
//! refused for a *different* declared clause, and asserts that clause.
//!
//! The refusal now fires inside step 3 (signature/proof validation), before the subject
//! checks and before step 6's fallback analysis over every enabled connection on the
//! issuer, so it pre-empts both.

use std::sync::OnceLock;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, authenticate_federation,
};
use mandate_federation::record::{FederationEvent, Projection};
use mandate_federation::verifier_real::{
    AllowedAlgorithms, FixedClock, InMemoryJwks, RealVerifier,
};
use mandate_federation::{DenialClause, Denied, RecordingSessionIssuer, RequestContext};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, PrincipalId, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/";
const CLIENT: &str = "platform-web-client";
const SUBJECT: &str = "pw|6f1c9b3e0a7d4c52b8e1f09a3d6c7e24";
const TENANT_CLAIM: &str = "https://idp.example/claims/org_id";
const TENANT_VALUE: &str = "org_7Hk2Pq9Xw3";
const EMAIL: &str = "user@idp.example";
const KID: &str = "kid-adv-rs256";
const NOW: u64 = 1_758_240_000;

struct Keys {
    signing: EncodingKey,
    published: Jwk,
}

fn rsa() -> &'static Keys {
    static GENERATED: OnceLock<Keys> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("an RSA key");
        let pkcs8: Pkcs8V1Der<'static> = pair.as_der().expect("PKCS#8 DER");
        let signing = EncodingKey::from_rsa_der(&pkcs1_of(pkcs8.as_ref()));
        let mut published =
            Jwk::from_encoding_key(&signing, Algorithm::RS256).expect("a public JWK");
        published.common.key_id = Some(KID.to_owned());
        Keys { signing, published }
    })
}

fn pkcs1_of(pkcs8: &[u8]) -> Vec<u8> {
    let (_, body, _) = element(pkcs8);
    let (_, _, after_version) = element(body);
    let (_, _, after_algorithm) = element(after_version);
    let (_, key, _) = element(after_algorithm);
    key.to_vec()
}

fn element(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let first = usize::from(input[1]);
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        let mut length = 0_usize;
        for byte in &input[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    (
        input[0],
        &input[header..header + length],
        &input[header + length..],
    )
}

fn mint(claims: &serde_json::Value) -> CredentialProof {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("JWT".to_owned());
    let token = encode(&header, claims, &rsa().signing).expect("a signed token");
    CredentialProof::from_bytes(token.into_bytes())
}

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary"),
    }
}

fn rule(name: &str, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization(),
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

/// Connections on one issuer in one organization, each with its own rule, and `subject`
/// linked under the first.
fn projection(rules: &[TenantResolutionRule], subject: &str) -> Projection {
    let mut log = Vec::new();
    for (index, tenant_resolution) in rules.iter().enumerate() {
        let tag = u8::try_from(index + 1).expect("a small tag");
        log.push(FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(tag),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: tenant_resolution.clone(),
            jit_provisioning: false,
        });
    }
    log.push(FederationEvent::ExternalPrincipalLinked {
        context: context(),
        connection_id: connection(1),
        principal_id: PrincipalId::new(uuid(0x21)),
        external_principal_id: ExternalPrincipalId::new(uuid(0x71)),
        subject: ExternalSubject::new(subject),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: at(),
    });
    Projection::fold(&log).expect("the connections and the link fold")
}

fn verifier(connections: u8) -> RealVerifier<InMemoryJwks, FixedClock> {
    let allowed = AllowedAlgorithms::configured(&[SigningAlgorithm::new("RS256")])
        .expect("RS256 is admitted");
    let source = InMemoryJwks::new();
    source.publish(
        &Issuer::new(ISSUER),
        serde_json::json!({
            "keys": [serde_json::to_value(&rsa().published).expect("a JWK")],
        }),
    );
    let mut built = RealVerifier::new(allowed, source, FixedClock::at(NOW));
    for tag in 1..=connections {
        built = built
            .configure_connection(connection(tag), &SigningAlgorithm::new("RS256"))
            .expect("RS256 for this connection");
    }
    built
}

fn authenticate(
    projection: &Projection,
    verifier: &RealVerifier<InMemoryJwks, FixedClock>,
    proof: CredentialProof,
) -> Result<Authenticated, Denied> {
    authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof,
        },
        &RequestContext {
            audience: Audience::new("mandate"),
            correlation: CorrelationId::new("adversary"),
            credential: CredentialId::new(uuid(0xcd)),
            at: at(),
        },
        verifier,
        projection,
        projection,
        &mut RecordingSessionIssuer::new(),
    )
}

fn claims(subject: &str, tenant: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "iss": ISSUER,
        "sub": subject,
        "aud": CLIENT,
        "iat": NOW - 5,
        "exp": NOW + 3600,
        TENANT_CLAIM: tenant,
    }) else {
        unreachable!("an object literal")
    };
    map
}

/// Control: with a string tenant claim that does not match, the unverified-email fallback
/// on the second connection is what the refusal names. Green at base and head.
#[test]
fn control_a_mismatched_string_tenant_claim_is_refused_as_unverified_fallback() {
    let projection = projection(
        &[rule(TENANT_CLAIM, TENANT_VALUE), rule("email", EMAIL)],
        SUBJECT,
    );
    let verifier = verifier(2);
    let mut body = claims(SUBJECT, "org_other".into());
    body.insert("email".into(), EMAIL.into());
    body.insert("email_verified".into(), false.into());
    let denied = authenticate(&projection, &verifier, mint(&body.into()))
        .expect_err("the tenant claim does not match");
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::UnverifiedFallback);
}

/// The same proof with the tenant claim sent as a number. At base the verifier skipped the
/// claim, `resolve_tenant` found no validated match and a rule matching an unverified hint,
/// and refused `UnverifiedFallback`. The type refusal now pre-empts that analysis and
/// answers `TenantZero` — which is not "what `authenticate_federation` would have answered
/// had the claim been skipped".
#[test]
fn a_numeric_tenant_claim_does_not_mask_the_unverified_fallback_clause() {
    let projection = projection(
        &[rule(TENANT_CLAIM, TENANT_VALUE), rule("email", EMAIL)],
        SUBJECT,
    );
    let verifier = verifier(2);
    let mut body = claims(SUBJECT, serde_json::json!(7_204_118));
    body.insert("email".into(), EMAIL.into());
    body.insert("email_verified".into(), false.into());
    let denied = authenticate(&projection, &verifier, mint(&body.into()))
        .expect_err("a numeric tenant claim resolves no tenant");
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(
        denied.clause,
        DenialClause::UnverifiedFallback,
        "the skipped-claim answer the refusal claims to preserve"
    );
}

/// A whitespace-only `sub` is refused as `EmptySubject` before tenant resolution runs.
/// At base, a numeric tenant claim beside it was skipped and the subject check refused.
/// The type refusal now fires in the verifier, before that check, and the subject defect
/// is reported as a tenant mismatch.
#[test]
fn a_numeric_tenant_claim_does_not_pre_empt_the_empty_subject_refusal() {
    let projection = projection(&[rule(TENANT_CLAIM, TENANT_VALUE)], SUBJECT);
    let verifier = verifier(1);
    let body = claims("   ", serde_json::json!(7_204_118));
    let denied = authenticate(&projection, &verifier, mint(&body.into()))
        .expect_err("a blank subject is refused");
    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::EmptySubject);
}
