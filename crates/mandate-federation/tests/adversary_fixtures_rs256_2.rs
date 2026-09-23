//! Adversary pass 2 on `story:federation-fixtures-rs256`.
//!
//! The correction moved the type refusal into `resolve_tenant`, reported through
//! `FederationVerifier::tenant_claim_refused` only on the path that answers `TenantZero`
//! for the selected connection. The denial is unchanged from base by construction, so
//! these cases drive the one thing that did change: what the verifier's refusal log says,
//! on the paths the implementing suite does not cover — the unverified-fallback path, the
//! provisioning command, and a rule that could never have matched whatever the claim's
//! type.

use std::sync::OnceLock;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, ProvisionExternalPrincipal, Provisioned,
    authenticate_federation, provision_external_principal,
};
use mandate_federation::record::{FederationEvent, Projection};
use mandate_federation::verifier_real::{
    AllowedAlgorithms, ClaimType, FixedClock, InMemoryJwks, RealVerifier, RefusalReason,
};
use mandate_federation::{
    DenialClause, Denied, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, PrincipalId, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/";
const CLIENT: &str = "platform-web-client";
const SUBJECT: &str = "pw|0b7e4c19d2a84f63a5c10e98f7d2b3a1";
const TENANT_CLAIM: &str = "https://idp.example/claims/org_id";
const TENANT_VALUE: &str = "org_Qm4Tz8Lw1R";
const EMAIL: &str = "person@idp.example";
const KID: &str = "kid-adv2-rs256";
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
    OrganizationId::new(uuid(12))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x52)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xce)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-2"),
    }
}

fn rule(name: &str, value: Option<&str>) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization(),
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: value.map(ToOwned::to_owned),
    }
}

/// Connections on one issuer in one organization, each with its own rule. When `linked`,
/// the subject is linked under the first.
fn projection(rules: &[TenantResolutionRule], jit_provisioning: bool, linked: bool) -> Projection {
    let mut log = Vec::new();
    for (index, tenant_resolution) in rules.iter().enumerate() {
        let tag = u8::try_from(index + 1).expect("a small tag");
        log.push(FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(tag),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: tenant_resolution.clone(),
            jit_provisioning,
        });
    }
    if linked {
        log.push(FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(1),
            principal_id: PrincipalId::new(uuid(0x22)),
            external_principal_id: ExternalPrincipalId::new(uuid(0x72)),
            subject: ExternalSubject::new(SUBJECT),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: at(),
        });
    }
    Projection::fold(&log).expect("the connections fold")
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

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-2"),
        credential: CredentialId::new(uuid(0xce)),
        at: at(),
    }
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
        &request(),
        verifier,
        projection,
        projection,
        &mut RecordingSessionIssuer::new(),
    )
}

fn provision(
    projection: &Projection,
    verifier: &RealVerifier<InMemoryJwks, FixedClock>,
    proof: CredentialProof,
) -> Result<Provisioned, Denied> {
    provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id: connection(1),
            proof,
        },
        &request(),
        verifier,
        projection,
        projection,
        &mut SequentialAllocator::new(),
    )
}

fn claims(tenant: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": CLIENT,
        "azp": CLIENT,
        "iat": NOW - 5,
        "exp": NOW + 3600,
        TENANT_CLAIM: tenant,
    }) else {
        unreachable!("an object literal")
    };
    map
}

/// Pass 1's fallback case, now read off the log as well as the clause. The trait doc says
/// the refusal is reported "only where no other refusal was owed first", and
/// `UnverifiedFallback` is owed first here. No implementing case asserts the log on this
/// path, so moving the report above the `if fallback` return in `resolve_tenant` leaves
/// the suite green; this case is the one that would catch it.
#[test]
fn a_numeric_tenant_claim_beside_an_unverified_fallback_logs_no_tenant_type() {
    let projection = projection(
        &[
            rule(TENANT_CLAIM, Some(TENANT_VALUE)),
            rule("email", Some(EMAIL)),
        ],
        false,
        true,
    );
    let verifier = verifier(2);
    let mut body = claims(serde_json::json!(7_204_118));
    body.insert("email".into(), EMAIL.into());
    body.insert("email_verified".into(), false.into());
    let denied = authenticate(&projection, &verifier, mint(&body.into()))
        .expect_err("a numeric tenant claim resolves no tenant");
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::UnverifiedFallback);
    assert_eq!(
        verifier.refusals(),
        Vec::<RefusalReason>::new(),
        "the fallback was the refusal owed; the log must not also claim a type refusal"
    );
}

/// The provisioning command shares `resolve`, and no implementing case drives it with a
/// non-string tenant claim. With provisioning not admitted, the tenant refusal still comes
/// first (as at base: `resolve` runs before the `jit_provisioning` check), and the log
/// names the type once.
#[test]
fn provisioning_refuses_a_numeric_tenant_claim_before_the_admission_check_and_names_its_type() {
    for jit_provisioning in [false, true] {
        let projection = projection(
            &[rule(TENANT_CLAIM, Some(TENANT_VALUE))],
            jit_provisioning,
            false,
        );
        let verifier = verifier(1);
        let denied = provision(
            &projection,
            &verifier,
            mint(&claims(serde_json::json!(7_204_118)).into()),
        )
        .expect_err("a numeric tenant claim provisions nothing");
        assert_eq!(
            denied.reason,
            DenialReason::TenantMismatch,
            "{jit_provisioning}"
        );
        assert_eq!(
            denied.clause,
            DenialClause::TenantZero,
            "{jit_provisioning}"
        );
        assert_eq!(
            verifier.refusals(),
            vec![RefusalReason::TenantClaimNotText(ClaimType::Number)],
            "{jit_provisioning}"
        );
    }
}

/// A rule naming a claim and no value matches nothing (`matches_validated`: "half a rule
/// is not a binding"), and `register_federation_connection` admits one (`record.rs`
/// `Shape::Nothing` collides with nothing). A string tenant claim is refused `TenantZero`
/// with an empty log; the same proof with the claim sent as a number is refused the same
/// way, and the log blames the claim's type — a cause that did not decide anything, since
/// no value of any type could have matched.
#[test]
fn a_rule_without_a_value_does_not_blame_the_tenant_claims_type() {
    let projection = projection(&[rule(TENANT_CLAIM, None)], false, true);

    let as_text = verifier(1);
    let denied = authenticate(
        &projection,
        &as_text,
        mint(&claims(TENANT_VALUE.into()).into()),
    )
    .expect_err("half a rule matches nothing");
    assert_eq!(denied.clause, DenialClause::TenantZero);
    assert_eq!(as_text.refusals(), Vec::<RefusalReason>::new());

    let as_number = verifier(1);
    let denied = authenticate(
        &projection,
        &as_number,
        mint(&claims(serde_json::json!(7_204_118)).into()),
    )
    .expect_err("half a rule matches nothing");
    assert_eq!(denied.clause, DenialClause::TenantZero);
    assert_eq!(
        as_number.refusals(),
        Vec::<RefusalReason>::new(),
        "the rule could match no value of any type, so the type is not why it refused"
    );
}
