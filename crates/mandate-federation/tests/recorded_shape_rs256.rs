//! `story:federation-fixtures-rs256`: an ID token shaped the way an external OIDC IdP
//! issues one is admitted, and a tenant claim that is not a string is refused by name.
//!
//! The shape is the one a hosted IdP signs, not the minimal one the other files mint:
//!
//! - RS256 over a key generated when the case runs, published in a JWKS under a `kid`;
//! - `iss` with a trailing slash, as hosted IdPs spell their issuer;
//! - `aud` naming the client and a second API, with an `azp` naming the client;
//! - a pairwise-looking opaque `sub` — the IdP derives one per client, so it reads as noise
//!   and carries nothing a reader could fold;
//! - numeric companions (`iat`, `auth_time`) beside the claims tenant resolution reads;
//! - a URL-named tenant claim, `https://idp.example/claims/org_id`, whose value is a string.
//!
//! The tenant is resolved by that claim across two connections on one issuer, each bound to
//! its own organization by its own value, so the claim is what decides and not the
//! connection alone.
//!
//! Before this story the verifier carried string-valued claims into resolution and skipped
//! every other one, so a tenant claim the IdP sent as a number or a list silently resolved
//! nothing: `TenantZero`, with no record of why. The refusal now names the JSON type the
//! claim arrived as. Every non-string JSON type is enumerated, not only the two the story
//! names, because the skip that hid them was one `continue` over all of them.
//!
//! No key is committed and no case reaches the network.

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

/// Hosted IdPs publish their issuer with a trailing slash, and `iss` must match it byte
/// for byte.
const ISSUER: &str = "https://idp.example/";
const CLIENT: &str = "platform-web-client";
/// A second audience the IdP adds for the API the client calls.
const API_AUDIENCE: &str = "platform-api";
/// A pairwise subject: opaque, per-client, case-sensitive.
const PAIRWISE_SUBJECT: &str = "pw|6f1c9b3e0a7d4c52b8e1f09a3d6c7e24";
const TENANT_CLAIM: &str = "https://idp.example/claims/org_id";
const TENANT_ONE: &str = "org_7Hk2Pq9Xw3";
const TENANT_TWO: &str = "org_Zr4Nc8Lm1b";
const KID: &str = "kid-2026-09-rs256";

/// The instant every case is dated from, as seconds since the Unix epoch.
const NOW: u64 = 1_758_240_000;

// ---------------------------------------------------------------- key material

struct Keys {
    signing: EncodingKey,
    published: Jwk,
}

/// One RSA-2048 key per test binary, generated here and never read from the repository.
fn rsa() -> &'static Keys {
    static GENERATED: OnceLock<Keys> = OnceLock::new();
    GENERATED.get_or_init(|| {
        let pair = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("an RSA key");
        let pkcs8: Pkcs8V1Der<'static> = pair.as_der().expect("the generated key in PKCS#8 DER");
        let signing = EncodingKey::from_rsa_der(&pkcs1_of(pkcs8.as_ref()));
        let mut published =
            Jwk::from_encoding_key(&signing, Algorithm::RS256).expect("a public JWK");
        published.common.key_id = Some(KID.to_owned());
        Keys { signing, published }
    })
}

/// `jsonwebtoken`'s RSA signer parses an RFC 8017 `RSAPrivateKey`; `aws_lc_rs` serializes
/// PKCS#8, whose third element is an OCTET STRING holding that `RSAPrivateKey`.
fn pkcs1_of(pkcs8: &[u8]) -> Vec<u8> {
    let (tag, body, _) = element(pkcs8);
    assert_eq!(tag, 0x30, "PKCS#8 is a SEQUENCE");
    let (_, _, after_version) = element(body);
    let (_, _, after_algorithm) = element(after_version);
    let (tag, key, _) = element(after_algorithm);
    assert_eq!(tag, 0x04, "the private key is an OCTET STRING");
    key.to_vec()
}

/// One DER element: its tag, its content, and what follows it.
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

fn published() -> InMemoryJwks {
    let source = InMemoryJwks::new();
    source.publish(
        &Issuer::new(ISSUER),
        serde_json::json!({
            "keys": [serde_json::to_value(&rsa().published).expect("a serializable JWK")],
        }),
    );
    source
}

// --------------------------------------------------------------------- tokens

/// The claims a hosted IdP signs into an ID token, with the tenant claim set to `tenant`.
fn recorded_shape(tenant: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": PAIRWISE_SUBJECT,
        "aud": [CLIENT, API_AUDIENCE],
        "azp": CLIENT,
        "iat": NOW - 5,
        "auth_time": NOW - 30,
        "exp": NOW + 3600,
        "nonce": "n-0S6_WzA2Mj",
        "sid": "3f2a9c1e-5b7d-4e8a-9c0f-1d2e3f4a5b6c",
        TENANT_CLAIM: tenant,
    })
}

fn mint(claims: &serde_json::Value) -> CredentialProof {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("JWT".to_owned());
    let token = encode(&header, claims, &rsa().signing).expect("a signed token");
    CredentialProof::from_bytes(token.into_bytes())
}

// ------------------------------------------------------------------- the crate

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("recorded-shape"),
    }
}

fn on_tenant_claim(organization_id: OrganizationId, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some(TENANT_CLAIM.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

fn at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("recorded-shape"),
        credential: CredentialId::new(uuid(0xcd)),
        at: at(),
    }
}

/// Two connections on one issuer and one client, each bound to its own organization by its
/// own value of the URL-named claim, and the pairwise subject linked under both.
fn two_tenants_on_one_issuer() -> Projection {
    let mut log = Vec::new();
    for (tag, organization_id, value, principal_id) in [
        (1, organization(10), TENANT_ONE, principal(0x21)),
        (2, organization(20), TENANT_TWO, principal(0x22)),
    ] {
        log.push(FederationEvent::FederationConnectionCreated {
            context: context(organization_id),
            connection_id: connection(tag),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: on_tenant_claim(organization_id, value),
            jit_provisioning: false,
        });
        log.push(FederationEvent::ExternalPrincipalLinked {
            context: context(organization_id),
            connection_id: connection(tag),
            principal_id,
            external_principal_id: ExternalPrincipalId::new(uuid(0x70 + tag)),
            subject: ExternalSubject::new(PAIRWISE_SUBJECT),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: at(),
        });
    }
    Projection::fold(&log).expect("two connections, two links")
}

fn verifier(clock: &FixedClock) -> RealVerifier<InMemoryJwks, FixedClock> {
    let allowed = AllowedAlgorithms::configured(&[SigningAlgorithm::new("RS256")])
        .expect("RS256 is admitted");
    let mut built = RealVerifier::new(allowed, published(), clock.clone());
    for tag in [1, 2] {
        built = built
            .configure_connection(connection(tag), &SigningAlgorithm::new("RS256"))
            .expect("RS256 for this connection");
    }
    built
}

fn authenticate(
    projection: &Projection,
    connection_id: FederationConnectionId,
    verifier: &RealVerifier<InMemoryJwks, FixedClock>,
    proof: CredentialProof,
) -> Result<Authenticated, Denied> {
    authenticate_federation(
        &AuthenticateFederation {
            connection_id,
            proof,
        },
        &request(),
        verifier,
        projection,
        projection,
        &mut RecordingSessionIssuer::new(),
    )
}

// ======================================================================= cases

/// The recorded shape is admitted, and the organization it lands in is the one whose
/// configured value the URL-named claim carries — for each of two tenants on one issuer.
#[test]
fn a_recorded_shape_rs256_token_is_admitted_and_resolves_its_tenant_by_the_url_named_claim() {
    let projection = two_tenants_on_one_issuer();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&clock);

    for (connection_id, value, organization_id, principal_id) in [
        (connection(1), TENANT_ONE, organization(10), principal(0x21)),
        (connection(2), TENANT_TWO, organization(20), principal(0x22)),
    ] {
        let authenticated = authenticate(
            &projection,
            connection_id,
            &verifier,
            mint(&recorded_shape(value.into())),
        )
        .unwrap_or_else(|denied| {
            panic!("the recorded shape carrying {value} is admitted: {denied:?}")
        });
        assert_eq!(authenticated.organization_id, organization_id);
        assert_eq!(authenticated.principal_id, principal_id);
    }
    assert_eq!(
        verifier.refusals(),
        Vec::new(),
        "the numeric `iat`, `auth_time` and `exp` beside the tenant claim refuse nothing"
    );
}

/// The claim decides, not the connection: the recorded shape carrying the *other*
/// tenant's value is refused on this connection rather than admitted into either.
#[test]
fn the_other_tenants_value_is_refused_on_this_connection() {
    let projection = two_tenants_on_one_issuer();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&clock);

    let denied = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&recorded_shape(TENANT_TWO.into())),
    )
    .expect_err("the claim names the other tenant");
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantZero);
}

/// The refusal a tenant claim of `value`'s type produces, read off the verifier's log.
fn refused_for(value: serde_json::Value) -> (Denied, String) {
    let projection = two_tenants_on_one_issuer();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&clock);
    let denied = authenticate(
        &projection,
        connection(1),
        &verifier,
        mint(&recorded_shape(value.clone())),
    )
    .expect_err("a tenant claim that is not a string resolves no tenant");
    (denied, format!("{:?}", verifier.refusals()))
}

/// A numeric tenant claim is refused, and the refusal says it was a number.
#[test]
fn a_numeric_tenant_claim_is_refused_with_a_reason_naming_its_type() {
    let (denied, refusals) = refused_for(serde_json::json!(7_204_118));
    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::TenantZero);
    assert_eq!(refusals, "[TenantClaimNotText(Number)]");
}

/// An array tenant claim is refused — a one-member list naming the configured value
/// included — and the refusal says it was an array.
#[test]
fn an_array_tenant_claim_is_refused_with_a_reason_naming_its_type() {
    for value in [
        serde_json::json!([TENANT_ONE]),
        serde_json::json!([TENANT_ONE, TENANT_TWO]),
    ] {
        let (denied, refusals) = refused_for(value);
        assert_eq!(denied.reason, DenialReason::TenantMismatch);
        assert_eq!(denied.clause, DenialClause::TenantZero);
        assert_eq!(refusals, "[TenantClaimNotText(Array)]");
    }
}

/// The rest of the class: every JSON type that is not a string is refused by its own name.
/// The skip this replaces was one `continue` over all of them.
#[test]
fn every_non_string_tenant_claim_type_is_refused_by_name() {
    for (value, named) in [
        (serde_json::json!(7_204_118), "Number"),
        (serde_json::json!(-1.5), "Number"),
        (serde_json::json!([TENANT_ONE]), "Array"),
        (serde_json::json!({ "id": TENANT_ONE }), "Object"),
        (serde_json::json!(true), "Boolean"),
        (serde_json::Value::Null, "Null"),
    ] {
        let (denied, refusals) = refused_for(value.clone());
        assert_eq!(denied.reason, DenialReason::TenantMismatch, "{value}");
        assert_eq!(denied.clause, DenialClause::TenantZero, "{value}");
        assert_eq!(
            refusals,
            format!("[TenantClaimNotText({named})]"),
            "{value}"
        );
    }
}

/// The type is reported only where resolution answers `TenantZero`. A refusal owed earlier
/// — here an untrimmed `sub`, checked before tenant resolution — keeps its own answer, and
/// the verifier's log does not claim a tenant refusal that was never made.
#[test]
fn a_refusal_owed_before_tenant_resolution_keeps_its_answer_and_logs_no_tenant_type() {
    let projection = two_tenants_on_one_issuer();
    let clock = FixedClock::at(NOW);
    let verifier = verifier(&clock);
    let mut body = recorded_shape(serde_json::json!(7_204_118));
    body["sub"] = format!(" {PAIRWISE_SUBJECT}").into();
    let denied = authenticate(&projection, connection(1), &verifier, mint(&body))
        .expect_err("an untrimmed subject is refused");
    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::SubjectNotTrimmed);
    assert_eq!(verifier.refusals(), Vec::new());
}
