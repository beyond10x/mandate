//! Adversary pass against `story:obligations-federation`.
//!
//! One defect, two cases, both driven through shipped handlers alone.
//!
//! `crates/mandate-federation/src/record.rs:913-917` documents `collides` as deciding
//! "whether two rules on one issuer could both match one proof", and
//! `register_federation_connection` refuses a registration on that answer so that "a rule
//! another organization's connection on this issuer could match for the same proof" never
//! reaches a login: "Refuse the configuration rather than the logins."
//!
//! `collides` does not decide that question. It answers whether either rule is
//! unconditional or the two name the *same* claim and value. Two rules naming **different**
//! claims — `{org: acme}` and `{dept: eng}` — are admitted, and one proof carrying both
//! claims satisfies both. That is the ordinary shape of two tenants behind one corporate
//! IdP, not a contrived one: each picks the claim it is keyed on.
//!
//! `crates/mandate-federation/tests/adversary_pass2.rs:231` closed the *equal-rule* half of
//! this (the guard now refuses a copied rule). This is the half the exact-equality fix left
//! open.
//!
//! Why it is this story's business: `contracts/obligations/federation.json:453` publishes
//! `ProvisionExternalPrincipal`'s clause "tenant resolution has zero or multiple matches" as
//! decided on the real path, and the multiple half is decided by
//! `obligations::a_proof_matching_two_configured_tenants_is_refused_at_provisioning`, whose
//! projection is hand-folded from two `FederationConnectionCreated` events carrying *equal*
//! claim rules — the pair `register_federation_connection` refuses to create. These two
//! cases build the ambiguity out of registrations the shipped writer accepts, and the
//! writer accepting them is the defect.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use mandate_federation::authenticate::{ProvisionExternalPrincipal, provision_external_principal};
use mandate_federation::record::{
    ConnectionRegistered, Projection, RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::verifier_real::{
    AllowedAlgorithms, FixedClock, InMemoryJwks, RealVerifier,
};
use mandate_federation::{DenialClause, RequestContext, SequentialAllocator};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, FederationConnectionId,
    Issuer, OrganizationId, PrincipalId, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/one";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";
const ES256: &str = "ES256";
const NOW: u64 = 1_758_240_000;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(0x51)),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-obligations-federation"),
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("adversary-obligations-federation"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new("2026-09-18T00:00:00Z"),
    }
}

fn on_claim(organization_id: OrganizationId, name: &str, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

/// A registration of `issuer` for `organization_id` under one claim rule.
fn registration(
    organization_id: OrganizationId,
    name: &str,
    value: &str,
) -> RegisterFederationConnection {
    RegisterFederationConnection {
        context: context(organization_id),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: on_claim(organization_id, name, value),
        jit_provisioning: true,
    }
}

// ------------------------------------------------------------------ key material

struct Keys {
    signing: EncodingKey,
    published: Jwk,
    kid: String,
}

fn keys(kid: &str) -> Keys {
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
            .expect("a generated elliptic-curve key");
    let signing = EncodingKey::from_ec_der(pkcs8.as_ref());
    let mut published = Jwk::from_encoding_key(&signing, Algorithm::ES256).expect("a public JWK");
    published.common.key_id = Some(kid.to_owned());
    Keys {
        signing,
        published,
        kid: kid.to_owned(),
    }
}

/// A proof this issuer signed, carrying both tenants' claims.
fn proof_carrying_both(signing: &Keys) -> CredentialProof {
    let claims = serde_json::json!({
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": CLIENT,
        "iat": NOW,
        "exp": NOW + 300,
        "org": "acme",
        "dept": "eng",
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signing.kid.clone());
    let token = encode(&header, &claims, &signing.signing).expect("a signed token");
    CredentialProof::from_bytes(token.into_bytes())
}

/// The shipped verifier over the issuer's published key set, configured for `configured`.
fn verifier(
    signing: &Keys,
    configured: &[FederationConnectionId],
) -> RealVerifier<InMemoryJwks, FixedClock> {
    let source = InMemoryJwks::new();
    source.publish(
        &Issuer::new(ISSUER),
        serde_json::json!({"keys": [serde_json::to_value(&signing.published)
            .expect("a serializable JWK")]}),
    );
    let allowed = AllowedAlgorithms::configured(&[SigningAlgorithm::new(ES256)])
        .expect("a non-empty allowlist is admitted");
    let mut built = RealVerifier::new(allowed, source, FixedClock::at(NOW));
    for connection_id in configured {
        built = built
            .configure_connection(*connection_id, &SigningAlgorithm::new(ES256))
            .expect("an admitted algorithm for this connection");
    }
    built
}

/// Register organization 10's connection on the shared issuer, keyed on `{org: acme}`.
fn incumbent(allocator: &mut SequentialAllocator) -> ConnectionRegistered {
    register_federation_connection(
        &registration(organization(10), "org", "acme"),
        &Projection::default(),
        allocator,
    )
    .expect("the first connection on an unheld issuer is admitted")
}

// ==================================================================================
// The guard
// ==================================================================================

/// `register_federation_connection` refuses a second organization's rule on one issuer
/// that one proof could satisfy alongside the incumbent's — `record.rs:946-953`, "a rule
/// another organization's connection on this issuer could match for the same proof …
/// Refuse the configuration rather than the logins."
///
/// The two rules name different claims, so `collides` compares `"org"` with `"dept"`,
/// finds them unequal and answers `false`. A proof carrying both claims satisfies both
/// rules, which is the question `collides` documents itself as deciding.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21
/// (`review-result:wave-d-obligations-federation-adversary-1` F1): the pair is admitted.
/// `story:federation-rule-disjointness` turns this into a refusal; the assertion flips there.
#[test]
fn a_second_organizations_rule_one_proof_also_satisfies_is_admitted_at_registration() {
    let mut allocator = SequentialAllocator::new();
    let held = incumbent(&mut allocator);
    let before = Projection::fold(&[held.event]).expect("one connection");

    let intruder = register_federation_connection(
        &registration(organization(11), "dept", "eng"),
        &before,
        &mut allocator,
    );

    assert!(
        intruder.is_ok(),
        "the shipped guard admits a rule on a different claim name; a refusal here means \
         story:federation-rule-disjointness landed and this pin is stale: {:?}",
        intruder.err()
    );
}

/// The consequence, end to end through shipped handlers and the shipped verifier: the
/// incumbent's first login resolves, a second organization registers a rule on a different
/// claim, and the same login stops resolving. No command un-registers a connection, so
/// organization 10 cannot undo it.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21
/// (`review-result:wave-d-obligations-federation-adversary-1` F1): the login answers
/// `TenantAmbiguous`. `story:federation-rule-disjointness` keeps it resolving; the assertion
/// flips there.
#[test]
fn the_admitted_pair_ends_the_incumbents_logins_on_that_issuer() {
    let mut allocator = SequentialAllocator::new();
    let signing = keys("2026-09");
    let held = incumbent(&mut allocator);
    let before = Projection::fold(std::slice::from_ref(&held.event)).expect("one connection");
    let login = |fold: &Projection, verifier: &RealVerifier<InMemoryJwks, FixedClock>| {
        provision_external_principal(
            &ProvisionExternalPrincipal {
                connection_id: held.connection_id,
                proof: proof_carrying_both(&signing),
            },
            &request(),
            verifier,
            fold,
            fold,
            &mut SequentialAllocator::new(),
        )
    };

    login(&before, &verifier(&signing, &[held.connection_id]))
        .expect("organization 10's first login resolves before any second connection exists");

    let intruder = register_federation_connection(
        &registration(organization(11), "dept", "eng"),
        &before,
        &mut allocator,
    )
    .expect("the guard admits the pair; case one is where that is asserted");
    let after =
        Projection::fold(&[held.event, intruder.event]).expect("two connections on one issuer");

    let again = login(
        &after,
        &verifier(&signing, &[held.connection_id, intruder.connection_id]),
    );

    let denied = again.expect_err(
        "the incumbent's login still resolves, so story:federation-rule-disjointness' premise \
         no longer holds and this pin is stale",
    );
    assert_eq!(
        denied.clause,
        DenialClause::TenantAmbiguous,
        "the admitted pair ends the incumbent's logins on the ambiguity clause"
    );
}
