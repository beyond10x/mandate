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
//!
//! `story:federation-rule-disjointness` closed it: `collides` now holds two claim rules
//! disjoint only when they name the same claim with different values, and both cases assert
//! the refusal and the incumbent's login that keeps resolving.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use mandate_federation::authenticate::{ProvisionExternalPrincipal, provision_external_principal};
use mandate_federation::record::{
    ConnectionRegistered, FederationEvent, Projection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::verifier_real::{
    AllowedAlgorithms, FixedClock, InMemoryJwks, RealVerifier,
};
use mandate_federation::{DenialClause, RequestContext, SequentialAllocator};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason,
    FederationConnectionId, Issuer, OrganizationId, PrincipalId, SigningAlgorithm, Timestamp,
    VerifiedContext,
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
/// that one proof could satisfy alongside the incumbent's — "a rule another organization's
/// connection on this issuer could match for the same proof … Refuse the configuration
/// rather than the logins."
///
/// The two rules name different claims, `{org: acme}` and `{dept: eng}`. A proof carrying
/// both claims satisfies both rules, so `collides` answers that they collide and the
/// registration is refused on the unadmitted-configuration clause
/// (`review-result:wave-d-obligations-federation-adversary-1` F1, closed by
/// `story:federation-rule-disjointness`).
#[test]
fn a_second_organizations_rule_one_proof_also_satisfies_is_refused_at_registration() {
    let mut allocator = SequentialAllocator::new();
    let held = incumbent(&mut allocator);
    let before = Projection::fold(&[held.event]).expect("one connection");

    let denied = register_federation_connection(
        &registration(organization(11), "dept", "eng"),
        &before,
        &mut allocator,
    )
    .expect_err(
        "a rule on a different claim name is one a proof carrying both claims also \
         satisfies; the guard must refuse it",
    );

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::TenantResolutionUnadmitted);
}

/// The consequence, end to end through shipped handlers and the shipped verifier: the
/// incumbent's first login resolves, a second organization tries to register a rule on a
/// different claim, is refused, and the same login keeps resolving to the incumbent. No
/// command un-registers a connection, so the refusal at registration is the only place the
/// incumbent's logins can be protected.
#[test]
fn the_admitted_pair_ends_the_incumbents_logins_on_that_issuer() {
    let mut allocator = SequentialAllocator::new();
    let signing = keys("2026-09");
    let held = incumbent(&mut allocator);
    let mut log = vec![held.event.clone()];
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
    let before = Projection::fold(&log).expect("one connection");

    login(&before, &verifier(&signing, &[held.connection_id]))
        .expect("organization 10's first login resolves before any second connection exists");

    let intruder = register_federation_connection(
        &registration(organization(11), "dept", "eng"),
        &before,
        &mut allocator,
    );
    let mut configured = vec![held.connection_id];
    if let Ok(admitted) = &intruder {
        log.push(admitted.event.clone());
        configured.push(admitted.connection_id);
    }
    let after = Projection::fold(&log).expect("the connections the writer admitted");

    let again = login(&after, &verifier(&signing, &configured));

    assert!(
        intruder.is_err(),
        "the second organization's rule is refused at registration"
    );
    let provisioned = again.unwrap_or_else(|denied| {
        panic!("the incumbent's login keeps resolving after the refused registration: {denied:?}")
    });
    assert!(
        matches!(
            provisioned.event,
            FederationEvent::ExternalPrincipalProvisioned { organization_id, .. }
                if organization_id == organization(10)
        ),
        "the login resolves to the incumbent: {:?}",
        provisioned.event
    );
}
