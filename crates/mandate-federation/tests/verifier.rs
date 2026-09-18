//! The verifier port's double.
//!
//! `decision-blocker:algorithm-policy` withholds the admitted algorithm names until an
//! approving authority records them, so no test in this file names one. What is
//! exercised is the shape the decision fixed: the allowlist is a constructor argument,
//! and an empty set is refused.
//!
//! No corpus case in `tests/security/cases.json` names this file's subject.

use mandate_federation::record::{ConnectionState, FederationConnection};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{DenialClause, FederationVerifier};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    ClientId, CredentialProof, DenialReason, ExternalSubject, FederationConnectionId, Issuer,
    OrganizationId, REDACTED, SigningAlgorithm,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn allowlist() -> Vec<SigningAlgorithm> {
    // A configured name stands in for the deployment's own list. The admitted names are
    // withheld (`docs/architecture/runtime-decisions.md`), so none is written here.
    vec![SigningAlgorithm::new("configured-by-deployment")]
}

fn connection() -> FederationConnection {
    let organization_id = OrganizationId::new(uuid(10));
    FederationConnection {
        id: FederationConnectionId::new(uuid(1)),
        organization_id,
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization_id,
            verified_claim_name: None,
            verified_claim_value: None,
        },
        jit_provisioning: false,
        state: ConnectionState::Enabled,
    }
}

fn proof() -> VerifiedProof {
    VerifiedProof::new(
        Issuer::new("https://idp.example/one"),
        ExternalSubject::new("subject-one"),
        ClientId::new("configured-client"),
    )
}

fn presented() -> CredentialProof {
    CredentialProof::from_bytes(b"proof-material-marker".to_vec())
}

#[test]
fn an_admitting_double_returns_what_it_was_constructed_with() {
    let verifier = ConstructedVerifier::admitting(&allowlist(), proof())
        .expect("a non-empty allowlist is admitted");

    let verified = verifier
        .verify(&connection(), &presented())
        .expect("this double admits by construction");

    assert_eq!(verified.issuer(), &Issuer::new("https://idp.example/one"));
    assert_eq!(verified.subject(), &ExternalSubject::new("subject-one"));
    assert_eq!(verified.audience(), &ClientId::new("configured-client"));
}

#[test]
fn a_refusing_double_denies_every_proof() {
    let verifier =
        ConstructedVerifier::refusing(&allowlist()).expect("a non-empty allowlist is admitted");

    let denied = verifier
        .verify(&connection(), &presented())
        .expect_err("this double refuses by construction");

    assert_eq!(denied.reason, DenialReason::InvalidCredential);
    assert_eq!(denied.clause, DenialClause::ProofInvalid);
}

#[test]
fn an_empty_algorithm_allowlist_is_refused_by_either_constructor() {
    for denied in [
        ConstructedVerifier::admitting(&[], proof())
            .expect_err("an empty allowlist is not a policy"),
        ConstructedVerifier::refusing(&[]).expect_err("an empty allowlist is not a policy"),
    ] {
        assert_eq!(denied.reason, DenialReason::InvalidCredential);
        assert_eq!(denied.clause, DenialClause::AlgorithmPolicy);
    }
}

#[test]
fn the_configured_allowlist_is_carried_verbatim() {
    let verifier = ConstructedVerifier::admitting(&allowlist(), proof())
        .expect("a non-empty allowlist is admitted");

    assert_eq!(verifier.admitted_algorithms(), allowlist().as_slice());
}

#[test]
fn a_refusal_carries_no_proof_material() {
    let verifier =
        ConstructedVerifier::refusing(&allowlist()).expect("a non-empty allowlist is admitted");
    let presented = presented();

    let denied = verifier
        .verify(&connection(), &presented)
        .expect_err("this double refuses by construction");

    let rendering = format!("{denied:?}");
    assert!(
        !rendering.contains("proof-material-marker"),
        "a denial renders no credential material: {rendering}"
    );
    assert!(
        format!("{presented:?}").contains(REDACTED),
        "the presented proof itself renders redacted"
    );
}

#[test]
fn a_validated_claim_and_an_unvalidated_hint_are_separate_reads() {
    let verified = proof()
        .with_verified_claim("org", "acme")
        .with_unverified_hint("org", "beta");

    assert_eq!(verified.verified_claim("org"), Some("acme"));
    assert_eq!(verified.unverified_hint("org"), Some("beta"));
    assert_eq!(
        verified.verified_claim("email_domain"),
        None,
        "a value that was never validated is not readable as a validated one"
    );
}
