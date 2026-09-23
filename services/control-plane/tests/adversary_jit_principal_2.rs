//! Adversarial pass 2 on `story:jit-principal-record`.
//!
//! The correction (4b0f452) folds the provisioning event into a clone of the federation
//! fold, lets the identity fold record or refuse, and swaps the clone in only on
//! acceptance. These cases read what that copy-then-swap leaves behind across a refusal
//! and across the retries that follow it: the whole federation fold unchanged, the identity
//! log unchanged, and exactly one record per provisioning thereafter — no lost state and no
//! double application.
//!
//! The refusal state is **constructed** exactly as pass 1 constructed it (a pre-recorded
//! creation for the identity the deployment is about to mint); production reaches it
//! through nothing found.

use mandate_contract::events::MandateFederationExternalPrincipalProvisioned;
use mandate_contract::types::{
    MandateCoreCorrelationId, MandateCoreExternalLinkMethod, MandateCoreExternalPrincipalId,
    MandateCoreExternalSubject, MandateCoreFederationConnectionId, MandateCoreOrganizationId,
    MandateCorePrincipalId, MandateCorePrincipalKind,
};
use mandate_control_plane::adapters::{Configuration, Deployment};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_identity::{IdentityEvent, IdentityRead};
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_types::{
    Audience, CorrelationId, CredentialId, CredentialProof, Duration, FederationConnectionId,
    OrganizationId, PrincipalId, Uuid, VerifiedContext,
};

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn connection_id() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

fn deployment() -> Wired {
    let mut deployment = Deployment::new(
        Configuration {
            issuer: "https://mandate.example".to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        ConstructedVerifier::admitting(
            &[mandate_types::SigningAlgorithm::new("ES256")],
            VerifiedProof::new(
                mandate_types::Issuer::new("https://idp.example"),
                mandate_types::ExternalSubject::new("subject-1"),
                mandate_types::ClientId::new("mandate-at-idp"),
            ),
        )
        .expect("a non-empty algorithm allowlist"),
        FixedClock::at(1_789_084_800),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: VerifiedContext {
                subject: PrincipalId::new(uuid(0x51)),
                actor: None,
                organization: organization(),
                audience: Audience::new("mandate"),
                credential: CredentialId::new(uuid(0xcd)),
                delegation: None,
                execution: None,
                correlation: CorrelationId::new("adversary"),
            },
            connection_id: connection_id(),
            issuer: mandate_types::Issuer::new("https://idp.example"),
            client_id: mandate_types::ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: true,
        })
        .expect("a readable federation history");
    deployment
}

fn login() -> mandate_server::decode::AuthenticateFederation {
    mandate_server::decode::AuthenticateFederation {
        connection_id: connection_id(),
        proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
    }
}

fn provisioned(principal: &PrincipalId, subject: &str) -> IdentityEvent {
    IdentityEvent::ExternalPrincipalProvisioned(MandateFederationExternalPrincipalProvisioned {
        organization_id: MandateCoreOrganizationId(organization().to_string()),
        correlation: MandateCoreCorrelationId("adversary".to_owned()),
        connection_id: MandateCoreFederationConnectionId(connection_id().to_string()),
        principal_id: MandateCorePrincipalId(principal.to_string()),
        kind: MandateCorePrincipalKind::User,
        display_name: "earlier".to_owned(),
        external_principal_id: MandateCoreExternalPrincipalId(uuid(0xe1).to_string()),
        subject: MandateCoreExternalSubject(subject.to_owned()),
        link_method: MandateCoreExternalLinkMethod::ConfiguredFederation,
        linked_at: "2026-09-01T00:00:00Z".to_owned(),
    })
}

fn provisionings(deployment: &Wired) -> usize {
    deployment
        .identity()
        .events()
        .iter()
        .filter(|event| matches!(event, IdentityEvent::ExternalPrincipalProvisioned(_)))
        .count()
}

/// A refused provisioning leaves the whole federation fold and the identity log exactly as
/// they were — not only the link list pass 1 read.
#[test]
fn a_refused_provisioning_leaves_both_folds_exactly_as_they_were() {
    let minted = deployment()
        .authenticate(&login())
        .expect("a first login provisions and opens a session")
        .principal_id;

    let mut deployment = deployment();
    deployment.record_identity(provisioned(&minted, "someone-else"));
    let federation_before = deployment.federation().clone();
    let identity_before = deployment.identity().events().len();

    assert!(deployment.authenticate(&login()).is_err());
    assert_eq!(
        deployment.federation(),
        &federation_before,
        "a refused provisioning changed the federation fold"
    );
    assert_eq!(
        deployment.identity().events().len(),
        identity_before,
        "a refused provisioning changed the identity log"
    );
}

/// The retry after a refusal provisions once, and every login after it provisions nothing:
/// the swap neither loses the earlier fold nor applies the event a second time.
#[test]
fn the_retry_after_a_refusal_provisions_exactly_once() {
    let minted = deployment()
        .authenticate(&login())
        .expect("a first login provisions and opens a session")
        .principal_id;

    let mut deployment = deployment();
    deployment.record_identity(provisioned(&minted, "someone-else"));
    assert!(deployment.authenticate(&login()).is_err());

    let retried = deployment
        .authenticate(&login())
        .expect("the retry draws a fresh principal identity and provisions it");
    assert_ne!(retried.principal_id, minted);
    let again = deployment
        .authenticate(&login())
        .expect("a linked subject logs in through its link");
    assert_eq!(again.principal_id, retried.principal_id);

    let links = deployment.federation().links();
    assert_eq!(links.len(), 1, "one provisioning, one link: {links:?}");
    assert_eq!(links[0].principal_id, retried.principal_id);
    assert!(
        deployment.federation().conflicts().is_empty(),
        "the swap double-applied a link"
    );
    assert_eq!(
        deployment.federation().connections().len(),
        1,
        "the swap lost or duplicated the connection folded before it"
    );
    assert_eq!(
        provisionings(&deployment),
        2,
        "the pre-recorded creation plus exactly one from the retry"
    );
    assert!(
        deployment
            .identity()
            .principal(&retried.principal_id)
            .is_some()
    );
}

/// On a clean deployment, repeated logins provision exactly once in both folds.
#[test]
fn repeated_logins_provision_once_in_both_folds() {
    let mut deployment = deployment();
    let first = deployment.authenticate(&login()).expect("first login");
    for _ in 0..3 {
        let next = deployment.authenticate(&login()).expect("a later login");
        assert_eq!(next.principal_id, first.principal_id);
    }
    assert_eq!(deployment.federation().links().len(), 1);
    assert_eq!(provisionings(&deployment), 1);
}
