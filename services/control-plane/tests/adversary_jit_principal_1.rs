//! Adversarial pass 1 on `story:jit-principal-record`.
//!
//! `Deployment::provisioned` folds the provisioning event into the federation read model
//! first and the identity read model second, and answers `false` when the second refuses.
//! Its own header states what `false` means to the caller: "a refused command and a fold
//! that cannot read the event it emitted are the same thing to the caller, which is a login
//! that still has no linked principal". This case builds the one state in which the identity
//! fold refuses an event the federation fold accepted — the identity log already holds a
//! creation for the principal identity the deployment is about to mint — and reads what
//! `false` left behind.
//!
//! The state is **constructed**: it is reached through the public `record_identity` and a
//! deterministic secret source. Production mints principal identities from a CSPRNG and no
//! production caller of `record_identity` exists, so this measures the ordering, not a road
//! anybody is shown to drive.

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
use mandate_identity::IdentityEvent;
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

/// A deployment with one connection that admits provisioning, built the same way every time.
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

/// A provisioning the identity fold admits, for a principal identity and a subject of the
/// caller's choosing.
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

/// A provisioning the identity fold refuses leaves no link behind.
///
/// `provisioned` answers `false` when `identity.try_record` refuses, and its header says
/// `false` is "a login that still has no linked principal". The federation fold was written
/// before the identity fold decided, so the refused login leaves a link to a principal the
/// identity fold holds no record of *from this provisioning* — and the retry that the
/// caller was told would still see no link authenticates against it.
#[test]
fn a_provisioning_the_identity_fold_refuses_leaves_no_federation_link() {
    // The principal identity a first login on this deployment mints, read off an identical
    // deployment: the secret source and clock are deterministic.
    let minted = deployment()
        .authenticate(&login())
        .expect("a first login provisions and opens a session")
        .principal_id;

    let mut deployment = deployment();
    deployment.record_identity(provisioned(&minted, "someone-else"));

    let refused = deployment.authenticate(&login());
    assert!(
        refused.is_err(),
        "the identity fold refuses a second creation of {minted:?}, so provisioning answers false"
    );
    assert!(
        deployment.federation().links().is_empty(),
        "a login refused because the identity fold would not record its principal left {} \
         federation link(s) behind; `provisioned` wrote the federation fold before the identity \
         fold decided",
        deployment.federation().links().len()
    );
}
