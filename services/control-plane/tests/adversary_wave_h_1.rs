//! Adversary pass 1 against `story:link-absent-discriminates` (`e9f69cf`), composition half.
//!
//! `e9f69cf` removed `Deployment::key_holds_no_record` and its call site, so the one
//! in-tree composition now inherits the refusal from the command alone. Two things the
//! suite it shipped with does not measure:
//!
//! 1. the recovery path `serve.rs` documents, driven through a `link_method` the domain's
//!    own `LinkExternalPrincipal` may actually use;
//! 2. a key holding **more than one** revoked record, which is the state the removed
//!    pre-check answered by scanning every record and the library now answers by
//!    `Projection::link`'s fallback.

use mandate_control_plane::adapters::{Configuration, Deployment};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, Duration, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OrganizationId,
    PrincipalId, Timestamp, Uuid, VerifiedContext,
};

const ISSUER: &str = "https://mandate.example";
const NOW: u64 = 1_789_084_800;
const SUBJECT: &str = "subject-1";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary-wave-h-1"),
    }
}

fn verifier() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[mandate_types::SigningAlgorithm::new("ES256")],
        VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new(SUBJECT),
            ClientId::new("mandate-at-idp"),
        ),
    )
    .expect("a non-empty algorithm allowlist")
}

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

fn deployment() -> (Wired, FederationConnectionId) {
    let mut deployment = Deployment::new(
        Configuration {
            issuer: ISSUER.to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        verifier(),
        FixedClock::at(NOW),
        CountingSecrets::new(),
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: mandate_model::TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: true,
        })
        .expect("a readable federation history");
    (deployment, connection())
}

fn login_input(connection_id: FederationConnectionId) -> decode::AuthenticateFederation {
    decode::AuthenticateFederation {
        connection_id,
        proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
    }
}

/// The recovery path, driven with a `link_method` `LinkExternalPrincipal` may use, and then
/// revoked a second time.
///
/// `serve.rs`'s `an_explicitly_relinked_subject_logs_in_again_and_provisions_nothing`
/// documents its fixture as "An administrator's `LinkExternalPrincipal` on the same key ...
/// the command a revoked user comes back through", and records an
/// `ExternalPrincipalLinked` carrying `link_method: ConfiguredFederation`. That is the one
/// method the command refuses: `link_external_principal`
/// (`crates/mandate-federation/src/link.rs`) denies `LinkingAuthority` for it, because it is
/// what `ProvisionExternalPrincipal` writes on first login and a caller may not name it. No
/// command in this domain emits that event, so the only composition-level evidence that
/// revocation is a revocation and not a brick rests on a log the write path cannot produce.
/// This case drives the same recovery with `ExternalLinkMethod::Administrator`.
///
/// It then revokes the administrator's link as well, which puts **two** `Unlinked` records
/// on one key. The removed `Deployment::key_holds_no_record` answered that state by scanning
/// every record; `Projection::link`'s fallback answers it by returning the smallest record
/// that remains. The composition must still answer `LinkAbsent` and create nothing.
#[test]
fn the_lawful_relink_recovers_and_a_second_revocation_is_not_provisioned_around() {
    let (mut deployment, connection_id) = deployment();
    let first = deployment
        .authenticate(&login_input(connection_id))
        .expect("the first login provisions the principal it opens a session for");
    let provisioned = deployment.federation().links()[0].clone();

    deployment
        .record_federation(&FederationEvent::ExternalPrincipalUnlinked {
            context: context(),
            id: provisioned.id,
        })
        .expect("a readable federation history");

    // The recovery, through the only `link_method` `LinkExternalPrincipal` admits.
    let administrators = ExternalPrincipalId::new(uuid(0xe5));
    deployment
        .record_federation(&FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id,
            principal_id: principal(0x51),
            external_principal_id: administrators,
            subject: ExternalSubject::new(SUBJECT),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: Timestamp::new("2026-09-21T00:00:00Z"),
        })
        .expect("a readable federation history");

    let login = deployment
        .authenticate(&login_input(connection_id))
        .expect("the explicitly relinked subject logs in again");
    assert_eq!(
        login.principal_id,
        principal(0x51),
        "the session is for the principal the administrator linked"
    );
    assert_ne!(
        login.principal_id, first.principal_id,
        "and not the one the revoked provisioning created"
    );
    assert_eq!(
        deployment.federation().links().len(),
        2,
        "the revoked record and the administrator's, and nothing this login created, got {:?}",
        deployment.federation().links()
    );

    // And revoked again: two `Unlinked` records now hold one key.
    deployment
        .record_federation(&FederationEvent::ExternalPrincipalUnlinked {
            context: context(),
            id: administrators,
        })
        .expect("a readable federation history");

    let refusal = deployment
        .authenticate(&login_input(connection_id))
        .expect_err("every record on the key is revoked, so the login has no linked principal");
    assert_eq!(
        refusal.clause, "LinkAbsent",
        "the login's own clause stands; a refused provisioning is not the login's refusal"
    );
    assert_eq!(
        deployment.federation().links().len(),
        2,
        "a key two revoked records hold is not free to create a third on, got {:?}",
        deployment.federation().links()
    );
    let principals: Vec<PrincipalId> = deployment
        .federation()
        .links()
        .iter()
        .map(|record| record.principal_id)
        .collect();
    assert_eq!(
        principals,
        vec![first.principal_id, principal(0x51)],
        "no revocation on this key was answered with a new principal for the same subject"
    );
}
