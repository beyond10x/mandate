//! Adversarial cases against `story:federated-jit-login`.
//!
//! The unit composes `AuthenticateFederation` → `ProvisionExternalPrincipal` →
//! `AuthenticateFederation` in `Deployment::authenticate`
//! (`services/control-plane/src/adapters.rs`). These cases drive that composition against
//! the states the unit's own cases do not build: a link that an operator has explicitly
//! revoked, and a deployment holding more than one connection.
//!
//! Written by the adversary pass; no implementation file is touched.

use mandate_federation::disable::{UnlinkExternalPrincipal, unlink_external_principal};
use mandate_federation::record::{FederationEvent, LinkState};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_model::TenantResolutionRule;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{CountingSecrets, SequentialAllocator};
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, DenialReason, Duration,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PrincipalId, SigningAlgorithm,
    Uuid, VerifiedContext,
};

use mandate_control_plane::adapters::{Configuration, Deployment};

/// The issuer this deployment publishes; as `tests/serve.rs` states it.
const ISSUER: &str = "https://mandate.example";

/// 2026-09-19T00:00:00Z, the instant every case is decided at.
const NOW: u64 = 1_789_084_800;

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(0x0a))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(0x51))
}

fn connection() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc0))
}

/// A second connection of the same organization on the same issuer.
fn sibling() -> FederationConnectionId {
    FederationConnectionId::new(uuid(0xc1))
}

/// The verified context an operator's own administrative command carries.
fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("adversary"),
    }
}

/// The verifier double every case here uses: one issuer, one subject, one client, the same
/// answer on every call. Deterministic on purpose — the unit's own retry case turns on a
/// verifier that answers differently per call, and none of these do.
fn verifier() -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("ES256")],
        VerifiedProof::new(
            Issuer::new("https://idp.example"),
            ExternalSubject::new("subject-1"),
            ClientId::new("mandate-at-idp"),
        ),
    )
    .expect("a non-empty algorithm allowlist")
}

type Wired = Deployment<ConstructedVerifier, FixedClock, CountingSecrets, SequentialAllocator>;

/// A deployment holding nothing but the connections the case seeds.
fn bare_deployment() -> Wired {
    Deployment::new(
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
    .expect("a configuration this deployment serves")
}

/// Seed one connection of this organization on this issuer.
fn seed_connection(
    deployment: &mut Wired,
    connection_id: FederationConnectionId,
    jit_provisioning: bool,
) {
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id,
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning,
        })
        .expect("a readable federation history");
}

/// A deployment holding one connection and nothing linked through it.
fn deployment_admitting(jit_provisioning: bool) -> (Wired, FederationConnectionId) {
    let mut deployment = bare_deployment();
    seed_connection(&mut deployment, connection(), jit_provisioning);
    (deployment, connection())
}

/// The login the verifier double admits, as the decoded input the route hands the adapter.
fn login_input(connection_id: FederationConnectionId) -> decode::AuthenticateFederation {
    decode::AuthenticateFederation {
        connection_id,
        proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
    }
}

/// Drive `mandate.federation.UnlinkExternalPrincipal` against the deployment's own fold and
/// seed the event its accepted outcome emits — the operator's revocation of a federated
/// identity, through the one command `federation.yaml` declares for it.
fn revoke_the_only_link(deployment: &mut Wired) {
    let link_id = deployment
        .federation()
        .links()
        .first()
        .expect("a link to revoke")
        .id;
    let unlinked = unlink_external_principal(
        &UnlinkExternalPrincipal {
            id: link_id,
            context: context(),
        },
        deployment.federation(),
    )
    .expect("the declared accepted outcome of UnlinkExternalPrincipal");
    deployment
        .record_federation(&unlinked)
        .expect("a readable federation history");
}

// ---------------------------------------------------------------------------------------
// The revoked subject
// ---------------------------------------------------------------------------------------

/// An external principal an operator has explicitly unlinked must not be handed back its
/// access by the next login.
///
/// `mandate.federation.ExternalPrincipal.Unlinked` is a **terminal** state
/// (`systems/mandate/domains/federation.yaml`, entity `ExternalPrincipal`, `terminal:
/// [Unlinked]`), and `UnlinkExternalPrincipal` is the only revocation this domain declares
/// for a federated identity — its denial clause names "unlinking and its required
/// invalidation/audit". `crates/mandate-federation/src/disable.rs` states what the terminal
/// state leaves open: the record "stops holding the composite external key, which is what
/// lets the same subject be **linked again**" — by `LinkExternalPrincipal`, which takes a
/// `mandate.core.VerifiedContext` and is therefore an *administrative* act.
///
/// `Deployment::authenticate`'s new sequence turns that administrative affordance into an
/// automatic one: the login that follows the revocation finds no `Linked` record on the
/// key, reads `jit_provisioning` off the connection, drives `ProvisionExternalPrincipal`,
/// and the retry resolves the link it just made. The revoked caller is admitted, under a
/// **new** `PrincipalId` that carries none of the revoked principal's history.
#[test]
fn a_revoked_external_principal_is_not_reprovisioned_by_the_next_login() {
    let (mut deployment, connection_id) = deployment_admitting(true);

    let first = deployment
        .authenticate(&login_input(connection_id))
        .expect("a connection admitting provisioning opens the first login a session");
    assert_eq!(
        deployment.federation().links().len(),
        1,
        "the first login provisions exactly one link"
    );

    revoke_the_only_link(&mut deployment);
    assert_eq!(
        deployment.federation().links()[0].state,
        LinkState::Unlinked,
        "the revocation moved the record to its terminal state"
    );

    let after = deployment.authenticate(&login_input(connection_id));

    assert!(
        after.is_err(),
        "a revoked external principal must not be admitted by the next login; it was admitted \
         for principal {:?} (the revoked one was {:?})",
        after.as_ref().ok().map(|login| login.principal_id),
        first.principal_id,
    );
    assert_eq!(
        deployment.federation().links().len(),
        1,
        "the revoked record is the only one: the login after a revocation provisions nothing, \
         got {:?}",
        deployment.federation().links(),
    );
}

/// The control for the case above: the same revocation on a connection that does not admit
/// provisioning. The refusal stands and the fold keeps exactly the revoked record.
///
/// This is what isolates the just-in-time branch as the cause rather than anything in
/// `mandate-federation`: the same fold, the same key, the same verifier, one flag apart.
#[test]
fn a_revoked_external_principal_stays_revoked_when_the_connection_admits_no_provisioning() {
    // The same revoked state as the case above, behind a connection that admits no
    // provisioning: a link recorded through it and then unlinked.
    let mut refusing = bare_deployment();
    seed_connection(&mut refusing, sibling(), false);
    for event in [
        FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: sibling(),
            principal_id: principal(),
            external_principal_id: mandate_types::ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: mandate_types::ExternalLinkMethod::ConfiguredFederation,
            linked_at: mandate_types::Timestamp::new("2026-09-19T00:00:00Z"),
        },
        FederationEvent::ExternalPrincipalUnlinked {
            context: context(),
            id: mandate_types::ExternalPrincipalId::new(uuid(0xe1)),
        },
    ] {
        refusing
            .record_federation(&event)
            .expect("a readable federation history");
    }

    let refusal = refusing
        .authenticate(&login_input(sibling()))
        .expect_err("a connection admitting no provisioning authenticates a revoked subject not");

    assert_eq!(
        refusal.clause, "LinkAbsent",
        "the refusal is `AuthenticateFederation`'s own"
    );
    assert_eq!(
        refusal.reason,
        DenialReason::Denied,
        "the declared reason of `LinkAbsent`"
    );
    assert_eq!(
        refusing.federation().links().len(),
        1,
        "a connection that does not admit provisioning creates nothing, got {:?}",
        refusing.federation().links(),
    );
}

// ---------------------------------------------------------------------------------------
// Whose flag admits the provisioning
// ---------------------------------------------------------------------------------------

/// `jit_provisioning` is read off the connection **the request selected**, and a sibling
/// connection of the same organization on the same issuer that admits provisioning does not
/// admit it on the selected one.
///
/// The unit's own cases hold one connection each, so nothing in them distinguishes "the
/// selected connection's flag" from "any connection's flag": a composition that read the
/// flag off the projection at large would pass every one of them. This case would catch
/// that.
#[test]
fn a_sibling_connection_that_admits_provisioning_does_not_admit_it_on_the_selected_one() {
    let mut deployment = bare_deployment();
    // The selected connection refuses provisioning; its sibling on the same issuer and in
    // the same organization admits it.
    seed_connection(&mut deployment, connection(), false);
    seed_connection(&mut deployment, sibling(), true);

    let refusal = deployment
        .authenticate(&login_input(connection()))
        .expect_err("the selected connection admits no provisioning");

    assert_eq!(
        refusal.clause, "LinkAbsent",
        "the selected connection's own refusal stands, got {refusal:?}"
    );
    assert!(
        deployment.federation().links().is_empty(),
        "a sibling's flag creates nothing on this connection, got {:?}",
        deployment.federation().links(),
    );
}
