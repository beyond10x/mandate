//! `story:control-plane-multi-fold-writes`: a control-plane command that writes several
//! folds keeps none of the earlier writes when a later one is refused.
//!
//! The one site of the three that a refusal reaches is `OpeningSessionIssuer::issue`
//! (`services/control-plane/src/adapters.rs`): a login records up to three
//! `SecurityEpochRecorded`, then an `EpochSnapshotRecorded`, then a `SessionOpened`, each
//! through `IdentityLog::try_record`. The other two — the `FederationAuthenticated` fold in
//! `authenticate_once` and the credential fold in `redeem` — are unreachable and documented
//! at the site.
//!
//! The refusal is reached here through a secret source that answers the same secret on every
//! draw, so every identity a deployment mints is one identity, learnt from a probe login. A
//! snapshot the log already records under that handle refuses the login's own snapshot
//! *after* the login has recorded the generations of three dimensions nothing had touched.

use mandate_control_plane::adapters::{Configuration, Deployment};
use mandate_federation::record::FederationEvent;
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::verifier_real::FixedClock;
use mandate_identity::{EpochSnapshotRecorded, Generation, IdentityEvent, SecurityEpochRecorded};
use mandate_model::TenantResolutionRule;
use mandate_server::decode;
use mandate_sts::code::CodeLifetime;
use mandate_sts::{SecretSource, SequentialAllocator};
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, CredentialSecret, Duration,
    EpochSnapshotRef, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject,
    FederationConnectionId, Issuer, OrganizationId, PrincipalId, SecurityEpochTarget,
    SigningAlgorithm, Timestamp, Uuid, VerifiedContext,
};

/// 2026-09-19T00:00:00Z, the instant every case is decided at.
const NOW: u64 = 1_789_084_800;

/// A secret source that answers one secret on every draw.
///
/// A fixture for reaching a collision, never a shipped source: every identity a deployment
/// mints from it is the same identity.
#[derive(Debug, Default)]
struct OneSecret;

impl SecretSource for OneSecret {
    fn next_secret(&mut self) -> CredentialSecret {
        CredentialSecret::from_bytes(b"the only secret".to_vec())
    }
}

type Wired = Deployment<ConstructedVerifier, FixedClock, OneSecret, SequentialAllocator>;

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

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("multi-fold"),
    }
}

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

/// A deployment holding one connection and one explicit link through it.
fn linked_deployment() -> Wired {
    let mut deployment = Deployment::new(
        Configuration {
            issuer: "https://mandate.example".to_owned(),
            code_lifetime: CodeLifetime::new(Duration::new("PT5M")),
            session_lifetime: Duration::new("PT8H"),
            keys: Vec::new(),
        },
        verifier(),
        FixedClock::at(NOW),
        OneSecret,
        SequentialAllocator::new(),
    )
    .expect("a configuration this deployment serves");
    deployment
        .record_federation(&FederationEvent::FederationConnectionCreated {
            context: context(),
            connection_id: connection(),
            issuer: Issuer::new("https://idp.example"),
            client_id: ClientId::new("mandate-at-idp"),
            tenant_resolution: TenantResolutionRule {
                configured_organization: organization(),
                verified_claim_name: None,
                verified_claim_value: None,
            },
            jit_provisioning: false,
        })
        .expect("a readable federation history");
    deployment
        .record_federation(&FederationEvent::ExternalPrincipalLinked {
            context: context(),
            connection_id: connection(),
            principal_id: principal(),
            external_principal_id: ExternalPrincipalId::new(uuid(0xe1)),
            subject: ExternalSubject::new("subject-1"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-01T00:00:00Z"),
        })
        .expect("a readable federation history");
    deployment
}

fn login_input() -> decode::AuthenticateFederation {
    decode::AuthenticateFederation {
        connection_id: connection(),
        proof: CredentialProof::from_bytes(b"an idp proof".to_vec()),
    }
}

/// The snapshot handle every login on a [`OneSecret`] deployment mints, read off a login
/// that nothing refuses.
fn the_handle_every_login_mints() -> EpochSnapshotRef {
    linked_deployment()
        .authenticate(&login_input())
        .expect("a linked subject on an enabled connection is admitted")
        .epochs
}

/// A login whose session the identity fold refuses leaves that fold exactly as it found it.
///
/// The snapshot is refused because the log already records its handle — under three other
/// dimensions, each stated first as the fold requires. The login's own three dimensions have
/// no generation yet, so the issuer states each of them before it reaches the snapshot. Kept,
/// those three records outlive a login that was refused: an epoch stated for a session that
/// was never opened.
#[test]
fn a_refused_session_opening_records_no_generation() {
    let handle = the_handle_every_login_mints();
    let mut deployment = linked_deployment();
    for target in [
        SecurityEpochTarget::Principal(PrincipalId::new(uuid(0x52))),
        SecurityEpochTarget::Organization(OrganizationId::new(uuid(0x0b))),
        SecurityEpochTarget::Federation(FederationConnectionId::new(uuid(0xc9))),
    ] {
        deployment.record_identity(IdentityEvent::SecurityEpochRecorded(
            SecurityEpochRecorded {
                target,
                generation: Generation::ZERO,
            },
        ));
    }
    deployment.record_identity(IdentityEvent::EpochSnapshotRecorded(
        EpochSnapshotRecorded {
            id: handle,
            principal_id: PrincipalId::new(uuid(0x52)),
            organization_id: OrganizationId::new(uuid(0x0b)),
            connection_id: Some(FederationConnectionId::new(uuid(0xc9))),
        },
    ));
    let before = deployment.identity().clone();
    assert_eq!(
        before.events().len(),
        4,
        "the seeded history is the four events above"
    );

    let refused = deployment
        .authenticate(&login_input())
        .expect_err("a snapshot handle the log already records opens no session");

    assert_eq!(refused.clause, "SessionUnknown", "{refused:?}");
    assert_eq!(
        deployment.identity(),
        &before,
        "a refused login leaves the identity fold as it found it"
    );
}

/// The copy the issuer records into is the one the deployment keeps when nothing refuses:
/// every event of an accepted login is in the fold afterwards, in order.
#[test]
fn an_accepted_session_opening_keeps_every_record() {
    let mut deployment = linked_deployment();
    let login = deployment
        .authenticate(&login_input())
        .expect("a linked subject on an enabled connection is admitted");

    let events = deployment.identity().events();
    assert_eq!(
        events.len(),
        5,
        "three generations, a snapshot, a session: {events:?}"
    );
    assert!(matches!(
        &events[3],
        IdentityEvent::EpochSnapshotRecorded(snapshot) if snapshot.id == login.epochs
    ));
    assert!(matches!(
        &events[4],
        IdentityEvent::SessionOpened(opened) if opened.id == login.session_id
    ));
}
