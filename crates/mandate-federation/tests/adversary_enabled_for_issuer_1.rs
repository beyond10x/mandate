//! Adversary pass 1 over `story:enabled-for-issuer-filters-in-the-implementor`.
//!
//! The unit moved the `Enabled` + exact-issuer filter into the crate
//! (`enabled_on_issuer`), but that filter still reads `state` off the record the store's
//! enumeration handed it, not off `ConnectionStore::connection(id)`. The crate's own
//! `Projection` can hand it an `Enabled` copy of a connection `connection(id)` answers
//! `Disabled`: the `FederationConnectionCreated` fold arm is a plain push, not the
//! insert-if-absent the rest of the workspace keeps for a redelivered creation
//! (`src/record.rs:627`, "which the kit's at-least-once delivery admits").
//!
//! The expected decision in every case is the one the same log produces without the
//! redelivered event: `fold([.., e, ..e]) == fold([.., e, ..])` is the redelivery rule.

use mandate_federation::authenticate::{AuthenticateFederation, authenticate_federation};
use mandate_federation::record::{
    ConnectionState, FederationEvent, Projection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    ConnectionStore, DenialClause, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PrincipalId, SigningAlgorithm,
    Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/one";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
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
        correlation: CorrelationId::new("adversary-enabled-for-issuer"),
    }
}

fn rule(organization_id: OrganizationId, claim: Option<(&str, &str)>) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: claim.map(|(name, _)| name.to_owned()),
        verified_claim_value: claim.map(|(_, value)| value.to_owned()),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    tenant_resolution: TenantResolutionRule,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new(CLIENT),
        tenant_resolution,
        jit_provisioning: false,
    }
}

fn disabled(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
) -> FederationEvent {
    FederationEvent::FederationConnectionDisabled {
        context: context(organization_id),
        id: connection_id,
    }
}

fn linked(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization_id),
        connection_id,
        principal_id: PrincipalId::new(uuid(0x21)),
        external_principal_id: mandate_types::ExternalPrincipalId::new(uuid(0x71)),
        subject: ExternalSubject::new(SUBJECT),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: Timestamp::new("2026-09-18T00:00:00Z"),
    }
}

fn authenticate(
    projection: &Projection,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
) -> Result<OrganizationId, DenialClause> {
    authenticate_federation(
        &AuthenticateFederation {
            connection_id,
            proof: CredentialProof::from_bytes(b"proof-material-marker".to_vec()),
        },
        &RequestContext {
            audience: Audience::new("mandate"),
            correlation: CorrelationId::new("adversary-enabled-for-issuer"),
            credential: CredentialId::new(uuid(0xcd)),
            at: Timestamp::new("2026-09-18T00:00:00Z"),
        },
        verifier,
        projection,
        projection,
        &mut RecordingSessionIssuer::new(),
    )
    .map(|authenticated| authenticated.organization_id)
    .map_err(|denied| denied.clause)
}

fn admitting_acme() -> ConstructedVerifier {
    let proof = VerifiedProof::new(
        Issuer::new(ISSUER),
        ExternalSubject::new(SUBJECT),
        ClientId::new(CLIENT),
    )
    .with_verified_claim("org", "acme");
    ConstructedVerifier::admitting(&[SigningAlgorithm::new("configured-by-deployment")], proof)
        .expect("a non-empty allowlist is admitted")
}

/// The shape the unit's filter trusts: a record the enumeration answers `Enabled` for an
/// identity `connection(id)` answers `Disabled`. Folded from a redelivered creation.
#[test]
fn a_redelivered_connection_creation_after_a_disable_is_not_enabled_on_the_issuer() {
    let projection = Projection::fold(&[
        created(
            connection(2),
            organization(11),
            rule(organization(11), None),
        ),
        disabled(connection(2), organization(11)),
        created(
            connection(2),
            organization(11),
            rule(organization(11), None),
        ),
    ])
    .expect("a redelivered creation leaves the log readable");

    assert_eq!(
        projection.connection(&connection(2)).map(|held| held.state),
        Some(ConnectionState::Disabled),
    );
    let enabled: Vec<FederationConnectionId> = projection
        .enabled_for_issuer(&Issuer::new(ISSUER))
        .into_iter()
        .filter(|held| held.state == ConnectionState::Enabled)
        .map(|held| held.id)
        .collect();
    assert_eq!(
        enabled,
        Vec::<FederationConnectionId>::new(),
        "a disabled connection is answered Enabled beside its own Disabled record"
    );
}

/// `story:enabled-for-issuer-filters-in-the-implementor` acceptance, through the crate's
/// own store: a `Disabled` connection for the issuer changes no decision. It does.
#[test]
fn a_redelivered_disabled_sibling_changes_no_authentication() {
    let without = vec![
        created(
            connection(2),
            organization(11),
            rule(organization(11), Some(("org", "acme"))),
        ),
        disabled(connection(2), organization(11)),
        created(
            connection(1),
            organization(10),
            rule(organization(10), Some(("org", "acme"))),
        ),
        linked(connection(1), organization(10)),
    ];
    let mut with = without.clone();
    with.push(created(
        connection(2),
        organization(11),
        rule(organization(11), Some(("org", "acme"))),
    ));

    let verifier = admitting_acme();
    let expected = authenticate(
        &Projection::fold(&without).expect("readable"),
        connection(1),
        &verifier,
    );
    assert_eq!(
        expected,
        Ok(organization(10)),
        "the log without the redelivery admits"
    );
    let observed = authenticate(
        &Projection::fold(&with).expect("readable"),
        connection(1),
        &verifier,
    );
    assert_eq!(
        observed, expected,
        "a redelivered creation of a disabled sibling changes the decision"
    );
}

/// The same finding at `register_federation_connection`.
#[test]
fn a_redelivered_disabled_sibling_changes_no_registration() {
    let without = vec![
        created(
            connection(2),
            organization(11),
            rule(organization(11), None),
        ),
        disabled(connection(2), organization(11)),
    ];
    let mut with = without.clone();
    with.push(created(
        connection(2),
        organization(11),
        rule(organization(11), None),
    ));
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: rule(organization(10), None),
        jit_provisioning: false,
    };
    let register = |log: &[FederationEvent]| {
        register_federation_connection(
            &input,
            &Projection::fold(log).expect("readable"),
            &mut SequentialAllocator::new(),
        )
        .map(|registered| registered.connection_id)
        .map_err(|denied| denied.clause)
    };

    let expected = register(&without);
    assert!(expected.is_ok(), "no enabled foreign connection collides");
    assert_eq!(
        register(&with),
        expected,
        "a redelivered creation of a disabled sibling refuses the registration"
    );
}

/// Probe that held: a store answering the selected connection twice cannot make one
/// organization ambiguous with itself.
#[test]
fn a_store_answering_the_selected_connection_twice_is_not_ambiguous() {
    struct Twice(Projection);
    impl ConnectionStore for Twice {
        fn connection(
            &self,
            id: &FederationConnectionId,
        ) -> Option<mandate_federation::record::FederationConnection> {
            self.0.connection(id)
        }
        fn enabled_for_issuer(
            &self,
            issuer: &Issuer,
        ) -> Vec<mandate_federation::record::FederationConnection> {
            let once = self.0.enabled_for_issuer(issuer);
            once.iter().chain(once.iter()).cloned().collect()
        }
    }
    impl mandate_federation::PrincipalStore for Twice {
        fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
            self.0.organization_of(principal_id)
        }
        fn state_of(
            &self,
            principal_id: &PrincipalId,
        ) -> Option<mandate_federation::PrincipalState> {
            self.0.state_of(principal_id)
        }
    }
    let log = vec![
        created(
            connection(1),
            organization(10),
            rule(organization(10), Some(("org", "acme"))),
        ),
        linked(connection(1), organization(10)),
    ];
    let projection = Projection::fold(&log).expect("readable");
    let twice = Twice(projection.clone());
    let observed = authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof: CredentialProof::from_bytes(b"proof-material-marker".to_vec()),
        },
        &RequestContext {
            audience: Audience::new("mandate"),
            correlation: CorrelationId::new("adversary-enabled-for-issuer"),
            credential: CredentialId::new(uuid(0xcd)),
            at: Timestamp::new("2026-09-18T00:00:00Z"),
        },
        &admitting_acme(),
        &twice,
        &projection,
        &mut RecordingSessionIssuer::new(),
    )
    .map(|authenticated| authenticated.organization_id)
    .map_err(|denied| denied.clause);
    assert_eq!(observed, Ok(organization(10)));
}
