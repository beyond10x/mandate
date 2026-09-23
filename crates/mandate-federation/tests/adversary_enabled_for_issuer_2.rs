//! Adversary pass 2 over `story:enabled-for-issuer-filters-in-the-implementor`.
//!
//! The correction makes `enabled_on_issuer` take only identities from the store's
//! enumeration and read each through `ConnectionStore::connection(id)`. These cases drive
//! a store whose two answers disagree, and the fold arm that now skips a held identity.

use mandate_federation::authenticate::{AuthenticateFederation, authenticate_federation};
use mandate_federation::record::{
    ConnectionState, FederationConnection, FederationEvent, Projection,
    RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    ConnectionStore, DenialClause, PrincipalState, PrincipalStore, RecordingSessionIssuer,
    RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PrincipalId, SigningAlgorithm,
    Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/one";
const OTHER_ISSUER: &str = "https://idp.example/other";
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
        correlation: CorrelationId::new("adversary-enabled-for-issuer-2"),
    }
}

fn acme(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some("org".to_owned()),
        verified_claim_value: Some("acme".to_owned()),
    }
}

fn created_on(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    issuer: &str,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(issuer),
        client_id: ClientId::new(CLIENT),
        tenant_resolution: acme(organization_id),
        jit_provisioning: false,
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

/// A store whose enumeration is `listed` verbatim, and whose `connection(id)` is the
/// projection's except for `unanswered`, which it answers `None`.
struct Disagreeing {
    projection: Projection,
    listed: Vec<FederationConnection>,
    unanswered: Vec<FederationConnectionId>,
}

impl ConnectionStore for Disagreeing {
    fn connection(&self, id: &FederationConnectionId) -> Option<FederationConnection> {
        if self.unanswered.contains(id) {
            return None;
        }
        self.projection.connection(id)
    }

    fn enabled_for_issuer(&self, _issuer: &Issuer) -> Vec<FederationConnection> {
        self.listed.clone()
    }
}

impl PrincipalStore for Disagreeing {
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
        self.projection.organization_of(principal_id)
    }

    fn state_of(&self, principal_id: &PrincipalId) -> Option<PrincipalState> {
        self.projection.state_of(principal_id)
    }
}

fn authenticate_through(
    store: &Disagreeing,
    verifier: &ConstructedVerifier,
) -> Result<OrganizationId, DenialClause> {
    authenticate_federation(
        &AuthenticateFederation {
            connection_id: connection(1),
            proof: CredentialProof::from_bytes(b"proof-material-marker".to_vec()),
        },
        &RequestContext {
            audience: Audience::new("mandate"),
            correlation: CorrelationId::new("adversary-enabled-for-issuer-2"),
            credential: CredentialId::new(uuid(0xcd)),
            at: Timestamp::new("2026-09-18T00:00:00Z"),
        },
        verifier,
        store,
        &store.projection,
        &mut RecordingSessionIssuer::new(),
    )
    .map(|authenticated| authenticated.organization_id)
    .map_err(|denied| denied.clause)
}

/// Organization 10 selected on connection 1; organization 11 on connection 2, same issuer,
/// the same rule, `Enabled`. The projection alone answers this login `TenantAmbiguous`.
fn two_enabled_on_one_issuer() -> Projection {
    Projection::fold(&[
        created_on(connection(1), organization(10), ISSUER),
        created_on(connection(2), organization(11), ISSUER),
        linked(connection(1), organization(10)),
    ])
    .expect("readable")
}

/// Red at HEAD. The enumeration lists organization 11's `Enabled`, colliding connection;
/// `connection(id)` has no answer for it. `enabled_on_issuer` drops it on the `None`
/// (`filter_map`, `src/lib.rs:657`) and the collision guard admits a rule that makes every
/// login on this issuer ambiguous. At 10e9036 and at the base the enumeration's record
/// was used and the registration was refused. The doc at `src/lib.rs:643` says the filter
/// "narrows, never widens"; dropping a listed collider widens admission.
#[test]
fn a_listed_collider_the_store_cannot_answer_by_identity_still_refuses_registration() {
    let projection =
        Projection::fold(&[created_on(connection(2), organization(11), ISSUER)]).expect("readable");
    let collider = projection.connection(&connection(2)).expect("held");
    let store = Disagreeing {
        projection,
        listed: vec![collider],
        unanswered: vec![connection(2)],
    };
    let observed = register_federation_connection(
        &RegisterFederationConnection {
            context: context(organization(10)),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: acme(organization(10)),
            jit_provisioning: false,
        },
        &store,
        &mut SequentialAllocator::new(),
    )
    .map(|registered| registered.connection_id)
    .map_err(|denied| denied.clause);
    assert_eq!(
        observed,
        Err(DenialClause::TenantResolutionUnadmitted),
        "a listed Enabled collider the store answers None by identity was dropped, and the colliding rule was admitted"
    );
}

/// Red at HEAD. The same shape at login: the listed sibling is dropped on `None`, and a
/// login the projection answers `TenantAmbiguous` is admitted to organization 10.
#[test]
fn a_listed_sibling_the_store_cannot_answer_by_identity_still_makes_the_login_ambiguous() {
    let projection = two_enabled_on_one_issuer();
    let listed = projection.enabled_for_issuer(&Issuer::new(ISSUER));
    assert_eq!(
        listed.len(),
        2,
        "both connections are Enabled on the issuer"
    );
    let store = Disagreeing {
        projection,
        listed,
        unanswered: vec![connection(2)],
    };
    assert_eq!(
        authenticate_through(&store, &admitting_acme()),
        Err(DenialClause::TenantAmbiguous),
        "a listed Enabled sibling the store answers None by identity was dropped, and the login was admitted"
    );
}

/// Green at HEAD; covers the correction's own claim. The enumeration presents an `Enabled`
/// copy of organization 11's connection, which `connection(id)` answers `Disabled`. The
/// fold arm now never produces that copy, so no `Projection`-backed case reaches the
/// re-read at `src/lib.rs:657`; this case fails if `enabled_on_issuer` goes back to reading
/// state off the enumeration.
#[test]
fn a_stale_enabled_copy_in_the_enumeration_decides_nothing() {
    let projection = Projection::fold(&[
        created_on(connection(1), organization(10), ISSUER),
        created_on(connection(2), organization(11), ISSUER),
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(11)),
            id: connection(2),
        },
        linked(connection(1), organization(10)),
    ])
    .expect("readable");
    let mut stale = projection.connection(&connection(2)).expect("held");
    assert_eq!(stale.state, ConnectionState::Disabled);
    stale.state = ConnectionState::Enabled;
    let selected = projection.connection(&connection(1)).expect("held");
    let store = Disagreeing {
        projection,
        listed: vec![selected, stale],
        unanswered: Vec::new(),
    };
    assert_eq!(
        authenticate_through(&store, &admitting_acme()),
        Ok(organization(10))
    );
}

/// Green at HEAD; the enumeration's issuer is not trusted either. The enumeration lists
/// connection 2 as on this issuer; by identity it is on another.
#[test]
fn an_enumeration_misreporting_the_issuer_decides_nothing() {
    let projection = Projection::fold(&[
        created_on(connection(1), organization(10), ISSUER),
        created_on(connection(2), organization(11), OTHER_ISSUER),
        linked(connection(1), organization(10)),
    ])
    .expect("readable");
    let mut misreported = projection.connection(&connection(2)).expect("held");
    misreported.issuer = Issuer::new(ISSUER);
    let selected = projection.connection(&connection(1)).expect("held");
    let store = Disagreeing {
        projection,
        listed: vec![selected, misreported],
        unanswered: Vec::new(),
    };
    assert_eq!(
        authenticate_through(&store, &admitting_acme()),
        Ok(organization(10))
    );
}

/// Green at HEAD; probe of the fold arm. A second creation of a held identity carrying
/// different fields — the shape `mandate-conformance`'s `seed_connection` appends for a
/// held `Disabled` connection — writes nothing: the first record, and its terminal state,
/// stand.
#[test]
fn a_second_creation_with_other_fields_keeps_the_first_record() {
    let projection = Projection::fold(&[
        created_on(connection(2), organization(11), ISSUER),
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(11)),
            id: connection(2),
        },
        created_on(connection(2), organization(12), OTHER_ISSUER),
    ])
    .expect("readable");
    assert_eq!(projection.connections().len(), 1);
    let held = projection.connection(&connection(2)).expect("held");
    assert_eq!(held.state, ConnectionState::Disabled);
    assert_eq!(held.organization_id, organization(11));
    assert_eq!(held.issuer, Issuer::new(ISSUER));
    assert!(
        projection
            .enabled_for_issuer(&Issuer::new(OTHER_ISSUER))
            .is_empty()
    );
}
