//! Adversary pass 2. Four cases, each red on one named defect.
//!
//! 1. `register_federation_connection`'s cross-organization guard refuses only the
//!    *unconditional* shape of the configuration its own comment forbids.
//! 2. The fold's "first wins" is first-in-slice, not a property of the log: the same
//!    events replayed in another order materialize the other link.
//! 3. `provision_external_principal` does not honour `ExternalPrincipal::state`, which
//!    the `LinkStore` port doc says every command that reads the port does.
//! 4. The principal a lost provision created is answerable by nothing, though the event
//!    that created it is that principal's creation record.

use mandate_federation::authenticate::{
    AuthenticateFederation, Authenticated, ProvisionExternalPrincipal, Provisioned,
    authenticate_federation, provision_external_principal,
};
use mandate_federation::link::{LinkExternalPrincipal, Linked, link_external_principal};
use mandate_federation::record::{
    ExternalKey, ExternalPrincipal, FederationEvent, LinkState, Projection,
    RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    Denied, LinkStore, PrincipalStore, RecordedPrincipals, RecordingSessionIssuer, RequestContext,
    SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer, OrganizationId,
    PrincipalId, PrincipalKind, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example/one";
const CLIENT: &str = "configured-client";
const SUBJECT: &str = "subject-one";
const EARLIER: &str = "2026-09-18T00:00:00Z";
const LATER: &str = "2026-09-18T00:00:01Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn connection(tag: u8) -> FederationConnectionId {
    FederationConnectionId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
}

fn external_principal(tag: u8) -> ExternalPrincipalId {
    ExternalPrincipalId::new(uuid(tag))
}

fn context(organization_id: OrganizationId) -> VerifiedContext {
    VerifiedContext {
        subject: principal(0x51),
        actor: None,
        organization: organization_id,
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(0xcd)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("federation-linking"),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

fn on_claim(organization_id: OrganizationId, name: &str, value: &str) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
        verified_claim_name: Some(name.to_owned()),
        verified_claim_value: Some(value.to_owned()),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    tenant_resolution: TenantResolutionRule,
    jit_provisioning: bool,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(ISSUER),
        client_id: ClientId::new(CLIENT),
        tenant_resolution,
        jit_provisioning,
    }
}

fn linked(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    external_principal_id: ExternalPrincipalId,
    principal_id: PrincipalId,
    at: &str,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization_id),
        connection_id,
        principal_id,
        external_principal_id,
        subject: ExternalSubject::new(SUBJECT),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: Timestamp::new(at),
    }
}

fn provisioned(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    external_principal_id: ExternalPrincipalId,
    principal_id: PrincipalId,
    at: &str,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalProvisioned {
        organization_id,
        correlation: CorrelationId::new("federation-linking"),
        connection_id,
        principal_id,
        kind: PrincipalKind::User,
        display_name: SUBJECT.to_owned(),
        external_principal_id,
        subject: ExternalSubject::new(SUBJECT),
        link_method: ExternalLinkMethod::ConfiguredFederation,
        linked_at: Timestamp::new(at),
    }
}

fn key(organization_id: OrganizationId) -> ExternalKey {
    ExternalKey {
        organization_id,
        issuer: Issuer::new(ISSUER),
        subject: ExternalSubject::new(SUBJECT),
    }
}

fn request() -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-linking"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(LATER),
    }
}

fn presented() -> CredentialProof {
    CredentialProof::from_bytes(b"proof-material-marker".to_vec())
}

/// A verifier admitting a proof for this issuer, subject and client, carrying whatever
/// verified claims the case needs.
fn admitting(claims: &[(&str, &str)]) -> ConstructedVerifier {
    let mut proof = VerifiedProof::new(
        Issuer::new(ISSUER),
        ExternalSubject::new(SUBJECT),
        ClientId::new(CLIENT),
    );
    for (name, value) in claims {
        proof = proof.with_verified_claim(name, value);
    }
    ConstructedVerifier::admitting(&[SigningAlgorithm::new("configured-by-deployment")], proof)
        .expect("a non-empty allowlist is admitted")
}

fn authenticate(
    connections: &Projection,
    links: &impl LinkStore,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
    sessions: &mut RecordingSessionIssuer,
) -> Result<Authenticated, Denied> {
    authenticate_federation(
        &AuthenticateFederation {
            connection_id,
            proof: presented(),
        },
        &request(),
        verifier,
        connections,
        links,
        sessions,
    )
}

fn provision(
    connections: &Projection,
    links: &impl LinkStore,
    connection_id: FederationConnectionId,
    verifier: &ConstructedVerifier,
    allocator: &mut SequentialAllocator,
) -> Result<Provisioned, Denied> {
    provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id,
            proof: presented(),
        },
        &request(),
        verifier,
        connections,
        links,
        allocator,
    )
}

/// The cross-organization registration guard (`src/record.rs:566-594`) refuses only the
/// *unconditional* shape.
///
/// Its own comment states the property: "two organizations sharing an issuer where
/// either resolves it unconditionally makes every login on that issuer ambiguous. Refuse
/// the configuration rather than the logins." Two *conditional* rules that name the same
/// claim and value make every login on that issuer ambiguous in exactly the same way,
/// and the guard admits them. `{org: acme}` is the canonical sample rule
/// (`crates/mandate-model/src/lib.rs:82-86`), so the colliding value is the documented
/// one, not an invented one.
#[test]
fn a_foreign_organization_may_copy_a_conditional_rule_and_end_the_incumbents_logins() {
    let mut allocator = SequentialAllocator::new();
    let empty = Projection::default();

    let incumbent = register_federation_connection(
        &RegisterFederationConnection {
            context: context(organization(10)),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: on_claim(organization(10), "org", "acme"),
            jit_provisioning: false,
        },
        &empty,
        &mut allocator,
    )
    .expect("the first connection on an unheld issuer is admitted");

    let mut log = vec![
        incumbent.event.clone(),
        linked(
            incumbent.connection_id,
            organization(10),
            external_principal(0x71),
            principal(0x21),
            EARLIER,
        ),
    ];
    let before = Projection::fold(&log).expect("one connection and one link");
    let mut sessions = RecordingSessionIssuer::new();
    authenticate(
        &before,
        &before,
        incumbent.connection_id,
        &admitting(&[("org", "acme")]),
        &mut sessions,
    )
    .expect("organization 10's login resolves before the intruder registers");

    // Organization 11 registers the same issuer and copies the claim rule verbatim,
    // resolving it to itself. Nothing but this command is needed, and its only declared
    // organization constraint — the rule resolves to the caller's own organization — is
    // satisfied.
    let intruder = register_federation_connection(
        &RegisterFederationConnection {
            context: context(organization(11)),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new(CLIENT),
            tenant_resolution: on_claim(organization(11), "org", "acme"),
            jit_provisioning: false,
        },
        &before,
        &mut allocator,
    );

    let incumbents_next_login = match &intruder {
        Err(_) => None,
        Ok(registered) => {
            log.push(registered.event.clone());
            let after = Projection::fold(&log).expect("two connections on one issuer");
            Some(authenticate(
                &after,
                &after,
                incumbent.connection_id,
                &admitting(&[("org", "acme")]),
                &mut sessions,
            ))
        }
    };

    assert!(
        intruder.is_err(),
        "organization 11's connection copies the rule organization 10 already resolves the \
         issuer with, and register_federation_connection admits it: the guard tests only \
         whether a rule is unconditional, so two equal conditional rules produce exactly the \
         configuration its comment refuses to admit. Organization 10's login, which resolved \
         a moment ago, now returns {incumbents_next_login:?}, and there is no command that \
         un-registers organization 11's connection"
    );
}

/// "First wins" is first-in-slice. The two link events are on two different
/// `ExternalPrincipal` aggregates through two different connections of one organization
/// — the configuration `tests/record.rs:533` admits — so ADR 0009's per-aggregate
/// compare-and-set append gives their relative order no definition. A projection is
/// "derived, droppable, rebuildable" there, and a rebuild that presents the two streams
/// in the other order materializes the other link for the one key. `linked_at`, the only
/// ordering datum the events carry, is read by nothing: here the event that wins is the
/// *later* of the two.
#[test]
fn the_link_that_wins_one_key_changes_with_the_order_the_streams_are_replayed_in() {
    let creations = [
        created(
            connection(1),
            organization(10),
            on_claim(organization(10), "dept", "engineering"),
            false,
        ),
        created(
            connection(2),
            organization(10),
            on_claim(organization(10), "org", "acme"),
            false,
        ),
    ];
    let through_one = linked(
        connection(1),
        organization(10),
        external_principal(0x71),
        principal(0x21),
        LATER,
    );
    let through_two = linked(
        connection(2),
        organization(10),
        external_principal(0x72),
        principal(0x22),
        EARLIER,
    );

    let mut one_first = creations.to_vec();
    one_first.push(through_one.clone());
    one_first.push(through_two.clone());
    let mut two_first = creations.to_vec();
    two_first.push(through_two);
    two_first.push(through_one);

    let replayed_one_first = Projection::fold(&one_first).expect("a duplicate key is a conflict");
    let replayed_two_first = Projection::fold(&two_first).expect("a duplicate key is a conflict");

    let resolved_one_first = replayed_one_first
        .link(&key(organization(10)))
        .map(|link| link.principal_id);
    let resolved_two_first = replayed_two_first
        .link(&key(organization(10)))
        .map(|link| link.principal_id);

    assert_eq!(
        resolved_one_first, resolved_two_first,
        "one set of events, two rebuilds, two different principals for the one canonical key: \
         record_link decides the winner by its position in the slice and reads linked_at for \
         nothing, so the link that lost the write race becomes the one the key resolves to as \
         soon as a replay presents the two aggregates in the other order. A session already \
         issued to the loser names a principal the key no longer resolves to"
    );
}

/// A `LinkStore` that answers one key with one row, in whatever state the case built.
///
/// `src/lib.rs:238-246` declares this to be within the port's contract: "An
/// implementation may return a row in any lifecycle state. Every command that reads this
/// port honours [`record::ExternalPrincipal::state`] itself rather than relying on an
/// implementation to filter."
struct RowInAnyState {
    key: ExternalKey,
    row: ExternalPrincipal,
    organizations: Vec<(PrincipalId, OrganizationId)>,
}

impl LinkStore for RowInAnyState {
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal> {
        (*key == self.key).then(|| self.row.clone())
    }
}

impl PrincipalStore for RowInAnyState {
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
        self.organizations
            .iter()
            .find(|(recorded, _)| recorded == principal_id)
            .map(|(_, organization_id)| *organization_id)
    }
}

/// Of the three commands that read `LinkStore`, two honour the state the port hands back
/// and one does not.
///
/// A terminal `Unlinked` row does not hold the key: `authenticate_federation`
/// (`src/authenticate.rs:85-88`) denies `LinkAbsent` on it, and
/// `link_external_principal` (`src/link.rs:104-107`) admits a relink over it.
/// `provision_external_principal` (`src/authenticate.rs:140`) tests `is_some()` alone, so
/// the same row that holds no key for either of the others blocks provisioning with
/// `ExternalKeyExists`. The adapter sequence `decision-blocker:jit-provisioning`
/// prescribes — authenticate, on an absent-link denial provision, authenticate again —
/// has no exit at all in that state.
#[test]
fn an_unlinked_row_holds_no_key_for_two_commands_and_blocks_the_third() {
    let log = vec![created(
        connection(1),
        organization(10),
        unconditional(organization(10)),
        true,
    )];
    let connections = Projection::fold(&log).expect("one connection");
    let store = RowInAnyState {
        key: key(organization(10)),
        row: ExternalPrincipal {
            id: external_principal(0x71),
            organization_id: organization(10),
            subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            connection_id: connection(1),
            link_method: ExternalLinkMethod::Administrator,
            linked_at: Timestamp::new(EARLIER),
            state: LinkState::Unlinked,
        },
        organizations: vec![(principal(0x22), organization(10))],
    };
    let verifier = admitting(&[]);
    let mut sessions = RecordingSessionIssuer::new();
    let mut allocator = SequentialAllocator::new();

    let authenticated = authenticate(
        &connections,
        &store,
        connection(1),
        &verifier,
        &mut sessions,
    );
    let relinked: Result<Linked, Denied> = link_external_principal(
        &LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id: connection(1),
            external_subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x22),
            method: ExternalLinkMethod::Administrator,
        },
        &request(),
        &connections,
        &store,
        &mut allocator,
    );
    let provisioned = provision(
        &connections,
        &store,
        connection(1),
        &verifier,
        &mut allocator,
    );

    assert!(
        provisioned.is_ok(),
        "the row the port returned is in the terminal Unlinked state. \
         authenticate_federation reads that state and denies ({authenticated:?}); \
         link_external_principal reads it and admits a relink over the key \
         ({relinked:?}); provision_external_principal reads only is_some() and denies \
         ({provisioned:?}). One key, one store, one moment, three answers — and the \
         adapter sequence decision-blocker:jit-provisioning declares, authenticate then \
         provision then authenticate, never terminates"
    );
}

/// The losing half of the `jit-conflict` race is a principal nothing can name.
///
/// `federation.yaml:258`: `ExternalPrincipalProvisioned` "is the creation record for both
/// entities it names — one mandate.identity.Principal of kind User, and one
/// mandate.federation.ExternalPrincipal". `src/lib.rs:248-258` says `Projection` answers
/// `PrincipalStore` "for the principals this crate's own events created, which is why an
/// unanswered principal is refused rather than admitted". The loser's event is one of
/// this crate's own events and it created that principal; first-wins routes its link to
/// `conflicts()`, which carries no `principal_id`, and `organization_of` is folded over
/// `links` alone. So the principal is created in `mandate.identity` and invisible here —
/// and with `link_external_principal`'s new target-principal read, unlinkable forever.
#[test]
fn the_principal_a_lost_provision_created_is_answerable_by_nothing() {
    let log = vec![
        created(
            connection(1),
            organization(10),
            unconditional(organization(10)),
            true,
        ),
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x71),
            principal(0xa1),
            EARLIER,
        ),
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x72),
            principal(0xa2),
            LATER,
        ),
    ];

    let projection = Projection::fold(&log).expect("a race does not make the log unreadable");
    assert_eq!(
        projection.conflicts().len(),
        1,
        "the second provision is the conflict this case is about"
    );

    let recorded = projection.organization_of(&principal(0xa2));
    let mut allocator = SequentialAllocator::new();
    let store = RecordedPrincipals::over(projection.clone());
    let relink = link_external_principal(
        &LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id: connection(1),
            external_subject: ExternalSubject::new("subject-two"),
            principal_id: principal(0xa2),
            method: ExternalLinkMethod::Administrator,
        },
        &request(),
        &projection,
        &store,
        &mut allocator,
    );

    assert_eq!(
        recorded,
        Some(organization(10)),
        "the event that lost the key is the creation record of principal 0xa2 in \
         organization 10, and the projection answers None for it: the conflict entry keeps \
         the key and the external-principal id and drops the principal the event created. \
         Nothing in src/ reads conflicts(), so the loss is surfaced to no caller and no \
         denial, and an administrator trying to give that principal a link of its own is \
         refused for a principal that does not exist: {relink:?}"
    );
}
