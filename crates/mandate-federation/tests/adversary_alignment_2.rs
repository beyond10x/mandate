//! Adversary pass 2: the fold's own claim that one external key resolves to one record
//! whatever order a rebuild presents two aggregates in.
//!
//! `crates/mandate-federation/src/record.rs:601-605` states it: "First wins, and 'first'
//! is a property of the events rather than of the order a rebuild presents them in: the
//! least `(linked_at, external_principal_id)` holds the key. Two links for one key are on
//! two aggregates, whose relative order the log does not define, so a replay that
//! interleaves the streams differently must still resolve the key to the same record."
//!
//! Every event here is a real handler's accepted output, decided against a projection the
//! handler was entitled to read: two writers link one composite key against the same
//! pre-append projection — the race `Projection::conflicts` exists for — and the earlier
//! writer's record is then unlinked, decided against a projection where it holds the key.
//! Nothing orders the second link's append against the unlink's: they are two
//! `ExternalPrincipal` aggregates, and the kit's compare-and-set is on the appending
//! stream alone (`src/disable.rs:29-33`).

use mandate_federation::authenticate::{AuthenticateFederation, authenticate_federation};
use mandate_federation::disable::{UnlinkExternalPrincipal, unlink_external_principal};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::record::{
    ExternalKey, FederationEvent, Projection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    PrincipalState, RecordedPrincipals, RecordingSessionIssuer, RequestContext, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalSubject, FederationConnectionId, Issuer, OrganizationId, PrincipalId, SigningAlgorithm,
    Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example";
const SUBJECT: &str = "subject-one";

/// The instant the writer whose record takes the key read its request at.
const EARLIER: &str = "2026-09-18T00:00:00Z";

/// The instant the other writer read its request at.
const LATER: &str = "2026-09-19T00:00:00Z";

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(10))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
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
        correlation: CorrelationId::new("federation-alignment"),
    }
}

/// A request read at a declared instant: two writers racing one key are ordered by
/// `linked_at`, which is the instant their request was served at.
fn request_at(at: &str) -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-alignment"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(at),
    }
}

fn unconditional() -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization(),
        verified_claim_name: None,
        verified_claim_value: None,
    }
}

/// A verifier admitting exactly one validated subject on the configured issuer.
fn admitting(subject: &str) -> ConstructedVerifier {
    ConstructedVerifier::admitting(
        &[SigningAlgorithm::new("declared-by-deployment")],
        VerifiedProof::new(
            Issuer::new(ISSUER),
            ExternalSubject::new(subject),
            ClientId::new("configured-client"),
        ),
    )
    .expect("a non-empty allowlist")
}

/// One race every handler accepted: a connection, two links on one composite key decided
/// against the same projection, and the unlink of the one that held the key.
struct Race {
    connection_id: FederationConnectionId,
    created: FederationEvent,
    earlier_link: FederationEvent,
    later_link: FederationEvent,
    unlink: FederationEvent,
    later_principal: PrincipalId,
    key: ExternalKey,
}

impl Race {
    /// The append order in which the unlink lands before the second writer's link.
    fn unlink_before_the_second_link(&self) -> Vec<FederationEvent> {
        vec![
            self.created.clone(),
            self.earlier_link.clone(),
            self.unlink.clone(),
            self.later_link.clone(),
        ]
    }

    /// The append order in which the second writer's link lands before the unlink. Each
    /// aggregate's own events keep their order; only the two streams interleave.
    fn second_link_before_the_unlink(&self) -> Vec<FederationEvent> {
        vec![
            self.created.clone(),
            self.earlier_link.clone(),
            self.later_link.clone(),
            self.unlink.clone(),
        ]
    }
}

/// Drive the real handlers to the four accepted events.
fn accepted_race() -> Race {
    let mut live = Projection::default();
    let mut allocator = SequentialAllocator::new();
    let registered = register_federation_connection(
        &RegisterFederationConnection {
            context: context(),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: unconditional(),
            jit_provisioning: true,
        },
        &live,
        &mut allocator,
    )
    .expect("the organization binding is the caller's own");
    live.apply(&registered.event)
        .expect("the decided event applies");

    let principals = RecordedPrincipals::over(live.clone())
        .with_principal(principal(0x21), organization(), PrincipalState::Active)
        .with_principal(principal(0x22), organization(), PrincipalState::Active);
    let link = LinkExternalPrincipal {
        context: context(),
        connection_id: registered.connection_id,
        external_subject: ExternalSubject::new(SUBJECT),
        principal_id: principal(0x21),
        method: ExternalLinkMethod::Administrator,
    };

    // Both decided against the projection as it stood before either append: neither
    // writer can see the other.
    let earlier = link_external_principal(
        &link,
        &request_at(EARLIER),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the key is free when this writer reads it");
    let later = link_external_principal(
        &LinkExternalPrincipal {
            principal_id: principal(0x22),
            ..link
        },
        &request_at(LATER),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("the key is free when the other writer reads it too");

    // The unlink is decided against the projection the earlier append left, where that
    // record holds the key and is `Linked`.
    let mut after_earlier = live.clone();
    after_earlier
        .apply(&earlier.event)
        .expect("the decided event applies");
    let unlink = unlink_external_principal(
        &UnlinkExternalPrincipal {
            id: earlier.external_principal_id,
            context: context(),
        },
        &after_earlier,
    )
    .expect("the earlier writer's record holds the key and is `Linked`");

    Race {
        connection_id: registered.connection_id,
        created: registered.event,
        earlier_link: earlier.event,
        later_link: later.event,
        unlink,
        later_principal: principal(0x22),
        key: ExternalKey {
            organization_id: organization(),
            issuer: Issuer::new(ISSUER),
            subject: ExternalSubject::new(SUBJECT),
        },
    }
}

/// The principal a federated login for the raced subject authenticates against one
/// rebuild, or `None` when the login is refused.
fn authenticated_principal(
    rebuild: &Projection,
    connection_id: FederationConnectionId,
) -> Option<PrincipalId> {
    let mut sessions = RecordingSessionIssuer::new();
    authenticate_federation(
        &AuthenticateFederation {
            connection_id,
            proof: CredentialProof::from_bytes(b"proof".to_vec()),
        },
        &request_at(LATER),
        &admitting(SUBJECT),
        rebuild,
        rebuild,
        &mut sessions,
    )
    .ok()
    .map(|authenticated| authenticated.principal_id)
}

/// One accepted race, two append orders its writers cannot order between them, two
/// different holders of the composite external key.
#[test]
fn two_append_orders_of_one_accepted_race_resolve_the_external_key_two_ways() {
    let race = accepted_race();
    let unlink_first = Projection::fold(&race.unlink_before_the_second_link())
        .expect("a log every handler accepted rebuilds");
    let link_first = Projection::fold(&race.second_link_before_the_unlink())
        .expect("a log every handler accepted rebuilds");

    assert_eq!(
        unlink_first.link(&race.key).map(|held| held.id),
        link_first.link(&race.key).map(|held| held.id),
        "`record_link` states that \"first\" is a property of the events rather than of \
         the order a rebuild presents them in (src/record.rs:601-605), and these two logs \
         carry the same four accepted events with each aggregate's own order kept"
    );
}

/// The same race decides which principal a federated login for that subject
/// authenticates, and whether it authenticates at all.
#[test]
fn the_same_accepted_race_authenticates_one_rebuild_and_refuses_the_other() {
    let race = accepted_race();
    let unlink_first = authenticated_principal(
        &Projection::fold(&race.unlink_before_the_second_link())
            .expect("a log every handler accepted rebuilds"),
        race.connection_id,
    );
    let link_first = authenticated_principal(
        &Projection::fold(&race.second_link_before_the_unlink())
            .expect("a log every handler accepted rebuilds"),
        race.connection_id,
    );

    assert_eq!(
        unlink_first, link_first,
        "one append order authenticates the subject as {:?} and the other refuses the \
         login, on one set of accepted decisions",
        race.later_principal
    );
}
