//! Each durable record of `mandate.federation` is rebuilt from its events alone.
//!
//! `docs/adr/0009-event-sourced-persistence.md`: "A command produces domain events; the
//! events are the record; every read is a fold over them ... State tables are
//! projections: derived, droppable, rebuildable, never authoritative."
//!
//! Every case here drives the real handlers: each returns the event its accepted outcome
//! emits, the case applies that event to the live projection and keeps it in a log, and
//! the log is then folded from empty. Nothing reconstructs state by re-running a command.
//!
//! `fold` and the live projection share one `apply`, so `fold(&log) == live` alone is
//! close to a tautology — a field `apply` drops is dropped identically on both sides.
//! Each case therefore *also* asserts the rebuilt record against a literal carrying every
//! field the compiled entity marks required. The equality says the rebuild is complete;
//! the literal says the log is what it was rebuilt from. This is the shape
//! `crates/mandate-model/tests/replay.rs` established.

use mandate_federation::authenticate::{ProvisionExternalPrincipal, provision_external_principal};
use mandate_federation::disable::{
    DisableFederationConnection, DisableOAuthClient, UnlinkExternalPrincipal,
    disable_federation_connection, disable_oauth_client, unlink_external_principal,
};
use mandate_federation::link::{LinkExternalPrincipal, link_external_principal};
use mandate_federation::record::{
    ConnectionState, ExternalKey, ExternalPrincipal, FederationConnection, FederationEvent,
    FoldError, LinkState, OAuthClient, OAuthClientState, Projection, RegisterFederationConnection,
    register_federation_connection,
};
use mandate_federation::register_client::{
    ConfiguredAdmission, RegisterOAuthClient, register_o_auth_client,
};
use mandate_federation::verifier::{ConstructedVerifier, VerifiedProof};
use mandate_federation::{
    ExternalPrincipalStore, PrincipalState, PrincipalStore, RecordedPrincipals, RequestContext,
    SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, CredentialProof, ExternalLinkMethod,
    ExternalSubject, FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PkceMethod,
    PrincipalId, RedirectUri, SigningAlgorithm, Timestamp, VerifiedContext,
};

const ISSUER: &str = "https://idp.example";
const SUBJECT: &str = "subject-one";
const REDIRECT: &str = "https://app.example/callback";

/// The admission the registered client is registered through: one administrator, one
/// organization and one redirect URI.
fn admission() -> ConfiguredAdmission {
    ConfiguredAdmission::new()
        .with_administrator(principal(0x51))
        .with_organization(organization(10))
        .with_redirect_uri(organization(10), RedirectUri::new(REDIRECT))
}

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::new(uuid(tag))
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
        correlation: CorrelationId::new("federation-alignment"),
    }
}

fn request() -> RequestContext {
    request_at("2026-09-19T00:00:00Z")
}

/// The same request, read at a declared instant: two writers racing one key are ordered
/// by `linked_at`, which is the instant their request was served at.
fn request_at(at: &str) -> RequestContext {
    RequestContext {
        audience: Audience::new("mandate"),
        correlation: CorrelationId::new("federation-alignment"),
        credential: CredentialId::new(uuid(0xcd)),
        at: Timestamp::new(at),
    }
}

fn unconditional(organization_id: OrganizationId) -> TenantResolutionRule {
    TenantResolutionRule {
        configured_organization: organization_id,
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

/// Decide, apply, record: the three steps a command path takes, in order. The decision is
/// read off the projection as it stands, the event is applied to it, and the log keeps the
/// event that was applied.
fn commit(live: &mut Projection, log: &mut Vec<FederationEvent>, event: FederationEvent) {
    live.apply(&event).expect("the decided event applies");
    log.push(event);
}

/// A registered connection, through the real handler.
fn register(
    live: &mut Projection,
    log: &mut Vec<FederationEvent>,
    organization_id: OrganizationId,
    jit_provisioning: bool,
) -> FederationConnectionId {
    let mut allocator = SequentialAllocator::new();
    let registered = register_federation_connection(
        &RegisterFederationConnection {
            context: context(organization_id),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: unconditional(organization_id),
            jit_provisioning,
        },
        live,
        &mut allocator,
    )
    .expect("the organization binding is the caller's own");
    commit(live, log, registered.event);
    registered.connection_id
}

/// `mandate.federation.FederationConnection`: registered, then disabled.
#[test]
fn a_federation_connection_replays_from_its_events() {
    let mut live = Projection::default();
    let mut log = Vec::new();

    let connection_id = register(&mut live, &mut log, organization(10), true);
    let disabled = disable_federation_connection(
        &DisableFederationConnection {
            context: context(organization(10)),
            id: connection_id,
        },
        &live,
    )
    .expect("an enabled connection of this tenant");
    commit(&mut live, &mut log, disabled);

    assert_eq!(log.len(), 2, "one event per accepted command");
    let replayed = Projection::fold(&log).expect("the log rebuilds");
    assert_eq!(
        replayed.connections(),
        [FederationConnection {
            id: connection_id,
            organization_id: organization(10),
            issuer: Issuer::new(ISSUER),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: unconditional(organization(10)),
            jit_provisioning: true,
            state: ConnectionState::Disabled,
        }],
        "every required field of the rebuilt record came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.federation.ExternalPrincipal`: linked, then unlinked — and a second record
/// provisioned on the same connection, so both creating events are replayed.
#[test]
fn an_external_principal_replays_from_its_events() {
    let mut live = Projection::default();
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();

    let connection_id = register(&mut live, &mut log, organization(10), true);

    let principals = RecordedPrincipals::over(live.clone()).with_principal(
        principal(0x21),
        organization(10),
        PrincipalState::Active,
    );
    let linked = link_external_principal(
        &LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id,
            external_subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            method: ExternalLinkMethod::Administrator,
        },
        &request(),
        &principals,
        &principals,
        &mut allocator,
    )
    .expect("an administrative link inside the connection's organization");
    commit(&mut live, &mut log, linked.event);

    let provisioned = provision_external_principal(
        &ProvisionExternalPrincipal {
            connection_id,
            proof: CredentialProof::from_bytes(b"proof".to_vec()),
        },
        &request(),
        &admitting("subject-two"),
        &live,
        &live,
        &mut allocator,
    )
    .expect("the connection admits provisioning and the second key is free");
    commit(&mut live, &mut log, provisioned.event);

    let unlinked = unlink_external_principal(
        &UnlinkExternalPrincipal {
            context: context(organization(10)),
            id: linked.external_principal_id,
        },
        &live,
    )
    .expect("a linked record of this tenant");
    commit(&mut live, &mut log, unlinked);

    assert_eq!(log.len(), 4, "one event per accepted command");
    let replayed = Projection::fold(&log).expect("the log rebuilds");
    assert_eq!(
        replayed.links(),
        [
            ExternalPrincipal {
                id: linked.external_principal_id,
                organization_id: organization(10),
                subject: ExternalSubject::new(SUBJECT),
                principal_id: principal(0x21),
                connection_id,
                link_method: ExternalLinkMethod::Administrator,
                linked_at: Timestamp::new("2026-09-19T00:00:00Z"),
                state: LinkState::Unlinked,
            },
            ExternalPrincipal {
                id: provisioned.external_principal_id,
                organization_id: organization(10),
                subject: ExternalSubject::new("subject-two"),
                principal_id: provisioned.principal_id,
                connection_id,
                link_method: ExternalLinkMethod::ConfiguredFederation,
                linked_at: Timestamp::new("2026-09-19T00:00:00Z"),
                state: LinkState::Linked,
            },
        ],
        "every required field of both rebuilt records came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
    assert!(
        replayed.conflicts().is_empty(),
        "two distinct subjects hold two distinct keys"
    );
}

/// One key, one holder, and the holder is a function of the records alone.
///
/// Two writers link one composite key against the same pre-append projection — neither can
/// see the other, because the kit's compare-and-set is on the appending `ExternalPrincipal`
/// aggregate's own stream — and then one of the two records is unlinked. Every interleaving
/// of the two aggregates' appends is a log the handlers accepted, so every one of them must
/// rebuild to the same read model: the smallest `external_principal_id` on the key holds
/// it, an unlink of the holder promotes the next smallest, and an unlink of a conflicted
/// record leaves the holder where it is.
///
/// Both unlinks and both orders, driven through the real handlers.
#[test]
fn one_external_key_resolves_the_same_way_in_every_append_order() {
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new(ISSUER),
        subject: ExternalSubject::new(SUBJECT),
    };

    // `unlinked` names which of the two records the unlink was decided against: the one
    // that holds the key, or the one that does not.
    for unlink_the_holder in [true, false] {
        let mut before = Projection::default();
        let mut head = Vec::new();
        let mut allocator = SequentialAllocator::new();
        let connection_id = register(&mut before, &mut head, organization(10), true);
        let principals = RecordedPrincipals::over(before.clone())
            .with_principal(principal(0x21), organization(10), PrincipalState::Active)
            .with_principal(principal(0x22), organization(10), PrincipalState::Active);
        let link = LinkExternalPrincipal {
            context: context(organization(10)),
            connection_id,
            external_subject: ExternalSubject::new(SUBJECT),
            principal_id: principal(0x21),
            method: ExternalLinkMethod::Administrator,
        };

        // Two writers, each against the projection as it stood before either append. The
        // allocator mints ascending identities, so the first call's record holds the key.
        let holder = link_external_principal(
            &link,
            &request_at("2026-09-19T00:00:00Z"),
            &principals,
            &principals,
            &mut allocator,
        )
        .expect("the key is free when this writer reads it");
        let conflicted = link_external_principal(
            &LinkExternalPrincipal {
                principal_id: principal(0x22),
                ..link
            },
            &request_at("2026-09-18T00:00:00Z"),
            &principals,
            &principals,
            &mut allocator,
        )
        .expect("the key is free when the other writer reads it too");
        assert!(
            holder.external_principal_id < conflicted.external_principal_id,
            "the identity is what decides, so the case has to know which is smaller"
        );

        // The unlink is decided against the projection its own writer's append left, where
        // that record is `Linked`.
        let unlinked_id = if unlink_the_holder {
            holder.external_principal_id
        } else {
            conflicted.external_principal_id
        };
        let mut after_its_own_link = before.clone();
        after_its_own_link
            .apply(if unlink_the_holder {
                &holder.event
            } else {
                &conflicted.event
            })
            .expect("the decided event applies");
        let unlink = unlink_external_principal(
            &UnlinkExternalPrincipal {
                id: unlinked_id,
                context: context(organization(10)),
            },
            &after_its_own_link,
        )
        .expect("a `Linked` record inside the caller's verified organization");

        // Both interleavings of the two aggregates, each keeping its own events in order.
        let mut orders = Vec::new();
        for unlink_first in [true, false] {
            let mut log = head.clone();
            if unlink_the_holder {
                log.push(holder.event.clone());
                if unlink_first {
                    log.push(unlink.clone());
                    log.push(conflicted.event.clone());
                } else {
                    log.push(conflicted.event.clone());
                    log.push(unlink.clone());
                }
            } else {
                log.push(conflicted.event.clone());
                if unlink_first {
                    log.push(unlink.clone());
                    log.push(holder.event.clone());
                } else {
                    log.push(holder.event.clone());
                    log.push(unlink.clone());
                }
            }
            orders.push(Projection::fold(&log).expect("a log every handler accepted rebuilds"));
        }

        let [unlink_first, unlink_last] = orders.as_slice() else {
            unreachable!("two orders");
        };
        assert_eq!(
            unlink_first, unlink_last,
            "two interleavings of one accepted race rebuild to one read model"
        );

        let expected = if unlink_the_holder {
            // Promotion: the holder left the key and the next smallest record holds it.
            Some(conflicted.external_principal_id)
        } else {
            Some(holder.external_principal_id)
        };
        assert_eq!(
            unlink_first.link(&key).map(|held| held.id),
            expected,
            "the key resolves to the smallest `Linked` record on it"
        );
        // Before either unlink, both records are `Linked` on one key: the smaller holds it
        // and the larger is the conflict the rebuild reports.
        let mut raced = head.clone();
        raced.push(holder.event.clone());
        raced.push(conflicted.event.clone());
        let raced = Projection::fold(&raced).expect("a race does not make the log unreadable");
        assert_eq!(
            raced
                .conflicts()
                .iter()
                .map(|conflict| conflict.external_principal_id)
                .collect::<Vec<_>>(),
            vec![conflicted.external_principal_id],
            "the larger identity is the conflict while both records are `Linked`"
        );

        // After either unlink one `Linked` record is left on the key, so it holds the key
        // and there is no conflict — promotion when the holder left, the holder standing
        // when the other did.
        assert!(
            unlink_first.conflicts().is_empty(),
            "one `Linked` record on a key is the holder and conflicts with nothing"
        );
        for id in [
            holder.external_principal_id,
            conflicted.external_principal_id,
        ] {
            let record = unlink_first
                .external_principal(&id)
                .unwrap_or_else(|| panic!("{id} is resolvable by its own identity"));
            assert_eq!(
                record.state == LinkState::Unlinked,
                id == unlinked_id,
                "exactly the unlinked record is in the terminal state"
            );
        }
        assert_eq!(
            unlink_first.organization_of(&principal(0x22)),
            Some(organization(10)),
            "every principal this crate's own events recorded is answerable"
        );
    }
}

/// `mandate.federation.OAuthClient`: registered, then disabled.
///
/// `mandate.federation.OAuthClientRegistered` is the creation record and carries the whole
/// entity — identity, organization, `public`, the exact redirect set and the PKCE method —
/// so the fold materializes the client from that event alone and reads no command input or
/// response (`federation.yaml`, `RegisterOAuthClient`).
#[test]
fn an_oauth_client_replays_from_its_events() {
    let mut live = Projection::default();
    let mut log = Vec::new();
    let mut allocator = SequentialAllocator::new();

    let registered = register_o_auth_client(
        &RegisterOAuthClient {
            context: context(organization(10)),
            public: true,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
        },
        &admission(),
        &mut allocator,
    )
    .expect("an administrator of an admitted organization registering an admitted redirect");
    commit(&mut live, &mut log, registered.event);

    let disabled = disable_oauth_client(
        &DisableOAuthClient {
            context: context(organization(10)),
            id: registered.id,
        },
        &live,
    )
    .expect("a recorded client of this tenant");
    commit(&mut live, &mut log, disabled);

    assert_eq!(log.len(), 2, "one event per accepted command");
    let replayed = Projection::fold(&log).expect("the log rebuilds");
    assert_eq!(
        replayed.clients(),
        [OAuthClient {
            id: registered.id,
            organization_id: organization(10),
            public: true,
            redirect_uris: vec![RedirectUri::new(REDIRECT)],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Disabled,
        }],
        "every required field of the rebuilt record came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// A move naming a client no event created is still a log this fold cannot read.
///
/// The creating command exists now, so this is no longer every log that carries an
/// `OAuthClientDisabled`: it is the one whose creation is missing, which is what keeps a
/// lost creation visible rather than inventing the record the move would apply to.
#[test]
fn an_oauth_client_disable_naming_a_client_no_event_created_is_unreadable() {
    let mut live = Projection::default();
    let mut log = Vec::new();
    let _ = register(&mut live, &mut log, organization(10), true);

    assert!(
        Projection::fold(&log)
            .expect("the log rebuilds")
            .clients()
            .is_empty(),
        "no client was registered in this log"
    );

    let orphan = FederationEvent::OAuthClientDisabled {
        context: context(organization(10)),
        id: OAuthClientId::new(uuid(0x0c)),
    };
    log.push(orphan);

    assert_eq!(
        Projection::fold(&log),
        Err(FoldError::UnknownOAuthClient {
            id: OAuthClientId::new(uuid(0x0c))
        }),
        "a move naming a record no event created is a log this fold cannot read"
    );
}

// The redelivery property of this creation arm — `fold([e, e]) == fold([e])`, and a
// redelivery after a disable leaving the record `Disabled` — is decided by
// `tests/adversary_writers_1.rs`, which pins exactly the two cases
// `crates/mandate-model/tests/replay.rs` pins for the six `mandate.tenancy` creating
// events. The case that stood here asserted the opposite and was wrong.
