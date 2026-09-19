//! The federation projections, the fold that materializes them, and
//! `RegisterFederationConnection`.
//!
//! `docs/adr/0009-event-sourced-persistence.md`: the events are the record and every
//! read is a fold. The store in these tests is exactly that — a `Vec` of events folded
//! by the crate's own projection.
//!
//! No corpus case in `tests/security/cases.json` names this file's subject; the eleven
//! cases that name `story:federation-linking` are exercised in `tests/link.rs` and
//! `tests/authenticate.rs`.

use mandate_federation::record::{
    ConnectionState, ExternalKey, FederationEvent, FoldError, OAuthClient, OAuthClientState,
    Projection, RegisterFederationConnection, register_federation_connection,
};
use mandate_federation::{
    ConnectionStore, DenialClause, LinkStore, PrincipalState, PrincipalStore, SequentialAllocator,
};
use mandate_model::TenantResolutionRule;
use mandate_types::value::Uuid;
use mandate_types::{
    Audience, ClientId, CorrelationId, CredentialId, DenialReason, EpochSnapshotRef,
    ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId, Issuer,
    OAuthClientId, OrganizationId, PkceMethod, PrincipalId, PrincipalKind, RedirectUri, SessionId,
    Timestamp, VerifiedContext,
};

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

fn session(tag: u8) -> SessionId {
    SessionId::new(uuid(tag))
}

/// The `correlation` the two context-free events declare, in place of the one a
/// `VerifiedContext` used to carry.
fn correlation() -> CorrelationId {
    CorrelationId::new("federation-linking")
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

fn linked_at() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn provisioned(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    external_principal_id: ExternalPrincipalId,
    subject: &str,
    link_method: ExternalLinkMethod,
    kind: PrincipalKind,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalProvisioned {
        organization_id,
        correlation: correlation(),
        connection_id,
        principal_id: principal(0x21),
        kind,
        display_name: String::from(subject),
        external_principal_id,
        subject: ExternalSubject::new(subject),
        link_method,
        linked_at: linked_at(),
    }
}

fn created(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    issuer: &str,
) -> FederationEvent {
    FederationEvent::FederationConnectionCreated {
        context: context(organization_id),
        connection_id,
        issuer: Issuer::new(issuer),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization_id),
        jit_provisioning: false,
    }
}

fn linked(
    connection_id: FederationConnectionId,
    organization_id: OrganizationId,
    external_principal_id: ExternalPrincipalId,
    subject: &str,
    principal_id: PrincipalId,
) -> FederationEvent {
    FederationEvent::ExternalPrincipalLinked {
        context: context(organization_id),
        connection_id,
        principal_id,
        external_principal_id,
        subject: ExternalSubject::new(subject),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: linked_at(),
    }
}

#[test]
fn fold_materializes_the_connection_projection() {
    let log = vec![created(
        connection(1),
        organization(10),
        "https://idp.example/one",
    )];

    let projection = Projection::fold(&log).expect("one connection is not a key conflict");

    let connections = projection.connections();
    assert_eq!(
        connections.len(),
        1,
        "one created connection, one projection"
    );
    assert_eq!(connections[0].id, connection(1));
    assert_eq!(connections[0].organization_id, organization(10));
    assert_eq!(
        connections[0].issuer,
        Issuer::new("https://idp.example/one")
    );
    assert_eq!(connections[0].state, ConnectionState::Enabled);
    assert!(
        !connections[0].jit_provisioning,
        "the created connection does not admit provisioning"
    );
}

#[test]
fn fold_materializes_the_external_principal_projection() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
    ];

    let projection = Projection::fold(&log).expect("one link is not a key conflict");

    let links = projection.links();
    assert_eq!(links.len(), 1, "one link event, one projection");
    assert_eq!(links[0].id, external_principal(0x71));
    assert_eq!(links[0].principal_id, principal(0x21));
    assert_eq!(links[0].subject, ExternalSubject::new("subject-one"));
    assert_eq!(links[0].link_method, ExternalLinkMethod::Administrator);
    assert_eq!(
        links[0].organization_id,
        organization(10),
        "the organization is read from the connection, never from the event"
    );
}

#[test]
fn an_oauth_client_disable_for_an_identity_no_event_created_is_refused() {
    // `mandate.federation.OAuthClientRegistered` is the creation record of an
    // `OAuthClient` (`systems/mandate/domains/federation.yaml`, `RegisterOAuthClient`).
    // A disable naming an identity no creation event put in the log is not a record this
    // fold can move, and it says so rather than inventing one.
    let log = vec![FederationEvent::OAuthClientDisabled {
        context: context(organization(10)),
        id: OAuthClientId::new(uuid(0x0c)),
    }];

    let refused = Projection::fold(&log).expect_err("no event in this log created that client");

    assert_eq!(
        refused,
        FoldError::UnknownOAuthClient {
            id: OAuthClientId::new(uuid(0x0c))
        }
    );
}

#[test]
fn register_federation_connection_creates_an_enabled_connection() {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(10)),
        jit_provisioning: true,
    };

    let existing = Projection::fold(&[]).expect("an empty log");
    let accepted = register_federation_connection(&input, &existing, &mut allocator)
        .expect("the organization binding is the caller's own");

    let projection = Projection::fold(&[accepted.event]).expect("one connection");
    let connections = projection.connections();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].id, accepted.connection_id);
    assert_eq!(connections[0].state, ConnectionState::Enabled);
    assert!(
        connections[0].jit_provisioning,
        "the provisioning setting is decided at registration"
    );
}

#[test]
fn register_federation_connection_denies_a_foreign_organization_binding() {
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(11)),
        jit_provisioning: false,
    };

    let existing = Projection::fold(&[]).expect("an empty log");
    let denied = register_federation_connection(&input, &existing, &mut allocator)
        .expect_err("the rule resolves to an organization the caller is not verified in");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
}

#[test]
fn a_disabled_connection_is_read_as_disabled_and_is_not_offered_for_its_issuer() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(10)),
            id: connection(1),
        },
    ];

    let projection = Projection::fold(&log).expect("a disable is not a key conflict");

    let read = projection
        .connection(&connection(1))
        .expect("a disabled connection is still a record");
    assert_eq!(read.state, ConnectionState::Disabled);
    assert!(
        projection
            .enabled_for_issuer(&Issuer::new("https://idp.example/one"))
            .is_empty(),
        "tenant resolution runs over enabled connections only"
    );
}

#[test]
fn a_second_link_for_one_external_key_is_recorded_as_a_conflict_and_the_smallest_holds_it() {
    // `decision-blocker:identity-uniqueness`: a unique index on the exact composite key,
    // on the projection. The index is a total order over the records: one key resolves to
    // the smallest `external_principal_id` on it, and every other record is recorded and
    // reported as a conflict rather than failing the whole log or being displaced out of
    // the map. A race must not poison every read that follows it, and must not resolve the
    // key by the order a rebuild presents the two aggregates in.
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
        linked(
            connection(1),
            organization(10),
            external_principal(0x72),
            "subject-one",
            principal(0x22),
        ),
    ];

    let projection = Projection::fold(&log).expect("a duplicate key does not fail the fold");

    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new("https://idp.example/one"),
        subject: ExternalSubject::new("subject-one"),
    };
    assert_eq!(
        projection.links().len(),
        2,
        "both records are materialized; neither is dropped or displaced"
    );
    assert_eq!(
        projection.link(&key).map(|link| link.id),
        Some(external_principal(0x71)),
        "the smallest external principal identity on the key is the one that resolves"
    );
    assert_eq!(
        projection.conflicts().len(),
        1,
        "the later event is recorded, not dropped"
    );
    assert_eq!(projection.conflicts()[0].key, key);
    assert_eq!(
        projection.conflicts()[0].external_principal_id,
        external_principal(0x72)
    );
}

#[test]
fn a_link_naming_a_connection_no_event_created_is_not_a_readable_history() {
    // J3: dropping a creation event loses a record silently. The fold refuses instead.
    let log = vec![linked(
        connection(1),
        organization(10),
        external_principal(0x71),
        "subject-one",
        principal(0x21),
    )];

    let refused = Projection::fold(&log).expect_err("no event created this connection");

    assert_eq!(
        refused,
        FoldError::UnknownConnection {
            connection_id: connection(1)
        }
    );
}

#[test]
fn every_event_naming_an_absent_connection_is_refused() {
    // The class: no event is silently discarded. Each of these names a connection the
    // log never created.
    for event in [
        FederationEvent::FederationConnectionDisabled {
            context: context(organization(10)),
            id: connection(1),
        },
        FederationEvent::FederationAuthenticated {
            session_id: session(0x91),
            principal_id: principal(0x21),
            audience: Audience::new("mandate"),
            correlation: correlation(),
            connection_id: connection(1),
            organization_id: organization(10),
            epochs: EpochSnapshotRef::new(uuid(0x3e)),
            expires_at: Timestamp::new("2026-12-31T00:00:00Z"),
        },
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            ExternalLinkMethod::ConfiguredFederation,
            PrincipalKind::User,
        ),
    ] {
        assert_eq!(
            Projection::fold(std::slice::from_ref(&event)),
            Err(FoldError::UnknownConnection {
                connection_id: connection(1)
            }),
            "silently discarded: {event:?}"
        );
    }
}

#[test]
fn the_literals_the_provisioned_payload_pins_are_enforced_by_the_fold() {
    // `federation.yaml` pins two literals in the `ExternalPrincipalProvisioned` payload:
    // `kind: User` and `link_method: ConfiguredFederation`. Both are enforced where the
    // event is read, not only where this crate writes it.
    let head = created(connection(1), organization(10), "https://idp.example/one");

    let wrong_method = vec![
        head.clone(),
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            ExternalLinkMethod::SecuritySupport,
            PrincipalKind::User,
        ),
    ];
    assert_eq!(
        Projection::fold(&wrong_method),
        Err(FoldError::ProvisionedLinkMethod {
            external_principal_id: external_principal(0x71),
            link_method: ExternalLinkMethod::SecuritySupport,
        })
    );

    let wrong_kind = vec![
        head,
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            ExternalLinkMethod::ConfiguredFederation,
            PrincipalKind::Service,
        ),
    ];
    assert_eq!(
        Projection::fold(&wrong_kind),
        Err(FoldError::ProvisionedKind {
            external_principal_id: external_principal(0x71),
            kind: PrincipalKind::Service,
        })
    );
}

#[test]
fn a_link_whose_subject_is_empty_is_not_a_readable_history() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "   ",
            principal(0x21),
        ),
    ];

    let refused = Projection::fold(&log).expect_err("an empty subject is not a key component");

    assert_eq!(
        refused,
        FoldError::EmptySubject {
            external_principal_id: external_principal(0x71)
        }
    );
}

#[test]
fn the_projection_answers_the_principal_store_only_for_principals_it_recorded() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
    ];
    let projection = Projection::fold(&log).expect("one link");

    assert_eq!(
        projection.organization_of(&principal(0x21)),
        Some(organization(10))
    );
    assert_eq!(
        projection.organization_of(&principal(0x22)),
        None,
        "a principal this crate's events never recorded is unanswered, and an \
         unanswered principal is refused rather than admitted"
    );
}

#[test]
fn an_unconditional_rule_is_unadmitted_where_another_organization_holds_the_issuer() {
    // J2, coordinator ruling: two organizations cannot share an issuer when either
    // resolves it unconditionally, because every login on that issuer would then match
    // the unconditional rule as well as the right one.
    let log = vec![created(
        connection(1),
        organization(10),
        "https://idp.example/one",
    )];
    let existing = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(11)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(11)),
        jit_provisioning: false,
    };

    let denied = register_federation_connection(&input, &existing, &mut allocator)
        .expect_err("organization 10 already holds a connection on this issuer");

    assert_eq!(denied.clause, DenialClause::TenantResolutionUnadmitted);
}

#[test]
fn a_connection_is_unadmitted_where_another_organization_resolves_the_issuer_unconditionally() {
    // The reverse direction of the same ruling: the unconditional rule may be the one
    // already registered.
    let log = vec![created(
        connection(1),
        organization(10),
        "https://idp.example/one",
    )];
    let existing = Projection::fold(&log).expect("one connection with an unconditional rule");
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(11)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization(11),
            verified_claim_name: Some(String::from("org")),
            verified_claim_value: Some(String::from("eleven")),
        },
        jit_provisioning: false,
    };

    let denied = register_federation_connection(&input, &existing, &mut allocator)
        .expect_err("organization 10 resolves this issuer unconditionally");

    assert_eq!(denied.clause, DenialClause::TenantResolutionUnadmitted);
}

#[test]
fn one_organization_may_hold_two_connections_on_one_issuer() {
    // The ruling is about *other* organizations. A single organization refining its own
    // issuer with a second connection is the configuration `enabled_for_issuer` serves.
    let log = vec![created(
        connection(1),
        organization(10),
        "https://idp.example/one",
    )];
    let existing = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(10)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: unconditional(organization(10)),
        jit_provisioning: false,
    };

    register_federation_connection(&input, &existing, &mut allocator)
        .expect("the same organization already holds this issuer");
}

#[test]
fn distinct_issuers_make_distinct_external_keys_for_one_subject() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        created(connection(2), organization(10), "https://idp.example/two"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
        linked(
            connection(2),
            organization(10),
            external_principal(0x72),
            "subject-one",
            principal(0x22),
        ),
    ];

    let projection = Projection::fold(&log).expect("two issuers, two keys, no conflict");

    let links = projection.links();
    assert_eq!(
        links.len(),
        2,
        "one subject under two issuers is two records"
    );
    let first = projection
        .key_of(&links[0])
        .expect("a link's connection is in the projection");
    let second = projection
        .key_of(&links[1])
        .expect("a link's connection is in the projection");
    assert_ne!(first, second, "the issuer is part of the key");
    assert_eq!(first.subject, second.subject);
}

#[test]
fn the_link_store_reads_the_exact_composite_key_only() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
    ];
    let projection = Projection::fold(&log).expect("one link");
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new("https://idp.example/one"),
        subject: ExternalSubject::new("subject-one"),
    };

    assert_eq!(
        projection.link(&key).map(|link| link.principal_id),
        Some(principal(0x21))
    );
    for other in [
        ExternalKey {
            organization_id: organization(11),
            ..key.clone()
        },
        ExternalKey {
            issuer: Issuer::new("https://idp.example/two"),
            ..key.clone()
        },
        ExternalKey {
            subject: ExternalSubject::new("subject-two"),
            ..key.clone()
        },
    ] {
        assert!(
            projection.link(&other).is_none(),
            "a key differing in one component is a different key: {other:?}"
        );
    }
}

/// R1: a rule another organization's connection could match for the same proof is
/// refused at registration. Two equal conditional rules are exactly that.
#[test]
fn a_conditional_rule_another_organization_already_holds_is_unadmitted() {
    let log = vec![FederationEvent::FederationConnectionCreated {
        context: context(organization(10)),
        connection_id: connection(1),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization(10),
            verified_claim_name: Some(String::from("org")),
            verified_claim_value: Some(String::from("acme")),
        },
        jit_provisioning: false,
    }];
    let existing = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();
    let input = RegisterFederationConnection {
        context: context(organization(11)),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization(11),
            verified_claim_name: Some(String::from("org")),
            verified_claim_value: Some(String::from("acme")),
        },
        jit_provisioning: false,
    };

    let denied = register_federation_connection(&input, &existing, &mut allocator)
        .expect_err("organization 10 already resolves this issuer on org=acme");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::TenantResolutionUnadmitted);
}

/// The boundary of R1: a different claim value on a shared issuer cannot match the same
/// proof, so it is admitted. The guard refuses collisions, not sharing.
#[test]
fn a_different_claim_value_on_a_shared_issuer_is_admitted() {
    let log = vec![FederationEvent::FederationConnectionCreated {
        context: context(organization(10)),
        connection_id: connection(1),
        issuer: Issuer::new("https://idp.example/one"),
        client_id: ClientId::new("configured-client"),
        tenant_resolution: TenantResolutionRule {
            configured_organization: organization(10),
            verified_claim_name: Some(String::from("org")),
            verified_claim_value: Some(String::from("acme")),
        },
        jit_provisioning: false,
    }];
    let existing = Projection::fold(&log).expect("one connection");
    let mut allocator = SequentialAllocator::new();

    for rule in [
        TenantResolutionRule {
            configured_organization: organization(11),
            verified_claim_name: Some(String::from("org")),
            verified_claim_value: Some(String::from("beta")),
        },
        TenantResolutionRule {
            configured_organization: organization(11),
            verified_claim_name: Some(String::from("dept")),
            verified_claim_value: Some(String::from("acme")),
        },
    ] {
        let input = RegisterFederationConnection {
            context: context(organization(11)),
            issuer: Issuer::new("https://idp.example/one"),
            client_id: ClientId::new("configured-client"),
            tenant_resolution: rule.clone(),
            jit_provisioning: false,
        };
        register_federation_connection(&input, &existing, &mut allocator).unwrap_or_else(
            |denied| panic!("{rule:?} matches no proof org 10's rule matches: {denied:?}"),
        );
    }
}

/// Finding 3: the holder of one key is a property of the records, not of the order a
/// rebuild presents them in. The order is the `external_principal_id`, and `linked_at`
/// decides nothing: two writers racing one key hold no clock in common.
#[test]
fn the_same_link_holds_the_key_whatever_order_the_log_is_replayed_in() {
    let head = created(connection(1), organization(10), "https://idp.example/one");
    let earlier = FederationEvent::ExternalPrincipalLinked {
        context: context(organization(10)),
        connection_id: connection(1),
        principal_id: principal(0x21),
        external_principal_id: external_principal(0x71),
        subject: ExternalSubject::new("subject-one"),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: Timestamp::new("2026-09-18T00:00:00Z"),
    };
    let later = FederationEvent::ExternalPrincipalLinked {
        context: context(organization(10)),
        connection_id: connection(1),
        principal_id: principal(0x22),
        external_principal_id: external_principal(0x72),
        subject: ExternalSubject::new("subject-one"),
        link_method: ExternalLinkMethod::Administrator,
        linked_at: Timestamp::new("2026-09-18T00:00:01Z"),
    };
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new("https://idp.example/one"),
        subject: ExternalSubject::new("subject-one"),
    };

    for log in [
        vec![head.clone(), earlier.clone(), later.clone()],
        vec![head, later, earlier],
    ] {
        let projection = Projection::fold(&log).expect("a duplicate key is a conflict");

        assert_eq!(
            projection.link(&key).map(|link| link.id),
            Some(external_principal(0x71)),
            "the smallest external principal identity holds the key whichever order the \
             streams arrive in"
        );
        assert_eq!(projection.conflicts().len(), 1);
        assert_eq!(
            projection.conflicts()[0].external_principal_id,
            external_principal(0x72)
        );
    }
}

/// The identity decides on its own, so equal timestamps are not a tie at all: the record
/// with the smallest `external_principal_id` holds the key, and that identity is unique
/// per event.
#[test]
fn an_equal_timestamp_is_broken_by_the_external_principal_identity() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x72),
            "subject-one",
            principal(0x22),
        ),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            principal(0x21),
        ),
    ];
    let key = ExternalKey {
        organization_id: organization(10),
        issuer: Issuer::new("https://idp.example/one"),
        subject: ExternalSubject::new("subject-one"),
    };

    let projection = Projection::fold(&log).expect("a duplicate key is a conflict");

    assert_eq!(
        projection.link(&key).map(|link| link.id),
        Some(external_principal(0x71)),
        "equal linked_at, lower identity wins, whichever arrived first"
    );
}

/// Finding 4: the event that lost the key is still the creation record of the principal
/// it named, so the principal is answerable.
#[test]
fn the_principal_a_losing_link_created_is_answerable_from_the_conflict() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        provisioned(
            connection(1),
            organization(10),
            external_principal(0x71),
            "subject-one",
            ExternalLinkMethod::ConfiguredFederation,
            PrincipalKind::User,
        ),
        FederationEvent::ExternalPrincipalProvisioned {
            organization_id: organization(10),
            correlation: correlation(),
            connection_id: connection(1),
            principal_id: principal(0x22),
            kind: PrincipalKind::User,
            display_name: String::from("subject-one"),
            external_principal_id: external_principal(0x72),
            subject: ExternalSubject::new("subject-one"),
            link_method: ExternalLinkMethod::ConfiguredFederation,
            linked_at: Timestamp::new("2026-09-18T00:00:01Z"),
        },
    ];

    let projection = Projection::fold(&log).expect("a duplicate key is a conflict");

    assert_eq!(projection.conflicts().len(), 1);
    assert_eq!(projection.conflicts()[0].principal_id, principal(0x22));
    assert_eq!(projection.conflicts()[0].connection_id, connection(1));
    assert_eq!(
        projection.organization_of(&principal(0x22)),
        Some(organization(10)),
        "the losing event created this principal; the conflict is where it is recorded"
    );
    assert_eq!(
        projection.state_of(&principal(0x22)),
        Some(PrincipalState::Active),
        "a principal this crate's events created is Active until the identity domain \
         says otherwise"
    );
}

/// R3/J4: the fold refuses a subject that differs from its own trim. Trim-refusal is the
/// only normalization; nothing is canonicalized.
#[test]
fn a_link_whose_subject_is_not_its_own_trim_is_not_a_readable_history() {
    for subject in [" subject-one", "subject-one ", "\tsubject-one"] {
        let log = vec![
            created(connection(1), organization(10), "https://idp.example/one"),
            linked(
                connection(1),
                organization(10),
                external_principal(0x71),
                subject,
                principal(0x21),
            ),
        ];

        let refused =
            Projection::fold(&log).expect_err("the subject is not the subject it was issued as");

        assert_eq!(
            refused,
            FoldError::SubjectNotTrimmed {
                external_principal_id: external_principal(0x71)
            },
            "subject {subject:?}"
        );
    }
}

/// The case the trim rule must not break: a subject with inner whitespace, or one that
/// differs from another only by case, is issued as it is and stored as it is.
#[test]
fn a_subject_is_stored_exactly_as_it_was_issued() {
    let log = vec![
        created(connection(1), organization(10), "https://idp.example/one"),
        linked(
            connection(1),
            organization(10),
            external_principal(0x71),
            "Subject One",
            principal(0x21),
        ),
        linked(
            connection(1),
            organization(10),
            external_principal(0x72),
            "subject one",
            principal(0x22),
        ),
    ];

    let projection = Projection::fold(&log).expect("two distinct subjects");

    assert_eq!(
        projection.links().len(),
        2,
        "case is part of the subject; nothing is folded together"
    );
    assert_eq!(
        projection.links()[0].subject,
        ExternalSubject::new("Subject One")
    );
}

/// The creation arm: the fold materializes the client from the event alone.
///
/// `mandate.federation.OAuthClientRegistered` carries the whole record, including its own
/// `organization_id`, so the binding is read from the payload and **not** from the
/// registering caller's context — which is where `FederationConnectionCreated` differs,
/// its payload declaring no organization at all. A case that carried the same organization
/// in both places could not tell the two apart, so this one carries different ones.
#[test]
fn an_oauth_client_registration_materializes_the_record_the_event_carries() {
    let log = vec![FederationEvent::OAuthClientRegistered {
        context: context(organization(11)),
        id: OAuthClientId::new(uuid(0x0c)),
        organization_id: organization(10),
        public: true,
        redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
        pkce_method: PkceMethod::S256,
    }];

    let projection = Projection::fold(&log).expect("one creation");

    assert_eq!(
        projection.clients(),
        [OAuthClient {
            id: OAuthClientId::new(uuid(0x0c)),
            organization_id: organization(10),
            public: true,
            redirect_uris: vec![RedirectUri::new("https://app.example/callback")],
            pkce_method: PkceMethod::S256,
            state: OAuthClientState::Recorded,
        }],
        "the record is the event's, organization included"
    );
}
