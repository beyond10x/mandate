//! `RegisterResourceServer` and `DisableResourceServer`, decided over the projection.
//!
//! The audience registry is what every other command in this domain reads: issuance
//! resolves a target through it, introspection resolves the caller's own registered server
//! through it, and `decision-blocker:identity-uniqueness` says an audience is unique within
//! an organization. Each case drives the real handler and then folds the event it returned,
//! so what is asserted is the record a rebuild would produce and not a value the handler
//! kept.

use mandate_sts::registry::{
    DisableResourceServer, RegisterResourceServer, ResourceServerReads, disable_resource_server,
    register_resource_server,
};
use mandate_sts::{IdentityAllocator, SequentialAllocator};
use mandate_token::CredentialProfile;
use mandate_token::projection::{
    CredentialEvent, DenialClause, Projection, RefusedOutcome, ResourceServerState,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, CredentialKind, DenialReason, Duration, OrganizationId,
    PrincipalId, ResourceServerId, RevocationGuarantee, Uuid, VerifiedContext,
};

fn uuid(tag: u8) -> Uuid {
    Uuid::from_bytes([tag; 16])
}

fn organization(tag: u8) -> OrganizationId {
    OrganizationId::new(uuid(tag))
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
        correlation: CorrelationId::new("registry"),
    }
}

fn reference_profile() -> CredentialProfile {
    CredentialProfile {
        name: "reference".to_owned(),
        kind: CredentialKind::Reference,
        revocation: RevocationGuarantee::ImmediateOnline,
        max_ttl: Duration::new("PT1H"),
        positive_cache_ttl: Duration::new("PT30S"),
        requires_online_authorization: true,
    }
}

fn registration(organization_id: OrganizationId, audience: &str) -> RegisterResourceServer {
    RegisterResourceServer {
        context: context(organization_id),
        audience: Audience::new(audience),
        profile: reference_profile(),
        allowed_exchange_sources: Vec::new(),
    }
}

/// One registration through the real handler, folded into a projection.
fn registered(
    organization_id: OrganizationId,
    audience: &str,
) -> (Projection, Vec<CredentialEvent>, ResourceServerId) {
    let mut allocator = SequentialAllocator::new();
    let outcome = register_resource_server(
        &registration(organization_id, audience),
        &Projection::default(),
        &mut allocator,
    )
    .expect("a free audience in the caller's own organization");
    let log = vec![outcome.event];
    (
        Projection::fold(&log).expect("one creation"),
        log,
        outcome.resource_server_id,
    )
}

#[test]
fn a_registration_responds_with_the_minted_identity_and_emits_the_declared_event() {
    let mut allocator = SequentialAllocator::new();
    let input = registration(organization(10), "api-a");

    let outcome = register_resource_server(&input, &Projection::default(), &mut allocator)
        .expect("a free audience in the caller's own organization");

    assert_eq!(
        outcome.event,
        CredentialEvent::ResourceServerRegistered {
            context: context(organization(10)),
            id: outcome.resource_server_id,
            audience: Audience::new("api-a"),
            credential_profile: reference_profile(),
            allowed_exchange_sources: Vec::new(),
        }
    );

    let held = Projection::fold(&[outcome.event]).expect("one creation");
    let record = held
        .resource_server(&outcome.resource_server_id)
        .expect("the registration the event created");
    assert_eq!(record.organization_id, organization(10));
    assert_eq!(record.audience, Audience::new("api-a"));
    assert_eq!(record.state, ResourceServerState::Enabled);
}

/// The registration is bound to the caller's verified organization and to nothing a caller
/// supplies: the input declares no organization at all.
#[test]
fn the_registration_is_bound_to_the_callers_verified_organization() {
    let (held, _, id) = registered(organization(11), "api-a");

    assert_eq!(held.organization_of(&id), Some(organization(11)));
    assert_eq!(held.is_enabled(&id), Some(true));
    assert_eq!(
        held.organization_of(&ResourceServerId::new(uuid(0x99))),
        None,
        "the read a composition needs answers nothing for a target no event created"
    );
    assert_eq!(held.is_enabled(&ResourceServerId::new(uuid(0x99))), None);
}

#[test]
fn a_second_registration_on_one_audience_is_refused_and_leaves_the_fold_unchanged() {
    let (held, log, _) = registered(organization(10), "api-a");
    let mut allocator = SequentialAllocator::new();

    let denied = register_resource_server(
        &registration(organization(10), "api-a"),
        &held,
        &mut allocator,
    )
    .expect_err("the audience is registered in this organization");

    assert_eq!(denied.reason, DenialReason::Denied);
    assert_eq!(denied.clause, DenialClause::AudienceAmbiguous);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
    assert_eq!(
        Projection::fold(&log).expect("the same log"),
        held,
        "a refusal writes no event, so the fold is the one it was"
    );
}

#[test]
fn the_same_audience_in_another_organization_is_a_different_key() {
    let (held, _, _) = registered(organization(10), "api-a");
    let mut allocator = SequentialAllocator::new();

    assert!(
        register_resource_server(
            &registration(organization(11), "api-a"),
            &held,
            &mut allocator
        )
        .is_ok()
    );
}

#[test]
fn an_allowed_source_that_does_not_resolve_is_refused() {
    let (held, _, _) = registered(organization(10), "api-a");
    let mut allocator = SequentialAllocator::new();
    let input = RegisterResourceServer {
        allowed_exchange_sources: vec![ResourceServerId::new(uuid(0x99))],
        ..registration(organization(10), "api-b")
    };

    let denied = register_resource_server(&input, &held, &mut allocator)
        .expect_err("the source is registered by no event");

    assert_eq!(denied.clause, DenialClause::SourceUnresolved);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn an_allowed_source_in_another_organization_is_refused() {
    let (held, log, _) = registered(organization(10), "api-a");
    let mut allocator = SequentialAllocator::new();
    // The helper minted the first identity from its own allocator; this one starts where
    // that left off, so the foreign registration is a distinct record.
    let _ = allocator.next_resource_server_id();
    let foreign = register_resource_server(
        &registration(organization(11), "api-x"),
        &held,
        &mut allocator,
    )
    .expect("another organization may register its own audience");
    let mut log = log;
    log.push(foreign.event);
    let held = Projection::fold(&log).expect("two creations");

    let input = RegisterResourceServer {
        allowed_exchange_sources: vec![foreign.resource_server_id],
        ..registration(organization(10), "api-b")
    };

    let denied = register_resource_server(&input, &held, &mut allocator)
        .expect_err("the source belongs to another organization");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::SourceOutsideOrganization);
}

#[test]
fn a_disabled_allowed_source_is_refused() {
    let (held, log, id) = registered(organization(10), "api-a");
    let mut log = log;
    log.push(
        disable_resource_server(
            &DisableResourceServer {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("an enabled registration in the caller's organization"),
    );
    let held = Projection::fold(&log).expect("a creation and its move");
    let mut allocator = SequentialAllocator::new();

    let input = RegisterResourceServer {
        allowed_exchange_sources: vec![id],
        ..registration(organization(10), "api-b")
    };

    let denied = register_resource_server(&input, &held, &mut allocator)
        .expect_err("the source is in its terminal state");

    assert_eq!(denied.clause, DenialClause::SourceDisabled);
}

/// "profile semantics are unadmitted" — three readings of it, each one a profile whose own
/// fields contradict what the profile promises a holder.
#[test]
fn a_profile_whose_semantics_contradict_themselves_is_refused() {
    let mut allocator = SequentialAllocator::new();
    let unadmitted = [
        // A positive cache that outlives the credential authorizes after it has expired.
        CredentialProfile {
            positive_cache_ttl: Duration::new("PT2H"),
            ..reference_profile()
        },
        // An immediate-online revocation guarantee that does not require online
        // authorization is a promise nothing keeps.
        CredentialProfile {
            requires_online_authorization: false,
            ..reference_profile()
        },
        // A lifetime that names no span is no bound at all.
        CredentialProfile {
            max_ttl: Duration::new("one hour"),
            ..reference_profile()
        },
        // A lifetime of nothing: the credential is expired when it is issued.
        CredentialProfile {
            max_ttl: Duration::new("PT0S"),
            positive_cache_ttl: Duration::new("PT0S"),
            ..reference_profile()
        },
    ];

    for profile in unadmitted {
        let input = RegisterResourceServer {
            profile: profile.clone(),
            ..registration(organization(10), "api-a")
        };

        let denied = register_resource_server(&input, &Projection::default(), &mut allocator)
            .err()
            .unwrap_or_else(|| panic!("{profile:?} was admitted"));
        assert_eq!(denied.clause, DenialClause::ProfileUnadmitted);
        assert_eq!(denied.outcome, RefusedOutcome::Denied);
    }
}

#[test]
fn disabling_emits_the_declared_event_and_moves_the_record() {
    let (held, log, id) = registered(organization(10), "api-a");

    let event = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect("an enabled registration in the caller's organization");

    assert_eq!(
        event,
        CredentialEvent::ResourceServerDisabled {
            context: context(organization(10)),
            id,
        }
    );

    let mut log = log;
    log.push(event);
    let held = Projection::fold(&log).expect("a creation and its move");
    assert_eq!(
        held.resource_server(&id).map(|server| server.state),
        Some(ResourceServerState::Disabled)
    );
}

#[test]
fn disabling_a_registration_no_event_created_is_refused() {
    let denied = disable_resource_server(
        &DisableResourceServer {
            id: ResourceServerId::new(uuid(0x99)),
            context: context(organization(10)),
        },
        &Projection::default(),
    )
    .expect_err("no event registered it");

    assert_eq!(denied.clause, DenialClause::TargetUnregistered);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

#[test]
fn disabling_another_organizations_registration_is_refused() {
    let (held, _, id) = registered(organization(10), "api-a");

    let denied = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(organization(11)),
        },
        &held,
    )
    .expect_err("the registration is another organization's");

    assert_eq!(denied.reason, DenialReason::TenantMismatch);
    assert_eq!(denied.clause, DenialClause::OrganizationMismatch);
    assert_eq!(denied.outcome, RefusedOutcome::Denied);
}

/// The declared `wrong-state` outcome, which is not the declared `denied` one: the contract
/// renders it 409 rather than 502 (`docs/architecture/command-obligations.md`).
#[test]
fn disabling_an_already_disabled_registration_is_the_wrong_state_outcome() {
    let (held, log, id) = registered(organization(10), "api-a");
    let mut log = log;
    log.push(
        disable_resource_server(
            &DisableResourceServer {
                id,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("the first disablement"),
    );
    let held = Projection::fold(&log).expect("a creation and its move");

    let denied = disable_resource_server(
        &DisableResourceServer {
            id,
            context: context(organization(10)),
        },
        &held,
    )
    .expect_err("`disable` starts from `Enabled` alone");

    assert_eq!(denied.outcome, RefusedOutcome::WrongState);
    assert_eq!(denied.clause, DenialClause::ServerDisabled);
}

/// A disabled registration releases its audience, so the deployment can register the
/// audience again — and the new registration is a new record, not the old one revived.
#[test]
fn a_disabled_registration_releases_its_audience() {
    let (held, log, first) = registered(organization(10), "api-a");
    let mut log = log;
    log.push(
        disable_resource_server(
            &DisableResourceServer {
                id: first,
                context: context(organization(10)),
            },
            &held,
        )
        .expect("the disablement"),
    );
    let held = Projection::fold(&log).expect("a creation and its move");
    let mut allocator = SequentialAllocator::new();
    let _ = allocator.next_resource_server_id();

    let outcome = register_resource_server(
        &registration(organization(10), "api-a"),
        &held,
        &mut allocator,
    )
    .expect("the audience is free again");

    assert_ne!(outcome.resource_server_id, first);
    log.push(outcome.event);
    let held = Projection::fold(&log).expect("two creations and a move");
    assert_eq!(
        held.registered(&organization(10), &Audience::new("api-a"))
            .map(|server| server.id),
        Some(outcome.resource_server_id)
    );
}
