//! The fold is rebuildable from its events alone.
//!
//! `docs/adr/0009-event-sourced-persistence.md`: "A command produces domain events; the
//! events are the record; every read is a fold over them ... State tables are
//! projections: derived, droppable, rebuildable, never authoritative."
//!
//! `crates/mandate-model/tests/adversary_tenancy_topology.rs`
//! `every_required_projection_field_is_carried_by_a_declared_event` decides that the
//! compiled *contract* carries every required field. These cases decide the other half:
//! that this crate's own `decide` / `apply` / `fold` split actually rebuilds each of the
//! six projections from the events its commands returned, field for field.
//!
//! Every case here drives the real API: `decide` returns the declared event without
//! touching the projection, `apply` writes it, `fold` replays a log from an empty
//! projection, and each of the twelve public command wrappers returns the event it
//! applied. Nothing reconstructs state by re-running commands.
//!
//! `fold` and the live projection share one `apply`, so `fold(&log) == live` alone is
//! close to a tautology: a field `apply` drops is dropped identically on both sides and
//! the equality still holds. That is not a hypothetical — deleting `display_name` from
//! the `TeamCreated` arm of `Tenancy::apply` left every equality here green. So each of
//! the six cases below *also* asserts the rebuilt record against a literal carrying every
//! field the compiled entity marks required. The equality says the rebuild is complete;
//! the literal says the log is what it was rebuilt from.

use std::collections::BTreeSet;

use mandate_model::graph::{Resource, ResourceEvent, ResourceState, Topology};
use mandate_model::tenancy::{
    MembershipAuthority, Organization, OrganizationMembership, OrganizationMembershipState,
    OrganizationState, Space, SpaceState, Team, TeamMembership, TeamMembershipState, TeamState,
    Tenancy, TenancyEvent,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DelegationId, ExecutionId, MembershipContributionId,
    OrganizationId, OrganizationMembershipId, PrincipalId, ResourceId, ResourceRef, ResourceType,
    SpaceId, TeamId, TeamMembershipId, VerifiedContext,
};

const EVENTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/events");

fn uuid(tag: u16) -> String {
    format!("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f{tag:04x}")
}

fn organization(tag: u16) -> OrganizationId {
    OrganizationId::parse(&uuid(tag)).expect("organization identity")
}

fn membership(tag: u16) -> OrganizationMembershipId {
    OrganizationMembershipId::parse(&uuid(tag)).expect("membership identity")
}

fn principal(tag: u16) -> PrincipalId {
    PrincipalId::parse(&uuid(tag)).expect("principal identity")
}

fn team(tag: u16) -> TeamId {
    TeamId::parse(&uuid(tag)).expect("team identity")
}

fn team_membership(tag: u16) -> TeamMembershipId {
    TeamMembershipId::parse(&uuid(tag)).expect("team membership identity")
}

fn contribution(tag: u16) -> MembershipContributionId {
    MembershipContributionId::parse(&uuid(tag)).expect("contribution identity")
}

fn space(tag: u16) -> SpaceId {
    SpaceId::parse(&uuid(tag)).expect("space identity")
}

fn resource(tag: u16) -> ResourceId {
    ResourceId::parse(&uuid(tag)).expect("resource identity")
}

fn resource_ref(tag: u16) -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: resource(tag),
    }
}

fn context(organization: OrganizationId, subject: PrincipalId) -> VerifiedContext {
    VerifiedContext {
        subject,
        actor: None,
        organization,
        audience: Audience::new("mandate"),
        credential: CredentialId::parse(&uuid(0xffff)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// The platform administrator's verified context.
///
/// `CreateOrganization` and `CloseOrganization` are platform-scoped and
/// `AddOrganizationMembership` has a platform path, so the organization this names is the
/// administrator's own and never the one being written. Every one of the three declares a
/// `mandate.core.VerifiedContext` in its payload, so every one of them takes one.
fn platform() -> VerifiedContext {
    context(organization(0xfff0), principal(0xfff1))
}

/// Decide, apply, record: the three steps a command path takes, in order. The decision
/// is read off the projection as it stands, the event is applied to it, and the log keeps
/// the event that was applied.
///
/// A macro rather than a function because `decide_*` borrows the projection immutably and
/// `apply` borrows it mutably; the decision has to be in hand before the write begins,
/// which is the ordering the split exists to enforce.
macro_rules! commit {
    ($fold:expr, $log:expr, $decided:expr $(,)?) => {{
        let decided: Result<_, _> = $decided;
        let event = decided.expect("the command is accepted");
        $fold.apply(&event);
        $log.push(event);
    }};
}

/// `mandate.tenancy.Organization`: created, then closed.
#[test]
fn an_organization_replays_from_its_events() {
    let acme = organization(1);
    let platform = context(organization(2), principal(9));
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&platform, acme, "Acme"),
    );
    commit!(live, log, live.decide_close_organization(&platform, acme));

    assert_eq!(log.len(), 2, "one event per accepted command");
    let replayed = Tenancy::fold(&log);
    assert_eq!(
        replayed.organization(acme),
        Some(&Organization {
            id: acme,
            display_name: "Acme".to_owned(),
            state: OrganizationState::Closed,
        }),
        "every required field of the rebuilt record came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.tenancy.OrganizationMembership`: added on the platform path, then removed.
#[test]
fn an_organization_membership_replays_from_its_events() {
    let acme = organization(1);
    let platform = context(organization(2), principal(9));
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&platform, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_add_organization_membership(
            &platform,
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        ),
    );
    commit!(
        live,
        log,
        live.decide_remove_organization_membership(&caller, membership(20)),
    );

    let replayed = Tenancy::fold(&log);
    assert_eq!(
        replayed.organization_membership(membership(20)),
        Some(&OrganizationMembership {
            id: membership(20),
            organization_id: acme,
            principal_id: joiner,
            state: OrganizationMembershipState::Removed,
        }),
        "every required field of the rebuilt record came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.tenancy.Team`: created inside the verified organization, then retired.
#[test]
fn a_team_replays_from_its_events() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&caller, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_create_team(&caller, team(30), "Platform"),
    );
    commit!(live, log, live.decide_retire_team(&caller, team(30)));

    let replayed = Tenancy::fold(&log);
    assert_eq!(
        replayed.team(team(30)),
        Some(&Team {
            id: team(30),
            organization_id: acme,
            display_name: "Platform".to_owned(),
            state: TeamState::Retired,
        }),
        "every required field of the rebuilt record came off the log, the organization \
         from the event's own context"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.tenancy.TeamMembership`: recorded, then removed.
#[test]
fn a_team_membership_replays_from_its_events() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&caller, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(20),
            acme,
            joiner,
        ),
    );
    commit!(
        live,
        log,
        live.decide_create_team(&caller, team(30), "Platform"),
    );
    commit!(
        live,
        log,
        live.decide_add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        ),
    );
    commit!(
        live,
        log,
        live.decide_remove_team_membership(&caller, team_membership(50)),
    );

    let replayed = Tenancy::fold(&log);
    assert_eq!(
        replayed.team_membership(team_membership(50)),
        Some(&TeamMembership {
            id: team_membership(50),
            organization_id: acme,
            team_id: team(30),
            principal_id: joiner,
            state: TeamMembershipState::Removed,
        }),
        "every required field of the rebuilt record came off the log"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.tenancy.Space`: created inside the verified organization, then retired.
#[test]
fn a_space_replays_from_its_events() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&caller, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_create_space(&caller, space(40), "Production"),
    );
    commit!(live, log, live.decide_retire_space(&caller, space(40)));

    let replayed = Tenancy::fold(&log);
    assert_eq!(
        replayed.space(space(40)),
        Some(&Space {
            id: space(40),
            organization_id: acme,
            display_name: "Production".to_owned(),
            state: SpaceState::Retired,
        }),
        "every required field of the rebuilt record came off the log, the organization \
         from the event's own context"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// `mandate.graph.Resource`: a parent and a child registered, the child deregistered,
/// then the parent — the whole supported lifecycle of the projection.
#[test]
fn a_resource_replays_from_its_events() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");

    let mut live = Topology::new();
    let mut log = Vec::new();
    commit!(
        live,
        log,
        live.decide_register(&tenancy, &caller, &resource_ref(100), None),
    );
    commit!(
        live,
        log,
        live.decide_register(&tenancy, &caller, &resource_ref(101), Some(resource(100))),
    );
    commit!(live, log, live.decide_deregister(&caller, resource(101)),);
    commit!(live, log, live.decide_deregister(&caller, resource(100)),);

    let replayed = Topology::fold(&log);
    assert_eq!(
        replayed.record(resource(101)),
        Some(&Resource {
            id: resource(101),
            organization_id: acme,
            resource_type: ResourceType::new("document"),
            parent: Some(resource(100)),
            space_id: None,
            state: ResourceState::Deregistered,
        }),
        "every required field of the rebuilt record came off the log; `space_id` stays \
         absent because no command in `systems/mandate` carries a space into it"
    );
    assert_eq!(replayed, live, "the log rebuilds the projection");
}

/// Every entity and every supported mutation in one log, replayed from empty.
#[test]
fn the_whole_tenancy_log_replays_field_for_field() {
    let acme = organization(1);
    let platform = context(organization(2), principal(9));
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&platform, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_add_organization_membership(
            &platform,
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        ),
    );
    commit!(
        live,
        log,
        live.decide_create_team(&caller, team(30), "Platform"),
    );
    commit!(
        live,
        log,
        live.decide_add_team_membership(
            &caller,
            team_membership(50),
            team(30),
            joiner,
            contribution(60),
        ),
    );
    commit!(
        live,
        log,
        live.decide_create_space(&caller, space(40), "Production"),
    );
    commit!(
        live,
        log,
        live.decide_remove_team_membership(&caller, team_membership(50)),
    );
    commit!(live, log, live.decide_retire_team(&caller, team(30)));
    commit!(live, log, live.decide_retire_space(&caller, space(40)));
    commit!(
        live,
        log,
        live.decide_remove_organization_membership(&caller, membership(20)),
    );
    commit!(live, log, live.decide_close_organization(&platform, acme),);

    assert_eq!(log.len(), 10, "all ten commands are exercised");
    let named: BTreeSet<&str> = log.iter().map(TenancyEvent::ess_name).collect();
    assert_eq!(
        named.len(),
        10,
        "each of the ten declared events appears once"
    );

    let replayed = Tenancy::fold(&log);
    assert_eq!(replayed.record_count(), live.record_count());
    assert_eq!(
        replayed, live,
        "a projection dropped and rebuilt from the log is the projection that was dropped"
    );
}

/// A log with nothing in it folds to the projection nothing has been written to.
#[test]
fn an_empty_log_folds_to_the_empty_projection() {
    assert_eq!(Tenancy::fold(&[]), Tenancy::new());
    assert_eq!(Topology::fold(&[]), Topology::new());
}

/// The property that actually holds, stated rather than assumed.
///
/// Every `apply` is a deterministic write keyed by the record's own identity: a creation
/// inserts at that key, a state move rewrites the state at that key, and nothing appends
/// or counts. So the projection after a log is a function of the last event touching each
/// identity, and replaying the same log twice reaches the same projection as replaying it
/// once. That is what makes a redelivered append group safe to re-apply
/// (`docs/adr/0009-event-sourced-persistence.md`, worker-orchestration), and it is a
/// claim about the whole log rather than about a single event: the intermediate states
/// inside the second pass differ, and only the end state is asserted.
#[test]
fn replaying_the_whole_log_twice_reaches_the_projection_replaying_it_once_reaches() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut live = Tenancy::new();
    let mut log = Vec::new();

    commit!(
        live,
        log,
        live.decide_create_organization(&caller, acme, "Acme"),
    );
    commit!(
        live,
        log,
        live.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(20),
            acme,
            joiner,
        ),
    );
    commit!(
        live,
        log,
        live.decide_remove_organization_membership(&caller, membership(20)),
    );
    commit!(live, log, live.decide_close_organization(&caller, acme),);

    let twice: Vec<TenancyEvent> = log.iter().chain(log.iter()).cloned().collect();
    assert_eq!(
        Tenancy::fold(&twice),
        Tenancy::fold(&log),
        "the fold of a log replayed twice is the fold of the log"
    );
    assert_eq!(Tenancy::fold(&twice), live);
}

/// Every public mutating method returns the event that reproduces its own write.
///
/// The twelve commands are this crate's whole public write surface, and each one now
/// returns its declared event rather than `()`. The other cases here drive `decide` and
/// `apply` directly; this one drives the wrappers a caller actually calls, keeps only what
/// they *returned*, and folds that into an empty projection. A wrapper that wrote anything
/// its return value does not describe — or that wrote without returning an event at all —
/// makes the two projections differ here.
#[test]
fn every_public_mutating_method_returns_the_event_that_reproduces_its_write() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    let mut log = vec![
        tenancy
            .create_organization(&platform(), acme, "Acme")
            .expect("the organization is recorded"),
    ];
    log.push(
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                membership(20),
                acme,
                joiner,
            )
            .expect("the platform path seeds the first membership"),
    );
    log.push(
        tenancy
            .create_team(&caller, team(30), "Platform")
            .expect("the team is recorded"),
    );
    log.push(
        tenancy
            .add_team_membership(
                &caller,
                team_membership(50),
                team(30),
                joiner,
                contribution(60),
            )
            .expect("the team membership is recorded"),
    );
    log.push(
        tenancy
            .create_space(&caller, space(40), "Production")
            .expect("the space is recorded"),
    );
    log.push(
        tenancy
            .remove_team_membership(&caller, team_membership(50))
            .expect("the team membership is removed"),
    );
    log.push(
        tenancy
            .retire_team(&caller, team(30))
            .expect("the team is retired"),
    );
    log.push(
        tenancy
            .retire_space(&caller, space(40))
            .expect("the space is retired"),
    );
    log.push(
        tenancy
            .remove_organization_membership(&caller, membership(20))
            .expect("the membership is removed"),
    );
    log.push(
        tenancy
            .close_organization(&platform(), acme)
            .expect("the organization is closed"),
    );

    assert_eq!(log.len(), 10, "all ten tenancy commands were driven");
    let named: BTreeSet<&str> = log.iter().map(TenancyEvent::ess_name).collect();
    assert_eq!(named.len(), 10, "each returned a different declared event");
    assert_eq!(
        Tenancy::fold(&log),
        tenancy,
        "what the ten wrappers returned rebuilds what the ten wrappers wrote"
    );

    let mut open = Tenancy::new();
    open.create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    let mut topology = Topology::new();
    let mut resources = vec![
        topology
            .register(&open, &caller, &resource_ref(100), None)
            .expect("the parent is registered"),
    ];
    resources.push(
        topology
            .register(&open, &caller, &resource_ref(101), Some(resource(100)))
            .expect("the child is registered"),
    );
    resources.push(
        topology
            .deregister(&caller, resource(101))
            .expect("the child is deregistered"),
    );

    assert_eq!(resources.len(), 3);
    assert_eq!(
        Topology::fold(&resources),
        topology,
        "and what the two resource wrappers returned rebuilds what they wrote"
    );
}

/// A creation names the first event of a record, so a redelivered creation writes
/// nothing — not even when the record has since reached a terminal state.
///
/// The event log is delivered at least once (`docs/adr/0009-event-sourced-persistence.md`,
/// worker-orchestration), so a log may present a creation twice. An unconditional keyed
/// insert would return the record to its initial state and overwrite the fields the first
/// creation carried, producing a projection no `decide_*` path can reach. `apply` is
/// insert-if-absent for all six creating events, and this decides it for each of them.
#[test]
fn a_redelivered_creation_after_a_terminal_state_writes_nothing() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);

    // One creation, one terminal move, and the same creation again carrying different
    // content — per creating event of `mandate.tenancy`.
    let cases: Vec<(&str, Vec<TenancyEvent>, Vec<TenancyEvent>)> = vec![
        (
            "mandate.tenancy.OrganizationCreated",
            vec![
                TenancyEvent::OrganizationCreated {
                    context: caller.clone(),
                    organization_id: acme,
                    display_name: "Acme".to_owned(),
                },
                TenancyEvent::OrganizationClosed {
                    context: caller.clone(),
                    id: acme,
                },
            ],
            vec![TenancyEvent::OrganizationCreated {
                context: caller.clone(),
                organization_id: acme,
                display_name: "Renamed".to_owned(),
            }],
        ),
        (
            "mandate.tenancy.OrganizationMembershipAdded",
            vec![
                TenancyEvent::OrganizationCreated {
                    context: caller.clone(),
                    organization_id: acme,
                    display_name: "Acme".to_owned(),
                },
                TenancyEvent::OrganizationMembershipAdded {
                    context: caller.clone(),
                    organization_id: acme,
                    principal_id: joiner,
                    membership_id: membership(20),
                },
                TenancyEvent::OrganizationMembershipRemoved {
                    context: caller.clone(),
                    id: membership(20),
                },
            ],
            vec![TenancyEvent::OrganizationMembershipAdded {
                context: caller.clone(),
                organization_id: acme,
                principal_id: principal(12),
                membership_id: membership(20),
            }],
        ),
        (
            "mandate.tenancy.TeamCreated",
            vec![
                TenancyEvent::TeamCreated {
                    context: caller.clone(),
                    team_id: team(30),
                    display_name: "Platform".to_owned(),
                },
                TenancyEvent::TeamRetired {
                    context: caller.clone(),
                    id: team(30),
                },
            ],
            vec![TenancyEvent::TeamCreated {
                context: caller.clone(),
                team_id: team(30),
                display_name: "Renamed".to_owned(),
            }],
        ),
        (
            "mandate.tenancy.TeamMembershipAdded",
            vec![
                TenancyEvent::TeamMembershipAdded {
                    context: caller.clone(),
                    team_id: team(30),
                    principal_id: joiner,
                    team_membership_id: team_membership(50),
                    contribution_id: contribution(60),
                },
                TenancyEvent::TeamMembershipRemoved {
                    context: caller.clone(),
                    id: team_membership(50),
                },
            ],
            vec![TenancyEvent::TeamMembershipAdded {
                context: caller.clone(),
                team_id: team(31),
                principal_id: principal(12),
                team_membership_id: team_membership(50),
                contribution_id: contribution(61),
            }],
        ),
        (
            "mandate.tenancy.SpaceCreated",
            vec![
                TenancyEvent::SpaceCreated {
                    context: caller.clone(),
                    space_id: space(40),
                    display_name: "Production".to_owned(),
                },
                TenancyEvent::SpaceRetired {
                    context: caller.clone(),
                    id: space(40),
                },
            ],
            vec![TenancyEvent::SpaceCreated {
                context: caller.clone(),
                space_id: space(40),
                display_name: "Renamed".to_owned(),
            }],
        ),
    ];

    for (name, settled_log, redelivery) in cases {
        let settled = Tenancy::fold(&settled_log);
        let mut replayed_log = settled_log.clone();
        replayed_log.extend(redelivery);
        let replayed = Tenancy::fold(&replayed_log);
        assert_eq!(
            replayed, settled,
            "{name}: a redelivered creation changed the projection"
        );

        // And the same creation redelivered before any terminal move is equally inert.
        let mut doubled = vec![settled_log[settled_log.len() - 2].clone()];
        doubled.push(settled_log[settled_log.len() - 2].clone());
        assert_eq!(
            Tenancy::fold(&doubled),
            Tenancy::fold(&doubled[..1]),
            "{name}: a creation applied twice in a row is not the creation applied once"
        );
    }

    // `mandate.graph.ResourceRegistered`, the sixth creating event.
    let registered = ResourceEvent::Registered {
        context: caller.clone(),
        resource_id: resource(100),
        resource: resource_ref(100),
        parent: None,
    };
    let deregistered = ResourceEvent::Deregistered {
        context: caller.clone(),
        id: resource(100),
    };
    let reregistered = ResourceEvent::Registered {
        context: caller,
        resource_id: resource(100),
        resource: ResourceRef {
            resource_type: ResourceType::new("folder"),
            resource_id: resource(100),
        },
        parent: Some(resource(101)),
    };
    let settled = Topology::fold(&[registered.clone(), deregistered.clone()]);
    assert_eq!(
        settled
            .record(resource(100))
            .expect("the record is kept")
            .state,
        ResourceState::Deregistered
    );
    assert_eq!(
        Topology::fold(&[registered, deregistered, reregistered]),
        settled,
        "mandate.graph.ResourceRegistered: a redelivered registration changed the topology"
    );
}

fn schema(ess_name: &str) -> serde_json::Value {
    let path = format!("{EVENTS}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled payload schema is JSON")
}

fn required_keys(ess_name: &str) -> BTreeSet<String> {
    schema(ess_name)["required"]
        .as_array()
        .expect("the declared required list")
        .iter()
        .map(|name| name.as_str().expect("a required name").to_owned())
        .collect()
}

fn serialized_keys(value: &serde_json::Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("an untagged variant serializes as the bare payload object")
        .keys()
        .cloned()
        .collect()
}

/// Follow a `$ref` into the document's own `$defs`, as many times as it takes.
fn resolved<'a>(root: &'a serde_json::Value, node: &'a serde_json::Value) -> &'a serde_json::Value {
    let mut current = node;
    while let Some(reference) = current.get("$ref").and_then(serde_json::Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .unwrap_or_else(|| panic!("an unexpected $ref form: {reference}"));
        current = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .unwrap_or_else(|| panic!("the schema declares no $def named {name}"));
    }
    current
}

/// A uuid as the compiled `pattern` writes it: five hex groups of 8-4-4-4-12.
fn matches_the_uuid_pattern(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(width, group)| {
                group.len() == *width && group.chars().all(|c| c.is_ascii_hexdigit())
            })
}

/// Decide one serialized value against one declared node, recording every disagreement.
///
/// Key sets alone are not an oracle: a payload can carry every declared key and still put
/// a number, a null or a malformed identifier behind one of them, and the contract refuses
/// all three. This resolves the node's `$ref`, then checks `type`, the uuid `pattern` where
/// one is declared, and — for an object — that every member of its own `required` is
/// present, that `additionalProperties: false` is respected, and that each member is in
/// turn the shape its own `$ref` declares.
fn check(
    root: &serde_json::Value,
    node: &serde_json::Value,
    value: &serde_json::Value,
    at: &str,
    problems: &mut Vec<String>,
) {
    let declared = resolved(root, node);

    match declared.get("type").and_then(serde_json::Value::as_str) {
        Some("string") => {
            let Some(text) = value.as_str() else {
                problems.push(format!("{at}: declared a string, serialized as {value}"));
                return;
            };
            if declared.get("pattern").is_some() && !matches_the_uuid_pattern(text) {
                problems.push(format!(
                    "{at}: {text:?} does not match the declared pattern"
                ));
            }
        }
        Some("object") => {
            let Some(members) = value.as_object() else {
                problems.push(format!("{at}: declared an object, serialized as {value}"));
                return;
            };
            let properties = declared
                .get("properties")
                .and_then(serde_json::Value::as_object);
            if let Some(required) = declared
                .get("required")
                .and_then(serde_json::Value::as_array)
            {
                for name in required {
                    let name = name.as_str().expect("a required name");
                    if !members.contains_key(name) {
                        problems.push(format!("{at}: the declared required {name} is absent"));
                    }
                }
            }
            for (name, member) in members {
                match properties.and_then(|declared| declared.get(name)) {
                    Some(node) => check(root, node, member, &format!("{at}.{name}"), problems),
                    None => {
                        if declared.get("additionalProperties")
                            == Some(&serde_json::Value::Bool(false))
                        {
                            problems.push(format!(
                                "{at}.{name}: not a declared property, and the schema refuses \
                                 additional ones"
                            ));
                        }
                    }
                }
            }
        }
        Some(other) => problems.push(format!("{at}: an unhandled declared type {other}")),
        None => problems.push(format!("{at}: the declared node names no type: {declared}")),
    }
}

/// The twelve events, each beside the qualified name it must carry.
///
/// Written as a literal per variant rather than as `event.ess_name()`: five compiled
/// payloads declare exactly `{context, id}`, so a key-set oracle cannot tell one of them
/// from another and `ess_name()` swapping two of them would pass every structural check in
/// this crate. The pairing below is what pins it — the variant on the left and the name on
/// the right — and `every_event_is_the_payload_its_name_claims` reads the compiled
/// `x-ess-name` to confirm the name on the right is the contract's own.
fn tenancy_samples() -> Vec<(TenancyEvent, &'static str)> {
    let acme = organization(1);
    // Optionals absent.
    let bare = context(acme, principal(10));
    // Every optional of `mandate.core.VerifiedContext` present.
    let full = VerifiedContext {
        actor: Some(principal(12)),
        delegation: Some(DelegationId::parse(&uuid(0x70)).expect("delegation identity")),
        execution: Some(ExecutionId::parse(&uuid(0x71)).expect("execution identity")),
        ..context(acme, principal(10))
    };
    vec![
        (
            TenancyEvent::OrganizationCreated {
                context: bare.clone(),
                organization_id: acme,
                display_name: "Acme".to_owned(),
            },
            "mandate.tenancy.OrganizationCreated",
        ),
        (
            TenancyEvent::OrganizationClosed {
                context: full.clone(),
                id: acme,
            },
            "mandate.tenancy.OrganizationClosed",
        ),
        (
            TenancyEvent::OrganizationMembershipAdded {
                context: bare.clone(),
                organization_id: acme,
                principal_id: principal(11),
                membership_id: membership(20),
            },
            "mandate.tenancy.OrganizationMembershipAdded",
        ),
        (
            TenancyEvent::OrganizationMembershipRemoved {
                context: full.clone(),
                id: membership(20),
            },
            "mandate.tenancy.OrganizationMembershipRemoved",
        ),
        (
            TenancyEvent::TeamCreated {
                context: bare.clone(),
                team_id: team(30),
                display_name: "Platform".to_owned(),
            },
            "mandate.tenancy.TeamCreated",
        ),
        (
            TenancyEvent::TeamRetired {
                context: full.clone(),
                id: team(30),
            },
            "mandate.tenancy.TeamRetired",
        ),
        (
            TenancyEvent::TeamMembershipAdded {
                context: bare.clone(),
                team_id: team(30),
                principal_id: principal(11),
                team_membership_id: team_membership(50),
                contribution_id: contribution(60),
            },
            "mandate.tenancy.TeamMembershipAdded",
        ),
        (
            TenancyEvent::TeamMembershipRemoved {
                context: full.clone(),
                id: team_membership(50),
            },
            "mandate.tenancy.TeamMembershipRemoved",
        ),
        (
            TenancyEvent::SpaceCreated {
                context: bare,
                space_id: space(40),
                display_name: "Production".to_owned(),
            },
            "mandate.tenancy.SpaceCreated",
        ),
        (
            TenancyEvent::SpaceRetired {
                context: full,
                id: space(40),
            },
            "mandate.tenancy.SpaceRetired",
        ),
    ]
}

/// The two resource events, with the one optional either enum declares — `parent` — built
/// both present and absent, because absence is the case that carries the defect: an
/// optional written as `null` is refused by a schema that types it as a string.
///
/// **Emitted, not hand-built.** Every sample here comes out of `decide_register` and
/// `decide_deregister`, so what the oracles decide is the payload the crate actually
/// produces. A hand-written literal would satisfy `resource_id == resource.resource_id` by
/// construction and say nothing about the emitter; the tenancy samples above are literals
/// because their pairing with a name is the thing being pinned, and no field of theirs is
/// derived from another.
fn resource_samples() -> Vec<(ResourceEvent, &'static str)> {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    let mut topology = Topology::new();

    let parentless = topology
        .register(&tenancy, &caller, &resource_ref(100), None)
        .expect("a resource with no parent is registered");
    let with_parent = topology
        .register(&tenancy, &caller, &resource_ref(101), Some(resource(100)))
        .expect("a child of it is registered");
    let deregistered = topology
        .deregister(&caller, resource(101))
        .expect("the child is deregistered");

    vec![
        (with_parent, "mandate.graph.ResourceRegistered"),
        (parentless, "mandate.graph.ResourceRegistered"),
        (deregistered, "mandate.graph.ResourceDeregistered"),
    ]
}

/// Every declared key is present, and no key the contract does not declare is written.
///
/// The ten tenancy payloads declare every property required, so the serialized key set is
/// the required set exactly. An optional is the one case where the two differ, and the two
/// resource payloads are decided in their own case below.
#[test]
fn every_tenancy_event_serializes_to_its_declared_payload_keys() {
    for (event, name) in tenancy_samples() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        assert_eq!(
            serialized_keys(&value),
            required_keys(name),
            "{name} serializes keys the contract does not declare, or drops one it does"
        );
    }
}

/// Both resource payloads against the compiled schema, with `parent` omitted when absent
/// rather than written as `null`.
///
/// `mandate.graph.ResourceRegistered` used to be asserted against a ruled literal set
/// here, on the ground that the compiled schema declared `required: [context, resource]`
/// and predated `resource_id`. That ground was false — the compiled payload requires
/// `context`, `resource_id` and `resource`, and has since `story:contract-creates` added
/// `resource_id` as the `instance:` of `creates: Resource` — so the literal is gone and
/// this event reads `required_keys(name)` like the other eleven. A literal is the one
/// thing that cannot notice the contract moving underneath it, which is the whole reason
/// the rest of this file reads the file.
///
/// `parent` is optional, so an absent parent is an absent key and never a null.
#[test]
fn every_resource_event_serializes_to_its_declared_payload_keys() {
    for (event, name) in resource_samples() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        let keys = serialized_keys(&value);
        match &event {
            ResourceEvent::Registered { parent, .. } => {
                let mut expected = required_keys(name);
                if parent.is_some() {
                    expected.insert("parent".to_owned());
                }
                assert_eq!(
                    keys,
                    expected,
                    "{name} with parent {}: wrong key set",
                    if parent.is_some() {
                        "present"
                    } else {
                        "absent"
                    }
                );
                assert!(
                    parent.is_some() || value.get("parent").is_none(),
                    "an absent optional was serialized: {value}"
                );
            }
            ResourceEvent::Deregistered { .. } => {
                assert_eq!(keys, required_keys(name), "{name}: wrong key set");
            }
        }
    }
}

/// Every value in every payload is the shape its `$ref` declares.
///
/// The key-set cases above cannot see a null, a number or a malformed identifier behind a
/// declared key, and the contract refuses all three. This walks each payload against its
/// compiled schema: `type`, the uuid `pattern`, and, for `context` and `resource`, the
/// nested `required` list and `additionalProperties: false`.
#[test]
fn every_payload_value_is_the_shape_its_ref_declares() {
    let mut problems: Vec<String> = Vec::new();
    for (event, name) in tenancy_samples() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        let declared = schema(name);
        check(&declared, &declared, &value, name, &mut problems);
    }
    for (event, name) in resource_samples() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        let declared = schema(name);
        if matches!(event, ResourceEvent::Registered { .. }) {
            // The payload carries the resource identity twice — `resource_id` (the
            // `instance:` the contract sources from the `RegisterResource` response) and
            // `resource.resource_id` — and their agreement is the one thing the schema
            // cannot decide, so it is asserted here; `check` below decides both keys.
            assert_eq!(
                value["resource_id"], value["resource"]["resource_id"],
                "{name}: resource_id and resource.resource_id name different resources"
            );
        }
        check(&declared, &declared, &value, name, &mut problems);
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Each event carries the qualified name of the payload it is, and that name is the
/// compiled `x-ess-name`.
///
/// Pinning per sample is what the key-set oracles cannot do: five compiled payloads
/// declare exactly `{context, id}`, so `ess_name()` returning another of the five for a
/// variant passes every structural check there is. The literal beside each variant in
/// `tenancy_samples` is the pin; this reads the compiled document that literal names and
/// requires `x-ess-name` to agree, so a variant renamed to a payload that does not exist
/// and a variant renamed to one that does are both red.
#[test]
fn every_event_is_the_payload_its_name_claims() {
    let mut pinned = 0;
    for (event, name) in tenancy_samples() {
        assert_eq!(
            event.ess_name(),
            name,
            "the variant does not name the payload it is paired with"
        );
        assert_eq!(
            schema(name)["x-ess-name"],
            name,
            "{name}: the compiled payload names itself differently"
        );
        pinned += 1;
    }
    for (event, name) in resource_samples() {
        assert_eq!(
            event.ess_name(),
            name,
            "the variant does not name the payload it is paired with"
        );
        assert_eq!(
            schema(name)["x-ess-name"],
            name,
            "{name}: the compiled payload names itself differently"
        );
        pinned += 1;
    }
    assert_eq!(pinned, 13, "ten tenancy samples and three resource samples");
}

/// Every compiled `mandate.tenancy` event and every compiled `mandate.graph.Resource*`
/// event is named by exactly one Rust variant above, and every variant names a compiled
/// event.
///
/// This is the check that closes the class rather than one instance of it: a declared
/// event with no variant — or a variant misnaming its event — is red here without anyone
/// having to remember to extend a list.
#[test]
fn the_declared_events_and_the_rust_variants_are_the_same_set() {
    let mut compiled = BTreeSet::new();
    let entries = std::fs::read_dir(EVENTS).unwrap_or_else(|error| panic!("{EVENTS}: {error}"));
    for entry in entries {
        let entry = entry.expect("a compiled event");
        let file = entry.file_name();
        let file = file.to_str().expect("a schema file name");
        let Some(ess_name) = file.strip_suffix(".schema.json") else {
            continue;
        };
        let owned = ess_name.starts_with("mandate.tenancy.")
            || ess_name.starts_with("mandate.graph.Resource");
        if owned {
            compiled.insert(ess_name.to_owned());
        }
    }
    assert_eq!(compiled.len(), 12, "the contract declares twelve of them");

    let mut named: BTreeSet<String> = tenancy_samples()
        .iter()
        .map(|(event, _)| event.ess_name().to_owned())
        .collect();
    named.extend(
        resource_samples()
            .iter()
            .map(|(event, _)| event.ess_name().to_owned()),
    );
    assert_eq!(
        named, compiled,
        "a declared event has no Rust variant, or a variant names an event the contract \
         does not declare"
    );
}
