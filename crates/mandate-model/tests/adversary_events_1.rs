//! Adversary pass 1 over `story:tenancy-graph-events`.
//!
//! Nothing here edits the implementation or an existing case. Each `#[test]` names one
//! property and drives the public API or the compiled contract under
//! `generated/schema/events`.
//!
//! The one deliberate exclusion is `resource_id` on
//! `mandate.graph.ResourceRegistered`: the coordinator's ruling of 2026-09-19 (PS3/D2)
//! fixes the emitted payload at `{context, resource_id, resource, parent}`, which the
//! schema compiled on this branch refuses under `additionalProperties: false` until
//! `story:contract-creates` lands. That one key is skipped by name wherever it appears,
//! and nothing else is.

use std::collections::{BTreeMap, BTreeSet};

use mandate_model::graph::{ResourceEvent, ResourceState, Topology};
use mandate_model::tenancy::{
    MembershipAuthority, OrganizationMembershipState, OrganizationState, SpaceState,
    TeamMembershipState, TeamState, Tenancy, TenancyEvent,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, MembershipContributionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId, TeamId,
    TeamMembershipId, VerifiedContext,
};

const EVENTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema/events");

/// The one key the coordinator ruled ahead of the contract it will be compiled into.
const RULED_AHEAD_OF_THE_CONTRACT: &str = "resource_id";

fn uuid(tag: u16) -> String {
    format!("7f3c91aa-51d2-4c77-9e42-a0b3c4d5{tag:04x}")
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
        credential: CredentialId::parse(&uuid(0xfffe)).expect("credential identity"),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn platform() -> VerifiedContext {
    context(organization(0xff00), principal(0xff01))
}

fn schema(ess_name: &str) -> serde_json::Value {
    let path = format!("{EVENTS}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled payload schema is JSON")
}

/// Follow a `$ref` into the schema's own `$defs`, once or as many times as it takes.
fn resolve<'a>(root: &'a serde_json::Value, node: &'a serde_json::Value) -> &'a serde_json::Value {
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

fn looks_like_a_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(width, group)| {
                group.len() == *width && group.chars().all(|c| c.is_ascii_hexdigit())
            })
}

/// Decide one serialized value against one declared node, appending every disagreement.
fn decide(
    root: &serde_json::Value,
    declared: &serde_json::Value,
    value: &serde_json::Value,
    path: &str,
    problems: &mut Vec<String>,
) {
    let declared = resolve(root, declared);
    if let Some(variants) = declared.get("enum").and_then(serde_json::Value::as_array) {
        if !variants.contains(value) {
            problems.push(format!("{path}: {value} is not one of {variants:?}"));
        }
        return;
    }
    match declared.get("type").and_then(serde_json::Value::as_str) {
        Some("string") => {
            let Some(text) = value.as_str() else {
                problems.push(format!(
                    "{path}: the contract declares a string and the payload carries {value}"
                ));
                return;
            };
            if declared.get("format").and_then(serde_json::Value::as_str) == Some("uuid")
                && !looks_like_a_uuid(text)
            {
                problems.push(format!("{path}: {text:?} is not the declared uuid shape"));
            }
        }
        Some("object") => {
            let Some(object) = value.as_object() else {
                problems.push(format!(
                    "{path}: the contract declares an object and the payload carries {value}"
                ));
                return;
            };
            let properties = declared
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .cloned()
                .unwrap_or_default();
            if declared.get("additionalProperties") == Some(&serde_json::Value::Bool(false)) {
                for key in object.keys() {
                    if key != RULED_AHEAD_OF_THE_CONTRACT && !properties.contains_key(key) {
                        problems.push(format!("{path}.{key}: the contract declares no such key"));
                    }
                }
            }
            if let Some(required) = declared
                .get("required")
                .and_then(serde_json::Value::as_array)
            {
                for name in required {
                    let name = name.as_str().expect("a required name");
                    if !object.contains_key(name) {
                        problems.push(format!("{path}.{name}: declared required and not written"));
                    }
                }
            }
            for (key, member) in object {
                if key == RULED_AHEAD_OF_THE_CONTRACT {
                    continue;
                }
                if let Some(node) = properties.get(key) {
                    decide(root, node, member, &format!("{path}.{key}"), problems);
                }
            }
        }
        other => problems.push(format!("{path}: unhandled declared node {other:?}")),
    }
}

/// A `Registered` event as `Topology::register` returns it, for a resource with no parent.
fn registration_without_a_parent() -> ResourceEvent {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    let mut topology = Topology::new();
    topology
        .register(&tenancy, &caller, &resource_ref(100), None)
        .expect("a resource with no parent is registered")
}

/// `mandate.graph.ResourceRegistered` declares `parent` optional and typed as a string;
/// an absent parent must therefore leave the key out, never write `null`.
#[test]
fn an_absent_parent_is_omitted_from_the_registration_payload_and_never_written_as_null() {
    let event = registration_without_a_parent();
    let value = serde_json::to_value(&event).expect("the payload serializes");
    let declared = schema("mandate.graph.ResourceRegistered");

    let required: Vec<&str> = declared["required"]
        .as_array()
        .expect("the declared required list")
        .iter()
        .map(|name| name.as_str().expect("a required name"))
        .collect();
    assert!(
        !required.contains(&"parent"),
        "the contract makes parent optional, so absence is legal: {required:?}"
    );
    let parent = resolve(&declared, &declared["properties"]["parent"]);
    assert_eq!(
        parent["type"], "string",
        "the contract types parent as mandate.core.ResourceId, a string"
    );
    assert!(
        parent.get("enum").is_none() && parent.get("oneOf").is_none(),
        "the contract admits no null for parent: {parent}"
    );

    match value.get("parent") {
        None => {}
        Some(written) => assert!(
            written.is_string(),
            "mandate.graph.ResourceRegistered writes parent as {written}, which the compiled \
             schema refuses: parent is optional and typed as a string, so an absent parent is \
             an absent key. `crates/mandate-model/src/graph.rs:151` chose to serialize it \
             always. The whole payload was: {value}"
        ),
    }
}

/// Every value in every declared payload is the shape its `$ref` declares — ids as
/// uuid-shaped strings, `resource` as the `ResourceRef` object, `context` as the
/// `VerifiedContext` object with its own required members present.
#[test]
fn every_declared_payload_value_is_the_shape_the_contract_declares() {
    let mut problems = Vec::new();
    for event in tenancy_samples() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        let name = event.ess_name();
        let declared = schema(name);
        decide(&declared, &declared, &value, name, &mut problems);
    }
    // The parent-absent registration is the subject of the case above; this one decides
    // every other payload, so that its silence means something.
    for event in resource_samples_with_a_parent() {
        let value = serde_json::to_value(&event).expect("the payload serializes");
        let name = event.ess_name();
        let declared = schema(name);
        decide(&declared, &declared, &value, name, &mut problems);
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// `ess_name()` is the qualified name the compiled payload carries in `x-ess-name`.
#[test]
fn every_ess_name_equals_the_x_ess_name_of_the_payload_it_names() {
    let mut named: Vec<&'static str> = tenancy_samples()
        .iter()
        .map(TenancyEvent::ess_name)
        .collect();
    named.extend(
        resource_samples_with_a_parent()
            .iter()
            .map(ResourceEvent::ess_name),
    );
    assert_eq!(named.len(), 12, "twelve declared payloads");
    for name in named {
        assert_eq!(
            schema(name)["x-ess-name"],
            name,
            "{name}: ess_name() and the compiled x-ess-name disagree"
        );
    }
}

fn tenancy_samples() -> Vec<TenancyEvent> {
    let acme = organization(1);
    let caller = context(acme, principal(10));
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
        TenancyEvent::OrganizationMembershipAdded {
            context: caller.clone(),
            organization_id: acme,
            principal_id: principal(11),
            membership_id: membership(20),
        },
        TenancyEvent::OrganizationMembershipRemoved {
            context: caller.clone(),
            id: membership(20),
        },
        TenancyEvent::TeamCreated {
            context: caller.clone(),
            team_id: team(30),
            display_name: String::new(),
        },
        TenancyEvent::TeamRetired {
            context: caller.clone(),
            id: team(30),
        },
        TenancyEvent::TeamMembershipAdded {
            context: caller.clone(),
            team_id: team(30),
            principal_id: principal(11),
            team_membership_id: team_membership(50),
            contribution_id: contribution(60),
        },
        TenancyEvent::TeamMembershipRemoved {
            context: caller.clone(),
            id: team_membership(50),
        },
        TenancyEvent::SpaceCreated {
            context: caller.clone(),
            space_id: space(40),
            display_name: "Production".to_owned(),
        },
        TenancyEvent::SpaceRetired {
            context: caller,
            id: space(40),
        },
    ]
}

fn resource_samples_with_a_parent() -> Vec<ResourceEvent> {
    let caller = context(organization(1), principal(10));
    vec![
        ResourceEvent::Registered {
            context: caller.clone(),
            resource_id: resource(101),
            resource: resource_ref(101),
            parent: Some(resource(100)),
        },
        ResourceEvent::Deregistered {
            context: caller,
            id: resource(101),
        },
    ]
}

/// A tenancy carrying one record of every kind in every state the denial sweep below
/// needs: an open organization, a closed one, an open neighbour, an active and a removed
/// organization membership, a recorded and a retired team, a recorded and a removed team
/// membership, and a recorded and a retired space.
fn a_tenancy_in_every_state() -> Tenancy {
    let acme = organization(1);
    let other = organization(2);
    let neighbour = organization(4);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    for (id, name) in [(acme, "Acme"), (other, "Other"), (neighbour, "Neighbour")] {
        tenancy
            .create_organization(&platform(), id, name)
            .expect("the organization is recorded");
    }
    for (id, who) in [
        (membership(20), principal(11)),
        (membership(22), principal(14)),
    ] {
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                id,
                acme,
                who,
            )
            .expect("the member is seeded");
    }
    tenancy
        .remove_organization_membership(&caller, membership(22))
        .expect("the second membership is removed");
    for (id, name) in [(team(30), "Platform"), (team(32), "Retired")] {
        tenancy
            .create_team(&caller, id, name)
            .expect("the team is recorded");
    }
    tenancy
        .add_team_membership(
            &caller,
            team_membership(52),
            team(32),
            principal(11),
            contribution(62),
        )
        .expect("the team membership is recorded");
    tenancy
        .remove_team_membership(&caller, team_membership(52))
        .expect("the team membership is removed");
    tenancy
        .retire_team(&caller, team(32))
        .expect("the team is retired");
    tenancy
        .add_team_membership(
            &caller,
            team_membership(53),
            team(30),
            principal(11),
            contribution(63),
        )
        .expect("the live team membership is recorded");
    for (id, name) in [(space(40), "Production"), (space(42), "Retired")] {
        tenancy
            .create_space(&caller, id, name)
            .expect("the space is recorded");
    }
    tenancy
        .retire_space(&caller, space(42))
        .expect("the space is retired");
    tenancy
        .close_organization(&platform(), other)
        .expect("the other organization is closed");
    tenancy
}

/// Every refusal of every one of the twelve commands leaves the projection it was asked
/// to write exactly as it found it.
///
/// The implementor asserts one or more denied paths per command; this drives the
/// authority path, the missing-record path, the terminal-state path, the
/// cross-organization path and the already-held-identity path in one sweep, and compares
/// the whole projection by `PartialEq` rather than one record.
#[test]
fn every_denied_path_of_every_command_leaves_the_whole_projection_equal() {
    let acme = organization(1);
    let closed = organization(2);
    let absent = organization(3);
    let caller = context(acme, principal(10));
    let stranger = context(closed, principal(12));
    let member = principal(11);

    let base = a_tenancy_in_every_state();
    let mut tenancy = base.clone();

    let mut driven: Vec<String> = Vec::new();
    let mut refuse = |result: Result<TenancyEvent, mandate_model::tenancy::Denied>, what: &str| {
        assert!(result.is_err(), "{what} was accepted and should refuse");
        driven.push(what.to_owned());
    };

    // CreateOrganization: an identity already recorded.
    refuse(
        tenancy.create_organization(&platform(), acme, "Again"),
        "CreateOrganization over a recorded identity",
    );
    // CloseOrganization: unresolved, and already closed.
    refuse(
        tenancy.close_organization(&platform(), absent),
        "CloseOrganization of an unresolved organization",
    );
    refuse(
        tenancy.close_organization(&platform(), closed),
        "CloseOrganization of a closed organization",
    );
    // AddOrganizationMembership: wrong authority, closed target, unresolved target,
    // already a member, identity already held.
    refuse(
        tenancy.add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(21),
            closed,
            principal(13),
        ),
        "AddOrganizationMembership naming another organization on the tenant path",
    );
    refuse(
        tenancy.add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(21),
            closed,
            principal(13),
        ),
        "AddOrganizationMembership into a closed organization",
    );
    refuse(
        tenancy.add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(21),
            absent,
            principal(13),
        ),
        "AddOrganizationMembership into an unresolved organization",
    );
    refuse(
        tenancy.add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(21),
            acme,
            member,
        ),
        "AddOrganizationMembership for a principal that is already a member",
    );
    refuse(
        tenancy.add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            principal(13),
        ),
        "AddOrganizationMembership over a recorded identity",
    );
    // RemoveOrganizationMembership: unresolved, outside the verified organization, and
    // already in its terminal state.
    refuse(
        tenancy.remove_organization_membership(&caller, membership(99)),
        "RemoveOrganizationMembership of an unresolved membership",
    );
    refuse(
        tenancy.remove_organization_membership(&stranger, membership(20)),
        "RemoveOrganizationMembership from another organization",
    );
    refuse(
        tenancy.remove_organization_membership(&caller, membership(22)),
        "RemoveOrganizationMembership of a removed membership",
    );
    // CreateTeam: closed verified organization, unresolved verified organization,
    // identity already recorded.
    refuse(
        tenancy.create_team(&stranger, team(31), "Nope"),
        "CreateTeam inside a closed organization",
    );
    refuse(
        tenancy.create_team(&context(absent, principal(10)), team(31), "Nope"),
        "CreateTeam inside an unresolved organization",
    );
    refuse(
        tenancy.create_team(&caller, team(30), "Again"),
        "CreateTeam over a recorded identity",
    );
    // RetireTeam: unresolved, outside the verified organization, already retired.
    refuse(
        tenancy.retire_team(&caller, team(99)),
        "RetireTeam of an unresolved team",
    );
    refuse(
        tenancy.retire_team(&stranger, team(30)),
        "RetireTeam from another organization",
    );
    refuse(
        tenancy.retire_team(&caller, team(32)),
        "RetireTeam of a retired team",
    );
    // AddTeamMembership: closed organization, unresolved team, retired team, principal
    // that is not an organization member, identity already recorded, principal that
    // already holds a membership of that team.
    refuse(
        tenancy.add_team_membership(
            &stranger,
            team_membership(51),
            team(30),
            member,
            contribution(60),
        ),
        "AddTeamMembership from a closed organization",
    );
    refuse(
        tenancy.add_team_membership(
            &caller,
            team_membership(51),
            team(99),
            member,
            contribution(60),
        ),
        "AddTeamMembership onto an unresolved team",
    );
    refuse(
        tenancy.add_team_membership(
            &caller,
            team_membership(51),
            team(32),
            member,
            contribution(60),
        ),
        "AddTeamMembership onto a retired team",
    );
    refuse(
        tenancy.add_team_membership(
            &caller,
            team_membership(51),
            team(30),
            principal(13),
            contribution(60),
        ),
        "AddTeamMembership for a principal that is not an organization member",
    );
    refuse(
        tenancy.add_team_membership(
            &caller,
            team_membership(52),
            team(30),
            principal(11),
            contribution(60),
        ),
        "AddTeamMembership over a recorded identity",
    );
    refuse(
        tenancy.add_team_membership(
            &caller,
            team_membership(54),
            team(30),
            principal(11),
            contribution(60),
        ),
        "AddTeamMembership for a principal already in that team",
    );
    // RemoveTeamMembership: unresolved, outside the verified organization, and already
    // in its terminal state.
    refuse(
        tenancy.remove_team_membership(&caller, team_membership(99)),
        "RemoveTeamMembership of an unresolved membership",
    );
    refuse(
        tenancy.remove_team_membership(&stranger, team_membership(53)),
        "RemoveTeamMembership from another organization",
    );
    refuse(
        tenancy.remove_team_membership(&caller, team_membership(52)),
        "RemoveTeamMembership of a removed membership",
    );
    // CreateSpace: closed organization, unresolved organization, identity recorded.
    refuse(
        tenancy.create_space(&stranger, space(41), "Nope"),
        "CreateSpace inside a closed organization",
    );
    refuse(
        tenancy.create_space(&context(absent, principal(10)), space(41), "Nope"),
        "CreateSpace inside an unresolved organization",
    );
    refuse(
        tenancy.create_space(&caller, space(40), "Again"),
        "CreateSpace over a recorded identity",
    );
    // RetireSpace: unresolved, outside the verified organization, already retired.
    refuse(
        tenancy.retire_space(&caller, space(99)),
        "RetireSpace of an unresolved space",
    );
    refuse(
        tenancy.retire_space(&stranger, space(40)),
        "RetireSpace from another organization",
    );
    refuse(
        tenancy.retire_space(&caller, space(42)),
        "RetireSpace of a retired space",
    );

    let unique: BTreeSet<&String> = driven.iter().collect();
    assert_eq!(unique.len(), driven.len(), "a denied path was driven twice");
    assert_eq!(driven.len(), 32, "every denied path above was driven");
    assert_eq!(tenancy, base, "a refusal wrote into the tenancy projection");

    // The two resource commands, against a topology holding a parent, a child, a
    // deregistered resource, and one resource in a neighbouring organization.
    let neighbour = context(organization(4), principal(15));
    let mut topology = Topology::new();
    topology
        .register(&tenancy, &caller, &resource_ref(100), None)
        .expect("the parent is registered");
    topology
        .register(&tenancy, &caller, &resource_ref(101), Some(resource(100)))
        .expect("the child is registered");
    topology
        .register(&tenancy, &caller, &resource_ref(103), None)
        .expect("the third resource is registered");
    topology
        .deregister(&caller, resource(103))
        .expect("the third resource is deregistered");
    topology
        .register(&tenancy, &neighbour, &resource_ref(104), None)
        .expect("the neighbour's resource is registered");
    let settled = topology.clone();

    let mut driven: Vec<String> = Vec::new();
    let mut refuse = |result: Result<ResourceEvent, mandate_model::graph::Denied>, what: &str| {
        assert!(result.is_err(), "{what} was accepted and should refuse");
        driven.push(what.to_owned());
    };
    refuse(
        topology.register(&tenancy, &stranger, &resource_ref(102), None),
        "RegisterResource inside a closed organization",
    );
    refuse(
        topology.register(
            &tenancy,
            &context(absent, principal(10)),
            &resource_ref(102),
            None,
        ),
        "RegisterResource inside an unresolved organization",
    );
    refuse(
        topology.register(&tenancy, &caller, &resource_ref(100), None),
        "RegisterResource over a registered identity",
    );
    refuse(
        topology.register(&tenancy, &caller, &resource_ref(103), None),
        "RegisterResource over a deregistered identity",
    );
    refuse(
        topology.register(&tenancy, &caller, &resource_ref(102), Some(resource(99))),
        "RegisterResource under an unresolved parent",
    );
    refuse(
        topology.register(&tenancy, &caller, &resource_ref(102), Some(resource(103))),
        "RegisterResource under a deregistered parent",
    );
    refuse(
        topology.register(&tenancy, &caller, &resource_ref(102), Some(resource(104))),
        "RegisterResource under a parent in another organization",
    );
    refuse(
        topology.deregister(&caller, resource(99)),
        "DeregisterResource of an unresolved resource",
    );
    refuse(
        topology.deregister(&stranger, resource(100)),
        "DeregisterResource from another organization",
    );
    refuse(
        topology.deregister(&neighbour, resource(100)),
        "DeregisterResource from a neighbouring organization",
    );
    refuse(
        topology.deregister(&caller, resource(103)),
        "DeregisterResource of a deregistered resource",
    );
    refuse(
        topology.deregister(&caller, resource(100)),
        "DeregisterResource of a resource a child still resolves through",
    );
    let unique: BTreeSet<&String> = driven.iter().collect();
    assert_eq!(unique.len(), driven.len(), "a denied path was driven twice");
    assert_eq!(
        driven.len(),
        12,
        "every denied resource path above was driven"
    );
    assert_eq!(
        topology, settled,
        "a refusal wrote into the topology projection"
    );
}

/// The fold of the events a long interleaved history emitted equals the live projection
/// at every prefix, not only at the end.
///
/// The interleaving is the one the brief names: a membership added, removed and added
/// again under a fresh identity; a team created, its membership added and removed, and
/// the team retired; a space created and retired; a resource tree deregistered leaf
/// first; and the organization closed last.
#[test]
fn the_fold_equals_the_live_projection_at_every_prefix_of_an_interleaved_history() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);

    let mut live = Tenancy::new();
    let mut log: Vec<TenancyEvent> = Vec::new();
    let mut prefixes: Vec<Tenancy> = Vec::new();

    macro_rules! step {
        ($decided:expr) => {{
            let event = $decided.expect("the command is accepted");
            live.apply(&event);
            log.push(event);
            prefixes.push(live.clone());
        }};
    }

    step!(live.decide_create_organization(&platform(), acme, "Acme"));
    step!(live.decide_add_organization_membership(
        &platform(),
        MembershipAuthority::PlatformOrganizationAdministration,
        membership(20),
        acme,
        joiner,
    ));
    step!(live.decide_remove_organization_membership(&caller, membership(20)));

    // Removed is terminal, so the same membership identity is refused; a fresh identity
    // for the same principal is admitted.
    assert!(
        live.decide_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            membership(20),
            acme,
            joiner,
        )
        .is_err(),
        "a removed membership identity must not be written over"
    );
    step!(live.decide_add_organization_membership(
        &caller,
        MembershipAuthority::VerifiedOrganization,
        membership(21),
        acme,
        joiner,
    ));

    step!(live.decide_create_team(&caller, team(30), "Platform"));
    step!(live.decide_add_team_membership(
        &caller,
        team_membership(50),
        team(30),
        joiner,
        contribution(60),
    ));
    step!(live.decide_remove_team_membership(&caller, team_membership(50)));
    step!(live.decide_add_team_membership(
        &caller,
        team_membership(51),
        team(30),
        joiner,
        contribution(61),
    ));
    step!(live.decide_retire_team(&caller, team(30)));

    // Retired is terminal for the team, so no membership follows it and the identity is
    // never re-created.
    assert!(
        live.decide_add_team_membership(
            &caller,
            team_membership(52),
            team(30),
            joiner,
            contribution(62),
        )
        .is_err(),
        "a retired team must admit no membership"
    );
    assert!(
        live.decide_create_team(&caller, team(30), "Platform again")
            .is_err(),
        "a retired team identity must not be re-created"
    );
    assert!(
        live.decide_retire_team(&caller, team(30)).is_err(),
        "a retired team must not be retired twice"
    );

    step!(live.decide_create_space(&caller, space(40), "Production"));
    step!(live.decide_retire_space(&caller, space(40)));
    step!(live.decide_close_organization(&platform(), acme));

    assert!(
        live.decide_create_space(&caller, space(41), "After closure")
            .is_err(),
        "a closed organization admits no new space"
    );

    assert_eq!(log.len(), 12, "twelve accepted commands");
    for (index, expected) in prefixes.iter().enumerate() {
        assert_eq!(
            &Tenancy::fold(&log[..=index]),
            expected,
            "the fold of the first {} events is not the projection those commands left",
            index + 1
        );
    }

    // The terminal states the history should have reached, read out of the rebuild.
    let rebuilt = Tenancy::fold(&log);
    assert_eq!(
        rebuilt.organization(acme).expect("the organization").state,
        OrganizationState::Closed
    );
    assert_eq!(
        rebuilt
            .organization_membership(membership(20))
            .expect("the first membership")
            .state,
        OrganizationMembershipState::Removed
    );
    assert_eq!(
        rebuilt
            .organization_membership(membership(21))
            .expect("the second membership")
            .state,
        OrganizationMembershipState::Active
    );
    assert_eq!(
        rebuilt.team(team(30)).expect("the team").state,
        TeamState::Retired
    );
    assert_eq!(
        rebuilt
            .team_membership(team_membership(50))
            .expect("the first team membership")
            .state,
        TeamMembershipState::Removed
    );
    assert_eq!(
        rebuilt
            .team_membership(team_membership(51))
            .expect("the second team membership")
            .state,
        TeamMembershipState::Recorded
    );
    assert_eq!(
        rebuilt.space(space(40)).expect("the space").state,
        SpaceState::Retired
    );
    assert_eq!(rebuilt.record_count(), 7, "nothing was destroyed");
}

/// A resource tree deregisters leaf first, refuses to deregister a parent a child still
/// resolves through, and folds to the live topology at every prefix.
#[test]
fn a_resource_tree_folds_at_every_prefix_and_refuses_to_orphan_a_child() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");

    let mut live = Topology::new();
    let mut log: Vec<ResourceEvent> = Vec::new();
    let mut prefixes: Vec<Topology> = Vec::new();

    macro_rules! step {
        ($decided:expr) => {{
            let event = $decided.expect("the command is accepted");
            live.apply(&event);
            log.push(event);
            prefixes.push(live.clone());
        }};
    }

    step!(live.decide_register(&tenancy, &caller, &resource_ref(100), None));
    step!(live.decide_register(&tenancy, &caller, &resource_ref(101), Some(resource(100))));
    step!(live.decide_register(&tenancy, &caller, &resource_ref(102), Some(resource(101))));

    assert!(
        live.decide_deregister(&caller, resource(100)).is_err(),
        "a parent a child resolves through must not deregister"
    );
    assert!(
        live.decide_deregister(&caller, resource(101)).is_err(),
        "a middle node a child resolves through must not deregister"
    );

    step!(live.decide_deregister(&caller, resource(102)));
    step!(live.decide_deregister(&caller, resource(101)));
    step!(live.decide_deregister(&caller, resource(100)));

    assert!(
        live.decide_register(&tenancy, &caller, &resource_ref(102), None)
            .is_err(),
        "a deregistered identity must not be registered again"
    );

    assert_eq!(log.len(), 6, "six accepted resource commands");
    for (index, expected) in prefixes.iter().enumerate() {
        assert_eq!(
            &Topology::fold(&log[..=index]),
            expected,
            "the fold of the first {} resource events is not the topology those commands left",
            index + 1
        );
    }
    let rebuilt = Topology::fold(&log);
    assert_eq!(rebuilt.len(), 3, "nothing was destroyed");
    for tag in [100u16, 101, 102] {
        assert_eq!(
            rebuilt.record(resource(tag)).expect("the record").state,
            ResourceState::Deregistered
        );
    }
    assert_eq!(
        rebuilt
            .record(resource(101))
            .expect("the child")
            .parent
            .expect("the parent it was registered under"),
        resource(100),
        "the parent a rebuild reads is the one the registration declared"
    );
}

/// `apply` is total: an event naming a record the projection does not hold moves nothing,
/// creates nothing and does not panic.
#[test]
fn applying_a_state_move_for_a_record_that_is_not_there_writes_nothing() {
    let acme = organization(1);
    let caller = context(acme, principal(10));

    let mut tenancy = Tenancy::new();
    let moves = [
        TenancyEvent::OrganizationClosed {
            context: caller.clone(),
            id: acme,
        },
        TenancyEvent::OrganizationMembershipRemoved {
            context: caller.clone(),
            id: membership(20),
        },
        TenancyEvent::TeamRetired {
            context: caller.clone(),
            id: team(30),
        },
        TenancyEvent::TeamMembershipRemoved {
            context: caller.clone(),
            id: team_membership(50),
        },
        TenancyEvent::SpaceRetired {
            context: caller.clone(),
            id: space(40),
        },
    ];
    for event in &moves {
        tenancy.apply(event);
    }
    assert_eq!(
        tenancy,
        Tenancy::new(),
        "a move wrote a record into the fold"
    );
    assert_eq!(tenancy.record_count(), 0);

    let mut topology = Topology::new();
    topology.apply(&ResourceEvent::Deregistered {
        context: caller,
        id: resource(100),
    });
    assert_eq!(
        topology,
        Topology::new(),
        "a move wrote a record into the topology"
    );

    // And a whole log of nothing but state moves folds to the empty projection.
    assert_eq!(Tenancy::fold(&moves), Tenancy::new());
}

/// The two oracles the suite uses for `ess_name()` pin each variant to its own payload.
///
/// `crates/mandate-model/tests/replay.rs:779`
/// `the_declared_events_and_the_rust_variants_are_the_same_set` compares the *set* of
/// names against the set of compiled files, and `:724`
/// Five compiled payloads declare exactly `{context, id}` — `OrganizationClosed`,
/// `OrganizationMembershipRemoved`, `TeamRetired`, `TeamMembershipRemoved`, `SpaceRetired` —
/// so no key-set or name-set oracle can tell them apart; each variant must be pinned to its
/// own name, one by one, against the compiled `x-ess-name`.
///
/// Coordinator ruling after adversary pass 1 (finding A1-4): the original case reconstructed
/// two `replay.rs` oracles and asserted that a swap survives both, which is true of any
/// set-based oracle and therefore unsatisfiable once the suite pins names per variant. This
/// case now asserts the property directly: a swap of any two of the five is a failure here.
#[test]
fn each_of_the_five_context_id_payloads_is_pinned_to_its_own_name() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let five: [(TenancyEvent, &str); 5] = [
        (
            TenancyEvent::OrganizationClosed {
                context: caller.clone(),
                id: acme,
            },
            "mandate.tenancy.OrganizationClosed",
        ),
        (
            TenancyEvent::OrganizationMembershipRemoved {
                context: caller.clone(),
                id: membership(20),
            },
            "mandate.tenancy.OrganizationMembershipRemoved",
        ),
        (
            TenancyEvent::TeamRetired {
                context: caller.clone(),
                id: team(30),
            },
            "mandate.tenancy.TeamRetired",
        ),
        (
            TenancyEvent::TeamMembershipRemoved {
                context: caller.clone(),
                id: team_membership(40),
            },
            "mandate.tenancy.TeamMembershipRemoved",
        ),
        (
            TenancyEvent::SpaceRetired {
                context: caller,
                id: space(50),
            },
            "mandate.tenancy.SpaceRetired",
        ),
    ];
    for (event, literal) in &five {
        assert_eq!(
            event.ess_name(),
            *literal,
            "a variant names another payload with the same key set"
        );
        assert_eq!(
            schema(literal)["x-ess-name"].as_str(),
            Some(*literal),
            "the compiled payload does not carry the name the variant claims"
        );
        let keys: BTreeSet<String> = serde_json::to_value(event)
            .expect("the payload serializes")
            .as_object()
            .expect("the bare payload object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from(["context".to_owned(), "id".to_owned()]),
            "{literal} is not a {{context, id}} payload"
        );
    }
}

/// A creation event replayed after its record reached a terminal state moves the record
/// back to the initial state, which the compiled lifecycle declares terminal.
///
/// A creation names the first event for an identity; a later creation for an identity the
/// projection already holds writes nothing, so a redelivered creation cannot return a record
/// from a terminal state to its initial one.
///
/// Coordinator ruling after adversary pass 1 (finding A1-5): the original case characterized
/// the unconditional insert (last creation wins, terminal state reopened). No `decide_*` path
/// emits that sequence, but a log that redelivers it must fail closed, so `apply` for a
/// creation is insert-if-absent and this case asserts that property.
#[test]
fn a_creation_event_replayed_after_a_terminal_state_writes_nothing() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let created = TenancyEvent::TeamCreated {
        context: caller.clone(),
        team_id: team(30),
        display_name: "Platform".to_owned(),
    };
    let retired = TenancyEvent::TeamRetired {
        context: caller.clone(),
        id: team(30),
    };
    let renamed = TenancyEvent::TeamCreated {
        context: caller.clone(),
        team_id: team(30),
        display_name: "Renamed".to_owned(),
    };

    let settled = Tenancy::fold(&[created.clone(), retired.clone()]);
    assert_eq!(
        settled.team(team(30)).expect("the team").state,
        TeamState::Retired
    );

    let redelivered = Tenancy::fold(&[created, retired, renamed]);
    let team_record = redelivered.team(team(30)).expect("the team");
    assert_eq!(
        team_record.state,
        TeamState::Retired,
        "a creation replayed after the terminal state reopened the record"
    );
    assert_eq!(
        team_record.display_name, "Platform",
        "the first creation is the one that stands"
    );
    assert_eq!(
        redelivered, settled,
        "the redelivered creation changed the projection"
    );

    let registered = ResourceEvent::Registered {
        context: caller.clone(),
        resource_id: resource(100),
        resource: resource_ref(100),
        parent: None,
    };
    let gone = ResourceEvent::Deregistered {
        context: caller,
        id: resource(100),
    };
    let settled = Topology::fold(&[registered.clone(), gone.clone()]);
    let topology = Topology::fold(&[registered.clone(), gone, registered]);
    assert_eq!(
        topology.record(resource(100)).expect("the record").state,
        ResourceState::Deregistered,
        "a registration replayed after deregistration reopened the record"
    );
    assert_eq!(
        topology, settled,
        "the redelivered registration changed the topology"
    );
}

/// Every declared payload name appears exactly once across the twelve variants, so no two
/// variants can name the same compiled payload.
#[test]
fn the_twelve_variants_name_twelve_distinct_payloads() {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for event in tenancy_samples() {
        *counts.entry(event.ess_name()).or_default() += 1;
    }
    for event in resource_samples_with_a_parent() {
        *counts.entry(event.ess_name()).or_default() += 1;
    }
    let repeated: BTreeSet<&str> = counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(name, _)| *name)
        .collect();
    assert!(
        repeated.is_empty(),
        "two variants name one payload: {repeated:?}"
    );
    assert_eq!(counts.len(), 12);
}
