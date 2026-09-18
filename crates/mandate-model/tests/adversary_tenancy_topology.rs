//! Adversarial cases for `story:tenancy-topology`, driven from the compiled contract.
//!
//! `crates/mandate-model/src/tenancy.rs`, under *These projections are rebuildable from
//! the log*, states the claim these cases attack: that the events are the record and
//! these structures are the fold of them, so a [`Tenancy`] is derived, droppable and
//! rebuildable, never authoritative. (The same paragraph said the opposite until
//! `story:event-payloads-for-folds` landed; these cases are what decides which is true.)
//!
//! ADR 0009 states the same thing normatively: "A command produces domain events; the
//! events are the record; every read is a fold over them ... State tables are
//! projections: derived, droppable, rebuildable, never authoritative."
//!
//! A projection is rebuildable only if every field it is required to carry can be read
//! out of the events. These two cases ask whether that holds, one from the compiled
//! schema and one from the fold's own API.

use std::collections::BTreeSet;

use mandate_model::tenancy::{
    MembershipAuthority, OrganizationMembershipState, TeamMembershipState, Tenancy,
};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, OrganizationId, OrganizationMembershipId,
    PrincipalId, TeamId, TeamMembershipId, VerifiedContext,
};

const SCHEMA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema");

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

fn document(kind: &str, ess_name: &str) -> serde_json::Value {
    let path = format!("{SCHEMA}/{kind}/{ess_name}.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    serde_json::from_str(&text).expect("the compiled document is JSON")
}

fn property_names(schema: &serde_json::Value) -> BTreeSet<String> {
    schema["properties"]
        .as_object()
        .expect("the declared properties")
        .keys()
        .cloned()
        .collect()
}

/// The event's own property names, plus the members of any struct it carries by value.
///
/// A field can be carried without being a top-level property of the event:
/// `mandate.graph.ResourceRegistered` declares `resource: mandate.core.ResourceRef`, and
/// `ResourceRef` declares `resource_type` and `resource_id`. A fold reading that event has
/// `resource_type` in hand, so a reader that only looked at top-level names would report a
/// field the log does carry — a false orphan. One level of descent, the same depth
/// `crates/mandate-types/tests/adversary_fold_inputs.rs:203` reads at.
///
/// `mandate.core.VerifiedContext` is excluded: its members are the caller's, not the
/// record's, and the one field a fold does take from it — `organization_id` — is exempted
/// explicitly below so that the exemption stays visible instead of being absorbed here.
fn property_names_carrying_struct_members(schema: &serde_json::Value) -> BTreeSet<String> {
    let mut names = property_names(schema);
    let definitions = &schema["$defs"];
    for property in schema["properties"]
        .as_object()
        .expect("the declared properties")
        .values()
    {
        let Some(reference) = property["$ref"].as_str() else {
            continue;
        };
        let Some(kind) = reference.strip_prefix("#/$defs/") else {
            continue;
        };
        if kind == "mandate.core.VerifiedContext" {
            continue;
        }
        let declared = &definitions[kind];
        if declared["x-ess-kind"].as_str() != Some("struct") {
            continue;
        }
        names.extend(property_names(declared));
    }
    names
}

/// Every property name any event of `domain` declares, including the members of a struct
/// an event carries by value.
///
/// Deliberately generous: it unions every event of the domain rather than asking which
/// event the accepted outcome of the writing command actually emits. A field that only
/// a *removal* event carries is counted as carried, which understates the gap.
fn every_event_property_of(domain: &str) -> BTreeSet<String> {
    let directory = format!("{SCHEMA}/events");
    let prefix = format!("{domain}.");
    let mut carried = BTreeSet::new();
    let entries = std::fs::read_dir(&directory).unwrap_or_else(|error| {
        panic!("{directory}: {error}");
    });
    for entry in entries {
        let entry = entry.expect("a compiled event");
        let file = entry.file_name();
        let file = file.to_str().expect("a schema file name");
        let Some(ess_name) = file.strip_suffix(".schema.json") else {
            continue;
        };
        if !ess_name.starts_with(&prefix) {
            continue;
        }
        carried.extend(property_names_carrying_struct_members(&document(
            "events", ess_name,
        )));
    }
    assert!(!carried.is_empty(), "{domain}: no compiled event was read");
    carried
}

/// The six projections, beside the domain whose events are supposed to rebuild them.
const PROJECTED: [(&str, &str); 6] = [
    ("mandate.tenancy", "mandate.tenancy.Organization"),
    ("mandate.tenancy", "mandate.tenancy.OrganizationMembership"),
    ("mandate.tenancy", "mandate.tenancy.Team"),
    ("mandate.tenancy", "mandate.tenancy.TeamMembership"),
    ("mandate.tenancy", "mandate.tenancy.Space"),
    ("mandate.graph", "mandate.graph.Resource"),
];

/// ADR 0009: "the events are the record; every read is a fold over them ... State tables
/// are projections: derived, droppable, rebuildable". The module docs of `src/tenancy.rs`
/// and `src/graph.rs` claim it for these six.
///
/// A projection that is required to carry a field no event declares cannot be rebuilt:
/// dropping it loses that field for good. This asks, for each of the six, whether every
/// required field is carried by some event of its own domain — a top-level property of
/// that event, or a member of a struct it carries by value.
///
/// Two exemptions, both derivable without an event field of their own:
///
/// * `state` — the lifecycle's `initial`, moved by each accepted outcome's declared
///   `moves`, so the event's identity is enough.
/// * `organization_id` — `mandate.core.VerifiedContext` carries `organization`, and
///   every event in both domains declares `context`, so the fold reads it from there.
///   `src/tenancy.rs:471` and `src/graph.rs:174` both do exactly that.
#[test]
fn every_required_projection_field_is_carried_by_a_declared_event() {
    let mut orphaned: Vec<String> = Vec::new();
    for (domain, ess_name) in PROJECTED {
        let carried = every_event_property_of(domain);
        let entity = document("entities", ess_name);
        let required = entity["required"]
            .as_array()
            .expect("the required list")
            .iter()
            .map(|name| name.as_str().expect("a required name").to_owned());
        for field in required {
            if field == "state" || field == "organization_id" {
                continue;
            }
            if !carried.contains(&field) {
                orphaned.push(format!("{ess_name}.{field}"));
            }
        }
    }
    // The tripwire the coordinator placed at integration pinned four orphaned fields —
    // `Organization.display_name`, `Team.display_name`, `Space.display_name` and
    // `Resource.resource_type` — and named `story:event-payloads-for-folds` as the fix.
    // That story landed: the three creation events declare `display_name`, and
    // `ResourceRegistered` carries `resource: mandate.core.ResourceRef`, whose members are
    // `resource_type` and `resource_id`. The tripwire is retired and the equality it
    // replaced is restored: no required field of these six projections is orphaned, so
    // each is droppable and rebuildable as ADR 0009 requires. A non-empty list here is a
    // real finding, not a pin to update.
    assert_eq!(
        orphaned,
        Vec::<String>::new(),
        "a required projection field is carried by no event of its domain, so the \
         projection is authoritative for it and a rebuild from the log loses it"
    );
}

/// `tenancy.yaml:231`, AddOrganizationMembership: "organization_id must equal the
/// organization in the caller's verified context; it may differ only for a caller
/// holding platform organization-administration authority, which is how the organization
/// CreateOrganization returns is first populated".
///
/// `src/tenancy.rs:75-81` makes that distinction a fold *input*, [`MembershipAuthority`],
/// and refuses the write on the tenant path. `mandate.tenancy.OrganizationMembershipAdded`
/// declares no field from which that input can be read, so the accepted history below —
/// the contract's own "how the organization is first populated" — cannot be replayed
/// from its declared events, and the row is lost on a rebuild.
///
/// Deriving "platform" from `organization_id != context.organization` is not available
/// to a replayer: that is inferring the authority from the very mismatch the authority
/// was required to write, which is the inference `src/tenancy.rs:280-284` exists to
/// refuse.
#[test]
fn a_platform_written_membership_replays_from_its_declared_event_alone() {
    let acme = organization(1);
    let elsewhere = organization(2);
    let _platform = context(elsewhere, principal(9));
    let joiner = principal(11);

    let mut live = Tenancy::new();
    live.create_organization(acme, "Acme").expect("acme");
    live.create_organization(elsewhere, "Platform")
        .expect("the platform administrator's own organization");
    live.add_organization_membership(membership(20), acme, joiner)
        .expect("the platform path seeds the first membership of acme");

    let declared = property_names(&document(
        "events",
        "mandate.tenancy.OrganizationMembershipAdded",
    ));
    assert_eq!(
        declared.iter().map(String::as_str).collect::<Vec<&str>>(),
        vec![
            "context",
            "membership_id",
            "organization_id",
            "principal_id"
        ],
        "the declared event is the whole record of what happened"
    );

    let mut replayed = Tenancy::new();
    replayed.create_organization(acme, "Acme").expect("acme");
    replayed
        .create_organization(elsewhere, "Platform")
        .expect("the platform administrator's own organization");
    replayed
        .add_organization_membership(membership(20), acme, joiner)
        .expect("the declared event carries no authority path, so replaying it must not need one");

    assert_eq!(replayed, live, "a rebuild reproduces the fold it dropped");
}

/// `tenancy.yaml`, AddOrganizationMembership denied: "... **the named organization is
/// closed** ...". CloseOrganization accepted: "The tenant stops admitting authority and
/// nothing it owns is destroyed."
///
/// That rule is not the authority rule, and the reason the authority rule had to leave the
/// apply half does not reach it: `mandate.tenancy.OrganizationClosed` declares `id`, so a
/// replayer knows a closed organization when it sees one, and a log applied in order never
/// presents `OrganizationMembershipAdded` after it. The closed rule is therefore
/// recoverable — the test `src/tenancy.rs:52-54` sets for a guard that may stay in the
/// fold — and `create_team` and `create_space` both keep it (`self.admits(...)`).
///
/// `add_organization_membership` does not: it tests
/// `self.organizations.contains_key(&organization_id)` alone, so the only method that
/// writes the row admits one into a `Closed` organization. Deciding and applying are two
/// calls with nothing between them, so a closure that lands between them — the sequence
/// below, and the sequence the module's own decide-then-apply protocol (`src/tenancy.rs:
/// 46-50`) invites — writes an `Active` membership of a tenant that admits no authority.
/// No accepted history produces that state, so no replay can rebuild it either.
#[test]
fn a_closed_organization_admits_no_membership_through_the_half_that_writes() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    tenancy.create_organization(acme, "Acme").expect("acme");
    tenancy
        .may_add_organization_membership(
            &caller,
            MembershipAuthority::VerifiedOrganization,
            acme,
            joiner,
        )
        .expect("the decide half admits the write while the organization is open");

    tenancy.close_organization(acme).expect("closed");
    assert!(!tenancy.admits(acme), "the tenant admits no new authority");

    let denial = tenancy
        .add_organization_membership(membership(20), acme, joiner)
        .expect_err("a closed organization admits no new membership");
    assert_eq!(denial.reason, DenialReason::Denied);
    assert!(
        tenancy.members_of(acme).is_empty(),
        "a closed tenant gained a member"
    );
    assert_eq!(
        tenancy.record_count(),
        1,
        "nothing but the organization was ever written"
    );
}

/// `tenancy.yaml`, RemoveOrganizationMembership denied: "membership is outside the
/// verified organization"; RemoveTeamMembership denied: "the membership is outside the
/// verified organization".
///
/// Both guards are written (`src/tenancy.rs:409-411`, `:519-521`) and nothing executes
/// them. This case is green on the tree it was written against; it is here because the
/// mutant that deletes either guard — `membership.organization_id != context.organization`
/// removed from `remove_organization_membership` and from `remove_team_membership` — leaves
/// all 37 cases of the package green. A guard no case reaches is a guard the next edit may
/// drop for free, and it is the one guard this story exists to hold: an outsider moving a
/// record of another tenant to a terminal state.
///
/// The second half of the case is what stops it being a tautology: the same two removals
/// succeed for the caller the records belong to, so what is being refused is the caller's
/// organization and not the removal.
#[test]
fn a_removal_is_confined_to_the_verified_organization() {
    let acme = organization(1);
    let other = organization(2);
    let caller = context(acme, principal(10));
    let outsider = context(other, principal(12));
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    tenancy.create_organization(acme, "Acme").expect("acme");
    tenancy.create_organization(other, "Other").expect("other");
    tenancy
        .add_organization_membership(membership(20), acme, joiner)
        .expect("membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy
        .add_team_membership(&caller, team_membership(50), team(30), joiner)
        .expect("team membership");

    assert_eq!(
        tenancy
            .remove_organization_membership(&outsider, membership(20))
            .expect_err("a membership of another organization is not the outsider's to remove")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .organization_membership(membership(20))
            .expect("the record is kept")
            .state,
        OrganizationMembershipState::Active,
        "a refused removal moves no state"
    );
    assert_eq!(
        tenancy
            .remove_team_membership(&outsider, team_membership(50))
            .expect_err("a team membership of another organization is not the outsider's to remove")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        tenancy
            .team_membership(team_membership(50))
            .expect("the record is kept")
            .state,
        TeamMembershipState::Recorded,
        "a refused removal moves no state"
    );

    tenancy
        .remove_team_membership(&caller, team_membership(50))
        .expect("the organization the record belongs to may remove it");
    tenancy
        .remove_organization_membership(&caller, membership(20))
        .expect("the organization the record belongs to may remove it");
}

/// `tenancy.yaml`, CloseOrganization: "The tenant stops admitting authority". The fold
/// keeps that rule for `AddTeamMembership` at `src/tenancy.rs:478` and nothing executes
/// it: `a_closed_organization_admits_no_new_membership_team_or_space`
/// (`tests/tenancy.rs:394`) covers membership, team and space and not team membership, and
/// deleting the `self.admits(context.organization)` guard from `add_team_membership`
/// leaves all 37 cases of the package green.
///
/// The guard is the only one that refuses here: the team is still `Recorded` and the
/// principal still holds an `Active` membership, because a closure destroys neither.
#[test]
fn a_closed_organization_admits_no_new_team_membership() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    tenancy.create_organization(acme, "Acme").expect("acme");
    tenancy
        .add_organization_membership(membership(20), acme, joiner)
        .expect("membership");
    tenancy
        .create_team(&caller, team(30), "Platform")
        .expect("team");
    tenancy.close_organization(acme).expect("closed");

    assert!(tenancy.is_member(acme, joiner), "the membership is kept");
    assert!(
        tenancy.team(team(30)).is_some(),
        "and so is the team it would be a membership of"
    );
    assert_eq!(
        tenancy
            .add_team_membership(&caller, team_membership(50), team(30), joiner)
            .expect_err("a closed organization admits no new team membership")
            .reason,
        DenialReason::Denied
    );
    assert!(tenancy.team_membership(team_membership(50)).is_none());
    assert_eq!(tenancy.record_count(), 3, "nothing was written");
}
