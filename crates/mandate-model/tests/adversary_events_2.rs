//! Adversary pass 2 over `story:tenancy-graph-events`: the decide/apply split as a class.
//!
//! Pass 1 asked whether a *log* rebuilds a projection. These cases fix where each guard
//! lives, after the coordinator ruling on adversary pass 2:
//!
//! * A guard is enforced by `decide_*`, which reads the projection and refuses. When the
//!   conflicting event (a closure, a retirement, a prior membership) is already in the
//!   projection the decide half reads, the decide half refuses.
//! * `apply` and `fold` are total. They take the event and write it; they re-check
//!   nothing, because a fold that could refuse would not be the rebuild
//!   `docs/adr/0009-event-sourced-persistence.md` requires — it could drop an event the
//!   accepted history contains.
//! * The window between a decide call and its append is closed by the command path, which
//!   ADR 0009 makes one transaction under optimistic concurrency, not by this library. A
//!   log that pairs a membership with a *later* closure of the same tenant is producible
//!   only when a second writer closes the tenant between this writer's decide and its
//!   append; the runtime's expected-version guard forbids that. These cases assert the
//!   two halves of that contract: decide refuses in order, and apply reproduces any log.

use mandate_model::graph::{ResourceEvent, Topology};
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_types::{
    Audience, CorrelationId, CredentialId, MembershipContributionId, OrganizationId,
    OrganizationMembershipId, PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId, TeamId,
    TeamMembershipId, VerifiedContext,
};

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

/// The platform administrator's verified context, verified in its own organization.
fn platform() -> VerifiedContext {
    context(organization(0xfff0), principal(0xfff1))
}

/// The org-closed guard is enforced at decide, and apply is total.
#[test]
fn the_org_closed_guard_lives_at_decide_and_apply_is_total() {
    let acme = organization(1);
    let joiner = principal(11);

    // In order — the closure the decide half reads — decide refuses.
    let mut ordered = Tenancy::new();
    ordered
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    ordered
        .close_organization(&platform(), acme)
        .expect("the organization is closed");
    assert!(
        ordered
            .decide_add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                membership(20),
                acme,
                joiner,
            )
            .is_err(),
        "decide refuses a membership into a closed organization the projection already holds"
    );

    // apply is total: handed the event decided while the organization was open, it writes
    // it and re-checks nothing. The pairing of this event with a later closure is only
    // producible by a second writer closing between decide and append, which the runtime's
    // expected-version guard forbids, not this library.
    let mut open = Tenancy::new();
    open.create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    let decided = open
        .decide_add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("the decide half admits the write while the organization is open");
    open.close_organization(&platform(), acme)
        .expect("the organization is closed");
    open.apply(&decided);
    assert!(
        open.organization_membership(membership(20)).is_some(),
        "apply writes the event it is handed and re-checks no guard"
    );
}

/// Every cross-record guard is enforced by the decide half that reads the projection.
#[test]
fn every_cross_record_guard_is_enforced_at_decide() {
    let acme = organization(1);
    let caller = context(acme, principal(10));
    let joiner = principal(11);
    let mut unguarded: Vec<&'static str> = Vec::new();

    // CreateTeam into a closed organization.
    {
        let mut tenancy = Tenancy::new();
        tenancy
            .create_organization(&platform(), acme, "Acme")
            .expect("the organization is recorded");
        tenancy
            .close_organization(&platform(), acme)
            .expect("the organization is closed");
        if tenancy
            .decide_create_team(&caller, team(30), "Platform")
            .is_ok()
        {
            unguarded.push("decide_create_team admitted a closed organization");
        }
    }

    // CreateSpace into a closed organization.
    {
        let mut tenancy = Tenancy::new();
        tenancy
            .create_organization(&platform(), acme, "Acme")
            .expect("the organization is recorded");
        tenancy
            .close_organization(&platform(), acme)
            .expect("the organization is closed");
        if tenancy
            .decide_create_space(&caller, space(40), "Production")
            .is_ok()
        {
            unguarded.push("decide_create_space admitted a closed organization");
        }
    }

    // AddTeamMembership into a retired team.
    {
        let mut tenancy = Tenancy::new();
        tenancy
            .create_organization(&platform(), acme, "Acme")
            .expect("the organization is recorded");
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                membership(20),
                acme,
                joiner,
            )
            .expect("the platform path seeds the first membership");
        tenancy
            .create_team(&caller, team(30), "Platform")
            .expect("the team is recorded");
        tenancy
            .retire_team(&caller, team(30))
            .expect("the team is retired");
        if tenancy
            .decide_add_team_membership(
                &caller,
                team_membership(50),
                team(30),
                joiner,
                contribution(60),
            )
            .is_ok()
        {
            unguarded.push("decide_add_team_membership admitted a retired team");
        }
    }

    // RegisterResource into a closed organization.
    {
        let mut tenancy = Tenancy::new();
        tenancy
            .create_organization(&platform(), acme, "Acme")
            .expect("the organization is recorded");
        tenancy
            .close_organization(&platform(), acme)
            .expect("the organization is closed");
        let topology = Topology::new();
        if topology
            .decide_register(&tenancy, &caller, &resource_ref(100), None)
            .is_ok()
        {
            unguarded.push("decide_register admitted a closed organization");
        }
    }

    assert_eq!(
        unguarded,
        Vec::<&'static str>::new(),
        "a cross-record guard was not enforced by the decide half that reads the projection"
    );
}

/// The one-active-membership-per-principal rule is enforced at decide, in order.
#[test]
fn the_one_active_membership_rule_is_enforced_at_decide() {
    let acme = organization(1);
    let joiner = principal(11);

    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            &platform(),
            MembershipAuthority::PlatformOrganizationAdministration,
            membership(20),
            acme,
            joiner,
        )
        .expect("the first membership is written");

    // With the first membership applied, the decide half reads it and refuses a second for
    // the same principal in the same organization. Two decisions taken before either
    // applies would both be admitted; that log is producible only by concurrent deciders,
    // which the runtime's expected-version guard forbids.
    assert!(
        tenancy
            .decide_add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                membership(21),
                acme,
                joiner,
            )
            .is_err(),
        "decide refuses a second active membership for a principal the projection already holds"
    );
}

/// The decide half never emits a registration whose two identities disagree.
#[test]
fn decide_register_never_emits_a_divergent_resource_identity() {
    let acme = organization(1);
    let caller = context(acme, principal(10));

    // `ResourceEvent::Registered` declares `resource_id` beside `resource`, and
    // `mandate.core.ResourceRef` declares `resource_id` of its own. The identity is set
    // once, from the reference, so the two are the same in every event decide produces. A
    // divergent pair is only constructible by hand and is not a value this library emits.
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(&platform(), acme, "Acme")
        .expect("the organization is recorded");
    let topology = Topology::new();
    let decided = topology
        .decide_register(&tenancy, &caller, &resource_ref(100), None)
        .expect("the registration is admitted");
    match decided {
        ResourceEvent::Registered {
            resource_id,
            resource,
            ..
        } => assert_eq!(
            resource_id, resource.resource_id,
            "decide emitted a registration whose top-level identity and reference disagree"
        ),
        other => panic!("decide_register emitted {other:?} rather than a registration"),
    }
}
