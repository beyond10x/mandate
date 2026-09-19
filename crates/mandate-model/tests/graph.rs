//! The record half of `mandate.graph.RegisterResource` and
//! `mandate.graph.DeregisterResource`, and the tenancy check on both.
//!
//! `graph.yaml`, RegisterResource denied: "Caller lacks resource registration/ownership
//! authority, parent is unresolved or belongs to another organization, or hierarchy
//! admission fails." One clause covers the unresolved parent and the parent in another
//! organization, and one error carries one reason, so the two refuse alike here.

use mandate_model::graph::{ResourceState, Topology};
use mandate_model::tenancy::{MembershipAuthority, Tenancy};
use mandate_types::{
    Audience, CorrelationId, CredentialId, DenialReason, OrganizationId, OrganizationMembershipId,
    PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId, VerifiedContext,
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

/// A refusal writes nothing; the pair of the macro in `tests/tenancy.rs`.
macro_rules! refuses {
    ($fold:expr, $decided:expr, $why:literal) => {{
        let before = $fold.clone();
        let denial = $decided.expect_err($why);
        assert_eq!(denial.reason, DenialReason::Denied, $why);
        assert_eq!(
            $fold, before,
            concat!("a refused command changed the projection: ", $why)
        );
    }};
}

/// Two recorded organizations, each with one member.
fn two_organizations() -> Tenancy {
    let mut tenancy = Tenancy::new();
    for (tag, name, member, identity) in [
        (1_u16, "Acme", principal(10), membership(20)),
        (2, "Other", principal(12), membership(21)),
    ] {
        let target = organization(tag);
        tenancy
            .create_organization(&platform(), target, name)
            .expect("recorded");
        tenancy
            .may_add_organization_membership(
                &context(target, principal(10)),
                MembershipAuthority::PlatformOrganizationAdministration,
                target,
                member,
            )
            .expect("the platform path admits the membership");
        tenancy
            .add_organization_membership(
                &platform(),
                MembershipAuthority::PlatformOrganizationAdministration,
                identity,
                target,
                member,
            )
            .expect("membership");
    }
    tenancy
}

/// `tests/security/cases.json`, case `cross-tenant-resource`: given "Parent resource
/// belongs to different org", action "Register child", expected "deny; child
/// unavailable" — the story's acceptance verbatim.
#[test]
fn cross_tenant_resource() {
    let tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));

    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("the parent is registered in its own organization");
    let registered = topology.len();

    let denial = topology
        .register(&tenancy, &other, &resource_ref(101), Some(resource(100)))
        .expect_err("a child beneath a parent in another organization is denied");
    assert_eq!(denial.reason, DenialReason::Denied);

    assert!(
        topology.resolve(&other, resource(101)).is_none(),
        "the denied child is unavailable to the caller that asked for it"
    );
    assert!(
        topology.resolve(&acme, resource(101)).is_none(),
        "and unavailable inside the organization that owns the parent"
    );
    assert!(
        topology.record(resource(101)).is_none(),
        "no record of the child was written at all"
    );
    assert_eq!(
        topology.len(),
        registered,
        "no partial topology was created"
    );
    assert!(
        topology.children(resource(100)).is_empty(),
        "the parent gained no child"
    );
    assert_eq!(
        topology
            .resolve(&acme, resource(100))
            .expect("the parent still resolves")
            .state,
        ResourceState::Recorded
    );
    assert!(
        topology.resolve(&other, resource(100)).is_none(),
        "the parent never resolved for the other organization either"
    );
}

/// The story's required observation: "cross-tenant-resource rejects mismatch and
/// unresolved parents without partial authority". A parent in another organization and a
/// parent that does not exist refuse identically, so the refusal is no existence oracle.
#[test]
fn an_unresolved_parent_and_a_parent_in_another_organization_refuse_alike() {
    let tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("the parent is registered");

    let elsewhere = topology
        .register(&tenancy, &other, &resource_ref(101), Some(resource(100)))
        .expect_err("a parent in another organization");
    let unresolved = topology
        .register(&tenancy, &other, &resource_ref(101), Some(resource(199)))
        .expect_err("a parent that was never registered");
    assert_eq!(elsewhere, unresolved);
    assert!(topology.record(resource(101)).is_none());
    assert_eq!(topology.len(), 1);
}

/// `graph.yaml`, DeregisterResource: "The security record of a deleted resource is kept
/// and stops resolving." A deregistered parent admits no new child.
#[test]
fn a_deregistered_resource_keeps_its_record_stops_resolving_and_admits_no_child() {
    let tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("the parent is registered");
    topology
        .deregister(&acme, resource(100))
        .expect("the parent is deregistered");

    assert_eq!(
        topology
            .record(resource(100))
            .expect("the record is kept")
            .state,
        ResourceState::Deregistered
    );
    assert!(
        topology.resolve(&acme, resource(100)).is_none(),
        "a deregistered resource stops resolving"
    );
    assert_eq!(
        topology
            .register(&tenancy, &acme, &resource_ref(101), Some(resource(100)))
            .expect_err("a deregistered parent admits no child")
            .reason,
        DenialReason::Denied
    );
    assert!(topology.record(resource(101)).is_none());
    assert_eq!(topology.len(), 1);
}

/// `graph.yaml`, DeregisterResource denied: "the resource is outside the verified
/// organization, a child resource still resolves through it".
#[test]
fn deregistration_is_confined_to_the_verified_organization_and_waits_for_its_children() {
    let tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("parent");
    topology
        .register(&tenancy, &acme, &resource_ref(101), Some(resource(100)))
        .expect("child");

    assert_eq!(
        topology
            .deregister(&other, resource(100))
            .expect_err("a resource outside the verified organization")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        topology
            .deregister(&acme, resource(100))
            .expect_err("a child still resolves through it")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        topology
            .resolve(&acme, resource(100))
            .expect("the parent is untouched")
            .state,
        ResourceState::Recorded
    );

    topology
        .deregister(&acme, resource(101))
        .expect("the child");
    topology
        .deregister(&acme, resource(100))
        .expect("the parent, once no child resolves through it");
    assert_eq!(topology.len(), 2, "both records are kept");
}

/// `RegisterResource` carries no organization selector: the record takes its organization
/// from the verified context. `graph.yaml` requires that organization to resolve
/// (`organization_id_record`), and CloseOrganization stops it "admitting authority".
#[test]
fn registration_resolves_its_organization_from_the_verified_context_and_requires_it_open() {
    let mut tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("parent");
    assert_eq!(
        topology
            .record(resource(100))
            .expect("the record")
            .organization_id,
        organization(1)
    );

    let unrecorded = context(organization(3), principal(10));
    assert_eq!(
        topology
            .register(&tenancy, &unrecorded, &resource_ref(102), None)
            .expect_err("an organization with no tenancy record admits nothing")
            .reason,
        DenialReason::Denied
    );

    tenancy
        .close_organization(&platform(), organization(1))
        .expect("closed");
    assert_eq!(
        topology
            .register(&tenancy, &acme, &resource_ref(103), None)
            .expect_err("a closed organization admits no new resource")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(topology.len(), 1);
}

/// `mandate.graph.Resource` declares `space_id`, and no command in `systems/mandate`
/// carries a space into it: `RegisterResource` takes `context`, `resource` and `parent`
/// and nothing else, and no other command writes a resource. A resource recorded by this
/// fold is therefore bound to no space, and a space that exists in tenancy does not
/// change that. The gap is the contract's, and is not closed by inventing an input here.
#[test]
fn a_registered_resource_is_bound_to_no_space_because_no_declared_command_names_one() {
    let mut tenancy = two_organizations();
    let acme = context(organization(1), principal(10));
    tenancy
        .create_space(&acme, space(40), "Production")
        .expect("space");
    assert_eq!(
        tenancy
            .space(space(40))
            .expect("the space resolves")
            .organization_id,
        organization(1)
    );

    let mut topology = Topology::new();
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("a root resource");
    topology
        .register(&tenancy, &acme, &resource_ref(101), Some(resource(100)))
        .expect("a child of that resource");
    for tag in [100_u16, 101] {
        assert_eq!(
            topology.record(resource(tag)).expect("the record").space_id,
            None,
            "no declared command binds a resource to a space"
        );
    }
}

/// A registered identity is never overwritten, in either direction across the tenant
/// boundary.
#[test]
fn a_registered_identity_is_never_overwritten() {
    let tenancy = two_organizations();
    let mut topology = Topology::new();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("parent");

    assert_eq!(
        topology
            .register(&tenancy, &other, &resource_ref(100), None)
            .expect_err("another organization cannot claim a registered identity")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        topology
            .register(&tenancy, &acme, &resource_ref(100), None)
            .expect_err("nor can the organization that holds it")
            .reason,
        DenialReason::Denied
    );
    assert_eq!(
        topology
            .record(resource(100))
            .expect("the first record stands")
            .organization_id,
        organization(1)
    );
    assert!(topology.resolve(&other, resource(100)).is_none());
    assert_eq!(topology.len(), 1);
}

/// `RegisterResource` denied: the verified organization has no tenancy record or is
/// closed, the identity is already registered, or the parent does not resolve inside the
/// verified organization — never registered, deregistered, or in another organization.
///
/// A refusal writes nothing, so the topology it refused from is the topology it leaves.
#[test]
fn register_denials_leave_the_projection_unchanged() {
    let mut tenancy = two_organizations();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));
    let stranger = context(organization(3), principal(13));
    let mut topology = Topology::new();
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("the parent is registered");
    topology
        .register(&tenancy, &acme, &resource_ref(102), Some(resource(100)))
        .expect("a child is registered");
    topology
        .register(&tenancy, &other, &resource_ref(103), None)
        .expect("a resource of the other organization is registered");

    refuses!(
        topology,
        topology.decide_register(&tenancy, &stranger, &resource_ref(104), None),
        "no tenancy record of the verified organization exists"
    );
    refuses!(
        topology,
        topology.decide_register(&tenancy, &acme, &resource_ref(100), None),
        "the identity is already registered"
    );
    refuses!(
        topology,
        topology.decide_register(&tenancy, &acme, &resource_ref(104), Some(resource(105))),
        "the parent was never registered"
    );
    refuses!(
        topology,
        topology.decide_register(&tenancy, &acme, &resource_ref(104), Some(resource(103))),
        "the parent belongs to another organization"
    );
    refuses!(
        topology,
        topology.register(&tenancy, &acme, &resource_ref(104), Some(resource(103))),
        "and the command wrapper refuses it too"
    );

    topology
        .deregister(&acme, resource(102))
        .expect("the child is deregistered");
    refuses!(
        topology,
        topology.decide_register(&tenancy, &acme, &resource_ref(104), Some(resource(102))),
        "a deregistered parent resolves for nothing"
    );

    tenancy
        .close_organization(&platform(), organization(1))
        .expect("the organization is closed");
    refuses!(
        topology,
        topology.decide_register(&tenancy, &acme, &resource_ref(106), None),
        "a closed organization admits no resource"
    );
}

/// `DeregisterResource` denied: the resource does not resolve inside the verified
/// organization, has already been deregistered, or a child still resolves through it.
#[test]
fn deregister_denials_leave_the_projection_unchanged() {
    let tenancy = two_organizations();
    let acme = context(organization(1), principal(10));
    let other = context(organization(2), principal(12));
    let mut topology = Topology::new();
    topology
        .register(&tenancy, &acme, &resource_ref(100), None)
        .expect("the parent is registered");
    topology
        .register(&tenancy, &acme, &resource_ref(101), Some(resource(100)))
        .expect("the child is registered");

    refuses!(
        topology,
        topology.decide_deregister(&acme, resource(105)),
        "no record of that resource exists"
    );
    refuses!(
        topology,
        topology.decide_deregister(&other, resource(100)),
        "a resource of another organization is not the outsider's to deregister"
    );
    refuses!(
        topology,
        topology.decide_deregister(&acme, resource(100)),
        "a child still resolves through it"
    );
    refuses!(
        topology,
        topology.deregister(&acme, resource(100)),
        "and the command wrapper refuses it too"
    );

    topology
        .deregister(&acme, resource(101))
        .expect("the child is deregistered");
    refuses!(
        topology,
        topology.decide_deregister(&acme, resource(101)),
        "a terminal state does not move twice"
    );
}
