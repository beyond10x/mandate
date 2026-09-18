//! Validated context is required, and the tenant, audience, resource and space bindings
//! are enforced before any authority is read.
//!
//! Corpus cases (`tests/security/cases.json`): `reference-audience` (`:223`) — a
//! credential targeting one audience presented to another; `cross-tenant-resource`
//! (`:589`) — a resource belonging to a different organization; `mapping-cross-org`
//! (`:80`) — a subject and a tenant that belong to different organizations contribute
//! nothing.

use mandate_authz::context::{Binding, bind, direct};
use mandate_graph::double::GraphDouble;
use mandate_graph::port::GraphError;
use mandate_graph::topology::{Placement, ResourceLookup, ResourceRegistry};
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_types::{
    Audience, AuthorityScope, AuthoritySubject, CorrelationId, CredentialId, DelegationId,
    DenialReason, ExecutionId, OrganizationId, OrganizationMembershipId, PrincipalId, ResourceId,
    ResourceRef, ResourceType, SpaceId, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn principal() -> PrincipalId {
    PrincipalId::new(uuid(2))
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

fn space() -> SpaceId {
    SpaceId::new(uuid(20))
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: principal(),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// An organization that admits authority, with the context's subject a member of it.
fn tenancy() -> Tenancy {
    let mut tenancy = Tenancy::new();
    tenancy
        .create_organization(organization(), "acme")
        .expect("the organization is recorded");
    tenancy
        .add_organization_membership(
            OrganizationMembershipId::new(uuid(3)),
            organization(),
            principal(),
        )
        .expect("the subject is a member");
    tenancy
}

/// A graph holding the resource, registered by the organization the context names.
fn graph() -> GraphDouble {
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&context(), &resource(), None)
        .expect("the resource is registered");
    graph
}

fn binding<'a>(
    context: &'a VerifiedContext,
    audience: &'a Audience,
    resource: &'a ResourceRef,
) -> Binding<'a> {
    Binding {
        context,
        resource,
        expected_audience: audience,
        scope: None,
    }
}

/// A lookup that refuses to be asked. The binding order is a security property, not a
/// preference: a context that does not bind must read nothing, so a refusal that reached
/// this would be a request for authority made on behalf of a context that never stood.
struct NeverAsked;

impl ResourceLookup for NeverAsked {
    fn placement(
        &self,
        _organization: &OrganizationId,
        _resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        unreachable!("the context did not bind, so no resource may be read");
    }
}

#[test]
fn a_bound_context_carries_the_verified_subject_and_organization() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();

    let bound = bind(
        &tenancy(),
        &Topology::new(),
        &graph(),
        &binding(&context, &audience, &resource),
    )
    .expect("the context binds");

    assert_eq!(bound.subject, AuthoritySubject::Principal(principal()));
    assert_eq!(bound.organization, organization());
    assert_eq!(bound.resource, resource);
    assert_eq!(bound.space, None);
}

#[test]
fn an_organization_that_admits_no_authority_refuses_the_context() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut tenancy = tenancy();
    tenancy
        .close_organization(organization())
        .expect("the organization is closed");

    let refusal = bind(
        &tenancy,
        &Topology::new(),
        &NeverAsked,
        &binding(&context, &audience, &resource),
    )
    .expect_err("a closed organization admits nothing");

    assert_eq!(refusal, DenialReason::InvalidCredential);
}

/// `mapping-cross-org`: a subject and a tenant that belong to different organizations
/// contribute no authority to each other. The credential is valid and names an
/// organization that admits authority; the subject is simply not a member of it.
#[test]
fn a_subject_that_is_not_a_member_of_the_verified_organization_is_a_tenant_mismatch() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut elsewhere = Tenancy::new();
    elsewhere
        .create_organization(organization(), "acme")
        .expect("the organization is recorded");

    let refusal = bind(
        &elsewhere,
        &Topology::new(),
        &NeverAsked,
        &binding(&context, &audience, &resource),
    )
    .expect_err("the subject is a member of no organization here");

    assert_eq!(refusal, DenialReason::TenantMismatch);
}

/// `reference-audience`: a credential issued for API A, presented to API B.
#[test]
fn a_credential_issued_for_another_audience_is_an_audience_mismatch() {
    let context = context();
    let other_api = Audience::new("other-api");
    let resource = resource();

    let refusal = bind(
        &tenancy(),
        &Topology::new(),
        &NeverAsked,
        &binding(&context, &other_api, &resource),
    )
    .expect_err("the credential names another audience");

    assert_eq!(refusal, DenialReason::AudienceMismatch);
}

/// `cross-tenant-resource`: the resource belongs to a different organization.
#[test]
fn a_resource_registered_by_another_organization_is_a_tenant_mismatch() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut elsewhere = context.clone();
    elsewhere.organization = OrganizationId::new(uuid(9));
    let mut graph = GraphDouble::new();
    graph
        .register_resource(&elsewhere, &resource, None)
        .expect("the other tenant registers it");

    let refusal = bind(
        &tenancy(),
        &Topology::new(),
        &graph,
        &binding(&context, &audience, &resource),
    )
    .expect_err("the resource is not this tenant's");

    assert_eq!(refusal, DenialReason::TenantMismatch);
}

/// A resource nobody registered is an absence, not a decision about the caller, and an
/// absence fails closed (`crates/mandate-graph/src/port.rs:76-85`).
#[test]
fn a_resource_that_does_not_resolve_is_unavailable() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();

    let refusal = bind(
        &tenancy(),
        &Topology::new(),
        &GraphDouble::new(),
        &binding(&context, &audience, &resource),
    )
    .expect_err("no such resource");

    assert_eq!(refusal, DenialReason::Unavailable);
}

#[test]
fn a_scope_naming_a_space_the_organization_does_not_hold_is_a_tenant_mismatch() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let scope = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: Some(space()),
    };

    let refusal = bind(
        &tenancy(),
        &Topology::new(),
        &graph(),
        &Binding {
            context: &context,
            resource: &resource,
            expected_audience: &audience,
            scope: Some(&scope),
        },
    )
    .expect_err("no such space in this organization");

    assert_eq!(refusal, DenialReason::TenantMismatch);
}

/// The space resolves, and the resource is still not bound to it. `mandate.graph.Resource`
/// declares `space_id` and no command writes it (`crates/mandate-model/src/graph.rs:34-41`),
/// so today this is every scoped request: the closed direction, and the record of a
/// contract gap that `story:event-payloads-for-folds` owns.
#[test]
fn a_scope_naming_a_space_the_resource_is_not_bound_to_is_a_tenant_mismatch() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut tenancy = tenancy();
    tenancy
        .create_space(&context, space(), "engineering")
        .expect("the space is recorded");
    let mut topology = Topology::new();
    topology
        .register(&tenancy, &context, &resource, None)
        .expect("the resource is recorded");
    let scope = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: Some(space()),
    };

    let refusal = bind(
        &tenancy,
        &topology,
        &graph(),
        &Binding {
            context: &context,
            resource: &resource,
            expected_audience: &audience,
            scope: Some(&scope),
        },
    )
    .expect_err("the resource is bound to no space");

    assert_eq!(refusal, DenialReason::TenantMismatch);
}

/// A scope that names no space binds without reading the topology at all.
#[test]
fn a_scope_naming_no_space_binds() {
    let context = context();
    let audience = Audience::new("mandate");
    let resource = resource();
    let scope = AuthorityScope {
        actions: Vec::new(),
        resources: Vec::new(),
        space: None,
    };

    let bound = bind(
        &tenancy(),
        &Topology::new(),
        &graph(),
        &Binding {
            context: &context,
            resource: &resource,
            expected_audience: &audience,
            scope: Some(&scope),
        },
    )
    .expect("the context binds");

    assert_eq!(bound.space, None);
}

/// `docs/architecture/combined.md:53` makes effective authority the intersection of, among
/// others, the actor ceiling and the explicit delegation. `mandate.core.VerifiedContext`
/// carries three inputs that say a request is not direct — `actor`, `delegation` and
/// `execution` — and no port in this crate's dependency ceiling reads any of them. Each is
/// refused closed rather than decided as though it were unbounded, and every one of the
/// three is listed here so none is left open while its neighbours are shut.
#[test]
fn a_context_that_is_not_direct_is_refused() {
    let subject_as_actor = {
        let mut context = context();
        context.actor = Some(principal());
        context
    };
    let another_actor = {
        let mut context = context();
        context.actor = Some(PrincipalId::new(uuid(99)));
        context
    };
    let delegated = {
        let mut context = context();
        context.delegation = Some(DelegationId::new(uuid(50)));
        context
    };
    let executing = {
        let mut context = context();
        context.execution = Some(ExecutionId::new(uuid(51)));
        context
    };

    assert!(direct(&context()), "no actor at all is the subject itself");
    assert!(
        direct(&subject_as_actor),
        "an actor equal to the subject is the subject acting as itself"
    );
    for context in [&another_actor, &delegated, &executing] {
        assert!(!direct(context));
    }
}

/// The refusal is a decision about this request's authority — `Denied` — and not an
/// outage, and it is taken before any resource is read.
#[test]
fn a_delegated_request_is_refused_closed_and_reads_nothing() {
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut delegated = context();
    delegated.actor = Some(PrincipalId::new(uuid(99)));

    let refusal = bind(
        &tenancy(),
        &Topology::new(),
        &NeverAsked,
        &binding(&delegated, &audience, &resource),
    )
    .expect_err("the actor ceiling cannot be intersected here, so the request is refused");

    assert_eq!(refusal, DenialReason::Denied);
}

/// The same request with the actor naming the subject itself is direct, and binds.
#[test]
fn an_actor_equal_to_the_subject_binds() {
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut acting_as_itself = context();
    acting_as_itself.actor = Some(principal());

    let bound = bind(
        &tenancy(),
        &Topology::new(),
        &graph(),
        &binding(&acting_as_itself, &audience, &resource),
    )
    .expect("the subject acting as itself is a direct request");

    assert_eq!(bound.subject, AuthoritySubject::Principal(principal()));
}

/// An explicit delegation and an execution are refused for the same reason and in the same
/// place, each without reading a resource.
#[test]
fn a_context_naming_a_delegation_or_an_execution_is_refused_closed() {
    let audience = Audience::new("mandate");
    let resource = resource();
    let mut delegation = context();
    delegation.delegation = Some(DelegationId::new(uuid(50)));
    let mut execution = context();
    execution.execution = Some(ExecutionId::new(uuid(51)));

    for context in [&delegation, &execution] {
        let refusal = bind(
            &tenancy(),
            &Topology::new(),
            &NeverAsked,
            &binding(context, &audience, &resource),
        )
        .expect_err("a bound this crate cannot evaluate cannot be intersected");

        assert_eq!(refusal, DenialReason::Denied);
    }
}
