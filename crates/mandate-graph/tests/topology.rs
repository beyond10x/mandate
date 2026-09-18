//! Parent-chain and inheritance traversal over a resource-lookup port.
//!
//! `mandate.graph.Resource` is `story:tenancy-topology`'s record. This crate never holds
//! it as a struct; it asks a [`ResourceLookup`] where a resource sits, so the traversal is
//! testable without that story having landed.

use mandate_graph::port::{GraphError, MutationOutcome, Unanswered};
use mandate_graph::topology::{
    Deregistration, MAX_ANCESTRY_DEPTH, Placement, Registration, ResourceLookup, ResourceRegistry,
    ancestry,
};
use mandate_types::{
    Audience, AuthzRevision, CorrelationId, CredentialId, DenialReason, OrganizationId,
    PrincipalId, ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn other_organization() -> OrganizationId {
    OrganizationId::new(uuid(9))
}

fn resource(byte: u8) -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(byte)),
    }
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(2)),
        actor: None,
        organization: organization(),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

/// A lookup stub written outside the crate: `(organization, resource, parent)` rows.
struct Tree(Vec<(OrganizationId, ResourceRef, Option<ResourceRef>)>);

impl ResourceLookup for Tree {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        let row = self
            .0
            .iter()
            .find(|(_, candidate, _)| candidate == resource)
            .ok_or(GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved))?;

        if &row.0 != organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }

        Ok(Placement {
            resource: row.1.clone(),
            parent: row.2.clone(),
        })
    }
}

/// A registry stub: the port half of `mandate.graph.RegisterResource` implemented outside
/// the crate, so the interface is shown to be one an adapter can satisfy.
struct RefusingRegistry;

impl ResourceRegistry for RefusingRegistry {
    fn register_resource(
        &mut self,
        _context: &VerifiedContext,
        _resource: &ResourceRef,
        _parent: Option<&ResourceId>,
    ) -> Result<Registration, GraphError> {
        Err(GraphError::Denied(DenialReason::Denied))
    }

    fn deregister_resource(
        &mut self,
        _context: &VerifiedContext,
        _id: &ResourceId,
    ) -> Result<Deregistration, GraphError> {
        Err(GraphError::Denied(DenialReason::Denied))
    }
}

fn chain() -> Tree {
    Tree(vec![
        (organization(), resource(10), None),
        (organization(), resource(11), Some(resource(10))),
        (organization(), resource(12), Some(resource(11))),
    ])
}

#[test]
fn ancestry_starts_at_the_resource_itself() {
    let found = ancestry(&chain(), &organization(), &resource(10)).expect("the root resolves");

    assert_eq!(found, vec![resource(10)]);
}

#[test]
fn ancestry_walks_the_parent_chain_with_the_root_last() {
    let found = ancestry(&chain(), &organization(), &resource(12)).expect("the leaf resolves");

    assert_eq!(found, vec![resource(12), resource(11), resource(10)]);
}

#[test]
fn a_resource_owned_by_another_organization_is_denied_as_a_tenant_mismatch() {
    let tree = Tree(vec![(other_organization(), resource(10), None)]);

    let refusal = ancestry(&tree, &organization(), &resource(10)).expect_err("another tenant");

    assert!(refusal.is_denial());
    assert_eq!(refusal.denial_reason(), DenialReason::TenantMismatch);
}

#[test]
fn a_resource_that_does_not_resolve_cannot_be_answered_for() {
    let refusal = ancestry(&chain(), &organization(), &resource(99)).expect_err("no such row");

    assert!(refusal.is_could_not_answer());
    assert_eq!(
        refusal,
        GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved)
    );
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
}

#[test]
fn a_hierarchy_that_loops_fails_closed_instead_of_looping() {
    let tree = Tree(vec![
        (organization(), resource(10), Some(resource(11))),
        (organization(), resource(11), Some(resource(10))),
    ]);

    let refusal = ancestry(&tree, &organization(), &resource(10)).expect_err("a cycle");

    assert_eq!(
        refusal,
        GraphError::CouldNotAnswer(Unanswered::HierarchyUnbounded)
    );
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
}

#[test]
fn a_chain_deeper_than_the_bound_fails_closed() {
    let deeper = u8::try_from(MAX_ANCESTRY_DEPTH + 2).expect("the bound fits a fixture byte");
    let mut rows = vec![(organization(), resource(0), None)];
    for step in 1..deeper {
        rows.push((organization(), resource(step), Some(resource(step - 1))));
    }
    let tree = Tree(rows);

    let refusal =
        ancestry(&tree, &organization(), &resource(deeper - 1)).expect_err("past the bound");

    assert_eq!(
        refusal,
        GraphError::CouldNotAnswer(Unanswered::HierarchyUnbounded)
    );
}

#[test]
fn the_bound_admits_a_chain_exactly_as_deep_as_it_declares() {
    let depth = u8::try_from(MAX_ANCESTRY_DEPTH).expect("the bound fits a fixture byte");
    let mut rows = vec![(organization(), resource(0), None)];
    for step in 1..depth {
        rows.push((organization(), resource(step), Some(resource(step - 1))));
    }
    let tree = Tree(rows);

    let found = ancestry(&tree, &organization(), &resource(depth - 1)).expect("at the bound");

    assert_eq!(found.len(), MAX_ANCESTRY_DEPTH);
}

#[test]
fn the_registration_port_is_implementable_outside_the_crate() {
    let mut registry = RefusingRegistry;
    let context = context();

    let registration = registry
        .register_resource(&context, &resource(10), None)
        .expect_err("the stub refuses");
    let deregistration = registry
        .deregister_resource(&context, &ResourceId::new(uuid(10)))
        .expect_err("the stub refuses");

    assert_eq!(registration.denial_reason(), DenialReason::Denied);
    assert_eq!(deregistration.denial_reason(), DenialReason::Denied);
}

#[test]
fn a_registration_reports_the_move_and_the_revision_the_fold_reached() {
    let registration = Registration {
        resource: resource(10),
        parent: None,
        outcome: MutationOutcome::Recorded,
        revision: AuthzRevision::new("1"),
    };
    let deregistration = Deregistration {
        id: ResourceId::new(uuid(10)),
        outcome: MutationOutcome::AlreadyRecorded,
        revision: AuthzRevision::new("1"),
    };

    assert!(registration.outcome.changed());
    assert_eq!(registration.revision, AuthzRevision::new("1"));
    assert!(!deregistration.outcome.changed());
    assert_eq!(deregistration.revision, AuthzRevision::new("1"));
}
