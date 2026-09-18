//! Parent-chain and inheritance traversal over a resource-lookup port.
//!
//! `mandate.graph.Resource` (`graph.yaml:8-47`) is `story:tenancy-topology`'s record, and
//! this crate carries no edge to that story. It therefore never holds the resource as a
//! struct: it asks a [`ResourceLookup`] where a resource sits, and an adapter answers from
//! wherever the resource projection actually lives.
//!
//! Inheritance is the parent chain. A subject that holds a relation on an ancestor holds
//! it on every descendant, which is what [`ancestry`] enumerates for the read in
//! [`crate::port::GraphRead`].

use mandate_types::{AuthzRevision, OrganizationId, ResourceId, ResourceRef, VerifiedContext};

use crate::port::{GraphError, MutationOutcome, Unanswered};

/// The deepest parent chain this crate will walk.
///
/// The contract declares no bound (`graph.yaml:17-18` makes `parent` optional and
/// `graph.yaml:39-43` makes it self-referential), so one is imposed here: a chain that does not terminate within it is
/// a hierarchy this crate cannot answer for, and it fails closed rather than looping.
pub const MAX_ANCESTRY_DEPTH: usize = 64;

/// Where a resource sits in its organization's hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The resource itself.
    pub resource: ResourceRef,
    /// The resource's parent, when it has one.
    pub parent: Option<ResourceRef>,
}

/// The resource-lookup port.
///
/// The organization is the tenancy bound: a resource that resolves under another
/// organization is a denial, not an absence.
pub trait ResourceLookup {
    /// Where the resource sits, for the given organization.
    ///
    /// # Errors
    ///
    /// [`GraphError::Denied`] with [`mandate_types::DenialReason::TenantMismatch`] when
    /// the resource resolves under another organization;
    /// [`GraphError::CouldNotAnswer`] with [`Unanswered::ResourceUnresolved`] when it does
    /// not resolve at all, or no longer resolves because it was deregistered.
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError>;
}

/// What `mandate.graph.RegisterResource` recorded.
///
/// The contract declares no response for this command; the revision is the fold position
/// the move reached, offered so a caller can read its own write, not a declared wire
/// response. `mandate.graph.WriteRelationship` is the one command that declares a
/// `revision` response (`graph.yaml:191-193`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The resource that is now recorded.
    pub resource: ResourceRef,
    /// The parent it was recorded under, when it has one.
    pub parent: Option<ResourceId>,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
    /// The fold position the graph reached.
    pub revision: AuthzRevision,
}

/// What `mandate.graph.DeregisterResource` recorded.
///
/// The security record is kept and stops resolving (`graph.yaml:210`). Nothing is
/// destroyed: no child resource, relation or grant is touched as a side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deregistration {
    /// The resource that stopped resolving.
    pub id: ResourceId,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
    /// The fold position the graph reached.
    pub revision: AuthzRevision,
}

/// `mandate.graph.RegisterResource` and `mandate.graph.DeregisterResource`.
pub trait ResourceRegistry {
    /// Record a resource, optionally under a parent that already resolves.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `graph.yaml:169`: missing authority, an
    /// unresolved parent or one in another organization, or a hierarchy that does not
    /// admit the resource.
    fn register_resource(
        &mut self,
        context: &VerifiedContext,
        resource: &ResourceRef,
        parent: Option<&ResourceId>,
    ) -> Result<Registration, GraphError>;

    /// Stop a resource resolving, keeping its security record.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `graph.yaml:212`: missing authority, a
    /// resource outside the verified organization, or a child that still resolves through
    /// it.
    fn deregister_resource(
        &mut self,
        context: &VerifiedContext,
        id: &ResourceId,
    ) -> Result<Deregistration, GraphError>;
}

/// The resource and every ancestor of it, nearest first.
///
/// The queried resource is the first element, so a caller that walks the result in order
/// finds the closest authority first.
///
/// # Errors
///
/// Whatever the lookup refuses, plus [`Unanswered::HierarchyUnbounded`] when the chain
/// repeats a resource or does not terminate within [`MAX_ANCESTRY_DEPTH`].
pub fn ancestry<L: ResourceLookup + ?Sized>(
    lookup: &L,
    organization: &OrganizationId,
    resource: &ResourceRef,
) -> Result<Vec<ResourceRef>, GraphError> {
    let mut chain: Vec<ResourceRef> = Vec::new();
    let mut next = Some(resource.clone());

    while let Some(current) = next {
        if chain.contains(&current) || chain.len() == MAX_ANCESTRY_DEPTH {
            return Err(GraphError::CouldNotAnswer(Unanswered::HierarchyUnbounded));
        }
        let placement = lookup.placement(organization, &current)?;
        chain.push(placement.resource);
        next = placement.parent;
    }

    Ok(chain)
}
