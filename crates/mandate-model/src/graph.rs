//! The `mandate.graph.Resource` projection and the fold that writes it.
//!
//! `systems/mandate/domains/graph.yaml` declares `Resource` and the two commands that
//! write it, `RegisterResource` and `DeregisterResource`. Their record halves are
//! [`Topology::register`] and [`Topology::deregister`]. `Relation` and `Grant` are
//! `mandate-graph`'s own projections (`docs/architecture/ownership.md`), and the graph
//! port is that crate's too; nothing here evaluates authorization.
//!
//! # The tenancy check
//!
//! `RegisterResource` denied: "Caller lacks resource registration/ownership authority,
//! parent is unresolved or belongs to another organization, or hierarchy admission
//! fails." A resource is recorded in the organization the verified context names — never
//! in one a selector supplies — and a parent is admitted only when it resolves inside
//! that same organization.
//!
//! # What the refusal does and does not hide
//!
//! One `denied` clause covers the unresolved parent and the parent in another
//! organization, and one error carries one [`mandate_types::DenialReason`]. So the
//! **reason** channel is closed: every refusal here is the same value, and a caller
//! cannot tell "no such resource" from "not yours" by reading it.
//!
//! The **accept/deny** channel is not, and claiming otherwise would be false.
//! [`Topology::register`] refuses an identity another organization already holds and
//! accepts a free one, so a caller that registers can discriminate over the whole
//! `ResourceId` space, one identity at a time. That is the contract's choice and not this
//! fold's to overturn: `graph.yaml` declares `mandate.graph.Resource`'s identity as
//! `id: mandate.core.ResourceId`, one global key, and keying per organization instead
//! would contradict the declared identity — and would admit two resources with one id,
//! which every relation and grant that references `resource_id` resolves through. What
//! bounds the channel is that a `ResourceId` is a UUID, so an enumerating caller has
//! nothing to enumerate.
//!
//! # `space_id` still has no writer; the rebuild no longer loses `resource_type`
//!
//! `Resource` declares `space_id`, and no command in `systems/mandate` carries a space
//! into it: `RegisterResource` takes `context`, `resource` and `parent`, and no other
//! command writes a resource. The projection carries the field because the entity
//! declares it; this fold leaves it absent rather than inventing an input the contract
//! does not declare. The compiled entity does not mark it required, so a rebuild that
//! leaves it absent is a rebuild of the whole declared record.
//!
//! `mandate.graph.ResourceRegistered` declared `context` and nothing else until
//! `story:event-payloads-for-folds` landed — not the identity, not the type, not the
//! parent — while the compiled entity marks `id`, `organization_id`, `resource_type` and
//! `state` required. It now declares `context`, `resource: mandate.core.ResourceRef` and
//! `parent`, and `ResourceRef` carries `resource_id` and `resource_type`. So `id` and
//! `resource_type` come off the registration itself, `organization_id` off
//! `context.organization`, and `state` off the declared `initial` and each outcome's
//! `moves`. Dropping this projection and replaying the log rebuilds it, exactly as
//! `crate::tenancy` now recovers its three `display_name`s, and
//! `docs/adr/0009-event-sourced-persistence.md`'s "derived, droppable, rebuildable" holds
//! for [`Topology`]. `crates/mandate-model/tests/adversary_tenancy_topology.rs`
//! `every_required_projection_field_is_carried_by_a_declared_event` decides it against
//! `generated/schema`, descending one level into a struct an event carries by value so
//! that the members of `resource` count as carried.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use mandate_types::{
    DenialReason, OrganizationId, ResourceId, ResourceRef, ResourceType, SpaceId, VerifiedContext,
};

use crate::tenancy::Tenancy;

/// `mandate.graph.Denied`: the fold refused, and wrote nothing.
///
/// Fail closed: no record, no state move and no partial topology follows a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Denied {
    /// The declared reason.
    pub reason: DenialReason,
}

impl Denied {
    /// The one refusal this fold produces.
    const fn refusal() -> Self {
        Self {
            reason: DenialReason::Denied,
        }
    }
}

/// `mandate.graph.Resource.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceState {
    /// The initial state.
    Recorded,
    /// The terminal state: the record is kept and stops resolving.
    Deregistered,
}

/// `mandate.graph.Resource`: a resource in the topology of one organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// The identity of this resource.
    pub id: ResourceId,
    /// The organization the resource belongs to.
    pub organization_id: OrganizationId,
    /// The declared resource type.
    pub resource_type: ResourceType,
    /// The resource this one resolves through, when it has one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub parent: Option<ResourceId>,
    /// The space the resource is bound to, when it is bound to one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub space_id: Option<SpaceId>,
    /// The recorded state.
    pub state: ResourceState,
}

/// The two declared `mandate.graph` resource event payloads.
///
/// `#[serde(untagged)]`, so a variant serializes as the bare payload object; see
/// [`crate::tenancy::TenancyEvent`], which carries the same shape for the ten tenancy
/// payloads.
///
/// `Registered` carries `resource_id` beside `resource`. The compiled
/// `mandate.graph.ResourceRegistered` on this branch declares `context`, `resource` and
/// an optional `parent` and no `resource_id`; the coordinator's ruling of 2026-09-19 for
/// `story:tenancy-graph-events` fixes the emitted payload at
/// `{context, resource_id, resource, parent}`, the shape it takes once
/// `story:contract-creates` adds `resource_id` as the `instance:` of `creates: Resource`.
/// `crates/mandate-model/tests/replay.rs` asserts that one event against the ruled set
/// and says so; the other eleven are asserted against their compiled `required` lists.
///
/// `parent` is optional and is therefore omitted when absent rather than written as
/// `null` — the rule for every optional either enum declares.
///
/// `Serialize` only, and not round-trippable; see [`crate::tenancy::TenancyEvent`] for
/// why the untagged encoding cannot be read back and where the envelope belongs.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResourceEvent {
    /// `mandate.graph.ResourceRegistered`.
    Registered {
        /// The caller's verified context; the resource is recorded in the organization it
        /// names.
        context: VerifiedContext,
        /// The identity `RegisterResource` returns.
        resource_id: ResourceId,
        /// The registration itself, which carries the identity and the declared type.
        resource: ResourceRef,
        /// The resource this one resolves through, when it has one.
        ///
        /// Absent rather than null: the compiled payload makes `parent` optional and
        /// types it `mandate.core.ResourceId`, a string, so `"parent": null` is a value
        /// the contract refuses. `skip_serializing_if` is the rule for every optional in
        /// both event enums, and `parent` is the only one either declares today.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<ResourceId>,
    },
    /// `mandate.graph.ResourceDeregistered`.
    Deregistered {
        /// The caller's verified context.
        context: VerifiedContext,
        /// The resource that stops resolving.
        id: ResourceId,
    },
}

impl ResourceEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub fn ess_name(&self) -> &'static str {
        match self {
            Self::Registered { .. } => "mandate.graph.ResourceRegistered",
            Self::Deregistered { .. } => "mandate.graph.ResourceDeregistered",
        }
    }
}

/// The fold of the `mandate.graph` resource events: the topology and what writes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Topology {
    resources: BTreeMap<ResourceId, Resource>,
}

impl Topology {
    /// An empty fold, before any event is applied.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The projection every event of a log has been applied to, from empty.
    ///
    /// The pair of [`crate::tenancy::Tenancy::fold`], and the rebuild
    /// `docs/adr/0009-event-sourced-persistence.md` requires of this projection too: it
    /// takes no verified context, no tenancy and no authority, because a log supplies
    /// none of them.
    #[must_use]
    pub fn fold(events: &[ResourceEvent]) -> Self {
        let mut fold = Self::new();
        for event in events {
            fold.apply(event);
        }
        fold
    }

    /// Write one declared event into the projection.
    ///
    /// **Total, and re-checks nothing**, exactly as [`crate::tenancy::Tenancy::apply`] is
    /// and for the same reason: a fold that refuses is not a rebuild. Every guard belongs
    /// to a `decide_*` half.
    ///
    /// The record's `organization_id` is read off the event's own `context`, its `id` and
    /// `resource_type` off the registration, and `space_id` stays absent because no
    /// command in `systems/mandate` carries a space into it — `ResourceRegistered` is
    /// `{context, resource_id, resource, parent}` and declares no `space_id`.
    pub fn apply(&mut self, event: &ResourceEvent) {
        match event {
            ResourceEvent::Registered {
                context,
                resource_id,
                resource,
                parent,
            } => {
                // Insert-if-absent: the first registration of an identity is the one that
                // stands, so a redelivered `ResourceRegistered` cannot return a record
                // from `Deregistered` to `Recorded`. The pair of
                // `crate::tenancy::Tenancy`'s five creating writes.
                self.resources
                    .entry(*resource_id)
                    .or_insert_with(|| Resource {
                        id: *resource_id,
                        organization_id: context.organization,
                        resource_type: resource.resource_type.clone(),
                        parent: *parent,
                        space_id: None,
                        state: ResourceState::Recorded,
                    });
            }
            ResourceEvent::Deregistered { id, .. } => {
                if let Some(record) = self.resources.get_mut(id) {
                    record.state = ResourceState::Deregistered;
                }
            }
        }
    }

    /// The decide half of `RegisterResource`: the declared event, or the refusal.
    ///
    /// The resource is recorded in the organization the verified context names. A named
    /// parent is admitted only when it resolves in that same organization. Nothing is
    /// written here; a command path appends the returned event and applies it.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization with no tenancy record or a closed one, an
    /// identity that is already registered, and a parent that does not resolve inside the
    /// verified organization — whether because it was never registered, because it has
    /// been deregistered, or because it belongs to another organization.
    pub fn decide_register(
        &self,
        tenancy: &Tenancy,
        context: &VerifiedContext,
        resource: &ResourceRef,
        parent: Option<ResourceId>,
    ) -> Result<ResourceEvent, Denied> {
        if !tenancy.admits(context.organization)
            || self.resources.contains_key(&resource.resource_id)
        {
            return Err(Denied::refusal());
        }
        if let Some(parent_id) = parent {
            let admitted = self
                .resources
                .get(&parent_id)
                .is_some_and(|record| Self::resolves_in(record, context.organization));
            if !admitted {
                return Err(Denied::refusal());
            }
        }
        Ok(ResourceEvent::Registered {
            context: context.clone(),
            resource_id: resource.resource_id,
            resource: resource.clone(),
            parent,
        })
    }

    /// The record half of `RegisterResource`: decide, apply, return the event a command
    /// path appends.
    ///
    /// # Errors
    ///
    /// Refuses a verified organization with no tenancy record or a closed one, an
    /// identity that is already registered, and a parent that does not resolve inside the
    /// verified organization.
    pub fn register(
        &mut self,
        tenancy: &Tenancy,
        context: &VerifiedContext,
        resource: &ResourceRef,
        parent: Option<ResourceId>,
    ) -> Result<ResourceEvent, Denied> {
        let event = self.decide_register(tenancy, context, resource, parent)?;
        self.apply(&event);
        Ok(event)
    }

    /// The decide half of `DeregisterResource`: the declared event, or the refusal.
    ///
    /// The security record is kept and stops resolving; no child, relation or grant is
    /// destroyed as a side effect.
    ///
    /// # Errors
    ///
    /// Refuses a resource that does not resolve inside the verified organization, one
    /// that has already been deregistered, and one a child still resolves through.
    pub fn decide_deregister(
        &self,
        context: &VerifiedContext,
        id: ResourceId,
    ) -> Result<ResourceEvent, Denied> {
        let resolves = self
            .resources
            .get(&id)
            .is_some_and(|record| Self::resolves_in(record, context.organization));
        if !resolves || !self.children(id).is_empty() {
            return Err(Denied::refusal());
        }
        Ok(ResourceEvent::Deregistered {
            context: context.clone(),
            id,
        })
    }

    /// The record half of `DeregisterResource`: decide, apply, return the event a command
    /// path appends.
    ///
    /// # Errors
    ///
    /// Refuses a resource that does not resolve inside the verified organization, one
    /// that has already been deregistered, and one a child still resolves through.
    pub fn deregister(
        &mut self,
        context: &VerifiedContext,
        id: ResourceId,
    ) -> Result<ResourceEvent, Denied> {
        let event = self.decide_deregister(context, id)?;
        self.apply(&event);
        Ok(event)
    }

    /// The resource as the verified caller can read it: recorded, and in the
    /// organization the context names.
    #[must_use]
    pub fn resolve(&self, context: &VerifiedContext, id: ResourceId) -> Option<&Resource> {
        self.resources
            .get(&id)
            .filter(|record| Self::resolves_in(record, context.organization))
    }

    /// The kept record, in whatever state and organization it holds.
    ///
    /// Nothing is destroyed, so a record outlives its resolution; reading one is not
    /// reading it as a caller.
    #[must_use]
    pub fn record(&self, id: ResourceId) -> Option<&Resource> {
        self.resources.get(&id)
    }

    /// The resources that still resolve through this one.
    ///
    /// A record-level read, like [`Topology::record`]: it answers for every organization,
    /// because `deregister` and a rebuild both need it to. A caller's read is
    /// [`Topology::resolve`]. Every child of a resource is in that resource's own
    /// organization, because [`Topology::register`] admits no parent outside it.
    #[must_use]
    pub fn children(&self, id: ResourceId) -> Vec<ResourceId> {
        self.resources
            .values()
            .filter(|record| record.parent == Some(id) && record.state == ResourceState::Recorded)
            .map(|record| record.id)
            .collect()
    }

    /// How many records the fold holds, in every state and every organization. Nothing is
    /// ever destroyed, so this count only grows.
    ///
    /// A fold-level read, like [`Topology::record`]; it is not a caller's read.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resources.len()
    }

    /// Whether the fold holds no record at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    fn resolves_in(record: &Resource, organization: OrganizationId) -> bool {
        record.organization_id == organization && record.state == ResourceState::Recorded
    }
}

impl mandate_types::PersistedValue for ResourceState {}

/// The credential boundary over the resource projection, asserted rather than described.
///
/// The same block `crate::tenancy` carries for its five, and the same reason: the record
/// is not declared through [`mandate_types::canonical_record`], so the check that macro
/// performs is written out here. Destructured without `..`, so a field added and not named
/// here does not compile.
const _: () = {
    fn persistable<T: mandate_types::PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_projection_field_is_persistable(resource: &Resource) {
        let Resource {
            id,
            organization_id,
            resource_type,
            parent,
            space_id,
            state,
        } = resource;
        persistable(id);
        persistable(organization_id);
        persistable(resource_type);
        persistable(parent);
        persistable(space_id);
        persistable(state);
    }
};
