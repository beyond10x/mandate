//! An in-memory graph double: the fold, behind every port this crate declares.
//!
//! `docs/adr/0009-event-sourced-persistence.md` makes every read a fold over recorded
//! moves, so this is the same shape an adapter has and not a different one. It is `pub`
//! and publicly constructible because `story:check-api` builds its scenarios with it.
//!
//! What it does *not* know, it refuses. A revision the double never issued is
//! [`Unanswered::NotCaughtUp`], not a read, and fails closed as
//! [`mandate_types::DenialReason::Unavailable`].
//!
//! Membership is the one question it answers as a decision rather than as an absence.
//! Membership belongs to `mandate.tenancy` and this crate carries no edge to it, so a
//! subject the double has not been told about is refused — but with the same answer it
//! gives for a subject it holds under another organization, because telling those apart
//! would make the port an existence oracle for other tenants' subjects. See
//! [`crate::relationship::SubjectAdmission`].

use mandate_types::{
    AuthoritySubject, AuthzRevision, DenialReason, GrantId, OrganizationId, RelationId, ResourceId,
    ResourceRef, Uuid, VerifiedContext,
};

use crate::port::{GraphError, GraphQuery, GraphRead, MutationOutcome, Observed, Unanswered};
use crate::record::{Grant, Relation};
use crate::relationship::{
    RelationshipWrite, RelationshipWriter, SubjectAdmission, Written, admit, declared_name,
};
use crate::revocation::{Removal, RevisionView, Revocation, RevocationWriter, require_revision};
use crate::topology::{
    Deregistration, Placement, Registration, ResourceLookup, ResourceRegistry, ancestry,
};

/// The declared lifecycle of `mandate.graph.Resource` (`graph.yaml:21-32`), held privately
/// because the resource record itself is `story:tenancy-topology`'s and this crate reaches
/// it only through [`ResourceLookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResourceState {
    Recorded,
    Deregistered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceEntry {
    organization: OrganizationId,
    resource: ResourceRef,
    parent: Option<ResourceRef>,
    state: ResourceState,
}

/// An in-memory fold of the graph, behind every port this crate declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphDouble {
    issued: Vec<AuthzRevision>,
    resources: Vec<ResourceEntry>,
    relations: Vec<Relation>,
    grants: Vec<Grant>,
    members: Vec<(OrganizationId, AuthoritySubject)>,
}

impl Default for GraphDouble {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphDouble {
    /// An empty fold at its initial revision.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issued: vec![AuthzRevision::new("0")],
            resources: Vec::new(),
            relations: Vec::new(),
            grants: Vec::new(),
            members: Vec::new(),
        }
    }

    /// Tell the double that a subject is a member of an organization.
    ///
    /// Membership is `mandate.tenancy`'s and no command in `graph.yaml` establishes it, so
    /// the double is told rather than deciding. Until it is told, it refuses.
    pub fn admit_subject(&mut self, organization: OrganizationId, subject: AuthoritySubject) {
        if !self
            .members
            .iter()
            .any(|held| held == &(organization, subject.clone()))
        {
            self.members.push((organization, subject));
        }
    }

    /// Fold in a grant and return the revision it is observable at.
    ///
    /// `graph.yaml` declares `RevokeGrant` and no grant-creation command, so a grant enters
    /// the fold from outside it. A grant whose identity is already folded in is left as it
    /// stands and nothing is recorded.
    ///
    /// The role name is taken as given: there is no grant-creation port to refuse a name
    /// at. That is why the read path refuses it instead — [`GraphRead::check`] applies
    /// [`crate::relationship::declared_name`] to the name it is asked about, so a grant
    /// carrying a name the write path would refuse confers nothing to anybody. The
    /// relation name does have a port, and [`crate::relationship::admit`] refuses it
    /// there.
    pub fn record_grant(&mut self, grant: Grant) -> AuthzRevision {
        if self.grants.iter().any(|held| held.id == grant.id) {
            return self.observed();
        }
        self.grants.push(grant);
        self.advance()
    }

    /// Every relation the fold holds, in the order they were recorded.
    #[must_use]
    pub fn relations(&self) -> &[Relation] {
        &self.relations
    }

    /// Every grant the fold holds, in the order they were recorded.
    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    fn advance(&mut self) -> AuthzRevision {
        let next = AuthzRevision::new(self.issued.len().to_string());
        self.issued.push(next.clone());
        next
    }

    fn minted(tag: u8, ordinal: usize) -> Uuid {
        let mut bytes = [0_u8; 16];
        bytes[0] = tag;
        bytes[8..].copy_from_slice(&u64::try_from(ordinal).unwrap_or(u64::MAX).to_be_bytes());
        Uuid::from_bytes(bytes)
    }

    /// The one entry an identity has, if any.
    ///
    /// `graph.yaml:8-11` declares `mandate.graph.Resource`'s identity as `id: ResourceId`
    /// alone, with `resource_type` a field of the record. Every path here keys on that id
    /// and nothing else, so the write path and the deregister path cannot disagree about
    /// what one resource is.
    fn entry_by_id(&self, id: &ResourceId) -> Option<&ResourceEntry> {
        self.resources
            .iter()
            .find(|entry| &entry.resource.resource_id == id)
    }

    fn admitted(&self, organization: &OrganizationId, subject: &AuthoritySubject) -> bool {
        self.members
            .iter()
            .any(|(held, member)| held == organization && member == subject)
    }

    fn holds(
        &self,
        organization: &OrganizationId,
        subject: &AuthoritySubject,
        name: &str,
        resource: &ResourceRef,
    ) -> bool {
        let relation = self.relations.iter().any(|relation| {
            relation.active()
                // Defence in depth, and unreachable from outside the crate: no public
                // path can record a relation under another organization, because
                // `write_relationship` refuses a resource that resolves elsewhere before
                // anything is recorded. Kept so the predicate is right on its own terms.
                && &relation.organization_id == organization
                && &relation.subject == subject
                && relation.relation == name
                && relation.resource_id == resource.resource_id
        });

        relation
            || self.grants.iter().any(|grant| {
                grant.active()
                    && &grant.organization_id == organization
                    && &grant.subject == subject
                    && grant.role == name
                    && grant.scope.space.is_none()
                    // Keyed on the identity, like every other path here. A grant naming
                    // the right resource id under a stale `resource_type` names the same
                    // resource: the type is a field of the record, not part of what
                    // identifies it (`graph.yaml:8-11`).
                    && grant
                        .scope
                        .resources
                        .iter()
                        .any(|named| named.resource_id == resource.resource_id)
            })
    }
}

impl RevisionView for GraphDouble {
    fn caught_up_to(&self, minimum: &AuthzRevision) -> bool {
        self.issued.contains(minimum)
    }

    fn observed(&self) -> AuthzRevision {
        self.issued
            .last()
            .cloned()
            .unwrap_or_else(|| AuthzRevision::new("0"))
    }
}

impl ResourceLookup for GraphDouble {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        let entry = self
            .entry_by_id(&resource.resource_id)
            .ok_or(GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved))?;

        if &entry.organization != organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }
        if entry.state == ResourceState::Deregistered {
            return Err(GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved));
        }
        // The identity resolves, but not under the type this reference names, so this
        // reference resolves to nothing. An absence, not a decision about the caller.
        if entry.resource.resource_type != resource.resource_type {
            return Err(GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved));
        }

        Ok(Placement {
            resource: entry.resource.clone(),
            parent: entry.parent.clone(),
        })
    }
}

impl ResourceRegistry for GraphDouble {
    fn register_resource(
        &mut self,
        context: &VerifiedContext,
        resource: &ResourceRef,
        parent: Option<&ResourceId>,
    ) -> Result<Registration, GraphError> {
        // The parent is checked on every call, recorded identity or not. `graph.yaml:169`
        // declares an unresolved parent a refusal with no exception, and whether the id
        // happens to be recorded already is not one.
        let resolved = match parent {
            None => None,
            Some(id) => {
                let entry = self
                    .entry_by_id(id)
                    .filter(|entry| entry.state == ResourceState::Recorded)
                    .ok_or(GraphError::Denied(DenialReason::Denied))?;
                if entry.organization != context.organization {
                    return Err(GraphError::Denied(DenialReason::TenantMismatch));
                }
                Some(entry.resource.clone())
            }
        };

        // Keyed on the declared identity (`graph.yaml:8-11`), so one id is one record. A
        // repeat is the same move only when it asks for the record that stands: the
        // contract declares no retype and no reparent, so a repeat that disagrees on
        // either is asking for a move that cannot be recorded, and `AlreadyRecorded` would
        // report a change nobody made. The parent in particular is the inheritance edge
        // `ancestry` walks, and answering `Ok` to a detach that did not happen would tell
        // a caller its resource stands alone while the fold still answers the old parent's
        // authority.
        if let Some(entry) = self.entry_by_id(&resource.resource_id) {
            if entry.organization != context.organization {
                return Err(GraphError::Denied(DenialReason::TenantMismatch));
            }
            if entry.state == ResourceState::Deregistered
                || entry.resource.resource_type != resource.resource_type
                || entry.parent != resolved
            {
                return Err(GraphError::Denied(DenialReason::Denied));
            }
            return Ok(Registration {
                resource: resource.clone(),
                parent: parent.copied(),
                outcome: MutationOutcome::AlreadyRecorded,
                revision: self.observed(),
            });
        }

        self.resources.push(ResourceEntry {
            organization: context.organization,
            resource: resource.clone(),
            parent: resolved,
            state: ResourceState::Recorded,
        });

        Ok(Registration {
            resource: resource.clone(),
            parent: parent.copied(),
            outcome: MutationOutcome::Recorded,
            revision: self.advance(),
        })
    }

    fn deregister_resource(
        &mut self,
        context: &VerifiedContext,
        id: &ResourceId,
    ) -> Result<Deregistration, GraphError> {
        let entry = self
            .entry_by_id(id)
            .ok_or(GraphError::Denied(DenialReason::Denied))?;

        if entry.organization != context.organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }
        if entry.state == ResourceState::Deregistered {
            return Ok(Deregistration {
                id: *id,
                outcome: MutationOutcome::AlreadyRecorded,
                revision: self.observed(),
            });
        }

        let resource = entry.resource.clone();
        let resolving_child = self.resources.iter().any(|candidate| {
            candidate.state == ResourceState::Recorded
                && candidate.parent.as_ref() == Some(&resource)
        });
        if resolving_child {
            return Err(GraphError::Denied(DenialReason::Denied));
        }

        for candidate in &mut self.resources {
            if &candidate.resource.resource_id == id {
                candidate.state = ResourceState::Deregistered;
            }
        }

        Ok(Deregistration {
            id: *id,
            outcome: MutationOutcome::Recorded,
            revision: self.advance(),
        })
    }
}

impl SubjectAdmission for GraphDouble {
    fn admits(
        &self,
        organization: &OrganizationId,
        subject: &AuthoritySubject,
    ) -> Result<(), GraphError> {
        // One answer for "never heard of it" and for "held under another organization".
        // Telling them apart would make this an existence oracle for other tenants'
        // subjects; `DenialReason::Denied` discloses nothing beyond the refusal itself.
        if self.admitted(organization, subject) {
            Ok(())
        } else {
            Err(GraphError::Denied(DenialReason::Denied))
        }
    }
}

impl RelationshipWriter for GraphDouble {
    fn write_relationship(&mut self, write: &RelationshipWrite<'_>) -> Result<Written, GraphError> {
        let resource = {
            let view: &Self = self;
            admit(view, view, write)?
        };

        let organization = write.context.organization;
        let held = self.relations.iter().find(|relation| {
            relation.active()
                && relation.organization_id == organization
                && &relation.subject == write.subject
                && relation.relation == write.relation
                && relation.resource_id == resource.resource_id
        });
        if let Some(relation) = held {
            let relation = relation.clone();
            return Ok(Written {
                relation,
                revision: self.observed(),
                outcome: MutationOutcome::AlreadyRecorded,
            });
        }

        let relation = Relation::recorded(
            RelationId::new(Self::minted(b'r', self.relations.len())),
            organization,
            write.subject.clone(),
            write.relation,
            resource.resource_id,
        );
        self.relations.push(relation.clone());

        Ok(Written {
            relation,
            revision: self.advance(),
            outcome: MutationOutcome::Recorded,
        })
    }
}

impl RevocationWriter for GraphDouble {
    fn remove_relation(
        &mut self,
        context: &VerifiedContext,
        id: &RelationId,
    ) -> Result<Removal, GraphError> {
        let position = self
            .relations
            .iter()
            .position(|relation| &relation.id == id)
            .ok_or(GraphError::Denied(DenialReason::Denied))?;

        if self.relations[position].organization_id != context.organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }

        let outcome = self.relations[position].remove();
        let relation = self.relations[position].clone();
        let revision = if outcome.changed() {
            self.advance()
        } else {
            self.observed()
        };

        Ok(Removal {
            relation,
            outcome,
            revision,
        })
    }

    fn revoke_grant(
        &mut self,
        context: &VerifiedContext,
        id: &GrantId,
    ) -> Result<Revocation, GraphError> {
        let position = self
            .grants
            .iter()
            .position(|grant| &grant.id == id)
            .ok_or(GraphError::Denied(DenialReason::Denied))?;

        if self.grants[position].organization_id != context.organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }

        let outcome = self.grants[position].revoke();
        let grant = self.grants[position].clone();
        let revision = if outcome.changed() {
            self.advance()
        } else {
            self.observed()
        };

        Ok(Revocation {
            grant,
            outcome,
            revision,
        })
    }
}

impl GraphRead for GraphDouble {
    type Revision = AuthzRevision;

    fn check(
        &self,
        query: &GraphQuery<'_>,
        minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        let revision = require_revision(self, minimum)?;
        let organization = query.organization();
        // The read path refuses what the write path refuses. A name that is not its own
        // trim cannot be written (`crate::relationship::declared_name`), so answering
        // authority for one would decide a check on a name no log can read back — and a
        // grant, which enters the fold with no port to refuse it at, is the one way such a
        // name can be present at all. A decision, not an outage: the name is the caller's.
        if !declared_name(query.relation) {
            return Err(GraphError::Denied(DenialReason::Denied));
        }
        // Membership before authority, and refused as a decision: a subject this double
        // was never told about and one it holds elsewhere get one indistinguishable
        // answer. A stale reader is still refused first — it answers nothing at all, not
        // even about membership.
        self.admits(organization, query.subject)?;

        for through in ancestry(self, organization, query.resource)? {
            if self.holds(organization, query.subject, query.relation, &through) {
                return Ok(Observed { revision, through });
            }
        }

        Err(GraphError::Denied(DenialReason::Denied))
    }
}
