//! `mandate.graph.Relation` and `mandate.graph.Grant` as projections of the graph fold.
//!
//! The entities and their lifecycles are declared in
//! `systems/mandate/domains/graph.yaml:49-116`. These are projections, not the record:
//! `docs/adr/0009-event-sourced-persistence.md` makes the events the record and every
//! read a fold, so a projection is derived, droppable and rebuildable. Plain structs, no
//! `serde`: neither this crate nor `mandate-policy` takes it.
//!
//! `mandate.graph.Resource` is deliberately absent. It is reached through
//! [`crate::topology::ResourceLookup`], never as a struct this crate owns.

use mandate_types::{
    AuthorityScope, AuthoritySubject, GrantId, OrganizationId, PersistedValue, RelationId,
    ResourceId,
};

use crate::port::MutationOutcome;

/// The declared lifecycle of `mandate.graph.Relation` (`graph.yaml:62-73`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationState {
    /// The declared initial state.
    Active,
    /// The declared terminal state, reached by `remove`.
    Removed,
}

impl RelationState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Active, Self::Removed];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Removed)
    }
}

impl PersistedValue for RelationState {}

/// The declared lifecycle of `mandate.graph.Grant` (`graph.yaml:98-109`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    /// The declared initial state.
    Active,
    /// The declared terminal state, reached by `revoke`.
    Revoked,
}

impl GrantState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Active, Self::Revoked];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

impl PersistedValue for GrantState {}

/// `mandate.graph.Relation`: a subject's named relation on a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    /// The declared identity.
    pub id: RelationId,
    /// The organization the relation is owned by.
    pub organization_id: OrganizationId,
    /// The tagged principal-or-team subject.
    pub subject: AuthoritySubject,
    /// The declared relation name, an unconstrained string (`graph.yaml:58-59`).
    pub relation: String,
    /// The resource the relation is on.
    pub resource_id: ResourceId,
    /// The folded lifecycle state.
    pub state: RelationState,
}

impl Relation {
    /// The projection of a recorded `mandate.graph.RelationshipWritten`.
    #[must_use]
    pub fn recorded(
        id: RelationId,
        organization_id: OrganizationId,
        subject: AuthoritySubject,
        relation: impl Into<String>,
        resource_id: ResourceId,
    ) -> Self {
        Self {
            id,
            organization_id,
            subject,
            relation: relation.into(),
            resource_id,
            state: RelationState::Active,
        }
    }

    /// Apply the declared `remove` transition.
    ///
    /// Repeating it is accepted and records nothing further.
    pub const fn remove(&mut self) -> MutationOutcome {
        match self.state {
            RelationState::Active => {
                self.state = RelationState::Removed;
                MutationOutcome::Recorded
            }
            RelationState::Removed => MutationOutcome::AlreadyRecorded,
        }
    }

    /// Whether the relation still resolves.
    #[must_use]
    pub const fn active(&self) -> bool {
        matches!(self.state, RelationState::Active)
    }
}

impl PersistedValue for Relation {}

/// `mandate.graph.Grant`: a subject's scoped authority under a named role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The declared identity.
    pub id: GrantId,
    /// The organization the grant is owned by.
    pub organization_id: OrganizationId,
    /// The tagged principal-or-team subject.
    pub subject: AuthoritySubject,
    /// The actions, resources and optional space the grant covers.
    pub scope: AuthorityScope,
    /// The declared role name, an unconstrained string (`graph.yaml:96-97`).
    pub role: String,
    /// The folded lifecycle state.
    pub state: GrantState,
}

impl Grant {
    /// The projection of a recorded grant.
    #[must_use]
    pub fn recorded(
        id: GrantId,
        organization_id: OrganizationId,
        subject: AuthoritySubject,
        scope: AuthorityScope,
        role: impl Into<String>,
    ) -> Self {
        Self {
            id,
            organization_id,
            subject,
            scope,
            role: role.into(),
            state: GrantState::Active,
        }
    }

    /// Apply the declared `revoke` transition.
    ///
    /// Repeating it is accepted and records nothing further.
    pub const fn revoke(&mut self) -> MutationOutcome {
        match self.state {
            GrantState::Active => {
                self.state = GrantState::Revoked;
                MutationOutcome::Recorded
            }
            GrantState::Revoked => MutationOutcome::AlreadyRecorded,
        }
    }

    /// Whether the grant still carries authority.
    #[must_use]
    pub const fn active(&self) -> bool {
        matches!(self.state, GrantState::Active)
    }
}

impl PersistedValue for Grant {}
