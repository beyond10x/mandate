//! `mandate.policy.Policy` and `mandate.policy.AuthorizationModel` as projections.
//!
//! The entities and their lifecycles are declared in
//! `systems/mandate/domains/policy.yaml:6-63`. Its header states what the projection has
//! to keep: a published version is immutable, a changed policy is a new version record,
//! the previous one is superseded, and no superseded record is ever reactivated or
//! deleted — so every decision stays attributable to the exact version that made it.
//!
//! These are projections, not the record: `docs/adr/0009-event-sourced-persistence.md`
//! makes the events the record and every read a fold. Plain structs, no `serde`.

use mandate_types::{
    AuthorizationModelId, OrganizationId, PersistedValue, PolicyId, PolicyVersion,
};

use crate::port::MutationOutcome;

/// The declared lifecycle of `mandate.policy.Policy` (`policy.yaml:17-28`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyState {
    /// The declared initial state: this is the current version.
    Recorded,
    /// The declared terminal state: a later version is current and this one is kept for
    /// attribution.
    Superseded,
}

impl PolicyState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Superseded];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Superseded)
    }
}

impl PersistedValue for PolicyState {}

/// The declared lifecycle of `mandate.policy.AuthorizationModel` (`policy.yaml:46-57`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationModelState {
    /// The declared initial state: this is the current version.
    Recorded,
    /// The declared terminal state: a later version is current and this one is kept for
    /// attribution.
    Superseded,
}

impl AuthorizationModelState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Superseded];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Superseded)
    }
}

impl PersistedValue for AuthorizationModelState {}

/// `mandate.policy.Policy`: one published, immutable policy version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// The declared identity.
    pub id: PolicyId,
    /// The organization the policy governs.
    pub organization_id: OrganizationId,
    /// The published version.
    pub version: PolicyVersion,
    /// The policy source, kept after superseding so decisions stay attributable.
    pub source: String,
    /// The folded lifecycle state.
    pub state: PolicyState,
}

impl Policy {
    /// The projection of a recorded policy version.
    #[must_use]
    pub fn recorded(
        id: PolicyId,
        organization_id: OrganizationId,
        version: PolicyVersion,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id,
            organization_id,
            version,
            source: source.into(),
            state: PolicyState::Recorded,
        }
    }

    /// Apply the declared `supersede` transition.
    ///
    /// Repeating it is accepted and records nothing further. Nothing is deleted: a
    /// rollback is a new version record carrying an earlier source, never a revival of
    /// this one.
    pub const fn supersede(&mut self) -> MutationOutcome {
        match self.state {
            PolicyState::Recorded => {
                self.state = PolicyState::Superseded;
                MutationOutcome::Recorded
            }
            PolicyState::Superseded => MutationOutcome::AlreadyRecorded,
        }
    }

    /// Whether this is the current version.
    #[must_use]
    pub const fn current(&self) -> bool {
        matches!(self.state, PolicyState::Recorded)
    }
}

impl PersistedValue for Policy {}

/// `mandate.policy.AuthorizationModel`: one published, immutable model version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationModel {
    /// The declared identity.
    pub id: AuthorizationModelId,
    /// The organization the model governs.
    pub organization_id: OrganizationId,
    /// The published version.
    pub version: PolicyVersion,
    /// The model schema, kept after superseding so decisions stay attributable.
    pub schema: String,
    /// The folded lifecycle state.
    pub state: AuthorizationModelState,
}

impl AuthorizationModel {
    /// The projection of a recorded model version.
    #[must_use]
    pub fn recorded(
        id: AuthorizationModelId,
        organization_id: OrganizationId,
        version: PolicyVersion,
        schema: impl Into<String>,
    ) -> Self {
        Self {
            id,
            organization_id,
            version,
            schema: schema.into(),
            state: AuthorizationModelState::Recorded,
        }
    }

    /// Apply the declared `supersede` transition.
    ///
    /// Repeating it is accepted and records nothing further. A breaking change is a new
    /// model version with its own migration; no superseded model is reactivated.
    pub const fn supersede(&mut self) -> MutationOutcome {
        match self.state {
            AuthorizationModelState::Recorded => {
                self.state = AuthorizationModelState::Superseded;
                MutationOutcome::Recorded
            }
            AuthorizationModelState::Superseded => MutationOutcome::AlreadyRecorded,
        }
    }

    /// Whether this is the current version.
    #[must_use]
    pub const fn current(&self) -> bool {
        matches!(self.state, AuthorizationModelState::Recorded)
    }
}

impl PersistedValue for AuthorizationModel {}
