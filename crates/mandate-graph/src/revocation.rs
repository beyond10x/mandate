//! `mandate.graph.RemoveRelation`, `mandate.graph.RevokeGrant`, and the revision-bound
//! read that makes a revocation observable.
//!
//! Both commands declare the same third refusal: "required graph revocation visibility
//! cannot be satisfied" (`graph.yaml:133,151`). That is what [`require_revision`] decides,
//! and it decides it *before* any authority is looked at, so a reader that has not caught
//! up never answers allowed and never answers denied — it answers that it could not tell.
//!
//! The minimum revision is a freshness floor, not a snapshot. `AuthzRevision` is an opaque
//! token in the contract (`mandate.core.AuthzRevision` is a bare string) and this crate
//! never orders two of them by comparing their text: a reader is caught up to a revision
//! only if it applied that exact revision. Mapping an engine's own consistency token onto
//! `AuthzRevision` is `story:graph-policy-adapter`'s.

use mandate_types::{AuthzRevision, GrantId, RelationId, VerifiedContext};

use crate::port::{GraphError, MutationOutcome, Unanswered};
use crate::record::{Grant, Relation};

/// What a reader can say about how far it has caught up.
pub trait RevisionView {
    /// Whether this reader has applied `minimum`.
    ///
    /// A reader that cannot establish this answers `false`: not knowing is the closed
    /// direction.
    fn caught_up_to(&self, minimum: &AuthzRevision) -> bool;

    /// The revision this reader has reached.
    fn observed(&self) -> AuthzRevision;
}

/// The revision the reader actually reached, or a refusal to answer.
///
/// # Errors
///
/// [`Unanswered::NotCaughtUp`] when the reader has not applied `minimum`. It fails closed
/// as [`mandate_types::DenialReason::Unavailable`] and is never reported as a denial.
pub fn require_revision<V: RevisionView + ?Sized>(
    view: &V,
    minimum: &AuthzRevision,
) -> Result<AuthzRevision, GraphError> {
    if view.caught_up_to(minimum) {
        Ok(view.observed())
    } else {
        Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp))
    }
}

/// What `mandate.graph.RemoveRelation` recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The relation projection as it now stands. It is kept, never destroyed.
    pub relation: Relation,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
    /// The fold position the graph reached.
    pub revision: AuthzRevision,
}

/// What `mandate.graph.RevokeGrant` recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The grant projection as it now stands. It is kept, never destroyed.
    pub grant: Grant,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
    /// The fold position the graph reached.
    pub revision: AuthzRevision,
}

/// `mandate.graph.RemoveRelation` and `mandate.graph.RevokeGrant`.
pub trait RevocationWriter {
    /// Remove a relation, keeping its record.
    ///
    /// Repeating a removal already recorded is accepted and records nothing further.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `graph.yaml:133`.
    fn remove_relation(
        &mut self,
        context: &VerifiedContext,
        id: &RelationId,
    ) -> Result<Removal, GraphError>;

    /// Revoke a grant, keeping its record.
    ///
    /// Repeating a revocation already recorded is accepted and records nothing further.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `graph.yaml:151`.
    fn revoke_grant(
        &mut self,
        context: &VerifiedContext,
        id: &GrantId,
    ) -> Result<Revocation, GraphError>;
}
