//! The graph ports: what a caller may ask, and what a refusal means.
//!
//! Every command `systems/mandate/domains/graph.yaml` declares is reached through a port
//! in this module or in the module that owns its rule. A refusal is one of two things and
//! the caller can tell them apart: the graph decided against the caller
//! ([`GraphError::Denied`]), or the graph could not decide ([`GraphError::CouldNotAnswer`]).
//! Both fail closed — `docs/architecture/combined.md:55` requires that outages and
//! unknown resources deny — but only the first is a statement about the caller's
//! authority.

use core::fmt;

use mandate_types::{
    AuthoritySubject, AuthzRevision, DenialReason, OrganizationId, ResourceRef, VerifiedContext,
};

mod sealed {
    /// The seal on [`super::Revision`].
    pub trait Sealed {}

    impl Sealed for mandate_types::AuthzRevision {}
}

/// The revision vocabulary a graph port speaks.
///
/// Sealed on purpose: [`mandate_types::AuthzRevision`] is the only implementor, and no
/// crate outside this one can add another. An adapter maps its backend's own consistency
/// token onto the canonical revision before it crosses the port, which is the mapping
/// `story:graph-policy-adapter` owns.
pub trait Revision: sealed::Sealed + Clone + Eq + fmt::Debug {
    /// This value as the canonical revision.
    fn as_authz_revision(&self) -> &AuthzRevision;
}

impl Revision for AuthzRevision {
    fn as_authz_revision(&self) -> &Self {
        self
    }
}

/// What the graph is asked: a subject, a resource, a relation name and the context the
/// question is asked in.
///
/// The relation name is the bare string both `mandate.graph.Relation.relation` and
/// `mandate.graph.Grant.role` are declared as (`graph.yaml:58-59,96-97`). The graph answers
/// the bare name; expanding a name into the actions it carries is `mandate-policy`'s.
#[derive(Debug)]
pub struct GraphQuery<'a> {
    /// The context the question is asked in. Its organization is the tenancy bound.
    pub context: &'a VerifiedContext,
    /// The subject the question is about.
    pub subject: &'a AuthoritySubject,
    /// The resource the question is about.
    pub resource: &'a ResourceRef,
    /// The relation or role name asked for.
    pub relation: &'a str,
}

impl GraphQuery<'_> {
    /// The organization the question is bound to, taken from the verified context.
    #[must_use]
    pub const fn organization(&self) -> &OrganizationId {
        &self.context.organization
    }
}

/// An answer the graph stands behind, with the revision it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The revision the reader had reached when it answered.
    pub revision: AuthzRevision,
    /// The resource the authority was found on: the queried resource, or an ancestor.
    pub through: ResourceRef,
}

/// Why the graph could not decide.
///
/// Each of these is an absence of knowledge, never a statement about the caller's
/// authority, and each fails closed as [`DenialReason::Unavailable`]. Every one of them is
/// produced by some path of this crate; a reason no path can emit is a promise to the
/// reader that nothing keeps, which is why there is no variant here for an unresolvable
/// subject. Whether a subject is a member is always answered as a decision —
/// [`GraphError::Denied`] — because an absence would tell a caller that a subject it
/// cannot see exists somewhere else. An adapter whose membership source is behind has not
/// caught up, and says so with [`Unanswered::NotCaughtUp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unanswered {
    /// The reader has not applied the revision the caller required, or the source it
    /// answers a question from has not caught up far enough to answer it.
    NotCaughtUp,
    /// The resource does not resolve in the verified organization.
    ResourceUnresolved,
    /// The resource hierarchy did not terminate within [`crate::topology::MAX_ANCESTRY_DEPTH`].
    HierarchyUnbounded,
}

impl Unanswered {
    /// Every reason this crate can fail to answer for, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::NotCaughtUp,
        Self::ResourceUnresolved,
        Self::HierarchyUnbounded,
    ];
}

/// A graph refusal: a decision against the caller, or an inability to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// The graph decided against the caller, for the reason the contract declares.
    Denied(DenialReason),
    /// The graph could not decide.
    CouldNotAnswer(Unanswered),
}

impl GraphError {
    /// The declared reason the caller is told.
    ///
    /// An inability to decide is told as [`DenialReason::Unavailable`], so a refusal is
    /// never reported as an authority decision that was not made.
    #[must_use]
    pub const fn denial_reason(&self) -> DenialReason {
        match self {
            Self::Denied(reason) => *reason,
            Self::CouldNotAnswer(_) => DenialReason::Unavailable,
        }
    }

    /// Whether the graph decided against the caller.
    #[must_use]
    pub const fn is_denial(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// Whether the graph could not decide.
    #[must_use]
    pub const fn is_could_not_answer(&self) -> bool {
        matches!(self, Self::CouldNotAnswer(_))
    }
}

/// What a mutation did to the fold.
///
/// `docs/adr/0009-event-sourced-persistence.md` makes every state a fold over recorded
/// moves, so repeating a move already recorded is accepted and records nothing further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    /// The move was recorded by this call.
    Recorded,
    /// The move was already recorded; this call changed nothing.
    AlreadyRecorded,
}

impl MutationOutcome {
    /// Whether this call changed the fold.
    #[must_use]
    pub const fn changed(self) -> bool {
        matches!(self, Self::Recorded)
    }
}

/// The revision-bound read `story:check-api` calls.
///
/// The minimum revision is a freshness floor, not a snapshot: a reader that has applied
/// it answers from its current state and reports the revision it actually reached. A
/// reader that has not applied it refuses with [`Unanswered::NotCaughtUp`].
pub trait GraphRead {
    /// The revision vocabulary this reader answers in. Sealed to
    /// [`mandate_types::AuthzRevision`] by [`Revision`].
    type Revision: Revision;

    /// Whether the subject holds the named relation on the resource, directly or through
    /// an ancestor of it, at no less than `minimum`.
    ///
    /// # Errors
    ///
    /// [`GraphError::Denied`] when no authority is found or the tenancy does not match;
    /// [`GraphError::CouldNotAnswer`] when the reader cannot decide.
    fn check(
        &self,
        query: &GraphQuery<'_>,
        minimum: &Self::Revision,
    ) -> Result<Observed, GraphError>;
}
