//! `mandate.graph.WriteRelationship`: subject admission, tenancy match, and the revision
//! an accepted write issues.
//!
//! The contract's denial text (`graph.yaml:189`) names four refusals. Two are the graph's
//! own and are decided here: a relation name that names nothing, and a resource that does
//! not belong to the verified organization. The third — whether the chosen principal or
//! team subject resolves and is a member — is behind [`SubjectAdmission`], because
//! `graph.yaml:1-4` requires a conditional foreign key and organization membership that
//! `decision-blocker:subject-relations` has not settled and `story:graph-policy-adapter`
//! carries. The fourth, admission by the authorization model, is `mandate-policy`'s.

use mandate_types::{
    AuthoritySubject, AuthzRevision, DenialReason, OrganizationId, ResourceRef, VerifiedContext,
};

use crate::port::{GraphError, MutationOutcome};
use crate::record::Relation;
use crate::topology::ResourceLookup;

/// The input `mandate.graph.WriteRelationship` declares (`graph.yaml:172-180`).
#[derive(Debug)]
pub struct RelationshipWrite<'a> {
    /// The context the write is made in. Its organization is the tenancy bound.
    pub context: &'a VerifiedContext,
    /// The tagged principal-or-team subject.
    pub subject: &'a AuthoritySubject,
    /// The resource the relation is on.
    pub resource: &'a ResourceRef,
    /// The relation name, an unconstrained string in the contract.
    pub relation: &'a str,
}

/// What an accepted `mandate.graph.WriteRelationship` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// The relation projection as it now stands.
    pub relation: Relation,
    /// The revision the command declares as its response (`graph.yaml:191-193`).
    pub revision: AuthzRevision,
    /// Whether this call recorded the move.
    pub outcome: MutationOutcome,
}

/// Whether a subject is admitted into an organization's graph.
///
/// The implementor owns the conditional foreign key and the membership check the contract
/// requires before admission; this crate owns neither `mandate.identity` nor
/// `mandate.tenancy`.
pub trait SubjectAdmission {
    /// Admit the subject, or refuse.
    ///
    /// A subject that is not a member of this organization is refused with one answer,
    /// whether the implementor has never heard of it or holds it under another
    /// organization. The two must be indistinguishable: an implementor that told them
    /// apart would be an existence oracle for other tenants' principals and teams, which
    /// is the isolation root the domain declares.
    ///
    /// # Errors
    ///
    /// [`GraphError::Denied`] when the subject is not a member — a decision about the
    /// caller, and the only answer a membership question has.
    /// [`GraphError::CouldNotAnswer`] with [`crate::port::Unanswered::NotCaughtUp`] when
    /// the implementor's membership source cannot answer at all; that is an absence of
    /// knowledge and not a decision.
    fn admits(
        &self,
        organization: &OrganizationId,
        subject: &AuthoritySubject,
    ) -> Result<(), GraphError>;
}

/// `mandate.graph.WriteRelationship`.
pub trait RelationshipWriter {
    /// Record a relationship and issue the revision it is observable at.
    ///
    /// # Errors
    ///
    /// The refusals the contract declares at `graph.yaml:189`.
    fn write_relationship(&mut self, write: &RelationshipWrite<'_>) -> Result<Written, GraphError>;
}

/// Whether a relation name is the name it prints as.
///
/// A name is admitted only when it is exactly its own trim and is not empty. The contract
/// declares the field as an unconstrained `String` and constrains nothing further, so the
/// rule imposed here is the narrow one that a stored name can be read back from a log
/// unambiguously: `" viewer "` and `"viewer"` print alike, compare unequal, and would be
/// two relations no reader could tell apart. Refusing at admission is the closed
/// direction and keeps the comparison in [`crate::double`] exact.
#[must_use]
pub fn declared_name(name: &str) -> bool {
    !name.is_empty() && name == name.trim()
}

/// Decide the two admissions the graph itself owns, and ask the port for the third.
///
/// Returns the resource the write was admitted on, as the lookup resolved it.
///
/// # Errors
///
/// [`GraphError::Denied`] for a relation name that is not [`declared_name`] or a tenancy
/// mismatch, plus whatever the lookup and the admission port refuse.
pub fn admit<A, L>(
    admission: &A,
    lookup: &L,
    write: &RelationshipWrite<'_>,
) -> Result<ResourceRef, GraphError>
where
    A: SubjectAdmission + ?Sized,
    L: ResourceLookup + ?Sized,
{
    if !declared_name(write.relation) {
        return Err(GraphError::Denied(DenialReason::Denied));
    }

    let organization = &write.context.organization;
    let placement = lookup.placement(organization, write.resource)?;
    admission.admits(organization, write.subject)?;

    Ok(placement.resource)
}
