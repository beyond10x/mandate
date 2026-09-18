//! `mandate.graph.WriteRelationship`: subject admission, tenancy match, and the revision
//! the accepted write issues.
//!
//! The contract's denial text for this command (`graph.yaml:189`) names four refusals:
//! missing authority, an unresolved or non-member subject, a resource tenancy mismatch,
//! and a relationship the authorization model does not admit. Admission here covers the
//! two the graph itself can decide and delegates the subject to a port, because
//! `decision-blocker:subject-relations` is `story:graph-policy-adapter`'s.

use mandate_graph::port::{GraphError, MutationOutcome, Unanswered};
use mandate_graph::record::Relation;
use mandate_graph::relationship::{
    RelationshipWrite, RelationshipWriter, SubjectAdmission, Written, admit,
};
use mandate_graph::topology::{Placement, ResourceLookup};
use mandate_types::{
    Audience, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId, DenialReason,
    OrganizationId, PrincipalId, RelationId, ResourceId, ResourceRef, ResourceType, TeamId, Uuid,
    VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn subject() -> AuthoritySubject {
    AuthoritySubject::Principal(PrincipalId::new(uuid(2)))
}

fn team() -> AuthoritySubject {
    AuthoritySubject::Team(TeamId::new(uuid(3)))
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

struct Tree(Vec<(OrganizationId, ResourceRef)>);

impl ResourceLookup for Tree {
    fn placement(
        &self,
        organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        let row = self
            .0
            .iter()
            .find(|(_, candidate)| candidate == resource)
            .ok_or(GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved))?;

        if &row.0 != organization {
            return Err(GraphError::Denied(DenialReason::TenantMismatch));
        }

        Ok(Placement {
            resource: row.1.clone(),
            parent: None,
        })
    }
}

/// Admission stub: members are admitted, one subject stands for an adapter whose
/// membership source cannot answer, everything else is refused as a decision.
struct Members(Vec<AuthoritySubject>);

impl SubjectAdmission for Members {
    fn admits(
        &self,
        _organization: &OrganizationId,
        subject: &AuthoritySubject,
    ) -> Result<(), GraphError> {
        if self.0.contains(subject) {
            return Ok(());
        }
        if subject == &team() {
            // An adapter whose membership source is behind cannot decide at all; the
            // crate's one "not caught up" reason carries that.
            return Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
        }
        Err(GraphError::Denied(DenialReason::TenantMismatch))
    }
}

/// The write port implemented outside the crate.
struct AcceptingWriter;

impl RelationshipWriter for AcceptingWriter {
    fn write_relationship(&mut self, write: &RelationshipWrite<'_>) -> Result<Written, GraphError> {
        Ok(Written {
            relation: Relation::recorded(
                RelationId::new(uuid(4)),
                write.context.organization,
                write.subject.clone(),
                write.relation,
                write.resource.resource_id,
            ),
            revision: AuthzRevision::new("1"),
            outcome: MutationOutcome::Recorded,
        })
    }
}

fn write<'a>(
    context: &'a VerifiedContext,
    subject: &'a AuthoritySubject,
    resource: &'a ResourceRef,
    relation: &'a str,
) -> RelationshipWrite<'a> {
    RelationshipWrite {
        context,
        subject,
        resource,
        relation,
    }
}

#[test]
fn an_admitted_write_reports_the_resource_it_was_admitted_on() {
    let tree = Tree(vec![(organization(), resource(10))]);
    let members = Members(vec![subject()]);
    let context = context();
    let subject = subject();
    let resource = resource(10);

    let admitted = admit(
        &members,
        &tree,
        &write(&context, &subject, &resource, "viewer"),
    )
    .expect("an admitted write");

    assert_eq!(admitted, resource);
}

#[test]
fn a_relation_name_that_is_blank_is_denied() {
    let tree = Tree(vec![(organization(), resource(10))]);
    let members = Members(vec![subject()]);
    let context = context();
    let subject = subject();
    let resource = resource(10);

    for blank in ["", "   "] {
        let refusal = admit(
            &members,
            &tree,
            &write(&context, &subject, &resource, blank),
        )
        .expect_err("a blank relation name");

        assert!(refusal.is_denial());
        assert_eq!(refusal.denial_reason(), DenialReason::Denied);
    }
}

#[test]
fn a_relation_name_that_differs_from_its_trim_is_denied() {
    let tree = Tree(vec![(organization(), resource(10))]);
    let members = Members(vec![subject()]);
    let context = context();
    let subject = subject();
    let resource = resource(10);

    for padded in [" viewer", "viewer ", " viewer ", "viewer\t", "\nviewer"] {
        let refusal = admit(
            &members,
            &tree,
            &write(&context, &subject, &resource, padded),
        )
        .expect_err("a name that is not the name it prints as");

        assert!(refusal.is_denial());
        assert_eq!(refusal.denial_reason(), DenialReason::Denied);
    }

    admit(
        &members,
        &tree,
        &write(&context, &subject, &resource, "viewer"),
    )
    .expect("the trimmed name is the admitted one");
}

#[test]
fn a_resource_in_another_organization_is_denied_as_a_tenant_mismatch() {
    let tree = Tree(vec![(OrganizationId::new(uuid(9)), resource(10))]);
    let members = Members(vec![subject()]);
    let context = context();
    let subject = subject();
    let resource = resource(10);

    let refusal = admit(
        &members,
        &tree,
        &write(&context, &subject, &resource, "viewer"),
    )
    .expect_err("another tenant's resource");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
}

#[test]
fn a_subject_outside_the_organization_is_denied() {
    let tree = Tree(vec![(organization(), resource(10))]);
    let members = Members(Vec::new());
    let context = context();
    let subject = subject();
    let resource = resource(10);

    let refusal = admit(
        &members,
        &tree,
        &write(&context, &subject, &resource, "viewer"),
    )
    .expect_err("a non-member subject");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
}

#[test]
fn an_adapter_that_cannot_decide_membership_is_not_reported_as_a_denial() {
    let tree = Tree(vec![(organization(), resource(10))]);
    let members = Members(Vec::new());
    let context = context();
    let team = team();
    let resource = resource(10);

    let refusal = admit(
        &members,
        &tree,
        &write(&context, &team, &resource, "viewer"),
    )
    .expect_err("a membership source that cannot answer");

    assert!(refusal.is_could_not_answer());
    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
}

#[test]
fn the_write_port_issues_the_revision_the_command_declares_as_its_response() {
    let mut writer = AcceptingWriter;
    let context = context();
    let subject = subject();
    let resource = resource(10);

    let written = writer
        .write_relationship(&write(&context, &subject, &resource, "viewer"))
        .expect("the stub accepts");

    assert_eq!(written.revision, AuthzRevision::new("1"));
    assert_eq!(written.outcome, MutationOutcome::Recorded);
    assert_eq!(written.relation.relation, "viewer");
    assert_eq!(written.relation.subject, subject);
    assert_eq!(written.relation.resource_id, resource.resource_id);
    assert!(written.relation.active());
}
