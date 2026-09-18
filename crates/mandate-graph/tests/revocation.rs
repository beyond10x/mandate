//! The story's acceptance: a grant revoked at revision R, checked for inherited access at
//! minimum revision R, is denied.
//!
//! `.engineering/planning/story/graph-policy.md` states it as "Given a grant revoked at
//! revision R, when the graph/policy conformance suite checks inherited access at minimum
//! revision R, then the suite exits zero." The check runs against the `graph-double`,
//! which is the fold `docs/adr/0009-event-sourced-persistence.md` describes.
//!
//! The minimum revision is a freshness floor, not a snapshot. A reader that has applied it
//! answers from its current state; it never replays an earlier one. So a check at a
//! revision recorded before the revocation is still denied, and the two cases below say so
//! separately.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, MutationOutcome, Unanswered};
use mandate_graph::record::{Grant, GrantState, RelationState};
use mandate_graph::relationship::{RelationshipWrite, RelationshipWriter};
use mandate_graph::revocation::{RevisionView, RevocationWriter, require_revision};
use mandate_graph::topology::ResourceRegistry;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId,
    DenialReason, GrantId, OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType,
    Uuid, VerifiedContext,
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

/// A parent resource `10`, a child `11` under it, and the subject admitted.
fn seeded() -> GraphDouble {
    let mut graph = GraphDouble::new();
    let context = context();

    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    graph
}

/// A grant of `role` over the parent resource, so the child inherits it.
fn grant(role: &str) -> Grant {
    Grant::recorded(
        GrantId::new(uuid(6)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![resource(10)],
            space: None,
        },
        role,
    )
}

fn check(
    graph: &GraphDouble,
    context: &VerifiedContext,
    subject: &AuthoritySubject,
    resource: &ResourceRef,
    relation: &str,
    minimum: &AuthzRevision,
) -> Result<mandate_graph::port::Observed, GraphError> {
    graph.check(
        &GraphQuery {
            context,
            subject,
            resource,
            relation,
        },
        minimum,
    )
}

#[test]
fn a_revision_the_reader_has_not_applied_fails_closed() {
    let graph = seeded();

    let refusal = require_revision(&graph, &AuthzRevision::new("never-issued"))
        .expect_err("the reader never applied it");

    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
    assert!(!refusal.is_denial());
}

#[test]
fn a_revision_the_reader_has_applied_reports_the_revision_it_actually_reached() {
    let mut graph = seeded();
    let early = graph.observed();
    let later = graph.record_grant(grant("editor"));

    assert_eq!(
        require_revision(&graph, &early).expect("the reader applied it"),
        later
    );
    assert_ne!(early, later);
}

#[test]
fn inherited_access_is_allowed_at_the_revision_the_grant_was_recorded_at() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant("editor"));

    let observed = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &recorded,
    )
    .expect("the child inherits the parent's grant");

    assert_eq!(observed.revision, recorded);
    assert_eq!(observed.through, resource(10));
}

#[test]
fn inherited_access_is_denied_at_the_revision_the_grant_was_revoked_at() {
    let mut graph = seeded();
    graph.record_grant(grant("editor"));

    let revocation = graph
        .revoke_grant(&context(), &GrantId::new(uuid(6)))
        .expect("the grant revokes");

    assert_eq!(revocation.outcome, MutationOutcome::Recorded);
    assert_eq!(revocation.grant.state, GrantState::Revoked);

    let refusal = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &revocation.revision,
    )
    .expect_err("the revoked grant carries no authority");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
    assert!(refusal.is_denial());
    assert!(!refusal.is_could_not_answer());
}

#[test]
fn a_revoked_grant_is_denied_at_an_earlier_minimum_revision_too() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant("editor"));
    graph
        .revoke_grant(&context(), &GrantId::new(uuid(6)))
        .expect("the grant revokes");

    let refusal = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &recorded,
    )
    .expect_err("a floor is not a snapshot");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
}

#[test]
fn a_check_at_a_revision_the_reader_never_issued_is_not_told_as_a_denial() {
    let mut graph = seeded();
    graph.record_grant(grant("editor"));

    let refusal = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &AuthzRevision::new("never-issued"),
    )
    .expect_err("the reader has not caught up");

    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
    assert!(!refusal.is_denial());
}

#[test]
fn a_stale_reader_refuses_before_it_decides_anything() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant("editor"));

    let allowed = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &recorded,
    );
    let stale = check(
        &graph,
        &context(),
        &subject(),
        &resource(11),
        "editor",
        &AuthzRevision::new("never-issued"),
    );

    assert!(allowed.is_ok());
    assert_eq!(
        stale.expect_err("a stale reader answers nothing"),
        GraphError::CouldNotAnswer(Unanswered::NotCaughtUp)
    );
}

#[test]
fn removing_an_inherited_relation_denies_the_check_at_that_revision() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let parent = resource(10);

    let written = graph
        .write_relationship(&RelationshipWrite {
            context: &context,
            subject: &subject,
            resource: &parent,
            relation: "viewer",
        })
        .expect("the relationship writes");

    check(
        &graph,
        &context,
        &subject,
        &resource(11),
        "viewer",
        &written.revision,
    )
    .expect("the child inherits the parent's relation");

    let removal = graph
        .remove_relation(&context, &written.relation.id)
        .expect("the relation removes");

    assert_eq!(removal.relation.state, RelationState::Removed);

    let refusal = check(
        &graph,
        &context,
        &subject,
        &resource(11),
        "viewer",
        &removal.revision,
    )
    .expect_err("the removed relation carries no authority");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
}

#[test]
fn revoking_a_grant_twice_records_one_move_and_one_revision() {
    let mut graph = seeded();
    graph.record_grant(grant("editor"));

    let first = graph
        .revoke_grant(&context(), &GrantId::new(uuid(6)))
        .expect("the grant revokes");
    let second = graph
        .revoke_grant(&context(), &GrantId::new(uuid(6)))
        .expect("the repeat is accepted");

    assert_eq!(first.outcome, MutationOutcome::Recorded);
    assert_eq!(second.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(first.revision, second.revision);
}

#[test]
fn removing_a_relation_twice_records_one_move_and_one_revision() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let parent = resource(10);

    let written = graph
        .write_relationship(&RelationshipWrite {
            context: &context,
            subject: &subject,
            resource: &parent,
            relation: "viewer",
        })
        .expect("the relationship writes");

    let first = graph
        .remove_relation(&context, &written.relation.id)
        .expect("the relation removes");
    let second = graph
        .remove_relation(&context, &written.relation.id)
        .expect("the repeat is accepted");

    assert_eq!(first.outcome, MutationOutcome::Recorded);
    assert_eq!(second.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(first.revision, second.revision);
}

#[test]
fn a_revocation_in_another_organization_is_a_tenant_mismatch() {
    let mut graph = seeded();
    graph.record_grant(grant("editor"));

    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    let refusal = graph
        .revoke_grant(&elsewhere, &GrantId::new(uuid(6)))
        .expect_err("another tenant's grant");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));
}
