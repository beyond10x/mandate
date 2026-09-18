//! The in-memory graph double: a fold, publicly constructible, fail-closed on what it has
//! not caught up to.
//!
//! `docs/adr/0009-event-sourced-persistence.md` makes a read a fold over recorded moves,
//! so the double is the same shape as an adapter and not a different one. It is `pub`
//! because `story:check-api` builds scenarios with it.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, MutationOutcome, Unanswered};
use mandate_graph::record::Grant;
use mandate_graph::relationship::{RelationshipWrite, RelationshipWriter, SubjectAdmission};
use mandate_graph::revocation::RevisionView;
use mandate_graph::topology::{Placement, ResourceLookup, ResourceRegistry};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId,
    DenialReason, GrantId, OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType,
    TeamId, Uuid, VerifiedContext,
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

#[test]
fn the_double_is_constructible_from_outside_the_crate() {
    let made = GraphDouble::new();
    let defaulted = GraphDouble::default();

    assert_eq!(made.observed(), defaulted.observed());
}

#[test]
fn a_revision_the_double_never_issued_is_not_caught_up() {
    let graph = GraphDouble::new();

    assert!(graph.caught_up_to(&graph.observed()));
    assert!(!graph.caught_up_to(&AuthzRevision::new("never-issued")));
}

#[test]
fn every_recorded_move_advances_the_fold_by_one_revision() {
    let mut graph = GraphDouble::new();
    let initial = graph.observed();

    graph
        .register_resource(&context(), &resource(10), None)
        .expect("the parent registers");
    let after = graph.observed();

    assert_ne!(initial, after);
    assert!(graph.caught_up_to(&initial));
    assert!(graph.caught_up_to(&after));
}

#[test]
fn registering_the_same_resource_twice_records_one_move() {
    let mut graph = GraphDouble::new();
    let context = context();

    let first = graph
        .register_resource(&context, &resource(10), None)
        .expect("the first registration");
    let second = graph
        .register_resource(&context, &resource(10), None)
        .expect("the repeat is accepted");

    assert_eq!(first.outcome, MutationOutcome::Recorded);
    assert_eq!(second.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(first.revision, second.revision);
}

#[test]
fn a_parent_that_does_not_resolve_is_denied() {
    let mut graph = GraphDouble::new();

    let refusal = graph
        .register_resource(&context(), &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect_err("no such parent");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
}

#[test]
fn a_resource_registered_by_another_organization_is_a_tenant_mismatch() {
    let mut graph = GraphDouble::new();
    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    graph
        .register_resource(&elsewhere, &resource(10), None)
        .expect("the other tenant registers it");

    let refusal = graph
        .register_resource(&context(), &resource(10), None)
        .expect_err("this tenant does not own it");

    assert_eq!(refusal, GraphError::Denied(DenialReason::TenantMismatch));

    let lookup = graph
        .placement(&organization(), &resource(10))
        .expect_err("nor can it be looked up");

    assert_eq!(lookup, GraphError::Denied(DenialReason::TenantMismatch));
}

#[test]
fn a_deregistered_resource_stops_resolving_and_is_not_destroyed() {
    let mut graph = GraphDouble::new();
    let context = context();

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");

    assert_eq!(
        graph
            .placement(&organization(), &resource(10))
            .expect("it resolves"),
        Placement {
            resource: resource(10),
            parent: None,
        }
    );

    let first = graph
        .deregister_resource(&context, &ResourceId::new(uuid(10)))
        .expect("it deregisters");
    let second = graph
        .deregister_resource(&context, &ResourceId::new(uuid(10)))
        .expect("the repeat is accepted");

    assert_eq!(first.outcome, MutationOutcome::Recorded);
    assert_eq!(second.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(
        graph
            .placement(&organization(), &resource(10))
            .expect_err("it no longer resolves"),
        GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved)
    );
}

#[test]
fn a_resource_a_child_still_resolves_through_cannot_be_deregistered() {
    let mut graph = GraphDouble::new();
    let context = context();

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the child registers");

    let refusal = graph
        .deregister_resource(&context, &ResourceId::new(uuid(10)))
        .expect_err("a child still resolves through it");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
}

#[test]
fn a_subject_the_double_has_not_been_told_about_fails_closed() {
    let mut graph = GraphDouble::new();
    let context = context();

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");

    let refusal = graph
        .admits(&organization(), &subject())
        .expect_err("the double knows no membership of its own");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));

    let write = graph
        .write_relationship(&RelationshipWrite {
            context: &context,
            subject: &subject(),
            resource: &resource(10),
            relation: "viewer",
        })
        .expect_err("and refuses the write for the same reason");

    assert!(write.is_denial());
}

#[test]
fn an_admitted_subject_is_admitted_only_in_the_organization_it_was_admitted_to() {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());

    assert!(graph.admits(&organization(), &subject()).is_ok());
    assert!(
        graph
            .admits(&OrganizationId::new(uuid(9)), &subject())
            .is_err()
    );
    assert!(
        graph
            .admits(
                &organization(),
                &AuthoritySubject::Team(TeamId::new(uuid(3)))
            )
            .is_err()
    );
}

#[test]
fn writing_the_same_relationship_twice_records_one_move() {
    let mut graph = GraphDouble::new();
    let context = context();
    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");

    let write = RelationshipWrite {
        context: &context,
        subject: &subject(),
        resource: &resource(10),
        relation: "viewer",
    };

    let first = graph.write_relationship(&write).expect("the first write");
    let second = graph.write_relationship(&write).expect("the repeat");

    assert_eq!(first.outcome, MutationOutcome::Recorded);
    assert_eq!(second.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(first.revision, second.revision);
    assert_eq!(first.relation.id, second.relation.id);
}

/// A parent `10`, a child `11` under it, and the subject admitted — the shape every
/// authority case below asks against.
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

fn grant_of(
    organization: OrganizationId,
    subject: AuthoritySubject,
    role: &str,
    over: ResourceRef,
) -> Grant {
    Grant::recorded(
        GrantId::new(uuid(6)),
        organization,
        subject,
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![over],
            space: None,
        },
        role,
    )
}

fn answer(
    graph: &GraphDouble,
    subject: &AuthoritySubject,
    relation: &str,
    minimum: &AuthzRevision,
) -> Result<mandate_graph::port::Observed, GraphError> {
    let context = context();
    let child = resource(11);

    graph.check(
        &GraphQuery {
            context: &context,
            subject,
            resource: &child,
            relation,
        },
        minimum,
    )
}

/// `graph.yaml:8-11` declares `mandate.graph.Resource`'s identity as `id: ResourceId`
/// alone. Keying on that is what stops one identity becoming two records — but it does not
/// make every repeat the same move. An outcome that reports "changed nothing" has to have
/// been asked for nothing: a repeat that disagrees with the standing record on any declared
/// field is asking for a change the contract declares no command for, and is refused.
#[test]
fn registering_a_recorded_identity_under_another_type_is_refused() {
    let mut graph = GraphDouble::new();
    let context = context();
    let identity = ResourceId::new(uuid(10));
    let document = ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: identity,
    };
    let folder = ResourceRef {
        resource_type: ResourceType::new("folder"),
        resource_id: identity,
    };

    graph
        .register_resource(&context, &document, None)
        .expect("the identity registers");

    assert_eq!(
        graph
            .register_resource(&context, &folder, None)
            .expect_err("the contract declares no retype"),
        GraphError::Denied(DenialReason::Denied)
    );
    assert_eq!(
        graph
            .placement(&organization(), &document)
            .expect("the record that stands is untouched")
            .resource,
        document
    );
    assert_eq!(
        graph
            .placement(&organization(), &folder)
            .expect_err("and nothing was recorded under the other type"),
        GraphError::CouldNotAnswer(Unanswered::ResourceUnresolved)
    );
}

/// The parent is the inheritance edge `ancestry` walks, and `graph.yaml` declares no
/// reparent command. A repeat asking for a different parent is therefore asking for a move
/// that cannot be recorded, and reporting it `AlreadyRecorded` would tell the caller its
/// resource had been detached while the fold still answered the old parent's authority.
#[test]
fn a_repeat_registration_that_asks_for_a_different_parent_is_refused() {
    let mut graph = seeded();
    let context = context();
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(10)));

    assert_eq!(
        graph
            .register_resource(&context, &resource(11), None)
            .expect_err("the contract declares no detach"),
        GraphError::Denied(DenialReason::Denied)
    );
    graph
        .register_resource(&context, &resource(12), None)
        .expect("an unrelated resource registers");
    assert_eq!(
        graph
            .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(12))))
            .expect_err("nor any reparent"),
        GraphError::Denied(DenialReason::Denied)
    );

    answer(&graph, &subject(), "editor", &recorded)
        .expect("and the standing edge still carries the authority it always did");
}

/// A repeat that asks for exactly the record that stands is the same move, and reports the
/// move it was asked for.
#[test]
fn a_repeat_registration_that_asks_for_the_standing_record_is_already_recorded() {
    let mut graph = seeded();
    let context = context();

    let repeat = graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the same move");

    assert_eq!(repeat.outcome, MutationOutcome::AlreadyRecorded);
    assert_eq!(repeat.resource, resource(11));
    assert_eq!(repeat.parent, Some(ResourceId::new(uuid(10))));
}

/// The parent is checked on every call. Whether the id happens to be recorded already
/// decides nothing about a refusal `graph.yaml:169` declares without exception.
#[test]
fn a_parent_that_does_not_resolve_is_refused_whether_or_not_the_id_is_recorded() {
    let mut graph = seeded();
    let context = context();
    let absent = ResourceId::new(uuid(200));

    assert_eq!(
        graph
            .register_resource(&context, &resource(13), Some(&absent))
            .expect_err("a new identity"),
        GraphError::Denied(DenialReason::Denied)
    );
    assert_eq!(
        graph
            .register_resource(&context, &resource(11), Some(&absent))
            .expect_err("a recorded identity"),
        GraphError::Denied(DenialReason::Denied)
    );
}

/// `double.rs` claims every path keys on the resource id and nothing else. `holds` is one
/// of those paths: a grant naming the right identity carries its authority whatever type
/// its scope happens to spell, because the type is a field of the record and not part of
/// what identifies it.
#[test]
fn a_grant_naming_the_right_id_under_a_stale_type_still_confers() {
    let mut graph = seeded();
    let stale = ResourceRef {
        resource_type: ResourceType::new("folder"),
        resource_id: ResourceId::new(uuid(10)),
    };
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", stale));

    let observed = answer(&graph, &subject(), "editor", &recorded)
        .expect("the identity is what the grant names");

    assert_eq!(observed.through, resource(10));
}

/// The read path refuses the names the write path refuses. A name that is not its own trim
/// cannot be written, so answering authority for one would decide a check on a name no log
/// can read back.
#[test]
fn a_check_for_a_relation_name_the_write_path_refuses_is_a_denial() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(10)));

    for refused in ["", "   ", " editor ", "editor "] {
        assert_eq!(
            answer(&graph, &subject(), refused, &recorded)
                .expect_err("the write path refuses this name"),
            GraphError::Denied(DenialReason::Denied)
        );
    }

    answer(&graph, &subject(), "editor", &recorded).expect("the declared name is answered");
}

/// A subject the double was never told about and a subject it holds under another
/// organization are refused with one indistinguishable answer, and that answer is a
/// decision about the caller rather than an outage: an inability to answer would make the
/// port an existence oracle for subjects of other tenants.
#[test]
fn a_check_for_a_subject_the_double_was_not_told_about_is_denied() {
    let mut graph = GraphDouble::new();
    let context = context();
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the child registers");
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(10)));

    let refusal = answer(&graph, &subject(), "editor", &recorded)
        .expect_err("membership was never established");

    assert_eq!(refusal, GraphError::Denied(DenialReason::Denied));
    assert!(refusal.is_denial());

    let mut elsewhere = GraphDouble::new();
    elsewhere.admit_subject(OrganizationId::new(uuid(9)), subject());

    assert_eq!(
        elsewhere
            .admits(&organization(), &subject())
            .expect_err("held under another organization"),
        graph
            .admits(&organization(), &subject())
            .expect_err("never heard of"),
        "the two refusals must be indistinguishable to the caller"
    );
}

/// A stale reader answers nothing at all — not even about membership.
#[test]
fn a_stale_reader_is_refused_before_membership_is_consulted() {
    let mut graph = GraphDouble::new();
    let context = context();
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &resource(11), Some(&ResourceId::new(uuid(10))))
        .expect("the child registers");

    let refusal = answer(
        &graph,
        &subject(),
        "editor",
        &AuthzRevision::new("never-issued"),
    )
    .expect_err("the reader has not caught up");

    assert_eq!(refusal, GraphError::CouldNotAnswer(Unanswered::NotCaughtUp));
}

#[test]
fn a_grant_for_another_subject_answers_nothing() {
    let mut graph = seeded();
    let other = AuthoritySubject::Team(TeamId::new(uuid(3)));
    graph.admit_subject(organization(), other.clone());
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(10)));

    assert_eq!(
        answer(&graph, &other, "editor", &recorded).expect_err("another subject's grant"),
        GraphError::Denied(DenialReason::Denied)
    );
    answer(&graph, &subject(), "editor", &recorded).expect("its own subject is allowed");
}

#[test]
fn a_grant_under_another_name_answers_nothing() {
    let mut graph = seeded();
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(10)));

    assert_eq!(
        answer(&graph, &subject(), "viewer", &recorded).expect_err("another relation name"),
        GraphError::Denied(DenialReason::Denied)
    );
}

#[test]
fn a_grant_whose_scope_names_no_ancestor_answers_nothing() {
    let mut graph = seeded();
    let context = context();
    graph
        .register_resource(&context, &resource(12), None)
        .expect("an unrelated resource registers");
    let recorded = graph.record_grant(grant_of(organization(), subject(), "editor", resource(12)));

    assert_eq!(
        answer(&graph, &subject(), "editor", &recorded).expect_err("no ancestor is in scope"),
        GraphError::Denied(DenialReason::Denied)
    );
}

#[test]
fn a_relation_for_another_subject_or_another_name_answers_nothing() {
    let mut graph = seeded();
    let other = AuthoritySubject::Team(TeamId::new(uuid(3)));
    graph.admit_subject(organization(), other.clone());
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

    answer(&graph, &subject, "viewer", &written.revision).expect("its own subject and name");
    assert_eq!(
        answer(&graph, &other, "viewer", &written.revision).expect_err("another subject"),
        GraphError::Denied(DenialReason::Denied)
    );
    assert_eq!(
        answer(&graph, &subject, "editor", &written.revision).expect_err("another name"),
        GraphError::Denied(DenialReason::Denied)
    );
}
