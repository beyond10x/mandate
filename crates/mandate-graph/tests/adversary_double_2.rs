//! Adversarial cases, second pass, against `crates/mandate-graph/src/double.rs`.
//!
//! Each case drives the implementation against a document this unit wrote about itself:
//! the mutation-outcome contract (`port.rs:137-147`), the relation-name rule
//! (`relationship.rs:75-86`), the grant-role note (`double.rs:94-98`) and the subject
//! admission port's declared errors (`relationship.rs:50-62`), read against
//! `systems/mandate/domains/graph.yaml:153-193`.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphQuery, GraphRead};
use mandate_graph::record::Grant;
use mandate_graph::relationship::{RelationshipWrite, RelationshipWriter, SubjectAdmission};
use mandate_graph::revocation::RevisionView;
use mandate_graph::topology::{ResourceLookup, ResourceRegistry};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, CorrelationId, CredentialId, GrantId,
    OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
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

/// A grant of `role` over `over`, to the fixed subject, in the fixed organization.
fn grant(id: u8, over: &ResourceRef, role: &str) -> Grant {
    Grant::recorded(
        GrantId::new(uuid(id)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![over.clone()],
            space: None,
        },
        role,
    )
}

/// Whether the read port answers this organization's check for `relation` on `on`.
fn answers(graph: &GraphDouble, on: &ResourceRef, relation: &str) -> bool {
    let context = context();
    let subject = subject();
    graph
        .check(
            &GraphQuery {
                context: &context,
                subject: &subject,
                resource: on,
                relation,
            },
            &graph.observed(),
        )
        .is_ok()
}

/// `graph.yaml:169` declares the `denied` outcome of `mandate.graph.RegisterResource` as
/// "Caller lacks resource registration/ownership authority, **parent is unresolved or
/// belongs to another organization**, or hierarchy admission fails", and `double.rs:251-263`
/// decides exactly that for an identity it has not recorded.
///
/// For an identity it *has* recorded, `double.rs:234-249` returns before the parent
/// argument is looked at at all, so the same command with the same unresolved parent is
/// accepted. One declared refusal, two answers, decided by whether the id happens to be
/// recorded already.
#[test]
fn a_repeat_registration_naming_a_parent_that_does_not_resolve_is_still_refused() {
    let mut graph = GraphDouble::new();
    let context = context();
    let child = resource(11);

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    let unresolved = ResourceId::new(uuid(200));
    let fresh = resource(12);
    let refused_for_a_new_identity = graph
        .register_resource(&context, &fresh, Some(&unresolved))
        .is_err();

    let repeat = graph.register_resource(&context, &child, Some(&unresolved));

    assert!(
        repeat.is_err(),
        "graph.yaml:169 declares an unresolved parent a refusal of RegisterResource, and \
         double.rs:251-263 refuses it for an identity that is not recorded yet \
         (refused here: {refused_for_a_new_identity}); for a recorded identity the parent \
         argument is never looked at and the same call answered {repeat:?}",
    );
}

/// `port.rs:141-147` declares [`mandate_graph::port::MutationOutcome::AlreadyRecorded`] as
/// "The move was already recorded; this call changed nothing", resting it on
/// `docs/adr/0009-event-sourced-persistence.md`: repeating *a move already recorded*
/// records nothing further.
///
/// `double.rs:234-249` reports it for any second `RegisterResource` naming a recorded id,
/// including one that asks for a different parent — a move that was never recorded. The
/// parent is the inheritance edge `ancestry` walks (`topology.rs:8-10`), so the caller is
/// told its resource stands with no parent while the fold still answers the authority the
/// old parent carries, and `graph.yaml` declares no other command that could detach it.
#[test]
fn a_registration_reported_as_already_recorded_recorded_the_move_that_was_asked_for() {
    let mut graph = GraphDouble::new();
    let context = context();
    let parent = resource(10);
    let child = resource(11);

    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context, &parent, None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");
    graph.record_grant(grant(6, &parent, "editor"));

    assert!(
        answers(&graph, &child, "editor"),
        "the child inherits the parent's grant before anything is asked to change",
    );

    // The one command there is, asking for this resource with no parent.
    let repeat = graph.register_resource(&context, &child, None);
    let still_inherits = answers(&graph, &child, "editor");

    match repeat {
        // A refusal is a coherent answer: the move asked for is not the move recorded.
        Err(_) => {}
        Ok(registration) => assert_eq!(
            registration.parent, None,
            "port.rs:141-147 says AlreadyRecorded means the move was already recorded and \
             this call changed nothing; this call asked for {child:?} with no parent, was \
             answered {:?} naming parent {:?}, and the inherited authority the caller asked \
             to detach is still answered: {still_inherits}",
            registration.outcome, registration.parent,
        ),
    }
}

/// `relationship.rs:75-86` states the rule the write path enforces: a relation name is
/// admitted "only when it is exactly its own trim and is not empty", because two names that
/// print alike and compare unequal "would be two relations no reader could tell apart.
/// Refusing at admission is the closed direction and keeps the comparison in
/// [`crate::double`] exact."
///
/// `GraphRead::check` (`double.rs:443-463`) applies no such rule to `GraphQuery.relation`,
/// and `double.rs:94-98` accounts only for the check that asks for the *trimmed* name. A
/// check that asks for the untrimmed one — or for the empty string — is answered from a
/// grant carrying that same name, which `record_grant` takes as given
/// (`double.rs:99-105`). The write path refuses the name; the read path answers authority
/// for it.
#[test]
fn a_relation_name_the_write_path_refuses_is_not_answered_for_by_the_read_path() {
    let mut graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let on = resource(10);

    graph.admit_subject(organization(), subject.clone());
    graph
        .register_resource(&context, &on, None)
        .expect("the resource registers");

    for (id, name) in [(20_u8, ""), (21, "   "), (22, " editor ")] {
        let refused_by_the_write_path = graph
            .write_relationship(&RelationshipWrite {
                context: &context,
                subject: &subject,
                resource: &on,
                relation: name,
            })
            .is_err();
        assert!(
            refused_by_the_write_path,
            "relationship.rs:84-86 refuses {name:?} at admission",
        );

        graph.record_grant(grant(id, &on, name));

        assert!(
            !answers(&graph, &on, name),
            "the write path refuses the relation name {name:?} and the read path answers \
             authority for it: a grant recorded under that same name is an allow, so the \
             name the log cannot read back is the one the check is decided on",
        );
    }
}

/// `graph.yaml:21-32` declares `Deregistered` the terminal state of
/// `mandate.graph.Resource` and no transition back out of it, so the identity can never be
/// recorded again. `double.rs:238-240` is the only thing holding that, and nothing in
/// `crates/mandate-graph/tests/**` re-registers a deregistered identity.
///
/// This case is green here and red against the mutant: with those three lines deleted from
/// a copy of `double.rs` in the adversary's scratch directory, all 65 cases in the eight
/// existing graph test binaries still pass, and `register_resource` answers
/// `Ok(AlreadyRecorded)` for an identity `placement` refuses as
/// [`mandate_graph::port::Unanswered::ResourceUnresolved`].
#[test]
fn an_identity_that_was_deregistered_cannot_be_registered_again() {
    let mut graph = GraphDouble::new();
    let context = context();
    let identity = ResourceId::new(uuid(10));

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");
    graph
        .deregister_resource(&context, &identity)
        .expect("it deregisters");

    let again = graph.register_resource(&context, &resource(10), None);
    let resolves = graph.placement(&organization(), &resource(10)).is_ok();

    assert!(
        again.is_err(),
        "graph.yaml:21-32 makes Deregistered terminal with no transition back; the double \
         answered {again:?} for an identity whose reference resolves: {resolves}",
    );
}

/// `relationship.rs:50-62` declares both errors of [`SubjectAdmission::admits`]:
/// "[`GraphError::Denied`] when the subject resolves but is outside the organization;
/// [`GraphError::CouldNotAnswer`] with [`crate::port::Unanswered::SubjectUnresolved`] when
/// it does not resolve, which is an absence of knowledge and not a decision about the
/// caller."
///
/// `double.rs:323-335` answers the second for both. The only implementor of the port
/// produces the declared `Denied` on no input, so the distinction `port.rs:1-9` is built
/// around — a decision about the caller against an inability to decide — is not made here,
/// and a subject the double holds under another organization is reported to the caller as
/// `DenialReason::Unavailable`, an outage that is not happening.
#[test]
fn a_subject_the_double_holds_elsewhere_is_refused_as_a_decision_not_as_an_outage() {
    let mut graph = GraphDouble::new();
    graph.admit_subject(organization(), subject());

    let elsewhere = OrganizationId::new(uuid(9));
    let held_under_another_organization = graph
        .admits(&elsewhere, &subject())
        .expect_err("the subject is not a member here");
    let never_heard_of = graph
        .admits(
            &organization(),
            &AuthoritySubject::Principal(PrincipalId::new(uuid(3))),
        )
        .expect_err("this subject the double was told nothing about");

    assert!(
        held_under_another_organization.is_denial(),
        "relationship.rs:54-56 declares Denied for a subject that resolves but is outside \
         the organization; the double answered {held_under_another_organization:?} \
         (reported as {:?}), which is the same value it answers for a subject it has never \
         heard of ({never_heard_of:?})",
        held_under_another_organization.denial_reason(),
    );
}
