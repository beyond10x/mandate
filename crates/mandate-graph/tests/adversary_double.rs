//! Adversarial cases against `crates/mandate-graph/src/double.rs`.
//!
//! Each case drives the implementation against a document the unit wrote about itself:
//! the double's own module header (`double.rs:7-11`), the read port's declared refusal set
//! (`port.rs:76-90`), and `systems/mandate/domains/graph.yaml:8-11`.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphQuery, GraphRead, MutationOutcome};
use mandate_graph::record::Grant;
use mandate_graph::topology::{ResourceLookup, ResourceRegistry};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, CorrelationId, CredentialId, GrantId,
    OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType, SpaceId, Uuid,
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

/// A grant of `editor` over the parent resource `10`, so the child `11` inherits it.
fn grant() -> Grant {
    Grant::recorded(
        GrantId::new(uuid(6)),
        organization(),
        subject(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![resource(10)],
            space: None,
        },
        "editor",
    )
}

/// `double.rs:7-11` says of this double: "What it does *not* know, it refuses. Membership
/// belongs to `mandate.tenancy` and this crate carries no edge to it, so a subject the
/// double has not been told about is [`Unanswered::SubjectUnresolved`], not an admission."
/// `port.rs:86-87` declares `SubjectUnresolved` — "The subject does not resolve as a member
/// of the verified organization" — as one of the four reasons `GraphRead::check` can fail
/// to answer for.
///
/// `GraphDouble::check` never consults membership. `record_grant` is the only way a grant
/// enters the fold (`double.rs:90-92`) and it checks nothing either, so a grant recorded
/// for a subject the double was never told about is answered `Ok` — an allow, and the open
/// direction.
#[test]
fn a_grant_for_a_subject_the_double_was_never_told_about_is_not_an_allow() {
    let mut graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let child = resource(11);

    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    // The subject is never passed to `admit_subject`: the double has been told nothing
    // about its membership of this organization.
    let recorded = graph.record_grant(grant());

    let answer = graph.check(
        &GraphQuery {
            context: &context,
            subject: &subject,
            resource: &child,
            relation: "editor",
        },
        &recorded,
    );

    assert!(
        answer.is_err(),
        "double.rs:7-9 promises a subject the double was never told about is refused, \
         and port.rs:86-87 declares SubjectUnresolved as a reason check cannot answer; \
         the read path consults no membership at all and answered {answer:?}",
    );
}

/// `graph.yaml:8-11` declares `mandate.graph.Resource`'s identity as a single
/// `id: mandate.core.ResourceId`; `resource_type` is a field of the record, not part of the
/// identity, and `DeregisterResource` takes `instance: id` (`graph.yaml:196-206`).
///
/// The double keys the write path by the whole `ResourceRef` (`double.rs:126-130`) and the
/// deregister path by the `ResourceId` alone (`double.rs:289-293`). The two disagree: the
/// second registration of one identity under another type is reported `Recorded`, a second
/// record, and one `DeregisterResource` then moves both records while reporting one move —
/// a side effect `topology.rs:72-73` and `graph.yaml:205` both say does not happen.
///
/// Whichever of the two is right, they cannot both be.
#[test]
fn a_resource_is_identified_the_same_way_by_the_write_path_and_the_deregister_path() {
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
    // Coordinator ruling at integration: a repeat registration that disagrees with the
    // standing record on any declared field is refused, so `Err` is one of the two
    // consistent answers here; the assertion below is unchanged.
    let second = graph.register_resource(&context, &folder, None);

    let write_path_holds_two_records =
        matches!(&second, Ok(registration) if registration.outcome == MutationOutcome::Recorded);

    let deregistration = graph
        .deregister_resource(&context, &identity)
        .expect("the identity deregisters");
    let deregister_path_moved_both = graph.placement(&organization(), &document).is_err()
        && graph.placement(&organization(), &folder).is_err();

    assert!(
        !(write_path_holds_two_records && deregister_path_moved_both),
        "the write path recorded two records for one declared identity ({:?}) and the \
         deregister path then moved both of them in one reported move ({:?}); \
         graph.yaml:8-11 identifies a Resource by its ResourceId alone",
        second.as_ref().map(|registration| registration.outcome),
        deregistration.outcome,
    );
}

/// A grant confined to a space contributes nothing (`double.rs:165`), which is what the
/// implementor reports as fail-closed. No case in `crates/mandate-graph/tests/**`
/// constructs `AuthorityScope.space` as anything but `None`, so deleting that guard leaves
/// all 52 of them green. This case is red against a copy of `double.rs` with the guard
/// removed.
#[test]
fn a_space_confined_grant_contributes_no_authority() {
    let mut graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let child = resource(11);

    graph.admit_subject(organization(), subject.clone());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    let confined = Grant::recorded(
        GrantId::new(uuid(6)),
        organization(),
        subject.clone(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![resource(10)],
            space: Some(SpaceId::new(uuid(8))),
        },
        "editor",
    );
    let recorded = graph.record_grant(confined);

    let answer = graph.check(
        &GraphQuery {
            context: &context,
            subject: &subject,
            resource: &child,
            relation: "editor",
        },
        &recorded,
    );

    assert!(
        answer.is_err(),
        "a grant confined to a space carries no authority outside it; \
         double.rs:165 is the only thing refusing it and nothing else asserts it: \
         {answer:?}",
    );
}

/// A grant owned by another organization answers nothing in this one (`double.rs:163`).
/// Deleting that guard — and the matching one for relations at `double.rs:153` — also
/// leaves all 52 existing cases green: the tenancy cases in the suite are all refused
/// earlier, by `placement` or by `admits`, and none of them reaches `holds`.
#[test]
fn a_grant_owned_by_another_organization_answers_nothing_in_this_one() {
    let mut graph = GraphDouble::new();
    let context = context();
    let subject = subject();
    let child = resource(11);

    graph.admit_subject(organization(), subject.clone());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers under it");

    let elsewhere = Grant::recorded(
        GrantId::new(uuid(6)),
        OrganizationId::new(uuid(9)),
        subject.clone(),
        AuthorityScope {
            actions: vec![Action::new("read")],
            resources: vec![resource(10)],
            space: None,
        },
        "editor",
    );
    let recorded = graph.record_grant(elsewhere);

    let answer = graph.check(
        &GraphQuery {
            context: &context,
            subject: &subject,
            resource: &child,
            relation: "editor",
        },
        &recorded,
    );

    assert!(
        answer.is_err(),
        "another organization's grant must not answer this organization's check: \
         {answer:?}",
    );
}
