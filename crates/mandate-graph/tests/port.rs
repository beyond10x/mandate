//! The graph port vocabulary: what a caller asks, and what a refusal means.
//!
//! `story:check-api` needs a denial told apart from an inability to answer
//! (`.engineering/planning/story/graph-policy.md`, "What `story:check-api` needs"), and
//! `docs/architecture/combined.md:55` requires the inability to fail closed.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{
    GraphError, GraphQuery, GraphRead, MutationOutcome, Observed, Unanswered,
};
use mandate_graph::topology::{Placement, ResourceLookup, ResourceRegistry, ancestry};
use mandate_types::{
    Audience, AuthoritySubject, AuthzRevision, CorrelationId, CredentialId, DenialReason,
    OrganizationId, PrincipalId, ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn context() -> VerifiedContext {
    VerifiedContext {
        subject: PrincipalId::new(uuid(2)),
        actor: None,
        organization: OrganizationId::new(uuid(1)),
        audience: Audience::new("mandate"),
        credential: CredentialId::new(uuid(7)),
        delegation: None,
        execution: None,
        correlation: CorrelationId::new("correlation"),
    }
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(5)),
    }
}

fn unanswered_index(reason: Unanswered) -> usize {
    match reason {
        Unanswered::NotCaughtUp => 0,
        Unanswered::ResourceUnresolved => 1,
        Unanswered::HierarchyUnbounded => 2,
    }
}

#[test]
fn a_denial_carries_the_reason_the_contract_declares() {
    for reason in DenialReason::VARIANTS {
        let error = GraphError::Denied(*reason);

        assert_eq!(error.denial_reason(), *reason);
        assert!(error.is_denial());
        assert!(!error.is_could_not_answer());
    }
}

#[test]
fn an_inability_to_answer_is_not_a_denial() {
    let error = GraphError::CouldNotAnswer(Unanswered::NotCaughtUp);

    assert!(!error.is_denial());
    assert!(error.is_could_not_answer());
}

#[test]
fn every_inability_to_answer_fails_closed_as_unavailable() {
    for reason in Unanswered::ALL {
        let error = GraphError::CouldNotAnswer(*reason);

        assert_eq!(error.denial_reason(), DenialReason::Unavailable);
        assert!(error.is_could_not_answer());
    }
}

#[test]
fn every_inability_to_answer_is_listed() {
    assert_eq!(Unanswered::ALL.len(), 3);

    for (position, reason) in Unanswered::ALL.iter().enumerate() {
        assert_eq!(unanswered_index(*reason), position);
    }
}

#[test]
fn a_query_carries_the_five_things_the_check_is_asked() {
    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let resource = resource();
    let query = GraphQuery {
        context: &context,
        subject: &subject,
        resource: &resource,
        relation: "viewer",
    };

    assert_eq!(query.organization(), &OrganizationId::new(uuid(1)));
    assert_eq!(query.subject, &subject);
    assert_eq!(query.resource, &resource);
    assert_eq!(query.relation, "viewer");
}

#[test]
fn an_answer_carries_the_revision_it_was_read_at() {
    let observed = Observed {
        revision: AuthzRevision::new("3"),
        through: resource(),
    };

    assert_eq!(observed.revision, AuthzRevision::new("3"));
    assert_eq!(observed.through, resource());
}

#[test]
fn a_repeat_of_a_recorded_move_changes_nothing() {
    assert!(MutationOutcome::Recorded.changed());
    assert!(!MutationOutcome::AlreadyRecorded.changed());
}

/// A lookup whose chain never terminates, so `ancestry` has to bound it.
struct Loop;

impl ResourceLookup for Loop {
    fn placement(
        &self,
        _organization: &OrganizationId,
        resource: &ResourceRef,
    ) -> Result<Placement, GraphError> {
        Ok(Placement {
            resource: resource.clone(),
            parent: Some(resource.clone()),
        })
    }
}

/// Every reason [`Unanswered`] declares must be one some path in this crate actually
/// produces. A declared refusal no code can emit is a promise to the reader that nothing
/// keeps — which is exactly what `SubjectUnresolved` was before this round.
///
/// This case is the check, not a list: it drives each reason out of the public API and
/// asserts the set it collected is [`Unanswered::ALL`]. A new variant with no producing
/// path fails here — and a variant that stopped having one is why `SubjectUnresolved` was
/// removed in this round rather than left declared and unreachable.
#[test]
fn every_declared_reason_the_graph_cannot_answer_for_is_produced_by_some_path() {
    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let parent = ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    };
    let child = ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(11)),
    };

    let mut graph = GraphDouble::new();
    graph
        .register_resource(&context, &parent, None)
        .expect("the parent registers");
    graph
        .register_resource(&context, &child, Some(&ResourceId::new(uuid(10))))
        .expect("the child registers");

    let query = GraphQuery {
        context: &context,
        subject: &subject,
        resource: &child,
        relation: "editor",
    };

    let produced = [
        // NotCaughtUp: a revision the reader never issued.
        graph.check(&query, &AuthzRevision::new("never-issued")),
        // ResourceUnresolved: a reference that resolves to nothing.
        graph
            .placement(&context.organization, &resource())
            .map(|_| Observed {
                revision: AuthzRevision::new("0"),
                through: resource(),
            }),
        // HierarchyUnbounded: a chain that does not terminate.
        ancestry(&Loop, &context.organization, &parent).map(|_| Observed {
            revision: AuthzRevision::new("0"),
            through: resource(),
        }),
    ]
    .into_iter()
    .map(
        |outcome| match outcome.expect_err("each of these refuses") {
            GraphError::CouldNotAnswer(reason) => reason,
            GraphError::Denied(reason) => panic!("expected an inability to answer, got {reason:?}"),
        },
    )
    .collect::<Vec<_>>();

    assert_eq!(produced, Unanswered::ALL.to_vec());
}
