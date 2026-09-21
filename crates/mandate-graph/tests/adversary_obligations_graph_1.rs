//! Adversary pass 1 on `story:obligations-graph`: the registry's `path: real` rows, driven
//! against the commands they are rows about.
//!
//! `contracts/obligations/README.md` defines `real` as "the crate's own shipped decision
//! path — a handler, a fold, a validator — **reached with a mismatched or malformed
//! input**", and defines the whole document as "every external denial an **implemented
//! command** can produce, mapped to the real-path test that decides it". A row is therefore
//! a claim about a *command*: drive that command under the clause's condition and the
//! clause's denial comes back.
//!
//! Every case below drives the command the row is filed under, under the condition the
//! clause names, and asserts the clause's denial. None of them is a new rule: each
//! assertion is the row's own claim read back.
//!
//! The clause text in each case is the verbatim `condition.cause` fragment
//! `generated/ir/system.json` declares and `contracts/obligations/graph.json` carries.

use mandate_graph::double::GraphDouble;
use mandate_graph::port::{GraphError, GraphQuery, GraphRead, MutationOutcome, Unanswered};
use mandate_graph::record::{Grant, GrantState, RelationState};
use mandate_graph::relationship::{RelationshipWrite, RelationshipWriter, admit};
use mandate_graph::revocation::{RevisionView, RevocationWriter, require_revision};
use mandate_graph::topology::{MAX_ANCESTRY_DEPTH, ResourceRegistry};
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

/// A resource `10` recorded and the subject admitted: the ordinary state a caller is in.
fn seeded() -> GraphDouble {
    let mut graph = GraphDouble::new();
    let context = context();

    graph.admit_subject(organization(), subject());
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");

    graph
}

/// A grant of `role` over resource `10`.
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

/// `mandate.graph.RemoveRelation`, clause "required graph revocation visibility cannot be
/// satisfied", which `contracts/obligations/graph.json` counts in `real_covered`.
///
/// The row names a case that calls the free function
/// [`mandate_graph::revocation::require_revision`] and never calls the command. This case
/// calls the command, with the reader in exactly the state that function refuses for — it
/// has not applied the revision the removal must be visible at — and asks for the clause's
/// denial.
///
/// `RevocationWriter::remove_relation` takes `(&VerifiedContext, &RelationId)` and no
/// minimum revision, so no caller can state the visibility the clause is about, and no
/// implementation of the trait in the workspace consults a [`RevisionView`]. The command
/// records the removal instead.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-graph-adversary-1` F1): the
/// removal is recorded. The registry row now defers the clause to `story:graph-policy-adapter`,
/// which owns the writer that would consult the view; the assertion flips there.
#[test]
fn remove_relation_does_not_refuse_when_the_required_revocation_visibility_cannot_be_satisfied() {
    let mut graph = seeded();
    let context = context();
    let subject = subject();
    let held = resource(10);
    let written = graph
        .write_relationship(&write(&context, &subject, &held, "viewer"))
        .expect("the relationship writes");
    let before = graph.observed();

    // The reader is in the state the bound case constructs: the revision the removal must be
    // observable at is one it has not applied, and the crate's own visibility rule refuses.
    let required = AuthzRevision::new("never-issued");
    assert!(
        !graph.caught_up_to(&required),
        "the reader has not applied the revision the removal must be visible at"
    );
    assert_eq!(
        require_revision(&graph, &required),
        Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp)),
        "the free function the registry names as this clause's decider does refuse here"
    );

    let outcome = graph.remove_relation(&context, &written.relation.id);

    // What the command did instead: it recorded the removal and advanced the fold, without
    // the reader's position entering the decision at all.
    assert_eq!(graph.relations()[0].state, RelationState::Removed);
    assert_ne!(graph.observed(), before);

    assert!(
        outcome.is_ok(),
        "the shipped writer refused a removal on visibility ({:?}); story:graph-policy-adapter \
         landed and this pin is stale",
        outcome.err()
    );
}

/// `mandate.graph.RevokeGrant`, clause "required graph revocation visibility cannot be
/// satisfied", which `contracts/obligations/graph.json` counts in `real_covered`.
///
/// The same rule read against the other revocation command, and the same result:
/// `RevocationWriter::revoke_grant` takes no minimum revision and consults no
/// [`RevisionView`].
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-graph-adversary-1` F2): the
/// revocation is recorded; the clause defers to `story:graph-policy-adapter`; the assertion
/// flips there.
#[test]
fn revoke_grant_does_not_refuse_when_the_required_revocation_visibility_cannot_be_satisfied() {
    let mut graph = seeded();
    let context = context();
    let recorded = graph.record_grant(grant("editor"));

    let required = AuthzRevision::new("never-issued");
    assert!(
        !graph.caught_up_to(&required),
        "the reader has not applied the revision the revocation must be visible at"
    );
    assert_eq!(
        require_revision(&graph, &required),
        Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp)),
        "the free function the registry names as this clause's decider does refuse here"
    );

    let outcome = graph.revoke_grant(&context, &GrantId::new(uuid(6)));

    assert_eq!(graph.grants()[0].state, GrantState::Revoked);
    assert_ne!(graph.observed(), recorded);

    assert!(
        outcome.is_ok(),
        "the shipped writer refused a revocation on visibility ({:?}); story:graph-policy-adapter \
         landed and this pin is stale",
        outcome.err()
    );
}

/// `mandate.graph.RegisterResource`, clause "hierarchy admission fails", which
/// `contracts/obligations/graph.json` counts in `real_covered` on two
/// [`mandate_graph::topology::ancestry`] cases — the depth bound and the cycle.
///
/// `ancestry` is the read-path traversal (`topology.rs:8-10`). `register_resource` never
/// calls it, so the registry admits a chain deeper than the bound the same crate declares,
/// and the read path can then never answer for the resource it just recorded: every
/// authorization check on it fails closed as `Unavailable` for as long as the chain stands.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-graph-adversary-1` F4): the
/// over-deep resource is recorded and is then unanswerable. The clause defers to
/// `story:graph-policy-adapter`, whose registry must refuse the chain at registration; the
/// assertion flips there.
#[test]
fn register_resource_does_not_refuse_a_hierarchy_deeper_than_the_bound_it_declares() {
    let mut graph = GraphDouble::new();
    let context = context();
    let bound = u8::try_from(MAX_ANCESTRY_DEPTH).expect("the bound fits a fixture byte");

    graph
        .register_resource(&context, &resource(0), None)
        .expect("the root registers");
    for step in 1..bound {
        graph
            .register_resource(
                &context,
                &resource(step),
                Some(&ResourceId::new(uuid(step - 1))),
            )
            .expect("a chain exactly as deep as the bound registers");
    }

    // One more takes the chain past MAX_ANCESTRY_DEPTH.
    let past = graph.register_resource(
        &context,
        &resource(bound),
        Some(&ResourceId::new(uuid(bound - 1))),
    );

    // What the command did instead, and what it costs: the resource is recorded, and the
    // read the crate ships can no longer answer any authority question about it.
    if let Ok(registration) = &past {
        assert_eq!(registration.outcome, MutationOutcome::Recorded);
        graph.admit_subject(organization(), subject());
        let subject = subject();
        let deepest = resource(bound);
        let query = GraphQuery {
            context: &context,
            subject: &subject,
            resource: &deepest,
            relation: "viewer",
        };
        assert_eq!(
            GraphRead::check(&graph, &query, &graph.observed())
                .expect_err("the chain the registry accepted is past the bound"),
            GraphError::CouldNotAnswer(Unanswered::HierarchyUnbounded),
            "the recorded resource is unanswerable for ever after"
        );
    }

    assert!(
        past.is_ok(),
        "the shipped registry refused the over-deep chain ({:?}); story:graph-policy-adapter \
         landed and this pin is stale",
        past.err()
    );
}

/// `mandate.graph.WriteRelationship`, clause "outside tenant membership", which
/// `contracts/obligations/graph.json` counts in `real_covered` on
/// `mandate-graph::relationship::a_subject_outside_the_organization_is_denied`.
///
/// That case asserts `GraphError::Denied(DenialReason::TenantMismatch)`, and the value comes
/// from `Members`, a stub declared inside the test file: `admit` decides nothing about
/// membership, it propagates whatever the [`mandate_graph::relationship::SubjectAdmission`]
/// port returned. The only other implementor of that port in the workspace —
/// [`GraphDouble`], which is what every conformance scenario and every other test in this
/// crate uses — answers `Denied(Denied)` for the same condition.
///
/// So the clause is published as decided on the real path with a discriminator no shipped
/// code produces, and the two implementations of its deciding port disagree.
///
/// Pinned by the coordinator to the shipped behaviour on 2026-09-21 (`review-result:wave-d-obligations-graph-adversary-1` F5): the
/// shipped port answers `Denied(Denied)`. The row is a `double` row deferring to
/// `story:graph-policy-adapter`, whose adapter answers the declared `TenantMismatch`; the
/// assertion flips there.
#[test]
fn the_shipped_subject_admission_answers_a_different_reason_than_the_real_row_for_membership() {
    let mut graph = GraphDouble::new();
    let context = context();
    graph
        .register_resource(&context, &resource(10), None)
        .expect("the resource registers");

    // The subject was never admitted into the organization: it is outside tenant membership.
    let subject = subject();
    let held = resource(10);
    let refusal = admit(&graph, &graph, &write(&context, &subject, &held, "viewer"))
        .expect_err("a subject outside tenant membership");

    assert_eq!(
        refusal,
        GraphError::Denied(DenialReason::Denied),
        "the shipped port answers the declared TenantMismatch; story:graph-policy-adapter \
         landed and this pin is stale"
    );
}
