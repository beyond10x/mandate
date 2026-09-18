//! The API boundary, checked from outside the crate.
//!
//! An integration test is its own crate, so what compiles here is what a consumer can
//! write. This file holds the positive half: the canonical revision is admitted, and an
//! adapter declared outside `mandate-graph` implements the read port with it. The
//! negative half — that a backend type cannot cross the port — is the `compile_fail`
//! doctest on the crate root, because rustdoc collects doctests from the library target
//! alone and never from `tests/`.

use mandate_graph::port::{GraphError, GraphQuery, GraphRead, Observed, Revision, Unanswered};
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

/// An adapter written outside `mandate-graph`, as a real one would be.
struct OutsideAdapter;

impl GraphRead for OutsideAdapter {
    type Revision = AuthzRevision;

    fn check(
        &self,
        _query: &GraphQuery<'_>,
        _minimum: &AuthzRevision,
    ) -> Result<Observed, GraphError> {
        Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp))
    }
}

#[test]
fn the_revision_vocabulary_admits_the_canonical_revision() {
    fn admitted<R: Revision>(value: &R) -> &AuthzRevision {
        value.as_authz_revision()
    }

    let revision = AuthzRevision::new("3");

    assert_eq!(admitted(&revision), &AuthzRevision::new("3"));
}

#[test]
fn an_adapter_outside_the_crate_answers_through_the_port() {
    let adapter = OutsideAdapter;
    let port: &dyn GraphRead<Revision = AuthzRevision> = &adapter;

    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let resource = resource();
    let query = GraphQuery {
        context: &context,
        subject: &subject,
        resource: &resource,
        relation: "viewer",
    };

    let refusal = port
        .check(&query, &AuthzRevision::new("3"))
        .expect_err("the adapter answers nothing");

    assert!(refusal.is_could_not_answer());
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
}
