//! The API boundary, checked from outside the crate.
//!
//! An integration test is its own crate, so what compiles here is what a consumer can
//! write. This file holds the positive half: every canonical value the attribute set
//! admits, and an evaluator declared outside `mandate-policy` answering through the port.
//! The negative half — that a backend row cannot be carried through the opaque attribute
//! input — is the `compile_fail` doctest on the crate root, because rustdoc collects
//! doctests from the library target alone and never from `tests/`.

use mandate_policy::port::{
    AttributeInput, AttributeSet, AttributeValue, Evaluation, PolicyError, PolicyEvaluator,
    PolicyRequest, Unanswered,
};
use mandate_types::{
    Action, Audience, AuthoritySubject, CorrelationId, CredentialId, DenialReason, OrganizationId,
    PrincipalId, ResourceId, ResourceRef, ResourceType, Uuid, VerifiedContext,
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

/// An evaluator written outside `mandate-policy`, as a real one would be.
struct OutsideEvaluator;

impl PolicyEvaluator for OutsideEvaluator {
    fn evaluate(&self, _request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        Err(PolicyError::CouldNotAnswer(Unanswered::Unreachable))
    }
}

#[test]
fn the_attribute_vocabulary_admits_exactly_the_canonical_values() {
    fn admitted<V: AttributeInput>(value: V) -> AttributeValue {
        value.into_value()
    }

    assert_eq!(
        admitted("restricted"),
        AttributeValue::Text("restricted".to_owned())
    );
    assert_eq!(
        admitted(String::from("restricted")),
        AttributeValue::Text("restricted".to_owned())
    );
    assert_eq!(admitted(true), AttributeValue::Flag(true));
    assert_eq!(
        admitted(Action::new("read")),
        AttributeValue::Action(Action::new("read"))
    );
    assert_eq!(admitted(resource()), AttributeValue::Resource(resource()));
    assert_eq!(
        admitted(AuthoritySubject::Principal(PrincipalId::new(uuid(2)))),
        AttributeValue::Subject(AuthoritySubject::Principal(PrincipalId::new(uuid(2))))
    );
    assert_eq!(
        admitted(OrganizationId::new(uuid(1))),
        AttributeValue::Organization(OrganizationId::new(uuid(1)))
    );
}

#[test]
fn an_evaluator_outside_the_crate_answers_through_the_port() {
    let evaluator = OutsideEvaluator;
    let port: &dyn PolicyEvaluator = &evaluator;

    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let action = Action::new("read");
    let resource = resource();
    let attributes = AttributeSet::new();

    let refusal = port
        .evaluate(&PolicyRequest {
            context: &context,
            subject: &subject,
            action: &action,
            resource: &resource,
            attributes: &attributes,
        })
        .expect_err("the evaluator answers nothing");

    assert!(refusal.is_could_not_answer());
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
}
