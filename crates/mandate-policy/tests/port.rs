//! The policy evaluation port: allow, deny or approval-required, the version the answer
//! was made under, and the challenge material an approval needs.
//!
//! The port returns components, never a `mandate.authorization.Decision`:
//! `docs/architecture/ownership.md:13` gives combined decision evaluation to
//! `mandate-authz`. The attribute input is left opaque because
//! `docs/sources/original-design.md:738` still asks "how are resource attributes trusted
//! and distributed?" and `:3369` requires authorization-critical attributes to arrive as
//! trusted context; `story:graph-policy-adapter` revisits the parameter.

use mandate_policy::port::{
    AttributeSet, AttributeValue, Challenge, ChallengeRequirement, Evaluation, PolicyEffect,
    PolicyError, PolicyEvaluator, PolicyRequest, Unanswered,
};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, Audience, AuthoritySubject, AuthorizationModelId, CorrelationId, CredentialId,
    DenialReason, OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef,
    ResourceType, Uuid, VerifiedContext,
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
        Unanswered::Unreachable => 0,
        Unanswered::ModelNotCaughtUp => 1,
        Unanswered::AttributeUntrusted => 2,
    }
}

fn effect_index(effect: PolicyEffect) -> usize {
    match effect {
        PolicyEffect::Allow => 0,
        PolicyEffect::Deny => 1,
        PolicyEffect::ApprovalRequired => 2,
    }
}

/// An evaluator written outside the crate, as a real one would be.
struct OutsideEvaluator;

impl PolicyEvaluator for OutsideEvaluator {
    fn evaluate(&self, request: &PolicyRequest<'_>) -> Result<Evaluation, PolicyError> {
        if request.attributes.is_empty() {
            return Err(PolicyError::CouldNotAnswer(Unanswered::AttributeUntrusted));
        }
        Ok(Evaluation {
            effect: PolicyEffect::ApprovalRequired,
            version: PolicyVersion::new("2026-09-18.1"),
            challenge: Some(Challenge {
                requirement: ChallengeRequirement::Approval,
                correlation: request.context.correlation.clone(),
            }),
        })
    }
}

#[test]
fn a_denial_carries_the_reason_the_contract_declares() {
    for reason in DenialReason::VARIANTS {
        let error = PolicyError::Denied(*reason);

        assert_eq!(error.denial_reason(), *reason);
        assert!(error.is_denial());
        assert!(!error.is_could_not_answer());
    }
}

#[test]
fn every_inability_to_answer_fails_closed_as_unavailable() {
    assert_eq!(Unanswered::ALL.len(), 3);

    for (position, reason) in Unanswered::ALL.iter().enumerate() {
        let error = PolicyError::CouldNotAnswer(*reason);

        assert_eq!(unanswered_index(*reason), position);
        assert_eq!(error.denial_reason(), DenialReason::Unavailable);
        assert!(error.is_could_not_answer());
        assert!(!error.is_denial());
    }
}

#[test]
fn the_port_returns_exactly_three_effects() {
    assert_eq!(PolicyEffect::ALL.len(), 3);

    for (position, effect) in PolicyEffect::ALL.iter().enumerate() {
        assert_eq!(effect_index(*effect), position);
    }
}

#[test]
fn an_attribute_set_carries_canonical_values_under_names() {
    let attributes = AttributeSet::new()
        .with("classification", "restricted")
        .with("owned_by_caller", true)
        .with("resource", resource())
        .with("action", Action::new("read"));

    assert_eq!(attributes.len(), 4);
    assert!(!attributes.is_empty());
    assert_eq!(
        attributes.get("classification"),
        Some(&AttributeValue::Text("restricted".to_owned()))
    );
    assert_eq!(
        attributes.get("owned_by_caller"),
        Some(&AttributeValue::Flag(true))
    );
    assert_eq!(
        attributes.get("resource"),
        Some(&AttributeValue::Resource(resource()))
    );
    assert_eq!(attributes.get("absent"), None);
    assert!(AttributeSet::new().is_empty());
}

#[test]
fn an_approval_required_answer_carries_the_challenge_and_the_version() {
    let evaluator = OutsideEvaluator;
    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let action = Action::new("read");
    let resource = resource();
    let attributes = AttributeSet::new().with("classification", "restricted");

    let evaluation = evaluator
        .evaluate(&PolicyRequest {
            context: &context,
            subject: &subject,
            action: &action,
            resource: &resource,
            attributes: &attributes,
        })
        .expect("the evaluator answers");

    assert_eq!(evaluation.effect, PolicyEffect::ApprovalRequired);
    assert_eq!(evaluation.version, PolicyVersion::new("2026-09-18.1"));
    assert_eq!(
        evaluation.challenge,
        Some(Challenge {
            requirement: ChallengeRequirement::Approval,
            correlation: CorrelationId::new("correlation"),
        })
    );
}

#[test]
fn an_evaluator_that_cannot_trust_its_input_refuses_rather_than_allowing() {
    let evaluator = OutsideEvaluator;
    let context = context();
    let subject = AuthoritySubject::Principal(PrincipalId::new(uuid(2)));
    let action = Action::new("read");
    let resource = resource();
    let attributes = AttributeSet::new();

    let refusal = evaluator
        .evaluate(&PolicyRequest {
            context: &context,
            subject: &subject,
            action: &action,
            resource: &resource,
            attributes: &attributes,
        })
        .expect_err("nothing trusted to evaluate");

    assert_eq!(
        refusal,
        PolicyError::CouldNotAnswer(Unanswered::AttributeUntrusted)
    );
    assert_eq!(refusal.denial_reason(), DenialReason::Unavailable);
}

#[test]
fn the_two_supersede_commands_wave_one_declared_are_reachable_through_a_port() {
    use mandate_policy::port::{PolicyAdministration, Superseded};

    struct RefusingAdministration;

    impl PolicyAdministration for RefusingAdministration {
        fn supersede_policy(
            &mut self,
            _context: &VerifiedContext,
            _id: &PolicyId,
        ) -> Result<Superseded<Policy>, PolicyError> {
            Err(PolicyError::Denied(DenialReason::Denied))
        }

        fn supersede_authorization_model(
            &mut self,
            _context: &VerifiedContext,
            _id: &AuthorizationModelId,
        ) -> Result<Superseded<AuthorizationModel>, PolicyError> {
            Err(PolicyError::Denied(DenialReason::Denied))
        }
    }

    let mut administration = RefusingAdministration;
    let context = context();

    let policy = administration
        .supersede_policy(&context, &PolicyId::new(uuid(4)))
        .expect_err("the stub refuses");
    let model = administration
        .supersede_authorization_model(&context, &AuthorizationModelId::new(uuid(5)))
        .expect_err("the stub refuses");

    assert_eq!(policy.denial_reason(), DenialReason::Denied);
    assert_eq!(model.denial_reason(), DenialReason::Denied);
}
