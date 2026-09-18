//! Adversarial cases, second pass, against `crates/mandate-policy/src/double.rs` and
//! `crates/mandate-policy/src/precedence.rs`.
//!
//! Both drive the implementation against a document this unit wrote about itself: the
//! fold's own account of why it is a fold (`double.rs:182-219`) and the combinator's
//! account of what a caller is told (`precedence.rs:86-99`), read against
//! `.engineering/planning/story/graph-policy.md:113`.

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, ChallengeRequirement, Evaluation, PolicyEffect, PolicyEvaluator, PolicyRequest,
};
use mandate_policy::precedence::{Component, combine};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, Audience, AuthoritySubject, AuthorizationModelId, CorrelationId, CredentialId,
    DenialReason, OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef,
    ResourceType, Uuid, VerifiedContext,
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

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(5)),
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

/// A double with one policy version and one model version recorded, so an answer can be
/// attributed and nothing is refused for an absence.
fn published() -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(Policy::recorded(
        PolicyId::new(uuid(4)),
        organization(),
        PolicyVersion::new("2026-09-18.1"),
        "permit(principal, action, resource);",
    ));
    double.record_model(AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(5)),
        organization(),
        PolicyVersion::new("2026-09-18.1"),
        "type document relations { viewer, editor }",
    ));
    double
}

fn evaluation(double: &PolicyDouble) -> Evaluation {
    let context = context();
    let subject = subject();
    let action = Action::new("read");
    let resource = resource();
    let attributes = AttributeSet::new();

    double
        .evaluate(&PolicyRequest {
            context: &context,
            subject: &subject,
            action: &action,
            resource: &resource,
            attributes: &attributes,
        })
        .expect("the double answers")
}

/// A double holding two approval rules for one request, recorded in the given order.
fn two_approvals(first: ChallengeRequirement, second: ChallengeRequirement) -> PolicyDouble {
    let mut double = published();
    for requirement in [first, second] {
        double.require_approval(
            organization(),
            subject(),
            Action::new("read"),
            resource(),
            requirement,
        );
    }
    double
}

/// `double.rs:182-187` is the correction this round made and the reason it gives for it:
/// "The double holds its rules in a list, and resolving them with `find` would have made
/// the answer depend on the order they were recorded in".
///
/// The effect no longer does. The challenge material still does: `double.rs:213-219`
/// resolves it with `Iterator::find` over the same list, so of two approval rules naming
/// the same `(organization, subject, action, resource)` the one recorded *first* names
/// what the caller must satisfy. Recording a rule that demands an approval from a second
/// party after one that demands the caller reauthenticate leaves the caller able to clear
/// the answer alone, and the two orders answer differently for identical rule sets —
/// which is the defect the fold was written to remove, in the field the fold does not
/// cover. `precedence::Component` carries no requirement, so nothing in the single home of
/// precedence (`lib.rs:6`) decides this; `double.rs` decides it by list position.
#[test]
fn the_challenge_material_does_not_depend_on_the_order_the_rules_were_recorded_in() {
    let reauthentication_first = two_approvals(
        ChallengeRequirement::Reauthentication,
        ChallengeRequirement::Approval,
    );
    let approval_first = two_approvals(
        ChallengeRequirement::Approval,
        ChallengeRequirement::Reauthentication,
    );

    let one = evaluation(&reauthentication_first);
    let other = evaluation(&approval_first);

    assert_eq!(
        one.effect,
        PolicyEffect::ApprovalRequired,
        "both rule sets come to an approval requirement",
    );
    assert_eq!(
        one.effect, other.effect,
        "both rule sets come to the same effect",
    );
    assert_eq!(
        one.challenge, other.challenge,
        "double.rs:184-187 says the answer must not depend on the order the rules were \
         recorded in; the same two approval rules answer {:?} recorded one way and {:?} \
         recorded the other, so which party has to clear the challenge is decided by list \
         position",
        one.challenge, other.challenge,
    );
}

/// `.engineering/planning/story/graph-policy.md:113` names what `story:check-api` needs
/// from this story: "a fail-closed error mapping onto
/// `DenialReason::{Denied, ApprovalRequired, TenantMismatch, Unavailable}`", and line 102
/// makes [`mandate_policy::precedence`] "the single home of precedence, consumed by
/// `story:check-api`".
///
/// Three of the four are produced here. `DenialReason::ApprovalRequired` appears nowhere in
/// either crate's `src/`: `Combined::ApprovalRequired` — which `double.rs:205-209` folds to
/// on the ordinary path — answers `false` to `allowed` and `None` to `denial_reason`, so a
/// caller holding it is told neither that the request is allowed nor any reason it is not,
/// and has to restate the fourth mapping outside the home that owns it.
#[test]
fn a_combination_that_is_not_an_allow_names_the_reason_the_caller_is_told() {
    let approval = combine(&[Component::ApprovalRequired]);

    assert!(
        !approval.allowed(),
        "an approval requirement is not an allow",
    );
    assert_eq!(
        approval.denial_reason(),
        Some(DenialReason::ApprovalRequired),
        "precedence.rs:87-99 is where a caller reads what it is told, and \
         DenialReason::ApprovalRequired is one of the four the story's line 113 names as \
         this story's output; {approval:?} answers allowed() false and denial_reason() \
         {:?}, which is a state with no report in it",
        approval.denial_reason(),
    );
}
