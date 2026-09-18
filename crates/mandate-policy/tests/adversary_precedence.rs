//! Adversarial cases against `crates/mandate-policy/src/double.rs` and
//! `crates/mandate-policy/src/precedence.rs`.
//!
//! Both drive the implementation against a document the unit wrote about itself: the
//! double's module header (`double.rs:10-12`) and the combinator's own claim that it is
//! associative (`precedence.rs:95-96`), each read against
//! `docs/architecture/combined.md:53` as both of them cite it.

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{PolicyEffect, PolicyError, PolicyEvaluator, PolicyRequest};
use mandate_policy::precedence::{Combined, Component, combine};
use mandate_policy::record::{AuthorizationModel, Policy};
use mandate_types::{
    Action, Audience, AuthoritySubject, AuthorizationModelId, CorrelationId, CredentialId,
    OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType,
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

fn effect(double: &PolicyDouble) -> Result<PolicyEffect, PolicyError> {
    let context = context();
    let subject = subject();
    let action = Action::new("read");
    let resource = resource();
    let attributes = mandate_policy::port::AttributeSet::new();

    double
        .evaluate(&PolicyRequest {
            context: &context,
            subject: &subject,
            action: &action,
            resource: &resource,
            attributes: &attributes,
        })
        .map(|evaluation| evaluation.effect)
}

/// `docs/architecture/combined.md:53` — the line `double.rs:12` and `precedence.rs:3` both
/// cite — says "Denies override grants".
///
/// `PolicyDouble::evaluate` resolves its own rules with `Vec::find` (`double.rs:182-192`),
/// so the rule recorded *first* answers. A deny recorded after an allow for exactly the
/// same `(organization, subject, action, resource)` is never seen, and the double answers
/// `Allow` while holding a `Deny` for that request.
#[test]
fn a_deny_rule_is_not_overridden_by_an_allow_recorded_before_it() {
    let mut allow_first = published();
    allow_first.allow(organization(), subject(), Action::new("read"), resource());
    allow_first.deny(organization(), subject(), Action::new("read"), resource());

    let mut deny_first = published();
    deny_first.deny(organization(), subject(), Action::new("read"), resource());
    deny_first.allow(organization(), subject(), Action::new("read"), resource());

    let answered = effect(&allow_first).expect("the double answers");

    assert_eq!(
        answered,
        PolicyEffect::Deny,
        "combined.md:53 (cited by double.rs:12) says denies override grants, and the \
         double holds a deny for exactly this request",
    );
    assert_eq!(
        answered,
        effect(&deny_first).expect("the double answers"),
        "the answer depends on the order the two rules were recorded in",
    );
}

/// `precedence.rs:95-96` says of `combine`: "the result does not depend on the order the
/// components arrive in: combining is commutative and associative". `Combined::component`
/// exists "so results can be combined further" (`precedence.rs:57-58`), which is the
/// composition that claim is about.
///
/// It does not hold when one of the groups is empty: `combine(&[])` is
/// `Denied` (`precedence.rs:122`), and that denial then survives into the combination of
/// the groups, where flattening the same components allows.
#[test]
fn combining_in_groups_agrees_with_combining_all_at_once_when_a_group_is_empty() {
    let left: [Component; 0] = [];
    let right = [Component::Allowed];

    let all_at_once = combine(&right);
    let in_two_steps = combine(&[combine(&left).component(), combine(&right).component()]);

    assert_eq!(
        in_two_steps,
        all_at_once,
        "precedence.rs:95-96 claims combining is associative; an empty group injects \
         {:?} into a combination that is otherwise {:?}",
        combine(&left),
        Combined::Allowed,
    );
}
