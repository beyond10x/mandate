//! The in-memory policy double: publicly constructible, fail-closed on what it has not
//! been told.
//!
//! It answers only what it can attribute to a recorded version, because `policy.yaml:2`
//! requires every decision to stay attributable to the exact version that made it.

use mandate_policy::double::PolicyDouble;
use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, PolicyAdministration, PolicyEffect, PolicyError,
    PolicyEvaluator, PolicyRequest, Unanswered,
};
use mandate_policy::precedence::RoleCatalog;
use mandate_policy::record::{AuthorizationModel, Policy, PolicyState};
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

fn policy(byte: u8, version: &str) -> Policy {
    Policy::recorded(
        PolicyId::new(uuid(byte)),
        organization(),
        PolicyVersion::new(version),
        "permit(principal, action, resource);",
    )
}

fn model(byte: u8, version: &str) -> AuthorizationModel {
    AuthorizationModel::recorded(
        AuthorizationModelId::new(uuid(byte)),
        organization(),
        PolicyVersion::new(version),
        "type document relations { viewer, editor }",
    )
}

/// A double with one policy version, one model version, and nothing else.
fn published() -> PolicyDouble {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));
    double.record_model(model(5, "2026-09-18.1"));
    double
}

fn evaluate(
    double: &PolicyDouble,
    attributes: &AttributeSet,
) -> Result<mandate_policy::port::Evaluation, PolicyError> {
    let context = context();
    let subject = subject();
    let action = Action::new("read");
    let resource = resource();

    double.evaluate(&PolicyRequest {
        context: &context,
        subject: &subject,
        action: &action,
        resource: &resource,
        attributes,
    })
}

#[test]
fn the_double_is_constructible_from_outside_the_crate() {
    let made = PolicyDouble::new();
    let defaulted = PolicyDouble::default();

    assert_eq!(made, defaulted);
}

#[test]
fn an_answer_that_cannot_be_attributed_to_a_version_is_refused() {
    let double = PolicyDouble::new();

    assert_eq!(
        evaluate(&double, &AttributeSet::new()).expect_err("no policy recorded"),
        PolicyError::CouldNotAnswer(Unanswered::Unreachable)
    );
}

#[test]
fn an_answer_whose_model_version_is_not_observable_is_refused() {
    let mut double = PolicyDouble::new();
    double.record_policy(policy(4, "2026-09-18.1"));

    assert_eq!(
        evaluate(&double, &AttributeSet::new()).expect_err("no model recorded"),
        PolicyError::CouldNotAnswer(Unanswered::ModelNotCaughtUp)
    );
}

#[test]
fn an_attribute_the_double_does_not_trust_is_refused_rather_than_read() {
    let double = published();
    let attributes = AttributeSet::new().with("classification", "restricted");

    assert_eq!(
        evaluate(&double, &attributes).expect_err("an untrusted attribute"),
        PolicyError::CouldNotAnswer(Unanswered::AttributeUntrusted)
    );
}

#[test]
fn a_trusted_attribute_is_read() {
    let mut double = published();
    double.trust_attribute("classification");
    double.allow(organization(), subject(), Action::new("read"), resource());

    let attributes = AttributeSet::new().with("classification", "restricted");
    let evaluation = evaluate(&double, &attributes).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::Allow);
}

#[test]
fn a_request_no_rule_matches_is_denied_rather_than_allowed() {
    let double = published();

    let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::Deny);
    assert_eq!(evaluation.version, PolicyVersion::new("2026-09-18.1"));
    assert_eq!(evaluation.challenge, None);
}

#[test]
fn a_matching_rule_names_the_version_the_answer_was_made_under() {
    let mut double = published();
    double.allow(organization(), subject(), Action::new("read"), resource());

    let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::Allow);
    assert_eq!(evaluation.version, PolicyVersion::new("2026-09-18.1"));
}

#[test]
fn an_approval_rule_carries_the_challenge_material() {
    let mut double = published();
    double.require_approval(
        organization(),
        subject(),
        Action::new("read"),
        resource(),
        ChallengeRequirement::Reauthentication,
    );

    let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::ApprovalRequired);
    assert_eq!(
        evaluation.challenge,
        Some(Challenge {
            requirement: ChallengeRequirement::Reauthentication,
            correlation: CorrelationId::new("correlation"),
        })
    );
}

#[test]
fn a_rule_in_another_organization_does_not_answer_this_one() {
    let mut double = published();
    double.allow(
        OrganizationId::new(uuid(9)),
        subject(),
        Action::new("read"),
        resource(),
    );

    let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::Deny);
}

#[test]
fn a_version_with_no_later_version_recorded_cannot_be_superseded() {
    let mut double = published();

    let refusal = double
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect_err("nothing later is recorded");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::Denied));
    assert_eq!(double.policies()[0].state, PolicyState::Recorded);
}

#[test]
fn superseding_a_policy_twice_records_one_move() {
    let mut double = published();
    double.record_policy(policy(6, "2026-09-18.2"));

    let first = double
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect("a later version is recorded");
    let second = double
        .supersede_policy(&context(), &PolicyId::new(uuid(4)))
        .expect("the repeat is accepted");

    assert!(first.outcome.changed());
    assert!(!second.outcome.changed());
    assert_eq!(first.record.state, PolicyState::Superseded);
    assert_eq!(double.policies().len(), 2);
}

#[test]
fn superseding_a_model_twice_records_one_move() {
    let mut double = published();
    double.record_model(model(7, "2026-09-18.2"));

    let first = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect("a later version is recorded");
    let second = double
        .supersede_authorization_model(&context(), &AuthorizationModelId::new(uuid(5)))
        .expect("the repeat is accepted");

    assert!(first.outcome.changed());
    assert!(!second.outcome.changed());
    assert_eq!(double.models().len(), 2);
}

#[test]
fn another_organizations_policy_is_a_tenant_mismatch() {
    let mut double = published();
    double.record_policy(policy(6, "2026-09-18.2"));

    let mut elsewhere = context();
    elsewhere.organization = OrganizationId::new(uuid(9));

    let refusal = double
        .supersede_policy(&elsewhere, &PolicyId::new(uuid(4)))
        .expect_err("another tenant's policy");

    assert_eq!(refusal, PolicyError::Denied(DenialReason::TenantMismatch));
}

#[test]
fn the_double_answers_the_role_catalog_it_was_told() {
    let mut double = published();
    double.record_role(
        organization(),
        "editor",
        vec![Action::new("read"), Action::new("write")],
    );

    assert_eq!(
        double.actions(&organization(), "editor"),
        Some(vec![Action::new("read"), Action::new("write")])
    );
    assert_eq!(double.actions(&organization(), "owner"), None);
    assert_eq!(
        double.actions(&OrganizationId::new(uuid(9)), "editor"),
        None
    );
}

/// `docs/architecture/combined.md:53` says denies override grants. The double holds its
/// rules in a list, so the question is whether the answer depends on the order they were
/// recorded in. It must not: the double folds every matching rule through
/// `crate::precedence::combine` rather than keeping a second copy of the rule.
#[test]
fn the_answer_does_not_depend_on_the_order_the_rules_were_recorded_in() {
    enum Record {
        Allow,
        Deny,
        Approval,
    }

    let orders = [
        [Record::Allow, Record::Deny, Record::Approval],
        [Record::Allow, Record::Approval, Record::Deny],
        [Record::Deny, Record::Allow, Record::Approval],
        [Record::Deny, Record::Approval, Record::Allow],
        [Record::Approval, Record::Allow, Record::Deny],
        [Record::Approval, Record::Deny, Record::Allow],
    ];

    for order in orders {
        let mut double = published();
        for record in order {
            match record {
                Record::Allow => {
                    double.allow(organization(), subject(), Action::new("read"), resource());
                }
                Record::Deny => {
                    double.deny(organization(), subject(), Action::new("read"), resource());
                }
                Record::Approval => double.require_approval(
                    organization(),
                    subject(),
                    Action::new("read"),
                    resource(),
                    ChallengeRequirement::Approval,
                ),
            }
        }

        assert_eq!(
            evaluate(&double, &AttributeSet::new())
                .expect("the double answers")
                .effect,
            PolicyEffect::Deny,
            "the deny must win whatever order the rules were recorded in"
        );
    }
}

/// Without a deny in the set, an approval requirement still outranks an allow, in either
/// recording order.
#[test]
fn an_approval_requirement_outranks_an_allow_in_either_order() {
    for allow_first in [true, false] {
        let mut double = published();
        if allow_first {
            double.allow(organization(), subject(), Action::new("read"), resource());
        }
        double.require_approval(
            organization(),
            subject(),
            Action::new("read"),
            resource(),
            ChallengeRequirement::Approval,
        );
        if !allow_first {
            double.allow(organization(), subject(), Action::new("read"), resource());
        }

        let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

        assert_eq!(evaluation.effect, PolicyEffect::ApprovalRequired);
        assert!(evaluation.challenge.is_some());
    }
}

#[test]
fn a_rule_for_another_subject_action_or_resource_does_not_answer_this_request() {
    let other_subject = AuthoritySubject::Principal(PrincipalId::new(uuid(3)));
    let other_resource = ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(6)),
    };

    for (subject, action, resource) in [
        (other_subject.clone(), Action::new("read"), resource()),
        (subject(), Action::new("write"), resource()),
        (subject(), Action::new("read"), other_resource),
    ] {
        let mut double = published();
        double.allow(organization(), subject, action, resource);

        assert_eq!(
            evaluate(&double, &AttributeSet::new())
                .expect("the double answers")
                .effect,
            PolicyEffect::Deny,
            "a rule that does not name this request must not answer it"
        );
    }
}

/// An attribute name that differs from its trim is a different name, so it is not one the
/// double was told to trust, and the evaluation is refused rather than read. Same class as
/// the relation name `mandate-graph` refuses at admission.
#[test]
fn an_attribute_name_that_differs_from_its_trim_is_not_trusted() {
    let mut double = published();
    double.trust_attribute("classification");
    double.allow(organization(), subject(), Action::new("read"), resource());

    for padded in [" classification", "classification ", " classification "] {
        let attributes = AttributeSet::new().with(padded, "restricted");

        assert_eq!(
            evaluate(&double, &attributes).expect_err("a name that is not the trusted name"),
            PolicyError::CouldNotAnswer(Unanswered::AttributeUntrusted)
        );
    }

    evaluate(
        &double,
        &AttributeSet::new().with("classification", "restricted"),
    )
    .expect("the trusted name is read");
}

/// Every reason [`Unanswered`] declares must be one some path actually produces; a
/// declared refusal no code can emit is a promise nothing keeps. This drives each one out
/// of the public API and asserts the set it collected is `Unanswered::ALL`.
#[test]
fn every_declared_reason_policy_cannot_answer_for_is_produced_by_some_path() {
    let unreachable = PolicyDouble::new();

    let mut without_model = PolicyDouble::new();
    without_model.record_policy(policy(4, "2026-09-18.1"));

    let published = published();

    let produced = [
        evaluate(&unreachable, &AttributeSet::new()),
        evaluate(&without_model, &AttributeSet::new()),
        evaluate(
            &published,
            &AttributeSet::new().with("classification", "restricted"),
        ),
    ]
    .into_iter()
    .map(
        |outcome| match outcome.expect_err("each of these refuses") {
            PolicyError::CouldNotAnswer(reason) => reason,
            PolicyError::Denied(reason) => {
                panic!("expected an inability to answer, got {reason:?}")
            }
        },
    )
    .collect::<Vec<_>>();

    assert_eq!(produced, Unanswered::ALL.to_vec());
}

/// The challenge the double reports is the strictest requirement among the rules that
/// matched, decided by `precedence::strictest` — the single home — and not by which rule
/// happens to sit first in the list.
#[test]
fn the_challenge_is_the_strictest_requirement_among_the_matching_rules() {
    use mandate_policy::precedence::strictest;

    let requirements = [
        ChallengeRequirement::Reauthentication,
        ChallengeRequirement::Approval,
    ];

    for order in [[0_usize, 1], [1, 0]] {
        let mut double = published();
        for index in order {
            double.require_approval(
                organization(),
                subject(),
                Action::new("read"),
                resource(),
                requirements[index],
            );
        }

        let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

        assert_eq!(evaluation.effect, PolicyEffect::ApprovalRequired);
        assert_eq!(
            evaluation.challenge,
            Some(Challenge {
                requirement: strictest(&requirements).expect("two requirements"),
                correlation: CorrelationId::new("correlation"),
            }),
            "the requirement must be the strictest of the matching rules, not the first"
        );
    }
}

/// A deny alongside an approval rule takes the answer to `Deny`, and no challenge material
/// survives: there is nothing for the caller to clear.
#[test]
fn a_denied_answer_carries_no_challenge_however_many_approval_rules_matched() {
    let mut double = published();
    double.require_approval(
        organization(),
        subject(),
        Action::new("read"),
        resource(),
        ChallengeRequirement::Approval,
    );
    double.deny(organization(), subject(), Action::new("read"), resource());

    let evaluation = evaluate(&double, &AttributeSet::new()).expect("the double answers");

    assert_eq!(evaluation.effect, PolicyEffect::Deny);
    assert_eq!(evaluation.challenge, None);
}
