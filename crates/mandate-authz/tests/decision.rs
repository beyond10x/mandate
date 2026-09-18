//! `mandate.core.Decision` assembly: the identifier, the revision, the policy version, the
//! absent model version, and the structured challenge an approval requirement carries.
//!
//! Corpus case (`tests/security/cases.json`): `approval-required` (`:553`) — a high-risk
//! policy without a valid scoped approval answers `allowed=false` with a structured
//! challenge.

use std::cell::Cell;

use mandate_authz::decision::{
    ChallengeIssuer, Denied, FixedChallenge, SequentialDecisionIds, Taken, decide, declared,
};
use mandate_authz::evaluate::Authority;
use mandate_policy::port::{Challenge, ChallengeRequirement};
use mandate_policy::precedence::Combined;
use mandate_types::{
    Action, Audience, AuthzRevision, CorrelationId, CredentialId, DecisionReason, DenialReason,
    OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceId, ResourceRef, ResourceType,
    Timestamp, Uuid, VerifiedContext,
};

fn uuid(byte: u8) -> Uuid {
    Uuid::from_bytes([byte; 16])
}

fn organization() -> OrganizationId {
    OrganizationId::new(uuid(1))
}

fn resource() -> ResourceRef {
    ResourceRef {
        resource_type: ResourceType::new("document"),
        resource_id: ResourceId::new(uuid(10)),
    }
}

fn action() -> Action {
    Action::new("deployment.restart")
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

fn approver() -> PolicyId {
    PolicyId::new(uuid(40))
}

fn deadline() -> Timestamp {
    Timestamp::new("2026-09-18T00:00:00Z")
}

fn issuer() -> FixedChallenge {
    FixedChallenge {
        expires_at: deadline(),
        approver_policy: Some(approver()),
    }
}

fn taken<'a>(
    context: &'a VerifiedContext,
    action: &'a Action,
    resource: &'a ResourceRef,
) -> Taken<'a> {
    Taken {
        context,
        action,
        resource,
    }
}

fn approval_required() -> Authority {
    Authority {
        combined: Combined::ApprovalRequired,
        revision: Some(AuthzRevision::new("7")),
        policy_version: Some(PolicyVersion::new("v1")),
        challenges: vec![Challenge {
            requirement: ChallengeRequirement::Approval,
            correlation: CorrelationId::new("correlation"),
        }],
    }
}

fn allowed() -> Authority {
    Authority {
        combined: Combined::Allowed,
        revision: Some(AuthzRevision::new("7")),
        policy_version: Some(PolicyVersion::new("v1")),
        challenges: Vec::new(),
    }
}

/// `approval-required`: allowed=false, a challenge scoped to the action and resource that
/// provoked it, and an identifier the audit record correlates on.
#[test]
fn an_approval_requirement_is_allowed_false_with_a_structured_scoped_challenge() {
    let context = context();
    let action = action();
    let resource = resource();

    let refusal = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &approval_required(),
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(refusal.reason, DenialReason::ApprovalRequired);
    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.decision.reason, DecisionReason::ApprovalRequired);
    let challenge = refusal
        .decision
        .challenge
        .expect("an approval requirement carries a challenge");
    assert_eq!(challenge.action, action);
    assert_eq!(challenge.resource, resource);
    assert_eq!(challenge.approver_policy, approver());
    assert_eq!(challenge.expires_at, deadline());
}

#[test]
fn an_allow_carries_the_revision_and_the_policy_version_and_no_challenge() {
    let context = context();
    let action = action();
    let resource = resource();

    let decision = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &allowed(),
    )
    .expect("the request is allowed");

    assert!(decision.allowed);
    assert_eq!(decision.reason, DecisionReason::Allowed);
    assert_eq!(decision.revision, Some(AuthzRevision::new("7")));
    assert_eq!(decision.policy_version, Some(PolicyVersion::new("v1")));
    assert_eq!(decision.challenge, None);
}

/// Every decision is identified, the refusals included: the identifier is what an audit
/// record and a later approval both point at.
#[test]
fn every_decision_carries_an_identifier() {
    let context = context();
    let action = action();
    let resource = resource();
    let mut allocator = SequentialDecisionIds::new();

    let allow = decide(
        &mut allocator,
        &issuer(),
        &taken(&context, &action, &resource),
        &allowed(),
    )
    .expect("the request is allowed");
    let refusal = decide(
        &mut allocator,
        &issuer(),
        &taken(&context, &action, &resource),
        &Authority::refused(DenialReason::TenantMismatch),
    )
    .expect_err("the resource is not this tenant's");

    assert_ne!(allow.decision_id, refusal.decision.decision_id);
    assert_eq!(allocator.issued(), 2);
}

/// The coordinator's ruling for this wave, asserted rather than described: no port in the
/// dependency ceiling returns an `AuthorizationModelVersion`, so no decision claims one.
#[test]
fn no_decision_claims_an_authorization_model_version() {
    let context = context();
    let action = action();
    let resource = resource();

    let allow = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &allowed(),
    )
    .expect("the request is allowed");
    let refusal = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &approval_required(),
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(allow.model_version, None);
    assert_eq!(refusal.decision.model_version, None);
}

/// An approval nobody can be asked for is unanswerable, so it fails closed rather than
/// telling the caller to satisfy a challenge that names no approver.
#[test]
fn an_approval_with_no_approver_policy_fails_closed_as_unavailable() {
    let context = context();
    let action = action();
    let resource = resource();
    let nameless = FixedChallenge {
        expires_at: deadline(),
        approver_policy: None,
    };

    let refusal = decide(
        &mut SequentialDecisionIds::new(),
        &nameless,
        &taken(&context, &action, &resource),
        &approval_required(),
    )
    .expect_err("no approver, no allow");

    assert_eq!(refusal.reason, DenialReason::Unavailable);
    assert_eq!(refusal.decision.reason, DecisionReason::Unavailable);
    assert_eq!(refusal.decision.challenge, None);
}

/// An approval requirement that names no requirement is challenged as an **approval**: the
/// strictest there is, and the one the caller cannot clear alone
/// (`crates/mandate-policy/src/precedence.rs:226-240`). Defaulting to the other way round
/// would tell a caller it can clear by itself something no source said it could.
#[test]
fn an_approval_requirement_naming_no_requirement_is_challenged_as_an_approval() {
    let context = context();
    let action = action();
    let resource = resource();
    let issuer = Recording {
        asked: Cell::new(None),
    };
    let silent = Authority {
        combined: Combined::ApprovalRequired,
        revision: None,
        policy_version: Some(PolicyVersion::new("v1")),
        challenges: Vec::new(),
    };

    let refusal = decide(
        &mut SequentialDecisionIds::new(),
        &issuer,
        &taken(&context, &action, &resource),
        &silent,
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(refusal.reason, DenialReason::ApprovalRequired);
    assert_eq!(refusal.decision.reason, DecisionReason::ApprovalRequired);
    assert!(
        refusal.decision.challenge.is_some(),
        "a decision that states an approval is required states what would clear it"
    );
    assert_eq!(issuer.asked.get(), Some(ChallengeRequirement::Approval));
}

/// An issuer that records which requirement it was asked to date.
struct Recording {
    asked: Cell<Option<ChallengeRequirement>>,
}

impl ChallengeIssuer for Recording {
    fn expires_at(
        &self,
        _context: &VerifiedContext,
        requirement: ChallengeRequirement,
    ) -> Timestamp {
        self.asked.set(Some(requirement));
        deadline()
    }

    fn approver_policy(&self, _organization: &OrganizationId) -> Option<PolicyId> {
        Some(approver())
    }
}

/// Which challenge is issued is a precedence question, and `mandate-policy` is its single
/// home: `strictest` ranks an approval above a reauthentication because the caller cannot
/// clear an approval alone (`crates/mandate-policy/src/precedence.rs:226-254`). The order
/// the requirements arrive in does not decide it.
///
/// The authority is built here rather than read from a run, because two requirements is a
/// state `crate::evaluate` cannot yet produce: one policy port is read per request and an
/// `Evaluation` carries at most one challenge, so `strictest` has a single source to rank
/// this wave. This case decides the ranking that a second source — a delegation or an
/// actor ceiling that also asks for one — would meet the day it lands.
#[test]
fn the_strictest_requirement_among_those_asked_for_is_the_one_challenged() {
    let context = context();
    let action = action();
    let resource = resource();
    let approval = Challenge {
        requirement: ChallengeRequirement::Approval,
        correlation: CorrelationId::new("correlation"),
    };
    let reauthentication = Challenge {
        requirement: ChallengeRequirement::Reauthentication,
        correlation: CorrelationId::new("correlation"),
    };

    for challenges in [
        vec![approval.clone(), reauthentication.clone()],
        vec![reauthentication.clone(), approval.clone()],
    ] {
        let issuer = Recording {
            asked: Cell::new(None),
        };

        decide(
            &mut SequentialDecisionIds::new(),
            &issuer,
            &taken(&context, &action, &resource),
            &Authority {
                combined: Combined::ApprovalRequired,
                revision: None,
                policy_version: None,
                challenges,
            },
        )
        .expect_err("an approval requirement is not an allow");

        assert_eq!(issuer.asked.get(), Some(ChallengeRequirement::Approval));
    }
}

/// Both requirements `mandate_policy::port::ChallengeRequirement` declares, and what each
/// comes to. The contract carries the choice nowhere — `mandate.core.DecisionChallenge`
/// declares `action`, `resource`, `approver_policy` and `expires_at` and no requirement
/// (`crates/mandate-model/src/lib.rs:103-116`) — so a reauthentication cannot be expressed
/// and fails closed rather than being issued as an approval, which would name an approver
/// for something the caller clears by itself. The gap is
/// `mandate.core.DecisionChallenge.requirement`; closing it is an ESS and `mandate-model`
/// change outside this story.
///
/// The `match` in `decide` is exhaustive over the enum, so a third requirement does not
/// compile until it is placed; the two that exist are decided here.
#[test]
fn each_challenge_requirement_comes_to_what_the_contract_can_express() {
    let context = context();
    let action = action();
    let resource = resource();

    for (requirement, reason, challenged, dated) in [
        (
            ChallengeRequirement::Approval,
            DenialReason::ApprovalRequired,
            true,
            Some(ChallengeRequirement::Approval),
        ),
        (
            ChallengeRequirement::Reauthentication,
            DenialReason::Unavailable,
            false,
            None,
        ),
    ] {
        let issuer = Recording {
            asked: Cell::new(None),
        };

        let refusal = decide(
            &mut SequentialDecisionIds::new(),
            &issuer,
            &taken(&context, &action, &resource),
            &Authority {
                combined: Combined::ApprovalRequired,
                revision: None,
                policy_version: None,
                challenges: vec![Challenge {
                    requirement,
                    correlation: CorrelationId::new("correlation"),
                }],
            },
        )
        .expect_err("neither requirement is an allow");

        assert_eq!(refusal.reason, reason, "requirement {requirement:?}");
        assert_eq!(
            refusal.decision.challenge.is_some(),
            challenged,
            "requirement {requirement:?}"
        );
        assert_eq!(
            issuer.asked.get(),
            dated,
            "a challenge that is not issued is not dated either"
        );
    }
}

/// A refusal taken before any port was read is assembled by the same path as every other
/// decision, and carries nothing it did not read.
#[test]
fn a_binding_refusal_is_assembled_as_a_decision_too() {
    let context = context();
    let action = action();
    let resource = resource();

    let refusal = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &Authority::refused(DenialReason::AudienceMismatch),
    )
    .expect_err("the audience does not match");

    assert_eq!(refusal.reason, DenialReason::AudienceMismatch);
    assert!(!refusal.decision.allowed);
    assert_eq!(refusal.decision.reason, DecisionReason::AudienceMismatch);
    assert_eq!(refusal.decision.revision, None);
    assert_eq!(refusal.decision.policy_version, None);
    assert_eq!(refusal.decision.challenge, None);
}

/// Every reason the contract declares is *mapped* under its own name, and the set is read
/// from the contract's own variant list rather than from a list maintained here: a reason
/// added to `mandate.core.DenialReason` is covered by this test the day it is declared.
///
/// What this proves is the mapping — `declared`, and a folded authority carrying a reason
/// reaching the caller under it — and not that `crate::check` can produce all seven. It
/// cannot: the authority is constructed here rather than run, and the reasons a real
/// request can reach today are enumerated by
/// `check_contract.rs`'s `the_reasons_a_check_can_produce_today_are_these_six`, which is
/// where `StaleEpoch`'s absence is recorded.
///
/// `ApprovalRequired` is the one reason with a further condition when it arrives as the
/// fold's own outcome rather than as a source's refusal: it needs something to clear, or it
/// is an absence rather than a requirement
/// (`an_approval_requirement_naming_nothing_to_clear_fails_closed_as_unavailable`). The
/// authority is built with what each reason needs so that all seven are decided here,
/// rather than the loop excusing one of them.
#[test]
fn every_declared_denial_reason_is_told_under_its_own_name() {
    let context = context();
    let action = action();
    let resource = resource();

    assert_eq!(DenialReason::VARIANTS.len(), 7);
    for reason in DenialReason::VARIANTS {
        let told = declared(*reason);

        assert_eq!(
            format!("{told:?}"),
            format!("{reason:?}"),
            "every denial reason is told under its own name"
        );
        assert!(DecisionReason::VARIANTS.contains(&told));

        let mut authority = Authority::refused(*reason);
        if *reason == DenialReason::ApprovalRequired {
            authority.combined = Combined::ApprovalRequired;
            authority.challenges = vec![Challenge {
                requirement: ChallengeRequirement::Approval,
                correlation: CorrelationId::new("correlation"),
            }];
        }

        let refusal: Denied = decide(
            &mut SequentialDecisionIds::new(),
            &issuer(),
            &taken(&context, &action, &resource),
            &authority,
        )
        .expect_err("no refusal is an allow");

        assert_eq!(refusal.reason, *reason);
        assert_eq!(refusal.decision.reason, told);
        assert!(!refusal.decision.allowed);
    }
}

/// An approval requirement reaches the fold two ways — as its own outcome, and as a
/// source's refusal naming that reason — and the caller is answered the same way by both.
/// A refusal carries no material of its own (`mandate_policy::port::PolicyError` has no
/// room for any), so the requirement defaults to the strictest there is and the challenge
/// is issued all the same: a decision that states an approval is required and withholds
/// what would clear it answers nothing.
#[test]
fn both_shapes_of_an_approval_requirement_answer_the_caller_the_same_way() {
    let context = context();
    let action = action();
    let resource = resource();

    let refused = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &Authority::refused(DenialReason::ApprovalRequired),
    )
    .expect_err("a refusal is not an allow");
    let asked = decide(
        &mut SequentialDecisionIds::new(),
        &issuer(),
        &taken(&context, &action, &resource),
        &approval_required(),
    )
    .expect_err("an approval requirement is not an allow");

    assert_eq!(refused.reason, DenialReason::ApprovalRequired);
    assert_eq!(asked.reason, DenialReason::ApprovalRequired);
    assert_eq!(
        refused.decision.challenge, asked.decision.challenge,
        "one requirement, one challenge, however it reached the fold"
    );
    assert!(
        refused.decision.challenge.is_some(),
        "a decision that states an approval is required states what would clear it"
    );
}

/// The one reason that is not a refusal has no producer here: a decision reports
/// `Allowed` only by being an allow.
#[test]
fn allowed_is_the_one_decision_reason_no_refusal_can_carry() {
    let context = context();
    let action = action();
    let resource = resource();

    for reason in DenialReason::VARIANTS {
        let refusal = decide(
            &mut SequentialDecisionIds::new(),
            &issuer(),
            &taken(&context, &action, &resource),
            &Authority::refused(*reason),
        )
        .expect_err("no refusal is an allow");

        assert_ne!(refusal.decision.reason, DecisionReason::Allowed);
    }
}
