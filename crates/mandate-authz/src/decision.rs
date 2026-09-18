//! Assembling `mandate.core.Decision`, and the two things no port in the ceiling supplies.
//!
//! Every path through this crate ends here, the refusals that never read a port included,
//! so a decision has one assembly and one shape whatever produced it. What is assembled is
//! the record `authorization.yaml:24-26` declares as the command's response and
//! `authorization.yaml:28-33` carries in `mandate.authorization.DecisionRecorded`.
//!
//! # `allowed=false` is a decision, and it is carried on the refusal
//!
//! `mandate.core.Decision` declares `allowed: bool`, and `crates/mandate-model/src/lib.rs:180-188`
//! is the contract's own sample of an `allowed: false` decision carrying a challenge. The
//! command's `denied` outcome is an error with one field, `reason`
//! (`authorization.yaml:35-39`), so a refusal that returned only that reason would drop
//! the decision the PDP took — and with it the challenge the caller is supposed to answer
//! and the identifier the audit record correlates on. [`Denied`] therefore carries both:
//! `reason` is the declared error field, and `decision` is the decision that was taken.
//! Nothing is invented on the wire; what crosses it is `reason`.
//!
//! # `model_version` is absent, and this is why
//!
//! [`mandate_policy::port::Evaluation`] carries `version: PolicyVersion` and nothing else,
//! `mandate.policy.AuthorizationModel.version` is itself a `PolicyVersion`
//! (`crates/mandate-policy/src/record.rs:129`), and no port in this crate's dependency
//! ceiling returns an [`mandate_types::AuthorizationModelVersion`]. So every decision this
//! crate assembles records `model_version: None`. Filling it from the policy version would
//! attribute a decision to a model version nobody stated. Widening the policy port is a
//! later change and is not this story's.
//!
//! # An approval requirement is one answer, however it reached the fold
//!
//! `mandate.core.DenialReason::ApprovalRequired` reaches a caller two ways: as the fold's
//! own outcome ([`mandate_policy::precedence::Combined::ApprovalRequired`], "no source
//! refused, and at least one requires an approval first") and as a source's refusal naming
//! that reason. Both are answered the same way — `allowed = false`, `ApprovalRequired`, and
//! the challenge that would clear it — because a decision that states an approval is
//! required and carries nothing to answer withholds the one thing that satisfies it, and
//! `mandate.core.Decision`'s own approval-required sample carries the challenge
//! (`crates/mandate-model/src/lib.rs:180-188`). A refusal carries no material of its own, so
//! the requirement defaults to the strictest one there is: an approval, which the caller
//! cannot clear alone.
//!
//! # A reauthentication challenge cannot be expressed, and so is refused
//!
//! See the crate documentation: `mandate.core.DecisionChallenge` declares `action`,
//! `resource`, `approver_policy` and `expires_at` and **no requirement**
//! (`crates/mandate-model/src/lib.rs:103-116`), so a decision cannot tell a caller to
//! reauthenticate. Where [`mandate_policy::precedence::strictest`] selects
//! [`ChallengeRequirement::Reauthentication`], this module fails closed with
//! [`DenialReason::Unavailable`] rather than issuing it as an approval, which would name an
//! approver for something the caller clears by itself.
//!
//! # `Decision` declares no correlation, and does not need one
//!
//! The correlation a request carries is `VerifiedContext.correlation`, and
//! `mandate.authorization.DecisionRecorded` declares `context` beside `decision`
//! (`authorization.yaml:28-33`), so the event carries it. The challenge carries it too:
//! [`mandate_policy::port::Challenge::correlation`] is taken from the request, which is
//! what scopes a challenge to the request that provoked it.
//!
//! # Two ports are declared here
//!
//! On the precedent of `crates/mandate-federation/src/lib.rs:218`: a value a response
//! binds that no crate in the dependency ceiling can produce is a port, not a function.
//!
//! * [`DecisionIdAllocator`] — `mandate_types::Uuid` has `from_bytes` and `parse` and no
//!   generator (`crates/mandate-types/src/value.rs:52-73`), so nothing here can mint a
//!   `DecisionId`.
//! * [`ChallengeIssuer`] — `DecisionChallenge` declares `expires_at: Timestamp` and
//!   `approver_policy: PolicyId` (`crates/mandate-model/src/lib.rs:107-116`). Nothing in
//!   the ceiling tells the time, and [`mandate_policy::port::Challenge`] carries a
//!   requirement and a correlation but no policy identity, so neither value can be read
//!   from a port this crate already has. Both are asked of the issuer.
//!
//! Each has a deterministic double in this module, `pub` for the same reason
//! [`mandate_graph::double::GraphDouble`] is: a caller under test builds its scenarios
//! with it.

use mandate_model::{Decision, DecisionChallenge};
use mandate_policy::port::ChallengeRequirement;
use mandate_policy::precedence::{Combined, strictest};
use mandate_types::{
    Action, DecisionId, DecisionReason, DenialReason, OrganizationId, PolicyId, ResourceRef,
    Timestamp, Uuid, VerifiedContext,
};

use crate::evaluate::Authority;

/// The identity a decision is recorded under.
///
/// See the module documentation: nothing in the dependency ceiling generates a UUID.
pub trait DecisionIdAllocator {
    /// The identity this decision is recorded under. Every call answers a new one.
    fn next_decision_id(&mut self) -> DecisionId;
}

/// What an approval-required decision needs and no port in the ceiling answers.
pub trait ChallengeIssuer {
    /// When the challenge stops being answerable.
    fn expires_at(&self, context: &VerifiedContext, requirement: ChallengeRequirement)
    -> Timestamp;

    /// The policy that names the approver, for this organization.
    ///
    /// `None` is an absence, not a refusal about the caller: an approval that names no
    /// approver cannot be answered by anybody, so the decision fails closed as
    /// [`DenialReason::Unavailable`] rather than telling a caller to satisfy a challenge
    /// that does not exist.
    fn approver_policy(&self, organization: &OrganizationId) -> Option<PolicyId>;
}

/// The contract's three inputs, for the decision that is assembled from them.
#[derive(Debug)]
pub struct Taken<'a> {
    /// The context the request was made in (`authorization.yaml:6-7`).
    pub context: &'a VerifiedContext,
    /// The action requested (`authorization.yaml:8-9`).
    pub action: &'a Action,
    /// The resource the action is on (`authorization.yaml:10-11`).
    pub resource: &'a ResourceRef,
}

/// `mandate.authorization.Denied`: the request was refused, and the decision that refused
/// it.
///
/// See the module documentation for why the decision travels with the refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The declared reason (`authorization.yaml:37-39`). This is what crosses the wire.
    pub reason: DenialReason,
    /// The decision that was taken. `allowed` is always `false`.
    ///
    /// Boxed: `mandate.core.Decision` is several times the size of the reason beside it,
    /// and a refusal is returned on every path that is not an allow. Field access reaches
    /// through it, so `denied.decision.allowed` reads the same as it would unboxed.
    pub decision: Box<Decision>,
}

/// The reason a caller is told, as the decision record spells it.
///
/// `mandate.core.DecisionReason` is `mandate.core.DenialReason` plus `Allowed`
/// (`crates/mandate-types/src/enumeration.rs:9,:11`), and this is the identity between
/// them. The match is exhaustive, so a variant added to `DenialReason` does not compile
/// until it is named here rather than silently landing on a neighbour.
#[must_use]
pub const fn declared(reason: DenialReason) -> DecisionReason {
    match reason {
        DenialReason::Denied => DecisionReason::Denied,
        DenialReason::ApprovalRequired => DecisionReason::ApprovalRequired,
        DenialReason::InvalidCredential => DecisionReason::InvalidCredential,
        DenialReason::TenantMismatch => DecisionReason::TenantMismatch,
        DenialReason::AudienceMismatch => DecisionReason::AudienceMismatch,
        DenialReason::Unavailable => DecisionReason::Unavailable,
        DenialReason::StaleEpoch => DecisionReason::StaleEpoch,
    }
}

/// Assemble the decision the folded authority comes to.
///
/// # Errors
///
/// [`Denied`] for every outcome that is not an allow, carrying the decision that was
/// taken. An approval requirement is one of them: it is not a denial, and it is not an
/// allow either (`crates/mandate-policy/src/precedence.rs:98-118`).
pub fn decide<A, I>(
    allocator: &mut A,
    issuer: &I,
    taken: &Taken<'_>,
    authority: &Authority,
) -> Result<Decision, Denied>
where
    A: DecisionIdAllocator + ?Sized,
    I: ChallengeIssuer + ?Sized,
{
    // Minted first, and for every outcome: a refusal the caller is told about is a
    // decision that was taken, and an audit record, an approval and a later reading of
    // either all point at the identity it was taken under.
    let decision_id = allocator.next_decision_id();

    if authority.combined.allowed() {
        return Ok(Decision {
            allowed: true,
            reason: DecisionReason::Allowed,
            decision_id,
            revision: authority.revision.clone(),
            challenge: None,
            policy_version: authority.policy_version.clone(),
            model_version: None,
        });
    }

    // `Combined` is total across `allowed` and `denial_reason`: a result either allows or
    // names a reason (`crates/mandate-policy/src/precedence.rs:98-118`). The fallback is
    // the closed direction for a shape that cannot occur, not a reason invented here.
    let combined = authority
        .combined
        .denial_reason()
        .unwrap_or(DenialReason::Denied);

    // Which challenge to issue is precedence's, not this crate's, and not the order the
    // sources happened to arrive in.
    let requirement = strictest(
        &authority
            .challenges
            .iter()
            .map(|challenge| challenge.requirement)
            .collect::<Vec<_>>(),
    );

    // An approval requirement reaches the fold two ways, and a caller is owed the same
    // answer by both. As the fold's own outcome, `Combined::ApprovalRequired` is "no source
    // refused, and at least one requires an approval first". As a source's refusal,
    // `Combined::Denied(DenialReason::ApprovalRequired)` is a decision policy made and
    // named — `mandate_policy::port::PolicyError` carries no material beside it, having no
    // room for any. Either way the answer is the same one the contract's own sample
    // declares (`crates/mandate-model/src/lib.rs:180-188`): `allowed = false`,
    // `ApprovalRequired`, and the challenge that would clear it. A decision naming an
    // approval and carrying nothing to answer would state a requirement and withhold the
    // one thing that satisfies it.
    let approval_required = matches!(
        authority.combined,
        Combined::ApprovalRequired | Combined::Denied(DenialReason::ApprovalRequired)
    );

    let (reason, challenge) = if approval_required {
        // Nothing named a requirement, so the strictest one there is applies: a second
        // party has to act (`crates/mandate-policy/src/precedence.rs:226-240`). Defaulting
        // to the one the caller *cannot* clear alone is the closed direction.
        match requirement.unwrap_or(ChallengeRequirement::Approval) {
            ChallengeRequirement::Approval => {
                match issuer.approver_policy(&taken.context.organization) {
                    Some(approver_policy) => (
                        DenialReason::ApprovalRequired,
                        Some(DecisionChallenge {
                            action: taken.action.clone(),
                            resource: taken.resource.clone(),
                            approver_policy,
                            expires_at: issuer
                                .expires_at(taken.context, ChallengeRequirement::Approval),
                        }),
                    ),
                    // An approval that names no approver cannot be cleared by anybody.
                    // Telling the caller to satisfy it would be an open direction dressed
                    // as a refusal, so the absence is reported as one.
                    None => (DenialReason::Unavailable, None),
                }
            }
            // The contract cannot express this challenge: see the crate documentation.
            // Issuing it as an approval would name an approver for something the caller
            // clears alone, so it fails closed until `mandate.core.DecisionChallenge`
            // carries the requirement.
            ChallengeRequirement::Reauthentication => (DenialReason::Unavailable, None),
        }
    } else {
        (combined, None)
    };

    Err(Denied {
        reason,
        decision: Box::new(Decision {
            allowed: false,
            reason: declared(reason),
            decision_id,
            revision: authority.revision.clone(),
            challenge,
            policy_version: authority.policy_version.clone(),
            model_version: None,
        }),
    })
}

/// A deterministic allocator, for a caller under test.
///
/// Mints each identity from a counter, so a scenario's decisions are the same identities
/// on every run and a test can state them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequentialDecisionIds {
    issued: u64,
}

impl SequentialDecisionIds {
    /// An allocator that has issued nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { issued: 0 }
    }

    /// How many identities this allocator has issued.
    #[must_use]
    pub const fn issued(&self) -> u64 {
        self.issued
    }
}

impl DecisionIdAllocator for SequentialDecisionIds {
    fn next_decision_id(&mut self) -> DecisionId {
        self.issued += 1;
        let mut bytes = [0_u8; 16];
        bytes[0] = b'd';
        bytes[8..].copy_from_slice(&self.issued.to_be_bytes());
        DecisionId::new(Uuid::from_bytes(bytes))
    }
}

/// A fixed issuer, for a caller under test: one deadline and one approver policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedChallenge {
    /// The deadline every challenge it issues carries.
    pub expires_at: Timestamp,
    /// The approver policy it names, or `None` for an organization it cannot name one
    /// for.
    pub approver_policy: Option<PolicyId>,
}

impl ChallengeIssuer for FixedChallenge {
    fn expires_at(
        &self,
        _context: &VerifiedContext,
        _requirement: ChallengeRequirement,
    ) -> Timestamp {
        self.expires_at.clone()
    }

    fn approver_policy(&self, _organization: &OrganizationId) -> Option<PolicyId> {
        self.approver_policy
    }
}
