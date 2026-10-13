//! The `mandate.delegation` commands: `CreateDelegation`, `RevokeDelegation`, `RetireAgent`,
//! `CompleteExecution` and `ConsumeApproval`, each decided over the records the agent
//! authority evaluator reads.
//!
//! `systems/mandate/domains/delegation.yaml` declares six commands; the sixth,
//! `SupersedeAgentCapabilityCeiling`, stays deferred on `story:agent-security` because ESS
//! cannot yet express a create beside a move in one outcome
//! (`docs/plans/2026-10-13-wave-7-execution.md`, "Spec first").
//!
//! # Decide, apply, fold
//!
//! The split `mandate_model::tenancy` and `mandate_model::workload` keep:
//!
//! * each `decide_*` function reads [`AgentAuthorityRead`] — and, for a clause no record
//!   answers, [`DelegationAdmission`] — and returns the declared event or [`Denied`]. It writes
//!   nothing;
//! * [`crate::event::DelegationProjection::apply`] writes the event, re-checking nothing;
//! * [`crate::event::DelegationProjection::fold`] applies a whole log.
//!
//! A refusal emits nothing and moves no record: the decide half has nothing to write with.
//!
//! # What a refusal discloses
//!
//! Every refusal carries `mandate.delegation.Denied` with one [`DenialReason`]. A record no
//! read carries and a record of another organization refuse with the same value — reason,
//! branch and clause — so a caller cannot tell "no such record" from "not yours" by reading
//! one (`story:unknown-instance-non-disclosing`; `crate::agent` applies the same rule to the
//! records a request names). A record of the caller's own organization that is already in
//! its terminal state is the declared `wrong-state`.
//!
//! # External refusals read through one port
//!
//! The clauses that are a judgement no record answers — whether a caller holds delegation,
//! revocation or agent-administration authority, and whether an audience is registered — are
//! read through [`DelegationAdmission`], the one substitutable admission port of this command
//! family. No implementation of it ships here: authority is `decision-blocker:guards`', the
//! audience registry is `mandate-token`'s, and [`ConfiguredDelegationAdmission`] is the double
//! a caller under test arranges.
//!
//! # `CreateDelegation`
//!
//! The delegator is the verified subject of the creating request, never an input. The request
//! is refused, in this order, when the caller lacks delegation authority; when its context is
//! itself delegated (a delegation created under one would hand on authority that was
//! delegated once: transitive); when the delegator is not an active principal; when the
//! delegate is not an active principal with an installed agent record of this organization;
//! when the audience is not registered; when the execution binding names no open execution
//! the delegate holds for the delegator; when the delegate has no current applicable ceiling
//! or two on one key; when the scope is not within the ceilings — through
//! [`crate::agent::intersect`], the evaluator's own intersection, which must keep every action
//! and resource requested and confine to the same space; when `expires_at - created_at` is not
//! inside `(0, max_delegation_ttl]` for the smallest `max_delegation_ttl` over the delegate's
//! applicable platform and tenant ceilings, read by [`mandate_types::Duration::seconds`]; and
//! when policy, asked about the delegator for every action on every resource of the scope,
//! requires an approval (the grant would skip it) or does not allow it.
//!
//! # Every denial clause this module does not realize
//!
//! Quoted from the declared causes; `contracts/obligations/authz.json` carries each as a
//! `blocked_on` row.
//!
//! * `CreateDelegation` — "requested scope/expiry exceeds source/delegation/policy limits":
//!   the delegator's own authority is the graph's and is not read here; policy is read, and
//!   the ceilings are, under the sibling clause "agent ceilings". `decision-blocker:guards`.
//! * `RevokeDelegation` — "durable revocation and affected exchange invalidation fail";
//!   `CompleteExecution` — "completion cannot durably stop further tool calls bound to it";
//!   `ConsumeApproval` — "one-use consumption cannot commit atomically with that decision".
//!   Each needs durable storage. `decision-blocker:epoch-atomicity`.
//! * `ConsumeApproval` — "its subject/actor/action/resource": the check being satisfied is
//!   not an input of the command, so only the subject and actor the context carries are
//!   compared (the sibling clause "Caller does not hold the decision context the approval
//!   answers"), and the action and resource wait for an approval input to `Check`
//!   (decision 9 of the wave). `story:agent-security`.

use mandate_policy::port::{AttributeSet, PolicyEffect, PolicyEvaluator, PolicyRequest};
use mandate_types::{
    ApprovalId, Audience, AuthorityScope, AuthoritySubject, DelegationId, DenialReason,
    ExecutionId, OrganizationId, PrincipalId, Timestamp, Uuid, VerifiedContext,
};

use crate::agent::{AgentAuthorityRead, AuthorityClause, PrincipalStanding, Unavailable, instant};
use crate::delegation::{AgentState, ApprovalState, DelegationState, ExecutionState};
use crate::event::{DelegationCreated, DelegationEvent};

/// The declared branch a refusal is answered through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedAs {
    /// `denied`.
    Denied,
    /// `wrong-state`: a record of the caller's own organization already in its terminal
    /// state.
    WrongState,
}

impl RefusedAs {
    /// The outcome's name in the compiled contract.
    #[must_use]
    pub const fn ir_name(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::WrongState => "wrong-state",
        }
    }
}

/// Which declared condition a refusal is an instance of.
///
/// A crate-local discriminator, not a contract field: the contract's error payload is
/// [`DenialReason`] alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DelegationClause {
    /// The admission does not hold the caller's authority for the command.
    CallerUnauthorized,
    /// The creating context is itself delegated, so the grant would be transitive.
    Transitive,
    /// The delegator is not an active principal.
    SubjectInvalid,
    /// The delegate is not an active, installed agent of the verified organization.
    DelegateInvalid,
    /// The audience is not registered for the verified organization.
    AudienceUnregistered,
    /// The execution binding names no open execution the delegate holds for the delegator.
    ExecutionBindingFails,
    /// The scope and the delegate's ceilings confine to different spaces.
    SpaceConflict,
    /// The scope or the window is not within the delegate's current applicable ceilings.
    ExceedsCeilings,
    /// Policy requires an approval for part of the scope.
    ApprovalRequired,
    /// Policy does not allow part of the scope.
    PolicyLimit,
    /// The record is in another organization, or no record carries the identity.
    RecordOutside,
    /// The caller is not the agent that holds the execution.
    NotTheRuntime,
    /// The caller is not the subject and actor of the decision the approval answers.
    NotTheDecisionContext,
    /// The approval's `expires_at` has passed.
    ApprovalExpired,
    /// The record is in its terminal state.
    WrongState,
    /// A read could not be answered.
    Unavailable,
}

/// `mandate.delegation.Denied`: the command refused, and nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied {
    /// The declared reason. This is what crosses the wire.
    pub reason: DenialReason,
    /// The declared branch.
    pub outcome: RefusedAs,
    /// The condition refused on.
    pub clause: DelegationClause,
}

impl Denied {
    const fn on(clause: DelegationClause) -> Self {
        let (reason, outcome) = match clause {
            DelegationClause::Unavailable => (DenialReason::Unavailable, RefusedAs::Denied),
            DelegationClause::WrongState => (DenialReason::Denied, RefusedAs::WrongState),
            _ => (DenialReason::Denied, RefusedAs::Denied),
        };
        Self {
            reason,
            outcome,
            clause,
        }
    }
}

/// A read the port could not answer: refused, as `Unavailable`.
const fn unavailable(_: Unavailable) -> Denied {
    Denied::on(DelegationClause::Unavailable)
}

/// The judgements of this command family no record answers.
pub trait DelegationAdmission {
    /// Whether this verified caller may delegate (`CreateDelegation`).
    fn admits_delegation(&self, context: &VerifiedContext) -> bool;

    /// Whether `audience` is registered for `organization` (`CreateDelegation`).
    fn admits_audience(&self, organization: &OrganizationId, audience: &Audience) -> bool;

    /// Whether this verified caller may revoke delegations (`RevokeDelegation`).
    fn admits_delegation_revocation(&self, context: &VerifiedContext) -> bool;

    /// Whether this verified caller may administer agents (`RetireAgent`).
    fn admits_agent_administration(&self, context: &VerifiedContext) -> bool;
}

/// A [`DelegationAdmission`] that admits exactly what it was built with, and nothing by
/// default.
///
/// A fixture, never a shipped implementation; `pub` because every file under `tests/`
/// compiles as its own crate. Each authority is held by the verified subject.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfiguredDelegationAdmission {
    delegators: Vec<PrincipalId>,
    revokers: Vec<PrincipalId>,
    agent_administrators: Vec<PrincipalId>,
    audiences: Vec<(OrganizationId, Audience)>,
}

impl ConfiguredDelegationAdmission {
    /// An admission that admits nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit this subject's delegations.
    #[must_use]
    pub fn with_delegator(mut self, principal: PrincipalId) -> Self {
        self.delegators.push(principal);
        self
    }

    /// Admit this subject's revocations.
    #[must_use]
    pub fn with_revoker(mut self, principal: PrincipalId) -> Self {
        self.revokers.push(principal);
        self
    }

    /// Admit this subject's agent administration.
    #[must_use]
    pub fn with_agent_administrator(mut self, principal: PrincipalId) -> Self {
        self.agent_administrators.push(principal);
        self
    }

    /// Register this audience for that organization.
    #[must_use]
    pub fn with_audience(mut self, organization: OrganizationId, audience: Audience) -> Self {
        self.audiences.push((organization, audience));
        self
    }
}

impl DelegationAdmission for ConfiguredDelegationAdmission {
    fn admits_delegation(&self, context: &VerifiedContext) -> bool {
        self.delegators.contains(&context.subject)
    }

    fn admits_audience(&self, organization: &OrganizationId, audience: &Audience) -> bool {
        self.audiences
            .iter()
            .any(|(held, registered)| held == organization && registered == audience)
    }

    fn admits_delegation_revocation(&self, context: &VerifiedContext) -> bool {
        self.revokers.contains(&context.subject)
    }

    fn admits_agent_administration(&self, context: &VerifiedContext) -> bool {
        self.agent_administrators.contains(&context.subject)
    }
}

/// Mints the identity a created delegation is recorded under.
///
/// `mandate_types::Uuid` has no generator, so nothing in this crate can mint one.
pub trait DelegationIdAllocator {
    /// A new identity. Every call answers a new one.
    fn next_delegation_id(&mut self) -> DelegationId;
}

/// A deterministic [`DelegationIdAllocator`], for a caller under test.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequentialDelegationIds {
    issued: u64,
}

impl SequentialDelegationIds {
    /// An allocator that has issued nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self { issued: 0 }
    }

    /// How many identities it has issued.
    #[must_use]
    pub const fn issued(&self) -> u64 {
        self.issued
    }
}

impl DelegationIdAllocator for SequentialDelegationIds {
    fn next_delegation_id(&mut self) -> DelegationId {
        self.issued += 1;
        let mut bytes = [0_u8; 16];
        bytes[0] = b'g';
        bytes[8..].copy_from_slice(&self.issued.to_be_bytes());
        DelegationId::new(Uuid::from_bytes(bytes))
    }
}

/// The declared input of `mandate.delegation.CreateDelegation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDelegation {
    /// The creating request's verified context; its subject is the delegator.
    pub context: VerifiedContext,
    /// The agent the authority is delegated to.
    pub delegate: PrincipalId,
    /// The authority delegated.
    pub scope: AuthorityScope,
    /// The audience the delegation is for.
    pub audience: Audience,
    /// When the delegation stops being in force.
    pub expires_at: Timestamp,
    /// When it starts to be in force, when not at creation.
    pub not_before: Option<Timestamp>,
    /// The execution it is bound to, when bound to one.
    pub execution_binding: Option<ExecutionId>,
}

/// What an accepted `CreateDelegation` returns: the event, and the declared response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    /// `mandate.delegation.DelegationCreated`.
    pub event: DelegationEvent,
    /// The response's `delegation_id`.
    pub delegation_id: DelegationId,
    /// The response's `delegator`: the verified subject.
    pub delegator: PrincipalId,
}

/// The decide half of `mandate.delegation.CreateDelegation`, at the instant `at`, which is
/// the delegation's `created_at`.
///
/// An identity is allocated only once every check has passed.
///
/// # Errors
///
/// [`Denied`] on each condition the module documentation lists, in that order.
pub fn decide_create_delegation<R, P, A, I>(
    records: &R,
    policy: &P,
    admission: &A,
    allocator: &mut I,
    input: &CreateDelegation,
    at: &Timestamp,
) -> Result<Created, Denied>
where
    R: AgentAuthorityRead + ?Sized,
    P: PolicyEvaluator + ?Sized,
    A: DelegationAdmission + ?Sized,
    I: DelegationIdAllocator + ?Sized,
{
    let context = &input.context;
    let organization = &context.organization;
    let delegator = context.subject;

    if !admission.admits_delegation(context) {
        return Err(Denied::on(DelegationClause::CallerUnauthorized));
    }
    if !crate::context::direct(context) {
        return Err(Denied::on(DelegationClause::Transitive));
    }
    if records.standing(&delegator).map_err(unavailable)? != Some(PrincipalStanding::Active) {
        return Err(Denied::on(DelegationClause::SubjectInvalid));
    }
    let installed = records
        .agent(&input.delegate)
        .map_err(unavailable)?
        .is_some_and(|agent| {
            agent.organization_id == *organization && agent.state == AgentState::Recorded
        });
    if !installed
        || records.standing(&input.delegate).map_err(unavailable)?
            != Some(PrincipalStanding::Active)
    {
        return Err(Denied::on(DelegationClause::DelegateInvalid));
    }
    if !admission.admits_audience(organization, &input.audience) {
        return Err(Denied::on(DelegationClause::AudienceUnregistered));
    }

    let created = instant::parse(at).ok_or(Denied::on(DelegationClause::ExceedsCeilings))?;
    if let Some(id) = &input.execution_binding {
        let open = records
            .execution(id)
            .map_err(unavailable)?
            .is_some_and(|execution| {
                execution.organization_id == *organization
                    && execution.state == ExecutionState::Recorded
                    && execution.agent_id == input.delegate
                    && execution.subject == Some(delegator)
                    && instant::parse(&execution.expires_at).is_some_and(|ends| created < ends)
            });
        if !open {
            return Err(Denied::on(DelegationClause::ExecutionBindingFails));
        }
    }

    let recorded = records.ceilings(&input.delegate).map_err(unavailable)?;
    within_ceilings(&recorded, input, created)?;
    approved(policy, context, &input.scope)?;

    let id = allocator.next_delegation_id();
    Ok(Created {
        event: DelegationEvent::Created(Box::new(DelegationCreated {
            context: context.clone(),
            id,
            delegator,
            delegate: input.delegate,
            scope: input.scope.clone(),
            audience: input.audience.clone(),
            not_before: input.not_before.clone(),
            expires_at: input.expires_at.clone(),
            execution_binding: input.execution_binding,
            created_at: at.clone(),
        })),
        delegation_id: id,
        delegator,
    })
}

/// The scope and the window are within the delegate's current applicable ceilings.
fn within_ceilings(
    recorded: &[crate::delegation::AgentCapabilityCeiling],
    input: &CreateDelegation,
    created: instant::Instant,
) -> Result<(), Denied> {
    let exceeds = Denied::on(DelegationClause::ExceedsCeilings);
    let ceilings = crate::agent::applicable(recorded, &input.delegate, &input.context.organization)
        .map_err(|_| exceeds)?;

    // The evaluator's own intersection. A delegation is created for exactly what was asked
    // or not at all: an action, a resource or a space the ceilings narrow away is refused
    // rather than silently dropped, and a scope with nothing in it delegates nothing.
    let permitted = match crate::agent::intersect(&input.scope, &[], &ceilings) {
        Ok(permitted) => permitted,
        Err(AuthorityClause::SpaceConflict) => {
            return Err(Denied::on(DelegationClause::SpaceConflict));
        }
        Err(_) => return Err(exceeds),
    };
    let scope = &input.scope;
    let kept = scope
        .actions
        .iter()
        .all(|action| permitted.actions.contains(action))
        && scope.resources.iter().all(|resource| {
            permitted
                .resources
                .iter()
                .any(|kept| kept.resource_id == resource.resource_id)
        });
    if !kept || permitted.actions.is_empty() || permitted.resources.is_empty() {
        return Err(exceeds);
    }
    if permitted.space != scope.space {
        return Err(exceeds);
    }

    // `expires_at - created_at` inside `(0, smallest max_delegation_ttl]`; a ttl or a
    // timestamp that names nothing bounds nothing, and is refused.
    let mut smallest: Option<i64> = None;
    for ceiling in &ceilings {
        let ttl = ceiling.max_delegation_ttl.seconds().ok_or(exceeds)?;
        smallest = Some(smallest.map_or(ttl, |held| held.min(ttl)));
    }
    let limit = created
        .plus_seconds(smallest.ok_or(exceeds)?)
        .ok_or(exceeds)?;
    let ends = instant::parse(&input.expires_at).ok_or(exceeds)?;
    if ends <= created || ends > limit {
        return Err(exceeds);
    }
    if let Some(not_before) = &input.not_before {
        let starts = instant::parse(not_before).ok_or(exceeds)?;
        if starts >= ends {
            return Err(exceeds);
        }
    }
    Ok(())
}

/// Policy allows the delegator every action of the scope on every resource, outright.
fn approved<P: PolicyEvaluator + ?Sized>(
    policy: &P,
    context: &VerifiedContext,
    scope: &AuthorityScope,
) -> Result<(), Denied> {
    let subject = AuthoritySubject::Principal(context.subject);
    let attributes = AttributeSet::new();
    for action in &scope.actions {
        for resource in &scope.resources {
            let answer = policy.evaluate(&PolicyRequest {
                context,
                subject: &subject,
                action,
                resource,
                attributes: &attributes,
            });
            let clause = match answer {
                Ok(evaluation) => match (evaluation.effect, evaluation.challenge) {
                    (PolicyEffect::Allow, None) => continue,
                    (PolicyEffect::ApprovalRequired, _) | (PolicyEffect::Allow, Some(_)) => {
                        DelegationClause::ApprovalRequired
                    }
                    (PolicyEffect::Deny, _) => DelegationClause::PolicyLimit,
                },
                Err(refusal) => match refusal.denial_reason() {
                    DenialReason::ApprovalRequired => DelegationClause::ApprovalRequired,
                    DenialReason::Unavailable => DelegationClause::Unavailable,
                    _ => DelegationClause::PolicyLimit,
                },
            };
            return Err(Denied::on(clause));
        }
    }
    Ok(())
}

/// The decide half of `mandate.delegation.RevokeDelegation`.
///
/// # Errors
///
/// [`Denied`] when the caller lacks revocation authority, when the delegation is in another
/// organization or unrecorded, and — as `wrong-state` — when it is already revoked.
pub fn decide_revoke_delegation<R, A>(
    records: &R,
    admission: &A,
    context: &VerifiedContext,
    id: DelegationId,
) -> Result<DelegationEvent, Denied>
where
    R: AgentAuthorityRead + ?Sized,
    A: DelegationAdmission + ?Sized,
{
    if !admission.admits_delegation_revocation(context) {
        return Err(Denied::on(DelegationClause::CallerUnauthorized));
    }
    let delegation = records
        .delegation(&id)
        .map_err(unavailable)?
        .filter(|delegation| delegation.organization_id == context.organization)
        .ok_or(Denied::on(DelegationClause::RecordOutside))?;
    if delegation.state == DelegationState::Revoked {
        return Err(Denied::on(DelegationClause::WrongState));
    }
    Ok(DelegationEvent::Revoked {
        context: context.clone(),
        id,
    })
}

/// The decide half of `mandate.delegation.RetireAgent`.
///
/// # Errors
///
/// [`Denied`] when the caller lacks agent-administration authority, when the agent is in
/// another organization or unrecorded, and — as `wrong-state` — when it is already retired.
pub fn decide_retire_agent<R, A>(
    records: &R,
    admission: &A,
    context: &VerifiedContext,
    id: PrincipalId,
) -> Result<DelegationEvent, Denied>
where
    R: AgentAuthorityRead + ?Sized,
    A: DelegationAdmission + ?Sized,
{
    if !admission.admits_agent_administration(context) {
        return Err(Denied::on(DelegationClause::CallerUnauthorized));
    }
    let agent = records
        .agent(&id)
        .map_err(unavailable)?
        .filter(|agent| agent.organization_id == context.organization)
        .ok_or(Denied::on(DelegationClause::RecordOutside))?;
    if agent.state == AgentState::Retired {
        return Err(Denied::on(DelegationClause::WrongState));
    }
    Ok(DelegationEvent::AgentRetired {
        context: context.clone(),
        id,
    })
}

/// The decide half of `mandate.delegation.CompleteExecution`.
///
/// The caller is the agent runtime that holds the execution when the acting principal — the
/// actor, or the subject acting as itself — is the execution's agent. That is checked before
/// the state, so a caller that does not hold the execution learns nothing about it.
///
/// # Errors
///
/// [`Denied`] when the execution is in another organization or unrecorded, when the caller
/// is not its agent, and — as `wrong-state` — when it is already completed.
pub fn decide_complete_execution<R>(
    records: &R,
    context: &VerifiedContext,
    id: ExecutionId,
) -> Result<DelegationEvent, Denied>
where
    R: AgentAuthorityRead + ?Sized,
{
    let execution = records
        .execution(&id)
        .map_err(unavailable)?
        .filter(|execution| execution.organization_id == context.organization)
        .ok_or(Denied::on(DelegationClause::RecordOutside))?;
    if context.actor.unwrap_or(context.subject) != execution.agent_id {
        return Err(Denied::on(DelegationClause::NotTheRuntime));
    }
    if execution.state == ExecutionState::Completed {
        return Err(Denied::on(DelegationClause::WrongState));
    }
    Ok(DelegationEvent::ExecutionCompleted {
        context: context.clone(),
        id,
    })
}

/// The decide half of `mandate.delegation.ConsumeApproval`, at the instant `at`.
///
/// The caller holds the decision context the approval answers when its verified subject is
/// the approval's subject and its actor — absent when the subject acts as itself — is the
/// approval's actor. Checked before the state, as `CompleteExecution` checks its runtime.
///
/// # Errors
///
/// [`Denied`] when the approval is in another organization or unrecorded, when the caller
/// does not hold its decision context, as `wrong-state` when it is already consumed, and when
/// its `expires_at` is not after `at`.
pub fn decide_consume_approval<R>(
    records: &R,
    context: &VerifiedContext,
    id: ApprovalId,
    at: &Timestamp,
) -> Result<DelegationEvent, Denied>
where
    R: AgentAuthorityRead + ?Sized,
{
    let approval = records
        .approval(&id)
        .map_err(unavailable)?
        .filter(|approval| approval.organization_id == context.organization)
        .ok_or(Denied::on(DelegationClause::RecordOutside))?;
    let acting = context.actor.filter(|actor| *actor != context.subject);
    let approved = approval.actor.filter(|actor| *actor != approval.subject);
    if context.subject != approval.subject || acting != approved {
        return Err(Denied::on(DelegationClause::NotTheDecisionContext));
    }
    if approval.state == ApprovalState::Consumed {
        return Err(Denied::on(DelegationClause::WrongState));
    }
    let open = match (instant::parse(at), instant::parse(&approval.expires_at)) {
        (Some(now), Some(ends)) => now < ends,
        _ => false,
    };
    if !open {
        return Err(Denied::on(DelegationClause::ApprovalExpired));
    }
    Ok(DelegationEvent::ApprovalConsumed {
        context: context.clone(),
        id,
    })
}
