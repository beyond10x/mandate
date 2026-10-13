//! The shared agent authority evaluator: what an agent may do for a subject, as the exact
//! intersection of every bound that applies.
//!
//! `docs/architecture/combined.md:53` makes effective authority the intersection of the
//! subject's authority, the **actor ceiling**, the **explicit delegation** and the requested
//! authority, inside the tenant binding and current policy. [`crate::check`] reads every one
//! of those bounds except the two in bold and refuses any request that carries them
//! ([`crate::context::direct`]). This module is the evaluator for the other kind of request,
//! the one `story:agent-authority-kernel` owns: an agent acting for itself, or for a subject
//! under a delegation. It is a reusable function for the token exchange to call. It issues
//! nothing, stores nothing and speaks no protocol: the records it reads arrive through
//! [`AgentAuthorityRead`], and policy is read through `mandate_policy`'s own
//! [`PolicyEvaluator`].
//!
//! # The permitted set
//!
//! Given a subject, an independently authenticated actor, the applicable ceilings, a
//! delegation and a requested capability, the permitted set is **exactly** the applicable
//! intersection and never exceeds any input bound:
//!
//! - an action is permitted when the request names it, both proofs' authority names it, the
//!   delegation's scope names it (on a delegated request), and every applicable current
//!   ceiling admits it — its `allowed_actions` cover it, its `denied_actions` do not, and its
//!   `scope.actions` name it;
//! - a resource is permitted when the request, both proofs, the delegation and every
//!   applicable ceiling's scope name it, by identity (the rule
//!   [`crate::evaluate::requested`] already applies);
//! - a space is permitted when every bound that names one names the same one; bounds naming
//!   two spaces permit nothing.
//!
//! The intersection narrows the request; an intersection with no action or no resource in it
//! permits nothing, and is refused. A bound grants nothing on its own: no source of authority
//! here is an allow, and an allow is the result of every bound admitting the same thing.
//!
//! # Ceilings: the key, the current record, and the conflict
//!
//! `decision-blocker:identity-uniqueness-ceiling` decided the rule this evaluator enforces,
//! and `systems/mandate/domains/delegation.yaml` records it: ceilings are keyed by
//! `(agent_id, organization_id)`, the current one per key is the latest still `Recorded`, a
//! ceiling recorded for another organization does not apply, and two current ceilings on one
//! key are the declared denial "two current capability ceilings share one agent and
//! organization-or-platform key". The evaluator never picks one of the two
//! ([`crate::delegation::current_ceilings`]). An agent with no applicable current ceiling is
//! refused: an intersection over no ceilings would bound nothing, which is the open direction.
//!
//! # Refusals
//!
//! Every refusal names an [`AuthorityClause`], and every clause names a verbatim phrase of
//! `mandate.credential.ExchangeCredential`'s declared denial (`tests/agent.rs` decides that
//! against `docs/architecture/command-obligations.md`). Refusals are decided in a fixed order
//! — chain, context, organization, proof expiry, principals, agent, delegation, ceilings,
//! intersection — and policy is read last, so every denial beats an approval requirement, and
//! an approval requirement is answered `allowed = false` with the challenge attached.
//!
//! # Expiry
//!
//! An allowed decision expires at the earliest of the subject proof's, the actor proof's and
//! the delegation's expiry, compared as instants: `Timestamp` orders on its bytes, and RFC 3339
//! byte order is not time order. The returned value is the input that named that instant,
//! verbatim. `max_delegation_ttl` bounds how long a delegation may be created for, which is
//! `CreateDelegation`'s to enforce and not read here.

use mandate_policy::port::{
    AttributeSet, Challenge, ChallengeRequirement, PolicyEvaluator, PolicyRequest,
};
use mandate_policy::precedence::{Combined, Component, combine};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthoritySubject, DecisionReason, DelegationId, DenialReason,
    OrganizationId, PrincipalId, ResourceRef, SpaceId, Timestamp, VerifiedContext,
};

use crate::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, Delegation, DelegationState, current_ceilings,
};
use crate::evaluate::covers;

/// What one independently validated proof established.
///
/// The fields are the ones `mandate.core.CredentialDescriptor` carries that bound authority;
/// the proof's validation is the caller's, and the evaluator reads only its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProof {
    /// The principal the proof was issued to.
    pub principal: PrincipalId,
    /// The organization the proof was validated in.
    pub organization: OrganizationId,
    /// The authority the proof carries. A bound, never a grant.
    pub authority: AuthorityScope,
    /// When the proof stops being valid.
    pub expires_at: Timestamp,
    /// The actor the proof was itself issued through, when it was. A proof that already
    /// carries an actor is authority that was delegated once, and is never delegated again.
    pub actor: Option<PrincipalId>,
    /// The delegation the proof was itself issued under, when it was.
    pub delegation: Option<DelegationId>,
}

/// The standing of a principal record (`mandate.identity.Principal`'s lifecycle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalStanding {
    /// `Active`.
    Active,
    /// The terminal `Disabled`.
    Disabled,
}

/// A read the port could not answer. Fails closed as [`DenialReason::Unavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unavailable;

/// The records the evaluator reads, behind one port.
///
/// Each read answers from current state. An adapter over the event log folds these; a test
/// answers them from a list. The evaluator writes nothing through it.
pub trait AgentAuthorityRead {
    /// The standing of a principal, or `None` when no principal is recorded.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the read cannot be answered.
    fn standing(&self, principal: &PrincipalId) -> Result<Option<PrincipalStanding>, Unavailable>;

    /// The agent record of a principal, or `None` when the principal is no agent.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the read cannot be answered.
    fn agent(&self, principal: &PrincipalId) -> Result<Option<Agent>, Unavailable>;

    /// Every ceiling recorded for the agent, superseded ones included, in recorded order.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the read cannot be answered.
    fn ceilings(&self, agent: &PrincipalId) -> Result<Vec<AgentCapabilityCeiling>, Unavailable>;

    /// The delegation record, or `None` when none is recorded.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when the read cannot be answered.
    fn delegation(&self, id: &DelegationId) -> Result<Option<Delegation>, Unavailable>;
}

/// What the evaluator is asked.
#[derive(Debug)]
pub struct AuthorityRequest<'a> {
    /// The credential-derived context the request is made in. Its organization is the
    /// tenancy bound, and it must name the proofs' subject, actor and delegation; policy is
    /// asked under it.
    pub context: &'a VerifiedContext,
    /// The subject's validated proof.
    pub subject: &'a ValidatedProof,
    /// The actor's independently validated proof. For an agent acting for itself, the same
    /// principal as the subject.
    pub actor: &'a ValidatedProof,
    /// The delegation the request is made under. Required exactly when the actor is not the
    /// subject.
    pub delegation: Option<&'a DelegationId>,
    /// The audience the requested authority is for; a delegation is for one audience.
    pub audience: &'a Audience,
    /// The requested capability.
    pub requested: &'a AuthorityScope,
    /// The attribute input policy evaluates against.
    pub attributes: &'a AttributeSet,
    /// The instant the request is evaluated at.
    pub at: &'a Timestamp,
}

/// Which declared denial phrase a refusal is an instance of.
///
/// A crate-local discriminator and not a contract field: the contract's error payload is
/// [`DenialReason`] alone. Every variant's [`AuthorityClause::phrase`] is a verbatim
/// substring of `mandate.credential.ExchangeCredential`'s declared denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AuthorityClause {
    /// A proof is expired at the evaluation instant.
    ProofExpired,
    /// A timestamp the evaluation compares names no instant, so no expiry can be bounded.
    ProofUnreadable,
    /// The subject's principal is disabled or unrecorded.
    SubjectInvalid,
    /// The actor's principal is disabled.
    ActorDisabled,
    /// The actor's principal is unrecorded, or is recorded as no agent.
    ActorNotAgent,
    /// The actor's agent record is retired.
    AgentRetired,
    /// The context does not name the proofs' subject, actor or delegation.
    ContextMismatch,
    /// A proof or record is bound to another organization than the context's.
    OrganizationMismatch,
    /// A delegated request names no delegation, or the delegation is unrecorded.
    DelegationAbsent,
    /// The delegation is revoked.
    DelegationRevoked,
    /// The delegation is expired at the evaluation instant.
    DelegationExpired,
    /// The delegation is not yet in force at the evaluation instant.
    DelegationNotYetInForce,
    /// The delegation names another delegator, delegate, audience or execution, or a
    /// request with no delegate names one.
    DelegationMismatch,
    /// No current ceiling applies to the agent.
    CeilingAbsent,
    /// Two current ceilings share one key.
    CeilingConflict,
    /// A delegation chain: a transitive delegation, or a proof itself issued through one.
    TransitiveChain,
    /// The bounds confine the request to different spaces.
    SpaceConflict,
    /// The intersection permits no action or no resource.
    NothingPermitted,
    /// Policy refused the request. The decision carries the reason policy declared.
    PolicyDenied,
    /// Policy requires an approval first.
    ApprovalRequired,
    /// A bound could not be read, so the intersection cannot be taken.
    Unavailable,
}

impl AuthorityClause {
    /// Every clause, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ProofExpired,
        Self::ProofUnreadable,
        Self::SubjectInvalid,
        Self::ActorDisabled,
        Self::ActorNotAgent,
        Self::AgentRetired,
        Self::ContextMismatch,
        Self::OrganizationMismatch,
        Self::DelegationAbsent,
        Self::DelegationRevoked,
        Self::DelegationExpired,
        Self::DelegationNotYetInForce,
        Self::DelegationMismatch,
        Self::CeilingAbsent,
        Self::CeilingConflict,
        Self::TransitiveChain,
        Self::SpaceConflict,
        Self::NothingPermitted,
        Self::PolicyDenied,
        Self::ApprovalRequired,
        Self::Unavailable,
    ];

    /// The phrase of `ExchangeCredential`'s declared denial this clause is an instance of.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::ProofExpired | Self::ProofUnreadable | Self::SubjectInvalid => {
                "Either independently validated proof is invalid/revoked/expired/stale"
            }
            Self::ActorDisabled
            | Self::ActorNotAgent
            | Self::AgentRetired
            | Self::ContextMismatch => "actor",
            Self::OrganizationMismatch => "tenant",
            Self::DelegationAbsent
            | Self::DelegationRevoked
            | Self::DelegationExpired
            | Self::DelegationNotYetInForce
            | Self::DelegationMismatch => "delegation or ceiling binding fails",
            Self::CeilingAbsent => "ceiling binding fails",
            Self::CeilingConflict => {
                "two current capability ceilings share one agent and organization-or-platform key"
            }
            Self::TransitiveChain => "transitive delegation is requested",
            Self::SpaceConflict => "space",
            Self::ApprovalRequired => "approval is required",
            Self::NothingPermitted | Self::PolicyDenied | Self::Unavailable => {
                "authority/expiry narrowing"
            }
        }
    }

    /// The declared reason a refusal on this clause carries, when the evaluator decides it.
    ///
    /// A [`Self::PolicyDenied`] refusal carries the reason policy declared instead, as
    /// `check` does; `Denied` here is that clause's reason only when policy found nothing.
    #[must_use]
    pub const fn reason(self) -> DenialReason {
        match self {
            Self::ProofExpired | Self::ProofUnreadable | Self::SubjectInvalid => {
                DenialReason::InvalidCredential
            }
            Self::OrganizationMismatch => DenialReason::TenantMismatch,
            Self::ApprovalRequired => DenialReason::ApprovalRequired,
            Self::Unavailable => DenialReason::Unavailable,
            _ => DenialReason::Denied,
        }
    }
}

/// What the evaluator decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDecision {
    /// Whether the permitted set may be used now. `false` for every refusal, and for an
    /// approval requirement.
    pub allowed: bool,
    /// The declared reason: `Allowed` exactly when `allowed`.
    pub reason: DecisionReason,
    /// The clause a refusal is an instance of; absent on an allow.
    pub clause: Option<AuthorityClause>,
    /// The subject, exactly as the subject's proof established it.
    pub subject: PrincipalId,
    /// The actor, exactly as the actor's proof established it.
    pub actor: PrincipalId,
    /// The permitted set: the exact applicable intersection, empty unless allowed.
    pub permitted: AuthorityScope,
    /// The earliest expiry across the inputs; present exactly when allowed.
    pub expires_at: Option<Timestamp>,
    /// The challenge material an approval requirement carries.
    pub challenges: Vec<Challenge>,
}

impl AuthorityDecision {
    fn refused(request: &AuthorityRequest<'_>, clause: AuthorityClause) -> Self {
        Self::not_allowed(request, clause, Vec::new())
    }

    /// A refusal whose reason its source declared, rather than the clause's own.
    fn refused_for(
        request: &AuthorityRequest<'_>,
        clause: AuthorityClause,
        reason: DecisionReason,
    ) -> Self {
        Self {
            reason,
            ..Self::refused(request, clause)
        }
    }

    fn not_allowed(
        request: &AuthorityRequest<'_>,
        clause: AuthorityClause,
        challenges: Vec<Challenge>,
    ) -> Self {
        Self {
            allowed: false,
            reason: decision_reason(clause.reason()),
            clause: Some(clause),
            subject: request.subject.principal,
            actor: request.actor.principal,
            permitted: AuthorityScope {
                actions: Vec::new(),
                resources: Vec::new(),
                space: None,
            },
            expires_at: None,
            challenges,
        }
    }
}

/// The decision reason a denial reason is told as.
const fn decision_reason(reason: DenialReason) -> DecisionReason {
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

/// Evaluate one agent authority request.
///
/// Reads the port and policy; writes nothing, and changes none of its inputs. See the module
/// documentation for the order refusals are decided in.
#[must_use]
pub fn evaluate_agent_authority<R, P>(
    records: &R,
    policy: &P,
    request: &AuthorityRequest<'_>,
) -> AuthorityDecision
where
    R: AgentAuthorityRead + ?Sized,
    P: PolicyEvaluator + ?Sized,
{
    match bounded(records, request) {
        Ok(bound) => decide(policy, request, bound),
        Err(clause) => AuthorityDecision::refused(request, clause),
    }
}

/// What every bound came to, before policy.
struct Bound {
    permitted: AuthorityScope,
    expires_at: Timestamp,
}

/// Decide every bound, in order, and take the intersection.
fn bounded<R>(records: &R, request: &AuthorityRequest<'_>) -> Result<Bound, AuthorityClause>
where
    R: AgentAuthorityRead + ?Sized,
{
    let subject = request.subject;
    let actor = request.actor;
    let context = request.context;
    let organization = &context.organization;
    let delegated = subject.principal != actor.principal;

    // A proof that already carries an actor or a delegation is authority that was delegated
    // once; acting on it again is a chain, whichever proof carries it.
    if [subject, actor]
        .iter()
        .any(|proof| proof.actor.is_some() || proof.delegation.is_some())
    {
        return Err(AuthorityClause::TransitiveChain);
    }

    // The context is credential-derived, and it must say what the proofs say.
    let context_actor = match context.actor {
        None => !delegated,
        Some(named) => named == actor.principal,
    };
    if context.subject != subject.principal
        || !context_actor
        || context.delegation.as_ref() != request.delegation
    {
        return Err(AuthorityClause::ContextMismatch);
    }

    if subject.organization != *organization || actor.organization != *organization {
        return Err(AuthorityClause::OrganizationMismatch);
    }

    let now = instant::parse(request.at).ok_or(AuthorityClause::ProofUnreadable)?;
    let mut expiry = Earliest::default();
    for proof in [subject, actor] {
        let ends = instant::parse(&proof.expires_at).ok_or(AuthorityClause::ProofUnreadable)?;
        if ends <= now {
            return Err(AuthorityClause::ProofExpired);
        }
        expiry.offer(ends, &proof.expires_at);
    }

    match (delegated, request.delegation) {
        (true, None) => return Err(AuthorityClause::DelegationAbsent),
        (false, Some(_)) => return Err(AuthorityClause::DelegationMismatch),
        _ => {}
    }

    let unavailable = |_: Unavailable| AuthorityClause::Unavailable;
    match records.standing(&subject.principal).map_err(unavailable)? {
        Some(PrincipalStanding::Active) => {}
        Some(PrincipalStanding::Disabled) | None => return Err(AuthorityClause::SubjectInvalid),
    }
    match records.standing(&actor.principal).map_err(unavailable)? {
        Some(PrincipalStanding::Active) => {}
        Some(PrincipalStanding::Disabled) => return Err(AuthorityClause::ActorDisabled),
        None => return Err(AuthorityClause::ActorNotAgent),
    }

    let agent = records
        .agent(&actor.principal)
        .map_err(unavailable)?
        .ok_or(AuthorityClause::ActorNotAgent)?;
    if agent.organization_id != *organization {
        return Err(AuthorityClause::OrganizationMismatch);
    }
    if agent.state == AgentState::Retired {
        return Err(AuthorityClause::AgentRetired);
    }

    let delegation = match request.delegation {
        Some(id) => Some(
            records
                .delegation(id)
                .map_err(unavailable)?
                .ok_or(AuthorityClause::DelegationAbsent)?,
        ),
        None => None,
    };
    if let Some(delegation) = &delegation {
        if delegation.organization_id != *organization {
            return Err(AuthorityClause::OrganizationMismatch);
        }
        if delegation.transitive {
            return Err(AuthorityClause::TransitiveChain);
        }
        if delegation.delegator != subject.principal
            || delegation.delegate != actor.principal
            || delegation.audience != *request.audience
            || delegation
                .execution_binding
                .is_some_and(|bound| context.execution != Some(bound))
        {
            return Err(AuthorityClause::DelegationMismatch);
        }
        if delegation.state == DelegationState::Revoked {
            return Err(AuthorityClause::DelegationRevoked);
        }
        if let Some(not_before) = &delegation.not_before {
            let starts = instant::parse(not_before).ok_or(AuthorityClause::ProofUnreadable)?;
            if now < starts {
                return Err(AuthorityClause::DelegationNotYetInForce);
            }
        }
        let ends =
            instant::parse(&delegation.expires_at).ok_or(AuthorityClause::ProofUnreadable)?;
        if ends <= now {
            return Err(AuthorityClause::DelegationExpired);
        }
        expiry.offer(ends, &delegation.expires_at);
    }
    let mut bounds: Vec<&AuthorityScope> = vec![&subject.authority, &actor.authority];
    if let Some(delegation) = &delegation {
        bounds.push(&delegation.scope);
    }

    let recorded = records.ceilings(&actor.principal).map_err(unavailable)?;
    let ceilings = current_ceilings(&recorded, &actor.principal, organization);
    if !ceilings.conflicts.is_empty() {
        return Err(AuthorityClause::CeilingConflict);
    }
    if ceilings.current.is_empty() {
        return Err(AuthorityClause::CeilingAbsent);
    }

    let permitted = intersect(request.requested, &bounds, &ceilings.current)?;
    if permitted.actions.is_empty() || permitted.resources.is_empty() {
        return Err(AuthorityClause::NothingPermitted);
    }
    let expires_at = expiry.value.ok_or(AuthorityClause::ProofUnreadable)?;
    Ok(Bound {
        permitted,
        expires_at,
    })
}

/// Ask policy about every permitted action on every permitted resource, and fold the answers
/// through deny precedence.
fn decide<P>(policy: &P, request: &AuthorityRequest<'_>, bound: Bound) -> AuthorityDecision
where
    P: PolicyEvaluator + ?Sized,
{
    let subject = AuthoritySubject::Principal(request.subject.principal);
    let mut components = Vec::new();
    let mut challenges = Vec::new();
    for action in &bound.permitted.actions {
        for resource in &bound.permitted.resources {
            match policy.evaluate(&PolicyRequest {
                context: request.context,
                subject: &subject,
                action,
                resource,
                attributes: request.attributes,
            }) {
                Ok(evaluation) => {
                    components.push(Component::of_effect(evaluation.effect));
                    if let Some(challenge) = evaluation.challenge {
                        components.push(Component::ApprovalRequired);
                        challenges.push(challenge);
                    }
                }
                Err(refusal) => components.push(Component::Denied(refusal.denial_reason())),
            }
        }
    }
    match combine(&components) {
        Combined::Allowed => AuthorityDecision {
            allowed: true,
            reason: DecisionReason::Allowed,
            clause: None,
            subject: request.subject.principal,
            actor: request.actor.principal,
            permitted: bound.permitted,
            expires_at: Some(bound.expires_at),
            challenges: Vec::new(),
        },
        // An approval requirement reaches the fold two ways, as `check` reads it
        // (`crate::decision`): as the fold's own outcome, and as a policy refusal naming
        // `ApprovalRequired`. Both are owed the same answer. A refusal carries no challenge
        // material, so the strictest requirement applies, as it does in `check`.
        Combined::ApprovalRequired | Combined::Denied(DenialReason::ApprovalRequired) => {
            if challenges.is_empty() {
                challenges.push(Challenge {
                    requirement: ChallengeRequirement::Approval,
                    correlation: request.context.correlation.clone(),
                });
            }
            AuthorityDecision::not_allowed(request, AuthorityClause::ApprovalRequired, challenges)
        }
        Combined::Denied(DenialReason::Unavailable) => {
            AuthorityDecision::refused(request, AuthorityClause::Unavailable)
        }
        // Every other refusal keeps the reason policy declared, as `check` keeps it; the
        // clause stays the declared phrase a policy refusal is an instance of.
        Combined::Denied(reason) => AuthorityDecision::refused_for(
            request,
            AuthorityClause::PolicyDenied,
            decision_reason(reason),
        ),
        Combined::Nothing => AuthorityDecision::refused(request, AuthorityClause::PolicyDenied),
    }
}

/// The exact intersection of the request with every bound and every applicable ceiling.
///
/// Requested order is kept and duplicates are dropped, so the result is a function of the
/// sets alone.
fn intersect(
    requested: &AuthorityScope,
    bounds: &[&AuthorityScope],
    ceilings: &[&AgentCapabilityCeiling],
) -> Result<AuthorityScope, AuthorityClause> {
    let scopes = || {
        bounds
            .iter()
            .copied()
            .chain(ceilings.iter().map(|ceiling| &ceiling.scope))
    };

    let mut actions: Vec<Action> = Vec::new();
    for action in &requested.actions {
        let named = scopes().all(|scope| scope.actions.contains(action));
        let admitted = ceilings.iter().all(|ceiling| {
            ceiling
                .allowed_actions
                .iter()
                .any(|pattern| covers(pattern, action))
                && !ceiling
                    .denied_actions
                    .iter()
                    .any(|pattern| covers(pattern, action))
        });
        if named && admitted && !actions.contains(action) {
            actions.push(action.clone());
        }
    }

    let mut resources: Vec<ResourceRef> = Vec::new();
    for resource in &requested.resources {
        let named = scopes().all(|scope| {
            scope
                .resources
                .iter()
                .any(|bound| bound.resource_id == resource.resource_id)
        });
        if named
            && !resources
                .iter()
                .any(|kept| kept.resource_id == resource.resource_id)
        {
            resources.push(resource.clone());
        }
    }

    let mut space: Option<SpaceId> = None;
    for named in std::iter::once(requested)
        .chain(scopes())
        .filter_map(|scope| scope.space)
    {
        match space {
            Some(held) if held != named => return Err(AuthorityClause::SpaceConflict),
            _ => space = Some(named),
        }
    }

    Ok(AuthorityScope {
        actions,
        resources,
        space,
    })
}

/// The earliest instant offered, and the value that named it.
#[derive(Default)]
struct Earliest {
    at: Option<instant::Instant>,
    value: Option<Timestamp>,
}

impl Earliest {
    fn offer(&mut self, at: instant::Instant, value: &Timestamp) {
        if self.at.is_none_or(|held| at < held) {
            self.at = Some(at);
            self.value = Some(value.clone());
        }
    }
}

/// Reading the declared `date-time` form as an instant.
///
/// The same reading `mandate-identity` and `mandate-federation` each keep privately
/// (`crates/mandate-identity/src/session.rs`), restated because neither is in this crate's
/// dependency ceiling: RFC 3339 with a mandatory offset, an optional fraction of up to nine
/// digits, and the leap second 60. A value that names no instant is `None`, and the
/// evaluator refuses rather than guess at it.
mod instant {
    use mandate_types::Timestamp;

    /// Seconds since `1970-01-01T00:00:00Z` and the nanoseconds within; the derived order is
    /// the chronological one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) struct Instant {
        seconds: i64,
        nanos: u32,
    }

    /// The instant a declared timestamp names, or `None` when it names none.
    pub(super) fn parse(value: &Timestamp) -> Option<Instant> {
        let text = value.as_str().as_bytes();
        if text.len() < 20 || !matches!(text[10], b'T' | b't') {
            return None;
        }
        if text[4] != b'-' || text[7] != b'-' || text[13] != b':' || text[16] != b':' {
            return None;
        }
        let year = i64::from(number(&text[0..4])?);
        let month = number(&text[5..7])?;
        let day = number(&text[8..10])?;
        let hour = number(&text[11..13])?;
        let minute = number(&text[14..16])?;
        let second = number(&text[17..19])?;
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }

        let mut rest = &text[19..];
        let mut nanos = 0_u32;
        if rest.first() == Some(&b'.') {
            let digits = rest[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 || digits > 9 {
                return None;
            }
            for index in 0..9 {
                nanos *= 10;
                if index < digits {
                    nanos += u32::from(rest[1 + index] - b'0');
                }
            }
            rest = &rest[1 + digits..];
        }

        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), tail @ ..] if tail.len() == 5 && tail[2] == b':' => {
                let hours = number(&tail[0..2])?;
                let minutes = number(&tail[3..5])?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                let magnitude = i64::from(hours) * 3600 + i64::from(minutes) * 60;
                if *sign == b'-' { -magnitude } else { magnitude }
            }
            _ => return None,
        };

        let seconds = days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second)
            - offset;
        Some(Instant { seconds, nanos })
    }

    fn number(digits: &[u8]) -> Option<u32> {
        let mut value = 0_u32;
        for byte in digits {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + u32::from(byte - b'0');
        }
        Some(value)
    }

    const fn is_leap_year(year: i64) -> bool {
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }

    const fn days_in_month(year: i64, month: u32) -> u32 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap_year(year) => 29,
            2 => 28,
            _ => 0,
        }
    }

    const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let shifted = (month as i64 + 9) % 12;
        let day_of_year = (153 * shifted + 2) / 5 + day as i64 - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }
}
