//! `mandate.delegation.Agent`, `AgentCapabilityCeiling`, `Delegation`, `Execution` and
//! `Approval` as projections, and the read that decides which ceilings are current.
//!
//! The entities and their lifecycles are declared in `systems/mandate/domains/delegation.yaml`.
//! These are projections, not the record: `docs/adr/0009-event-sourced-persistence.md` makes
//! the events the record and every read a fold. They reach the evaluator in [`crate::agent`]
//! through [`crate::agent::AgentAuthorityRead`], and nothing in this crate stores them. Plain
//! structs, no `serde`, as `mandate_policy::record` declares its own.
//!
//! # The ceiling key, and what "current" means
//!
//! `decision-blocker:identity-uniqueness-ceiling` decided the key and `delegation.yaml`'s header
//! records it: a ceiling is keyed by `(agent_id, organization_id)`, an absent organization is
//! the platform key, and the current ceiling for a key is the latest recorded one still in
//! `Recorded` — an earlier one on the same key is superseded, never edited. Two current
//! ceilings on one key are a declared denial (`ExchangeCredential`: "two current capability
//! ceilings share one agent and organization-or-platform key"). [`current_ceilings`] is the
//! read that says so: it never picks one of two conflicting records, it reports the key.

use mandate_types::{
    Action, ActionPattern, AgentCapabilityCeilingId, ApprovalId, Audience, AuthorityScope,
    DelegationId, Duration, ExecutionId, OrganizationId, PersistedValue, PolicyVersion,
    PrincipalId, ResourceRef, SessionId, Timestamp,
};

/// The declared lifecycle of `mandate.delegation.Delegation` (`delegation.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationState {
    /// The declared initial state: the delegation is in force inside its window.
    Active,
    /// The declared terminal state: the delegation was revoked and admits nothing.
    Revoked,
}

impl DelegationState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Active, Self::Revoked];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

impl PersistedValue for DelegationState {}

/// `mandate.delegation.Delegation`: one explicit, non-transitive grant of a delegator's
/// authority to a delegate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The declared identity.
    pub id: DelegationId,
    /// The organization the delegation is recorded in.
    pub organization_id: OrganizationId,
    /// The principal whose authority is delegated: the subject of a delegated request.
    pub delegator: PrincipalId,
    /// The principal the authority is delegated to: the actor of a delegated request.
    pub delegate: PrincipalId,
    /// The authority delegated. A bound, never a grant.
    pub scope: AuthorityScope,
    /// The audience the delegation is for.
    pub audience: Audience,
    /// When the delegation starts to be in force, when it does not start at creation.
    pub not_before: Option<Timestamp>,
    /// When the delegation stops being in force.
    pub expires_at: Timestamp,
    /// The execution the delegation is bound to, when it is bound to one.
    pub execution_binding: Option<ExecutionId>,
    /// Always `false` for a record the contract admits (`invariants: transitive == false`).
    pub transitive: bool,
    /// When the delegation was created.
    pub created_at: Timestamp,
    /// The folded lifecycle state.
    pub state: DelegationState,
}

impl PersistedValue for Delegation {}

/// The declared lifecycle of `mandate.delegation.Agent` (`delegation.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    /// The declared initial state: the agent installation is recorded.
    Recorded,
    /// The declared terminal state: the installation is withdrawn, and a retired agent is
    /// admitted by no exchange (`RetireAgent`'s summary).
    Retired,
}

impl AgentState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Retired];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Retired)
    }
}

impl PersistedValue for AgentState {}

/// `mandate.delegation.Agent`: the record that makes a principal an agent of one
/// organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The declared identity: the agent's principal.
    pub id: PrincipalId,
    /// The organization the agent is installed in.
    pub organization_id: OrganizationId,
    /// The kind of agent, as recorded.
    pub agent_type: String,
    /// The folded lifecycle state.
    pub state: AgentState,
}

impl PersistedValue for Agent {}

/// The declared lifecycle of `mandate.delegation.AgentCapabilityCeiling` (`delegation.yaml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingState {
    /// The declared initial state: the ceiling is current for its key.
    Recorded,
    /// The declared terminal state: a later ceiling on the same key replaced it.
    Superseded,
}

impl CeilingState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Superseded];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Superseded)
    }
}

impl PersistedValue for CeilingState {}

/// `mandate.delegation.AgentCapabilityCeiling`: the most an agent may do, for the platform
/// or for one organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCapabilityCeiling {
    /// The declared identity.
    pub id: AgentCapabilityCeilingId,
    /// The agent the ceiling bounds.
    pub agent_id: PrincipalId,
    /// The organization the ceiling is recorded for; absent is the platform ceiling.
    pub organization_id: Option<OrganizationId>,
    /// The action patterns the ceiling admits.
    pub allowed_actions: Vec<ActionPattern>,
    /// The action patterns the ceiling refuses, whatever it admits.
    pub denied_actions: Vec<ActionPattern>,
    /// The actions and resources the ceiling confines the agent to.
    pub scope: AuthorityScope,
    /// The longest delegation the ceiling admits. Bounds `CreateDelegation`
    /// (`crate::command`), not an evaluation.
    pub max_delegation_ttl: Duration,
    /// The folded lifecycle state.
    pub state: CeilingState,
}

impl PersistedValue for AgentCapabilityCeiling {}

impl AgentCapabilityCeiling {
    /// The key one current ceiling is held on: the agent and the organization, absent for
    /// the platform.
    #[must_use]
    pub fn key(&self) -> CeilingKey {
        CeilingKey {
            agent_id: self.agent_id,
            organization_id: self.organization_id,
        }
    }

    /// Whether this ceiling is current: still `Recorded`, not superseded.
    #[must_use]
    pub const fn current(&self) -> bool {
        matches!(self.state, CeilingState::Recorded)
    }

    /// Whether this ceiling bounds the agent in a request made in `organization`: the
    /// platform ceiling and the ceiling recorded for that organization do; a ceiling recorded
    /// for another organization does not.
    #[must_use]
    pub fn applies(&self, agent: &PrincipalId, organization: &OrganizationId) -> bool {
        self.agent_id == *agent
            && self
                .organization_id
                .as_ref()
                .is_none_or(|recorded| recorded == organization)
    }
}

/// The declared lifecycle of `mandate.delegation.Execution` (`delegation.yaml`).
///
/// An execution is never expired by a recorded move: eligibility is read from its
/// `expires_at`, and completion is the only declared transition (`delegation.yaml:3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionState {
    /// The declared initial state: the agent invocation is recorded and admits tool calls
    /// inside its window.
    Recorded,
    /// The declared terminal state: the invocation ended, and no further tool call is
    /// admitted under it (`CompleteExecution`'s summary).
    Completed,
}

impl ExecutionState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Completed];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl PersistedValue for ExecutionState {}

/// `mandate.delegation.Execution`: one agent invocation, the window its tool calls are
/// admitted in, and what it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execution {
    /// The declared identity.
    pub id: ExecutionId,
    /// The organization the execution is recorded in.
    pub organization_id: OrganizationId,
    /// The agent that holds the execution: the actor of every request made under it.
    pub agent_id: PrincipalId,
    /// The subject the agent acts for, when it acts for one; absent, it acts for itself.
    pub subject: Option<PrincipalId>,
    /// The delegation the execution runs under, when it runs under one.
    pub delegation_id: Option<DelegationId>,
    /// The session that started the execution, when one did.
    pub initiating_session: Option<SessionId>,
    /// When the execution was recorded.
    pub created_at: Timestamp,
    /// When the execution stops admitting tool calls, without any recorded move.
    pub expires_at: Timestamp,
    /// The policy version the execution was started under.
    pub policy_version: PolicyVersion,
    /// The folded lifecycle state.
    pub state: ExecutionState,
}

impl PersistedValue for Execution {}

/// The declared lifecycle of `mandate.delegation.Approval` (`delegation.yaml`).
///
/// One-use and never reinstated: it is consumed by exactly one decision, or it expires by its
/// own `expires_at` with no recorded move (`delegation.yaml:4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalState {
    /// The declared initial state: the approval is recorded and not yet used.
    Recorded,
    /// The declared terminal state: one decision used it.
    Consumed,
}

impl ApprovalState {
    /// Every state the contract declares, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Recorded, Self::Consumed];

    /// Whether the contract declares this state terminal.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Consumed)
    }
}

impl PersistedValue for ApprovalState {}

/// `mandate.delegation.Approval`: a second party's one-use answer to one approval challenge.
///
/// Read through [`crate::agent::AgentAuthorityRead::approval`] for the command that consumes
/// it. No evaluation here satisfies a challenge with one: `mandate.authorization.Check`
/// declares no approval input, so an approval requirement is answered `allowed = false` with
/// the challenge attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The declared identity.
    pub id: ApprovalId,
    /// The organization the approval is recorded in.
    pub organization_id: OrganizationId,
    /// The subject of the decision the approval answers.
    pub subject: PrincipalId,
    /// The actor of that decision, when it had one.
    pub actor: Option<PrincipalId>,
    /// The action approved.
    pub action: Action,
    /// The resource the action is on.
    pub resource: ResourceRef,
    /// When the approval stops being usable, without any recorded move.
    pub expires_at: Timestamp,
    /// The principal who approved.
    pub approver: PrincipalId,
    /// The folded lifecycle state.
    pub state: ApprovalState,
}

impl PersistedValue for Approval {}

/// The key one current capability ceiling is held on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CeilingKey {
    /// The agent.
    pub agent_id: PrincipalId,
    /// The organization; absent is the platform key.
    pub organization_id: Option<OrganizationId>,
}

/// Two or more current ceilings on one key: a declared denial, never a choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingConflict {
    /// The key more than one current ceiling holds.
    pub key: CeilingKey,
    /// Every current ceiling on the key, in recorded order.
    pub ceilings: Vec<AgentCapabilityCeilingId>,
}

/// The current ceilings that apply to one agent in one organization, read from the records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCeilings<'a> {
    /// The one current ceiling of every applicable key that holds exactly one.
    pub current: Vec<&'a AgentCapabilityCeiling>,
    /// Every applicable key that holds more than one current ceiling.
    pub conflicts: Vec<CeilingConflict>,
}

/// Which recorded ceilings bound `agent` in `organization`, and which keys conflict.
///
/// `records` is every ceiling recorded for the agent, in recorded order; superseded ones are
/// kept because nothing is deleted, and are passed over here. A record for another agent, or
/// for another organization, applies to nothing and is passed over too. A key with exactly
/// one current record contributes it; a key with two or more contributes a
/// [`CeilingConflict`] and no ceiling, so no caller can read one of them as the answer.
#[must_use]
pub fn current_ceilings<'a>(
    records: &'a [AgentCapabilityCeiling],
    agent: &PrincipalId,
    organization: &OrganizationId,
) -> CurrentCeilings<'a> {
    let mut keys: Vec<(CeilingKey, Vec<&'a AgentCapabilityCeiling>)> = Vec::new();
    for ceiling in records
        .iter()
        .filter(|ceiling| ceiling.current() && ceiling.applies(agent, organization))
    {
        let key = ceiling.key();
        match keys.iter_mut().find(|(held, _)| *held == key) {
            Some((_, held)) => held.push(ceiling),
            None => keys.push((key, vec![ceiling])),
        }
    }
    let mut current = Vec::new();
    let mut conflicts = Vec::new();
    for (key, held) in keys {
        if let [only] = held.as_slice() {
            current.push(*only);
        } else {
            conflicts.push(CeilingConflict {
                key,
                ceilings: held.iter().map(|ceiling| ceiling.id).collect(),
            });
        }
    }
    CurrentCeilings { current, conflicts }
}
