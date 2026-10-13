//! The `mandate.delegation` events the commands of [`crate::command`] emit, and the fold that
//! writes them into the records [`crate::agent::AgentAuthorityRead`] answers from.
//!
//! `docs/adr/0009-event-sourced-persistence.md` makes the events the record and every read a
//! fold. [`DelegationProjection`] is that fold: it starts from the records no command of this
//! contract creates — principal standings, agents, ceilings, executions and approvals, which
//! `story:declared-writers` and `SupersedeAgentCapabilityCeiling` will give writers — and
//! applies the log over them. Delegations are the one record a command here creates, so a
//! delegation exists in the projection exactly when a `DelegationCreated` in its log says so.
//!
//! The projection implements [`AgentAuthorityRead`], so [`crate::check`] and the token
//! exchange read what the commands wrote: a revoked delegation, a retired agent, a completed
//! execution and a consumed approval are answered in their terminal state the moment the
//! event is applied.
//!
//! # Applying is total
//!
//! [`DelegationProjection::apply`] re-checks nothing and cannot refuse, as
//! `mandate_model::tenancy::Tenancy::apply` cannot: the decide half has already refused
//! everything the contract refuses, and a fold that refused would not be a rebuild. An event
//! naming a record the projection does not hold changes no record; it is still logged.

use serde::Serialize;

use mandate_types::{
    ApprovalId, Audience, AuthorityScope, DelegationId, ExecutionId, PrincipalId, Timestamp,
    VerifiedContext,
};

use crate::agent::{AgentAuthorityRead, AgentRecords, PrincipalStanding, Unavailable};
use crate::delegation::{
    Agent, AgentCapabilityCeiling, AgentState, Approval, ApprovalState, Delegation,
    DelegationState, Execution, ExecutionState,
};

/// `mandate.delegation.DelegationCreated`: the one payload that carries a whole record.
///
/// A struct of its own and boxed in [`DelegationEvent::Created`], so the enum is not as large
/// as its largest variant for every `{context, id}` beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationCreated {
    /// The creating request's verified context.
    pub context: VerifiedContext,
    /// The identity the delegation is recorded under.
    pub id: DelegationId,
    /// The verified subject of the creating request.
    pub delegator: PrincipalId,
    /// The agent the authority is delegated to.
    pub delegate: PrincipalId,
    /// The authority delegated.
    pub scope: AuthorityScope,
    /// The audience the delegation is for.
    pub audience: Audience,
    /// When the delegation starts to be in force, when not at creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<Timestamp>,
    /// When the delegation stops being in force.
    pub expires_at: Timestamp,
    /// The execution the delegation is bound to, when it is bound to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_binding: Option<ExecutionId>,
    /// The instant the delegation was created at.
    pub created_at: Timestamp,
}

/// The declared `mandate.delegation` event payloads this crate emits.
///
/// `#[serde(untagged)]`, so a variant serializes as the bare payload object, as
/// `mandate_model::tenancy::TenancyEvent` does; `Serialize` only, because an event is read
/// back by folding it here and never by decoding a document.
/// `AgentCapabilityCeilingSuperseded` is absent: its command stays deferred on
/// `story:agent-security` (`docs/plans/2026-10-13-wave-7-execution.md`, "Spec first").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum DelegationEvent {
    /// `mandate.delegation.DelegationCreated`.
    Created(Box<DelegationCreated>),
    /// `mandate.delegation.DelegationRevoked`.
    Revoked {
        /// The revoking request's verified context.
        context: VerifiedContext,
        /// The delegation that stops being in force.
        id: DelegationId,
    },
    /// `mandate.delegation.AgentRetired`.
    AgentRetired {
        /// The retiring request's verified context.
        context: VerifiedContext,
        /// The agent whose installation is withdrawn.
        id: PrincipalId,
    },
    /// `mandate.delegation.ExecutionCompleted`.
    ExecutionCompleted {
        /// The completing request's verified context.
        context: VerifiedContext,
        /// The execution that admits no further tool call.
        id: ExecutionId,
    },
    /// `mandate.delegation.ApprovalConsumed`.
    ApprovalConsumed {
        /// The consuming request's verified context.
        context: VerifiedContext,
        /// The approval one decision used.
        id: ApprovalId,
    },
}

impl DelegationEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// Exhaustive and without a wildcard arm, so a variant added without a name here does
    /// not compile.
    #[must_use]
    pub const fn ess_name(&self) -> &'static str {
        match self {
            Self::Created(_) => "mandate.delegation.DelegationCreated",
            Self::Revoked { .. } => "mandate.delegation.DelegationRevoked",
            Self::AgentRetired { .. } => "mandate.delegation.AgentRetired",
            Self::ExecutionCompleted { .. } => "mandate.delegation.ExecutionCompleted",
            Self::ApprovalConsumed { .. } => "mandate.delegation.ApprovalConsumed",
        }
    }
}

/// The `mandate.delegation` projection: the starting records with every event of the log
/// applied, answering [`AgentAuthorityRead`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationProjection {
    records: AgentRecords,
    log: Vec<DelegationEvent>,
}

impl DelegationProjection {
    /// A projection holding these records and no event.
    ///
    /// The records stand in for the creations no command of this contract declares; see
    /// the module documentation. Delegations among them are kept as given.
    #[must_use]
    pub const fn holding(records: AgentRecords) -> Self {
        Self {
            records,
            log: Vec::new(),
        }
    }

    /// The projection every event of `events` has been applied to, from `records`.
    #[must_use]
    pub fn fold(records: AgentRecords, events: &[DelegationEvent]) -> Self {
        let mut fold = Self::holding(records);
        for event in events {
            fold.apply(event);
        }
        fold
    }

    /// Every event applied, in order.
    #[must_use]
    pub fn log(&self) -> &[DelegationEvent] {
        &self.log
    }

    /// Write one declared event into the projection, and log it.
    ///
    /// Total, and re-checks nothing; see the module documentation. Creation is monotone: a
    /// `DelegationCreated` for an id already held changes nothing, and one whose revocation
    /// the log already holds records the delegation revoked, so no repetition or order of the
    /// log puts a revoked delegation back in force.
    pub fn apply(&mut self, event: &DelegationEvent) {
        let revoked_earlier = |id: &DelegationId| {
            self.log.iter().any(
                |logged| matches!(logged, DelegationEvent::Revoked { id: revoked, .. } if revoked == id),
            )
        };
        let created_revoked = match event {
            DelegationEvent::Created(created) => revoked_earlier(&created.id),
            _ => false,
        };
        let records = &mut self.records;
        match event {
            DelegationEvent::Created(created)
                if records.delegations.iter().any(|d| d.id == created.id) => {}
            DelegationEvent::Created(created) => {
                let DelegationCreated {
                    context,
                    id,
                    delegator,
                    delegate,
                    scope,
                    audience,
                    not_before,
                    expires_at,
                    execution_binding,
                    created_at,
                } = created.as_ref();
                records.delegations.push(Delegation {
                    id: *id,
                    organization_id: context.organization,
                    delegator: *delegator,
                    delegate: *delegate,
                    scope: scope.clone(),
                    audience: audience.clone(),
                    not_before: not_before.clone(),
                    expires_at: expires_at.clone(),
                    execution_binding: *execution_binding,
                    transitive: false,
                    created_at: created_at.clone(),
                    state: if created_revoked {
                        DelegationState::Revoked
                    } else {
                        DelegationState::Active
                    },
                });
            }
            DelegationEvent::Revoked { id, .. } => {
                if let Some(record) = records.delegations.iter_mut().rev().find(|d| d.id == *id) {
                    record.state = DelegationState::Revoked;
                }
            }
            DelegationEvent::AgentRetired { id, .. } => {
                if let Some(record) = records.agents.iter_mut().rev().find(|a| a.id == *id) {
                    record.state = AgentState::Retired;
                }
            }
            DelegationEvent::ExecutionCompleted { id, .. } => {
                if let Some(record) = records.executions.iter_mut().rev().find(|e| e.id == *id) {
                    record.state = ExecutionState::Completed;
                }
            }
            DelegationEvent::ApprovalConsumed { id, .. } => {
                if let Some(record) = records.approvals.iter_mut().rev().find(|a| a.id == *id) {
                    record.state = ApprovalState::Consumed;
                }
            }
        }
        self.log.push(event.clone());
    }
}

impl AgentAuthorityRead for DelegationProjection {
    fn standing(&self, principal: &PrincipalId) -> Result<Option<PrincipalStanding>, Unavailable> {
        self.records.standing(principal)
    }

    fn agent(&self, principal: &PrincipalId) -> Result<Option<Agent>, Unavailable> {
        self.records.agent(principal)
    }

    fn ceilings(&self, agent: &PrincipalId) -> Result<Vec<AgentCapabilityCeiling>, Unavailable> {
        self.records.ceilings(agent)
    }

    fn delegation(&self, id: &DelegationId) -> Result<Option<Delegation>, Unavailable> {
        self.records.delegation(id)
    }

    fn execution(&self, id: &ExecutionId) -> Result<Option<Execution>, Unavailable> {
        self.records.execution(id)
    }

    fn approval(&self, id: &ApprovalId) -> Result<Option<Approval>, Unavailable> {
        self.records.approval(id)
    }
}
