//! Five of the six `mandate.delegation` commands, decided by `mandate-authz` over this
//! scenario's delegation fold.
//!
//! `CreateDelegation`, `RevokeDelegation` and `RetireAgent` read the judgements no record
//! answers through `mandate_authz::command::DelegationAdmission`, so an armed external outcome
//! is placed there: the [`Substituted`] admission admits nothing and the decider refuses for
//! it. Unarmed, the standing admission holds the verified subject as a delegator, revoker and
//! agent administrator and registers the context's audience for its organization — authority
//! is `decision-blocker:guards`', the audience registry `mandate-token`'s — so a scenario is
//! refused for its records and never for an authority this target cannot evaluate.
//! `CompleteExecution` and `ConsumeApproval` consult no admission: every clause they decide
//! is a record's, so their fault is placed at `mandate_authz::agent::AgentAuthorityRead`,
//! where the [`Substituted`] reader answers absence.
//!
//! All five are decided standing-first (`external.rs`, "An arming the input already
//! decides"). The fold starts from no record — no command creates a standing, an agent, a
//! ceiling, an execution or an approval — so the standing decision of every synthesized input
//! already refuses, and a fault placed first would decide nothing. Every synthesized
//! `accepted` scenario names records that do not exist (`story:ess-synthesizer-prerequisites`).
//! A record no read carries refuses through `denied`, exactly as one of another organization
//! does, and never through `wrong-state`; the synthesized `wrong-state` scenarios expect the
//! unknown record to be disclosed, and that gap is `story:unknown-instance-non-disclosing`'s.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_authz::command::{
    ConfiguredDelegationAdmission, CreateDelegation, Denied, SequentialDelegationIds,
    decide_complete_execution, decide_consume_approval, decide_create_delegation,
    decide_retire_agent, decide_revoke_delegation,
};
use mandate_authz::event::DelegationEvent;
use mandate_types::{
    ApprovalId, AuthorityScope, DelegationId, ExecutionId, PrincipalId, Timestamp, VerifiedContext,
};

use crate::commands::{accepted, refused, standing_first};
use crate::external::Substituted;
use crate::node;
use crate::{FIXED_INSTANT, Live};

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.delegation.Denied";

/// The delegation identity allocator `CreateDelegation` advances; the other four commands
/// hold it and leave it as it was.
fn delegation_ids(live: &mut Live) -> &mut SequentialDelegationIds {
    &mut live.delegation_ids
}

/// The standing admission: the verified subject holds every authority this command family
/// asks about, and the context's audience is registered for its organization.
fn standing_admission(context: &VerifiedContext) -> ConfiguredDelegationAdmission {
    ConfiguredDelegationAdmission::new()
        .with_delegator(context.subject)
        .with_revoker(context.subject)
        .with_agent_administrator(context.subject)
        .with_audience(context.organization, context.audience.clone())
}

/// Report what the decider returned: the event appended and refolded, or the refusal with
/// the fold shown unmoved.
fn answered(
    live: &mut Live,
    command: &str,
    decided: Result<DelegationEvent, Denied>,
) -> Result<SemanticCommandResult, TargetError> {
    match decided {
        Ok(event) => {
            live.append_delegation(event.clone())?;
            accepted(live, command, event.ess_name(), &event, Vec::new())
        }
        Err(denied) => {
            live.delegations_unchanged()?;
            refused(command, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.delegation.CreateDelegation`, at [`FIXED_INSTANT`], which is its `created_at`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn create_delegation(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.delegation.CreateDelegation";
    let input = CreateDelegation {
        context: node::field(&request.input, "context")?,
        delegate: node::field::<PrincipalId>(&request.input, "delegate")?,
        scope: node::field::<AuthorityScope>(&request.input, "scope")?,
        audience: node::field(&request.input, "audience")?,
        expires_at: node::field::<Timestamp>(&request.input, "expires_at")?,
        not_before: node::optional(&request.input, "not_before")?,
        execution_binding: node::optional(&request.input, "execution_binding")?,
    };
    let at = Timestamp::new(FIXED_INSTANT);
    let standing = standing_admission(&input.context);
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        delegation_ids,
        |live, ids, faulted| {
            if faulted {
                decide_create_delegation(
                    &live.delegations,
                    &live.policy,
                    &substituted,
                    ids,
                    &input,
                    &at,
                )
            } else {
                decide_create_delegation(
                    &live.delegations,
                    &live.policy,
                    &standing,
                    ids,
                    &input,
                    &at,
                )
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    match decided {
        Ok(created) => {
            live.append_delegation(created.event.clone())?;
            let response = vec![
                (
                    "delegation_id",
                    node::response_field(&created.delegation_id)?,
                ),
                ("delegator", node::response_field(&created.delegator)?),
            ];
            accepted(
                live,
                COMMAND,
                created.event.ess_name(),
                &created.event,
                response,
            )
        }
        Err(denied) => {
            live.delegations_unchanged()?;
            refused(COMMAND, denied.outcome.ir_name(), DENIED, denied.reason)
        }
    }
}

/// `mandate.delegation.RevokeDelegation`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn revoke_delegation(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.delegation.RevokeDelegation";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: DelegationId = node::field(&request.input, "id")?;
    let standing = standing_admission(&context);
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        delegation_ids,
        |live, _, faulted| {
            if faulted {
                decide_revoke_delegation(&live.delegations, &substituted, &context, id)
            } else {
                decide_revoke_delegation(&live.delegations, &standing, &context, id)
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    answered(live, COMMAND, decided)
}

/// `mandate.delegation.RetireAgent`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn retire_agent(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.delegation.RetireAgent";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: PrincipalId = node::field(&request.input, "id")?;
    let standing = standing_admission(&context);
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        delegation_ids,
        |live, _, faulted| {
            if faulted {
                decide_retire_agent(&live.delegations, &substituted, &context, id)
            } else {
                decide_retire_agent(&live.delegations, &standing, &context, id)
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    answered(live, COMMAND, decided)
}

/// `mandate.delegation.CompleteExecution`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn complete_execution(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.delegation.CompleteExecution";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: ExecutionId = node::field(&request.input, "id")?;
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        delegation_ids,
        |live, _, faulted| {
            if faulted {
                decide_complete_execution(&substituted, &context, id)
            } else {
                decide_complete_execution(&live.delegations, &context, id)
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    answered(live, COMMAND, decided)
}

/// `mandate.delegation.ConsumeApproval`, at [`FIXED_INSTANT`].
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn consume_approval(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.delegation.ConsumeApproval";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: ApprovalId = node::field(&request.input, "id")?;
    let at = Timestamp::new(FIXED_INSTANT);
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        delegation_ids,
        |live, _, faulted| {
            if faulted {
                decide_consume_approval(&substituted, &context, id, &at)
            } else {
                decide_consume_approval(&live.delegations, &context, id, &at)
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    answered(live, COMMAND, decided)
}
