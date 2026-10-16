//! The two `mandate.workload` commands: the revocation, decided by `mandate-model` over its
//! read port, and the authentication, decided by `mandate-authz` over the workload records,
//! the agent records and a trust-domain verifier.
//!
//! `mandate_model::workload::decide_revoke_workload_identity` reads the record through
//! `WorkloadIdentityRead`, so an armed external outcome is placed at that port: the
//! [`Substituted`] reader answers absence and the decider refuses for it. Unarmed, it reads
//! this scenario's workload fold.
//!
//! An identity no record carries refuses through `denied`, exactly as one in another
//! organization does, and never through `wrong-state`, which only an identity of the
//! caller's own organization already revoked takes. The synthesized `wrong-state` scenario
//! names an identity no record carries and so expects the unknown identity to be disclosed;
//! that gap is `story:unknown-instance-non-disclosing`'s.
//!
//! `mandate_authz::workload::decide_authenticate_workload` verifies the proof through
//! `TrustDomainVerifier` first, so its fault is placed there: the [`Substituted`] verifier
//! refuses every proof. It is decided standing-first (`external.rs`, "An arming the input
//! already decides"): the standing verifier, `ConfiguredTrustDomains::new()`, verifies no
//! proof — no trust bundle is configured for a scenario and the real verifier is
//! `story:agent-security`'s — and the workload fold holds no identity, so every synthesized
//! input is already refused `denied`, and the synthesized `accepted` scenario names records
//! that do not exist (`story:ess-synthesizer-prerequisites`).

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_authz::workload::{
    AuthenticateWorkload, ConfiguredTrustDomains, decide_authenticate_workload,
};
use mandate_model::workload::decide_revoke_workload_identity;
use mandate_types::{CredentialProof, PrincipalId, Timestamp, VerifiedContext, WorkloadIdentityId};

use crate::commands::{accepted, refused, standing_first};
use crate::external::Substituted;
use crate::node;
use crate::{FIXED_INSTANT, Live};

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.workload.Denied";

/// `mandate.workload.RevokeWorkloadIdentity`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when the fold moved under a refusal.
pub fn revoke_workload_identity(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.workload.RevokeWorkloadIdentity";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id: WorkloadIdentityId = node::field(&request.input, "id")?;
    let reader = Substituted::new();
    let armed = live.armed.take(COMMAND);
    let decided = if armed.is_some() {
        decide_revoke_workload_identity(&reader, &context, id)
    } else {
        decide_revoke_workload_identity(&live.workloads, &context, id)
    };
    if let Some(arming) = armed {
        live.record_reads(arming, reader.consulted(), reader.refused());
    }
    match decided {
        Ok(event) => {
            live.append_workload(event.clone())?;
            accepted(live, COMMAND, event.ess_name(), &event, Vec::new())
        }
        Err(denied) => {
            live.workloads_unchanged()?;
            refused(
                COMMAND,
                denied.outcome.outcome(),
                DENIED,
                denied.denied.reason,
            )
        }
    }
}

/// The state `standing_first` trials over. `AuthenticateWorkload` advances none, so it holds
/// the delegation identity allocator and leaves it as it was, as the delegation commands that
/// allocate nothing do.
fn untouched(live: &mut Live) -> &mut mandate_authz::command::SequentialDelegationIds {
    &mut live.delegation_ids
}

/// `mandate.workload.AuthenticateWorkload`, at [`FIXED_INSTANT`].
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits, or when a fold moved under a refusal.
pub fn authenticate_workload(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.workload.AuthenticateWorkload";
    let input = AuthenticateWorkload {
        workload_proof: node::field::<CredentialProof>(&request.input, "workload_proof")?,
        agent: node::field::<PrincipalId>(&request.input, "agent")?,
        execution: node::optional(&request.input, "execution")?,
    };
    let at = Timestamp::new(FIXED_INSTANT);
    let standing = ConfiguredTrustDomains::new();
    let substituted = Substituted::new();
    let decided = standing_first(
        live,
        COMMAND,
        untouched,
        |live, _, faulted| {
            if faulted {
                decide_authenticate_workload(
                    &substituted,
                    &live.workloads,
                    &live.delegations,
                    &input,
                    &at,
                )
            } else {
                decide_authenticate_workload(
                    &standing,
                    &live.workloads,
                    &live.delegations,
                    &input,
                    &at,
                )
            }
        },
        || (substituted.consulted(), substituted.refused()),
    );
    match decided {
        Ok(authenticated) => {
            // Appended to the workload log, which it folds into no record of.
            live.append_workload(authenticated.event.clone())?;
            let response = vec![
                ("workload", node::response_field(&authenticated.workload)?),
                ("runtime", node::response_field(&authenticated.runtime)?),
                (
                    "organization",
                    node::response_field(&authenticated.organization)?,
                ),
            ];
            accepted(
                live,
                COMMAND,
                authenticated.event.ess_name(),
                &authenticated.event,
                response,
            )
        }
        Err(denied) => {
            live.workloads_unchanged()?;
            live.delegations_unchanged()?;
            refused(COMMAND, "denied", DENIED, denied.reason)
        }
    }
}
