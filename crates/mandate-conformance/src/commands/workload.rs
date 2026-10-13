//! The one `mandate.workload` command, decided by `mandate-model` over its read port.
//!
//! `mandate_model::workload::decide_revoke_workload_identity` reads the record through
//! `WorkloadIdentityRead`, so an armed external outcome is placed at that port: the
//! [`Substituted`] reader answers absence and the decider refuses for it. Unarmed, it reads
//! this scenario's workload fold.
//!
//! An identity no record carries refuses through `denied`, exactly as one in another
//! organization does, and never through `wrong-state`; the synthesized `wrong-state` scenario
//! expects the unknown identity to be disclosed, and that gap is
//! `story:unknown-instance-non-disclosing`'s.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_model::workload::decide_revoke_workload_identity;
use mandate_types::{VerifiedContext, WorkloadIdentityId};

use crate::Live;
use crate::commands::{accepted, refused};
use crate::external::Substituted;
use crate::node;

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
            // `mandate_model::workload::Denied` carries no discriminator between the two
            // refusing outcomes, and an unknown identity is not disclosed: `denied`.
            refused(COMMAND, "denied", DENIED, denied.reason)
        }
    }
}
