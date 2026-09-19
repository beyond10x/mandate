//! The two `mandate.graph` registration commands, decided inside the topology fold.
//!
//! `WriteRelationship`, `RemoveRelation` and `RevokeGrant` are the other three the domain
//! declares and are not here: the relationship and grant stores are doubles that no command
//! writes, which is `story:graph-policy-adapter`'s, and the registry in
//! [`crate::commands`] names them with that story.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_model::graph::{Denied, ResourceEvent};
use mandate_types::{ResourceId, ResourceRef, VerifiedContext};

use crate::Live;
use crate::commands::{accepted, refused};
use crate::node;

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.graph.Denied";

/// `mandate.graph.RegisterResource`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn register_resource(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.graph.RegisterResource";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let resource: ResourceRef = node::field(&request.input, "resource")?;
    let parent: Option<ResourceId> = node::optional(&request.input, "parent")?;
    let decided = live
        .topology
        .decide_register(&live.tenancy, &context, &resource, parent);
    match decided {
        Ok(event) => {
            let resource_id = match &event {
                ResourceEvent::Registered { resource_id, .. } => *resource_id,
                ResourceEvent::Deregistered { .. } => {
                    return Err(TargetError::unavailable(
                        "reading the registration's identity",
                        "the accepted outcome emitted an event that is not the declared one",
                    ));
                }
            };
            live.append_topology(event.clone())?;
            accepted(
                live,
                COMMAND,
                event.ess_name(),
                &event,
                vec![("resource_id", node::response_field(&resource_id)?)],
            )
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// `mandate.graph.DeregisterResource`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn deregister_resource(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.graph.DeregisterResource";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    match live.topology.decide_deregister(&context, id) {
        Ok(event) => {
            live.append_topology(event.clone())?;
            accepted(live, COMMAND, event.ess_name(), &event, Vec::new())
        }
        Err(denied) => refuse(live, COMMAND, denied),
    }
}

/// Report the refusal, having shown the fold is exactly as it was.
///
/// Reported through the declared `denied` outcome for the reason
/// [`crate::commands::tenancy`] gives: `mandate_model::graph::Denied` carries no
/// discriminator between the two refusing outcomes the contract declares.
fn refuse(
    live: &mut Live,
    command: &str,
    denied: Denied,
) -> Result<SemanticCommandResult, TargetError> {
    live.topology_unchanged()?;
    refused(command, "denied", DENIED, denied.reason)
}
