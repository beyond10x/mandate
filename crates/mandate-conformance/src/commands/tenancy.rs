//! The ten `mandate.tenancy` commands, each decided inside the fold.
//!
//! None of the ten reads a port. `Tenancy` is the whole decision, which is why
//! [`crate::external`] refuses the arming step for every one of them rather than pretending
//! a fault was placed somewhere.
//!
//! # The identity these commands are given
//!
//! `tenancy.yaml` binds `organization_id`, `team_id`, `space_id`, `membership_id`,
//! `team_membership_id` and `contribution_id` from the accepted outcome's response, and
//! `Tenancy` takes each as an argument rather than minting one: the fold is a fold and
//! generates nothing. The target mints them from a counter ([`crate::Mint`]), which is the
//! same placement §37 gives every other source of variation — outside the thing under test,
//! and reproducible between runs.

use ess_conformance::target::{SemanticCommandRequest, SemanticCommandResult, TargetError};
use mandate_model::tenancy::{Denied, MembershipAuthority, TenancyEvent};
use mandate_types::VerifiedContext;

use crate::Live;
use crate::commands::{accepted, refused};
use crate::node;

/// The declared error every refusing outcome of this domain carries.
const DENIED: &str = "mandate.tenancy.Denied";

/// `mandate.tenancy.CreateOrganization`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn create_organization(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.CreateOrganization";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let display_name: String = node::field(&request.input, "display_name")?;
    let id = live.mint.organization();
    let decided = live
        .tenancy
        .decide_create_organization(&context, id, display_name);
    finish(
        live,
        COMMAND,
        decided,
        vec![("organization_id", node::response_field(&id)?)],
    )
}

/// `mandate.tenancy.CloseOrganization`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn close_organization(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.CloseOrganization";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    let decided = live.tenancy.decide_close_organization(&context, id);
    finish(live, COMMAND, decided, Vec::new())
}

/// `mandate.tenancy.CreateTeam`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn create_team(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.CreateTeam";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let display_name: String = node::field(&request.input, "display_name")?;
    let id = live.mint.team();
    let decided = live.tenancy.decide_create_team(&context, id, display_name);
    finish(
        live,
        COMMAND,
        decided,
        vec![("team_id", node::response_field(&id)?)],
    )
}

/// `mandate.tenancy.RetireTeam`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn retire_team(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.RetireTeam";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    let decided = live.tenancy.decide_retire_team(&context, id);
    finish(live, COMMAND, decided, Vec::new())
}

/// `mandate.tenancy.CreateSpace`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn create_space(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.CreateSpace";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let display_name: String = node::field(&request.input, "display_name")?;
    let id = live.mint.space();
    let decided = live.tenancy.decide_create_space(&context, id, display_name);
    finish(
        live,
        COMMAND,
        decided,
        vec![("space_id", node::response_field(&id)?)],
    )
}

/// `mandate.tenancy.RetireSpace`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn retire_space(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.RetireSpace";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    let decided = live.tenancy.decide_retire_space(&context, id);
    finish(live, COMMAND, decided, Vec::new())
}

/// `mandate.tenancy.AddOrganizationMembership`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn add_organization_membership(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.AddOrganizationMembership";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let organization_id = node::field(&request.input, "organization_id")?;
    let principal_id = node::field(&request.input, "principal_id")?;
    let id = live.mint.organization_membership();
    // `authority` is the one input of this domain that decides an outcome and that nothing
    // in the log supplies: "for a caller holding platform organization-administration
    // authority" (`tenancy.yaml`). The declared command input does not carry it and no
    // port answers it, so the target states the authority the contract's default caller
    // has — the verified one — and records the choice as a standing double.
    let decided = live.tenancy.decide_add_organization_membership(
        &context,
        MembershipAuthority::VerifiedOrganization,
        id,
        organization_id,
        principal_id,
    );
    finish(
        live,
        COMMAND,
        decided,
        vec![("membership_id", node::response_field(&id)?)],
    )
}

/// `mandate.tenancy.RemoveOrganizationMembership`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn remove_organization_membership(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.RemoveOrganizationMembership";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    let decided = live
        .tenancy
        .decide_remove_organization_membership(&context, id);
    finish(live, COMMAND, decided, Vec::new())
}

/// `mandate.tenancy.AddTeamMembership`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn add_team_membership(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.AddTeamMembership";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let team_id = node::field(&request.input, "team_id")?;
    let principal_id = node::field(&request.input, "principal_id")?;
    let id = live.mint.team_membership();
    let contribution_id = live.mint.contribution();
    let decided = live.tenancy.decide_add_team_membership(
        &context,
        id,
        team_id,
        principal_id,
        contribution_id,
    );
    finish(
        live,
        COMMAND,
        decided,
        vec![
            ("team_membership_id", node::response_field(&id)?),
            ("contribution_id", node::response_field(&contribution_id)?),
        ],
    )
}

/// `mandate.tenancy.RemoveTeamMembership`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a declared input is not one the contract's
/// schema admits.
pub fn remove_team_membership(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    const COMMAND: &str = "mandate.tenancy.RemoveTeamMembership";
    let context: VerifiedContext = node::field(&request.input, "context")?;
    let id = node::field(&request.input, "id")?;
    let decided = live.tenancy.decide_remove_team_membership(&context, id);
    finish(live, COMMAND, decided, Vec::new())
}

/// Append the decided event and report it, or report the refusal and assert the fold is
/// exactly as it was.
///
/// The refusal is reported through the declared `denied` outcome for every command of this
/// domain, because `mandate_model::tenancy::Denied` carries no discriminator: the federation
/// and identity refusals name which declared refusing outcome they are
/// (`RefusedOutcome`), and this one does not. A scenario asserting `wrong-state` therefore
/// fails here rather than being agreed with, which is the finding and not a workaround.
fn finish(
    live: &mut Live,
    command: &str,
    decided: Result<TenancyEvent, Denied>,
    response: Vec<(&str, ess_primitives::node::Node)>,
) -> Result<SemanticCommandResult, TargetError> {
    match decided {
        Ok(event) => {
            live.append_tenancy(event.clone())?;
            accepted(live, command, event.ess_name(), &event, response)
        }
        Err(denied) => {
            live.tenancy_unchanged()?;
            refused(command, "denied", DENIED, denied.reason)
        }
    }
}
