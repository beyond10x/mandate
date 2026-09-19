//! One function per command the contract declares, and the registry of the ones nothing
//! here can drive.
//!
//! The shape is the same in every module: decode the declared input into the crate's own
//! input type, call the real handler against this scenario's fold, and report what came
//! back — the event through the crate's own `Serialize`, the response from the values the
//! handler returned, the refusal with the reason and the declared branch the crate says it
//! is. Nothing in these modules decides an outcome, and nothing assembles a payload.
//!
//! # The two registries partition the contract
//!
//! [`REALIZED`] names every command with a function below; [`UNREALIZED`] names every other
//! command the contract declares, with the live story that owns it and why. A command in
//! neither, or in both, is a failing case in
//! `crates/mandate-conformance/tests/target.rs` — the partition is asserted against the
//! suite rather than reviewed, because a hand-kept list of gaps is the defect an adversary
//! finds one entry at a time.

pub mod authz;
pub mod credential;
pub mod federation;
pub mod graph;
pub mod identity;
pub mod tenancy;

use ess_conformance::target::{
    DeclaredErrorValue, ObservedEvent, SemanticCommandRequest, SemanticCommandResult, TargetError,
};
use ess_primitives::consistency::ConsistencyToken;
use ess_primitives::node::Node;
use mandate_types::DenialReason;
use serde::Serialize;

use crate::Live;
use crate::node;

/// Every command this target drives against a real handler.
pub const REALIZED: &[&str] = &[
    "mandate.authorization.Check",
    "mandate.credential.DisableResourceServer",
    "mandate.credential.IntrospectCredential",
    "mandate.credential.IssueAuthorizationCode",
    "mandate.credential.IssueReferenceCredential",
    "mandate.credential.IssueSelfContainedCredential",
    "mandate.credential.RedeemAuthorizationCode",
    "mandate.credential.RegisterResourceServer",
    "mandate.credential.RegisterSigningKey",
    "mandate.credential.RetireSigningKey",
    "mandate.credential.RevokeAccessCredential",
    "mandate.credential.RevokeSigningKey",
    "mandate.federation.AuthenticateFederation",
    "mandate.federation.AuthorizePublicClient",
    "mandate.federation.DisableFederationConnection",
    "mandate.federation.DisableOAuthClient",
    "mandate.federation.LinkExternalPrincipal",
    "mandate.federation.ProvisionExternalPrincipal",
    "mandate.federation.RegisterFederationConnection",
    "mandate.federation.RegisterOAuthClient",
    "mandate.federation.UnlinkExternalPrincipal",
    "mandate.graph.DeregisterResource",
    "mandate.graph.RegisterResource",
    "mandate.identity.IncrementSecurityEpoch",
    "mandate.identity.RefreshSession",
    "mandate.identity.RevokeSession",
    "mandate.tenancy.AddOrganizationMembership",
    "mandate.tenancy.AddTeamMembership",
    "mandate.tenancy.CloseOrganization",
    "mandate.tenancy.CreateOrganization",
    "mandate.tenancy.CreateSpace",
    "mandate.tenancy.CreateTeam",
    "mandate.tenancy.RemoveOrganizationMembership",
    "mandate.tenancy.RemoveTeamMembership",
    "mandate.tenancy.RetireSpace",
    "mandate.tenancy.RetireTeam",
];

/// Every command the contract declares that this target answers `Unsupported` for, with the
/// live story that owns it and the reason in that story's own terms.
///
/// `Unsupported` and not `Unavailable`: ESS defines the first as a permanent property of the
/// target (`ess-conformance/src/target.rs:854`) and the second as a check the runner could
/// not execute this time. A command no crate realizes is the first, and reporting it as the
/// second would say a retry might answer differently.
///
/// The `mandate.credential` rows are a different gap from the others and say so: those
/// eleven commands **are** realized, in `services/sts`, and are unreachable from here
/// because the read model they decide against — `mandate_token::projection::Projection`,
/// its `CredentialEvent` and its `Denied` — lives in `mandate-token`, which is not on
/// `crates/mandate-conformance`'s dependency line. Only the coordinator writes that line.
pub const UNREALIZED: &[(&str, &str, &str)] = &[
    (
        "mandate.audit.RecordAuditEvent",
        "story:audit-worker-delivery",
        "the worker owns RecordAuditEvent; no crate projects mandate.audit",
    ),
    (
        "mandate.audit.RedactAuditEvent",
        "story:audit-worker-delivery",
        "the worker owns the audit record; no crate projects mandate.audit",
    ),
    (
        "mandate.credential.ExchangeCredential",
        "story:constrained-exchange",
        "story:constrained-exchange owns token exchange",
    ),
    (
        "mandate.delegation.CompleteExecution",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.delegation.ConsumeApproval",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.delegation.CreateDelegation",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.delegation.RetireAgent",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.delegation.RevokeDelegation",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.delegation.SupersedeAgentCapabilityCeiling",
        "story:agent-authority-kernel",
        "mandate.delegation is projected by nothing on any dependency line",
    ),
    (
        "mandate.directory.CompleteSyncJob",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.CreateDirectoryGroupTeamMapping",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.FailSyncJob",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.RemoveDirectoryGroupMembership",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.RemoveDirectoryGroupTeamMapping",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.RemoveMembershipContribution",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.RetireDirectoryGroup",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.directory.SyncDirectoryMembership",
        "story:directory-provenance",
        "mandate-provisioning owns directory behaviour and realizes no command yet",
    ),
    (
        "mandate.graph.RemoveRelation",
        "story:graph-policy-adapter",
        "the relationship store is a double; no command writes it",
    ),
    (
        "mandate.graph.RevokeGrant",
        "story:graph-policy-adapter",
        "the grant store is a double; no command writes it",
    ),
    (
        "mandate.graph.WriteRelationship",
        "story:graph-policy-adapter",
        "the relationship store is a double; no command writes it",
    ),
    (
        "mandate.identity.DisablePrincipal",
        "story:declared-writers",
        "no handler decides it and mandate.identity.PrincipalDisabled is folded nowhere",
    ),
    (
        "mandate.identity.RevokeRefreshCredential",
        "story:declared-writers",
        "the RefreshCredential record is projected nowhere",
    ),
    (
        "mandate.policy.SupersedeAuthorizationModel",
        "story:graph-policy-adapter",
        "policy administration is a double; no command supersedes a model",
    ),
    (
        "mandate.policy.SupersedePolicy",
        "story:graph-policy-adapter",
        "policy administration is a double; no command supersedes a policy",
    ),
    (
        "mandate.workload.RevokeWorkloadIdentity",
        "story:agent-security",
        "mandate.workload is projected by nothing on any dependency line",
    ),
];

/// The story and the reason an unrealized command is blocked on, when it is one.
#[must_use]
pub fn unrealized(command: &str) -> Option<(&'static str, &'static str)> {
    UNREALIZED
        .iter()
        .find(|(named, _, _)| *named == command)
        .map(|(_, story, why)| (*story, *why))
}

/// Invoke the command the request names against this scenario's fold.
///
/// # Errors
///
/// Returns [`TargetError::Unsupported`] for a command no crate on this line realizes, and
/// [`TargetError::Unavailable`] when a declared input is not one the contract's own schema
/// admits.
pub fn execute(
    live: &mut Live,
    request: &SemanticCommandRequest,
) -> Result<SemanticCommandResult, TargetError> {
    let command = request.command.to_string();
    if let Some((story, why)) = unrealized(&command) {
        live.ledger
            .block(&live.scenario, &command, "unrealized-command", story);
        return Err(TargetError::unsupported(
            format!("invoking `{command}`"),
            format!("{why}; owner {story}"),
        ));
    }
    match command.as_str() {
        "mandate.federation.RegisterFederationConnection" => {
            federation::register_federation_connection(live, request)
        }
        "mandate.federation.LinkExternalPrincipal" => {
            federation::link_external_principal(live, request)
        }
        "mandate.federation.AuthenticateFederation" => {
            federation::authenticate_federation(live, request)
        }
        "mandate.federation.ProvisionExternalPrincipal" => {
            federation::provision_external_principal(live, request)
        }
        "mandate.federation.AuthorizePublicClient" => {
            federation::authorize_public_client(live, request)
        }
        "mandate.federation.DisableFederationConnection" => {
            federation::disable_federation_connection(live, request)
        }
        "mandate.federation.UnlinkExternalPrincipal" => {
            federation::unlink_external_principal(live, request)
        }
        "mandate.federation.DisableOAuthClient" => federation::disable_oauth_client(live, request),
        "mandate.federation.RegisterOAuthClient" => {
            federation::register_oauth_client(live, request)
        }
        "mandate.credential.RegisterResourceServer" => {
            credential::register_resource_server(live, request)
        }
        "mandate.credential.DisableResourceServer" => {
            credential::disable_resource_server(live, request)
        }
        "mandate.credential.IssueReferenceCredential" => {
            credential::issue_reference_credential(live, request)
        }
        "mandate.credential.IssueSelfContainedCredential" => {
            credential::issue_self_contained_credential(live, request)
        }
        "mandate.credential.IntrospectCredential" => {
            credential::introspect_credential(live, request)
        }
        "mandate.credential.RevokeAccessCredential" => {
            credential::revoke_access_credential(live, request)
        }
        "mandate.credential.RegisterSigningKey" => credential::register_signing_key(live, request),
        "mandate.credential.RetireSigningKey" => credential::retire_signing_key(live, request),
        "mandate.credential.RevokeSigningKey" => credential::revoke_signing_key(live, request),
        "mandate.credential.IssueAuthorizationCode" => {
            credential::issue_authorization_code(live, request)
        }
        "mandate.credential.RedeemAuthorizationCode" => {
            credential::redeem_authorization_code(live, request)
        }
        "mandate.identity.RevokeSession" => identity::revoke_session(live, request),
        "mandate.identity.RefreshSession" => identity::refresh_session(live, request),
        "mandate.identity.IncrementSecurityEpoch" => {
            identity::increment_security_epoch(live, request)
        }
        "mandate.authorization.Check" => authz::check(live, request),
        "mandate.graph.RegisterResource" => graph::register_resource(live, request),
        "mandate.graph.DeregisterResource" => graph::deregister_resource(live, request),
        "mandate.tenancy.CreateOrganization" => tenancy::create_organization(live, request),
        "mandate.tenancy.CloseOrganization" => tenancy::close_organization(live, request),
        "mandate.tenancy.CreateTeam" => tenancy::create_team(live, request),
        "mandate.tenancy.RetireTeam" => tenancy::retire_team(live, request),
        "mandate.tenancy.CreateSpace" => tenancy::create_space(live, request),
        "mandate.tenancy.RetireSpace" => tenancy::retire_space(live, request),
        "mandate.tenancy.AddOrganizationMembership" => {
            tenancy::add_organization_membership(live, request)
        }
        "mandate.tenancy.RemoveOrganizationMembership" => {
            tenancy::remove_organization_membership(live, request)
        }
        "mandate.tenancy.AddTeamMembership" => tenancy::add_team_membership(live, request),
        "mandate.tenancy.RemoveTeamMembership" => tenancy::remove_team_membership(live, request),
        other => Err(TargetError::unavailable(
            format!("invoking `{other}`"),
            "this target dispatches only the commands `systems/mandate` declares, and the \
             registries account for every one of them",
        )),
    }
}

/// The accepted branch of `command`, carrying the event the handler emitted and the
/// declared response it returned.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the event does not serialize or a name is not
/// a well-formed reference.
pub fn accepted(
    live: &mut Live,
    command: &str,
    event_name: &str,
    event: &impl Serialize,
    response: Vec<(&str, Node)>,
) -> Result<SemanticCommandResult, TargetError> {
    let sequence = live.next_sequence();
    let occurrence = node::observed(event_name, event, &live.correlation, sequence)?;
    Ok(emitting(live, command, "accepted", occurrence, response))
}

/// The same, for a branch the contract names something other than `accepted`.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when the event does not serialize or a name is not
/// a well-formed reference.
pub fn accepted_as(
    live: &mut Live,
    command: &str,
    branch: &str,
    event_name: &str,
    event: &impl Serialize,
    response: Vec<(&str, Node)>,
) -> Result<SemanticCommandResult, TargetError> {
    let sequence = live.next_sequence();
    let occurrence = node::observed(event_name, event, &live.correlation, sequence)?;
    Ok(emitting(live, command, branch, occurrence, response))
}

/// Assemble the accepted result from an occurrence the crate rendered.
fn emitting(
    live: &mut Live,
    command: &str,
    branch: &str,
    occurrence: ObservedEvent,
    response: Vec<(&str, Node)>,
) -> SemanticCommandResult {
    let Ok(outcome) = node::outcome_ref(command, branch) else {
        return SemanticCommandResult::undeclared();
    };
    let mut result = SemanticCommandResult::took(outcome).emitting(occurrence);
    if let Some(token) = live.token() {
        result = result.with_consistency(token);
    }
    if !response.is_empty() {
        result.response = Some(
            response
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
        );
    }
    result
}

/// A refusal the handler decided, through the declared branch the crate says it is.
///
/// The reason travels on the error as the contract's own `mandate.core.DenialReason`, which
/// is the only payload the declared error carries.
///
/// # Errors
///
/// Returns [`TargetError::Unavailable`] when a name is not a well-formed reference.
pub fn refused(
    command: &str,
    branch: &str,
    error: &str,
    reason: DenialReason,
) -> Result<SemanticCommandResult, TargetError> {
    Ok(
        SemanticCommandResult::took(node::outcome_ref(command, branch)?).with_error(
            DeclaredErrorValue::new(node::error_ref(error)?)
                .with("reason", node::response_field(&reason)?),
        ),
    )
}

/// The consistency token minted for one invocation, from a counter and never a clock.
#[must_use]
pub fn token(sequence: u64) -> Option<ConsistencyToken> {
    ConsistencyToken::new(format!("seq:{sequence}")).ok()
}

#[cfg(test)]
mod tests {
    use super::{REALIZED, UNREALIZED, unrealized};
    use std::collections::BTreeSet;

    /// The two registries are disjoint, each is sorted and neither repeats a command.
    ///
    /// Sortedness is not cosmetic: a reader checking whether a command is accounted for
    /// reads one of two lists, and a list nobody can scan is a list an entry goes missing
    /// from.
    #[test]
    fn the_registries_are_disjoint_sorted_and_free_of_repeats() {
        let realized: BTreeSet<&str> = REALIZED.iter().copied().collect();
        assert_eq!(realized.len(), REALIZED.len(), "a command is named twice");
        assert!(
            REALIZED.windows(2).all(|pair| pair[0] < pair[1]),
            "the realized registry is not sorted"
        );
        let blocked: BTreeSet<&str> = UNREALIZED.iter().map(|(command, _, _)| *command).collect();
        assert_eq!(blocked.len(), UNREALIZED.len(), "a command is named twice");
        assert!(
            UNREALIZED.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "the unrealized registry is not sorted"
        );
        assert!(
            realized.is_disjoint(&blocked),
            "a command is both dispatched and named unrealized"
        );
        for (command, story, why) in UNREALIZED {
            assert!(story.starts_with("story:"), "`{command}` names no story");
            assert!(!why.is_empty(), "`{command}` gives no reason");
        }
        assert_eq!(
            unrealized("mandate.credential.ExchangeCredential").map(|(story, _)| story),
            Some("story:constrained-exchange")
        );
        assert_eq!(unrealized("mandate.tenancy.CreateTeam"), None);
    }
}
