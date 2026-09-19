//! The three declared lifecycle commands of `mandate.federation`:
//! `DisableFederationConnection`, `UnlinkExternalPrincipal` and `DisableOAuthClient`.
//!
//! Each moves one record along the lifecycle `federation.yaml` declares for it, each
//! emits the one event its accepted outcome declares, and each declares **two** refusing
//! outcomes rather than one:
//!
//! * `denied`, the externally caused refusal — the record does not resolve, or it is
//!   outside the caller's verified organization.
//! * `wrong-state`, "the branch taken when the subject is in a state none of that
//!   command's declared moves start from" (`docs/architecture/command-obligations.md`).
//!   All three declared transitions start from the initial state alone, so a record
//!   already in its terminal state is exactly that branch.
//!
//! Which one a refusal is, is carried by [`crate::RefusedOutcome`] and not inferred from
//! the reason: both outcomes report the same `mandate.federation.Denied` error, and the
//! contract gives them different renderings (409 against 502).
//!
//! # Decide, apply, fold
//!
//! Each handler is the **decide** half: it takes `&self`-style shared reads of the
//! projection, writes nothing, and returns either the declared event or [`Denied`]. The
//! **apply** half is [`crate::record::Projection::apply`], which writes what it is handed
//! and re-checks nothing, and the **fold** is `Projection::fold`. That is the split
//! `crates/mandate-model/src/tenancy.rs` established and the one
//! `docs/adr/0009-event-sourced-persistence.md` requires: a fold that re-decided a guard
//! would not be a rebuild of an accepted history.
//!
//! The window between a decision and the append that follows it is not closed here and no
//! function here promises to close it. The command path closes it: ADR 0009 makes the
//! decide-and-append step one transaction whose aggregate append is a compare-and-set on
//! the expected stream version, so a decision read from a state that has since moved
//! fails the append and is retried against the state that moved it.
//!
//! # What is decided elsewhere
//!
//! Whether the caller holds federation-, link- or client-administration authority is an
//! authorization decision, and no crate in this crate's dependency ceiling decides one —
//! the same boundary [`crate::record::register_federation_connection`] keeps. The
//! invalidation each declared denial names ("affected generation invalidation",
//! "required invalidation/audit") is the adapter's transaction, not this decision.
//!
//! # What disablement does not reach
//!
//! `DisableOAuthClient` "stops new authorization codes being issued" and no declared move
//! invalidates an outstanding one (`federation.yaml`, `DisableOAuthClient`). The
//! outstanding code is refused at redemption instead, where the client the code is bound
//! to is read again — [`crate::authorize::validate_authorization_code`] performs that read
//! through [`crate::publicclient::registered_public_client`], which refuses a client in
//! the terminal state.

use mandate_types::{
    DenialReason, ExternalPrincipalId, FederationConnectionId, OAuthClientId, VerifiedContext,
};

use serde::Serialize;

use crate::publicclient::OAuthClientStore;
use crate::record::{ConnectionState, FederationEvent, LinkState, OAuthClientState};
use crate::{ConnectionStore, DenialClause, Denied, ExternalPrincipalStore};

/// `mandate.federation.DisableFederationConnection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisableFederationConnection {
    /// The declared `id`.
    pub id: FederationConnectionId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// `mandate.federation.UnlinkExternalPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlinkExternalPrincipal {
    /// The declared `id`.
    pub id: ExternalPrincipalId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// `mandate.federation.DisableOAuthClient`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisableOAuthClient {
    /// The declared `id`.
    pub id: OAuthClientId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// Realize `mandate.federation.DisableFederationConnection`.
///
/// The connection stops being selectable for a login and the registration record is kept;
/// nothing is destroyed (`decision-blocker:lifecycle`). A connection's issuer is
/// immutable, so this is also the first half of the "new connection and explicit
/// relinking" the contract requires for an issuer change (`federation.yaml:2`).
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the connection does not
/// resolve or belongs to another organization than the caller's verified one, and through
/// the declared `wrong-state` outcome when it is already in the terminal `Disabled` state.
pub fn disable_federation_connection(
    input: &DisableFederationConnection,
    connections: &impl ConnectionStore,
) -> Result<FederationEvent, Denied> {
    let connection = connections
        .connection(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ConnectionUnknown))?;
    // "connection is outside the verified organization". The binding is the record's own;
    // a caller-supplied organization never stands in for it (`federation.yaml:2`).
    if connection.organization_id != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    match connection.state {
        ConnectionState::Enabled => {}
        // `disable` starts from `Enabled` alone.
        ConnectionState::Disabled => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::ConnectionDisabled,
            ));
        }
    }
    Ok(FederationEvent::FederationConnectionDisabled {
        context: input.context.clone(),
        id: connection.id,
    })
}

/// Realize `mandate.federation.UnlinkExternalPrincipal`.
///
/// The link record is kept and stops holding the composite external key, which is what
/// lets the same subject be linked again — the fold reads the lifecycle state when it
/// resolves a key (`crate::record::Projection`).
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the link does not resolve
/// or belongs to another organization than the caller's verified one, and through the
/// declared `wrong-state` outcome when it is already in the terminal `Unlinked` state.
pub fn unlink_external_principal(
    input: &UnlinkExternalPrincipal,
    links: &impl ExternalPrincipalStore,
) -> Result<FederationEvent, Denied> {
    let link = links
        .external_principal(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::LinkAbsent))?;
    // "link is outside the verified organization".
    if link.organization_id != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    match link.state {
        LinkState::Linked => {}
        // `unlink` starts from `Linked` alone.
        LinkState::Unlinked => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::LinkAbsent,
            ));
        }
    }
    Ok(FederationEvent::ExternalPrincipalUnlinked {
        context: input.context.clone(),
        id: link.id,
    })
}

/// Realize `mandate.federation.DisableOAuthClient`.
///
/// The registration record is kept and stops being admitted; see the module documentation
/// for what this does *not* reach.
///
/// # The record it moves is one this domain's own fold creates
///
/// `mandate.federation.RegisterOAuthClient` is the creating command and
/// `mandate.federation.OAuthClientRegistered` its creation record
/// ([`crate::register_client`]), so a client registered through that handler is in
/// [`crate::record::Projection`] and this one reads it there:
/// `crates/mandate-federation/tests/replay.rs` drives register-then-disable through both
/// handlers and rebuilds the record from the two events alone. A client the fold did not
/// put there is still reachable through a store that holds one — the `pub` double
/// [`crate::publicclient::RecordedClients`], or an adapter over a registry this domain
/// does not write — and the event this handler then emits names a record no log of this
/// domain created, which `Projection::apply` reports as `UnknownOAuthClient` rather than
/// inventing the record the move would apply to.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the client does not
/// resolve or belongs to another organization than the caller's verified one, and through
/// the declared `wrong-state` outcome when it is already in the terminal `Disabled` state.
pub fn disable_oauth_client(
    input: &DisableOAuthClient,
    clients: &impl OAuthClientStore,
) -> Result<FederationEvent, Denied> {
    let client = clients
        .client(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ClientUnknown))?;
    // "the client is outside the verified organization".
    if client.organization_id != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    match client.state {
        OAuthClientState::Recorded => {}
        // `disable` starts from `Recorded` alone.
        OAuthClientState::Disabled => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::ClientDisabled,
            ));
        }
    }
    Ok(FederationEvent::OAuthClientDisabled {
        context: input.context.clone(),
        id: client.id,
    })
}
