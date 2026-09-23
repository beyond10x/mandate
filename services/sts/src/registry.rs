//! The audience registry: `RegisterResourceServer` and `DisableResourceServer`.
//!
//! A `ResourceServer` is the registration every other command in this domain reads. Its
//! organization binding is the caller's verified one and nothing a caller supplies — the
//! command input declares no organization at all — and its audience is unique within that
//! organization (`decision-blocker:identity-uniqueness`).
//!
//! # The read API, and what is not here
//!
//! [`ResourceServerReads`] is the fold's read surface: the registration by identity, the
//! registration that holds an `(organization_id, audience)` key, and the two questions a
//! composition asks — which organization a target belongs to, and whether it is enabled.
//!
//! This module deliberately does **not** implement `mandate_federation::authorize::TargetRegistry`.
//! `mandate-sts` has no `mandate-federation` dependency (`dependency-boundaries.json`), and
//! the adapter that presents this read model as that port belongs to the composition
//! (`story:product-listener`, `story:port-adapters`) — ruled on `story:credential-profiles`
//! at the wave B opening.

use mandate_token::CredentialProfile;
use mandate_token::projection::{
    CredentialEvent, DenialClause, Denied, Projection, ResourceServer, ResourceServerState,
};
use mandate_types::{
    Audience, DenialReason, OrganizationId, ResourceServerId, RevocationGuarantee, VerifiedContext,
};
use serde::Serialize;

use crate::{IdentityAllocator, instant};

/// The `mandate.credential.ResourceServer` read model. A fold over the event log; see
/// [`mandate_token::projection::Projection`].
pub trait ResourceServerReads {
    /// The registration with this identity, whatever its lifecycle state.
    ///
    /// A lifecycle command needs to tell "no such record" from "already disabled", and the
    /// two are different declared outcomes, so an implementation never filters by state.
    fn resource_server(&self, id: &ResourceServerId) -> Option<ResourceServer>;

    /// The enabled registration that holds an `(organization_id, audience)` key.
    fn registered(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Option<ResourceServer>;

    /// Whether that key is free to register.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal — "audience registration is ambiguous" — when it is not.
    fn admits_audience(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Result<(), Denied>;

    /// The organization a registered target belongs to, if it is registered at all.
    ///
    /// One of the two reads a composition needs; the adapter that answers another domain's
    /// target port is built over this and over [`ResourceServerReads::is_enabled`].
    fn organization_of(&self, id: &ResourceServerId) -> Option<OrganizationId> {
        self.resource_server(id)
            .map(|server| server.organization_id)
    }

    /// Whether a registered target is enabled, or `None` when no event registered it.
    ///
    /// The two answers are different: "not registered" and "registered and disabled" are
    /// different refusals in every command that reads them.
    fn is_enabled(&self, id: &ResourceServerId) -> Option<bool> {
        self.resource_server(id)
            .map(|server| server.state == ResourceServerState::Enabled)
    }
}

impl ResourceServerReads for Projection {
    fn resource_server(&self, id: &ResourceServerId) -> Option<ResourceServer> {
        Self::resource_server(self, id)
    }

    fn registered(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Option<ResourceServer> {
        Self::registered(self, organization_id, audience)
    }

    fn admits_audience(
        &self,
        organization_id: &OrganizationId,
        audience: &Audience,
    ) -> Result<(), Denied> {
        Self::admits_audience(self, organization_id, audience)
    }
}

/// `mandate.credential.RegisterResourceServer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterResourceServer {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `audience`.
    pub audience: Audience,
    /// The declared `profile`.
    pub profile: CredentialProfile,
    /// The declared `allowed_exchange_sources`.
    pub allowed_exchange_sources: Vec<ResourceServerId>,
}

/// The accepted outcome of [`RegisterResourceServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerRegistered {
    /// The declared `resource_server_id` response, which the event's `id` is sourced from.
    pub resource_server_id: ResourceServerId,
    /// The event the accepted outcome emits.
    pub event: CredentialEvent,
}

/// `mandate.credential.DisableResourceServer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisableResourceServer {
    /// The declared `id`.
    pub id: ResourceServerId,
    /// The declared `context`.
    pub context: VerifiedContext,
}

/// Whether a profile's own fields keep the promises the profile makes.
///
/// "Profile semantics are unadmitted" is a denial clause of `RegisterResourceServer`, and
/// this is what a deployment can decide about a profile before anything is issued under it:
///
/// - `max_ttl` names a positive span. A lifetime that names none is no bound, and a
///   lifetime of nothing issues a credential that has already expired.
/// - `max_ttl`, added to [`instant::LATEST_CHECKED_REQUEST_INSTANT`], lands on an instant
///   [`instant::at`] renders readably. The handler has no clock, so this is a promise about a
///   stated range of request instants and no other: under a profile admitted here, no
///   issuing path refuses for want of a readable expiry at any request instant from
///   `0000-01-01T00:00:00Z` through `3000-01-01T00:00:00Z`, both in UTC. It is not a
///   statement about what a refused bound would issue. Each path decides that per request,
///   and refuses as `ExpiryUnbounded` exactly when the request instant plus the lifetime
///   that path actually issues falls outside `0000-01-01T00:00:00Z` to
///   `9999-12-31T23:59:59Z` — under this profile or under a record carrying one this
///   handler refused. The lifetime is `max_ttl` for `IssueReferenceCredential`, the
///   signer's TTL for `IssueSelfContainedCredential` (`crate::issue`), and for
///   `RedeemAuthorizationCode` the earlier of `max_ttl` and the code's own `expires_at`
///   (`crate::redemption`), which the reader has already read and so never passes the upper
///   end.
/// - `positive_cache_ttl` names a non-negative span no longer than `max_ttl`. A cache that
///   outlives the credential authorizes after the credential has expired.
/// - `ImmediateOnline` requires online authorization. The guarantee is that a revocation is
///   effective at the next resolution; a profile that does not resolve online cannot keep
///   it.
fn admits_profile(profile: &CredentialProfile) -> Result<(), Denied> {
    let unadmitted = || Denied::new(DenialReason::Denied, DenialClause::ProfileUnadmitted);
    let max_ttl = instant::span_of(&profile.max_ttl).ok_or_else(unadmitted)?;
    let cache = instant::span_of(&profile.positive_cache_ttl).ok_or_else(unadmitted)?;
    if max_ttl <= 0 || cache < 0 || cache > max_ttl {
        return Err(unadmitted());
    }
    instant::LATEST_CHECKED_REQUEST_INSTANT
        .checked_add(max_ttl)
        .and_then(instant::at)
        .ok_or_else(unadmitted)?;
    if profile.revocation == RevocationGuarantee::ImmediateOnline
        && !profile.requires_online_authorization
    {
        return Err(unadmitted());
    }
    Ok(())
}

/// Realize `mandate.credential.RegisterResourceServer`.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the audience is already
/// registered in the caller's organization, when the profile's semantics are unadmitted, or
/// when an allowed exchange source is unresolved, disabled or outside that organization.
///
/// Whether the caller holds resource-server administration authority is an authorization
/// decision, and no crate in this crate's dependency ceiling decides one; the adapter has
/// decided it before the handler is reached.
pub fn register_resource_server(
    input: &RegisterResourceServer,
    servers: &impl ResourceServerReads,
    allocator: &mut impl IdentityAllocator,
) -> Result<ResourceServerRegistered, Denied> {
    // "audience registration is ambiguous". A read-then-write guard; storage enforces the
    // same index atomically (`docs/adr/0009-event-sourced-persistence.md`).
    servers.admits_audience(&input.context.organization, &input.audience)?;
    admits_profile(&input.profile)?;
    // "an allowed source server is unresolved/disabled/outside the verified organization".
    // Every source, not the first: a registration that admitted one bad source would admit
    // an exchange the contract refuses.
    for source in &input.allowed_exchange_sources {
        let Some(record) = servers.resource_server(source) else {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::SourceUnresolved,
            ));
        };
        if record.organization_id != input.context.organization {
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::SourceOutsideOrganization,
            ));
        }
        if record.state != ResourceServerState::Enabled {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::SourceDisabled,
            ));
        }
    }
    let resource_server_id = allocator.next_resource_server_id();
    Ok(ResourceServerRegistered {
        resource_server_id,
        event: CredentialEvent::ResourceServerRegistered {
            context: input.context.clone(),
            id: resource_server_id,
            audience: input.audience.clone(),
            credential_profile: input.profile.clone(),
            allowed_exchange_sources: input.allowed_exchange_sources.clone(),
        },
    })
}

/// Realize `mandate.credential.DisableResourceServer`.
///
/// The registration record is kept and stops being admitted; nothing is destroyed
/// (`decision-blocker:lifecycle`). It also stops holding its audience, which is what lets
/// the deployment register that audience again.
///
/// What disablement does not reach is the `AccessCredential` record of a credential already
/// issued for this target: no declared move revokes one, and `RevokeAccessCredential` is the
/// command that does. Such a credential is **not** refused at introspection — that outcome
/// is `accepted` — and it is not usable either: `crate::resolve::introspect_credential`
/// answers `active: false` for a credential whose issuing registration is disabled, or is no
/// longer the registration holding its audience. Both are read from the record's own
/// `target`, which the fold keeps for exactly this
/// (`mandate_token::projection::AccessCredential`), so the answer does not depend on which
/// registration holds that audience now.
///
/// The record is left where it is, so the credential can still be revoked afterwards, and a
/// rebuild of the log says what happened rather than what the current registry looks like.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the registration does not
/// resolve or belongs to another organization than the caller's verified one, and through
/// the declared `wrong-state` outcome when it is already in the terminal `Disabled` state.
pub fn disable_resource_server(
    input: &DisableResourceServer,
    servers: &impl ResourceServerReads,
) -> Result<CredentialEvent, Denied> {
    let server = servers
        .resource_server(&input.id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered))?;
    // "server is outside the verified organization". The binding is the record's own; a
    // caller-supplied organization never stands in for it.
    if server.organization_id != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    match server.state {
        ResourceServerState::Enabled => {}
        // `disable` starts from `Enabled` alone.
        ResourceServerState::Disabled => {
            return Err(Denied::wrong_state(
                DenialReason::Denied,
                DenialClause::ServerDisabled,
            ));
        }
    }
    Ok(CredentialEvent::ResourceServerDisabled {
        context: input.context.clone(),
        id: server.id,
    })
}
