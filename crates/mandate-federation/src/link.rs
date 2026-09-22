//! `mandate.federation.LinkExternalPrincipal`.

use serde::Serialize;

use mandate_types::{
    DenialReason, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject, FederationConnectionId,
    PrincipalId, VerifiedContext,
};

use crate::PrincipalState;
use crate::RequestContext;
use crate::record::{ConnectionState, ExternalKey, FederationEvent, LinkState};
use crate::{
    ConnectionStore, DenialClause, Denied, IdentityAllocator, LinkResolution, LinkStore,
    PrincipalStore,
};

/// `mandate.federation.LinkExternalPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkExternalPrincipal {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `connection_id`.
    pub connection_id: FederationConnectionId,
    /// The declared `external_subject`.
    pub external_subject: ExternalSubject,
    /// The declared `principal_id`.
    pub principal_id: PrincipalId,
    /// The declared `method`.
    pub method: ExternalLinkMethod,
}

/// The accepted outcome of [`LinkExternalPrincipal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    /// The declared response.
    pub external_principal_id: ExternalPrincipalId,
    /// The event the accepted outcome emits.
    pub event: FederationEvent,
}

/// Realize `mandate.federation.LinkExternalPrincipal`.
///
/// # Errors
///
/// Returns [`Denied`] when the connection is unresolved or disabled, the caller's
/// verified organization is not the connection's, the method is not one this command may
/// use, or the composite key already resolves to a link.
pub fn link_external_principal(
    input: &LinkExternalPrincipal,
    request: &RequestContext,
    connections: &impl ConnectionStore,
    links: &(impl LinkStore + PrincipalStore),
    allocator: &mut impl IdentityAllocator,
) -> Result<Linked, Denied> {
    let connection = connections
        .connection(&input.connection_id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ConnectionUnknown))?;
    // "proof/connection trust is invalid".
    if connection.state != ConnectionState::Enabled {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ConnectionDisabled,
        ));
    }
    // "organization or target principal mismatches". The target principal's own
    // organization is a `mandate.identity` read this crate's ports do not declare.
    if input.context.organization != connection.organization_id {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    // "organization or target principal mismatches", the target-principal half. The
    // principal must be recorded, and recorded in this connection's organization. An
    // unanswered principal is refused: this path fails closed.
    if links.organization_of(&input.principal_id) != Some(connection.organization_id) {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::PrincipalMismatch,
        ));
    }
    // `mandate.identity.Principal` declares `Disabled` as a terminal state. A link to a
    // disabled principal is a credential waiting to be minted: the next federated login
    // on that key would resolve it and issue a session.
    if links.state_of(&input.principal_id) == Some(PrincipalState::Disabled) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::PrincipalDisabled,
        ));
    }
    // "Caller/method lacks linking authority". `ConfiguredFederation` is the method
    // `ProvisionExternalPrincipal` writes on first login; a caller may not name it here.
    // Whether the caller holds link-administration authority is an authorization
    // decision, which no crate in this crate's dependency ceiling decides.
    if input.method == ExternalLinkMethod::ConfiguredFederation {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::LinkingAuthority,
        ));
    }
    // An empty key component is not a key component: every subject that trims to
    // nothing would resolve to one record. A subject that is not its own trim is refused
    // rather than trimmed, because the trimmed form is a different subject and `sub` is
    // opaque — nothing here canonicalizes one.
    if input.external_subject.as_str().trim().is_empty() {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::EmptySubject,
        ));
    }
    if input.external_subject.as_str() != input.external_subject.as_str().trim() {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::SubjectNotTrimmed,
        ));
    }
    // "composite (organization, configured issuer, subject) key conflicts". The issuer
    // is the connection's; email equality is not consulted and cannot be. A row in the
    // terminal `Unlinked` state does not hold the key — the command reads the lifecycle
    // state itself rather than trusting an implementation of the port to filter.
    let key = ExternalKey {
        organization_id: connection.organization_id,
        issuer: connection.issuer.clone(),
        subject: input.external_subject.clone(),
    };
    if links
        .link(&key)
        .is_some_and(|held| held.state == LinkState::Linked)
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::LinkConflict,
        ));
    }
    let external_principal_id = allocator.next_external_principal_id();
    Ok(Linked {
        external_principal_id,
        event: FederationEvent::ExternalPrincipalLinked {
            context: input.context.clone(),
            connection_id: connection.id,
            principal_id: input.principal_id,
            external_principal_id,
            subject: key.subject,
            link_method: input.method,
            linked_at: request.at.clone(),
        },
    })
}
