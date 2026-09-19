//! `mandate.federation.RegisterOAuthClient`: the command that creates an `OAuthClient`.
//!
//! Until this landed, `federation.yaml` declared `DisableOAuthClient`,
//! `mandate.federation.OAuthClientDisabled` and **no creation**, so every log carrying a
//! disable named a record no event created and [`crate::record::Projection`] could only
//! report it as unreadable. This is the writer that closes that: its accepted outcome
//! `creates: mandate.federation.OAuthClient` with `id` as the instance, and the event it
//! emits carries the whole record.
//!
//! # The tenant is not a caller's choice
//!
//! The command takes **no organization input**. The client is bound to the organization
//! the verified context carries, and the response returns the identity and that
//! organization — which is where `mandate.federation.OAuthClientRegistered` sources both
//! from, "read from the response rather than from a value the implementation invented"
//! (`federation.yaml`, `RegisterOAuthClient`). There is therefore no caller-supplied
//! organization here for a guard to compare against the context, which is what
//! [`crate::record::register_federation_connection`] does for a connection's tenant rule.
//!
//! # What is decided here and what is admitted through a port
//!
//! Every phrase of the declared denial is decided, and the two that are judgements no
//! crate in this crate's dependency ceiling can make are admitted through
//! [`ClientRegistrationAdmission`]:
//!
//! * "Caller lacks client-administration authority" — an authorization decision, the same
//!   boundary `register_federation_connection` and `crate::disable` keep.
//! * "organization binding is invalid" — whether clients may be registered into this
//!   organization at all. The organization record is `mandate.tenancy`'s, which this crate
//!   does not read.
//! * "a redirect URI is unadmitted" — a deployment's redirect policy. Which URIs are
//!   admitted is configuration, not a property of the input, and the fold cannot answer it.
//!
//! The rest is decided here, because the contract decides it:
//!
//! * An **empty redirect set is admitted and is not a denial**. The client it registers is
//!   inert — `AuthorizePublicClient` matches the presented redirect against the registered
//!   set exactly, and an empty set matches nothing, so every authorization request to that
//!   client is refused (`crate::publicclient::registered_public_client`).
//! * `mandate.core.PkceMethod` admits `S256` and nothing else, "so no registration can name
//!   another method and none is refused for naming one". The match below is exhaustive and
//!   carries no wildcard, so a second method would have to be decided here rather than
//!   admitted unchecked.
//!
//! # Decide, apply, fold
//!
//! The handler is the **decide** half: it reads a port, writes nothing, and returns either
//! the declared event or [`Denied`]. `crate::record::Projection::apply` is the apply half
//! and re-checks no guard; see `crate::disable`.

use serde::Serialize;

use mandate_types::{
    DenialReason, OAuthClientId, OrganizationId, PkceMethod, PrincipalId, RedirectUri,
    VerifiedContext,
};

use crate::record::FederationEvent;
use crate::{DenialClause, Denied, IdentityAllocator};

/// `mandate.federation.RegisterOAuthClient`.
///
/// The declared input, field for field. No `organization_id`: see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterOAuthClient {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `public`.
    pub public: bool,
    /// The declared `redirect_uris`: the exact set that will be admitted.
    pub redirect_uris: Vec<RedirectUri>,
    /// The declared `pkce_method`.
    pub pkce_method: PkceMethod,
}

/// The accepted outcome of [`RegisterOAuthClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientRegistered {
    /// The declared response `id`: the identity this outcome decided.
    pub id: OAuthClientId,
    /// The declared response `organization_id`: the organization the client is bound to.
    pub organization_id: OrganizationId,
    /// The event the accepted outcome emits.
    pub event: FederationEvent,
}

/// What admits a client registration, behind a port.
///
/// Three questions, one per phrase of the declared denial that this crate cannot answer
/// itself. An implementation is the deployment's registration policy; the `pub` double
/// [`ConfiguredAdmission`] admits exactly what it was built with.
pub trait ClientRegistrationAdmission {
    /// Whether this verified caller holds client-administration authority.
    ///
    /// An authorization decision. No crate in this crate's dependency ceiling decides one,
    /// which is why this is a port and not a function.
    fn admits_client_administration(&self, context: &VerifiedContext) -> bool;

    /// Whether a client may be registered into this organization at all.
    ///
    /// The organization is never the caller's choice — it is the one the verified context
    /// carries — so "organization binding is invalid" is a statement about the
    /// organization and not about an input that disagrees with it.
    fn admits_organization(&self, organization_id: &OrganizationId) -> bool;

    /// Whether this exact redirect URI is admitted for that organization.
    ///
    /// Byte for byte, as everything about a redirect URI is in this crate: nothing is
    /// normalized, because every normalization admits a URI the registrant did not name
    /// (`crate::publicclient`).
    fn admits_redirect_uri(&self, organization_id: &OrganizationId, uri: &RedirectUri) -> bool;
}

/// Realize `mandate.federation.RegisterOAuthClient`.
///
/// The organization is read from `context.organization` and returned in the response, which
/// is what the emitted event sources it from.
///
/// # Errors
///
/// Returns [`Denied`] through the declared `denied` outcome when the caller lacks
/// client-administration authority, when the organization the verified context carries is
/// not one a client may be registered into, or when any presented redirect URI is
/// unadmitted. An empty redirect set is not one of those cases.
pub fn register_o_auth_client(
    input: &RegisterOAuthClient,
    admission: &impl ClientRegistrationAdmission,
    allocator: &mut impl IdentityAllocator,
) -> Result<OAuthClientRegistered, Denied> {
    // "Caller lacks client-administration authority".
    if !admission.admits_client_administration(&input.context) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ClientAdministrationAuthority,
        ));
    }
    let organization_id = input.context.organization;
    // "organization binding is invalid". The binding is the verified context's own; no
    // caller-supplied organization stands in for it (`federation.yaml:2`).
    if !admission.admits_organization(&organization_id) {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    // "a redirect URI is unadmitted" — each of them, so a set that is admitted except for
    // one entry is refused rather than silently registered without it. An empty set asks
    // nothing of the policy and is admitted.
    if input
        .redirect_uris
        .iter()
        .any(|uri| !admission.admits_redirect_uri(&organization_id, uri))
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectUriUnadmitted,
        ));
    }
    match input.pkce_method {
        // Exhaustive and without a wildcard: see the module documentation.
        PkceMethod::S256 => {}
    }
    let id = allocator.next_o_auth_client_id();
    Ok(OAuthClientRegistered {
        id,
        organization_id,
        event: FederationEvent::OAuthClientRegistered {
            context: input.context.clone(),
            id,
            organization_id,
            public: input.public,
            redirect_uris: input.redirect_uris.clone(),
            pkce_method: input.pkce_method,
        },
    })
}

/// A [`ClientRegistrationAdmission`] that admits exactly what it was built with.
///
/// A fixture, never a shipped implementation: a real admission reads the deployment's
/// policy and an authorization decision. It is `pub` because every file under `tests/`
/// compiles as its own crate; `story:testkit-doubles` moves it, with this crate's other
/// doubles, into `crates/mandate-testkit`.
///
/// It admits nothing by default, so a case that means to exercise one refusal states the
/// other two admissions and leaves that one out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfiguredAdmission {
    administrators: Vec<PrincipalId>,
    organizations: Vec<OrganizationId>,
    redirect_uris: Vec<(OrganizationId, RedirectUri)>,
}

impl ConfiguredAdmission {
    /// An admission that admits nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit this verified subject as a client administrator.
    #[must_use]
    pub fn with_administrator(mut self, principal_id: PrincipalId) -> Self {
        self.administrators.push(principal_id);
        self
    }

    /// Admit client registration into this organization.
    #[must_use]
    pub fn with_organization(mut self, organization_id: OrganizationId) -> Self {
        self.organizations.push(organization_id);
        self
    }

    /// Admit this exact redirect URI for that organization.
    #[must_use]
    pub fn with_redirect_uri(mut self, organization_id: OrganizationId, uri: RedirectUri) -> Self {
        self.redirect_uris.push((organization_id, uri));
        self
    }
}

impl ClientRegistrationAdmission for ConfiguredAdmission {
    /// The verified `subject` is the caller; the `actor` is whom it acts for, and no
    /// declared authority of this contract is held by an actor this double was not told
    /// about.
    fn admits_client_administration(&self, context: &VerifiedContext) -> bool {
        self.administrators.contains(&context.subject)
    }

    fn admits_organization(&self, organization_id: &OrganizationId) -> bool {
        self.organizations.contains(organization_id)
    }

    fn admits_redirect_uri(&self, organization_id: &OrganizationId, uri: &RedirectUri) -> bool {
        self.redirect_uris
            .iter()
            .any(|(admitted, admitted_uri)| admitted == organization_id && admitted_uri == uri)
    }
}
