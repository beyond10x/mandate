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
//! The phrases of the declared denial that are judgements no crate in this crate's
//! dependency ceiling can make, or reads of records this handler does not hold, are
//! admitted through [`ClientRegistrationAdmission`]:
//!
//! * "Caller lacks client-administration authority" — an authorization decision, the same
//!   boundary `register_federation_connection` and `crate::disable` keep.
//! * "organization binding is invalid" — whether clients may be registered into this
//!   organization at all. The organization record is `mandate.tenancy`'s, which this crate
//!   does not read.
//! * "a redirect URI is unadmitted" — a deployment's redirect policy. Which URIs are
//!   admitted is configuration, not a property of the input, and the fold cannot answer it.
//! * "a ... post-logout redirect URI is unadmitted" — the same policy question about the
//!   other redirect set, asked through its own method
//!   ([`ClientRegistrationAdmission::admits_post_logout_redirect_uri`]): a URI admitted as a
//!   login redirect is not thereby admitted as a post-logout one, and the provided answer is
//!   `false`, as for a trusted peer.
//! * "a trusted peer names ... no client registered in the verified organization" — a read
//!   of the registered clients, which this decide-only handler does not hold. The port
//!   answers it per peer, and fails closed by default
//!   ([`ClientRegistrationAdmission::admits_trusted_peer`]).
//!
//! The phrases the input alone decides are decided here, before any identity is allocated:
//!
//! * "a public client states a secret verifier or does not require PKCE" — a public client
//!   authenticates with PKCE alone (forks F2 and F3).
//! * "a confidential client states no verifier or more than two" — one, or two so that a
//!   secret can be rotated (fork F2).
//! * "a trusted peer names the client itself" — compared against the identity this outcome
//!   allocates, so it holds even for an admission that would answer for that identity.
//!
//! The client-type phrases are [`decide_client_type`], `pub` so that a composition seeding
//! clients from documents decides them by this same function rather than by a copy.
//!
//! The rest is decided here, because the contract decides it:
//!
//! * An **empty redirect set is admitted and is not a denial**. The client it registers is
//!   inert — `AuthorizeClient` matches the presented redirect against the registered
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
    CredentialVerifier, DenialReason, IdTokenSigningAlgorithm, OAuthClientId, OAuthClientType,
    OrganizationId, PkceMethod, PrincipalId, RedirectUri, VerifiedContext,
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
    /// The declared `client_type`.
    pub client_type: OAuthClientType,
    /// The declared `secret_verifiers`.
    pub secret_verifiers: Vec<CredentialVerifier>,
    /// The declared `redirect_uris`: the exact set that will be admitted.
    pub redirect_uris: Vec<RedirectUri>,
    /// The declared `pkce_method`.
    pub pkce_method: PkceMethod,
    /// The declared `pkce_required`.
    pub pkce_required: bool,
    /// The declared `trusted_peers`.
    pub trusted_peers: Vec<OAuthClientId>,
    /// The declared `post_logout_redirect_uris`.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The declared `id_token_signed_response_alg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<IdTokenSigningAlgorithm>,
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

    /// Whether `peer` names a client registered in that organization, so that it may be
    /// listed as a trusted peer of the client being registered.
    ///
    /// A read of the registered clients, which the decide-only handler does not hold. The
    /// provided answer is `false`: an implementation that does not read the registry
    /// refuses every trusted peer rather than admitting one it cannot place.
    fn admits_trusted_peer(&self, organization_id: &OrganizationId, peer: &OAuthClientId) -> bool {
        let _ = (organization_id, peer);
        false
    }

    /// Whether this exact post-logout redirect URI is admitted for that organization.
    ///
    /// Byte for byte, as [`Self::admits_redirect_uri`], and a separate question: where a
    /// client may send the browser after logout is not where it may receive a code. The
    /// provided answer is `false`, so an implementation that states no post-logout policy
    /// refuses every such URI rather than admitting one nobody admitted. An empty set asks
    /// nothing.
    fn admits_post_logout_redirect_uri(
        &self,
        organization_id: &OrganizationId,
        uri: &RedirectUri,
    ) -> bool {
        let _ = (organization_id, uri);
        false
    }
}

/// The phrases of the declared denial the client type alone decides, given the number of
/// secret verifiers the registration carries and whether it requires PKCE.
///
/// "a public client states a secret verifier or does not require PKCE" (forks F2 and F3) and
/// "a confidential client states no verifier or more than two" (fork F2). Exhaustive over
/// [`OAuthClientType`], so a third client type would have to be decided here.
///
/// # Errors
///
/// The declared [`Denied`] for the first phrase the inputs meet.
pub fn decide_client_type(
    client_type: OAuthClientType,
    verifiers: usize,
    pkce_required: bool,
) -> Result<(), Denied> {
    match client_type {
        OAuthClientType::Public => {
            // "a public client states a secret verifier" (fork F2).
            if verifiers != 0 {
                return Err(Denied::new(
                    DenialReason::Denied,
                    DenialClause::PublicClientVerifier,
                ));
            }
            // "a public client ... does not require PKCE" (fork F3).
            if !pkce_required {
                return Err(Denied::new(
                    DenialReason::Denied,
                    DenialClause::PublicClientPkceOptional,
                ));
            }
            Ok(())
        }
        OAuthClientType::Confidential => match verifiers {
            // "a confidential client states no verifier".
            0 => Err(Denied::new(
                DenialReason::Denied,
                DenialClause::ConfidentialVerifierAbsent,
            )),
            // One, or two so that a secret can be rotated (fork F2).
            1 | 2 => Ok(()),
            // "... or more than two".
            _ => Err(Denied::new(
                DenialReason::Denied,
                DenialClause::ConfidentialVerifierExcess,
            )),
        },
    }
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
/// not one a client may be registered into, when any presented redirect URI or post-logout
/// redirect URI is
/// unadmitted, when a public client states a secret verifier or does not require PKCE,
/// when a confidential client states no verifier or more than two, or when a trusted peer
/// names the client itself or a client the admission does not place in the verified
/// organization. An empty redirect set is not one of those cases.
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
    // "a ... post-logout redirect URI is unadmitted" — each of them, through its own
    // question. An empty set asks nothing of the policy.
    if input
        .post_logout_redirect_uris
        .iter()
        .any(|uri| !admission.admits_post_logout_redirect_uri(&organization_id, uri))
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
    // The client type's own constraints, which the input alone decides.
    decide_client_type(
        input.client_type,
        input.secret_verifiers.len(),
        input.pkce_required,
    )?;
    // "a trusted peer names ... no client registered in the verified organization" — each
    // of them, as for the redirect set.
    if input
        .trusted_peers
        .iter()
        .any(|peer| !admission.admits_trusted_peer(&organization_id, peer))
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TrustedPeerUnknown,
        ));
    }
    let id = allocator.next_o_auth_client_id();
    // "a trusted peer names the client itself". Decided against the identity just
    // allocated, so it holds whatever the admission answers for that identity.
    if input.trusted_peers.contains(&id) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TrustedPeerSelf,
        ));
    }
    Ok(OAuthClientRegistered {
        id,
        organization_id,
        event: FederationEvent::OAuthClientRegistered {
            context: input.context.clone(),
            id,
            organization_id,
            client_type: input.client_type,
            secret_verifiers: input.secret_verifiers.clone(),
            redirect_uris: input.redirect_uris.clone(),
            pkce_method: input.pkce_method,
            pkce_required: input.pkce_required,
            trusted_peers: input.trusted_peers.clone(),
            post_logout_redirect_uris: input.post_logout_redirect_uris.clone(),
            id_token_signed_response_alg: input.id_token_signed_response_alg,
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
    post_logout_redirect_uris: Vec<(OrganizationId, RedirectUri)>,
    registered_clients: Vec<(OrganizationId, OAuthClientId)>,
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

    /// Admit this exact post-logout redirect URI for that organization.
    #[must_use]
    pub fn with_post_logout_redirect_uri(
        mut self,
        organization_id: OrganizationId,
        uri: RedirectUri,
    ) -> Self {
        self.post_logout_redirect_uris.push((organization_id, uri));
        self
    }

    /// Answer that this client is registered in that organization, so it may be named as
    /// a trusted peer there.
    #[must_use]
    pub fn with_registered_client(
        mut self,
        organization_id: OrganizationId,
        id: OAuthClientId,
    ) -> Self {
        self.registered_clients.push((organization_id, id));
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

    fn admits_post_logout_redirect_uri(
        &self,
        organization_id: &OrganizationId,
        uri: &RedirectUri,
    ) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|(admitted, admitted_uri)| admitted == organization_id && admitted_uri == uri)
    }

    fn admits_trusted_peer(&self, organization_id: &OrganizationId, peer: &OAuthClientId) -> bool {
        self.registered_clients
            .iter()
            .any(|(admitted, id)| admitted == organization_id && id == peer)
    }
}
