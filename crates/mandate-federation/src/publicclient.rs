//! The registered OAuth client read model, and what makes one a *registered public
//! client* for `mandate.federation.AuthorizePublicClient` (`federation.yaml:320-368`).
//!
//! # The port, and why it has a double
//!
//! [`OAuthClientStore`] is the sibling of [`crate::ConnectionStore`]: a read model that
//! is a fold over the event log ([`crate::record::Projection`]), declared as a trait so
//! that an adapter with a different store answers the same question. The fold's own
//! answer is implemented here.
//!
//! `mandate.federation.OAuthClientRegistered` is the creation record — emitted by
//! `RegisterOAuthClient`'s accepted outcome (`crate::register_client`) — so the fold
//! materializes every client a log of this domain registered and this port answers for it.
//! A client no registration in the log created is answered `None`, which is what makes an
//! unregistered client a refusal rather than an admission. [`RecordedClients`] stays as the
//! `pub` double for cases that need a client without a log, `pub` for the reason every
//! double in this crate is: each file under `tests/` compiles as its own crate.
//!
//! # Exactly registered
//!
//! A redirect URI is compared byte for byte. Nothing is normalized — not a trailing
//! slash, not the case of a host, not a percent-encoding, not a `..` segment — because
//! every normalization admits a URI the registrant did not register, and the contract
//! declares an "exact redirect URI" binding.

use mandate_types::{
    DenialReason, OAuthClientId, OrganizationId, PkceMethod, RedirectUri, ResourceServerId,
};

use crate::authorize::TargetRegistry;
use crate::record::{OAuthClient, OAuthClientState, Projection};
use crate::{DenialClause, Denied};

/// The registered-client read model, keyed by the client identity.
pub trait OAuthClientStore {
    /// The client with this identity, whatever its lifecycle state.
    ///
    /// An implementation may return a row in any state. The command reads
    /// [`OAuthClient::state`] itself rather than relying on an implementation to filter,
    /// because a port cannot make that a property of the command.
    fn client(&self, id: &OAuthClientId) -> Option<OAuthClient>;
}

impl OAuthClientStore for Projection {
    fn client(&self, id: &OAuthClientId) -> Option<OAuthClient> {
        self.clients()
            .iter()
            .find(|client| &client.id == id)
            .cloned()
    }
}

/// Resolve the registered public client a request names, or refuse.
///
/// Every condition the declared denial names about the client is decided here: "client is
/// not a registered public client", "the client is disabled", the "exact redirect URI"
/// binding, and the organization the client is bound to. The organization is the one the
/// authenticated session resolves to; it is never read from the caller's request.
///
/// The client's `pkce_method` is matched exhaustively and without a wildcard: the
/// contract declares one method (`crates/mandate-types/src/enumeration.rs:10`), so a
/// second one would fail to compile here rather than be admitted unchecked.
///
/// # Errors
///
/// Returns [`Denied`] when the client does not resolve, is not public, is in the terminal
/// `Disabled` state, is bound to another organization, or has not registered the
/// presented redirect URI exactly.
pub fn registered_public_client(
    clients: &impl OAuthClientStore,
    client_id: &OAuthClientId,
    redirect_uri: &RedirectUri,
    organization_id: &OrganizationId,
) -> Result<OAuthClient, Denied> {
    let client = clients
        .client(client_id)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::ClientUnknown))?;
    match client.state {
        OAuthClientState::Recorded => {}
        OAuthClientState::Disabled => {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::ClientDisabled,
            ));
        }
    }
    if !client.public {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ClientNotPublic,
        ));
    }
    // The tenant binding is the client's own; a caller-supplied organization never
    // stands in for it (`federation.yaml:2`).
    if &client.organization_id != organization_id {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectMismatch,
        ));
    }
    match client.pkce_method {
        // Exhaustive and without a wildcard: see the function documentation.
        PkceMethod::S256 => {}
    }
    Ok(client)
}

/// An [`OAuthClientStore`] over the clients a test recorded, and the
/// [`TargetRegistry`] over the targets it recorded.
///
/// One double answering two read models, exactly as [`crate::RecordedPrincipals`] answers
/// three: `AuthorizePublicClient` reads both. The client half now has a creating command
/// and a fold that answers it (`crate::register_client`), so a case may drive either; the
/// target half is `mandate.tenancy`'s record, which no event of this domain creates and
/// this double is the only answer for.
///
/// A fixture, never a shipped implementation: the clients and targets it answers for are
/// the ones a test put in it. It is `pub` because every file under `tests/` compiles as
/// its own crate; `story:testkit-doubles` moves it, with this crate's other doubles, into
/// `crates/mandate-testkit`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordedClients {
    clients: Vec<OAuthClient>,
    targets: Vec<(ResourceServerId, OrganizationId)>,
}

impl RecordedClients {
    /// A store that records no client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one client, in whatever lifecycle state it carries.
    ///
    /// # Panics
    ///
    /// Panics, naming the identity, when a client with that identity is already recorded.
    /// A read model answering two rows for one identity is not a state any log can reach,
    /// so a fixture that builds one has a mistake in it, and a silent first-wins answer
    /// would hide it behind whichever line was written first.
    #[must_use]
    pub fn with_client(mut self, client: OAuthClient) -> Self {
        assert!(
            !self.clients.iter().any(|recorded| recorded.id == client.id),
            "client {} is already recorded in this store",
            client.id
        );
        self.clients.push(client);
        self
    }

    /// Record one registered target as belonging to an organization.
    #[must_use]
    pub fn with_target(
        mut self,
        target: ResourceServerId,
        organization_id: OrganizationId,
    ) -> Self {
        self.targets.push((target, organization_id));
        self
    }
}

impl OAuthClientStore for RecordedClients {
    fn client(&self, id: &OAuthClientId) -> Option<OAuthClient> {
        self.clients.iter().find(|client| &client.id == id).cloned()
    }
}

impl TargetRegistry for RecordedClients {
    fn target_organization(&self, id: &ResourceServerId) -> Option<OrganizationId> {
        self.targets
            .iter()
            .find(|(target, _)| target == id)
            .map(|(_, organization_id)| *organization_id)
    }
}
