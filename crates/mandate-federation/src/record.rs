//! The federation projections and the fold that materializes them.
//!
//! # What a shared issuer admits
//!
//! `register_federation_connection` refuses a rule another organization's connection on
//! the same issuer could match for the same proof: an unconditional rule where another
//! organization holds the issuer, a new connection where another organization holds an
//! unconditional rule, and a conditional rule another organization already holds with the
//! same claim name and value. One organization may hold as many connections on one issuer
//! as it likes, with any rules. The residue: the first registrant holds a claim value on a
//! shared issuer, and verifying who may claim a value is a platform registration question
//! outside this story.
//!
//! # Subjects are stored exactly as issued
//!
//! `sub` is opaque and case-sensitive, so normalizing it would merge identities the
//! issuer keeps distinct. Trim-refusal is the only normalization here: a subject that is
//! not its own trim is refused — by every command and by this fold — rather than
//! silently replaced by its trimmed form, which would be a different subject.

use mandate_model::TenantResolutionRule;
use mandate_types::{
    Audience, ClientId, CorrelationId, ExternalLinkMethod, ExternalPrincipalId, ExternalSubject,
    FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PersistedValue, PkceMethod,
    PrincipalId, PrincipalKind, RedirectUri, SessionId, Timestamp, VerifiedContext,
};

use mandate_types::DenialReason;

use crate::{
    ConnectionStore, DenialClause, Denied, IdentityAllocator, LinkStore, PrincipalState,
    PrincipalStore,
};

/// The canonical external key: `(organization, connection.issuer, external subject)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalKey {
    /// The resolved organization.
    pub organization_id: OrganizationId,
    /// The issuer, read from the validated connection.
    pub issuer: Issuer,
    /// The subject, read from the validated proof.
    pub subject: ExternalSubject,
}

/// `mandate.federation.FederationConnection.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// The declared initial state.
    Enabled,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.federation.ExternalPrincipal.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The declared initial state.
    Linked,
    /// The declared terminal state.
    Unlinked,
}

/// `mandate.federation.OAuthClient.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClientState {
    /// The declared initial state.
    Recorded,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.federation.FederationConnection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationConnection {
    /// The connection identity.
    pub id: FederationConnectionId,
    /// The organization this connection is bound to.
    pub organization_id: OrganizationId,
    /// The configured issuer. Immutable.
    pub issuer: Issuer,
    /// The configured client.
    pub client_id: ClientId,
    /// How a configured organization is selected.
    pub tenant_resolution: TenantResolutionRule,
    /// Whether this connection admits just-in-time provisioning.
    pub jit_provisioning: bool,
    /// The lifecycle state.
    pub state: ConnectionState,
}

/// `mandate.federation.ExternalPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalPrincipal {
    /// The link identity.
    pub id: ExternalPrincipalId,
    /// The organization, read from the connection.
    pub organization_id: OrganizationId,
    /// The external subject.
    pub subject: ExternalSubject,
    /// The Mandate principal.
    pub principal_id: PrincipalId,
    /// The connection the link was made through.
    pub connection_id: FederationConnectionId,
    /// How the link was made.
    pub link_method: ExternalLinkMethod,
    /// When the link was made.
    pub linked_at: Timestamp,
    /// The lifecycle state.
    pub state: LinkState,
}

/// `mandate.federation.OAuthClient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClient {
    /// The client identity.
    pub id: OAuthClientId,
    /// The organization the client belongs to.
    pub organization_id: OrganizationId,
    /// Whether the client is a public client.
    pub public: bool,
    /// The exact redirect URIs admitted.
    pub redirect_uris: Vec<RedirectUri>,
    /// The PKCE method required.
    pub pkce_method: PkceMethod,
    /// The lifecycle state.
    pub state: OAuthClientState,
}

/// An event of `mandate.federation`, in the form this crate folds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationEvent {
    /// `mandate.federation.FederationConnectionCreated`.
    FederationConnectionCreated {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `connection_id`.
        connection_id: FederationConnectionId,
        /// The declared `issuer`.
        issuer: Issuer,
        /// The declared `client_id`.
        client_id: ClientId,
        /// The declared `tenant_resolution`.
        tenant_resolution: TenantResolutionRule,
        /// The declared `jit_provisioning`.
        jit_provisioning: bool,
    },
    /// `mandate.federation.FederationConnectionDisabled`.
    FederationConnectionDisabled {
        /// The declared `context`.
        context: VerifiedContext,
        /// The instance the declared `moves` names.
        connection_id: FederationConnectionId,
    },
    /// `mandate.federation.ExternalPrincipalLinked`.
    ExternalPrincipalLinked {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `connection_id`.
        connection_id: FederationConnectionId,
        /// The declared `principal_id`.
        principal_id: PrincipalId,
        /// The command's response identity.
        external_principal_id: ExternalPrincipalId,
        /// The command's `external_subject` input.
        subject: ExternalSubject,
        /// The command's `method` input.
        link_method: ExternalLinkMethod,
        /// When the link was made.
        linked_at: Timestamp,
    },
    /// `mandate.federation.ExternalPrincipalProvisioned`.
    ///
    /// `ProvisionExternalPrincipal` has no verified caller and mints no credential, so
    /// this payload declares no `context`: `federation.yaml` names the two context fields
    /// the record actually needs — the resolved `organization_id` and the request's
    /// `correlation` — and nothing that would have to be invented.
    ExternalPrincipalProvisioned {
        /// The declared `organization_id`: the organization the connection resolved to.
        organization_id: OrganizationId,
        /// The declared `correlation`.
        correlation: CorrelationId,
        /// The declared `connection_id`.
        connection_id: FederationConnectionId,
        /// The declared `principal_id`.
        principal_id: PrincipalId,
        /// The declared `kind`.
        kind: PrincipalKind,
        /// The declared `display_name`.
        display_name: String,
        /// The declared `external_principal_id`.
        external_principal_id: ExternalPrincipalId,
        /// The declared `subject`.
        subject: ExternalSubject,
        /// The declared `link_method`.
        link_method: ExternalLinkMethod,
        /// When the link was made.
        linked_at: Timestamp,
    },
    /// `mandate.federation.FederationAuthenticated`.
    ///
    /// The authentication is what establishes a context; it cannot declare one it has not
    /// yet established. `federation.yaml` declares the four fields the record needs
    /// instead of a `mandate.core.VerifiedContext` whose `credential` this command has no
    /// source for.
    FederationAuthenticated {
        /// The declared `session_id`: the session this authentication opened.
        session_id: SessionId,
        /// The declared `principal_id`: the linked principal that authenticated.
        principal_id: PrincipalId,
        /// The declared `audience`.
        audience: Audience,
        /// The declared `correlation`.
        correlation: CorrelationId,
        /// The declared `connection_id`.
        connection_id: FederationConnectionId,
    },
    /// `mandate.federation.OAuthClientDisabled`.
    OAuthClientDisabled {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`.
        id: OAuthClientId,
    },
}

/// A link event the fold did not materialize because its key was already taken.
///
/// First wins: the key resolves to the link that reached it first, and the later event
/// is recorded here rather than failing the whole log. The write path still refuses —
/// `link_external_principal` and `provision_external_principal` deny before emitting —
/// so a conflict on the read side is the record of a race, not of an accepted command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalKeyConflict {
    /// The key that was already taken.
    pub key: ExternalKey,
    /// The link identity the refused event carried.
    pub external_principal_id: ExternalPrincipalId,
    /// The principal the refused event named.
    ///
    /// For `ExternalPrincipalProvisioned` this is a principal that event *created*
    /// (`federation.yaml:258`), so losing the key must not make it unnameable.
    pub principal_id: PrincipalId,
    /// The connection the refused event was made through.
    pub connection_id: FederationConnectionId,
}

/// A log that is not a history this fold can read.
///
/// Every variant is a statement the log makes that the contract does not admit. None of
/// them is a race: a race is an [`ExternalKeyConflict`], which the fold records and
/// carries on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FoldError {
    /// An event names a connection no event created. A dropped event is a lost record.
    UnknownConnection {
        /// The connection the event named.
        connection_id: FederationConnectionId,
    },
    /// `OAuthClientDisabled` names a client no event created — which no log can avoid,
    /// because the contract declares no command that creates an `OAuthClient`.
    UnknownOAuthClient {
        /// The client the event named.
        id: OAuthClientId,
    },
    /// `ExternalPrincipalProvisioned` carries a `link_method` other than the literal
    /// `ConfiguredFederation` that `federation.yaml` pins in its payload.
    ProvisionedLinkMethod {
        /// The link the event named.
        external_principal_id: ExternalPrincipalId,
        /// The method it carried.
        link_method: ExternalLinkMethod,
    },
    /// `ExternalPrincipalProvisioned` carries a `kind` other than the literal `User`
    /// that `federation.yaml` pins in its payload.
    ProvisionedKind {
        /// The link the event named.
        external_principal_id: ExternalPrincipalId,
        /// The kind it carried.
        kind: PrincipalKind,
    },
    /// A link event records a key whose subject is empty. Retained so that a log written
    /// before the commands refused one is read as corrupt rather than collapsed.
    EmptySubject {
        /// The link the event named.
        external_principal_id: ExternalPrincipalId,
    },
    /// A link event records a subject that is not its own trim.
    SubjectNotTrimmed {
        /// The link the event named.
        external_principal_id: ExternalPrincipalId,
    },
}

/// The read model: a fold over the event log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    connections: Vec<FederationConnection>,
    links: Vec<ExternalPrincipal>,
    clients: Vec<OAuthClient>,
    conflicts: Vec<ExternalKeyConflict>,
}

impl Projection {
    /// Materialize the read model from a log.
    ///
    /// A duplicate key does not fail the fold: the first link wins and the later one is
    /// recorded in [`Projection::conflicts`].
    ///
    /// # Errors
    ///
    /// Returns [`FoldError`] when the log is not a history this fold can read.
    pub fn fold(events: &[FederationEvent]) -> Result<Self, FoldError> {
        let mut projection = Self::default();
        for event in events {
            projection.apply(event)?;
        }
        Ok(projection)
    }

    /// Apply one event.
    ///
    /// No event is silently discarded. An event naming an instance no event created —
    /// a creation-linked one or a lifecycle move — is a log this fold cannot read, and
    /// saying so is the only way a lost record is ever noticed.
    fn apply(&mut self, event: &FederationEvent) -> Result<(), FoldError> {
        match event {
            FederationEvent::FederationConnectionCreated {
                context,
                connection_id,
                issuer,
                client_id,
                tenant_resolution,
                jit_provisioning,
            } => {
                self.connections.push(FederationConnection {
                    id: *connection_id,
                    // The payload declares no organization; the registering caller's
                    // verified organization is the binding, and
                    // `register_federation_connection` refuses any other.
                    organization_id: context.organization,
                    issuer: issuer.clone(),
                    client_id: client_id.clone(),
                    tenant_resolution: tenant_resolution.clone(),
                    jit_provisioning: *jit_provisioning,
                    state: ConnectionState::Enabled,
                });
            }
            FederationEvent::FederationConnectionDisabled {
                context: _,
                connection_id,
            } => {
                let connection = self
                    .connections
                    .iter_mut()
                    .find(|connection| connection.id == *connection_id)
                    .ok_or(FoldError::UnknownConnection {
                        connection_id: *connection_id,
                    })?;
                connection.state = ConnectionState::Disabled;
            }
            FederationEvent::ExternalPrincipalLinked {
                context: _,
                connection_id,
                principal_id,
                external_principal_id,
                subject,
                link_method,
                linked_at,
            } => {
                self.record_link(
                    *connection_id,
                    *external_principal_id,
                    subject,
                    *principal_id,
                    *link_method,
                    linked_at,
                )?;
            }
            FederationEvent::ExternalPrincipalProvisioned {
                // The key's organization is read from the connection, exactly as it is
                // for `ExternalPrincipalLinked`, so that one key is resolved one way.
                organization_id: _,
                correlation: _,
                connection_id,
                principal_id,
                kind,
                display_name: _,
                external_principal_id,
                subject,
                link_method,
                linked_at,
            } => {
                // `federation.yaml` pins two literals in this payload. They are enforced
                // where the event is read, because the write path is not the only way an
                // event reaches a fold.
                if *link_method != ExternalLinkMethod::ConfiguredFederation {
                    return Err(FoldError::ProvisionedLinkMethod {
                        external_principal_id: *external_principal_id,
                        link_method: *link_method,
                    });
                }
                if *kind != PrincipalKind::User {
                    return Err(FoldError::ProvisionedKind {
                        external_principal_id: *external_principal_id,
                        kind: *kind,
                    });
                }
                // The same event is the creation record of a `mandate.identity.Principal`.
                // That entity is projected by `mandate.identity`, not here.
                self.record_link(
                    *connection_id,
                    *external_principal_id,
                    subject,
                    *principal_id,
                    *link_method,
                    linked_at,
                )?;
            }
            // An authentication mutates no record; it is the authentication record
            // itself. It still names a connection, and a name that resolves to nothing
            // is a log this fold cannot read.
            FederationEvent::FederationAuthenticated {
                session_id: _,
                principal_id: _,
                audience: _,
                correlation: _,
                connection_id,
            } => {
                if !self
                    .connections
                    .iter()
                    .any(|connection| connection.id == *connection_id)
                {
                    return Err(FoldError::UnknownConnection {
                        connection_id: *connection_id,
                    });
                }
            }
            FederationEvent::OAuthClientDisabled { context: _, id } => {
                let client = self
                    .clients
                    .iter_mut()
                    .find(|client| client.id == *id)
                    .ok_or(FoldError::UnknownOAuthClient { id: *id })?;
                client.state = OAuthClientState::Disabled;
            }
        }
        Ok(())
    }

    /// Materialize one link, refusing a composite key the log already records.
    ///
    /// `decision-blocker:identity-uniqueness`: the unique index on
    /// `(organization, connection.issuer, external subject)` lives on the projection.
    fn record_link(
        &mut self,
        connection_id: FederationConnectionId,
        id: ExternalPrincipalId,
        subject: &ExternalSubject,
        principal_id: PrincipalId,
        link_method: ExternalLinkMethod,
        linked_at: &Timestamp,
    ) -> Result<(), FoldError> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.id == connection_id)
            .ok_or(FoldError::UnknownConnection { connection_id })?;
        // An empty key component is not a key component; the commands refuse one, and a
        // log written before they did is read as corrupt rather than collapsed.
        if subject.as_str().trim().is_empty() {
            return Err(FoldError::EmptySubject {
                external_principal_id: id,
            });
        }
        if subject.as_str() != subject.as_str().trim() {
            return Err(FoldError::SubjectNotTrimmed {
                external_principal_id: id,
            });
        }
        let key = ExternalKey {
            organization_id: connection.organization_id,
            issuer: connection.issuer.clone(),
            subject: subject.clone(),
        };
        // First wins, and "first" is a property of the events rather than of the order a
        // rebuild presents them in: the least `(linked_at, external_principal_id)` holds
        // the key. Two links for one key are on two aggregates, whose relative order the
        // log does not define, so a replay that interleaves the streams differently must
        // still resolve the key to the same record.
        let incumbent = self.links.iter().position(|link| {
            link.state == LinkState::Linked && self.key_of(link).as_ref() == Some(&key)
        });
        let incoming = ExternalPrincipal {
            id,
            organization_id: key.organization_id,
            subject: key.subject.clone(),
            principal_id,
            connection_id,
            link_method,
            linked_at: linked_at.clone(),
            state: LinkState::Linked,
        };
        if let Some(position) = incumbent {
            let held = &self.links[position];
            if (linked_at, &id) >= (&held.linked_at, &held.id) {
                self.conflicts.push(ExternalKeyConflict {
                    key,
                    external_principal_id: id,
                    principal_id,
                    connection_id,
                });
                return Ok(());
            }
            // The incoming link is the earlier one. It takes the key in place, so the
            // slot order of `links` stays the order the keys were first reached in, and
            // the record it displaces becomes the conflict.
            let displaced = std::mem::replace(&mut self.links[position], incoming);
            self.conflicts.push(ExternalKeyConflict {
                key,
                external_principal_id: displaced.id,
                principal_id: displaced.principal_id,
                connection_id: displaced.connection_id,
            });
            return Ok(());
        }
        self.links.push(ExternalPrincipal {
            id,
            organization_id: key.organization_id,
            subject: key.subject,
            principal_id,
            connection_id,
            link_method,
            linked_at: linked_at.clone(),
            state: LinkState::Linked,
        });
        Ok(())
    }

    /// Every connection, in the order it was created.
    #[must_use]
    pub fn connections(&self) -> &[FederationConnection] {
        &self.connections
    }

    /// Every external principal, in the order it was linked.
    #[must_use]
    pub fn links(&self) -> &[ExternalPrincipal] {
        &self.links
    }

    /// Every OAuth client.
    #[must_use]
    pub fn clients(&self) -> &[OAuthClient] {
        &self.clients
    }

    /// Every link event the fold did not give the key to.
    ///
    /// A read for the adapter, not for a command: no command in this crate consults it.
    /// The adapter that owns the storage is expected to read it after a rebuild — each
    /// entry is a link that was written and did not win, and for a provisioning event a
    /// principal that exists and has no link of its own.
    #[must_use]
    pub fn conflicts(&self) -> &[ExternalKeyConflict] {
        &self.conflicts
    }

    /// The canonical key of a recorded link.
    #[must_use]
    pub fn key_of(&self, link: &ExternalPrincipal) -> Option<ExternalKey> {
        let connection = self
            .connections
            .iter()
            .find(|connection| connection.id == link.connection_id)?;
        Some(ExternalKey {
            // Equal to `connection.organization_id` by construction: the fold reads it
            // from the connection and nothing else writes it.
            organization_id: link.organization_id,
            // The issuer is read from the connection, never from the link.
            issuer: connection.issuer.clone(),
            subject: link.subject.clone(),
        })
    }
}

impl ConnectionStore for Projection {
    fn connection(&self, id: &FederationConnectionId) -> Option<FederationConnection> {
        self.connections
            .iter()
            .find(|connection| connection.id == *id)
            .cloned()
    }

    fn enabled_for_issuer(&self, issuer: &Issuer) -> Vec<FederationConnection> {
        self.connections
            .iter()
            .filter(|connection| {
                connection.state == ConnectionState::Enabled && connection.issuer == *issuer
            })
            .cloned()
            .collect()
    }
}

impl PrincipalStore for Projection {
    /// The organization a principal this crate's own events recorded belongs to.
    ///
    /// A link that lost its key is still the record of the principal it names — for
    /// `ExternalPrincipalProvisioned` it is that principal's creation record
    /// (`federation.yaml:258`) — so the conflicts are read here too. Without that, the
    /// losing half of a race creates a principal in `mandate.identity` that nothing in
    /// this domain can name, and `link_external_principal` refuses it forever.
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
        self.links
            .iter()
            .find(|link| link.principal_id == *principal_id)
            .map(|link| link.organization_id)
            .or_else(|| {
                self.conflicts
                    .iter()
                    .find(|conflict| conflict.principal_id == *principal_id)
                    .map(|conflict| conflict.key.organization_id)
            })
    }

    /// `Active` for every principal this crate's events recorded.
    ///
    /// Disablement is `mandate.identity`'s own event, which this domain's log does not
    /// carry; an adapter composes this port over that domain's read model and answers
    /// `Disabled` where it applies.
    fn state_of(&self, principal_id: &PrincipalId) -> Option<PrincipalState> {
        self.organization_of(principal_id)
            .map(|_| PrincipalState::Active)
    }
}

impl LinkStore for Projection {
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal> {
        self.links
            .iter()
            .find(|link| link.state == LinkState::Linked && self.key_of(link).as_ref() == Some(key))
            .cloned()
    }
}

/// `mandate.federation.RegisterFederationConnection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterFederationConnection {
    /// The declared `context`.
    pub context: VerifiedContext,
    /// The declared `issuer`.
    pub issuer: Issuer,
    /// The declared `client_id`.
    pub client_id: ClientId,
    /// The declared `tenant_resolution`.
    pub tenant_resolution: TenantResolutionRule,
    /// The declared `jit_provisioning`.
    pub jit_provisioning: bool,
}

/// The accepted outcome of [`RegisterFederationConnection`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRegistered {
    /// The declared response.
    pub connection_id: FederationConnectionId,
    /// The event the accepted outcome emits.
    pub event: FederationEvent,
}

/// What one `mandate.core.TenantResolutionRule` matches.
enum Shape<'a> {
    /// No claim is named: every proof on the issuer matches.
    Any,
    /// Exactly the proofs carrying this validated claim and value.
    Claim(&'a str, &'a str),
    /// A claim without a value, or a value without a claim: nothing matches.
    Nothing,
}

fn shape(rule: &TenantResolutionRule) -> Shape<'_> {
    match (&rule.verified_claim_name, &rule.verified_claim_value) {
        (None, None) => Shape::Any,
        (Some(name), Some(value)) => Shape::Claim(name, value),
        _ => Shape::Nothing,
    }
}

/// Whether two rules on one issuer could both match one proof.
///
/// Decidable for the rule shapes `mandate.core.TenantResolutionRule` has, which is why
/// the registration guard can be a refusal rather than a warning.
fn collides(one: &TenantResolutionRule, other: &TenantResolutionRule) -> bool {
    match (shape(one), shape(other)) {
        (Shape::Nothing, _) | (_, Shape::Nothing) => false,
        (Shape::Any, _) | (_, Shape::Any) => true,
        (Shape::Claim(name, value), Shape::Claim(held_name, held_value)) => {
            name == held_name && value == held_value
        }
    }
}

/// Realize `mandate.federation.RegisterFederationConnection`.
///
/// # Errors
///
/// Returns [`Denied`] when the organization binding is invalid.
pub fn register_federation_connection(
    input: &RegisterFederationConnection,
    connections: &impl ConnectionStore,
    allocator: &mut impl IdentityAllocator,
) -> Result<ConnectionRegistered, Denied> {
    // "organization binding is invalid": the rule may only resolve to the organization
    // the caller is verified in. Federation-administration authority itself is an
    // authorization decision, which no crate in this crate's dependency ceiling decides.
    if input.tenant_resolution.configured_organization != input.context.organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    // "tenant-resolution ... configuration is unadmitted": a rule another organization's
    // connection on this issuer could match for the same proof makes every such login
    // ambiguous, and no command un-registers a connection, so the incumbent could not
    // undo it. Refuse the configuration rather than the logins.
    //
    // This is a read-then-write guard. Storage must enforce the same rule atomically, as
    // it must the external key; `federation.yaml:2` names only the external key, which is
    // a contract gap the coordinator records against this story.
    let foreign: Vec<FederationConnection> = connections
        .enabled_for_issuer(&input.issuer)
        .into_iter()
        .filter(|held| held.organization_id != input.context.organization)
        .collect();
    if foreign
        .iter()
        .any(|held| collides(&input.tenant_resolution, &held.tenant_resolution))
    {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TenantResolutionUnadmitted,
        ));
    }
    let connection_id = allocator.next_connection_id();
    Ok(ConnectionRegistered {
        connection_id,
        event: FederationEvent::FederationConnectionCreated {
            context: input.context.clone(),
            connection_id,
            issuer: input.issuer.clone(),
            client_id: input.client_id.clone(),
            tenant_resolution: input.tenant_resolution.clone(),
            jit_provisioning: input.jit_provisioning,
        },
    })
}

const _: () = {
    // Raw credentials never enter a persistent domain record or an audit record
    // (`AGENTS.md`). This is the check rather than a list: the match is exhaustive and
    // no pattern uses `..`, so a variant or a field added to `FederationEvent` whose
    // type is not a `PersistedValue` does not compile. Neither `CredentialSecret` nor
    // `CredentialProof` is one, and no crate can add that impl for them.
    fn persistable<T: PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_payload_is_persistable(event: &FederationEvent) {
        match event {
            FederationEvent::FederationConnectionCreated {
                context,
                connection_id,
                issuer,
                client_id,
                tenant_resolution,
                jit_provisioning,
            } => {
                persistable(context);
                persistable(connection_id);
                persistable(issuer);
                persistable(client_id);
                persistable(tenant_resolution);
                persistable(jit_provisioning);
            }
            FederationEvent::FederationConnectionDisabled {
                context,
                connection_id,
            } => {
                persistable(context);
                persistable(connection_id);
            }
            FederationEvent::ExternalPrincipalLinked {
                context,
                connection_id,
                principal_id,
                external_principal_id,
                subject,
                link_method,
                linked_at,
            } => {
                persistable(context);
                persistable(connection_id);
                persistable(principal_id);
                persistable(external_principal_id);
                persistable(subject);
                persistable(link_method);
                persistable(linked_at);
            }
            FederationEvent::ExternalPrincipalProvisioned {
                organization_id,
                correlation,
                connection_id,
                principal_id,
                kind,
                display_name,
                external_principal_id,
                subject,
                link_method,
                linked_at,
            } => {
                persistable(organization_id);
                persistable(correlation);
                persistable(connection_id);
                persistable(principal_id);
                persistable(kind);
                persistable(display_name);
                persistable(external_principal_id);
                persistable(subject);
                persistable(link_method);
                persistable(linked_at);
            }
            FederationEvent::FederationAuthenticated {
                session_id,
                principal_id,
                audience,
                correlation,
                connection_id,
            } => {
                persistable(session_id);
                persistable(principal_id);
                persistable(audience);
                persistable(correlation);
                persistable(connection_id);
            }
            FederationEvent::OAuthClientDisabled { context, id } => {
                persistable(context);
                persistable(id);
            }
        }
    }
};
