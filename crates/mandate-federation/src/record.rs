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

use serde::Serialize;

use mandate_model::TenantResolutionRule;
use mandate_types::{
    Audience, ClientId, CorrelationId, EpochSnapshotRef, ExternalLinkMethod, ExternalPrincipalId,
    ExternalSubject, FederationConnectionId, Issuer, OAuthClientId, OrganizationId, PersistedValue,
    PkceMethod, PrincipalId, PrincipalKind, RedirectUri, SessionId, Timestamp, VerifiedContext,
};

use mandate_types::DenialReason;

use crate::{
    ConnectionStore, DenialClause, Denied, ExternalPrincipalStore, IdentityAllocator, LinkStore,
    PrincipalState, PrincipalStore,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConnectionState {
    /// The declared initial state.
    Enabled,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.federation.ExternalPrincipal.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LinkState {
    /// The declared initial state.
    Linked,
    /// The declared terminal state.
    Unlinked,
}

/// `mandate.federation.OAuthClient.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OAuthClientState {
    /// The declared initial state.
    Recorded,
    /// The declared terminal state.
    Disabled,
}

/// `mandate.federation.FederationConnection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
///
/// Each variant is one compiled payload under `generated/schema/events`, field for field:
/// the variant's fields are that payload's `properties`, with the same names and the same
/// types. `#[serde(untagged)]` is what makes that true on the wire — a variant serializes
/// as the bare payload object, with no discriminant wrapping it — and
/// `crates/mandate-federation/tests/contract_agreement.rs` decides it against the
/// generated shape of the element [`FederationEvent::ess_name`] answers. This is the shape
/// `crates/mandate-model/src/tenancy.rs` established for `mandate.tenancy`.
///
/// **`Serialize` only, deliberately: this enum does not round-trip and no code should
/// assume it does.** Under `#[serde(untagged)]` a reader cannot tell
/// `FederationConnectionDisabled`, `ExternalPrincipalUnlinked` and `OAuthClientDisabled`
/// apart — all three serialize exactly `{context, id}`, and the three `id`s are all uuid
/// strings. Reading an event back needs a tagged envelope carrying the ESS name beside the
/// payload, which belongs to the persistence story.
///
/// `mandate.federation.AuthorizationCodeIssued` is the one declared event of this domain
/// with no variant here: no handler in this crate emits it. `crate::authorize` is
/// non-consuming and returns a validation candidate that carries no event, and the STS
/// transaction that issues the code owns the emission (`federation.yaml`,
/// `AuthorizePublicClient`). A variant for it would be a payload nothing in this crate can
/// fill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
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
        /// The declared `id`: the instance the declared `moves` names.
        id: FederationConnectionId,
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
    /// `mandate.federation.ExternalPrincipalUnlinked`.
    ExternalPrincipalUnlinked {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`: the instance the declared `moves` names.
        id: ExternalPrincipalId,
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
    /// yet established. `federation.yaml` declares the fields the record needs instead of
    /// a `mandate.core.VerifiedContext` whose `credential` this command has no source for.
    ///
    /// The payload carries the whole `mandate.identity.Session` record — identity,
    /// principal, organization, connection, epoch snapshot handle and expiry — "so the
    /// identity fold materializes the session from this event alone and reads no command
    /// input or response" (`federation.yaml`, `AuthenticateFederation`). The audience and
    /// the correlation ride beside the record and are not Session fields.
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
        /// The declared `organization_id`: the organization tenant resolution reached.
        organization_id: OrganizationId,
        /// The declared `epochs`: the snapshot handle the session is bound to.
        epochs: EpochSnapshotRef,
        /// The declared `expires_at`: when the session stops being refreshable.
        expires_at: Timestamp,
    },
    /// `mandate.federation.OAuthClientDisabled`.
    OAuthClientDisabled {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `id`.
        id: OAuthClientId,
    },
}

impl FederationEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub fn ess_name(&self) -> &'static str {
        match self {
            Self::FederationConnectionCreated { .. } => {
                "mandate.federation.FederationConnectionCreated"
            }
            Self::FederationConnectionDisabled { .. } => {
                "mandate.federation.FederationConnectionDisabled"
            }
            Self::ExternalPrincipalLinked { .. } => "mandate.federation.ExternalPrincipalLinked",
            Self::ExternalPrincipalUnlinked { .. } => {
                "mandate.federation.ExternalPrincipalUnlinked"
            }
            Self::ExternalPrincipalProvisioned { .. } => {
                "mandate.federation.ExternalPrincipalProvisioned"
            }
            Self::FederationAuthenticated { .. } => "mandate.federation.FederationAuthenticated",
            Self::OAuthClientDisabled { .. } => "mandate.federation.OAuthClientDisabled",
        }
    }
}

/// A recorded link that does not hold its composite key, because another link on the same
/// key holds it.
///
/// **A view over [`Projection::links`], not a place records are kept.** Every link event
/// materializes its record, and which of several records on one key *holds* the key is
/// decided by [`Projection::link`] — the smallest `external_principal_id` — so this list is
/// recomputed from the records and their lifecycle states rather than fixed at the moment
/// an event was applied. An unlink of the holder therefore promotes the next record and
/// removes it from this list, and no entry is ever a record the fold dropped.
///
/// The write path still refuses — `link_external_principal` and
/// `provision_external_principal` deny before emitting — so a conflict on the read side is
/// the record of a race, not of an accepted command.
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
    /// A lifecycle event names a link no event created. A dropped event is a lost record.
    UnknownExternalPrincipal {
        /// The link the event named.
        id: ExternalPrincipalId,
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
///
/// # One key, one holder, whatever order a rebuild presents the streams in
///
/// Two links on one composite external key are two `ExternalPrincipal` aggregates. Nothing
/// orders their appends against each other — the event log's compare-and-set is on the
/// appending aggregate's own stream version (`docs/adr/0009-event-sourced-persistence.md`)
/// — so the key's holder cannot be a property of the order a log presents them in, and it
/// cannot be a property of the order they were *applied* either. It is a total order over
/// the records themselves: **the smallest `external_principal_id` on the key holds it**
/// ([`Projection::link`]), every other `Linked` record on that key is a
/// [`ExternalKeyConflict`], and a rebuild that interleaves the two streams differently
/// resolves the key the same way.
///
/// Every link event's record lives in one map, keyed by its own identity: a record is never
/// displaced anywhere, so [`ExternalPrincipalStore::external_principal`] and
/// [`PrincipalStore::organization_of`] answer for every link the log created, and the
/// declared `unlink` move applies to any of them. When the holder is unlinked the next
/// smallest `Linked` record on the key holds it — promotion, not a vacancy — which is what
/// makes the key's holder a function of the records alone.
///
/// `linked_at` decides nothing about the key. It is the declared timestamp of the link and
/// is carried as such; two writers racing one key hold no clock in common, and an instant
/// one of them read is not an order over the other's append.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    connections: Vec<FederationConnection>,
    links: Vec<ExternalPrincipal>,
    clients: Vec<OAuthClient>,
}

impl Projection {
    /// Materialize the read model from a log.
    ///
    /// A duplicate key does not fail the fold: every link's record is materialized, one of
    /// them holds the key ([`Projection::link`]) and the others are
    /// [`Projection::conflicts`].
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
    ///
    /// **This is the write half of decide-and-apply, and it re-checks no guard.** Every
    /// guard belongs to a handler, which reads the projection before the event exists and
    /// returns [`Denied`] instead of the event; this writes what it is handed. A fold that
    /// re-decided a guard would not be a rebuild of an accepted history
    /// (`docs/adr/0009-event-sourced-persistence.md`). What it does refuse is a log it
    /// cannot read — an event naming a record no event created — which is a statement
    /// about the log and not about the command that wrote it.
    ///
    /// # Errors
    ///
    /// Returns [`FoldError`] when the event names an instance no event created, or
    /// carries a value `federation.yaml` pins as a literal and this one does not match.
    pub fn apply(&mut self, event: &FederationEvent) -> Result<(), FoldError> {
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
            FederationEvent::FederationConnectionDisabled { context: _, id } => {
                let connection = self
                    .connections
                    .iter_mut()
                    .find(|connection| connection.id == *id)
                    .ok_or(FoldError::UnknownConnection { connection_id: *id })?;
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
            // The declared `unlink` move. The record is kept and stops holding the
            // composite key, which `record_link` reads off the lifecycle state.
            //
            // Every link the log created has a record in one map, whichever of them holds
            // the key, so this applies to any of them: two writers deciding on one key
            // against one projection is a race the write path cannot refuse — they append
            // to two `ExternalPrincipal` aggregates, so the kit's compare-and-set on the
            // appending stream does not see the other — and an unlink decided against
            // either is a log every handler accepted. Unlinking the holder promotes the
            // next smallest record on the key; unlinking a record that held nothing
            // changes no key. An identity no event ever created is still a log this fold
            // cannot read.
            FederationEvent::ExternalPrincipalUnlinked { context: _, id } => {
                let link = self
                    .links
                    .iter_mut()
                    .find(|link| link.id == *id)
                    .ok_or(FoldError::UnknownExternalPrincipal { id: *id })?;
                link.state = LinkState::Unlinked;
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
            // An authentication mutates no record *of this domain*: the record its
            // accepted outcome creates is `mandate.identity.Session`, which `mandate
            // .identity` folds from this same payload. It still names a connection, and a
            // name that resolves to nothing is a log this fold cannot read.
            FederationEvent::FederationAuthenticated {
                session_id: _,
                principal_id: _,
                audience: _,
                correlation: _,
                connection_id,
                organization_id: _,
                epochs: _,
                expires_at: _,
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

    /// Materialize one link's record.
    ///
    /// `decision-blocker:identity-uniqueness`: the unique index on
    /// `(organization, connection.issuer, external subject)` lives on the projection, and
    /// it is [`Projection::link`] — which of the records on one key holds it — rather than
    /// a refusal here. A fold records what happened; two writers that each read a free key
    /// is a race the write path refused to the extent it could see it, and the log is the
    /// record of both.
    ///
    /// Writing is insert-if-absent at the record's own identity, so a redelivered creation
    /// — which the kit's at-least-once delivery admits — writes nothing rather than
    /// returning a record from a terminal state to its initial one.
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
        if self.links.iter().any(|link| link.id == id) {
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

    /// Every recorded link that does not hold its composite key, derived from the records.
    ///
    /// A read for the adapter, not for a command: no command in this crate consults it.
    /// The adapter that owns the storage is expected to read it after a rebuild — each
    /// entry is a link that was written and does not hold its key, and its record is still
    /// in [`Projection::links`], nameable by [`ExternalPrincipalStore::external_principal`]
    /// and answerable by [`PrincipalStore::organization_of`].
    ///
    /// Recomputed on each call, in `links` order: which record holds a key is a function of
    /// the records and their lifecycle states, so an unlink of the holder promotes the next
    /// smallest record and takes it off this list.
    #[must_use]
    pub fn conflicts(&self) -> Vec<ExternalKeyConflict> {
        self.links
            .iter()
            .filter(|link| link.state == LinkState::Linked)
            .filter_map(|link| {
                let key = self.key_of(link)?;
                let holder = self.link(&key)?;
                if holder.id == link.id {
                    return None;
                }
                Some(ExternalKeyConflict {
                    key,
                    external_principal_id: link.id,
                    principal_id: link.principal_id,
                    connection_id: link.connection_id,
                })
            })
            .collect()
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
    /// Read from the one map every link's record lives in, so a link that does not hold its
    /// key is answered for exactly as the holder is. That matters because such a link is
    /// still the record of the principal it names — for `ExternalPrincipalProvisioned` it is
    /// that principal's creation record (`federation.yaml:258`) — and a principal this
    /// domain could not name would be refused by `link_external_principal` forever.
    fn organization_of(&self, principal_id: &PrincipalId) -> Option<OrganizationId> {
        self.links
            .iter()
            .find(|link| link.principal_id == *principal_id)
            .map(|link| link.organization_id)
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
    /// The record that holds the key: the smallest `external_principal_id` among the
    /// `Linked` records on it.
    ///
    /// `ExternalPrincipalId` orders on the sixteen bytes of its UUID, which is the order of
    /// its canonical lexical form, so "smallest" is a property of the identity the event
    /// carried and of nothing else — not of `linked_at`, not of the order the log presents
    /// the two aggregates in, not of the order they were applied. An unlink of the holder
    /// promotes the next smallest; see [`Projection`].
    fn link(&self, key: &ExternalKey) -> Option<ExternalPrincipal> {
        self.links
            .iter()
            .filter(|link| {
                link.state == LinkState::Linked && self.key_of(link).as_ref() == Some(key)
            })
            .min_by_key(|link| link.id)
            .cloned()
    }
}

impl ExternalPrincipalStore for Projection {
    /// The record in whatever state it holds, including the terminal `Unlinked` one: a
    /// lifecycle command needs to tell "no such record" from "already unlinked", and the
    /// two are different declared outcomes.
    fn external_principal(&self, id: &ExternalPrincipalId) -> Option<ExternalPrincipal> {
        self.links.iter().find(|link| link.id == *id).cloned()
    }
}

/// `mandate.federation.RegisterFederationConnection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
            FederationEvent::FederationConnectionDisabled { context, id } => {
                persistable(context);
                persistable(id);
            }
            FederationEvent::ExternalPrincipalUnlinked { context, id } => {
                persistable(context);
                persistable(id);
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
                organization_id,
                epochs,
                expires_at,
            } => {
                persistable(session_id);
                persistable(principal_id);
                persistable(audience);
                persistable(correlation);
                persistable(connection_id);
                persistable(organization_id);
                persistable(epochs);
                persistable(expires_at);
            }
            FederationEvent::OAuthClientDisabled { context, id } => {
                persistable(context);
                persistable(id);
            }
        }
    }
};
