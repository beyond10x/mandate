//! What a redemption re-reads before it consumes anything: the session and its epochs, the
//! bound client, the exact redirect, and the tenant.
//!
//! # The session port, and why it mirrors rather than imports
//!
//! `RedeemAuthorizationCode` "takes no context input and admits no caller-supplied selector
//! — the generated context on the emitted event takes its subject, organization and audience
//! from the code record and the session it names through the STS's session port"
//! (`credential.yaml`, the accepted summary). "The epoch whose staleness the denial names is
//! the session's own, resolved through that same port, because a redemption presents no
//! source credential of its own."
//!
//! [`SessionReads`] is that port. It is a narrowed mirror of
//! `mandate_identity::IdentityRead` — `resolve` and `snapshot`/`current`, and nothing else —
//! and it names no `mandate-identity` type: `mandate-sts` may not depend on that crate
//! (`dependency-boundaries.json`, which `cargo run -p xtask -- boundaries` decides), so
//! every value it carries is a `mandate-types` one and the verdict it needs is re-declared
//! here as [`EpochStanding`]. What answers it in a deployment is an adapter over
//! `mandate-identity`'s fold, which is the composition's
//! (`story:product-listener`, `port-adapters`), exactly as the target registry and the
//! client store are.
//!
//! The mirror is narrow on purpose. `IdentityRead` also answers `principal` and `as_of`;
//! neither is read here — a redemption reads the subject off the session it resolved, and
//! the request instant is [`crate::RequestContext::at`], which the adapter supplies so that
//! two handlers serving one request decide the same instant.
//!
//! # Four re-reads, four clauses
//!
//! `RedeemAuthorizationCode`'s denial names them: "client, redirect URI or S256 verifier
//! mismatches; the bound client is disabled; source/session epoch is stale; registered
//! target is disabled or outside the verified tenant". Each is a function here so that the
//! redemption reads as the order it decides them in, and so each can be given the shape it
//! refuses.
//!
//! **The redirect comparison is byte-exact.** `pkce-redirect` is "Redirect differs from
//! exact registered/authorized URI", and the binding the code carries is the one the
//! authorization request authorized — not whatever the client registered. Nothing is
//! normalized: not the case of the scheme or the host, not a trailing slash, not a default
//! port, not a percent-encoding of an unreserved character, not a dot segment. A comparison
//! that normalized any of those would admit a redirect the authorization request never
//! authorized, and there is no reading of "exact" under which it would not.

use mandate_token::projection::{DenialClause, Denied, ResourceServer};
use mandate_types::{
    DenialReason, EpochSnapshotRef, OAuthClientId, OrganizationId, PrincipalId,
    SecurityEpochTarget, SessionId, Timestamp,
};

use crate::code::{OAuthClientReads, admitted_client};
use crate::registry::ResourceServerReads;
use crate::store::AuthorizationCode;
use crate::{RequestContext, instant};

/// Whether the epoch snapshot a session names is still the authoritative one.
///
/// The verdict this crate needs from the identity domain, re-declared over
/// `mandate-types` values. `mandate_identity::Eligibility` is the same decision in the crate
/// that folds the generations; naming it here would be a dependency
/// `dependency-boundaries.json` refuses, and this crate compares no generations itself —
/// "an `EpochSnapshotRef` is an immutable record handle and never a generation"
/// (`decision-blocker:epoch`). What is carried is which dimension moved, because that is the
/// one thing a refusal can usefully say beyond "stale".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochStanding {
    /// Every dimension the snapshot names is at the authoritative generation.
    Current,
    /// One dimension the snapshot names has moved since it was taken.
    Stale(SecurityEpochTarget),
}

/// `mandate.identity.Session`, as a redemption reads it.
///
/// The four facts this domain needs and no more: who the session authenticates, which
/// organization it binds, which epoch snapshot it was opened under, and when it stops being
/// usable — plus whether it was revoked, which is the one lifecycle question a redemption
/// asks. It is a value over `mandate-types` types and not a view of
/// `mandate_identity::Session`; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    /// The session identity the code record names.
    pub id: SessionId,
    /// The principal the session authenticates, which becomes the credential's subject.
    pub subject: PrincipalId,
    /// The organization the session binds, which is the tenant everything else is re-read
    /// against.
    pub organization: OrganizationId,
    /// The epoch snapshot the session was opened under, when it names one.
    pub epochs: Option<EpochSnapshotRef>,
    /// When the session stops being usable.
    pub expires_at: Timestamp,
    /// Whether the session has been revoked.
    pub revoked: bool,
}

/// The session and epoch read model, behind a port.
///
/// Every method takes `&self`; none of them mutates anything, and nothing here can advance
/// a generation — the write half of the identity domain is not mirrored at all.
pub trait SessionReads {
    /// The session with this identity, when the reader records one.
    ///
    /// Named for `mandate_identity::IdentityRead::resolve`, which it mirrors.
    fn resolve(&self, id: &SessionId) -> Option<SessionBinding>;

    /// Whether the snapshot is still the authoritative one, or `None` when the reader
    /// records no such snapshot.
    ///
    /// `None` is not "current": a snapshot that cannot be resolved has not been shown to be
    /// current, and every caller here fails closed on it.
    fn epoch_standing(&self, snapshot: &EpochSnapshotRef) -> Option<EpochStanding>;
}

/// A [`SessionReads`] that answers for the sessions and snapshots it was told about.
///
/// **A double, never a shipped implementation**: a deployment answers this port from
/// `mandate-identity`'s own fold. It is `pub` and lives here because every file under
/// `tests/` compiles as its own crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordedSessions {
    sessions: Vec<SessionBinding>,
    snapshots: Vec<(EpochSnapshotRef, EpochStanding)>,
}

impl RecordedSessions {
    /// A double that knows no session and no snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a session.
    #[must_use]
    pub fn session(mut self, session: SessionBinding) -> Self {
        self.sessions.push(session);
        self
    }

    /// Record a snapshot that is still the authoritative one.
    #[must_use]
    pub fn current(mut self, snapshot: EpochSnapshotRef) -> Self {
        self.snapshots.push((snapshot, EpochStanding::Current));
        self
    }

    /// Record a snapshot one of whose dimensions has moved.
    #[must_use]
    pub fn stale(mut self, snapshot: EpochSnapshotRef, target: SecurityEpochTarget) -> Self {
        self.snapshots
            .push((snapshot, EpochStanding::Stale(target)));
        self
    }
}

impl SessionReads for RecordedSessions {
    fn resolve(&self, id: &SessionId) -> Option<SessionBinding> {
        self.sessions
            .iter()
            .find(|session| session.id == *id)
            .cloned()
    }

    fn epoch_standing(&self, snapshot: &EpochSnapshotRef) -> Option<EpochStanding> {
        self.snapshots
            .iter()
            .find(|(recorded, _)| recorded == snapshot)
            .map(|(_, standing)| standing.clone())
    }
}

/// The client a redemption presents is the one the code is bound to, and that client is
/// still a registered, enabled client of the session's organization.
///
/// Two questions, in that order. The first is this command's own — "client ... mismatches",
/// and `crates/mandate-federation/src/authorize.rs` says why it is asked here: that
/// validation "is given the record, not the proof", and a `client_id` presented alongside
/// the code "is not an input there", so `RedeemAuthorizationCode` "declares its own for STS
/// to check against the record it consumes". The second is the same re-read
/// [`crate::code::admitted_client`] performs at issuance, against the organization the
/// session binds rather than a caller-supplied one.
///
/// # Errors
///
/// Returns [`Denied`] when the presented client is not the code's, and whatever
/// [`crate::code::admitted_client`] returns for the code's own client.
pub fn bound_client(
    code: &AuthorizationCode,
    presented: &OAuthClientId,
    organization: &OrganizationId,
    clients: &impl OAuthClientReads,
) -> Result<(), Denied> {
    if code.client_id != *presented {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::ClientMismatch,
        ));
    }
    // The public-client question is issuance's: it decided whether this code could exist,
    // and a code that exists was already decided. What a redemption re-reads is the
    // registration, the tenant and the enabled state.
    admitted_client(&code.client_id, organization, clients, false)
}

/// The presented redirect is byte-for-byte the one the code authorized.
///
/// No normalization of any kind; see the module documentation for the enumeration and the
/// reason.
///
/// # Errors
///
/// Returns [`Denied`] when the two are not the same bytes.
pub fn authorized_redirect(
    code: &AuthorizationCode,
    presented: &mandate_types::RedirectUri,
) -> Result<(), Denied> {
    if code.redirect_uri.as_str().as_bytes() != presented.as_str().as_bytes() {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectMismatch,
        ));
    }
    Ok(())
}

/// The session the code names, re-read and still usable at the request instant.
///
/// The order is: the session resolves, it has not been revoked, its epoch snapshot is still
/// current, and it has not expired. The epoch is decided before the expiry because a stale
/// epoch is the condition the contract gives its own `DenialReason` to, and a session that
/// is both stale and expired is more usefully reported as stale.
///
/// A session that names **no** snapshot binds no epoch and is admitted: the response's
/// `epochs` is `Optional`, nothing failed to resolve, and there is no generation for it to
/// be behind. A session that names one the reader cannot resolve is refused `Unavailable`,
/// because nothing established that it is current — the reading
/// `mandate_identity::refresh_session` and `mandate_federation::authorize` both take for a
/// reader that cannot answer.
///
/// # Errors
///
/// Returns [`Denied`] when the session resolves to nothing, has been revoked, names a
/// snapshot that cannot be resolved, names one that is stale, or has expired — including
/// when its expiry names no instant, which is a session this handler cannot certify rather
/// than one it may admit. Two clauses carry the five conditions, because the declared
/// denial carries two phrases: [`DenialClause::SessionEpochStale`] for the epoch and
/// [`DenialClause::SessionUnusable`] for the session itself, with [`Denied::reason`]
/// telling a moved generation from a reader that could not answer.
pub fn fresh_session(
    code: &AuthorizationCode,
    sessions: &impl SessionReads,
    request: &RequestContext,
) -> Result<SessionBinding, Denied> {
    // One clause for all three of "no record", "revoked" and "expired". The declared denial
    // names "source/session epoch is stale" and no phrase for the session itself, so these
    // are reported under the nearest one it carries — the same phrase
    // [`DenialClause::SessionEpochStale`] names, with a different clause and a different
    // reason, because what a caller can act on differs. The gap is a contract observation,
    // recorded on [`DenialClause::SessionUnusable`] and on that clause's row in
    // `services/sts/tests/declared_denials.rs`.
    let unusable = || {
        Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SessionUnusable,
        )
    };
    let session = sessions.resolve(&code.session_id).ok_or_else(unusable)?;
    if session.revoked {
        return Err(unusable());
    }
    if let Some(snapshot) = session.epochs.as_ref() {
        match sessions.epoch_standing(snapshot) {
            // A snapshot that cannot be resolved has not been shown to be current, and the
            // reason tells it apart from a generation that has moved.
            None => {
                return Err(Denied::new(
                    DenialReason::Unavailable,
                    DenialClause::SessionEpochStale,
                ));
            }
            Some(EpochStanding::Stale(_)) => {
                return Err(Denied::new(
                    DenialReason::StaleEpoch,
                    DenialClause::SessionEpochStale,
                ));
            }
            Some(EpochStanding::Current) => {}
        }
    }
    // Strictly before the instant it expires at, and a session whose expiry names no
    // instant is not one this handler can date: it fails closed rather than certifying a
    // session it cannot show is live.
    if instant::is_before(&request.at, &session.expires_at) != Some(true) {
        return Err(unusable());
    }
    Ok(session)
}

/// The registration the code names, re-read against the organization the session binds.
///
/// "Registered target is disabled or outside the verified tenant", where the tenant is the
/// session's and never a caller-supplied selector. The registration is returned because the
/// redemption needs what it publishes: the audience the generated context carries and the
/// profile that bounds the credential's expiry.
///
/// # Errors
///
/// Returns [`Denied`] when the registration resolves to nothing, belongs to another
/// organization, or is disabled.
pub fn target_in_tenant(
    code: &AuthorizationCode,
    servers: &impl ResourceServerReads,
    organization: &OrganizationId,
) -> Result<ResourceServer, Denied> {
    let server = servers
        .resource_server(&code.target)
        .ok_or_else(|| Denied::new(DenialReason::Denied, DenialClause::TargetUnregistered))?;
    if server.organization_id != *organization {
        return Err(Denied::new(
            DenialReason::TenantMismatch,
            DenialClause::OrganizationMismatch,
        ));
    }
    if servers.is_enabled(&code.target) != Some(true) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::TargetDisabled,
        ));
    }
    Ok(server)
}
