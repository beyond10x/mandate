//! The authorization-code record, its fold, and the append the command path commits
//! through.
//!
//! # Why the record is here
//!
//! "STS alone owns authorization-code verifier storage and consumption"
//! (`systems/mandate/domains/credential.yaml`), `docs/architecture/ownership.md:15` assigns
//! the authorization-code projection to the STS, and
//! [`mandate_token::projection`] says the same from the other side: the code record is
//! **not** projected there. So this is the fourth `mandate.credential` entity, folded here,
//! beside the three `mandate-token` folds.
//!
//! The fold type is [`CodeProjection`] and not `Projection`: a handler in this crate reads
//! both it and [`mandate_token::projection::Projection`], and two types called the same
//! thing in one function body is a name a later reader has to disambiguate by import.
//!
//! # What `mandate-federation` holds, and why it is not this
//!
//! `mandate_federation::authorize::AuthorizationCode` mirrors the fields
//! `AuthorizePublicClient` validates, as a caller-supplied **input**, and deliberately
//! omits the declared `verifier`. This is the record: it carries the verifier, it is
//! written by events and by nothing else, and since this story it is the single realizer of
//! `mandate.credential.AuthorizationCode` and of its `.State`
//! (`services/sts/src/lib.rs`; `crates/mandate-federation/src/lib.rs` releases the latter).
//!
//! # Decide, apply, fold — and the window between them
//!
//! [`CodeProjection::apply`] writes what it is handed and re-checks no guard; the guards are
//! [`crate::code`]'s and [`crate::redemption`]'s. Writing a record is insert-if-absent at
//! the record's own identity and `consume` honours its declared `from: [Issued]` set, so a
//! redelivered or late event under the kit's at-least-once delivery writes nothing rather
//! than returning a record to a state the contract does not admit it moving back to.
//!
//! The window between a decision and the append that follows it is closed by
//! [`AuthorizationCodeLog::append`]: `docs/adr/0009-event-sourced-persistence.md` makes the
//! aggregate append a compare-and-set on the expected stream version, one append group per
//! boundary, with the projection committing inside the group or rolling back with it. A
//! decision read from a state that has since moved fails the append, which is the whole of
//! the one-winner redemption `decision-blocker:epoch-atomicity` asks for.
//!
//! # The fake is a double, not a second mechanism
//!
//! [`InMemoryCodeLog`] has the kit's shape and none of its durability. `eventlog-core` is
//! not in this crate's dependency ceiling (`dependency-boundaries.json`) and ADR 0009
//! introduces no second mechanism, so the deployment attaches the kit at
//! [`AuthorizationCodeLog`] and this double is what the cases run against — wave C ruling 6:
//! the race case advances `decision-blocker:epoch-atomicity` and does not clear it. It is
//! `pub` for the reason every double in this crate is: each file under `tests/` compiles as
//! its own crate.

use mandate_token::CredentialDescriptor;
use mandate_token::projection::CredentialEvent;
use mandate_token::verifier::matches;
use mandate_types::{
    AuthorityScope, AuthorizationCodeId, CredentialId, CredentialVerifier, EpochSnapshotRef,
    OAuthClientId, PersistedValue, PkceChallenge, PkceMethod, RedirectUri, ResourceServerId,
    SessionId, Timestamp, VerifiedContext,
};
use serde::Serialize;
use std::fmt;

/// `mandate.credential.AuthorizationCode.State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AuthorizationCodeState {
    /// The declared initial state.
    Issued,
    /// The declared terminal state `consume` moves to.
    Consumed,
}

/// `mandate.credential.AuthorizationCode`.
///
/// Every declared field, and no field the entity does not declare. `verifier` is the
/// non-reversible verifier of the code itself and never the code:
/// `mandate.core.CredentialSecret` is not a [`PersistedValue`], which the check at the foot
/// of this module makes the compiler's business, and
/// [`mandate_token::verifier::CredentialDomain::AuthorizationCodeVerifier`] is the domain it
/// is derived in, so a code presented where a credential proof is expected resolves to
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationCode {
    /// The declared identity.
    pub id: AuthorizationCodeId,
    /// The registered public client the code is bound to.
    pub client_id: OAuthClientId,
    /// The authenticated session the code was issued under.
    pub session_id: SessionId,
    /// The non-reversible verifier of the code itself.
    pub verifier: CredentialVerifier,
    /// The recorded PKCE challenge.
    pub challenge: PkceChallenge,
    /// The recorded PKCE method.
    pub method: PkceMethod,
    /// The exact redirect URI the code authorized.
    pub redirect_uri: RedirectUri,
    /// When the code stops being redeemable.
    pub expires_at: Timestamp,
    /// The registered target the code was issued for.
    pub target: ResourceServerId,
    /// The narrowed scope the code carries.
    pub scope: AuthorityScope,
    /// The lifecycle state.
    pub state: AuthorizationCodeState,
}

/// An event of `mandate.credential` that writes the authorization-code record.
///
/// Each variant is one compiled payload under `generated/schema/events`, field for field.
/// `#[serde(untagged)]` is what makes that true on the wire — a variant serializes as the
/// bare payload object, with no discriminant wrapping it — and
/// `services/sts/tests/store.rs` decides each against the generated shape of the element
/// [`AuthorizationCodeEvent::ess_name`] answers.
///
/// **`Serialize` only, deliberately**, for the reason
/// [`mandate_token::projection::CredentialEvent`] is: under `#[serde(untagged)]` reading an
/// event back needs a tagged envelope carrying the ESS name beside the payload, which
/// belongs to the persistence story.
///
/// `AuthorizationCodeRedeemed` is declared in two folds because it writes two records.
/// `credential.yaml`'s header: the event "also seeds a `mandate.credential.AccessCredential`
/// ... The event carries the whole AccessCredential record ... so a fold materializes the
/// credential from the event and the issuing registration the log already holds". This
/// fold consumes the code; [`AuthorizationCodeEvent::credential_event`] is the same payload
/// as the credential fold reads it, and `services/sts/tests/store.rs` decides that the two
/// encode identically rather than trusting that they were kept in step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AuthorizationCodeEvent {
    /// `mandate.credential.AuthorizationCodeIssued`.
    AuthorizationCodeIssued {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `code_id`: the command's response identity.
        code_id: AuthorizationCodeId,
        /// The declared `client_id`.
        client_id: OAuthClientId,
        /// The declared `session_id`.
        session_id: SessionId,
        /// The declared `verifier`: non-reversible, never the code.
        verifier: CredentialVerifier,
        /// The declared `challenge`.
        challenge: PkceChallenge,
        /// The declared `method`.
        method: PkceMethod,
        /// The declared `redirect_uri`.
        redirect_uri: RedirectUri,
        /// The declared `expires_at`.
        expires_at: Timestamp,
        /// The declared `target`.
        target: ResourceServerId,
        /// The declared `scope`: the narrowed authority the code carries.
        scope: AuthorityScope,
    },
    /// `mandate.credential.AuthorizationCodeRedeemed`.
    AuthorizationCodeRedeemed {
        /// The declared `context`.
        context: VerifiedContext,
        /// The declared `code_id`: the instance the declared `moves` names.
        code_id: AuthorizationCodeId,
        /// The declared `credential_id`: the command's response identity.
        credential_id: CredentialId,
        /// The declared `reference_verifier`: non-reversible, never the credential.
        #[serde(skip_serializing_if = "Option::is_none")]
        reference_verifier: Option<CredentialVerifier>,
        /// The declared `epochs`.
        #[serde(skip_serializing_if = "Option::is_none")]
        epochs: Option<EpochSnapshotRef>,
        /// The declared `issued_at`.
        issued_at: Timestamp,
        /// The declared `descriptor`.
        descriptor: CredentialDescriptor,
        /// The declared `target`.
        target: ResourceServerId,
    },
}

impl AuthorizationCodeEvent {
    /// The qualified ESS name of the payload this event is.
    ///
    /// The match is exhaustive and carries no wildcard arm, so a variant added without a
    /// name here does not compile.
    #[must_use]
    pub const fn ess_name(&self) -> &'static str {
        match self {
            Self::AuthorizationCodeIssued { .. } => "mandate.credential.AuthorizationCodeIssued",
            Self::AuthorizationCodeRedeemed { .. } => {
                "mandate.credential.AuthorizationCodeRedeemed"
            }
        }
    }

    /// The same payload, as the `mandate-token` credential fold reads it.
    ///
    /// `None` for an issuance, which seeds no credential. `Some` for a redemption, which
    /// seeds one: the credential the outcome issues is declared by this event and by
    /// nothing else (`credential.yaml`'s header), so the composition that appends the
    /// consume to this crate's log appends the same payload to the credential log.
    #[must_use]
    pub fn credential_event(&self) -> Option<CredentialEvent> {
        match self {
            Self::AuthorizationCodeIssued { .. } => None,
            Self::AuthorizationCodeRedeemed {
                context,
                code_id,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
            } => Some(CredentialEvent::AuthorizationCodeRedeemed {
                context: context.clone(),
                code_id: *code_id,
                credential_id: *credential_id,
                reference_verifier: reference_verifier.clone(),
                epochs: *epochs,
                issued_at: issued_at.clone(),
                descriptor: descriptor.clone(),
                target: *target,
            }),
        }
    }

    /// The code record this event writes.
    #[must_use]
    pub const fn code_id(&self) -> &AuthorizationCodeId {
        match self {
            Self::AuthorizationCodeIssued { code_id, .. }
            | Self::AuthorizationCodeRedeemed { code_id, .. } => code_id,
        }
    }
}

/// A log that is not a history this fold can read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodeFoldError {
    /// A lifecycle event names a code no event created.
    UnknownAuthorizationCode {
        /// The code the event named.
        id: AuthorizationCodeId,
    },
}

impl fmt::Display for CodeFoldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAuthorizationCode { id } => {
                write!(formatter, "no event created the authorization code {id}")
            }
        }
    }
}

impl std::error::Error for CodeFoldError {}

/// The read model of `mandate.credential.AuthorizationCode`: a fold over the event log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeProjection {
    codes: Vec<AuthorizationCode>,
}

impl CodeProjection {
    /// Materialize the read model from a log.
    ///
    /// # Errors
    ///
    /// Returns [`CodeFoldError`] when the log is not a history this fold can read.
    pub fn fold(events: &[AuthorizationCodeEvent]) -> Result<Self, CodeFoldError> {
        let mut projection = Self::default();
        for event in events {
            projection.apply(event)?;
        }
        Ok(projection)
    }

    /// Apply one event.
    ///
    /// # Errors
    ///
    /// Returns [`CodeFoldError`] when the event names a code no event created.
    pub fn apply(&mut self, event: &AuthorizationCodeEvent) -> Result<(), CodeFoldError> {
        match event {
            AuthorizationCodeEvent::AuthorizationCodeIssued {
                context: _,
                code_id,
                client_id,
                session_id,
                verifier,
                challenge,
                method,
                redirect_uri,
                expires_at,
                target,
                scope,
            } => {
                // Insert-if-absent: a redelivered creation is a normal event under the
                // kit's at-least-once delivery and writes nothing.
                if self.authorization_code(code_id).is_some() {
                    return Ok(());
                }
                self.codes.push(AuthorizationCode {
                    id: *code_id,
                    client_id: *client_id,
                    session_id: *session_id,
                    verifier: verifier.clone(),
                    challenge: challenge.clone(),
                    method: *method,
                    redirect_uri: redirect_uri.clone(),
                    expires_at: expires_at.clone(),
                    target: *target,
                    scope: scope.clone(),
                    state: AuthorizationCodeState::Issued,
                });
            }
            AuthorizationCodeEvent::AuthorizationCodeRedeemed { code_id, .. } => {
                let code = self
                    .codes
                    .iter_mut()
                    .find(|code| code.id == *code_id)
                    .ok_or(CodeFoldError::UnknownAuthorizationCode { id: *code_id })?;
                // `consume` starts `from: [Issued]` and `Consumed` is terminal: a
                // redelivery after it writes nothing. Refusing here instead would make a
                // redelivered event a log this fold cannot read, and under
                // `docs/adr/0009-event-sourced-persistence.md` there is nowhere else to
                // read the record from. The *command* is refused through the declared
                // `wrong-state` outcome ([`crate::redemption`]); this is the fold's half of
                // the same rule.
                if code.state == AuthorizationCodeState::Issued {
                    code.state = AuthorizationCodeState::Consumed;
                }
            }
        }
        Ok(())
    }

    /// Every code, in the order it was issued.
    #[must_use]
    pub fn authorization_codes(&self) -> &[AuthorizationCode] {
        &self.codes
    }

    /// The code with this identity, whatever its lifecycle state.
    ///
    /// A redemption needs to tell "no such code" from "already consumed": the two are
    /// different declared outcomes, so this never filters by state.
    #[must_use]
    pub fn authorization_code(&self, id: &AuthorizationCodeId) -> Option<AuthorizationCode> {
        self.codes.iter().find(|code| code.id == *id).cloned()
    }

    /// The code whose recorded verifier is this one, whatever its lifecycle state.
    ///
    /// The whole slice is read: this does **not** stop at the record it matches. A scan
    /// that returned early would take a time that depends on *where* the matching record
    /// sits in the log, which is a position a caller can move by having codes issued, and
    /// `mandate_token::projection::Projection::resolve` only promises that the time does
    /// not depend on how much of a presented verifier is correct. Here it depends on how
    /// many records there are and on nothing else.
    ///
    /// The comparison is [`mandate_token::verifier::matches`], which reads both values to
    /// the end of the longer one.
    #[must_use]
    pub fn authorization_code_by_verifier(
        &self,
        verifier: &CredentialVerifier,
    ) -> Option<AuthorizationCode> {
        let mut found: Option<&AuthorizationCode> = None;
        for code in &self.codes {
            if matches(&code.verifier, verifier) && found.is_none() {
                found = Some(code);
            }
        }
        found.cloned()
    }
}

/// The `mandate.credential.AuthorizationCode` read model, as a deciding handler names it.
///
/// A port rather than the concrete fold, for the reason
/// [`crate::registry::ResourceServerReads`] is one: a deployment reads the record from its
/// own store, and the fold is one implementation of that.
pub trait AuthorizationCodeReads {
    /// The code with this identity, whatever its lifecycle state.
    fn authorization_code(&self, id: &AuthorizationCodeId) -> Option<AuthorizationCode>;

    /// The code whose recorded verifier is this one, whatever its lifecycle state.
    ///
    /// **The read the token endpoint's `code_id` is resolved through.**
    /// `RedeemAuthorizationCode.code_id` "is resolved by the trusted adapter from proof; it
    /// is not a public OAuth parameter or authority selector" (`credential.yaml`'s header),
    /// and the wire form carries only the `code` — `crates/mandate-server/src/decode.rs`
    /// refuses a caller-presented `code_id` and leaves the field absent. The composition
    /// derives the verifier from the presented proof in
    /// [`mandate_token::verifier::CredentialDomain::AuthorizationCodeVerifier`], the same
    /// domain [`crate::code`] stores it in, and asks this. A proof that resolves to nothing
    /// is the unknown-code denial [`crate::redemption::redeem_authorization_code`] already
    /// declares for a `code_id` that names no record — the two are one refusal, reason and
    /// all, because a caller that could tell them apart would hold an oracle over which
    /// codes exist.
    ///
    /// It is a read by *verifier* and never by the code: the record keeps only the
    /// non-reversible verifier, so an implementation answers by deriving and comparing, and
    /// the comparison must not stop at the first differing byte.
    fn authorization_code_by_verifier(
        &self,
        verifier: &CredentialVerifier,
    ) -> Option<AuthorizationCode>;
}

impl AuthorizationCodeReads for CodeProjection {
    fn authorization_code(&self, id: &AuthorizationCodeId) -> Option<AuthorizationCode> {
        Self::authorization_code(self, id)
    }

    fn authorization_code_by_verifier(
        &self,
        verifier: &CredentialVerifier,
    ) -> Option<AuthorizationCode> {
        Self::authorization_code_by_verifier(self, verifier)
    }
}

/// The expected version of one code's event stream.
///
/// The kit's aggregate append is a compare-and-set on this value
/// (`docs/adr/0009-event-sourced-persistence.md`, `decision-blocker:epoch-atomicity`).
/// `crates/mandate-identity/src/port.rs` declares the same value for its own streams;
/// `mandate-sts` may not see that crate (`dependency-boundaries.json`) and the shared home
/// is `mandate-types`, which this story may not edit, so the two copies are the cost of the
/// dependency direction and are named here as residue rather than left to be found.
///
/// A version is a compare-and-set key, so advancing one must always produce a strictly
/// greater value: the counter is wider than any version the public constructor can name, so
/// [`StreamVersion::advance`] of a constructible version is total and strictly increasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StreamVersion(u128);

impl StreamVersion {
    /// The version of a stream that holds no event.
    pub const INITIAL: Self = Self(0);

    /// The version for a declared value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value as u128)
    }

    /// The declared value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }

    /// The version one appended event later.
    #[must_use]
    pub const fn advance(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Why an append group was not committed.
///
/// Both answers mean the same thing to a caller — nothing was written — and they are
/// different facts: one is a race another writer won, the other is a group this fold cannot
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppendRefused {
    /// The stream moved since the version the decision was read at.
    Conflict {
        /// The version the decision was read at.
        expected: StreamVersion,
        /// The version the stream is at now.
        actual: StreamVersion,
    },
    /// The group is not a history the fold can read, so the whole group rolled back.
    Unreadable(CodeFoldError),
}

impl fmt::Display for AppendRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { expected, actual } => write!(
                formatter,
                "the stream was read at version {} and is at version {}",
                expected.get(),
                actual.get()
            ),
            Self::Unreadable(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for AppendRefused {}

/// The event log, behind a port: one append group per boundary, compare-and-set on the
/// expected stream version.
///
/// The one write surface this crate has. A deployment attaches the organization `eventlog`
/// kit here; [`InMemoryCodeLog`] is the double the cases run against.
pub trait AuthorizationCodeLog {
    /// The version one code's stream is at.
    ///
    /// A stream no event has been appended to is at [`StreamVersion::INITIAL`].
    fn version(&self, stream: &AuthorizationCodeId) -> StreamVersion;

    /// The projection every appended group has been folded into.
    fn projection(&self) -> &CodeProjection;

    /// Append one group to one code's stream, if the stream is still at `expected`.
    ///
    /// All of the group or none of it, and the projection commits inside the group: a
    /// refused append leaves the stream and the projection exactly where they were.
    ///
    /// # Errors
    ///
    /// Returns [`AppendRefused::Conflict`] when the stream has moved since `expected` was
    /// read, and [`AppendRefused::Unreadable`] when the group is not a history the fold can
    /// read.
    fn append(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        group: &[AuthorizationCodeEvent],
    ) -> Result<StreamVersion, AppendRefused>;

    /// Append the event `build` produces, if the stream is still at `expected` — and decide
    /// that **before** `build` runs.
    ///
    /// The reservation a command path needs when the event it appends carries what it drew
    /// from the deployment: a redemption's event records the verifier of the secret it mints
    /// and the identity it allocates, so the draw cannot follow the append, and a draw ahead
    /// of the compare-and-set is a draw the losing writer has already made when the append
    /// refuses. Here the stream is held at `expected` from the compare until the group
    /// commits or rolls back: `build` runs only once the compare-and-set is won, and at most
    /// once. A deployment's kit holds the stream for that span inside the append group's own
    /// transaction; a read of the version before the draw is not the same thing, because a
    /// writer that commits between that read and the append is not seen by it.
    ///
    /// What `build` returns beside the event comes back to the caller on a commit.
    ///
    /// # Errors
    ///
    /// Returns [`AppendRefused::Conflict`] without running `build` when the stream has moved
    /// since `expected` was read, and [`AppendRefused::Unreadable`] when the built event is
    /// not a history the fold can read.
    fn append_built<T>(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        build: impl FnOnce() -> (AuthorizationCodeEvent, T),
    ) -> Result<T, AppendRefused>
    where
        Self: Sized;
}

/// An [`AuthorizationCodeLog`] that holds its streams in memory.
///
/// **A double, never a shipped implementation**: nothing here is durable and nothing here is
/// concurrent. It has the kit's shape — one append group per boundary, a compare-and-set on
/// the expected version, the projection committing inside the group or rolling back with it
/// — which is what lets a case decide the one-winner redemption without a second durable
/// mechanism (ADR 0009). It is `pub` because every file under `tests/` compiles as its own
/// crate.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCodeLog {
    streams: Vec<(AuthorizationCodeId, Vec<AuthorizationCodeEvent>)>,
    projection: CodeProjection,
    lose_next_append: bool,
}

impl InMemoryCodeLog {
    /// A log that holds nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The version one code's stream is at.
    #[must_use]
    pub fn version(&self, stream: &AuthorizationCodeId) -> StreamVersion {
        StreamVersion::new(
            u64::try_from(self.events(stream).len()).expect("a stream this double can hold"),
        )
    }

    /// The events appended to one code's stream, in order.
    #[must_use]
    pub fn events(&self, stream: &AuthorizationCodeId) -> Vec<AuthorizationCodeEvent> {
        self.streams
            .iter()
            .find(|(id, _)| id == stream)
            .map(|(_, events)| events.clone())
            .unwrap_or_default()
    }

    /// The projection every appended group has been folded into.
    #[must_use]
    pub const fn projection(&self) -> &CodeProjection {
        &self.projection
    }

    /// Make the next append lose its compare-and-set, whatever version it presents.
    ///
    /// The injection a race case needs: it is the losing half of two concurrent writers,
    /// without two threads and without a second store. Spent by the append it refuses.
    pub const fn lose_the_next_append(&mut self) {
        self.lose_next_append = true;
    }

    /// Append one group, if the stream is still at `expected`.
    ///
    /// # Errors
    ///
    /// Returns [`AppendRefused`]; see [`AuthorizationCodeLog::append`].
    pub fn append(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        group: &[AuthorizationCodeEvent],
    ) -> Result<StreamVersion, AppendRefused> {
        self.compare(stream, expected)?;
        self.commit(stream, group)
    }

    /// Append the event `build` produces, deciding the compare-and-set before it runs.
    ///
    /// The double holds the stream for the span by holding `&mut self`: nothing else can
    /// append between the compare and the commit. [`Self::lose_the_next_append`] is spent by
    /// the compare, so an injected loss refuses before `build` runs, exactly as a real one
    /// does.
    ///
    /// # Errors
    ///
    /// Returns [`AppendRefused`]; see [`AuthorizationCodeLog::append_built`].
    pub fn append_built<T>(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        build: impl FnOnce() -> (AuthorizationCodeEvent, T),
    ) -> Result<T, AppendRefused> {
        self.compare(stream, expected)?;
        let (event, built) = build();
        self.commit(stream, std::slice::from_ref(&event))?;
        Ok(built)
    }

    /// The compare half of the compare-and-set, spending an injected loss.
    fn compare(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
    ) -> Result<(), AppendRefused> {
        let actual = self.version(stream);
        if self.lose_next_append {
            self.lose_next_append = false;
            return Err(AppendRefused::Conflict {
                expected,
                actual: actual.advance(),
            });
        }
        if expected != actual {
            return Err(AppendRefused::Conflict { expected, actual });
        }
        Ok(())
    }

    /// The set half: fold the group and commit it, or roll the whole of it back.
    fn commit(
        &mut self,
        stream: &AuthorizationCodeId,
        group: &[AuthorizationCodeEvent],
    ) -> Result<StreamVersion, AppendRefused> {
        // The projection commits inside the group or rolls back with it: it is folded on a
        // copy, and the copy replaces the committed one only once the whole group has been
        // read.
        let mut committed = self.projection.clone();
        for event in group {
            committed.apply(event).map_err(AppendRefused::Unreadable)?;
        }
        self.projection = committed;
        match self.streams.iter_mut().find(|(id, _)| id == stream) {
            Some((_, events)) => events.extend_from_slice(group),
            None => self.streams.push((*stream, group.to_vec())),
        }
        Ok(self.version(stream))
    }
}

impl AuthorizationCodeLog for InMemoryCodeLog {
    fn version(&self, stream: &AuthorizationCodeId) -> StreamVersion {
        Self::version(self, stream)
    }

    fn projection(&self) -> &CodeProjection {
        Self::projection(self)
    }

    fn append(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        group: &[AuthorizationCodeEvent],
    ) -> Result<StreamVersion, AppendRefused> {
        Self::append(self, stream, expected, group)
    }

    fn append_built<T>(
        &mut self,
        stream: &AuthorizationCodeId,
        expected: StreamVersion,
        build: impl FnOnce() -> (AuthorizationCodeEvent, T),
    ) -> Result<T, AppendRefused> {
        Self::append_built(self, stream, expected, build)
    }
}

const _: () = {
    // Raw credentials never enter a persistent domain record or an audit record
    // (`AGENTS.md`). This is the check rather than a list: the match is exhaustive and no
    // pattern uses `..`, so a variant or a field added to [`AuthorizationCodeEvent`] whose
    // type is not a `PersistedValue` does not compile. Neither `CredentialSecret` nor
    // `CredentialProof` is one, and no crate can add that impl for them.
    fn persistable<T: PersistedValue + ?Sized>(_: &T) {}

    #[allow(dead_code)]
    fn every_payload_is_persistable(event: &AuthorizationCodeEvent) {
        match event {
            AuthorizationCodeEvent::AuthorizationCodeIssued {
                context,
                code_id,
                client_id,
                session_id,
                verifier,
                challenge,
                method,
                redirect_uri,
                expires_at,
                target,
                scope,
            } => {
                persistable(context);
                persistable(code_id);
                persistable(client_id);
                persistable(session_id);
                persistable(verifier);
                persistable(challenge);
                persistable(method);
                persistable(redirect_uri);
                persistable(expires_at);
                persistable(target);
                persistable(scope);
            }
            AuthorizationCodeEvent::AuthorizationCodeRedeemed {
                context,
                code_id,
                credential_id,
                reference_verifier,
                epochs,
                issued_at,
                descriptor,
                target,
            } => {
                persistable(context);
                persistable(code_id);
                persistable(credential_id);
                persistable(reference_verifier);
                persistable(epochs);
                persistable(issued_at);
                persistable(descriptor);
                persistable(target);
            }
        }
    }

    #[allow(dead_code)]
    fn every_record_field_is_persistable(record: &AuthorizationCode) {
        let AuthorizationCode {
            id,
            client_id,
            session_id,
            verifier,
            challenge,
            method,
            redirect_uri,
            expires_at,
            target,
            scope,
            state: _,
        } = record;
        persistable(id);
        persistable(client_id);
        persistable(session_id);
        persistable(verifier);
        persistable(challenge);
        persistable(method);
        persistable(redirect_uri);
        persistable(expires_at);
        persistable(target);
        persistable(scope);
    }
};
