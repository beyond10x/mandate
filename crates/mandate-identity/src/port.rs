//! The ports: reading identity state, and the compare-and-set that advances a
//! generation.
//!
//! Under `docs/adr/0009-event-sourced-persistence.md` every durable state here is
//! event-sourced: commands produce events, the events are the record and every read is a
//! fold. The write port is therefore the log's own aggregate append — a compare-and-set
//! on the expected stream version — and not a setter. [`IdentityLog`] is that fold over a
//! `Vec` of events, which is what the tests run against until the event-log kit is
//! admitted to the workspace.
//!
//! Reading and writing are two traits, not one. A holder of a read port cannot advance a
//! generation through the type it holds, which is what keeps a non-consuming reader of
//! this crate non-consuming.

use mandate_types::{DenialReason, EpochSnapshotRef, SecurityEpochTarget, SessionId, Timestamp};

use crate::{Denial, Generation, SecurityEpochSnapshot, Session};

/// The expected version of one target's event stream.
///
/// The kit's aggregate append is a compare-and-set on this value
/// (`decision-blocker:epoch-atomicity`); the signature is revisited when the kit lands.
///
/// A version is a compare-and-set key, so advancing one must always produce a strictly
/// greater value: a version that wrapped to [`StreamVersion::INITIAL`] would be the key
/// the compare-and-set accepts for an untouched stream. The counter is therefore wider
/// than any version the public constructor can name — `new` takes a `u64`, the value is
/// held as a `u128` — so [`StreamVersion::advance`] of a constructible version is total
/// and strictly increasing. Saturation needs 2^128 appends and is unreachable; the
/// compare-and-set refuses a stream whose version does not advance in any case.
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

    /// The version one appended event later, which is always greater than this one for
    /// every version `new` can produce.
    #[must_use]
    pub const fn advance(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// One dimension's authoritative generation together with the version it was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochState {
    generation: Generation,
    version: StreamVersion,
}

impl EpochState {
    /// The state for a declared generation and version.
    #[must_use]
    pub const fn new(generation: Generation, version: StreamVersion) -> Self {
        Self {
            generation,
            version,
        }
    }

    /// The authoritative generation.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// The version this generation was read at, which a write compares against.
    #[must_use]
    pub const fn version(self) -> StreamVersion {
        self.version
    }
}

/// The read port. Every method takes `&self`; none of them mutates anything.
pub trait IdentityRead {
    /// The session with this identity, when the fold records one.
    fn resolve(&self, id: &SessionId) -> Option<Session>;

    /// The authoritative generation for a target, and the version it was read at.
    ///
    /// A target no increment has been recorded for is at [`Generation::ZERO`].
    fn current(&self, target: &SecurityEpochTarget) -> EpochState;

    /// The snapshot a session's handle refers to, when the fold records one.
    fn snapshot(&self, id: &EpochSnapshotRef) -> Option<SecurityEpochSnapshot>;

    /// The instant this read is evaluated at, when the host has supplied one.
    ///
    /// A reader that has none cannot decide whether a record has expired, and
    /// [`crate::refresh_session`] fails closed rather than certifying a session it
    /// cannot date. The default is no instant.
    fn as_of(&self) -> Option<Timestamp> {
        None
    }
}

/// The write port: the one operation that advances a generation.
///
/// Separate from [`IdentityRead`] so that holding a reader is not holding a mutator.
pub trait SecurityEpochWrite {
    /// Advance one target's generation, if the stream is still at `expected`.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the stream has moved since it was read, and
    /// when the generation is already at [`Generation::MAX`] — which fails closed rather
    /// than wrapping or reusing a generation.
    fn increment(
        &mut self,
        target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial>;
}

/// The recorded events this crate folds.
///
/// All five are declared by the contract's `events:` list. `SessionRevoked` and
/// `SecurityEpochIncremented` always were; `SessionOpened`, `EpochSnapshotRecorded` and
/// `SecurityEpochRecorded` — the fold inputs that put a session, a snapshot and a
/// target's first generation into existence — were the crate's own until
/// `story:event-payloads-for-folds` declared them in `identity.yaml`. While they were
/// undeclared they carried `#[doc(hidden)]`; they no longer do, because a reader of this
/// enum can now find every one of them in the contract.
///
/// What this module ships, exactly: the two port traits, and [`IdentityLog`] as an
/// in-memory double of the event-log adapter that a later story supplies. Its seeding is
/// a fixture path — for this crate's own tests, and for a host that has no adapter yet —
/// and never a command path: a generation is advanced for real through
/// [`SecurityEpochWrite::increment`], which is the compare-and-set
/// `decision-blocker:epoch-atomicity` requires. A caller holding this type can seed a
/// target at any generation, including [`Generation::MAX`], which is how the overflow
/// cases are written; what it cannot do is move one backwards, reopen a revoked session
/// or rewrite a snapshot, because every append goes through the same guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvent {
    /// A session came into existence.
    ///
    /// `mandate.identity.SessionOpened`. One identity is opened once: a second
    /// `SessionOpened` for a session the fold already records is refused by
    /// [`IdentityLog::try_record`] and ignored by the fold, because `Revoked` is
    /// declared terminal and no transition leaves it.
    SessionOpened(Session),
    /// `mandate.identity.SessionRevoked`.
    SessionRevoked(SessionId),
    /// An epoch snapshot was recorded for a session to refer to.
    ///
    /// `mandate.identity.EpochSnapshotRecorded`. `EpochSnapshotRef` is an immutable
    /// record handle and `SecurityEpochSnapshot`'s only lifecycle state is `Recorded`, so
    /// a second recording of a handle the fold already holds is refused and ignored.
    EpochSnapshotRecorded(SecurityEpochSnapshot),
    /// A target's first generation.
    ///
    /// `mandate.identity.SecurityEpochRecorded`, and **not** a reset: the authoritative
    /// generation never moves backwards. A value below the one already folded for that
    /// target is refused by [`IdentityLog::try_record`] and ignored by the fold.
    ///
    /// At [`Generation::MAX`] the increment denies for that target from then on, and the
    /// out-of-band recovery the architecture names is not a rewind: it is the revocation
    /// of every session whose snapshot names that target. A generation is never reused,
    /// so a snapshot that was once stale is stale forever.
    SecurityEpochRecorded {
        /// What the generation applies to.
        target: SecurityEpochTarget,
        /// The generation the target is set to.
        generation: Generation,
    },
    /// `mandate.identity.SecurityEpochIncremented`: one target advanced by exactly one.
    SecurityEpochIncremented {
        /// What advanced.
        target: SecurityEpochTarget,
    },
}

/// An event log held in memory, and the fold over it.
///
/// The SQLite backend the ADR names is `:memory:`-capable for the same reason: what is
/// proved over this fold is proved over the deployment's.
///
/// Every append is guarded, because there is no other way to reach the events. The
/// vector is not exposed for writing:
///
/// ```compile_fail
/// use mandate_identity::{IdentityEvent, IdentityLog};
/// use mandate_types::{SessionId, Uuid};
///
/// let mut log = IdentityLog::new();
/// log.events()
///     .push(IdentityEvent::SessionRevoked(SessionId::new(Uuid::from_bytes([20; 16]))));
/// ```
///
/// and the type cannot be assembled around it either:
///
/// ```compile_fail
/// use mandate_identity::IdentityLog;
///
/// let log = IdentityLog {
///     events: Vec::new(),
///     as_of: None,
/// };
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityLog {
    events: Vec<IdentityEvent>,
    as_of: Option<Timestamp>,
}

impl IdentityLog {
    /// An empty log, with no evaluation instant.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same log, evaluated as of a declared instant.
    ///
    /// A log that has not been told what time it is cannot certify that a session has
    /// not expired, and [`crate::refresh_session`] fails closed on it.
    #[must_use]
    pub fn with_as_of(self, as_of: Timestamp) -> Self {
        Self {
            as_of: Some(as_of),
            ..self
        }
    }

    /// Seed one event, or refuse it.
    ///
    /// The same append as [`IdentityLog::try_record`], with the refusal discarded rather
    /// than returned. There is no third, unguarded path: both go through
    /// [`IdentityLog::refusal`], and the only other append in this crate is the
    /// compare-and-set in [`SecurityEpochWrite::increment`].
    pub fn record(&mut self, event: IdentityEvent) {
        let _ = self.try_record(event);
    }

    /// Seed one event.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the event would move a target's generation
    /// backwards or leave it where it is, open a session identity the log already
    /// records — whether it currently projects to one or has only been revoked — or
    /// record a snapshot handle the log already holds. The log is unchanged in each
    /// case.
    pub fn try_record(&mut self, event: IdentityEvent) -> Result<(), Denial> {
        if let Some(denial) = self.refusal(&event) {
            return Err(denial);
        }
        self.append(event);
        Ok(())
    }

    /// The one place an event is added to the log.
    fn append(&mut self, event: IdentityEvent) {
        self.events.push(event);
    }

    /// Why an event cannot be appended, if it cannot.
    ///
    /// Each guard reads the recorded history rather than a projection of it: a
    /// projection is a fold of the events that happen to have arrived, so a guard keyed
    /// on one is a guard on the order they arrived in.
    fn refusal(&self, event: &IdentityEvent) -> Option<Denial> {
        let refused = match event {
            IdentityEvent::SecurityEpochRecorded { target, generation } => {
                let state = self.current(target);
                // A first recording seeds the target. Afterwards a recording must move
                // the generation: one that does not is not an event, and appending it
                // would consume a stream version and invalidate every concurrent
                // writer's compare-and-set token for nothing.
                state.version() > StreamVersion::INITIAL && *generation <= state.generation()
            }
            // `Revoked` is terminal for the identity, not for one projection of it: an
            // identity any recorded event names has been opened once already.
            IdentityEvent::SessionOpened(session) => self.records_session(session.id()),
            IdentityEvent::EpochSnapshotRecorded(snapshot) => self.records_snapshot(snapshot.id()),
            IdentityEvent::SessionRevoked(_) | IdentityEvent::SecurityEpochIncremented { .. } => {
                false
            }
        };
        refused.then(|| Denial::new(DenialReason::Denied))
    }

    /// Whether any recorded event names this session identity.
    fn records_session(&self, id: &SessionId) -> bool {
        self.events.iter().any(|event| match event {
            IdentityEvent::SessionOpened(session) => session.id() == id,
            IdentityEvent::SessionRevoked(revoked) => revoked == id,
            _ => false,
        })
    }

    /// Whether any recorded event names this snapshot handle.
    fn records_snapshot(&self, id: &EpochSnapshotRef) -> bool {
        self.events.iter().any(|event| match event {
            IdentityEvent::EpochSnapshotRecorded(snapshot) => snapshot.id() == id,
            _ => false,
        })
    }

    /// Every recorded event, in order.
    #[must_use]
    pub fn events(&self) -> &[IdentityEvent] {
        &self.events
    }
}

impl IdentityRead for IdentityLog {
    fn resolve(&self, id: &SessionId) -> Option<Session> {
        let mut resolved: Option<Session> = None;
        for event in &self.events {
            match event {
                IdentityEvent::SessionOpened(session)
                    if session.id() == id && resolved.is_none() =>
                {
                    // `Revoked` is declared terminal and no transition leaves it, so a
                    // replayed open of a session the fold already holds changes nothing.
                    resolved = Some(session.clone());
                }
                IdentityEvent::SessionRevoked(revoked) if revoked == id => {
                    resolved = resolved.map(Session::revoke);
                }
                _ => {}
            }
        }
        resolved
    }

    fn current(&self, target: &SecurityEpochTarget) -> EpochState {
        let mut generation = Generation::ZERO;
        let mut version = StreamVersion::INITIAL;
        for event in &self.events {
            match event {
                IdentityEvent::SecurityEpochRecorded {
                    target: recorded,
                    generation: value,
                } if recorded == target => {
                    // The authoritative generation never moves backwards, whoever built
                    // the log: a recorded value below the folded one is not applied.
                    if *value > generation {
                        generation = *value;
                    }
                    version = version.advance();
                }
                IdentityEvent::SecurityEpochIncremented {
                    target: incremented,
                } if incremented == target => {
                    // The write port refuses to advance past the maximum, so no log it
                    // produced holds this event at the maximum; a hand-recorded one that
                    // does holds there rather than wrapping.
                    generation = generation.advance().unwrap_or(generation);
                    version = version.advance();
                }
                _ => {}
            }
        }
        EpochState::new(generation, version)
    }

    fn as_of(&self) -> Option<Timestamp> {
        self.as_of.clone()
    }

    fn snapshot(&self, id: &EpochSnapshotRef) -> Option<SecurityEpochSnapshot> {
        let mut resolved: Option<SecurityEpochSnapshot> = None;
        for event in &self.events {
            // An `EpochSnapshotRef` is an immutable record handle: the first recording
            // of it is the record, and a later one does not rewrite it.
            if let IdentityEvent::EpochSnapshotRecorded(snapshot) = event
                && snapshot.id() == id
                && resolved.is_none()
            {
                resolved = Some(snapshot.clone());
            }
        }
        resolved
    }
}

impl SecurityEpochWrite for IdentityLog {
    fn increment(
        &mut self,
        target: &SecurityEpochTarget,
        expected: StreamVersion,
    ) -> Result<EpochState, Denial> {
        let state = self.current(target);
        if state.version() != expected {
            return Err(Denial::new(DenialReason::Unavailable));
        }
        let Some(generation) = state.generation().advance() else {
            return Err(Denial::new(DenialReason::Denied));
        };
        let version = state.version().advance();
        if version <= state.version() {
            return Err(Denial::new(DenialReason::Unavailable));
        }
        self.append(IdentityEvent::SecurityEpochIncremented {
            target: target.clone(),
        });
        Ok(EpochState::new(generation, version))
    }
}
