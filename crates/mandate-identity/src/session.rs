//! The identity-local session record and the eligibility half of `RefreshSession`.
//!
//! The fields are the ones `mandate.identity.Session` declares
//! (`systems/mandate/domains/identity.yaml`): the principal, the organization, the
//! optional federation connection, the epoch snapshot handle and the expiry, with the
//! declared `Active`/`Revoked` lifecycle. The record is this crate's projection of the
//! event fold, not a canonical type; see the crate documentation.

use mandate_types::{
    DenialReason, EpochSnapshotRef, FederationConnectionId, OrganizationId, PrincipalId, SessionId,
    Timestamp,
};

use crate::{Denial, Eligibility, IdentityRead};

/// The declared session lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// The initial state.
    Active,
    /// The terminal state `revoke` moves to.
    Revoked,
}

/// A session, as this crate folds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    id: SessionId,
    principal: PrincipalId,
    organization: OrganizationId,
    connection: Option<FederationConnectionId>,
    epochs: EpochSnapshotRef,
    expires_at: Timestamp,
    state: SessionState,
}

/// The accepted outcome of `mandate.identity.RefreshSession`.
///
/// The declared response is the session identity, and since
/// `story:event-payloads-for-folds` the `SessionRefreshed` event declares `session_id` and
/// nothing else — no `context` for a host to generate. This type carries exactly that
/// payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRefreshed {
    session_id: SessionId,
}

impl SessionRefreshed {
    /// The refreshed session.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

impl Session {
    /// An active session over the two dimensions every session has.
    #[must_use]
    pub const fn new(
        id: SessionId,
        principal: PrincipalId,
        organization: OrganizationId,
        epochs: EpochSnapshotRef,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            id,
            principal,
            organization,
            connection: None,
            epochs,
            expires_at,
            state: SessionState::Active,
        }
    }

    /// The same session, recorded as having come from a federation connection.
    #[must_use]
    pub fn with_connection(self, connection: FederationConnectionId) -> Self {
        Self {
            connection: Some(connection),
            ..self
        }
    }

    /// The session after the declared `revoke` transition.
    #[must_use]
    pub fn revoke(self) -> Self {
        Self {
            state: SessionState::Revoked,
            ..self
        }
    }

    /// The session identity.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// The principal the session authenticates.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// The organization the session is contained in.
    #[must_use]
    pub const fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// The federation connection the session came from, when it came from one.
    #[must_use]
    pub const fn connection(&self) -> Option<&FederationConnectionId> {
        self.connection.as_ref()
    }

    /// The handle of the epoch snapshot the session was issued against.
    #[must_use]
    pub const fn epochs(&self) -> &EpochSnapshotRef {
        &self.epochs
    }

    /// When the session stops being refreshable.
    #[must_use]
    pub const fn expires_at(&self) -> &Timestamp {
        &self.expires_at
    }

    /// The current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Whether the session has not been revoked.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// The epoch verdict for this session's snapshot.
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the session's snapshot handle resolves to no
    /// record, or resolves to a record that is bound to another subject.
    pub fn eligibility<R>(&self, epochs: &R) -> Result<Eligibility, Denial>
    where
        R: IdentityRead + ?Sized,
    {
        let Some(snapshot) = epochs.snapshot(&self.epochs) else {
            return Err(Denial::new(DenialReason::Denied));
        };
        if snapshot.principal() != &self.principal
            || snapshot.organization() != &self.organization
            || snapshot.connection() != self.connection.as_ref()
        {
            return Err(Denial::new(DenialReason::TenantMismatch));
        }
        Ok(snapshot.eligibility(epochs))
    }

    /// Whether this session's declared expiry has passed at an instant.
    ///
    /// Both values are read as the RFC 3339 `date-time` the contract declares and
    /// compared as instants, not as text: the declared form admits `+hh:mm`/`-hh:mm`
    /// offsets and a fractional second, and two spellings of one instant are equal while
    /// the later of two instants may sort earlier as a string. A session is refreshable
    /// strictly before the instant it expires at.
    ///
    /// A value that names no instant fails closed — it cannot show a session unexpired —
    /// so this answers `true`. [`Session::refresh`] distinguishes the two cases: a
    /// malformed `expires_at` denies `InvalidCredential`, a malformed `as_of`
    /// `Unavailable`.
    #[must_use]
    pub fn is_expired_at(&self, as_of: &Timestamp) -> bool {
        match (instant::parse(&self.expires_at), instant::parse(as_of)) {
            (Some(expiry), Some(now)) => expiry <= now,
            _ => true,
        }
    }

    /// Everything `RefreshSession` decides that does not need an instant: the revocation
    /// state, the snapshot binding and the epochs.
    fn certified<R>(&self, epochs: &R) -> Result<(), Denial>
    where
        R: IdentityRead + ?Sized,
    {
        if !self.is_active() {
            return Err(Denial::new(DenialReason::InvalidCredential));
        }
        match self.eligibility(epochs)?.denial() {
            Some(denial) => Err(denial),
            None => Ok(()),
        }
    }

    /// The eligibility half of `mandate.identity.RefreshSession`, as of an instant.
    ///
    /// Credential proof verification is the credential domain's; what is decided here is
    /// the revocation state, the epoch snapshot and the declared expiry — the contract's
    /// `denied` clause names a record that is "expired/revoked"
    /// (`systems/mandate/domains/identity.yaml`).
    ///
    /// # Errors
    ///
    /// Returns the declared refusal when the session is revoked, when its snapshot does
    /// not resolve or is bound to another subject, when any applicable generation does
    /// not match the authoritative one, when the session expired at or before `as_of`,
    /// when `expires_at` names no instant (`InvalidCredential` — the record cannot be
    /// read), and when `as_of` names none (`Unavailable` — the reader cannot be dated).
    pub fn refresh<R>(&self, epochs: &R, as_of: &Timestamp) -> Result<SessionRefreshed, Denial>
    where
        R: IdentityRead + ?Sized,
    {
        self.certified(epochs)?;
        let Some(now) = instant::parse(as_of) else {
            return Err(Denial::new(DenialReason::Unavailable));
        };
        let Some(expiry) = instant::parse(&self.expires_at) else {
            return Err(Denial::new(DenialReason::InvalidCredential));
        };
        if expiry <= now {
            return Err(Denial::new(DenialReason::InvalidCredential));
        }
        Ok(SessionRefreshed {
            session_id: self.id,
        })
    }
}

/// `mandate.identity.RefreshSession` over the read port, from the session identity the
/// verified refresh proof resolves to, at the instant the port is evaluated in.
///
/// The refusals that do not depend on an instant are decided first, so a stale session
/// denies for staleness whatever the reader knows about the time. A reader that supplies
/// no instant ([`IdentityRead::as_of`]) cannot certify that a session has not expired,
/// and this fails closed rather than refreshing one it cannot date.
///
/// That ordering is observable: with an undated reader, `Unavailable` is returned only
/// for a session that passed every other check, so the order of refusals distinguishes a
/// current session from a stale one. This call presumes an authenticated caller — the
/// proof that resolves a session identity is verified by the credential domain before
/// this is reached — and the distinction is not defended against a caller that can name
/// a session identity without one.
///
/// `Unavailable` from this call is terminal, not retryable: it says the reader has no
/// clock, or a clock that names no instant, and a retry against the same reader returns
/// it again. The same reason from [`SecurityEpochWrite::increment`] means the opposite —
/// the stream moved, read it again and retry.
///
/// # Errors
///
/// Returns the declared refusal when the session does not resolve, when the reader
/// supplies no instant, and whatever [`Session::refresh`] refuses otherwise.
pub fn refresh_session<R>(epochs: &R, id: &SessionId) -> Result<SessionRefreshed, Denial>
where
    R: IdentityRead + ?Sized,
{
    let Some(session) = epochs.resolve(id) else {
        return Err(Denial::new(DenialReason::InvalidCredential));
    };
    session.certified(epochs)?;
    let Some(as_of) = epochs.as_of() else {
        return Err(Denial::new(DenialReason::Unavailable));
    };
    session.refresh(epochs, &as_of)
}

/// Reading the declared `date-time` form as an instant.
///
/// `Timestamp` carries a lexical form verbatim and orders on its bytes; the contract
/// declares that form as RFC 3339 `date-time`, whose byte order is not its chronological
/// order. Everything this crate decides about time goes through here, so the comparison
/// is over instants and the refusal of a value that names none is in one place.
mod instant {
    use mandate_types::Timestamp;

    /// A point on the timeline: seconds since `1970-01-01T00:00:00Z`, and the
    /// nanoseconds within that second. The derived order is the chronological one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(super) struct Instant {
        seconds: i64,
        nanos: u32,
    }

    /// The instant a declared timestamp names, or `None` when it names none.
    pub(super) fn parse(value: &Timestamp) -> Option<Instant> {
        let text = value.as_str().as_bytes();
        // full-date "T" full-time: 10 + 1 + 8 characters before the optional fraction
        // and the mandatory offset.
        if text.len() < 20 || !matches!(text[10], b'T' | b't') {
            return None;
        }
        let year = i64::from(number(&text[0..4])?);
        let month = number(&text[5..7])?;
        let day = number(&text[8..10])?;
        let hour = number(&text[11..13])?;
        let minute = number(&text[14..16])?;
        let second = number(&text[17..19])?;
        if text[4] != b'-' || text[7] != b'-' || text[13] != b':' || text[16] != b':' {
            return None;
        }
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        // RFC 3339 admits the leap second 60; it admits no hour 24.
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }

        let mut rest = &text[19..];
        let mut nanos = 0_u32;
        if rest.first() == Some(&b'.') {
            let digits = rest[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 || digits > 9 {
                return None;
            }
            let mut scaled = 0_u32;
            for index in 0..9 {
                scaled *= 10;
                if index < digits {
                    scaled += u32::from(rest[1 + index] - b'0');
                }
            }
            nanos = scaled;
            rest = &rest[1 + digits..];
        }

        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), rest @ ..] if rest.len() == 5 && rest[2] == b':' => {
                let hours = number(&rest[0..2])?;
                let minutes = number(&rest[3..5])?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                let magnitude = i64::from(hours) * 3600 + i64::from(minutes) * 60;
                if *sign == b'-' { -magnitude } else { magnitude }
            }
            _ => return None,
        };

        let seconds = days_from_civil(year, month, day) * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second)
            - offset;
        Some(Instant { seconds, nanos })
    }

    /// The value of a run of ASCII digits, or `None` when it is not one.
    fn number(digits: &[u8]) -> Option<u32> {
        let mut value = 0_u32;
        for byte in digits {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value * 10 + u32::from(byte - b'0');
        }
        Some(value)
    }

    /// Whether a year has a 29th of February.
    const fn is_leap_year(year: i64) -> bool {
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }

    /// The last day of a month.
    const fn days_in_month(year: i64, month: u32) -> u32 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if is_leap_year(year) => 29,
            2 => 28,
            _ => 0,
        }
    }

    /// Days from `1970-01-01` to a civil date, by the era arithmetic that needs no table.
    const fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = if year >= 0 { year } else { year - 399 } / 400;
        let year_of_era = year - era * 400;
        let shifted = (month as i64 + 9) % 12;
        let day_of_year = (153 * shifted + 2) / 5 + day as i64 - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }
}
