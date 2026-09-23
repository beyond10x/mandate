//! The security token service as a library: the credential domain's deciding handlers over
//! the projections `mandate-token` folds, behind ports, with no listener.
//!
//! `src/main.rs` stays the scaffold that refuses `serve`; `cargo xtask check` asserts it.
//!
//! # Decide, apply, fold
//!
//! Every handler here is the **decide** half: it reads the projection, writes nothing, and
//! returns either the event its accepted outcome emits or the declared
//! [`mandate_token::projection::Denied`]. The **apply** half is
//! [`mandate_token::projection::Projection::apply`] — and, for the authorization-code
//! record this crate folds itself, [`store::CodeProjection::apply`] — which writes what it
//! is handed and re-checks no guard; the **fold** is `fold`
//! (`docs/adr/0009-event-sourced-persistence.md`).
//!
//! The window between a decision and the append that follows it is closed by the command
//! path, and **one** function here is one: [`redemption::redeem_and_consume`]. ADR 0009
//! makes the decide-and-append step one transaction whose aggregate append is a
//! compare-and-set on the expected stream version, so a decision read from a state that has
//! since moved fails the append and is retried against the state that moved it — which is
//! how two concurrent redemptions of one code issue at most one credential. Every other
//! handler here still returns its event and appends nothing; the deployment holds the log
//! and [`store::AuthorizationCodeLog`] is the port it attaches at.
//!
//! # What is decided elsewhere
//!
//! **Authority.** Every denial clause of this domain opens with "caller lacks … authority",
//! and no crate in this crate's dependency ceiling decides an authorization question
//! (`dependency-boundaries.json`: no `mandate-authz`). The adapter that reaches a handler
//! has already decided it; the handlers decide the rest of each clause — the tenant
//! binding, the lifecycle state, the registration, the profile and the window.
//!
//! **Audit.** `decision-blocker:guards` writes a denial to the audit stream. `mandate-audit`
//! is outside this crate's ceiling, so a refusal is returned and the adapter records it.
//!
//! **Rehydrating the signer.** `mandate_token::signing_real::RealSigner::new_with_revocations`
//! takes the keys a restart must not admit again. Rebuilding that list from the
//! [`mandate_token::projection::SigningKey`] fold — every `Revoked` key's `id` and
//! `thumbprint` — is the composition's, not a handler's: nothing here holds a signer for
//! longer than one call. Named here as residue rather than left to be noticed.
//!
//! # Why the doubles are `pub`
//!
//! Every file under `tests/` compiles as its own crate, so a double declared in one of them
//! is unreachable from the others. The ports whose doubles more than one case needs are
//! doubled here: [`SequentialAllocator`] and [`CountingSecrets`]. The doubles a single port
//! needs are `pub` beside that port — [`store::InMemoryCodeLog`],
//! [`code::RecordedClients`], [`binding::RecordedSessions`] — for the same reason.

pub mod binding;
pub mod code;
pub mod issue;
pub mod keys;
pub mod redemption;
pub mod registry;
pub mod resolve;
pub mod store;

use mandate_types::{
    AuthorizationCodeId, CorrelationId, CredentialId, CredentialSecret, EpochSnapshotRef,
    ResourceServerId, SigningKeyId, Timestamp, Uuid,
};

// Every `mandate.credential` element this workspace realizes, against the item that
// realizes it. Each entry is expanded into a `use` of the named symbol, so a registry line
// whose symbol was renamed, moved or deleted does not compile
// (`crates/mandate-types/src/macros.rs`), and
// `services/sts/tests/contract_agreement.rs` reads every name on the left back out of
// `generated/ir/system.json`.
//
// One registry for one domain. `crates/mandate-token` projects three of this domain's four
// entities and folds ten of its thirteen events; those realizations are accounted here, by
// path, rather than in a second registry that would have to be reconciled with this one. The
// fourth entity — `mandate.credential.AuthorizationCode` — is folded in this crate, because
// "STS alone owns authorization-code verifier storage and consumption"
// (`credential.yaml`), and since this story it is realized here and nowhere else:
// `crates/mandate-federation` released `mandate.credential.AuthorizationCode.State` when
// this crate started folding the record, and what it keeps is a port view.
//
// `mandate.credential.AuthorizationCodeRedeemed` writes two records and is therefore read by
// two folds — the code's consume here, the `AccessCredential` it seeds in
// `mandate_token::projection` (`credential.yaml`'s header). One element has one registry
// entry, and it names the writer: `crate::store::AuthorizationCodeEvent`, which is the
// payload this crate emits. The credential half is accounted the way every other
// `mandate-token` fold is — by path, on this same list's reading — and
// `services/sts/tests/store.rs` decides that the two declarations encode identically.
//
// What nothing realizes is [`ESS_UNREALIZED`], named element by element with the reason and
// the owning story: a registry that lists what is covered and waves at the rest overstates
// itself in the one direction that matters.
mandate_types::realizes! {
    "mandate.credential.RegisterResourceServer" => crate::registry::register_resource_server,
    "mandate.credential.DisableResourceServer" => crate::registry::disable_resource_server,
    "mandate.credential.IssueReferenceCredential" => crate::issue::issue_reference_credential,
    "mandate.credential.IssueSelfContainedCredential" => crate::issue::issue_self_contained_credential,
    "mandate.credential.IntrospectCredential" => crate::resolve::introspect_credential,
    "mandate.credential.RevokeAccessCredential" => crate::resolve::revoke_access_credential,
    "mandate.credential.RegisterSigningKey" => crate::keys::SigningKeyAdministration,
    "mandate.credential.RetireSigningKey" => crate::keys::retire_signing_key,
    "mandate.credential.RevokeSigningKey" => crate::keys::revoke_signing_key,
    "mandate.credential.IssueAuthorizationCode" => crate::code::CodeIssuance,
    "mandate.credential.RedeemAuthorizationCode" => crate::redemption::redeem_authorization_code,
    "mandate.credential.ResourceServerRegistered" => mandate_token::projection::CredentialEvent,
    "mandate.credential.ResourceServerDisabled" => mandate_token::projection::CredentialEvent,
    "mandate.credential.CredentialReferenceIssued" => mandate_token::projection::CredentialEvent,
    "mandate.credential.CredentialSelfContainedIssued" => mandate_token::projection::CredentialEvent,
    "mandate.credential.AccessCredentialRevoked" => mandate_token::projection::CredentialEvent,
    "mandate.credential.CredentialIntrospected" => mandate_token::projection::CredentialEvent,
    "mandate.credential.SigningKeyRegistered" => mandate_token::projection::CredentialEvent,
    "mandate.credential.SigningKeyRetired" => mandate_token::projection::CredentialEvent,
    "mandate.credential.SigningKeyRevoked" => mandate_token::projection::CredentialEvent,
    "mandate.credential.AuthorizationCodeIssued" => crate::store::AuthorizationCodeEvent,
    "mandate.credential.AuthorizationCodeRedeemed" => crate::store::AuthorizationCodeEvent,
    "mandate.credential.ResourceServer" => mandate_token::projection::ResourceServer,
    "mandate.credential.AccessCredential" => mandate_token::projection::AccessCredential,
    "mandate.credential.SigningKey" => mandate_token::projection::SigningKey,
    "mandate.credential.AuthorizationCode" => crate::store::AuthorizationCode,
    "mandate.credential.ResourceServer.State" => mandate_token::projection::ResourceServerState,
    "mandate.credential.AccessCredential.State" => mandate_token::projection::AccessCredentialState,
    "mandate.credential.SigningKey.State" => mandate_token::projection::SigningKeyState,
    "mandate.credential.AuthorizationCode.State" => crate::store::AuthorizationCodeState,
    "mandate.credential.Denied" => mandate_token::projection::Denied,
}

/// Every declared `mandate.credential` element nothing realizes yet, with the reason and
/// the story that owns it.
///
/// The other half of [`ESS_REALIZATIONS`]. `services/sts/tests/contract_agreement.rs`
/// decides the pair against `generated/ir/system.json` in both directions: an element this
/// list names and the registry also realizes is a contradiction, and an element neither one
/// names is an element nobody accounted for.
///
/// One group, and it is not an oversight: token exchange — `ExchangeCredential` and the two
/// events it emits — which `story:constrained-exchange` owns.
///
/// The authorization-code road left this list when `story:oauth-transaction` landed it:
/// `IssueAuthorizationCode`, `RedeemAuthorizationCode`, the `AuthorizationCode` record, its
/// `.State` and the two events that write it are all realized above, in this crate.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[
    (
        "mandate.credential.ExchangeCredential",
        "story:constrained-exchange owns token exchange",
    ),
    (
        "mandate.credential.TokenExchangeAllowed",
        "story:constrained-exchange owns token exchange",
    ),
    (
        "mandate.credential.TokenExchangeDenied",
        "story:constrained-exchange owns token exchange",
    ),
];

/// What the adapter carries that neither a command input nor the read model supplies.
///
/// A clock is an adapter concern, and so is the correlation a request is traced by. Both
/// are values a handler must be *given*: a handler that read a clock would decide an expiry
/// no caller could reproduce, and `mandate.credential.CredentialIntrospected` declares its
/// `context` `generated: true`, which is this correlation on the context the caller's own
/// proof resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// The correlation carried through the request.
    pub correlation: CorrelationId,
    /// The moment the request is being served.
    ///
    /// Every expiry this crate decides is relative to it, so two handlers serving one
    /// request decide the same instant.
    pub at: Timestamp,
    /// The epoch snapshot an issued credential is bound to, when the adapter recorded one.
    ///
    /// `decision-blocker:epoch`: an `EpochSnapshotRef` is an immutable record handle and
    /// never a generation. Nothing here compares generations.
    pub epochs: Option<EpochSnapshotRef>,
}

/// The identities a command's *response* binds, behind a port.
///
/// `credential.yaml` binds `resource_server_id`, `credential_id` and the signing key's `id`
/// from the response rather than from the caller, so the handler mints them. No crate in
/// this crate's dependency ceiling generates a UUID, which is why this is a port and not a
/// function.
pub trait IdentityAllocator {
    /// The identity `RegisterResourceServer` responds with.
    fn next_resource_server_id(&mut self) -> ResourceServerId;
    /// The identity both issuance commands respond with.
    fn next_credential_id(&mut self) -> CredentialId;
    /// The identity `RegisterSigningKey` responds with, which is also the `kid`.
    fn next_signing_key_id(&mut self) -> SigningKeyId;
    /// The identity `IssueAuthorizationCode` responds with.
    ///
    /// `credential.yaml` binds the emitted `code_id` from the response rather than from the
    /// caller, exactly as it binds `resource_server_id`, `credential_id` and the signing
    /// key's `id`.
    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId;
}

/// The transient secret a reference issuance returns once, behind a port.
///
/// `mandate-sts` has no `rand` (`dependency-boundaries.json`), and a secret minted from
/// anything a caller could reproduce is not a secret. The deployment supplies a source over
/// its CSPRNG; nothing here inspects what it returns beyond digesting it.
pub trait SecretSource {
    /// The next secret. It is returned to the holder once and never recorded.
    fn next_secret(&mut self) -> CredentialSecret;
}

/// An [`IdentityAllocator`] that mints distinct identities in order.
///
/// A fixture, never a shipped implementation: a real allocator does not mint from a
/// counter. It is `pub` and lives here because every file under `tests/` compiles as its own
/// crate. Each kind of identity is minted from its own prefix, so a resource server and a
/// credential never share a wire form.
#[derive(Debug, Clone, Default)]
pub struct SequentialAllocator {
    resource_servers: u8,
    credentials: u8,
    signing_keys: u8,
    authorization_codes: u8,
}

impl SequentialAllocator {
    /// A double that has minted nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

const fn minted(prefix: u8, ordinal: u8) -> Uuid {
    Uuid::from_bytes([
        prefix, ordinal, 0x28, 0xba, 0x2f, 0xa1, 0x4d, 0x8e, 0xb1, 0xb0, 0x8c, 0x1d, 0x4e, 0x5f,
        0x6a, 0x7b,
    ])
}

impl IdentityAllocator for SequentialAllocator {
    fn next_resource_server_id(&mut self) -> ResourceServerId {
        self.resource_servers += 1;
        ResourceServerId::new(minted(0x40, self.resource_servers))
    }

    fn next_credential_id(&mut self) -> CredentialId {
        self.credentials += 1;
        CredentialId::new(minted(0xcd, self.credentials))
    }

    fn next_signing_key_id(&mut self) -> SigningKeyId {
        self.signing_keys += 1;
        SigningKeyId::new(minted(0x7e, self.signing_keys))
    }

    fn next_authorization_code_id(&mut self) -> AuthorizationCodeId {
        self.authorization_codes += 1;
        AuthorizationCodeId::new(minted(0xac, self.authorization_codes))
    }
}

/// A [`SecretSource`] that mints a distinct, entirely predictable secret per call.
///
/// **A fixture, never a shipped implementation.** What it returns is a counter; a
/// deployment that used it would issue credentials anyone could guess. It exists so a case
/// can show that the secret it received is the one the verifier was derived from, which is
/// the whole of `reference-persistence`.
#[derive(Debug, Clone, Default)]
pub struct CountingSecrets {
    minted: u32,
}

impl CountingSecrets {
    /// A double that has minted nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many secrets this double has minted.
    #[must_use]
    pub const fn minted(&self) -> u32 {
        self.minted
    }
}

impl SecretSource for CountingSecrets {
    fn next_secret(&mut self) -> CredentialSecret {
        self.minted += 1;
        CredentialSecret::from_bytes(format!("secret-{}", self.minted).into_bytes())
    }
}

/// Reading the declared `date-time` and `duration` forms as spans on a timeline.
///
/// `Timestamp` and `Duration` carry a lexical form verbatim and order on their bytes; the
/// contract declares those forms as RFC 3339 `date-time` and ISO 8601 `duration`, and
/// neither byte order is the order of the thing it spells. Everything this crate decides
/// about time goes through here, so the comparison is over instants and the refusal of a
/// value that names none is in one place.
///
/// `crates/mandate-identity/src/session.rs` holds the same reading, privately, for its own
/// refresh decision. Two copies of one rule is the cost of the dependency direction —
/// `mandate-sts` may not see `mandate-identity` — and the shared home is `mandate-types`,
/// which this story may not edit. Named as residue rather than left to be found.
pub(crate) mod instant {
    use mandate_types::{Duration, Timestamp};

    /// The instant a declared timestamp names, in seconds from `1970-01-01T00:00:00Z`, or
    /// `None` when it names none.
    ///
    /// Sub-second precision is admitted by the form and dropped here: nothing this crate
    /// decides is finer than a second, and a value that carries a fraction is not refused
    /// for carrying one.
    pub(crate) fn seconds_of(value: &Timestamp) -> Option<i64> {
        let text = value.as_str().as_bytes();
        // full-date "T" full-time: 10 + 1 + 8 characters before the optional fraction and
        // the mandatory offset.
        if text.len() < 20 || !matches!(text[10], b'T' | b't') {
            return None;
        }
        if text[4] != b'-' || text[7] != b'-' || text[13] != b':' || text[16] != b':' {
            return None;
        }
        let year = i64::from(number(&text[0..4])?);
        let month = number(&text[5..7])?;
        let day = number(&text[8..10])?;
        let hour = number(&text[11..13])?;
        let minute = number(&text[14..16])?;
        let second = number(&text[17..19])?;
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        // RFC 3339 admits the leap second 60; it admits no hour 24.
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }

        let mut rest = &text[19..];
        if rest.first() == Some(&b'.') {
            let digits = rest[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 || digits > 9 {
                return None;
            }
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

        Some(
            days_from_civil(year, month, day) * 86_400
                + i64::from(hour) * 3600
                + i64::from(minute) * 60
                + i64::from(second)
                - offset,
        )
    }

    /// Whether one declared timestamp names an instant strictly before another's.
    ///
    /// `None` when either names no instant: a comparison that cannot be made is not a
    /// comparison that succeeded, and every caller fails closed on it.
    pub(crate) fn is_before(one: &Timestamp, other: &Timestamp) -> Option<bool> {
        Some(seconds_of(one)? < seconds_of(other)?)
    }

    /// The span a declared duration names, in seconds, or `None` when it names none.
    ///
    /// `P[nD]T[nH][nM][nS]` with integer components. The calendar designators — years,
    /// months and weeks — are refused rather than approximated: a month is not a number of
    /// seconds, and a credential lifetime that depended on which month it was issued in
    /// would not be the bound the profile promises. A fraction is refused for the same
    /// reason a sub-second expiry is not decided here.
    pub(crate) fn span_of(value: &Duration) -> Option<i64> {
        let text = value.as_str().as_bytes();
        let [b'P', rest @ ..] = text else {
            return None;
        };
        let mut seconds: i64 = 0;
        let mut digits: Option<i64> = None;
        let mut in_time = false;
        let mut components = 0_u32;
        for byte in rest {
            match byte {
                b'0'..=b'9' => {
                    let value = digits.unwrap_or(0).checked_mul(10)?;
                    digits = Some(value.checked_add(i64::from(byte - b'0'))?);
                }
                b'T' => {
                    if in_time || digits.is_some() {
                        return None;
                    }
                    in_time = true;
                }
                b'D' | b'H' | b'M' | b'S' => {
                    let value = digits.take()?;
                    let unit = match (in_time, byte) {
                        (false, b'D') => 86_400,
                        (true, b'H') => 3_600,
                        (true, b'M') => 60,
                        (true, b'S') => 1,
                        // A day designator after `T`, or an hour, minute or second before
                        // one, is not this form.
                        _ => return None,
                    };
                    seconds = seconds.checked_add(value.checked_mul(unit)?)?;
                    components += 1;
                }
                _ => return None,
            }
        }
        if digits.is_some() || components == 0 {
            return None;
        }
        Some(seconds)
    }

    /// The last request instant a profile's `max_ttl` is checked from at registration:
    /// `3000-01-01T00:00:00Z`.
    ///
    /// The registration handler has no clock, so the bound it applies to a profile is decided
    /// from a stated instant rather than from "now" — the same instant
    /// `services/control-plane/src/adapters.rs` checks the code and session lifetimes from.
    /// A request after it can still reach an expiry [`at`] refuses, and the issuance refuses
    /// that one itself.
    pub(crate) const LATEST_CHECKED_REQUEST_INSTANT: i64 = 32_503_680_000;

    /// The declared `date-time` form of an instant, in UTC, or `None` when the rendering is
    /// not one [`seconds_of`] reads back as that same instant.
    ///
    /// The one rendering this crate performs, so an expiry it decides is written the way
    /// the contract's schema reads it back. The year is rendered `{year:04}`, a minimum width
    /// and not a maximum: past `9999-12-31T23:59:59Z` it has five digits, and before
    /// `0000-01-01T00:00:00Z` it carries a sign, and the reader refuses both. Deciding it by
    /// reading the rendering back, rather than by arithmetic on the seconds, makes "rendered"
    /// and "readable" one set by construction.
    pub(crate) fn at(seconds: i64) -> Option<Timestamp> {
        let days = seconds.div_euclid(86_400);
        let rest = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let rendered = Timestamp::new(format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rest / 3600,
            (rest % 3600) / 60,
            rest % 60
        ));
        (seconds_of(&rendered) == Some(seconds)).then_some(rendered)
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

    /// The civil date a day count from `1970-01-01` names: the inverse of
    /// [`days_from_civil`].
    const fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let shifted = days + 719_468;
        let era = if shifted >= 0 {
            shifted
        } else {
            shifted - 146_096
        } / 146_097;
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        } as u32;
        (if month <= 2 { year + 1 } else { year }, month, day)
    }
}
