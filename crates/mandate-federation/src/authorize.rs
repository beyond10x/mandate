//! `mandate.federation.AuthorizePublicClient` (`federation.yaml:269-302`), up to the
//! input of the STS call its accepted outcome makes.
//!
//! # What this decides, and what it deliberately does not
//!
//! Everything the declared denial names that is decidable from the read model and the
//! request: the authenticated session and its epoch, the registered public client, the
//! exact redirect binding, the state and applicable nonce, the S256 challenge, the
//! registered target inside the verified tenant, and the code record's own expiry and
//! lifecycle state. What it produces is a [`ValidationCandidate`] — a statement that every
//! one of those held at the instant the request was served.
//!
//! The target is decided through [`TargetRegistry`], a read port, for the same reason the
//! client is: `mandate.credential.ResourceServer` is another domain's record and this
//! crate holds no fold of it. `story:credential-profiles` supplies the real registry; the
//! double until then is [`crate::publicclient::RecordedClients`], which answers this port
//! and the client one together the way [`crate::RecordedPrincipals`] answers three.
//!
//! It is **non-consuming**. No code is consumed, no credential is created, no redemption
//! is committed and no event is emitted: every argument is a shared reference, the result
//! carries no event, and `mandate.credential.IssueAuthorizationCode` is assembled as an
//! input and never called — this crate declares no port for it, so nothing here can call
//! it. Two concurrent callers that each meet every condition each obtain a candidate;
//! neither holds authority to redeem, and the one-winner decision belongs to the atomic
//! STS transaction `story:oauth-integration` owns (`docs/architecture/ownership.md:28`).
//!
//! # The code record is an input, not a store
//!
//! `mandate.credential.AuthorizationCode` (`credential.yaml:109-127`) is the credential
//! domain's record and STS alone stores it (`credential.yaml:4`). [`AuthorizationCode`]
//! here is a read-only mirror of the fields this validation reads, supplied by the
//! caller. The declared `verifier` field (`credential.yaml:117-118`) is deliberately not
//! mirrored: it is the non-reversible verifier of the code itself (`credential.yaml:393`),
//! it is never read by this validation, and mirroring it would put stored credential
//! material into a record this crate holds.
//!
//! # The session is named by identity, never by proof
//!
//! The declared input carries a `session_proof`; resolving one to a session is the
//! trusted adapter's work (`decision-blocker:guards`), and `AuthenticateFederation`
//! already responds with the identity. The code record names that identity, and it is
//! read through [`mandate_identity::IdentityRead`] — the read port, which cannot advance
//! a generation or revoke anything.

use mandate_identity::{Eligibility, IdentityRead};
use mandate_types::{
    AuthorityScope, AuthorizationCodeId, CredentialProof, DenialReason, OAuthClientId,
    OrganizationId, PkceChallenge, PkceMethod, PrincipalId, RedirectUri, ResourceServerId,
    SessionId, Timestamp, VerifiedContext,
};

use crate::pkce::{PkceDigest, equal_in_constant_time, verify_pkce};
use crate::publicclient::{OAuthClientStore, registered_public_client};
use crate::record::Projection;
use crate::{DenialClause, Denied, RequestContext};

/// The registered-target read model: is this `ResourceServerId` registered, and to which
/// organization?
///
/// `mandate.credential.ResourceServer` (`credential.yaml:10-34`) is the credential
/// domain's record, so this crate reads it through a port rather than folding it — the
/// shape [`crate::ConnectionStore`] established. An implementation answers for every
/// target it has registered, in any lifecycle state it knows; the command decides the
/// tenant binding itself, because a port cannot make that a property of the command.
pub trait TargetRegistry {
    /// The organization a registered target belongs to, when it is registered.
    ///
    /// `None` means *not registered*, and only a registry that can see the registered set
    /// may say it: an implementation that cannot answer says so through
    /// [`TargetRegistry::can_answer`] instead, and never reports its own blindness as an
    /// unregistered target.
    fn target_organization(&self, id: &ResourceServerId) -> Option<OrganizationId>;

    /// Whether this registry can answer for this target at all.
    ///
    /// The third answer. A registry that cannot see `mandate.credential`'s records has not
    /// decided that the target is unregistered — it has decided nothing — and the command
    /// refuses `Unavailable` rather than `Denied`, exactly as it does for a request instant
    /// that names no instant. Defaulted to `true`, so an implementation that can see its
    /// own set says nothing extra.
    fn can_answer(&self, id: &ResourceServerId) -> bool {
        let _ = id;
        true
    }
}

/// The federation fold is not a target registry.
///
/// It answers [`TargetRegistry`] so that the crate's own read model satisfies every port
/// the command reads — the shape `authenticate_federation` established, where
/// [`crate::record::Projection`] answers the connection, link and principal reads together
/// — and what it answers is the truth about itself: `mandate.credential.ResourceServer` is
/// another domain's record, this fold holds none, and so it decides nothing about a
/// target. Every request it is asked about is refused `Unavailable`, never `Denied`.
/// `story:credential-profiles` supplies the registry that can answer.
impl TargetRegistry for Projection {
    fn target_organization(&self, id: &ResourceServerId) -> Option<OrganizationId> {
        let _ = id;
        None
    }

    fn can_answer(&self, id: &ResourceServerId) -> bool {
        let _ = id;
        false
    }
}

/// `mandate.credential.AuthorizationCode.State` (`credential.yaml:132-143`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationCodeState {
    /// The declared initial state.
    Issued,
    /// The declared terminal state `consume` moves to.
    Consumed,
}

/// `mandate.credential.AuthorizationCode`, as this validation reads it.
///
/// A read-only input; see the module documentation for why it is not a store and why the
/// declared `verifier` field is not mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    /// The declared identity.
    pub id: AuthorizationCodeId,
    /// The client the code is bound to.
    pub client_id: OAuthClientId,
    /// The authenticated session the code was issued under.
    pub session_id: SessionId,
    /// The recorded S256 challenge.
    pub challenge: PkceChallenge,
    /// The recorded method.
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

/// What the authorization request recorded, to be presented back unchanged.
///
/// Neither value is on the code record (`credential.yaml:109-127`), so both are inputs:
/// the adapter that served the authorization request holds them.
///
/// Both are required, because `AuthorizePublicClient` declares both as `String` and
/// neither as `Optional<String>` (`federation.yaml:279-282`): a request that recorded no
/// nonce is not a request this command served. "Applicable" therefore never means
/// "absent" — it means the value the authorization request carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBinding {
    /// The declared `state` of `AuthorizePublicClient`.
    pub state: String,
    /// The declared `nonce` of `AuthorizePublicClient`.
    pub nonce: String,
}

/// What the caller presents now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedRedemption {
    /// The redirect URI presented with the request.
    pub redirect_uri: RedirectUri,
    /// The presented code verifier, `mandate.core.CredentialProof`
    /// (`credential.yaml:205-206`). Absent when the caller omitted it.
    pub verifier: Option<CredentialProof>,
    /// The state presented back.
    pub state: String,
    /// The nonce presented back, when one is presented.
    pub nonce: Option<String>,
}

/// One non-consuming validation: the code record, what the authorization request
/// recorded, and what the caller presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateAuthorizationCode {
    /// The read-only code record.
    pub code: AuthorizationCode,
    /// What the authorization request recorded.
    pub binding: RequestBinding,
    /// What the caller presents.
    pub presented: PresentedRedemption,
}

/// The declared input of `mandate.credential.IssueAuthorizationCode`
/// (`credential.yaml:363-381`).
///
/// Assembled from validated facts and never invoked: this crate declares no port for that
/// command, and the call belongs to the STS transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueAuthorizationCodeInput {
    /// The declared `context`, generated from the validated session and the request.
    pub context: VerifiedContext,
    /// The declared `client_id`.
    pub client_id: OAuthClientId,
    /// The declared `session_id`.
    pub session_id: SessionId,
    /// The declared `target`.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
    /// The declared `challenge`.
    pub challenge: PkceChallenge,
    /// The declared `method`.
    pub method: PkceMethod,
    /// The declared `redirect_uri`.
    pub redirect_uri: RedirectUri,
    /// The declared `expires_at`.
    pub expires_at: Timestamp,
}

/// Every declared condition held, at the instant the request was served.
///
/// A candidate is not an authority to redeem and carries no code, no credential and no
/// event. It says what was validated and names the STS input the accepted outcome stops
/// at.
///
/// # What a candidate does not prove
///
/// * **Possession of the code.** The code itself is a `CredentialSecret` returned to the
///   public client, and the proof of holding it is `RedeemAuthorizationCode.code`
///   (`credential.yaml:203-204`), which STS resolves against the non-reversible verifier
///   it stored (`credential.yaml:393`). This validation is given the record, not the
///   proof, and never sees either.
/// * **That a caller-presented `client_id` is the code's.** The client is read from the
///   code record and the record alone; a `client_id` presented alongside the code is not
///   an input here, and `RedeemAuthorizationCode` declares its own (`:201-202`) for STS to
///   check against the record it consumes.
/// * **That this caller wins.** Two callers can each hold a candidate for one code; the
///   atomic consume-and-issue transaction decides which one redeems it, and a candidate
///   that was valid when it was made says nothing about the record a moment later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCandidate {
    /// The code record that was validated, by identity alone.
    pub code_id: AuthorizationCodeId,
    /// The registered public client the code is bound to.
    pub client_id: OAuthClientId,
    /// The authenticated session the code was issued under.
    pub session_id: SessionId,
    /// The principal that session authenticates.
    pub principal_id: PrincipalId,
    /// The organization the client and the session are both bound to.
    pub organization_id: OrganizationId,
    /// The call the accepted outcome would make, assembled and not made.
    pub issuance: IssueAuthorizationCodeInput,
}

/// Validate an authorization code, consuming nothing.
///
/// The order is: the request instant, the code record's own lifecycle and expiry, the
/// redirect the code authorized, the authenticated session and its epoch, the registered
/// public client under that session's organization, the registered target inside that
/// tenant, the state and applicable nonce, and the S256 challenge last.
///
/// The client read model and the target registry are separate arguments: they are
/// separate records of separate domains, and a deployment that has a real client fold and
/// no target registry yet can still name both. One adapter may answer both, as the test
/// double does.
///
/// # Errors
///
/// Returns [`Denied`] when the request names no instant, when the code is already
/// consumed or expired, when the presented redirect is not the one the code authorized,
/// when the session does not resolve, is revoked, is stale or has expired, when the client
/// is not a registered public client of that session's organization or has not registered
/// the redirect, when the target is unregistered or registered outside that organization,
/// when the state or the applicable nonce does not match, and when the presented verifier
/// does not redeem the recorded challenge.
pub fn validate_authorization_code(
    input: &ValidateAuthorizationCode,
    request: &RequestContext,
    clients: &impl OAuthClientStore,
    targets: &impl TargetRegistry,
    sessions: &impl IdentityRead,
    digest: &impl PkceDigest,
) -> Result<ValidationCandidate, Denied> {
    let code = &input.code;
    // A reader that cannot be dated cannot certify that a record has not expired, and
    // says so with its own reason rather than reporting the record as expired
    // (`mandate_identity`'s `refresh_session` fails closed the same way). `Unavailable`
    // from here is terminal: a retry against the same request instant returns it again.
    if !names_an_instant(&request.at) {
        return Err(Denied::new(
            DenialReason::Unavailable,
            DenialClause::CodeExpired,
        ));
    }
    match code.state {
        AuthorizationCodeState::Issued => {}
        // "code is consumed/expired" (`credential.yaml:223`). The *concurrent* second
        // redemption is not decided here; only the recorded terminal state is.
        AuthorizationCodeState::Consumed => {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::CodePreviouslyRedeemed,
            ));
        }
    }
    if is_expired_at(&code.expires_at, &request.at) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::CodeExpired,
        ));
    }
    // "exact registered/authorized URI": the code's own binding is the authorized one,
    // and a URI the client registered but this code did not authorize is not it.
    if input.presented.redirect_uri != code.redirect_uri {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::RedirectMismatch,
        ));
    }
    let session = sessions.resolve(&code.session_id).ok_or_else(|| {
        Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SessionUnknown,
        )
    })?;
    if !session.is_active() {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SessionRevoked,
        ));
    }
    // The snapshot is resolved through the same read port; an unresolved or misbound one
    // is the identity crate's refusal, carried with its declared reason.
    let eligibility = session
        .eligibility(sessions)
        .map_err(|denial| Denied::new(denial.reason(), DenialClause::SessionEpochUnresolved))?;
    match eligibility {
        Eligibility::Current => {}
        Eligibility::Stale(_) => {
            return Err(Denied::new(
                DenialReason::StaleEpoch,
                DenialClause::SessionStale,
            ));
        }
    }
    if session.is_expired_at(&request.at) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::SessionExpired,
        ));
    }
    // The organization is the authenticated session's, never a caller-supplied selector.
    let client = registered_public_client(
        clients,
        &code.client_id,
        &input.presented.redirect_uri,
        session.organization(),
    )?;
    // "target is unregistered/outside tenant" (`federation.yaml:298`). The tenant is
    // the session's organization, which the client is already bound to. A registry that
    // cannot answer has decided nothing, and is not read as having decided "unregistered".
    if !targets.can_answer(&code.target) {
        return Err(Denied::new(
            DenialReason::Unavailable,
            DenialClause::TargetUnanswerable,
        ));
    }
    match targets.target_organization(&code.target) {
        None => {
            return Err(Denied::new(
                DenialReason::Denied,
                DenialClause::TargetUnknown,
            ));
        }
        Some(registered) if registered != client.organization_id => {
            return Err(Denied::new(
                DenialReason::TenantMismatch,
                DenialClause::TargetOutsideTenant,
            ));
        }
        Some(_) => {}
    }
    if !state_matches(&input.binding.state, &input.presented.state) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::StateMismatch,
        ));
    }
    if !nonce_matches(&input.binding.nonce, input.presented.nonce.as_deref()) {
        return Err(Denied::new(
            DenialReason::Denied,
            DenialClause::NonceMismatch,
        ));
    }
    verify_pkce(
        &code.challenge,
        code.method,
        input.presented.verifier.as_ref(),
        digest,
    )?;
    Ok(ValidationCandidate {
        code_id: code.id,
        client_id: client.id,
        session_id: *session.id(),
        principal_id: *session.principal(),
        organization_id: client.organization_id,
        issuance: IssueAuthorizationCodeInput {
            context: VerifiedContext {
                subject: *session.principal(),
                actor: None,
                organization: client.organization_id,
                audience: request.audience.clone(),
                credential: request.credential,
                delegation: None,
                execution: None,
                correlation: request.correlation.clone(),
            },
            client_id: client.id,
            session_id: *session.id(),
            target: code.target,
            requested_scope: code.scope.clone(),
            challenge: code.challenge.clone(),
            method: code.method,
            redirect_uri: code.redirect_uri.clone(),
            expires_at: code.expires_at.clone(),
        },
    })
}

/// Whether the presented state is the one the authorization request recorded.
///
/// An empty state binds nothing: a request that recorded none is not matched by a
/// presentation that carries none either. The comparison does not return early on the
/// first differing byte ([`crate::pkce::equal_in_constant_time`]): a state is an
/// unguessable value a caller presents back, which is the same shape as the challenge
/// comparison next to it.
fn state_matches(recorded: &str, presented: &str) -> bool {
    !recorded.is_empty() && equal_in_constant_time(recorded, presented)
}

/// Whether the applicable nonce matches.
///
/// The authorization request always recorded one (`federation.yaml:281-282`), so the only
/// question is whether it was presented back unchanged. A presentation that omits it is
/// refused rather than excused, and a recorded empty nonce is not a nonce.
fn nonce_matches(recorded: &str, presented: Option<&str>) -> bool {
    !recorded.is_empty()
        && presented.is_some_and(|presented| equal_in_constant_time(recorded, presented))
}

/// Whether a declared expiry has passed at an instant.
///
/// Both values are read as the RFC 3339 `date-time` the contract declares and compared as
/// instants, not as text: the declared form admits `+hh:mm`/`-hh:mm` offsets and a
/// fractional second, and two spellings of one instant are equal while the later of two
/// instants may sort earlier as a string. A record is usable strictly before the instant
/// it expires at.
///
/// A value that names no instant fails closed — it cannot show a record unexpired — so
/// this answers `true`.
///
/// This is the same reading `mandate_identity` performs for a session's expiry, whose
/// own is private to that crate. `crates/mandate-federation/tests/authorize.rs` pins the
/// two against each other spelling by spelling, so the duplication is checked rather than
/// assumed; a single home for it is a later story's, because `mandate-types` is the only
/// crate both see and this story may not edit it.
#[must_use]
pub fn is_expired_at(expires_at: &Timestamp, as_of: &Timestamp) -> bool {
    match (instant::parse(expires_at), instant::parse(as_of)) {
        (Some(expiry), Some(now)) => expiry <= now,
        _ => true,
    }
}

/// Whether a declared timestamp names an instant at all.
fn names_an_instant(value: &Timestamp) -> bool {
    instant::parse(value).is_some()
}

/// Reading the declared `date-time` form as an instant.
mod instant {
    use mandate_types::Timestamp;

    /// A point on the timeline: seconds since `1970-01-01T00:00:00Z`, and the nanoseconds
    /// within that second. The derived order is the chronological one.
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
