//! The OAuth road's wire encodings.
//!
//! Three things, and they are here together because they are the encodings one road speaks:
//! the `application/x-www-form-urlencoded` form of RFC 6749, the JSON documents that road
//! renders and reads, and the standard error bodies of RFC 6749 section 5.2 — including the
//! mapping from the STS's crate-local denial clauses onto them.
//!
//! # Why the JSON helpers are here and not in the crate that uses them
//!
//! `dependency-boundaries.json` gives `mandate-server` exactly `mandate-types` and
//! `mandate-proto`. It has no `serde`, no `serde_json` and no percent-decoder, so the
//! adapter library cannot read a JSON request body or render a JSON document by itself, and
//! nothing may be added to its ceiling. This module is the only place in that ceiling that
//! carries a JSON codec, so [`object`] and [`flat_object`] live here and the adapters call
//! them. Two of their callers are not OAuth — the federation login body and the RFC 8414
//! metadata document — and both are on this same road; naming them here is cheaper than a
//! hand-rolled JSON parser in a crate that was kept deliberately thin.
//!
//! # Nothing a caller sent comes back out
//!
//! Every refusal this module produces is a unit value or a `&'static str`. [`FormError`] and
//! [`JsonError`] carry no captured text, and [`ErrorBody::description`] is `&'static str`, so
//! a caller's bytes cannot reach a body that is rendered back to that caller. That is a
//! property of the types, not of the care taken at each construction site.
//!
//! # What this module does not decide
//!
//! It refuses wire forms. It does not decide a code, a client, a session or a credential: a
//! well-formed request that this module admits is a request a deciding handler has not yet
//! seen. `crates/mandate-server/src/decode.rs` builds the declared command inputs from what
//! is admitted here, and the handlers in `crates/mandate-federation` and `services/sts`
//! decide them.
//!
//! At the authorization endpoint RFC 6749 section 4.1.2.1 returns an error by redirecting to
//! a validated redirect URI rather than as a body. This module produces the error *value*;
//! which of the two renderings a listener uses is the listener's, and it cannot redirect to a
//! redirect URI it has not validated.

use std::collections::BTreeMap;
use std::fmt;

use mandate_token::projection::DenialClause;
use mandate_types::DenialReason;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

/// The only `code_challenge_method` this system admits.
///
/// `mandate.core.PkceMethod` declares exactly one variant
/// (`crates/mandate-types/src/enumeration.rs:10`), so RFC 7636's `plain` is the method of no
/// value that can be constructed here.
pub const S256_METHOD: &str = "S256";

/// A decoded `application/x-www-form-urlencoded` body or query string.
///
/// The pairs are kept in the order they were presented and no key appears twice: a duplicate
/// is refused at decode rather than resolved by a rule, because every rule for resolving one
/// (first wins, last wins) is a rule an attacker can aim at a parser that chose the other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Form {
    pairs: Vec<(String, String)>,
}

impl Form {
    /// The value presented for `key`, or `None` when the form carries none.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    /// Every key the form carries, in the order presented.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.pairs.iter().map(|(name, _)| name.as_str())
    }

    /// How many pairs the form carries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether the form carries no pair at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

/// Why a form was not decoded.
///
/// Every variant is a unit: see the module's note on caller-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormError {
    /// A key appeared more than once.
    DuplicateKey,
    /// A key was empty.
    EmptyKey,
    /// A segment carried no `=`, or two separators were adjacent.
    MalformedPair,
    /// A `%` escape was truncated or was not two hexadecimal digits.
    MalformedEscape,
    /// The decoded octets were not UTF-8.
    NotUtf8,
}

impl fmt::Display for FormError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateKey => "a form key appeared more than once",
            Self::EmptyKey => "a form key was empty",
            Self::MalformedPair => "a form segment carried no separator",
            Self::MalformedEscape => "a percent escape was malformed",
            Self::NotUtf8 => "a decoded form value was not UTF-8",
        })
    }
}

impl std::error::Error for FormError {}

/// Decode an `application/x-www-form-urlencoded` body or query string.
///
/// Splitting on `&` and then on the first `=`, percent-decoding both halves with `+` as a
/// space (the `application/x-www-form-urlencoded` rule, which is not RFC 3986's). An empty
/// input is an empty form; anything else that is not a `name=value` sequence is refused.
///
/// # Errors
///
/// Returns [`FormError`] for a duplicate key, an empty key, a segment with no separator, a
/// malformed percent escape, or octets that are not UTF-8.
pub fn decode_form(text: &str) -> Result<Form, FormError> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    if text.is_empty() {
        return Ok(Form { pairs });
    }
    for segment in text.split('&') {
        let (key, value) = segment.split_once('=').ok_or(FormError::MalformedPair)?;
        let key = percent_decode(key)?;
        if key.is_empty() {
            return Err(FormError::EmptyKey);
        }
        if pairs.iter().any(|(name, _)| *name == key) {
            return Err(FormError::DuplicateKey);
        }
        pairs.push((key, percent_decode(value)?));
    }
    Ok(Form { pairs })
}

/// Percent-decode one half of a form pair, with `+` as a space.
///
/// # Errors
///
/// Returns [`FormError::MalformedEscape`] for a truncated or non-hexadecimal escape and
/// [`FormError::NotUtf8`] when the decoded octets are not UTF-8.
pub fn percent_decode(text: &str) -> Result<String, FormError> {
    let bytes = text.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes
                    .get(index + 1)
                    .copied()
                    .and_then(hexadecimal)
                    .ok_or(FormError::MalformedEscape)?;
                let low = bytes
                    .get(index + 2)
                    .copied()
                    .and_then(hexadecimal)
                    .ok_or(FormError::MalformedEscape)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| FormError::NotUtf8)
}

/// The value a hexadecimal digit carries, or `None` when it carries none.
const fn hexadecimal(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A standard OAuth 2.0 error code.
///
/// **The two endpoints on this road answer from two different sets, and RFC 6749 declares
/// them separately.** Section 5.2 is the token endpoint's — `invalid_request`,
/// `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `invalid_scope` — and
/// section 4.1.2.1 is the authorization endpoint's — `invalid_request`,
/// `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`,
/// `server_error`, `temporarily_unavailable`. A code from one set answered at the other
/// endpoint misreports the refusal, which is what [`code_for_clause`] and [`code_for_reason`]
/// exist to keep apart: refusals are mapped **by clause at the token endpoint and by reason at
/// the authorization endpoint**.
///
/// `unauthorized_client` is section 4.1.2.1's "the client is not authorized to request an
/// authorization code using this method", and three refusals on this road are exactly that:
/// `crates/mandate-federation/src/publicclient.rs` refuses a client that is unregistered,
/// disabled or not public. They carry `DenialReason::Denied`, which the by-reason mapping
/// alone answers `access_denied` — "the resource owner or authorization server denied the
/// request", which tells a client developer the end user refused. [`code_for_denial`] reads
/// the clause first for exactly those three and falls back to the reason for every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// Both endpoints: the request is missing a required parameter, repeats one, or is
    /// otherwise malformed.
    InvalidRequest,
    /// Token endpoint: client authentication failed. Section 5.2 obliges an HTTP 401 for it,
    /// so it is answered only where a caller did present a credential that could have failed —
    /// on this road, RFC 7662 section 2.1's introspection caller proof. A client *redeeming a
    /// code* never authenticates (`token_endpoint_auth_methods_supported: ["none"]`), so no
    /// clause reachable from a redemption answers this; see [`CLAUSE_CODES`].
    InvalidClient,
    /// Token endpoint: the grant presented is invalid, expired, revoked, was issued to another
    /// client, or does not match this request.
    InvalidGrant,
    /// Token endpoint: the grant type is not one this endpoint supports.
    UnsupportedGrantType,
    /// Authorization endpoint: the client is not authorized to request an authorization code
    /// using this method. [`UNAUTHORIZED_CLIENT_CLAUSES`] is the set of refusals that produce
    /// it.
    UnauthorizedClient,
    /// Both endpoints: the requested authority is invalid, unknown or exceeds what can be
    /// granted.
    InvalidScope,
    /// Authorization endpoint: the response type is not one this endpoint supports.
    UnsupportedResponseType,
    /// Authorization endpoint: the resource owner or the authorization server refused.
    AccessDenied,
    /// Authorization endpoint: the request could not be served for a reason on this side.
    ServerError,
    /// Authorization endpoint: this side cannot answer right now.
    TemporarilyUnavailable,
}

impl ErrorCode {
    /// Every code this module can emit, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::InvalidRequest,
        Self::InvalidClient,
        Self::InvalidGrant,
        Self::UnsupportedGrantType,
        Self::UnauthorizedClient,
        Self::InvalidScope,
        Self::UnsupportedResponseType,
        Self::AccessDenied,
        Self::ServerError,
        Self::TemporarilyUnavailable,
    ];

    /// The codes RFC 6749 section 5.2 declares for the token endpoint.
    pub const TOKEN_ENDPOINT: &'static [Self] = &[
        Self::InvalidRequest,
        Self::InvalidClient,
        Self::InvalidGrant,
        Self::UnsupportedGrantType,
        Self::InvalidScope,
    ];

    /// The codes RFC 6749 section 4.1.2.1 declares for the authorization endpoint.
    pub const AUTHORIZATION_ENDPOINT: &'static [Self] = &[
        Self::InvalidRequest,
        Self::UnauthorizedClient,
        Self::AccessDenied,
        Self::UnsupportedResponseType,
        Self::InvalidScope,
        Self::ServerError,
        Self::TemporarilyUnavailable,
    ];

    /// The declared wire name of this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidScope => "invalid_scope",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The error body RFC 6749 section 5.2 declares.
///
/// The description is `&'static str` by construction: a description assembled from what the
/// caller sent would put the caller's bytes into a document rendered back to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorBody {
    /// The standard code.
    pub error: ErrorCode,
    /// A fixed human-readable description. Never caller-derived.
    pub description: &'static str,
}

impl ErrorBody {
    /// Carry a code and its description.
    #[must_use]
    pub const fn new(error: ErrorCode, description: &'static str) -> Self {
        Self { error, description }
    }

    /// `tests/security/cases.json`, case `pkce-missing`: the token request carried no
    /// `code_verifier`.
    #[must_use]
    pub const fn pkce_missing() -> Self {
        Self::new(
            ErrorCode::InvalidRequest,
            "the token request carries no code_verifier",
        )
    }

    /// `tests/security/cases.json`, case `pkce-plain`: the authorization request named a
    /// `code_challenge_method` other than `S256`, or named none.
    #[must_use]
    pub const fn pkce_plain() -> Self {
        Self::new(
            ErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
        )
    }

    /// The declared JSON rendering.
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&[
            ("error", Member::Text(self.error.as_str().to_owned())),
            (
                "error_description",
                Member::Text(self.description.to_owned()),
            ),
        ])
    }
}

impl fmt::Display for ErrorBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.error, self.description)
    }
}

impl std::error::Error for ErrorBody {}

/// RFC 7636 section 4.5: the token request of a transaction that recorded a challenge must
/// carry `code_verifier`. Every authorization code this deployment issues records one.
///
/// # Errors
///
/// Returns [`ErrorBody::pkce_missing`] when the form carries no `code_verifier`, or an empty
/// one — case `pkce-missing`.
pub fn require_code_verifier(form: &Form) -> Result<&str, ErrorBody> {
    match form.get("code_verifier") {
        Some(verifier) if !verifier.is_empty() => Ok(verifier),
        _ => Err(ErrorBody::pkce_missing()),
    }
}

/// RFC 7636 section 4.3: the authorization request names its `code_challenge_method`, and an
/// absent one defaults to `plain`. This deployment admits [`S256_METHOD`] and nothing else.
///
/// # Errors
///
/// Returns [`ErrorBody::pkce_plain`] when the form names another method or names none — case
/// `pkce-plain`.
pub fn require_s256_challenge_method(form: &Form) -> Result<(), ErrorBody> {
    if form.get("code_challenge_method") == Some(S256_METHOD) {
        Ok(())
    } else {
        Err(ErrorBody::pkce_plain())
    }
}

/// Every declared denial clause of `mandate.credential`, with the standard error code a
/// refusal carrying it is answered with.
///
/// [`DenialClause`] is `#[non_exhaustive]`, so a `match` outside `mandate-token` cannot be
/// made exhaustive by the compiler. The table is therefore decided against the enum's own
/// declaration by `crates/mandate-proto/tests/oauth.rs`, which reads the variant names from
/// `crates/mandate-token/src/projection.rs`: a clause added upstream and not mapped here
/// fails that case, naming it, rather than falling into [`code_for_clause`]'s wildcard.
///
/// # The grouping, in RFC 6749 section 5.2's own words
///
/// * `invalid_grant` — "The provided authorization grant ... is invalid, expired, revoked,
///   does not match the redirection URI used in the authorization request, **or was issued to
///   another client**." Every clause about the *grant presented* sits here, and the RFC's last
///   phrase is why `ClientMismatch` — "the presented client is not the one the code is bound
///   to" — is `invalid_grant` and not `invalid_client`.
/// * `invalid_client` — "**Client authentication failed** (unknown client, no client
///   authentication included, or unsupported authentication method)." A refusal sits here only
///   where the caller presented a credential that could have failed, which on this road is the
///   introspection endpoint's caller proof and nothing else: the metadata advertises
///   `token_endpoint_auth_methods_supported: ["none"]`, so no client redeeming a code
///   authenticates and no refusal on that path can be an authentication failure. Adversary
///   pass 2 (F1) found the four client clauses of `services/sts/src/code.rs::admitted_client`
///   here — `binding::bound_client` calls that function on **every** redemption, so all four
///   are reachable from one, and section 5.2 obliges an HTTP 401 for the code they answered
///   with.
/// * `invalid_scope` — "**The requested scope** is invalid, unknown, malformed, or exceeds
///   the scope granted by the resource owner." Only refusals about an authority the request
///   *asked for*. `crate::oauth` cannot check this itself, but
///   `crates/mandate-proto/tests/oauth.rs` can and does: the token request declares no `scope`
///   parameter (`decode::TOKEN_PARAMETERS`), so no clause reachable from
///   `services/sts/src/redemption.rs::redeem_authorization_code` may map to `invalid_scope` or
///   to `invalid_client`. That case **follows the calls**: it takes each function's body, reads
///   the clauses it names, and walks on through every call into a sibling module of the STS
///   crate, transitively. Reading a fixed pair of files was one hop short of
///   `code::admitted_client` (adversary pass 2, F2), and a set named by file is a set that is
///   right until a call moves.
/// * `invalid_request` — the request itself was wrong, or the condition names no grant, client
///   or scope the caller could have stated differently.
///
/// Adversary pass 1 (`review-result:wave-d-login-adapters-adversary-1`, F1 and F2) found five
/// clauses on the wrong side of that rule, and pass 2 (F1) found four more that the check's own
/// reachable set did not yet cover. The rule was right both times and the table was not; the
/// class is closed by the reachability case above — over the set the calls reach — rather than
/// by the nine corrections.
pub const CLAUSE_CODES: &[(DenialClause, ErrorCode)] = &[
    (DenialClause::AudienceAmbiguous, ErrorCode::InvalidScope),
    (DenialClause::ProfileUnadmitted, ErrorCode::InvalidScope),
    (DenialClause::SourceUnresolved, ErrorCode::InvalidGrant),
    (DenialClause::SourceDisabled, ErrorCode::InvalidGrant),
    (
        DenialClause::SourceOutsideOrganization,
        ErrorCode::InvalidGrant,
    ),
    (DenialClause::TargetUnregistered, ErrorCode::InvalidGrant),
    (DenialClause::TargetDisabled, ErrorCode::InvalidGrant),
    (DenialClause::OrganizationMismatch, ErrorCode::InvalidGrant),
    (DenialClause::ExpiryUnbounded, ErrorCode::InvalidRequest),
    (DenialClause::SigningRefused, ErrorCode::InvalidGrant),
    (DenialClause::ProofMalformed, ErrorCode::InvalidRequest),
    (DenialClause::CallerProofInvalid, ErrorCode::InvalidClient),
    (
        DenialClause::IntrospectionAuthority,
        ErrorCode::InvalidClient,
    ),
    (DenialClause::AudienceMismatch, ErrorCode::InvalidGrant),
    (DenialClause::ResolutionUnavailable, ErrorCode::InvalidGrant),
    (DenialClause::CredentialUnknown, ErrorCode::InvalidGrant),
    (DenialClause::CredentialRevoked, ErrorCode::InvalidGrant),
    (DenialClause::ServerDisabled, ErrorCode::InvalidScope),
    (DenialClause::AlgorithmUnadmitted, ErrorCode::InvalidRequest),
    (
        DenialClause::KeyReferenceUnresolvable,
        ErrorCode::InvalidRequest,
    ),
    (
        DenialClause::KeyReferenceRecorded,
        ErrorCode::InvalidRequest,
    ),
    (DenialClause::KeyMaterialRecorded, ErrorCode::InvalidRequest),
    (DenialClause::KeyWindowNotOrdered, ErrorCode::InvalidRequest),
    (DenialClause::KeyUnknown, ErrorCode::InvalidRequest),
    (DenialClause::NoReplacementKey, ErrorCode::InvalidRequest),
    (DenialClause::KeyNotRecorded, ErrorCode::InvalidRequest),
    (DenialClause::ChallengeMalformed, ErrorCode::InvalidGrant),
    (DenialClause::VerifierMalformed, ErrorCode::InvalidGrant),
    (DenialClause::VerifierMismatch, ErrorCode::InvalidGrant),
    (DenialClause::CodeProofMismatch, ErrorCode::InvalidGrant),
    (DenialClause::CodeUnknown, ErrorCode::InvalidGrant),
    (DenialClause::CodeExpired, ErrorCode::InvalidGrant),
    (DenialClause::CodeConsumed, ErrorCode::InvalidGrant),
    (DenialClause::ClientMismatch, ErrorCode::InvalidGrant),
    (DenialClause::ClientUnregistered, ErrorCode::InvalidGrant),
    (DenialClause::ClientNotPublic, ErrorCode::InvalidGrant),
    (DenialClause::ClientDisabled, ErrorCode::InvalidGrant),
    (
        DenialClause::ClientOutsideOrganization,
        ErrorCode::InvalidGrant,
    ),
    (DenialClause::RedirectUnregistered, ErrorCode::InvalidGrant),
    (DenialClause::RedirectMismatch, ErrorCode::InvalidGrant),
    (DenialClause::SessionEpochStale, ErrorCode::InvalidGrant),
    (DenialClause::SessionUnusable, ErrorCode::InvalidGrant),
];

/// The standard error code a refusal carrying this clause is answered with.
///
/// The wildcard is unreachable for every clause [`CLAUSE_CODES`] names, and that is every
/// clause `mandate-token` declares today; it exists because `#[non_exhaustive]` requires one.
/// `invalid_grant` is the conservative answer for an unmapped clause: it tells a caller the
/// grant did not work and nothing about why.
#[must_use]
pub fn code_for_clause(clause: DenialClause) -> ErrorCode {
    CLAUSE_CODES
        .iter()
        .find(|(declared, _)| *declared == clause)
        .map_or(ErrorCode::InvalidGrant, |(_, code)| *code)
}

/// The authorization endpoint's error code for a declared denial reason.
///
/// **The authorization endpoint refuses by reason, not by clause, and it has to.** The
/// handler behind it is `crates/mandate-federation`, whose refusals carry that crate's *own*
/// `DenialClause` — a different type from `mandate_token::projection::DenialClause`, declared
/// in a crate that is outside `mandate-proto`'s dependency ceiling and outside
/// `mandate-server`'s. What both crates do share is `mandate.core.DenialReason`, which is the
/// contract's only wire field on a `Denied` error, so that is what this maps.
///
/// The codes are RFC 6749 section 4.1.2.1's, not section 5.2's. Answering `invalid_grant` at
/// the authorization endpoint would name a grant the caller has not presented — the
/// authorization request *asks for* the grant — so the refusals that a token endpoint would
/// call `invalid_grant` are `access_denied` here: "The resource owner or authorization server
/// denied the request."
///
/// The match is exhaustive and carries no wildcard. `mandate.core.DenialReason` is a
/// `canonical_enums!` type and is not `#[non_exhaustive]`, so a reason added to the contract
/// fails this function to compile rather than falling into a default — which is the guarantee
/// [`code_for_clause`] cannot have and buys with a test instead.
#[must_use]
pub const fn code_for_reason(reason: DenialReason) -> ErrorCode {
    match reason {
        // "the resource owner or authorization server denied the request" covers every refusal
        // of the authority itself: a declared denial, an invalid session proof, a tenant that
        // does not match, and an epoch that has moved.
        DenialReason::Denied
        | DenialReason::InvalidCredential
        | DenialReason::TenantMismatch
        | DenialReason::StaleEpoch
        | DenialReason::ApprovalRequired => ErrorCode::AccessDenied,
        // The requested target's audience is an authority the request asked for.
        DenialReason::AudienceMismatch => ErrorCode::InvalidScope,
        // "currently unable to handle the request" — a reader that could not answer has not
        // answered no, and a caller may retry. `server_error` is the listener's answer for a
        // failure that is not a declared denial at all.
        DenialReason::Unavailable => ErrorCode::TemporarilyUnavailable,
    }
}

/// The `mandate-federation` denial clauses the authorization endpoint answers
/// `unauthorized_client` for, by name.
///
/// RFC 6749 section 4.1.2.1: "the client is not authorized to request an authorization code
/// using this method". `crates/mandate-federation/src/publicclient.rs::registered_public_client`
/// raises all three — the client is not registered, is disabled, or is not a public client —
/// and each carries `DenialReason::Denied`, which the by-reason mapping alone answers
/// `access_denied`.
///
/// **They are names and not values because the type is out of reach.** That crate's
/// `DenialClause` is its own, distinct from `mandate_token::projection::DenialClause`, and
/// `mandate-federation` is outside this crate's dependency ceiling; what a caller holds is the
/// variant's name, which is what `{:?}` on the clause renders.
/// `crates/mandate-proto/tests/oauth.rs` reads `publicclient.rs` and fails if a name here is
/// no longer raised there, so a rename upstream is reported rather than answered by the
/// fallback.
pub const UNAUTHORIZED_CLIENT_CLAUSES: &[&str] =
    &["ClientUnknown", "ClientDisabled", "ClientNotPublic"];

/// The authorization endpoint's error code for a refusal, by clause first and reason second.
///
/// This is what a listener calls with a `mandate_federation::Denied`: the `clause` is that
/// error's own clause name (`format!("{:?}", denied.clause)`) and `reason` is its
/// `DenialReason`. Composing the two here is the point — a listener that had to test the
/// clause itself would be reassembling this mapping at each of its call sites, and the one
/// that forgot would answer `access_denied` for a client the end user never saw.
///
/// [`code_for_reason`] remains the mapping for a refusal that carries no clause a caller can
/// name, and is the fallback here.
#[must_use]
pub fn code_for_denial(clause: &str, reason: DenialReason) -> ErrorCode {
    if UNAUTHORIZED_CLIENT_CLAUSES.contains(&clause) {
        ErrorCode::UnauthorizedClient
    } else {
        code_for_reason(reason)
    }
}

/// A member of a rendered JSON document.
///
/// The three forms the documents on this road carry, and no more: a text, a list of texts,
/// and a list of flat objects (the `keys` of a JWKS document).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member {
    /// A JSON string.
    Text(String),
    /// A JSON array of strings.
    List(Vec<String>),
    /// A JSON array of flat objects of strings.
    Objects(Vec<Vec<(String, String)>>),
}

impl Member {
    /// The `serde_json` value this member renders as.
    fn value(&self) -> Value {
        match self {
            Self::Text(text) => Value::String(text.clone()),
            Self::List(items) => Value::Array(
                items
                    .iter()
                    .map(|item| Value::String(item.clone()))
                    .collect(),
            ),
            Self::Objects(objects) => Value::Array(
                objects
                    .iter()
                    .map(|members| {
                        let mut map = Map::new();
                        for (name, text) in members {
                            map.insert(name.clone(), Value::String(text.clone()));
                        }
                        Value::Object(map)
                    })
                    .collect(),
            ),
        }
    }
}

/// Render a flat JSON object through `serde_json`.
///
/// The members are rendered in sorted key order rather than the order given, so the document
/// does not depend on whether `serde_json`'s `preserve_order` feature is on somewhere else in
/// the graph. JSON gives object members no order, so nothing is lost and a byte-for-byte
/// case is possible.
#[must_use]
pub fn object(members: &[(&str, Member)]) -> String {
    let mut sorted: BTreeMap<&str, Value> = BTreeMap::new();
    for (name, member) in members {
        sorted.insert(name, member.value());
    }
    let mut map = Map::new();
    for (name, value) in sorted {
        map.insert(name.to_owned(), value);
    }
    Value::Object(map).to_string()
}

/// Why a JSON body was not read as a flat object of text members.
///
/// Every variant is a unit: see the module's note on caller-supplied text. In particular no
/// `serde_json` error message, which quotes the input, reaches a value that can be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonError {
    /// The body was not JSON at all.
    NotJson,
    /// The body was JSON, and was not an object.
    NotAnObject,
    /// A member's value was not a string.
    ValueNotText,
    /// A member name appeared more than once.
    DuplicateKey,
}

impl fmt::Display for JsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotJson => "the body is not JSON",
            Self::NotAnObject => "the body is not a JSON object",
            Self::ValueNotText => "a member of the body is not a string",
            Self::DuplicateKey => "a member name appeared more than once",
        })
    }
}

impl std::error::Error for JsonError {}

/// Read a JSON body as a flat object of text members, in the order presented.
///
/// A duplicate member name is refused rather than resolved: `serde_json`'s own map keeps the
/// last, and a body carrying `{"proof":"a","proof":"b"}` is a body two readers can disagree
/// about. Nesting, numbers, booleans, nulls and arrays are refused for the same reason the
/// form decoder refuses a segment with no separator — the declared request bodies on this
/// road are flat objects of declared lexical forms, and admitting more admits shapes no
/// command declares.
///
/// # Errors
///
/// Returns [`JsonError`] for a body that is not JSON, is not an object, carries a member that
/// is not a string, or repeats a member name.
pub fn flat_object(text: &str) -> Result<Vec<(String, String)>, JsonError> {
    FLAT_OBJECT_REFUSAL.with(|cell| cell.set(JsonError::NotAnObject));
    let read: FlatObject = serde_json::from_str(text).map_err(|error| {
        if error.is_syntax() || error.is_eof() {
            JsonError::NotJson
        } else {
            FLAT_OBJECT_REFUSAL.with(std::cell::Cell::get)
        }
    })?;
    Ok(read.0)
}

thread_local! {
    /// The refusal the visitor below decided, carried past `serde`'s own error type.
    ///
    /// `serde`'s `Error::custom` takes a `Display`, and rendering one would put the body's
    /// own bytes into the message. The visitor records which refusal it took here and hands
    /// `serde` a message with no input in it.
    static FLAT_OBJECT_REFUSAL: std::cell::Cell<JsonError> =
        const { std::cell::Cell::new(JsonError::NotAnObject) };
}

/// A flat JSON object of text members, read in the order presented.
struct FlatObject(Vec<(String, String)>);

impl<'de> serde::Deserialize<'de> for FlatObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(FlatObjectVisitor)
    }
}

struct FlatObjectVisitor;

impl<'de> Visitor<'de> for FlatObjectVisitor {
    type Value = FlatObject;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a flat JSON object of string members")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut members: Vec<(String, String)> = Vec::new();
        while let Some(name) = access.next_key::<String>()? {
            if members.iter().any(|(declared, _)| *declared == name) {
                return Err(refuse(JsonError::DuplicateKey));
            }
            let value = access.next_value::<Value>()?;
            let Value::String(text) = value else {
                return Err(refuse(JsonError::ValueNotText));
            };
            members.push((name, text));
        }
        Ok(FlatObject(members))
    }
}

/// Record the refusal and hand `serde` a message carrying none of the body.
fn refuse<E: de::Error>(refusal: JsonError) -> E {
    FLAT_OBJECT_REFUSAL.with(|cell| cell.set(refusal));
    E::custom("the body is not a flat JSON object of string members")
}
