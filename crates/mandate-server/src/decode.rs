//! The decoding boundary of the customer login road.
//!
//! One decoder per road command, building exactly the input that command declares from the
//! wire form the protocol declares. `story:login-adapters` ruling 1 (wave D opening): no road
//! command declares a `mandate.core.VerifiedContext` input — `AuthenticateFederation` takes a
//! connection and a proof, `AuthorizePublicClient` a session proof and the request fields,
//! `RedeemAuthorizationCode` a client, a code, a verifier and a redirect, and
//! `IntrospectCredential` two proofs — so the adapter's whole job here is the wire form, and
//! `VerifiedContext` is built nowhere in this module.
//!
//! # What "exactly the declared inputs" means
//!
//! Three separate refusals, and each is a different thing a caller can try:
//!
//! * A parameter no command input binds to is refused ([`Refusal::UndeclaredField`]). The
//!   set of admitted keys is closed per endpoint, so a caller cannot smuggle an
//!   `organization_id`, an `audience` or a `subject` past a decoder by adding it.
//! * A parameter the *contract* declares but the *protocol* does not put on the wire is
//!   refused ([`Refusal::ServerResolvedField`]). There is exactly one:
//!   `RedeemAuthorizationCode.code_id`, which `systems/mandate/domains/credential.yaml`'s
//!   header calls out — "resolved by the trusted adapter from proof; it is not a public OAuth
//!   parameter or authority selector". [`RedeemAuthorizationCode::code_id`] is therefore
//!   `Option` and is always `None` here; the resolution is the STS's.
//! * A repeated parameter is refused ([`Refusal::DuplicateField`]) rather than resolved, and
//!   so is a repeated header ([`Refusal::DuplicateHeader`]). Every rule for picking one of two
//!   values is a rule an attacker can aim at a reader that picked the other.
//!
//! # What this module does not decide
//!
//! The challenge and the verifier are checked for **shape** and nothing more
//! ([`challenge_has_s256_shape`], [`verifier_has_rfc7636_shape`]): a value outside RFC 7636's
//! form is not a challenge or a verifier at all and does not need a handler to say so. Whether
//! a verifier *redeems* a challenge, whether a client is registered, whether a session is
//! live, whether a code exists — every one of those is a handler's, and this module reaches
//! none of the reads they need. `crates/mandate-federation/src/pkce.rs` carries the deciding
//! predicate, including the base64url pad-bit check this module deliberately leaves to it.
//!
//! # Why the request value names no `http` type
//!
//! `dependency-boundaries.json` gives this crate `mandate-types` and `mandate-proto` and
//! nothing else — no `http`, no `url`, no `percent-encoding`, no `httparse`. [`Request`] is
//! therefore a crate-local value over `String` and `Vec<u8>`, on the precedent of the two
//! `RequestContext` types that already name no transport type
//! (`crates/mandate-federation/src/lib.rs:373-395`, `services/sts/src/lib.rs:160-175`). A
//! listener parses the bytes; this module never sees a socket.

use mandate_proto::oauth::{self, ErrorBody, ErrorCode, Form, FormError};
use mandate_types::{
    Action, Audience, AuthorityScope, AuthorizationCodeId, CredentialProof, DelegationId,
    FederationConnectionId, OAuthClientId, PkceChallenge, PkceMethod, RedirectUri,
    ResourceServerId,
};

/// The largest request body, and the largest query string, this module reads.
///
/// Checked before anything is parsed, so an oversized request costs a length comparison. Every
/// road request is a handful of short declared fields; the ceiling is two orders of magnitude
/// above the largest of them and is a bound, not a budget.
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// The media type of the token and introspection requests.
pub const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";

/// The media type of the federation login request.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// The authorization-code `grant_type` (RFC 6749 section 4.1.3).
pub const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";

/// The token-exchange `grant_type` (RFC 8693 section 2.1).
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The two `grant_type` values the token endpoint serves, in the order the metadata document
/// advertises them.
pub const TOKEN_GRANTS: &[&str] = &[AUTHORIZATION_CODE_GRANT, TOKEN_EXCHANGE_GRANT];

/// The only token type a token exchange admits, as `subject_token_type` and as
/// `requested_token_type` (RFC 8693 section 3): a Mandate access credential.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The URN prefix a `resource` names a registration by (RFC 4122 section 3, RFC 8707).
///
/// RFC 8707 requires `resource` to be an absolute URI; a registration identity is a UUID, and
/// `urn:uuid:<uuid>` is the absolute URI of one.
pub const RESOURCE_URN_PREFIX: &str = "urn:uuid:";

/// The only `response_type` the authorization endpoint serves.
pub const CODE_RESPONSE_TYPE: &str = "code";

/// The length of an S256 challenge: a 32-byte digest in unpadded base64url.
pub const CHALLENGE_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is 43 to 128 characters of the unreserved set.
pub const VERIFIER_LENGTH: std::ops::RangeInclusive<usize> = 43..=128;

/// The largest free-text parameter this module admits, in bytes.
///
/// `state`, `nonce`, `redirect_uri` and `scope` are the values on this road whose content the
/// contract does not constrain, and every one of them is a value a listener puts back on the
/// wire: RFC 6749 section 4.1.2.1 obliges the authorization endpoint to redirect to the
/// presented `redirect_uri` carrying the presented `state` back, so all four reach a `Location`
/// header. The body ceiling alone would admit an eight-kilobyte `state`.
pub const MAX_TEXT_BYTES: usize = 512;

/// A request as this library reads it: a method, a target, header pairs and body bytes.
///
/// Plain `String` and `Vec<u8>` over `mandate-types` values. No `http::Request`, no
/// `httparse::Request`, no borrowed lifetime from a socket buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    /// The request method, as presented.
    pub method: String,
    /// The request target: a path, and a query string when one was presented.
    pub path: String,
    /// The header pairs, in the order presented, names as presented.
    pub headers: Vec<(String, String)>,
    /// The body bytes, as presented.
    pub body: Vec<u8>,
}

impl Request {
    /// A request with a method and a target and nothing else.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The same request, carrying one more header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The same request, carrying this body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The target's path: everything before the first `?`.
    #[must_use]
    pub fn route_path(&self) -> &str {
        self.path
            .split_once('?')
            .map_or(self.path.as_str(), |(path, _)| path)
    }

    /// The target's query string: everything after the first `?`, or the empty string.
    #[must_use]
    pub fn query(&self) -> &str {
        self.path.split_once('?').map_or("", |(_, query)| query)
    }

    /// The single value presented for `name`, matched without regard to case.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::DuplicateHeader`] when the header was presented more than once.
    pub fn single_header(&self, name: &str) -> Result<Option<&str>, Refusal> {
        let mut found: Option<&str> = None;
        for (presented, value) in &self.headers {
            if presented.eq_ignore_ascii_case(name) {
                if found.is_some() {
                    return Err(Refusal::DuplicateHeader);
                }
                found = Some(value.as_str());
            }
        }
        Ok(found)
    }
}

/// Why a request was not decoded into a declared command input.
///
/// Every variant is a unit, so no caller-supplied byte can be carried into the [`ErrorBody`]
/// that is rendered back to that caller. [`Refusal::body`] is the whole rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Refusal {
    /// The route does not serve this method.
    MethodNotAllowed,
    /// The body or the query string is over [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// A body was presented to a route that reads none.
    BodyNotAdmitted,
    /// A query string was presented to a route that reads none.
    QueryNotAdmitted,
    /// The body is not UTF-8.
    BodyNotUtf8,
    /// The `Content-Type` is not the one this route reads.
    ContentTypeUnsupported,
    /// A header was presented more than once.
    DuplicateHeader,
    /// The body is not the declared wire form at all.
    MalformedBody,
    /// A parameter was presented more than once.
    DuplicateField,
    /// A parameter no declared input binds to was presented.
    UndeclaredField,
    /// A parameter the trusted adapter resolves, not the caller: `code_id`.
    ServerResolvedField,
    /// A declared input had no value on the wire.
    MissingField,
    /// A value was not the lexical form its declared type admits.
    MalformedField,
    /// The `grant_type` is not one of [`TOKEN_GRANTS`].
    UnsupportedGrantType,
    /// A token exchange named a `subject_token_type` or a `requested_token_type` other than
    /// [`ACCESS_TOKEN_TYPE`].
    UnsupportedTokenType,
    /// A token exchange named its target twice: by `audience` and by `resource`.
    TargetAmbiguous,
    /// The `response_type` is not [`CODE_RESPONSE_TYPE`].
    UnsupportedResponseType,
    /// No session proof was presented to the authorization endpoint.
    MissingSessionProof,
    /// The session proof was not `Bearer` followed by the declared base64 form.
    MalformedSessionProof,
    /// No caller proof was presented to the introspection endpoint (RFC 7662 section 2.1).
    MissingCallerProof,
    /// The caller proof was not `Bearer` followed by the declared base64 form.
    MalformedCallerProof,
    /// `tests/security/cases.json`, case `pkce-missing`: no `code_verifier`.
    PkceMissing,
    /// `tests/security/cases.json`, case `pkce-plain`: a `code_challenge_method` other than
    /// `S256`, or none.
    PkceMethodUnsupported,
    /// The `code_challenge` is not in the S256 shape.
    ChallengeMalformed,
    /// The `code_verifier` is not in the RFC 7636 section 4.1 form.
    VerifierMalformed,
    /// A free-text parameter is over [`MAX_TEXT_BYTES`].
    TextTooLong,
    /// A free-text parameter carries a character in Unicode general category `Cc`: the C0
    /// controls, DEL, and the C1 block U+0080–U+009F.
    ///
    /// The C1 block is in the class because U+0085 NEXT LINE is a line terminator to some
    /// readers, which is the same hazard CR and LF are refused for. The predicate is
    /// `char::is_control`, whose class is exactly `Cc`; U+2028 LINE SEPARATOR is outside it
    /// and is admitted.
    ControlCharacter,
}

impl Refusal {
    /// Every refusal this module can produce, in declaration order.
    ///
    /// The list is what `crates/mandate-server/tests/decode.rs` reads to decide that each one
    /// answers with a standard code and a description that carries no caller text. A variant
    /// added without a row here fails that case rather than reaching a client unnamed.
    pub const ALL: &'static [Self] = &[
        Self::MethodNotAllowed,
        Self::BodyTooLarge,
        Self::BodyNotAdmitted,
        Self::QueryNotAdmitted,
        Self::BodyNotUtf8,
        Self::ContentTypeUnsupported,
        Self::DuplicateHeader,
        Self::MalformedBody,
        Self::DuplicateField,
        Self::UndeclaredField,
        Self::ServerResolvedField,
        Self::MissingField,
        Self::MalformedField,
        Self::UnsupportedGrantType,
        Self::UnsupportedTokenType,
        Self::TargetAmbiguous,
        Self::UnsupportedResponseType,
        Self::MissingSessionProof,
        Self::MalformedSessionProof,
        Self::MissingCallerProof,
        Self::MalformedCallerProof,
        Self::PkceMissing,
        Self::PkceMethodUnsupported,
        Self::ChallengeMalformed,
        Self::VerifierMalformed,
        Self::TextTooLong,
        Self::ControlCharacter,
    ];

    /// The standard OAuth error code this refusal is answered with.
    #[must_use]
    pub const fn error_code(self) -> ErrorCode {
        match self {
            Self::UnsupportedGrantType => ErrorCode::UnsupportedGrantType,
            Self::UnsupportedResponseType => ErrorCode::UnsupportedResponseType,
            Self::MissingCallerProof | Self::MalformedCallerProof => ErrorCode::InvalidClient,
            _ => ErrorCode::InvalidRequest,
        }
    }

    /// The declared error body this refusal is answered with.
    #[must_use]
    pub const fn body(self) -> ErrorBody {
        match self {
            Self::PkceMissing => ErrorBody::pkce_missing(),
            Self::PkceMethodUnsupported => ErrorBody::pkce_plain(),
            _ => ErrorBody::new(self.error_code(), self.description()),
        }
    }

    /// The fixed description of this refusal. Never caller-derived.
    const fn description(self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "this route does not serve that method",
            Self::BodyTooLarge => "the request is larger than this endpoint reads",
            Self::BodyNotAdmitted => "this route reads no request body",
            Self::QueryNotAdmitted => "this route reads no query string",
            Self::BodyNotUtf8 => "the request body is not UTF-8",
            Self::ContentTypeUnsupported => "this route does not read that media type",
            Self::DuplicateHeader => "a header was presented more than once",
            Self::MalformedBody => "the request body is not the declared wire form",
            Self::DuplicateField => "a parameter was presented more than once",
            Self::UndeclaredField => {
                "the request carries a parameter this endpoint declares no input for"
            }
            Self::ServerResolvedField => {
                "code_id is resolved by the server and is not a request parameter"
            }
            Self::MissingField => "the request is missing a required parameter",
            Self::MalformedField => "a parameter is not in the form its declared type admits",
            Self::UnsupportedGrantType => {
                "the token endpoint serves the authorization_code and token-exchange grants and no other"
            }
            Self::UnsupportedTokenType => {
                "a token exchange admits the access_token token type and no other"
            }
            Self::TargetAmbiguous => {
                "a token exchange names one target, by audience or by resource"
            }
            Self::UnsupportedResponseType => {
                "the authorization endpoint serves the code response type and no other"
            }
            Self::MissingSessionProof => "the authorization request carries no session proof",
            Self::MalformedSessionProof => {
                "the session proof is not a bearer credential in its declared form"
            }
            Self::MissingCallerProof => "the introspection request carries no caller credential",
            Self::MalformedCallerProof => {
                "the caller credential is not a bearer credential in its declared form"
            }
            Self::PkceMissing => "the token request carries no code_verifier",
            Self::PkceMethodUnsupported => "code_challenge_method must be S256",
            Self::ChallengeMalformed => "code_challenge is not an S256 challenge",
            Self::VerifierMalformed => "code_verifier is not in the form RFC 7636 declares",
            Self::TextTooLong => "a parameter is longer than this endpoint reads",
            Self::ControlCharacter => "a parameter carries a control character",
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.description())
    }
}

impl std::error::Error for Refusal {}

impl From<FormError> for Refusal {
    fn from(error: FormError) -> Self {
        match error {
            FormError::DuplicateKey => Self::DuplicateField,
            FormError::EmptyKey | FormError::MalformedPair | FormError::MalformedEscape => {
                Self::MalformedBody
            }
            FormError::NotUtf8 => Self::BodyNotUtf8,
            _ => Self::MalformedBody,
        }
    }
}

/// `mandate.federation.AuthenticateFederation`, as the wire form presents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateFederation {
    /// The declared `connection_id`.
    pub connection_id: FederationConnectionId,
    /// The declared `proof`.
    pub proof: CredentialProof,
}

impl AuthenticateFederation {
    /// The declared input names this value carries, in contract order.
    pub const DECLARED_INPUTS: &'static [&'static str] = &["connection_id", "proof"];
}

/// `mandate.federation.AuthorizePublicClient`, as the wire form presents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizePublicClient {
    /// The declared `client_id`.
    pub client_id: OAuthClientId,
    /// The declared `redirect_uri`.
    pub redirect_uri: RedirectUri,
    /// The declared `challenge`.
    pub challenge: PkceChallenge,
    /// The declared `method`.
    pub method: PkceMethod,
    /// The declared `state`.
    pub state: String,
    /// The declared `nonce`.
    pub nonce: String,
    /// The declared `session_proof`.
    pub session_proof: CredentialProof,
    /// The declared `target`.
    pub target: ResourceServerId,
    /// The declared `requested_scope`.
    pub requested_scope: AuthorityScope,
}

impl AuthorizePublicClient {
    /// The declared input names this value carries, in contract order.
    pub const DECLARED_INPUTS: &'static [&'static str] = &[
        "client_id",
        "redirect_uri",
        "challenge",
        "method",
        "state",
        "nonce",
        "session_proof",
        "target",
        "requested_scope",
    ];
}

/// `mandate.credential.RedeemAuthorizationCode`, as the wire form presents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemAuthorizationCode {
    /// The declared `code_id`, which the wire never carries.
    ///
    /// `credential.yaml`'s header: resolved by the trusted adapter from the proof, and not a
    /// public OAuth parameter or authority selector. It is `None` on every value this module
    /// produces, and a request that presents one is refused
    /// ([`Refusal::ServerResolvedField`]).
    pub code_id: Option<AuthorizationCodeId>,
    /// The declared `client_id`.
    pub client_id: OAuthClientId,
    /// The declared `code`.
    pub code: CredentialProof,
    /// The declared `pkce_verifier`.
    pub pkce_verifier: CredentialProof,
    /// The declared `redirect_uri`.
    pub redirect_uri: RedirectUri,
}

impl RedeemAuthorizationCode {
    /// The declared input names this value carries, in contract order.
    pub const DECLARED_INPUTS: &'static [&'static str] = &[
        "code_id",
        "client_id",
        "code",
        "pkce_verifier",
        "redirect_uri",
    ];
}

/// `mandate.credential.ExchangeCredential`, as RFC 8693's request presents it, subject-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeCredential {
    /// The declared `subject_proof`, from `subject_token`.
    pub subject_proof: CredentialProof,
    /// The declared `actor_proof`, from `actor_token`: `Some` whenever the request presents
    /// an `actor_token` or an `actor_token_type`, so that the handler — which exchanges
    /// subject-only (`story:federated-token-exchange`) — refuses it and records the refusal
    /// (correction round 1, F3). A decoder refusal would record nothing.
    ///
    /// The material is carried as the bytes presented and never decoded or read: a proof
    /// whose only use is to be refused has no form worth checking, and a check here would put
    /// a decoder refusal back in front of the recorded one.
    pub actor_proof: Option<CredentialProof>,
    /// The declared `target`, from `audience` or `resource`: a registration identity, or the
    /// audience name one holds.
    pub target: ExchangeTarget,
    /// The declared `requested_scope`, from `scope`.
    pub requested_scope: AuthorityScope,
    /// The declared `delegation_id`, which RFC 8693 has no parameter for. `None` on every
    /// value this module produces.
    pub delegation_id: Option<DelegationId>,
}

impl ExchangeCredential {
    /// The declared input names this value carries, in contract order.
    pub const DECLARED_INPUTS: &'static [&'static str] = &[
        "subject_proof",
        "actor_proof",
        "target",
        "requested_scope",
        "delegation_id",
    ];
}

/// How an exchange request names its target (RFC 8693 section 2.1, RFC 8707).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExchangeTarget {
    /// A registration identity: `audience=<uuid>` or `resource=urn:uuid:<uuid>`.
    Registration(ResourceServerId),
    /// Any other `audience`: RFC 8693's "logical name of the target service", which the
    /// handler resolves among the subject's organization's registrations and nowhere else.
    ///
    /// An audience whose text is itself a UUID is read as the identity, so a registration
    /// whose audience is spelled as a UUID is reachable by its identity and not by that name.
    Audience(Audience),
}

/// What the token endpoint was asked for, by `grant_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRequest {
    /// `grant_type=authorization_code`: `mandate.credential.RedeemAuthorizationCode`.
    AuthorizationCode(RedeemAuthorizationCode),
    /// RFC 8693's grant: `mandate.credential.ExchangeCredential`.
    TokenExchange(ExchangeCredential),
}

/// `mandate.credential.IntrospectCredential`, as the wire form presents it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectCredential {
    /// The declared `caller_proof`, from the `Authorization` header.
    pub caller_proof: CredentialProof,
    /// The declared `credential_proof`, from the form's `token` (RFC 7662 section 2.1).
    pub credential_proof: CredentialProof,
}

impl IntrospectCredential {
    /// The declared input names this value carries, in contract order.
    pub const DECLARED_INPUTS: &'static [&'static str] = &["caller_proof", "credential_proof"];
}

/// The parameters the authorization endpoint admits, and nothing else.
pub const AUTHORIZE_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "code_challenge",
    "code_challenge_method",
    "state",
    "nonce",
    "target",
    "scope",
];

/// The parameters the token endpoint admits on the authorization-code grant, and nothing
/// else.
pub const TOKEN_PARAMETERS: &[&str] = &[
    "grant_type",
    "client_id",
    "code",
    "code_verifier",
    "redirect_uri",
];

/// The parameters the token endpoint admits on the token-exchange grant, and nothing else.
///
/// RFC 8693 section 2.1's request, less client authentication, because this is the
/// public-client road (`token_endpoint_auth_methods_supported: ["none"]`). `actor_token` and
/// `actor_token_type` are admitted so that an actor reaches the handler and is refused there,
/// recorded (see [`ExchangeCredential::actor_proof`]). `scope` is required rather than
/// optional: the declared `requested_scope` is not optional, and an absent one has no
/// reading this module could supply without inventing authority.
pub const EXCHANGE_PARAMETERS: &[&str] = &[
    "grant_type",
    "subject_token",
    "subject_token_type",
    "audience",
    "resource",
    "scope",
    "requested_token_type",
    "actor_token",
    "actor_token_type",
];

/// The parameters the introspection endpoint admits, and nothing else.
///
/// `token_type_hint` is RFC 7662 section 2.1's optional hint. No declared input of
/// `mandate.credential.IntrospectCredential` binds to it, so it is read and discarded: the
/// value never reaches a handler and never becomes authority.
pub const INTROSPECT_PARAMETERS: &[&str] = &["token", "token_type_hint"];

/// The members the federation login body admits, and nothing else.
pub const LOGIN_MEMBERS: &[&str] = &["connection_id", "proof"];

/// Decode `mandate.federation.AuthenticateFederation` from its JSON request body.
///
/// # Errors
///
/// Returns [`Refusal`] for another method or media type, an oversized or non-UTF-8 body, a
/// presented client credential, a body that is not a flat JSON object of strings, an undeclared
/// or repeated member, a missing member, or a member outside the lexical form its declared type
/// admits.
pub fn authenticate_federation(request: &Request) -> Result<AuthenticateFederation, Refusal> {
    entry(request, "POST", Reads::Body)?;
    let body = require_body(request, JSON_MEDIA_TYPE)?;
    // This command declares no caller credential. A presented one is an authority the contract
    // has no input for, refused for the same reason an undeclared parameter is.
    no_presented_credential(request)?;
    let members = oauth::flat_object(body).map_err(|_| Refusal::MalformedBody)?;
    for (name, _) in &members {
        if !LOGIN_MEMBERS.contains(&name.as_str()) {
            return Err(Refusal::UndeclaredField);
        }
    }
    let connection_id = FederationConnectionId::parse(member(&members, "connection_id")?)
        .map_err(|_| Refusal::MalformedField)?;
    let proof = credential(member(&members, "proof")?)?;
    Ok(AuthenticateFederation {
        connection_id,
        proof,
    })
}

/// Decode `mandate.federation.AuthorizePublicClient` from its query string and its bearer
/// session proof.
///
/// RFC 6749 section 3.1: the authorization endpoint serves `GET`, and the request parameters
/// are in the query component. The session proof is presented as a bearer credential
/// (RFC 6750 section 2.1) rather than in the query, because a credential in a query string is
/// a credential in every access log the request passes through.
///
/// # Errors
///
/// Returns [`Refusal`] for another method, an oversized query or body, a presented body, a
/// malformed or repeated parameter, an undeclared parameter, a missing parameter, a free-text
/// parameter that is too long or carries a control character, a `response_type` other than
/// `code`, a `code_challenge_method` other than `S256` (case `pkce-plain`), a challenge
/// outside the S256 shape, or an absent or malformed session proof.
pub fn authorize_public_client(request: &Request) -> Result<AuthorizePublicClient, Refusal> {
    entry(request, "GET", Reads::Query)?;
    let session_proof = bearer(
        request,
        Refusal::MissingSessionProof,
        Refusal::MalformedSessionProof,
    )?;
    let form = oauth::decode_form(request.query())?;
    closed(&form, AUTHORIZE_PARAMETERS)?;
    if field(&form, "response_type")? != CODE_RESPONSE_TYPE {
        return Err(Refusal::UnsupportedResponseType);
    }
    oauth::require_s256_challenge_method(&form).map_err(|_| Refusal::PkceMethodUnsupported)?;
    let challenge = field(&form, "code_challenge")?;
    if !challenge_has_s256_shape(challenge) {
        return Err(Refusal::ChallengeMalformed);
    }
    Ok(AuthorizePublicClient {
        client_id: OAuthClientId::parse(field(&form, "client_id")?)
            .map_err(|_| Refusal::MalformedField)?,
        redirect_uri: RedirectUri::new(free_text(&form, "redirect_uri")?),
        challenge: PkceChallenge::new(challenge),
        method: PkceMethod::S256,
        state: free_text(&form, "state")?,
        nonce: free_text(&form, "nonce")?,
        session_proof,
        target: ResourceServerId::parse(field(&form, "target")?)
            .map_err(|_| Refusal::MalformedField)?,
        requested_scope: requested_scope(&free_text(&form, "scope")?),
    })
}

/// Decode `mandate.credential.RedeemAuthorizationCode` from the token endpoint's form body.
///
/// # Errors
///
/// Returns [`Refusal`] for another method or media type, an oversized or non-UTF-8 body, a
/// presented client credential, a malformed or repeated parameter, an undeclared parameter, a
/// caller-presented `code_id`, a missing parameter, a `grant_type` other than
/// `authorization_code`, an absent `code_verifier` (case `pkce-missing`), a verifier outside
/// RFC 7636's form, or a value outside the lexical form its declared type admits.
pub fn redeem_authorization_code(request: &Request) -> Result<RedeemAuthorizationCode, Refusal> {
    entry(request, "POST", Reads::Body)?;
    let body = require_body(request, FORM_MEDIA_TYPE)?;
    // RFC 6749 section 2.3.1 makes `Authorization: Basic` the *preferred* presentation of a
    // client secret and the body parameter the fallback. Refusing only the fallback would leave
    // `token_endpoint_auth_methods_supported: ["none"]` enforced against one of two forms.
    no_presented_credential(request)?;
    let form = oauth::decode_form(body)?;
    if form.get("code_id").is_some() {
        return Err(Refusal::ServerResolvedField);
    }
    closed(&form, TOKEN_PARAMETERS)?;
    if field(&form, "grant_type")? != AUTHORIZATION_CODE_GRANT {
        return Err(Refusal::UnsupportedGrantType);
    }
    let verifier = oauth::require_code_verifier(&form).map_err(|_| Refusal::PkceMissing)?;
    if !verifier_has_rfc7636_shape(verifier) {
        return Err(Refusal::VerifierMalformed);
    }
    Ok(RedeemAuthorizationCode {
        code_id: None,
        client_id: OAuthClientId::parse(field(&form, "client_id")?)
            .map_err(|_| Refusal::MalformedField)?,
        code: credential(field(&form, "code")?)?,
        pkce_verifier: CredentialProof::from_bytes(verifier.as_bytes().to_vec()),
        redirect_uri: RedirectUri::new(free_text(&form, "redirect_uri")?),
    })
}

/// Decode the token endpoint's request, dispatching on its `grant_type`.
///
/// The grant is read first and each grant's own decoder decides the rest, so each grant's
/// parameter set is closed on its own: a code-grant parameter on an exchange, and an exchange
/// parameter on a code grant, are both undeclared.
///
/// # Errors
///
/// Returns [`Refusal`] for anything [`entry`] refuses, a missing media type or an oversized
/// or non-UTF-8 body, a malformed or repeated parameter, a missing `grant_type`, a
/// `grant_type` outside [`TOKEN_GRANTS`], and whatever the grant's own decoder refuses.
pub fn token_request(request: &Request) -> Result<TokenRequest, Refusal> {
    entry(request, "POST", Reads::Body)?;
    let body = require_body(request, FORM_MEDIA_TYPE)?;
    let form = oauth::decode_form(body)?;
    match field(&form, "grant_type")? {
        AUTHORIZATION_CODE_GRANT => {
            redeem_authorization_code(request).map(TokenRequest::AuthorizationCode)
        }
        TOKEN_EXCHANGE_GRANT => exchange_credential(request).map(TokenRequest::TokenExchange),
        _ => Err(Refusal::UnsupportedGrantType),
    }
}

/// Decode `mandate.credential.ExchangeCredential` from RFC 8693 section 2.1's request.
///
/// The subject token is a Mandate access credential in its declared base64 form, typed
/// [`ACCESS_TOKEN_TYPE`]. The target is named by `audience` — a registration identity, or the
/// audience name a registration holds — or by `resource` as a registration identity's
/// `urn:uuid:` URI: exactly one of the two, because a request naming two targets is not a
/// request for one credential. The audience the issued credential carries is the
/// registration's own, never this parameter's text.
///
/// # Errors
///
/// Returns [`Refusal`] for another method or media type, an oversized or non-UTF-8 body, a
/// presented client credential, a malformed, repeated or undeclared parameter, a missing
/// parameter, a `grant_type` other than [`TOKEN_EXCHANGE_GRANT`], a token type other than
/// [`ACCESS_TOKEN_TYPE`], a target named twice or in neither form, a `resource` that is not a
/// registration's `urn:uuid:` URI, an audience name that is too long or carries a control
/// character, and a value outside the lexical form its declared type admits. An actor is not
/// among them: it reaches the handler.
pub fn exchange_credential(request: &Request) -> Result<ExchangeCredential, Refusal> {
    entry(request, "POST", Reads::Body)?;
    let body = require_body(request, FORM_MEDIA_TYPE)?;
    no_presented_credential(request)?;
    let form = oauth::decode_form(body)?;
    closed(&form, EXCHANGE_PARAMETERS)?;
    if field(&form, "grant_type")? != TOKEN_EXCHANGE_GRANT {
        return Err(Refusal::UnsupportedGrantType);
    }
    if field(&form, "subject_token_type")? != ACCESS_TOKEN_TYPE {
        return Err(Refusal::UnsupportedTokenType);
    }
    if form
        .get("requested_token_type")
        .is_some_and(|requested| requested != ACCESS_TOKEN_TYPE)
    {
        return Err(Refusal::UnsupportedTokenType);
    }
    let target = match (form.get("audience"), form.get("resource")) {
        (Some(_), Some(_)) => return Err(Refusal::TargetAmbiguous),
        (None, None) => return Err(Refusal::MissingField),
        (Some(audience), None) => match ResourceServerId::parse(audience) {
            Ok(id) => ExchangeTarget::Registration(id),
            Err(_) => ExchangeTarget::Audience(Audience::new(free_text(&form, "audience")?)),
        },
        (None, Some(resource)) => ExchangeTarget::Registration(
            resource
                .strip_prefix(RESOURCE_URN_PREFIX)
                .and_then(|id| ResourceServerId::parse(id).ok())
                .ok_or(Refusal::MalformedField)?,
        ),
    };
    let actor_proof = match (form.get("actor_token"), form.get("actor_token_type")) {
        (None, None) => None,
        (token, _) => Some(CredentialProof::from_bytes(
            token.unwrap_or_default().as_bytes().to_vec(),
        )),
    };
    Ok(ExchangeCredential {
        subject_proof: credential(field(&form, "subject_token")?)?,
        actor_proof,
        target,
        requested_scope: requested_scope(&free_text(&form, "scope")?),
        delegation_id: None,
    })
}

/// Decode `mandate.credential.IntrospectCredential` from RFC 7662's request.
///
/// The caller proof is the bearer credential the introspection endpoint was reached with; the
/// presented credential is the form's `token`. The two are separate inputs in the contract and
/// separate values on the wire, and neither is read from the other.
///
/// # Errors
///
/// Returns [`Refusal`] for another method or media type, an oversized or non-UTF-8 body, a
/// malformed, repeated or undeclared parameter, an absent or malformed caller proof, or an
/// absent or malformed presented credential.
pub fn introspect_credential(request: &Request) -> Result<IntrospectCredential, Refusal> {
    entry(request, "POST", Reads::Body)?;
    let body = require_body(request, FORM_MEDIA_TYPE)?;
    let caller_proof = bearer(
        request,
        Refusal::MissingCallerProof,
        Refusal::MalformedCallerProof,
    )?;
    let form = oauth::decode_form(body)?;
    closed(&form, INTROSPECT_PARAMETERS)?;
    let credential_proof = credential(field(&form, "token")?)?;
    Ok(IntrospectCredential {
        caller_proof,
        credential_proof,
    })
}

/// Whether a `code_challenge` is in the S256 shape: [`CHALLENGE_LENGTH`] base64url characters.
///
/// Shape only. RFC 4648 section 3.5's pad bits are not checked here — three of every four
/// 43-character base64url strings encode no value, and deciding that is
/// `mandate_federation::pkce::challenge_is_well_formed`'s, which is the predicate the handler
/// runs and which this crate's dependency ceiling cannot reach.
#[must_use]
pub fn challenge_has_s256_shape(challenge: &str) -> bool {
    challenge.len() == CHALLENGE_LENGTH
        && challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Whether a `code_verifier` is in the form RFC 7636 section 4.1 declares:
/// [`VERIFIER_LENGTH`] characters of the unreserved set `[A-Za-z0-9-._~]`.
///
/// Shape only. Whether the verifier redeems the recorded challenge is decided by the digest
/// comparison in `mandate_federation::pkce::verify_pkce`.
#[must_use]
pub fn verifier_has_rfc7636_shape(verifier: &str) -> bool {
    VERIFIER_LENGTH.contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// RFC 6749 section 3.3: `scope` is a space-delimited list of case-sensitive strings.
///
/// Each token becomes a declared `mandate.core.Action`. `mandate.core.AuthorityScope` also
/// declares `resources` and an optional `space`, and RFC 6749's parameter has no wire form for
/// either, so the adapter leaves both as the request stated them — empty and absent. It does
/// not invent a resource, and a narrower authority than the caller asked for is the handler's
/// to decide, never this module's to assume.
fn requested_scope(scope: &str) -> AuthorityScope {
    AuthorityScope {
        actions: scope
            .split(' ')
            .filter(|token| !token.is_empty())
            .map(Action::new)
            .collect(),
        resources: Vec::new(),
        space: None,
    }
}

/// Which component of the request a route reads its parameters from.
///
/// Every route on this road reads exactly one, and the other is a component that route reads
/// nothing out of — see [`entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reads {
    /// The request body: the token, introspection and federation login routes.
    Body,
    /// The query component of the target: the authorization route.
    Query,
}

/// The gate every decoder runs first: the method, the ceiling on everything the request
/// carries, and the component this route reads nothing from.
///
/// One helper rather than a line in each decoder, because adversary pass 1 (F7) found the
/// ceiling applied to the body in three decoders and to the query in one — which is the shape
/// a rule written four times always ends up in. `MAX_BODY_BYTES` bounds **both** components in
/// **all four**, before anything is parsed: a decoder that reads only the query still receives
/// a body from a listener, and a decoder that reads only the body still receives a target.
///
/// # The component a route does not read is refused, not ignored
///
/// Adversary pass 2 (F3) drove the other half of the same asymmetry. The authorization
/// endpoint refused a presented body, and the three body routes *measured* a presented query
/// and then read nothing out of it — so `POST /oauth/token?organization_id=evil` decoded `Ok`,
/// which is exactly the "add it and have it ignored" that
/// `docs/architecture/adapter-contract.md` rule 1 says is refused. A query string is in every
/// access log, every referrer and every proxy trace the request passes; admitting one a
/// decoder never reads means the request a reader sees and the request the handler decides are
/// two different requests. Both refusals are therefore taken here, on one rule, for all four.
///
/// **The ceiling is measured first.** An oversized query is [`Refusal::BodyTooLarge`] on a body
/// route, not [`Refusal::QueryNotAdmitted`]: a request nobody will read is refused by its size
/// before any component of it is looked at.
///
/// # Errors
///
/// Returns [`Refusal::MethodNotAllowed`], [`Refusal::BodyTooLarge`],
/// [`Refusal::QueryNotAdmitted`] or [`Refusal::BodyNotAdmitted`].
fn entry(request: &Request, method: &str, reads: Reads) -> Result<(), Refusal> {
    if request.method != method {
        return Err(Refusal::MethodNotAllowed);
    }
    if request.body.len() > MAX_BODY_BYTES || request.query().len() > MAX_BODY_BYTES {
        return Err(Refusal::BodyTooLarge);
    }
    match reads {
        // The separator is the component: `/oauth/token?` carries an empty query and is still
        // a target that presented one.
        Reads::Body if request.path.contains('?') => Err(Refusal::QueryNotAdmitted),
        Reads::Query if !request.body.is_empty() => Err(Refusal::BodyNotAdmitted),
        _ => Ok(()),
    }
}

/// A credential field, from its declared base64 lexical form.
///
/// One helper for every credential the wire carries — the login `proof`, the token endpoint's
/// `code`, the introspection `token`, and the bearer credential of both header-bearing routes.
/// Adversary pass 1 (F3, F4) found the empty string admitted on three of them: `""` is inside
/// the declared base64 form and decodes to zero bytes, so *the credential nobody holds* reached
/// a handler as a presented credential. A zero-byte credential is not a credential, and the
/// refusal belongs where every field of the kind passes rather than at each of the five.
///
/// # Errors
///
/// Returns [`Refusal::MalformedField`] for text outside the declared base64 form, for the empty
/// string, and for any form that decodes to zero bytes.
fn credential(text: &str) -> Result<CredentialProof, Refusal> {
    if text.is_empty() {
        return Err(Refusal::MalformedField);
    }
    let proof = CredentialProof::parse_base64(text).map_err(|_| Refusal::MalformedField)?;
    if proof.expose_bytes().is_empty() {
        return Err(Refusal::MalformedField);
    }
    Ok(proof)
}

/// A required free-text parameter, bounded and free of control characters.
///
/// The four values on this road the contract leaves unconstrained — `state`, `nonce`,
/// `redirect_uri` and `scope` — are the four a listener puts back on the wire: RFC 6749
/// section 4.1.2.1 has the authorization endpoint redirect to the presented `redirect_uri`
/// carrying the presented `state`, so both land in a `Location` header, and the RFC requires
/// the state be "the exact value received from the client". *Exact* and *sanitized* cannot both
/// hold, so a value carrying CR, LF or any other control is refused here rather than mangled
/// downstream. Adversary pass 1 (F8) named `state`; the class is every unconstrained text value
/// the adapter passes through, and all four go through this helper.
///
/// # Errors
///
/// Returns [`Refusal::MissingField`], [`Refusal::TextTooLong`] over [`MAX_TEXT_BYTES`], or
/// [`Refusal::ControlCharacter`] for any character in Unicode general category `Cc` — the C0
/// controls, DEL, and the C1 block U+0080–U+009F, which is `char::is_control`'s own class.
fn free_text(form: &Form, key: &str) -> Result<String, Refusal> {
    let value = field(form, key)?;
    if value.len() > MAX_TEXT_BYTES {
        return Err(Refusal::TextTooLong);
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(Refusal::ControlCharacter);
    }
    Ok(value.to_owned())
}

/// Refuse a caller credential presented to a route whose command declares no input for one.
///
/// `AuthenticateFederation` takes a connection and a proof in its body; `RedeemAuthorizationCode`
/// takes five form parameters and this road's clients are public. Neither declares a caller
/// credential, so a presented `Authorization` header is caller-supplied authority the contract
/// has nowhere to put — refused as an undeclared field is, and answered `invalid_request`,
/// because `invalid_client` is RFC 6749's "client authentication failed" and a road that
/// authenticates no client cannot fail to.
///
/// Routed through [`Request::single_header`], so a header presented twice is refused as
/// [`Refusal::DuplicateHeader`] on every one of the four decoders and not only on the two that
/// read one (adversary pass 1, F5).
///
/// # Errors
///
/// Returns [`Refusal::DuplicateHeader`] or [`Refusal::UndeclaredField`].
fn no_presented_credential(request: &Request) -> Result<(), Refusal> {
    if request.single_header("Authorization")?.is_some() {
        return Err(Refusal::UndeclaredField);
    }
    Ok(())
}

/// The body as text, once the media type holds. The ceiling is [`entry`]'s.
fn require_body<'a>(request: &'a Request, media_type: &str) -> Result<&'a str, Refusal> {
    let presented = request
        .single_header("Content-Type")?
        .ok_or(Refusal::ContentTypeUnsupported)?;
    let presented = presented
        .split(';')
        .next()
        .unwrap_or(presented)
        .trim()
        .to_ascii_lowercase();
    if presented != media_type {
        return Err(Refusal::ContentTypeUnsupported);
    }
    std::str::from_utf8(&request.body).map_err(|_| Refusal::BodyNotUtf8)
}

/// The bearer credential the request was reached with.
fn bearer(
    request: &Request,
    missing: Refusal,
    malformed: Refusal,
) -> Result<CredentialProof, Refusal> {
    let presented = request.single_header("Authorization")?.ok_or(missing)?;
    let (scheme, material) = presented.split_once(' ').ok_or(malformed)?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return Err(malformed);
    }
    // Through the same credential helper as every other credential field, so an empty or
    // zero-byte bearer credential is refused here too.
    credential(material.trim()).map_err(|_| malformed)
}

/// Refuse any key outside the endpoint's admitted set.
fn closed(form: &Form, admitted: &[&str]) -> Result<(), Refusal> {
    for key in form.keys() {
        if !admitted.contains(&key) {
            return Err(Refusal::UndeclaredField);
        }
    }
    Ok(())
}

/// The value presented for a required parameter.
fn field<'a>(form: &'a Form, key: &str) -> Result<&'a str, Refusal> {
    form.get(key).ok_or(Refusal::MissingField)
}

/// The value presented for a required JSON member.
fn member<'a>(members: &'a [(String, String)], name: &str) -> Result<&'a str, Refusal> {
    members
        .iter()
        .find(|(declared, _)| declared == name)
        .map(|(_, value)| value.as_str())
        .ok_or(Refusal::MissingField)
}
