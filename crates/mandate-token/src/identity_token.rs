//! The OpenID Connect ID token: its claim set, its subject (fork F1) and its algorithm
//! (fork F8).
//!
//! # What this module is
//!
//! The renderer half of ID-token issuance. [`IdentityTokenClaims::render`] turns what a
//! redemption knows — the issuer, the rendered subject, the client, the login's time and
//! nonce, the access token issued beside it and the profile the login recorded — into the
//! claim set of OpenID Connect Core 3.1.3.6 (`iss`, `sub`, `aud`, `jti`, `auth_time`,
//! `nonce`, `at_hash`, and the `email`, `email_verified`, `name` and `groups` the granted
//! scopes admit). [`crate::signing_real::RealSigner::sign_identity_token`] signs it and owns
//! `iat` and `exp`, exactly as it owns them for every other credential.
//!
//! # The subject (fork F1)
//!
//! A connection's `subject_format` decides `sub`. `MandatePrincipal` renders the principal
//! id. `DexCompatible` renders the subject the replaced Dex connector issued for the same
//! upstream subject, byte for byte: `base64url(protobuf{user_id: 1, conn_id: 2})`, unpadded,
//! so an application keyed on `sub` keeps its accounts across the move.
//!
//! # The algorithm (fork F8)
//!
//! RS256 unless the client registered `id_token_signed_response_alg: ES256`. Discovery lists
//! exactly the algorithms `mandate.core.IdTokenSigningAlgorithm` declares, RS256 first
//! (OpenID Connect Core 15.1 makes it mandatory to implement).
//!
//! # What never appears
//!
//! A claim with no value is not rendered at all, never as `null`: a relying party that reads
//! `email: null` as "the person has no email" is reading something nobody said.

use aws_lc_rs::digest::{SHA256, digest};
use jsonwebtoken::Algorithm;
use serde::Serialize;

use mandate_types::value::encode_base64;
use mandate_types::{
    DexConnectorId, ExternalSubject, IdTokenSigningAlgorithm, Issuer, OAuthClientId, PrincipalId,
    SubjectFormat,
};

use crate::signing_real::{AlgorithmPolicyError, Clock, RealSigner, SigningError};

/// Dex's ID-token lifetime, `PT24H`: the default a Dex-configured application already sees.
pub const DEFAULT_ID_TOKEN_LIFETIME_SECONDS: u64 = 86_400;

/// The algorithm a client's ID tokens are signed with: its registered choice, or RS256.
#[must_use]
pub fn algorithm_for_client(choice: Option<IdTokenSigningAlgorithm>) -> IdTokenSigningAlgorithm {
    choice.unwrap_or(IdTokenSigningAlgorithm::RS256)
}

/// The JOSE `alg` name of `algorithm`, the form a header and a discovery document write.
#[must_use]
pub fn algorithm_name(algorithm: IdTokenSigningAlgorithm) -> &'static str {
    match algorithm {
        IdTokenSigningAlgorithm::RS256 => "RS256",
        IdTokenSigningAlgorithm::ES256 => "ES256",
    }
}

/// The `jsonwebtoken` algorithm `algorithm` signs and verifies under.
#[must_use]
pub fn jose_algorithm(algorithm: IdTokenSigningAlgorithm) -> Algorithm {
    match algorithm {
        IdTokenSigningAlgorithm::RS256 => Algorithm::RS256,
        IdTokenSigningAlgorithm::ES256 => Algorithm::ES256,
    }
}

/// A discovery document's `id_token_signing_alg_values_supported`: every declared
/// algorithm, in declaration order, so RS256 comes first and a variant the contract adds
/// cannot go unadvertised.
#[must_use]
pub fn supported_algorithm_names() -> Vec<&'static str> {
    IdTokenSigningAlgorithm::VARIANTS
        .iter()
        .copied()
        .map(algorithm_name)
        .collect()
}

/// Why no subject renders for a connection.
///
/// `RegisterFederationConnection` refuses both shapes, so a record carrying one broke its
/// own registration; the renderer refuses rather than inventing a subject from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectError {
    /// `DexCompatible` without the Dex connector id it replaces.
    ReplacedConnectorMissing,
    /// `MandatePrincipal` naming a replaced Dex connector.
    ReplacedConnectorUnexpected,
}

impl core::fmt::Display for SubjectError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ReplacedConnectorMissing => {
                formatter.write_str("a DexCompatible connection names no replaced connector id")
            }
            Self::ReplacedConnectorUnexpected => {
                formatter.write_str("a MandatePrincipal connection names a replaced connector id")
            }
        }
    }
}

impl std::error::Error for SubjectError {}

/// Unpadded base64url (RFC 4648 section 5), the encoding JOSE and Dex both use.
fn base64url(bytes: &[u8]) -> String {
    encode_base64(bytes)
        .trim_end_matches('=')
        .chars()
        .map(|character| match character {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect()
}

/// Append `value` as a protobuf base-128 varint.
fn push_varint(wire: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        wire.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    wire.push(value as u8);
}

/// Append a length-delimited protobuf field (wire type 2), omitted when empty as proto3
/// omits a field holding its default value.
fn push_text_field(wire: &mut Vec<u8>, field: u8, text: &str) {
    if text.is_empty() {
        return;
    }
    wire.push((field << 3) | 2);
    push_varint(wire, text.len());
    wire.extend_from_slice(text.as_bytes());
}

/// The subject Dex issues for `user_id` through connector `connector_id`:
/// `base64url(protobuf{user_id: 1, conn_id: 2})`, unpadded, byte for byte.
#[must_use]
pub fn dex_compatible_subject(user_id: &str, connector_id: &str) -> String {
    let mut wire = Vec::with_capacity(user_id.len() + connector_id.len() + 8);
    push_text_field(&mut wire, 1, user_id);
    push_text_field(&mut wire, 2, connector_id);
    base64url(&wire)
}

/// The `sub` a connection's ID tokens carry (fork F1).
///
/// # Errors
///
/// [`SubjectError::ReplacedConnectorMissing`] for a `DexCompatible` connection without a
/// replaced connector id, and [`SubjectError::ReplacedConnectorUnexpected`] for a
/// `MandatePrincipal` connection with one.
pub fn render_subject(
    format: SubjectFormat,
    replaced_connector_id: Option<&DexConnectorId>,
    principal: &PrincipalId,
    upstream: &ExternalSubject,
) -> Result<String, SubjectError> {
    match (format, replaced_connector_id) {
        (SubjectFormat::MandatePrincipal, None) => Ok(principal.to_string()),
        (SubjectFormat::MandatePrincipal, Some(_)) => {
            Err(SubjectError::ReplacedConnectorUnexpected)
        }
        (SubjectFormat::DexCompatible, Some(connector)) => Ok(dex_compatible_subject(
            upstream.as_str(),
            connector.as_str(),
        )),
        (SubjectFormat::DexCompatible, None) => Err(SubjectError::ReplacedConnectorMissing),
    }
}

/// `at_hash` (OpenID Connect Core 3.1.3.6): the left-most half of the hash of the ASCII
/// access token, under the hash `algorithm` signs with, base64url.
#[must_use]
pub fn at_hash(access_token: &str, algorithm: IdTokenSigningAlgorithm) -> String {
    // Both declared algorithms hash with SHA-256; the match keeps a variant added to the
    // contract from inheriting it unexamined.
    let full = match algorithm {
        IdTokenSigningAlgorithm::RS256 | IdTokenSigningAlgorithm::ES256 => {
            digest(&SHA256, access_token.as_bytes())
        }
    };
    let bytes = full.as_ref();
    base64url(&bytes[..bytes.len() / 2])
}

/// The profile a login recorded for the person (fork F13), read at issuance and on refresh.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedProfile {
    /// `email`.
    pub email: Option<String>,
    /// `email_verified`, meaningful only beside an `email`.
    pub email_verified: bool,
    /// `name`.
    pub name: Option<String>,
    /// `groups`, already filtered by the connection's allowlist (fork F10).
    pub groups: Vec<String>,
}

/// The profile scopes the authorization granted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProfileScopes {
    /// `email`: admits `email` and `email_verified`.
    pub email: bool,
    /// `profile`: admits `name`.
    pub profile: bool,
    /// `groups`: admits `groups`.
    pub groups: bool,
}

/// What an ID token is rendered from.
#[derive(Clone, Debug)]
pub struct IdentityTokenRequest<'a> {
    /// `iss`.
    pub issuer: &'a Issuer,
    /// `sub`, already rendered by [`render_subject`].
    pub subject: String,
    /// `aud`: the client the token is for.
    pub audience: &'a OAuthClientId,
    /// `jti`.
    pub token_id: String,
    /// `auth_time`: when the person authenticated, in seconds since the epoch.
    pub auth_time: u64,
    /// `nonce`, echoed from the authorization request when it carried one.
    pub nonce: Option<String>,
    /// The access token issued beside this ID token, which `at_hash` is computed over.
    pub access_token: Option<&'a str>,
    /// The granted scopes.
    pub scopes: ProfileScopes,
    /// The recorded profile.
    pub profile: &'a RecordedProfile,
}

/// The rendered claims of one ID token, without `iat` and `exp`, which the signer owns.
///
/// The algorithm the claims were rendered for is carried but never serialized: `at_hash`
/// depends on it, so a signer whose key is another algorithm refuses them
/// ([`RealSigner::sign_identity_token`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    jti: String,
    auth_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
    #[serde(skip)]
    algorithm: IdTokenSigningAlgorithm,
}

impl IdentityTokenClaims {
    /// Render the claim set of `request` for a token signed under `algorithm`.
    ///
    /// A profile claim is rendered only when its scope was granted and the profile holds a
    /// value: `email_verified` rides with `email`, and an empty `groups` list is absent.
    #[must_use]
    pub fn render(request: &IdentityTokenRequest<'_>, algorithm: IdTokenSigningAlgorithm) -> Self {
        let profile = request.profile;
        let email = if request.scopes.email {
            profile.email.clone()
        } else {
            None
        };
        let email_verified = email.as_ref().map(|_| profile.email_verified);
        let name = if request.scopes.profile {
            profile.name.clone()
        } else {
            None
        };
        let groups = if request.scopes.groups && !profile.groups.is_empty() {
            Some(profile.groups.clone())
        } else {
            None
        };
        Self {
            iss: request.issuer.as_str().to_owned(),
            sub: request.subject.clone(),
            aud: request.audience.to_string(),
            jti: request.token_id.clone(),
            auth_time: request.auth_time,
            nonce: request.nonce.clone(),
            at_hash: request
                .access_token
                .map(|access_token| at_hash(access_token, algorithm)),
            email,
            email_verified,
            name,
            groups,
            algorithm,
        }
    }

    /// The algorithm these claims were rendered for.
    #[must_use]
    pub fn algorithm(&self) -> IdTokenSigningAlgorithm {
        self.algorithm
    }
}

/// The signer whose active key signs `algorithm`, among the deployment's ID-token signers.
///
/// # Errors
///
/// [`SigningError::Algorithm`] with [`AlgorithmPolicyError::NotConfigured`], naming the
/// algorithm, when no signer's active key is of that algorithm — a client registered a
/// choice this deployment holds no key for.
pub fn signer_for<'a, C: Clock>(
    signers: &[&'a RealSigner<C>],
    algorithm: IdTokenSigningAlgorithm,
) -> Result<&'a RealSigner<C>, SigningError> {
    let wanted = jose_algorithm(algorithm);
    signers
        .iter()
        .copied()
        .find(|signer| signer.active_algorithm() == Some(wanted))
        .ok_or_else(|| {
            SigningError::Algorithm(AlgorithmPolicyError::NotConfigured(
                algorithm_name(algorithm).to_owned(),
            ))
        })
}
