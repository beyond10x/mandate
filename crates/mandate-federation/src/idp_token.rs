//! The relying party's half of an external OIDC IdP's authorization-code flow: the
//! authorization request a browser is sent with, and the token endpoint the code is redeemed
//! at (`story:relying-party-code-flow`).
//!
//! # What is here, and what is not
//!
//! The ID token the token endpoint answers is **not** verified here. It is a
//! [`CredentialProof`] like any other federation proof, and it goes through the one verifier
//! every proof goes through ([`crate::verifier_real::RealVerifier`]) and then through
//! [`crate::authenticate::authenticate_federation`]. What this module adds is the part of
//! OIDC Core 3.1 a proof presented by its holder never needed: the endpoints, the code
//! redemption under client authentication, and the `nonce` comparison
//! ([`nonce_matches`]) the verifier has no expected value for.
//!
//! # The network is a port, and it reuses the hardened fetch
//!
//! [`IdpTokenEndpoint`] is the port; [`UreqIdpToken`] is the shipped implementation. It adds
//! no second hardening of its own. Discovery is read through
//! [`crate::verifier_real::UreqJwks`], the same fetcher the verifier reads it through; the
//! token request is sent over an agent built from
//! [`crate::verifier_real::UreqJwks::hardened_config`] — no redirect, no environment proxy, a
//! five-second deadline — and **every** endpoint is put through
//! [`crate::verifier_real::UreqJwks::admits`] before it is used: the issuer's own origin, or a
//! host the deployment listed for the connection, and never a scheme downgrade.
//!
//! # Client authentication
//!
//! `client_secret_basic` alone (RFC 6749 section 2.3.1), because an IdP that accepts only it
//! is the reason this module exists, and a second method is a second place a secret can be
//! put. The secret is a [`ClientSecret`], which renders as a redaction marker, is not
//! `Serialize`, and is read from a file ([`ClientSecret::read`]); it reaches the wire in the
//! `Authorization` header and nowhere else.

use core::fmt;
use std::path::Path;
use std::time::Duration;

use mandate_types::{ClientId, CredentialProof, Issuer};

use crate::verifier::VerifiedProof;
use crate::verifier_real::{JwksSource, UreqJwks};

/// The most bytes of a token response this module reads.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// A relying party's client secret, as the IdP issued it.
///
/// Never rendered: [`fmt::Debug`] writes a marker, and there is no `Display` and no
/// `Serialize`. The only reader of the bytes is [`basic_authorization`].
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSecret(Vec<u8>);

impl ClientSecret {
    /// Carry secret material.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read the secret from a file, without the one line end an editor leaves on it.
    ///
    /// # Errors
    ///
    /// The file's own error when it cannot be read, and [`std::io::ErrorKind::InvalidData`]
    /// when what is left is empty: an empty secret authenticates nobody.
    pub fn read(path: &Path) -> std::io::Result<Self> {
        let mut bytes = std::fs::read(path)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the client secret file is empty",
            ));
        }
        Ok(Self(bytes))
    }

    /// Read the carried material. Named for what it does.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ClientSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientSecret(<redacted>)")
    }
}

/// Why the IdP's endpoints could not be used, or a code was not redeemed.
///
/// Log-safe by construction: every variant is a bare name, carrying no code, no secret, no
/// token and no byte the IdP answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TokenRefusal {
    /// No discovery document could be read for the issuer.
    DiscoveryUnavailable,
    /// The discovery document names another issuer than the one it was read for.
    DiscoveryIssuerMismatch,
    /// The discovery document names no authorization or no token endpoint.
    EndpointAbsent,
    /// An endpoint is neither on the issuer's origin nor on a host the deployment listed.
    EndpointNotAdmitted,
    /// An endpoint carries a control or whitespace byte, which no URI does and which would
    /// become a header or a request line of its own where the endpoint is written.
    EndpointMalformed,
    /// The token endpoint could not be reached, or did not answer within the deadline.
    Unreachable,
    /// The token endpoint answered with anything but success: a refused client
    /// authentication, a refused grant, a PKCE mismatch.
    Refused,
    /// The token endpoint's answer is not a JSON object.
    ResponseMalformed,
    /// The token endpoint's answer carries no `id_token`.
    IdTokenAbsent,
}

impl fmt::Display for TokenRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TokenRefusal {}

/// The two endpoints of an IdP's discovery document the relying party uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpEndpoints {
    /// Where the browser is sent.
    pub authorization_endpoint: String,
    /// Where the code is redeemed.
    pub token_endpoint: String,
    /// Whether the metadata advertises `iss` in the authorization response
    /// (`authorization_response_iss_parameter_supported: true`, RFC 9207 section 3). When it
    /// does, a callback without `iss` is refused (section 2.4).
    pub issuer_in_response: bool,
}

/// The endpoints `document` publishes for `issuer`, each admitted by the fetch guard.
///
/// The document is read for the issuer it names: one naming another issuer is refused
/// rather than used, which is the check [`crate::verifier_real::RealVerifier`] makes of the
/// same document before it trusts a key set from it.
///
/// # Errors
///
/// [`TokenRefusal::DiscoveryIssuerMismatch`], [`TokenRefusal::EndpointAbsent`],
/// [`TokenRefusal::EndpointMalformed`] or [`TokenRefusal::EndpointNotAdmitted`].
pub fn endpoints(
    issuer: &Issuer,
    document: &serde_json::Value,
    allowed_hosts: &[String],
) -> Result<IdpEndpoints, TokenRefusal> {
    if document.get("issuer").and_then(serde_json::Value::as_str) != Some(issuer.as_str()) {
        return Err(TokenRefusal::DiscoveryIssuerMismatch);
    }
    let named = |name: &str| {
        document
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or(TokenRefusal::EndpointAbsent)
    };
    let found = IdpEndpoints {
        authorization_endpoint: named("authorization_endpoint")?,
        token_endpoint: named("token_endpoint")?,
        issuer_in_response: document.get("authorization_response_iss_parameter_supported")
            == Some(&serde_json::Value::Bool(true)),
    };
    for endpoint in [&found.authorization_endpoint, &found.token_endpoint] {
        // `admits` reads the origin and nothing after it, so a byte later in the string is
        // decided here: the authorization endpoint is written into a `Location` header and
        // the token endpoint into a request line, and a CR LF in either is a header of its own.
        if endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(TokenRefusal::EndpointMalformed);
        }
        if !UreqJwks::admits(issuer, endpoint, allowed_hosts) {
            return Err(TokenRefusal::EndpointNotAdmitted);
        }
    }
    Ok(found)
}

/// The URL a browser is sent to: `endpoint` with the OIDC Core 3.1.2.1 code-flow request
/// and an RFC 7636 S256 challenge.
///
/// A query the endpoint already carries is kept, and the request is appended to it.
#[must_use]
pub fn authorization_request(
    endpoint: &str,
    client_id: &ClientId,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> String {
    let separator = match endpoint.split_once('?') {
        None => '?',
        Some((_, "")) => '\0',
        Some(_) => '&',
    };
    let mut url = endpoint.to_owned();
    if separator != '\0' {
        url.push(separator);
    }
    let parameters = [
        ("response_type", "code"),
        ("client_id", client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("scope", "openid"),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    let query: Vec<String> = parameters
        .iter()
        .map(|(name, value)| format!("{name}={}", form_encode(value.as_bytes())))
        .collect();
    url.push_str(&query.join("&"));
    url
}

/// The `Authorization` header value of RFC 6749 section 2.3.1's `client_secret_basic`.
///
/// Each half is `application/x-www-form-urlencoded` before the two are joined by `:` and
/// base64-encoded, so a `:` inside the client identifier or the secret is not the separator.
#[must_use]
pub fn basic_authorization(client_id: &ClientId, secret: &ClientSecret) -> String {
    let pair = format!(
        "{}:{}",
        form_encode(client_id.as_str().as_bytes()),
        form_encode(secret.expose_bytes())
    );
    format!(
        "Basic {}",
        mandate_types::value::encode_base64(pair.as_bytes())
    )
}

/// Whether the validated `nonce` claim of an ID token is the one the authorization request
/// sent (OIDC Core 3.1.3.7 step 11).
///
/// Read from [`VerifiedProof::verified_claim`] alone: a value that arrived unvalidated is
/// not the nonce. An empty expected nonce matches nothing, and the comparison does not stop
/// at the first differing byte.
#[must_use]
pub fn nonce_matches(verified: &VerifiedProof, expected: &str) -> bool {
    let Some(carried) = verified.verified_claim("nonce") else {
        return false;
    };
    if expected.is_empty() || carried.len() != expected.len() {
        return false;
    }
    carried
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (one, other)| difference | (one ^ other))
        == 0
}

/// The unpadded base64url form (RFC 4648 section 5) a PKCE verifier, a `state` and a
/// `nonce` are rendered in.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    mandate_types::value::encode_base64(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// One redemption of an authorization code at a token endpoint.
#[derive(Debug, Clone, Copy)]
pub struct CodeRedemption<'a> {
    /// The connection's issuer, which bounds where the endpoint may be.
    pub issuer: &'a Issuer,
    /// The token endpoint, as discovery named it.
    pub token_endpoint: &'a str,
    /// The hosts the deployment listed for the connection, beside the issuer's origin.
    pub allowed_hosts: &'a [String],
    /// The client identifier the IdP issued.
    pub client_id: &'a ClientId,
    /// The client secret the IdP issued.
    pub client_secret: &'a ClientSecret,
    /// The code the IdP returned to the callback.
    pub code: &'a CredentialProof,
    /// The redirect URI the authorization request named, exactly.
    pub redirect_uri: &'a str,
    /// The PKCE verifier whose S256 challenge the authorization request sent.
    pub code_verifier: &'a CredentialProof,
}

/// An IdP's discovery document and token endpoint, behind a port.
pub trait IdpTokenEndpoint {
    /// The discovery document published for `issuer`, if one can be read.
    fn discovery(&self, issuer: &Issuer) -> Option<serde_json::Value>;

    /// Redeem one code, answering the ID token the endpoint returned.
    ///
    /// # Errors
    ///
    /// [`TokenRefusal`] when the endpoint is not admitted, cannot be reached, refuses, or
    /// answers no ID token.
    fn redeem(&self, redemption: &CodeRedemption<'_>) -> Result<CredentialProof, TokenRefusal>;
}

/// The shipped [`IdpTokenEndpoint`]: discovery through [`UreqJwks`], redemption over an
/// agent built from [`UreqJwks::hardened_config`].
pub struct UreqIdpToken {
    documents: UreqJwks,
    agent: ureq::Agent,
}

impl UreqIdpToken {
    /// A port over the hardened configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            documents: UreqJwks::new(),
            agent: ureq::Agent::new_with_config(UreqJwks::hardened_config()),
        }
    }
}

impl Default for UreqIdpToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for UreqIdpToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UreqIdpToken")
    }
}

impl IdpTokenEndpoint for UreqIdpToken {
    fn discovery(&self, issuer: &Issuer) -> Option<serde_json::Value> {
        self.documents.discovery(issuer)
    }

    fn redeem(&self, redemption: &CodeRedemption<'_>) -> Result<CredentialProof, TokenRefusal> {
        // Decided here too, not only by `endpoints`: the port may be called with an endpoint
        // nobody read out of a discovery document, and the guard is the port's.
        if redemption
            .token_endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(TokenRefusal::EndpointMalformed);
        }
        if !UreqJwks::admits(
            redemption.issuer,
            redemption.token_endpoint,
            redemption.allowed_hosts,
        ) {
            return Err(TokenRefusal::EndpointNotAdmitted);
        }
        let code = std::str::from_utf8(redemption.code.expose_bytes())
            .map_err(|_| TokenRefusal::Refused)?;
        let verifier = std::str::from_utf8(redemption.code_verifier.expose_bytes())
            .map_err(|_| TokenRefusal::Refused)?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redemption.redirect_uri),
            ("code_verifier", verifier),
        ]
        .iter()
        .map(|(name, value)| format!("{name}={}", form_encode(value.as_bytes())))
        .collect::<Vec<String>>()
        .join("&");
        let answered = self
            .agent
            .post(redemption.token_endpoint)
            .header(
                "Authorization",
                basic_authorization(redemption.client_id, redemption.client_secret),
            )
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .config()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .send(form);
        let mut response = answered.map_err(|_| TokenRefusal::Unreachable)?;
        if !response.status().is_success() {
            return Err(TokenRefusal::Refused);
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|_| TokenRefusal::ResponseMalformed)?;
        let document: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| TokenRefusal::ResponseMalformed)?;
        let token = document
            .as_object()
            .ok_or(TokenRefusal::ResponseMalformed)?
            .get("id_token")
            .and_then(serde_json::Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or(TokenRefusal::IdTokenAbsent)?;
        Ok(CredentialProof::from_bytes(token.as_bytes().to_vec()))
    }
}

/// `application/x-www-form-urlencoded` of one value: RFC 3986's unreserved set kept, every
/// other byte percent-encoded.
fn form_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
