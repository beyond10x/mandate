//! Credential signing over a real cryptographic implementation.
//!
//! # What this module is
//!
//! `mandate-federation` declares `FederationVerifier` and `SessionIssuer` as the traits its
//! handlers call through. `mandate-token` had no matching seam, so the signing port is
//! declared here, beside its only implementation, by the ruling recorded on
//! `story:signing-and-verification` after critic round 1. The crate root is untouched;
//! `pub mod signing_real;` is all it carries.
//!
//! [`CredentialSigner`] is the port. [`RealSigner`] is the implementation over
//! `jsonwebtoken`, which `story:signing-and-verification`'s dependency decision admitted at
//! `=10.4.0` with the `aws_lc_rs` provider.
//!
//! # What the STS will call
//!
//! The STS deployment owns the allowlist half of `decision-blocker:algorithm-policy`. It
//! builds one [`AllowedAlgorithms`] from deployment configuration at startup — which is
//! where an unknown name, an empty list and `none` are refused, before any request is
//! served — loads the key the deployment supplies into [`SigningKeyMaterial`], and holds a
//! [`RealSigner`] for the lifetime of the process:
//!
//! - `sign` for every credential it issues, under the active key, with `exp` taken from the
//!   clock and the profile's TTL rather than from the caller — a caller value naming one of
//!   `iss sub aud exp nbf iat jti`, in any letter case, is refused rather than overwritten;
//! - `published_keys` for the JWK set a verifier would read: the active key and the still
//!   accepted previous keys, public parts only;
//! - `rotate` when a new key is recorded, which keeps the previous key verifying for the
//!   configured overlap and then drops it;
//! - `revoke` on the emergency path, which drops a key at once and records it so neither
//!   the `kid` nor the same public key is ever installed again while the process lives.
//!
//! The deployment's `overlap_seconds` must be at least its `ttl_seconds`; `RealSigner::new`
//! refuses a shorter pairing, because a key must stay published until every credential it
//! signed has expired.
//!
//! # What `story:credential-profiles` wires
//!
//! That story's `signing` row is superseded: it consumes this port rather than declaring
//! its own. It supplies the per-profile TTL (`CredentialProfile::max_ttl`), the standard
//! claims in [`StandardClaims`], and the profile-shaped claims that ride alongside them; it
//! maps the `kid` this module carries onto the `mandate.credential.SigningKey` it records,
//! whose `retire` transition is the rotation window here and whose `revoke` transition is
//! [`CredentialSigner::revoke`]. This module knows nothing about entities, events or
//! storage, and mints no identifiers — the revocation record here lives only as long as the
//! process does, and `story:credential-profiles` rehydrates it through
//! [`RealSigner::new_with_revocations`] after a restart.
//!
//! # What is a later story
//!
//! A JWKS publication endpoint is not here. [`CredentialSigner::published_keys`] returns
//! the set; serving it over HTTP at a discoverable URL, with its cache headers and its
//! rotation-aware caching contract, is a later story. Nothing in this module opens a
//! socket.
//!
//! # What never appears
//!
//! No private key is written down: every key is material the deployment supplies at
//! runtime, and no [`core::fmt::Debug`] implementation in this module can reach the private
//! bytes — [`SigningKeyMaterial`] and [`RealSigner`] both render by hand, naming the `kid`
//! and the algorithm and nothing else.

use core::fmt;

use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse, ThumbprintHash};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, get_current_timestamp};
use serde::Serialize;
use serde_json::Value;

use mandate_types::value::decode_base64;
use mandate_types::{Audience, Issuer, PrincipalId, SigningAlgorithm};

/// The algorithm names an authorized owner admitted, and the only ones this crate maps.
///
/// Recorded on `decision-blocker:algorithm-policy` (operator, 2026-09-18) and repeated as a
/// coordinator ruling on `story:signing-and-verification`: RS256 and ES256, deployment
/// configured, validated at startup. The table is the single place a name becomes an
/// algorithm; nothing else in this module matches on a name, so a name that is not here
/// cannot be configured, cannot become key material and cannot be signed under.
const ADMITTED: [(&str, Algorithm); 2] = [("RS256", Algorithm::RS256), ("ES256", Algorithm::ES256)];

/// The claims the signer owns outright. No caller value may carry one.
///
/// Refusing rather than overwriting is the point: a caller that names `exp` has a belief
/// about the credential's lifetime, and silently discarding it leaves that belief standing.
/// Compared case-insensitively, because a JSON object distinguishes `exp` from `EXP` while
/// a careless reader does not.
const RESERVED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// The most keys a caller's claims map may carry.
pub const MAX_CLAIM_KEYS: usize = 256;

/// The most serialized JSON a caller's claims map may occupy.
pub const MAX_CLAIM_BYTES: usize = 64 * 1024;

/// The PEM labels a deployment may supply, and the algorithm each is legal for.
///
/// `EC PRIVATE KEY` (SEC1, RFC 5915) is absent on purpose: unwrapping it would mean
/// *building* a PKCS#8 wrapper rather than walking one, which is a larger change than this
/// unit carries. A deployment holding one converts it with `openssl pkcs8 -topk8`.
const PEM_LABELS: [(&str, Option<Algorithm>); 2] = [
    ("PRIVATE KEY", None),
    ("RSA PRIVATE KEY", Some(Algorithm::RS256)),
];

/// The refusals the algorithm policy makes, each by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlgorithmPolicyError {
    /// The deployment configured no algorithm at all.
    EmptyAllowlist,
    /// The deployment named `none`, in any spelling. A token needs a signature.
    NoneRefused,
    /// The name is not one this crate admits, whatever a schema makes of it.
    UnadmittedName(String),
    /// The name is admitted by the policy but this deployment did not configure it.
    NotConfigured(String),
}

impl fmt::Display for AlgorithmPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAllowlist => formatter.write_str("no signing algorithm is configured"),
            Self::NoneRefused => formatter.write_str("the `none` algorithm is refused"),
            Self::UnadmittedName(name) => {
                write!(formatter, "signing algorithm `{name}` is not admitted")
            }
            Self::NotConfigured(name) => write!(
                formatter,
                "signing algorithm `{name}` is not configured for this deployment"
            ),
        }
    }
}

impl std::error::Error for AlgorithmPolicyError {}

/// Resolve one configured name against the admitted table.
fn resolve(name: &SigningAlgorithm) -> Result<Algorithm, AlgorithmPolicyError> {
    let text = name.as_str();
    if text.eq_ignore_ascii_case("none") {
        return Err(AlgorithmPolicyError::NoneRefused);
    }
    ADMITTED
        .iter()
        .find(|(admitted, _)| *admitted == text)
        .map(|(_, algorithm)| *algorithm)
        .ok_or_else(|| AlgorithmPolicyError::UnadmittedName(text.to_owned()))
}

/// The algorithms one deployment admits, validated the moment it is built.
///
/// Construction is the startup check `decision-blocker:algorithm-policy` asks for: an empty
/// list, `none` and any name outside the admitted table are refused here, so a running
/// signer cannot hold a policy that was never checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedAlgorithms {
    configured: Vec<Algorithm>,
}

impl AllowedAlgorithms {
    /// Validate the names a deployment configured.
    ///
    /// # Errors
    ///
    /// [`AlgorithmPolicyError::EmptyAllowlist`] when `names` is empty,
    /// [`AlgorithmPolicyError::NoneRefused`] when any entry spells `none`, and
    /// [`AlgorithmPolicyError::UnadmittedName`] for any other name outside the admitted
    /// table.
    pub fn new(names: &[SigningAlgorithm]) -> Result<Self, AlgorithmPolicyError> {
        if names.is_empty() {
            return Err(AlgorithmPolicyError::EmptyAllowlist);
        }
        let mut configured = Vec::with_capacity(names.len());
        for name in names {
            let algorithm = resolve(name)?;
            if !configured.contains(&algorithm) {
                configured.push(algorithm);
            }
        }
        Ok(Self { configured })
    }

    /// Whether this deployment configured `algorithm`.
    #[must_use]
    pub fn admits(&self, algorithm: Algorithm) -> bool {
        self.configured.contains(&algorithm)
    }

    /// Resolve a name against the policy and this deployment's configuration.
    ///
    /// # Errors
    ///
    /// The refusals [`AllowedAlgorithms::new`] makes, plus
    /// [`AlgorithmPolicyError::NotConfigured`] for an admitted name this deployment left
    /// out.
    pub fn admit(&self, name: &SigningAlgorithm) -> Result<Algorithm, AlgorithmPolicyError> {
        let algorithm = resolve(name)?;
        if self.admits(algorithm) {
            Ok(algorithm)
        } else {
            Err(AlgorithmPolicyError::NotConfigured(
                name.as_str().to_owned(),
            ))
        }
    }

    /// The algorithms configured, in the order they were configured.
    #[must_use]
    pub fn configured(&self) -> &[Algorithm] {
        &self.configured
    }
}

/// The refusals signing makes, each by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// The algorithm policy refused the name.
    Algorithm(AlgorithmPolicyError),
    /// The text supplied is not a PEM envelope around base64 key material, or carries more
    /// than one block.
    MalformedPem,
    /// The PEM label is not one this algorithm may be supplied under.
    UnsupportedPemLabel(String),
    /// The key material did not parse as a private key for the declared algorithm.
    KeyRejected(String),
    /// Every key has been revoked; there is nothing to sign under.
    NoActiveKey,
    /// The `kid` is already the active key's or still inside the rotation window.
    DuplicateKid(String),
    /// This exact public key is already held, under the `kid` named.
    DuplicateMaterial(String),
    /// No key with that `kid` is active or inside the rotation window.
    UnknownKid(String),
    /// The `kid`, or this exact public key, was revoked on the emergency path.
    RevokedKey(String),
    /// A caller claim names one of the claims the signer owns.
    ReservedClaim(String),
    /// The caller's claims map carries more than [`MAX_CLAIM_KEYS`] keys.
    TooManyClaims(usize),
    /// The caller's claims map serializes to more than [`MAX_CLAIM_BYTES`].
    ClaimsTooLarge(usize),
    /// The overlap is shorter than the TTL, so a key would stop being published while
    /// credentials it signed are still valid.
    OverlapShorterThanTtl {
        /// How far past the clock each credential's `exp` would sit.
        ttl_seconds: u64,
        /// How long a key rotated out would have stayed published.
        overlap_seconds: u64,
    },
    /// The claims or the header would not encode.
    Encode(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algorithm(error) => fmt::Display::fmt(error, formatter),
            Self::MalformedPem => formatter.write_str("the key material is not a PEM envelope"),
            Self::UnsupportedPemLabel(label) => write!(
                formatter,
                "PEM label `{label}` is not supplied for this algorithm"
            ),
            Self::KeyRejected(reason) => {
                write!(formatter, "the key material was rejected: {reason}")
            }
            Self::NoActiveKey => formatter.write_str("no active signing key"),
            Self::DuplicateKid(kid) => write!(formatter, "key `{kid}` is already held"),
            Self::DuplicateMaterial(kid) => {
                write!(formatter, "this public key is already held under `{kid}`")
            }
            Self::UnknownKid(kid) => write!(formatter, "no key `{kid}` is held"),
            Self::RevokedKey(kid) => write!(formatter, "key `{kid}` was revoked"),
            Self::ReservedClaim(name) => write!(
                formatter,
                "claim `{name}` is the signer's and may not be supplied"
            ),
            Self::TooManyClaims(keys) => write!(
                formatter,
                "the claims map carries {keys} keys, more than the {MAX_CLAIM_KEYS} allowed"
            ),
            Self::ClaimsTooLarge(bytes) => write!(
                formatter,
                "the claims map serializes to {bytes} bytes, more than the \
                 {MAX_CLAIM_BYTES} allowed"
            ),
            Self::OverlapShorterThanTtl {
                ttl_seconds,
                overlap_seconds,
            } => write!(
                formatter,
                "the rotation overlap ({overlap_seconds}s) is shorter than the credential TTL \
                 ({ttl_seconds}s)"
            ),
            Self::Encode(reason) => write!(formatter, "the credential would not encode: {reason}"),
        }
    }
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Algorithm(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgorithmPolicyError> for SigningError {
    fn from(error: AlgorithmPolicyError) -> Self {
        Self::Algorithm(error)
    }
}

/// Split one DER tag-length-value, returning its tag, contents and what follows.
///
/// Total: any input it cannot read as one definite-length TLV answers `None`.
fn der_take(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0_usize;
        for byte in input.get(2..2 + count)? {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    Some((tag, input.get(header..end)?, input.get(end..)?))
}

/// The `RSAPrivateKey` (RFC 8017) inside a PKCS#8 `PrivateKeyInfo`, when that is what this is.
///
/// `jsonwebtoken`'s `aws_lc` provider reads an RSA [`EncodingKey`] with
/// `aws_lc_rs::signature::RsaKeyPair::from_der`, which parses RFC 8017 and nothing else. A
/// deployment holding a modern `BEGIN PRIVATE KEY` file has PKCS#8, so this unwraps it;
/// a deployment holding `BEGIN RSA PRIVATE KEY` already has RFC 8017 and answers `None`,
/// which leaves its bytes alone.
fn pkcs1_inside_pkcs8(der: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = der_take(der)?;
    if tag != 0x30 {
        return None;
    }
    let (version, _, after_version) = der_take(body)?;
    if version != 0x02 {
        return None;
    }
    let (algorithm, _, after_algorithm) = der_take(after_version)?;
    if algorithm != 0x30 {
        return None;
    }
    let (key, contents, _) = der_take(after_algorithm)?;
    if key != 0x04 {
        return None;
    }
    Some(contents)
}

/// Whether `der` is exactly one definite-length SEQUENCE and nothing else.
///
/// The backends read the structure and stop, so bytes after it are neither rejected nor
/// signed with — they simply vanish. A deployment whose key file grew a stray byte, or was
/// concatenated with a second key, gets a refusal instead of a key it did not check.
fn is_one_complete_sequence(der: &[u8]) -> bool {
    matches!(der_take(der), Some((0x30, _, rest)) if rest.is_empty())
}

/// The single PEM block in `text`: its label and the DER it wraps.
///
/// More than one block is refused rather than silently reduced to the first: a file holding
/// two keys is a deployment that believes something about the second one.
fn pem_block(text: &str) -> Option<(String, Vec<u8>)> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let begin = lines.next()?;
    let label = begin
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.strip_suffix("-----"))?
        .to_owned();
    let mut body = String::new();
    let mut closed = false;
    for line in lines {
        if closed || line.starts_with("-----BEGIN ") {
            // A second block, or anything at all after the first one closed.
            return None;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            if rest.strip_suffix("-----") != Some(label.as_str()) {
                return None;
            }
            closed = true;
            continue;
        }
        body.push_str(line);
    }
    if !closed || body.is_empty() {
        return None;
    }
    Some((label, decode_base64(&body).ok()?))
}

/// One signing key: the private material the deployment supplied, and the JWK a verifier
/// would be published.
///
/// The public half is derived once, at construction, from the private material — so a key
/// that cannot be published cannot be installed, and the published set can never disagree
/// with what actually signs.
#[derive(Clone)]
pub struct SigningKeyMaterial {
    kid: String,
    name: SigningAlgorithm,
    algorithm: Algorithm,
    encoding: EncodingKey,
    published: Jwk,
}

impl SigningKeyMaterial {
    /// Load DER the deployment supplies.
    ///
    /// RSA accepts both spellings a deployment can hold: PKCS#8 `PrivateKeyInfo` and the
    /// bare RFC 8017 `RSAPrivateKey` inside it. EC accepts PKCS#8, which is the form
    /// `jsonwebtoken`'s provider parses.
    ///
    /// The DER must be exactly one complete structure: bytes after it are refused rather
    /// than ignored, in both families.
    ///
    /// # Errors
    ///
    /// [`SigningError::Algorithm`] when the name is not admitted, and
    /// [`SigningError::KeyRejected`] when the bytes are not exactly one private key for it.
    pub fn from_der(
        kid: impl Into<String>,
        algorithm: &SigningAlgorithm,
        der: &[u8],
    ) -> Result<Self, SigningError> {
        let resolved = resolve(algorithm)?;
        if !is_one_complete_sequence(der) {
            return Err(SigningError::KeyRejected(
                "the key material is not exactly one DER structure".to_owned(),
            ));
        }
        let encoding = match resolved {
            Algorithm::ES256 => EncodingKey::from_ec_der(der),
            _ => {
                let content = pkcs1_inside_pkcs8(der).unwrap_or(der);
                if !is_one_complete_sequence(content) {
                    return Err(SigningError::KeyRejected(
                        "the RSA key inside the wrapper is not exactly one DER structure"
                            .to_owned(),
                    ));
                }
                EncodingKey::from_rsa_der(content)
            }
        };
        let mut published = Jwk::from_encoding_key(&encoding, resolved)
            .map_err(|error| SigningError::KeyRejected(error.to_string()))?;
        let kid = kid.into();
        published.common.key_id = Some(kid.clone());
        published.common.public_key_use = Some(PublicKeyUse::Signature);
        Ok(Self {
            kid,
            name: algorithm.clone(),
            algorithm: resolved,
            encoding,
            published,
        })
    }

    /// Load a PEM envelope the deployment supplies, around the DER
    /// [`SigningKeyMaterial::from_der`] accepts.
    ///
    /// The label must match the family: `PRIVATE KEY` (PKCS#8) for either, `RSA PRIVATE
    /// KEY` (RFC 8017) for RS256 only. A label the module does not know — `EC PRIVATE KEY`,
    /// `CERTIFICATE`, `ENCRYPTED PRIVATE KEY` — is refused by name rather than guessed at.
    ///
    /// # Errors
    ///
    /// [`SigningError::MalformedPem`] when the text is not one PEM envelope around base64,
    /// [`SigningError::UnsupportedPemLabel`] when the label is not legal for the algorithm,
    /// and then the refusals [`SigningKeyMaterial::from_der`] makes.
    pub fn from_pem(
        kid: impl Into<String>,
        algorithm: &SigningAlgorithm,
        pem: &str,
    ) -> Result<Self, SigningError> {
        let resolved = resolve(algorithm)?;
        let (label, der) = pem_block(pem).ok_or(SigningError::MalformedPem)?;
        let legal = PEM_LABELS
            .iter()
            .any(|(known, only)| *known == label && only.is_none_or(|family| family == resolved));
        if !legal {
            return Err(SigningError::UnsupportedPemLabel(label));
        }
        Self::from_der(kid, algorithm, &der)
    }

    /// The stable `kid` this key signs under and is published as.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The configured name this key was loaded under.
    #[must_use]
    pub fn name(&self) -> &SigningAlgorithm {
        &self.name
    }

    /// The algorithm this key signs with.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The JWK a verifier would be published: public parts only.
    #[must_use]
    pub fn published(&self) -> &Jwk {
        &self.published
    }

    /// The RFC 7638 SHA-256 thumbprint of the public key: its identity as *material*,
    /// independent of the `kid` it happens to be filed under.
    ///
    /// Revocation records this alongside the `kid`, so the same compromised key cannot come
    /// back under a new name.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        self.published.thumbprint(ThumbprintHash::SHA256)
    }
}

impl fmt::Debug for SigningKeyMaterial {
    /// Names the key; never renders it. The private material is unreachable from here, so
    /// no caller can put it in a log by formatting a value this module handed them.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyMaterial")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The claims the caller supplies for every credential, whatever its profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardClaims {
    /// `iss`: the issuer the STS speaks as.
    pub issuer: Issuer,
    /// `sub`: the principal the credential speaks for.
    pub subject: PrincipalId,
    /// `aud`: the audience the credential is for.
    pub audience: Audience,
    /// `jti`: the caller's unique identifier for this credential.
    pub token_id: String,
}

/// What signing produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCredential {
    /// The compact JWS.
    pub token: String,
    /// The `kid` it was signed under, which names a key in the published set.
    pub kid: String,
}

/// Build the claims object that goes on the wire.
///
/// The caller's value is serialized to a JSON object *first*, checked, and only then are
/// the standard claims written in. Three properties follow, and none of them survives a
/// `#[serde(flatten)]` of the caller's value beside named fields:
///
/// - the object holds each key exactly once, so there is no "which one wins" for a reader
///   to disagree about — `serde_json`, `encoding/json` and `JSON.parse` take the last
///   duplicate, so a flattened caller claim would silently be the effective one;
/// - `exp`, `nbf` and `iat` come from the signer's clock and TTL, never from the caller;
/// - a caller value that is not a JSON object is refused as [`SigningError::Encode`]
///   instead of producing a token whose claims segment is not an object at all.
///
/// The map is also bounded: at most [`MAX_CLAIM_KEYS`] keys and [`MAX_CLAIM_BYTES`] of
/// serialized JSON. A credential travels in an `Authorization` header, and a caller that
/// can put unbounded data there turns the signer into an amplifier — for the proxies and
/// log pipelines downstream, not for itself. The bound is on the caller's map alone; the
/// standard claims the signer adds are not counted against it.
fn claims_object<T: Serialize>(
    claims: &T,
    standard: &StandardClaims,
    now: u64,
    ttl_seconds: u64,
) -> Result<Value, SigningError> {
    let serialized =
        serde_json::to_value(claims).map_err(|error| SigningError::Encode(error.to_string()))?;
    let mut object = match serialized {
        Value::Object(object) => object,
        other => {
            let shape = match other {
                Value::Null => "null",
                Value::Bool(_) => "a boolean",
                Value::Number(_) => "a number",
                Value::String(_) => "a string",
                Value::Array(_) => "an array",
                Value::Object(_) => unreachable!("matched above"),
            };
            return Err(SigningError::Encode(format!(
                "the claims value is {shape}, not a JSON object"
            )));
        }
    };
    if object.len() > MAX_CLAIM_KEYS {
        return Err(SigningError::TooManyClaims(object.len()));
    }
    let measured = serde_json::to_vec(&object)
        .map_err(|error| SigningError::Encode(error.to_string()))?
        .len();
    if measured > MAX_CLAIM_BYTES {
        return Err(SigningError::ClaimsTooLarge(measured));
    }
    if let Some(reserved) = object.keys().find(|name| {
        RESERVED_CLAIMS
            .iter()
            .any(|owned| owned.eq_ignore_ascii_case(name))
    }) {
        return Err(SigningError::ReservedClaim(reserved.clone()));
    }
    let mut write = |name: &str, value: Value| {
        object.insert(name.to_owned(), value);
    };
    write("iss", Value::String(standard.issuer.as_str().to_owned()));
    write("sub", Value::String(standard.subject.to_string()));
    write("aud", Value::String(standard.audience.as_str().to_owned()));
    write("exp", Value::from(now.saturating_add(ttl_seconds)));
    write("nbf", Value::from(now));
    write("iat", Value::from(now));
    write("jti", Value::String(standard.token_id.clone()));
    Ok(Value::Object(object))
}

/// The clock the signer reads. One implementation per deployment; the cases drive their own.
pub trait Clock {
    /// Seconds since the Unix epoch, the form JWT numeric dates take.
    fn now_unix(&self) -> u64;
}

/// The host wall clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        get_current_timestamp()
    }
}

/// The signing port `story:credential-profiles` consumes.
///
/// Not a trait object: signing is generic over the caller's claims type, because
/// `mandate-token` admits no JSON value type to name in its place. Consumers take
/// `impl CredentialSigner` or a type parameter.
pub trait CredentialSigner {
    /// Sign `claims` and `standard` under the active key.
    ///
    /// # Errors
    ///
    /// [`SigningError::NoActiveKey`] when every key has been revoked,
    /// [`SigningError::ReservedClaim`] when `claims` names a claim the signer owns, and
    /// [`SigningError::Encode`] when `claims` is not a JSON object or would not encode.
    fn sign<T: Serialize>(
        &self,
        claims: &T,
        standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError>;

    /// The rotation window as a verifier would publish it: the active key and the still
    /// accepted previous keys, public parts only.
    fn published_keys(&self) -> JwkSet;

    /// The emergency path: drop a key at once, before its overlap would have ended, and
    /// record it so it can never be installed again.
    ///
    /// Every holding of that key goes, not only the one named: the compromised thing is the
    /// private key, so a second holding under another `kid` would keep signing.
    ///
    /// # Errors
    ///
    /// [`SigningError::RevokedKey`] when that `kid` was already revoked, and
    /// [`SigningError::UnknownKid`] when it was never held.
    fn revoke(&mut self, kid: &str) -> Result<(), SigningError>;
}

/// A previous key, still accepted until the overlap it was rotated out under ends.
#[derive(Clone)]
struct WindowedKey {
    key: SigningKeyMaterial,
    drops_at: u64,
}

/// A key the emergency path revoked, recorded so it cannot come back.
///
/// Both halves matter. The `kid` catches the same name; the thumbprint catches the same
/// *material* re-filed under a new name, which is what an operator working through an
/// incident under pressure will actually produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedKey {
    /// The `kid` the key was held under when it was revoked.
    pub kid: String,
    /// The RFC 7638 SHA-256 thumbprint of its public key.
    pub thumbprint: String,
}

/// [`CredentialSigner`] over `jsonwebtoken`, an admitted algorithm, a clock and a TTL.
///
/// Three invariants, each established at every site that could break it rather than checked
/// where it happens to be read:
///
/// - **the active key is always one the deployment configured.** There are exactly two ways
///   a key gets in — [`RealSigner::new`] and [`RealSigner::rotate`] — and both refuse an
///   algorithm [`AllowedAlgorithms`] does not admit, which is why
///   [`CredentialSigner::sign`] carries no algorithm check of its own.
/// - **a revoked key never returns.** Both of those sites also refuse a `kid` or a public
///   key that [`CredentialSigner::revoke`] recorded, for the signer's lifetime. Carrying
///   the record across a restart belongs to `story:credential-profiles` with the
///   `mandate.credential.SigningKey` record; [`RealSigner::new_with_revocations`] is the
///   seam it rehydrates through.
/// - **a key stays published, and its `kid` reserved, through the instant every credential
///   it signed expires.** A credential signed an instant before a rotation is valid for
///   `ttl_seconds` afterwards, so an overlap shorter than the TTL would strand it:
///   [`RealSigner::new`] refuses that pairing. The window is closed at the far end too —
///   `drops_at = rotated_at + overlap + 1`, retained while `drops_at > now` — because a
///   relying party with no leeway still accepts a credential at exactly `now == exp`. At
///   that second the key is still published and its `kid` is not free, so a rotation cannot
///   hand the name to material that never signed it.
///
/// - **one public key is held under one name.** [`RealSigner::rotate`] compares thumbprints
///   as well as `kid`s, so the same key file supplied twice is refused rather than
///   published under two names; and [`CredentialSigner::revoke`] drops every holding whose
///   thumbprint matches, because the compromised thing is the key, not the name.
#[derive(Clone)]
pub struct RealSigner<C> {
    allowed: AllowedAlgorithms,
    active: Option<SigningKeyMaterial>,
    window: Vec<WindowedKey>,
    revoked: Vec<RevokedKey>,
    clock: C,
    ttl_seconds: u64,
    overlap_seconds: u64,
}

impl<C: Clock> RealSigner<C> {
    /// Build a signer over the key a deployment supplied.
    ///
    /// `ttl_seconds` is how far past the clock each credential's `exp` sits.
    /// `overlap_seconds` is how long a key rotated out stays in the published set, and must
    /// be at least `ttl_seconds`.
    ///
    /// # Errors
    ///
    /// [`SigningError::Algorithm`] when `active`'s algorithm is not one `allowed` admits,
    /// and [`SigningError::OverlapShorterThanTtl`] when the overlap would strand a
    /// credential the signer would still call valid.
    pub fn new(
        allowed: AllowedAlgorithms,
        active: SigningKeyMaterial,
        clock: C,
        ttl_seconds: u64,
        overlap_seconds: u64,
    ) -> Result<Self, SigningError> {
        Self::new_with_revocations(
            allowed,
            active,
            clock,
            ttl_seconds,
            overlap_seconds,
            Vec::new(),
        )
    }

    /// Build a signer that already knows which keys were revoked.
    ///
    /// The seam `story:credential-profiles` rehydrates through after a restart, from the
    /// `mandate.credential.SigningKey` records whose lifecycle reached `Revoked`.
    ///
    /// # Errors
    ///
    /// The refusals [`RealSigner::new`] makes, plus [`SigningError::RevokedKey`] when
    /// `active` is one of `revoked` by `kid` or by public key.
    pub fn new_with_revocations(
        allowed: AllowedAlgorithms,
        active: SigningKeyMaterial,
        clock: C,
        ttl_seconds: u64,
        overlap_seconds: u64,
        revoked: Vec<RevokedKey>,
    ) -> Result<Self, SigningError> {
        if overlap_seconds < ttl_seconds {
            return Err(SigningError::OverlapShorterThanTtl {
                ttl_seconds,
                overlap_seconds,
            });
        }
        Self::admit(&allowed, &active)?;
        Self::not_revoked(&revoked, &active)?;
        Ok(Self {
            allowed,
            active: Some(active),
            window: Vec::new(),
            revoked,
            clock,
            ttl_seconds,
            overlap_seconds,
        })
    }

    /// The one revocation check every key-install site runs.
    fn not_revoked(revoked: &[RevokedKey], key: &SigningKeyMaterial) -> Result<(), SigningError> {
        let thumbprint = key.thumbprint();
        if revoked
            .iter()
            .any(|entry| entry.kid == key.kid || entry.thumbprint == thumbprint)
        {
            return Err(SigningError::RevokedKey(key.kid.clone()));
        }
        Ok(())
    }

    /// The one algorithm check every key-install site runs.
    fn admit(
        allowed: &AllowedAlgorithms,
        key: &SigningKeyMaterial,
    ) -> Result<(), AlgorithmPolicyError> {
        if allowed.admits(key.algorithm) {
            Ok(())
        } else {
            Err(AlgorithmPolicyError::NotConfigured(
                key.name.as_str().to_owned(),
            ))
        }
    }

    /// Install `next` as the active key, keeping the previous one published for the overlap.
    ///
    /// # Errors
    ///
    /// [`SigningError::Algorithm`] when `next`'s algorithm is not admitted,
    /// [`SigningError::RevokedKey`] when its `kid` or its public key was revoked,
    /// [`SigningError::DuplicateKid`] when its `kid` is already active or still inside the
    /// window, and [`SigningError::DuplicateMaterial`] when the signer already holds that
    /// exact public key — a rotation onto the key already in use rotates nothing, and would
    /// publish one key under two names.
    pub fn rotate(&mut self, next: SigningKeyMaterial) -> Result<(), SigningError> {
        Self::admit(&self.allowed, &next)?;
        Self::not_revoked(&self.revoked, &next)?;
        let now = self.clock.now_unix();
        self.window.retain(|windowed| windowed.drops_at > now);
        let thumbprint = next.thumbprint();
        for key in self.holdings() {
            if key.kid == next.kid {
                return Err(SigningError::DuplicateKid(next.kid));
            }
            if key.thumbprint() == thumbprint {
                return Err(SigningError::DuplicateMaterial(key.kid.clone()));
            }
        }
        if let Some(previous) = self.active.take() {
            self.window.push(WindowedKey {
                key: previous,
                // Through the instant of `exp`, not up to it. A credential signed in the
                // same second as this rotation expires at `now + ttl`, and a relying party
                // with no leeway still accepts it at exactly that second — so the key that
                // signed it has to still be published then, and its `kid` still reserved.
                // `overlap >= ttl` is enforced at construction, so `+ 1` closes the gap for
                // every legal pairing.
                drops_at: now.saturating_add(self.overlap_seconds).saturating_add(1),
            });
        }
        self.active = Some(next);
        Ok(())
    }

    /// Every key the signer holds right now: the active one and the live window.
    fn holdings(&self) -> impl Iterator<Item = &SigningKeyMaterial> {
        self.active
            .iter()
            .chain(self.window.iter().map(|windowed| &windowed.key))
    }

    /// The `kid` credentials are being signed under, while there is one.
    #[must_use]
    pub fn active_kid(&self) -> Option<&str> {
        self.active.as_ref().map(SigningKeyMaterial::kid)
    }

    /// How far past the clock each credential's `exp` sits.
    #[must_use]
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// How long a key rotated out stays in the published set.
    #[must_use]
    pub fn overlap_seconds(&self) -> u64 {
        self.overlap_seconds
    }

    /// The algorithms this deployment configured.
    #[must_use]
    pub fn allowed(&self) -> &AllowedAlgorithms {
        &self.allowed
    }

    /// The keys the emergency path revoked, which no site will install again.
    #[must_use]
    pub fn revoked(&self) -> &[RevokedKey] {
        &self.revoked
    }
}

impl<C: Clock> CredentialSigner for RealSigner<C> {
    fn sign<T: Serialize>(
        &self,
        claims: &T,
        standard: &StandardClaims,
    ) -> Result<SignedCredential, SigningError> {
        let key = self.active.as_ref().ok_or(SigningError::NoActiveKey)?;
        let now = self.clock.now_unix();
        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.kid.clone());
        let envelope = claims_object(claims, standard, now, self.ttl_seconds)?;
        let token = encode(&header, &envelope, &key.encoding)
            .map_err(|error| SigningError::Encode(error.to_string()))?;
        Ok(SignedCredential {
            token,
            kid: key.kid.clone(),
        })
    }

    fn published_keys(&self) -> JwkSet {
        let now = self.clock.now_unix();
        let keys = self
            .active
            .iter()
            .map(|key| key.published.clone())
            .chain(
                self.window
                    .iter()
                    .filter(|windowed| windowed.drops_at > now)
                    .map(|windowed| windowed.key.published.clone()),
            )
            .collect();
        JwkSet { keys }
    }

    fn revoke(&mut self, kid: &str) -> Result<(), SigningError> {
        let now = self.clock.now_unix();
        self.window.retain(|windowed| windowed.drops_at > now);

        let Some(held) = self.holdings().find(|key| key.kid == kid) else {
            // Distinguish "never held" from "already revoked". A repeat of the emergency
            // path is an operator checking their work, not a mistake, and it must not add a
            // second tombstone for the same key.
            return Err(if self.revoked.iter().any(|entry| entry.kid == kid) {
                SigningError::RevokedKey(kid.to_owned())
            } else {
                SigningError::UnknownKid(kid.to_owned())
            });
        };
        let tombstone = RevokedKey {
            kid: held.kid.clone(),
            thumbprint: held.thumbprint(),
        };

        // Drop by *material*, not by name. The compromised thing is the private key, and
        // every holding of it has to go — naming one `kid` would leave the same key signing
        // under another.
        if self
            .active
            .as_ref()
            .is_some_and(|key| key.thumbprint() == tombstone.thumbprint)
        {
            self.active = None;
        }
        self.window
            .retain(|windowed| windowed.key.thumbprint() != tombstone.thumbprint);
        self.revoked.push(tombstone);
        Ok(())
    }
}

impl<C> fmt::Debug for RealSigner<C> {
    /// Names the keys; never renders them. Written by hand rather than derived so that no
    /// future field can put private material into a log by being added.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let window: Vec<(&str, u64)> = self
            .window
            .iter()
            .map(|windowed| (windowed.key.kid.as_str(), windowed.drops_at))
            .collect();
        formatter
            .debug_struct("RealSigner")
            .field("allowed", &self.allowed)
            .field("active_kid", &self.active.as_ref().map(|key| &key.kid))
            .field("window", &window)
            .field(
                "revoked",
                &self
                    .revoked
                    .iter()
                    .map(|entry| entry.kid.as_str())
                    .collect::<Vec<_>>(),
            )
            .field("ttl_seconds", &self.ttl_seconds)
            .field("overlap_seconds", &self.overlap_seconds)
            .finish_non_exhaustive()
    }
}
