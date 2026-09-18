//! PKCE: the S256 digest port, the declared forms, and the challenge/verifier predicate.
//!
//! # Why the digest is a port
//!
//! `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` (RFC 7636 section 4.2) needs SHA-256, and
//! `dependency-boundaries.json:36-41` admits no crate into `mandate-federation` that
//! computes one. The digest therefore sits behind [`PkceDigest`], with the `pub` double
//! [`StandInDigest`] for the same reason [`crate::verifier::ConstructedVerifier`] is
//! `pub`: every file under `tests/` compiles as its own crate. The implementation over
//! `sha2` lives where `sha2` is admitted.
//!
//! # `plain` is unrepresentable
//!
//! `mandate.core.PkceMethod` declares exactly one variant
//! (`crates/mandate-types/src/enumeration.rs:10`), so the `plain` method of RFC 7636 has
//! no Rust value: it cannot be constructed, passed or folded. [`verify_pkce`] matches the
//! method exhaustively and without a wildcard, so a second declared method would fail to
//! compile here rather than fall through to the S256 branch.
//!
//! # Which type the presented verifier is
//!
//! `mandate.credential.RedeemAuthorizationCode` declares `pkce_verifier` as
//! `mandate.core.CredentialProof` (`credential.yaml:205-206`), the transient boundary
//! type: a presented code verifier is credential material, so it is carried in a type
//! that cannot be a field of a persisted record and renders redacted. It is *not*
//! `mandate.core.CredentialVerifier`, which that domain's `AuthorizationCode` uses for the
//! non-reversible verifier of the code itself (`credential.yaml:118`, `:393`) and which is
//! a `PersistedValue`.
//!
//! # Nothing here consumes anything
//!
//! The predicate reads a recorded challenge and a presented verifier and answers. It
//! holds no store, takes no `&mut`, and neither consumes a code nor creates a credential;
//! `story:oauth-integration` owns the transaction that does.

use mandate_types::{CredentialProof, DenialReason, PkceChallenge, PkceMethod};

use crate::{DenialClause, Denied};

/// The length of an S256 digest, in bytes.
pub const DIGEST_LENGTH: usize = 32;

/// The length of an S256 challenge: a [`DIGEST_LENGTH`]-byte digest in unpadded
/// base64url.
pub const CHALLENGE_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is at least 43 characters.
pub const VERIFIER_MINIMUM_LENGTH: usize = 43;

/// RFC 7636 section 4.1: a code verifier is at most 128 characters.
pub const VERIFIER_MAXIMUM_LENGTH: usize = 128;

/// The S256 digest, behind a port.
///
/// An implementation answers `BASE64URL-ENCODE(SHA256(ASCII(verifier)))` for the verifier
/// it is given and nothing else. It records nothing: a verifier is credential material
/// and `AGENTS.md` admits none of it into a log, an audit record or a persisted record.
pub trait PkceDigest {
    /// The S256 challenge of this verifier.
    fn challenge(&self, verifier: &CredentialProof) -> PkceChallenge;
}

/// Whether a challenge is in the declared S256 form.
///
/// The decode is what decides: the value must be the unpadded base64url encoding of
/// exactly [`DIGEST_LENGTH`] bytes. Length and alphabet alone are not the form — RFC 4648
/// section 3.5 requires the pad bits of the final quantum to be zero, and a 43-character
/// base64url string whose last character carries either pad bit is the encoding of no
/// value at all (three of every four are), so it is the S256 challenge of no verifier that
/// exists. Admitting one would carry it past the "S256 challenge is absent/invalid"
/// refusal and into a digest comparison it can never win.
///
/// [`CHALLENGE_LENGTH`] is checked alongside, so the declared rendered length is enforced
/// rather than implied by the decode: the two agree by construction — 32 bytes encode to
/// 43 characters — and a constant that nothing reads is a constant that can drift.
#[must_use]
pub fn challenge_is_well_formed(challenge: &PkceChallenge) -> bool {
    let text = challenge.as_str();
    text.len() == CHALLENGE_LENGTH
        && decode_base64url(text).is_some_and(|digest| digest.len() == DIGEST_LENGTH)
}

/// Whether a verifier is in the form RFC 7636 section 4.1 declares.
///
/// Between [`VERIFIER_MINIMUM_LENGTH`] and [`VERIFIER_MAXIMUM_LENGTH`] characters of the
/// unreserved set `[A-Za-z0-9-._~]`.
#[must_use]
pub fn verifier_is_well_formed(verifier: &CredentialProof) -> bool {
    let material = verifier.expose_bytes();
    (VERIFIER_MINIMUM_LENGTH..=VERIFIER_MAXIMUM_LENGTH).contains(&material.len())
        && material.iter().copied().all(is_unreserved)
}

/// The challenge/verifier predicate: does this presented verifier redeem this recorded
/// challenge?
///
/// The recorded challenge and method are read from the code record
/// (`mandate.credential.AuthorizationCode`, `credential.yaml:109-127`), which is an input
/// here and never a store. Nothing is consumed and nothing is issued.
///
/// # Errors
///
/// Returns [`Denied`] when the recorded challenge is not in the declared S256 form, when
/// no verifier is presented, when the presented verifier is not in the declared form, and
/// when its digest is not the recorded challenge.
pub fn verify_pkce(
    challenge: &PkceChallenge,
    method: PkceMethod,
    presented: Option<&CredentialProof>,
    digest: &impl PkceDigest,
) -> Result<(), Denied> {
    match method {
        // Exhaustive and without a wildcard: see the module documentation.
        PkceMethod::S256 => {}
    }
    if !challenge_is_well_formed(challenge) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::ChallengeMalformed,
        ));
    }
    let Some(presented) = presented else {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMissing,
        ));
    };
    // The form is decided before the digest: a value outside it is not a code verifier,
    // and a short one that happened to collide would otherwise be admitted.
    if !verifier_is_well_formed(presented) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMalformed,
        ));
    }
    if !equal_in_constant_time(digest.challenge(presented).as_str(), challenge.as_str()) {
        return Err(Denied::new(
            DenialReason::InvalidCredential,
            DenialClause::VerifierMismatch,
        ));
    }
    Ok(())
}

/// The value a base64url character carries, or `None` when it carries none.
fn alphabet_index(byte: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|entry| *entry == byte)
        .and_then(|index| u8::try_from(index).ok())
}

/// Decode unpadded base64url, answering `None` for text that is the encoding of no value.
///
/// RFC 4648 section 5 for the alphabet and section 3.5 for the pad bits: a leftover of six
/// bits or more is not a quantum at all, and any leftover bit that is set is a value the
/// encoder could not have produced.
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    let mut decoded = Vec::with_capacity(text.len() / 4 * 3);
    for byte in text.bytes() {
        accumulator = (accumulator << 6) | u32::from(alphabet_index(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    if bits >= 6 || accumulator & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(decoded)
}

/// Encode bytes as unpadded base64url (RFC 4648 section 5).
fn encode_base64url(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for index in 0..=chunk.len() {
            let shift = 18 - 6 * index;
            text.push(char::from(ALPHABET[((accumulator >> shift) & 63) as usize]));
        }
    }
    text
}

/// Whether a byte is in RFC 3986's unreserved set.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Equality that does not stop at the first differing byte.
///
/// The challenge is public — the client sent it — so this leaks nothing a caller does not
/// already hold; it is written this way so that no later reader has to decide whether the
/// comparison is on a secret. `authorize.rs` compares the state and the applicable nonce
/// through it for the same reason: both are values a caller presents back, and a
/// comparison that returns early on the first differing byte is a comparison somebody has
/// to think about.
pub(crate) fn equal_in_constant_time(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

/// The base64url alphabet, in order.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A [`PkceDigest`] that stands in for one, deterministically.
///
/// A fixture, never a shipped implementation. It is **not** SHA-256 and is neither
/// preimage- nor collision-resistant: it derives [`DIGEST_LENGTH`] bytes from the verifier
/// by a mixing function and encodes them exactly as a real digest is encoded, so what it
/// answers has the shape of an S256 challenge — the unpadded base64url encoding of a
/// 32-byte value — and the predicate can be exercised in a crate that cannot link `sha2`.
/// A deployment attaches a real implementation at [`PkceDigest`]; nothing in this crate
/// selects this one.
///
/// Hidden from the rendered documentation because it is a test double: `story:testkit-doubles`
/// moves it, with this crate's other doubles, into `crates/mandate-testkit`. It stays `pub`
/// until then because every file under `tests/` compiles as its own crate.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StandInDigest;

impl PkceDigest for StandInDigest {
    fn challenge(&self, verifier: &CredentialProof) -> PkceChallenge {
        let mut state = fnv1a(verifier.expose_bytes()) | 1;
        let mut derived = [0_u8; DIGEST_LENGTH];
        for byte in &mut derived {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = u8::try_from(state & 0xff).unwrap_or_default();
        }
        PkceChallenge::new(encode_base64url(&derived))
    }
}

/// FNV-1a over the verifier's bytes. A mixing function, not a digest.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
