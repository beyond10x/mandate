//! The keyed verifier of a confidential OAuth client's secret (ADR 0012, fork F2 A).
//!
//! A confidential client's document names a secret *reference*; the process resolves it to
//! the secret at start, derives a [`CredentialVerifier`] from it under a deployment key, and
//! only that verifier enters `mandate.federation.OAuthClient.secret_verifiers` and the
//! `OAuthClientRegistered` event. The secret itself is never recorded, rendered or logged.
//!
//! # The derivation
//!
//! `hmac-sha256:` followed by the lowercase hex of HMAC-SHA-256 (RFC 2104) keyed by the
//! [`VerifierKey`], over the domain tag [`CLIENT_SECRET_DOMAIN`], a `0x00` separator and the
//! secret. The tag keeps a client-secret verifier disjoint from every other verifier family
//! (`mandate_token::verifier::CredentialDomain`), and the key makes a recorded verifier
//! useless to anyone who reads the event log without the deployment's key: a slow hash buys
//! nothing for a high-entropy generated secret (fork F2 C), and the [entropy
//! floor](OAuthClientSecret::configured) is what makes the secret high-entropy.
//!
//! # The comparison
//!
//! [`client_secret_presents`] derives the presented secret's verifier and compares it with
//! *every* recorded verifier through [`constant_time_eq`], folding the results without a
//! short circuit, so neither which verifier matched nor how much of one matched changes the
//! work done. Up to two verifiers are active per client so a secret rotates without
//! downtime.
//!
//! # Rendering
//!
//! [`OAuthClientSecret`] and [`VerifierKey`] implement neither `Display`, `Serialize` nor
//! `PartialEq`, and their `Debug` renders [`crate::REDACTED`]. [`ClientSecretError`] states
//! sizes and estimates, never material.

use sha2::{Digest, Sha256};

use crate::{CredentialVerifier, REDACTED};

/// The domain tag prefixed to a client secret before it is keyed.
pub const CLIENT_SECRET_DOMAIN: &str = "mandate.federation.oauth-client-secret";

/// The prefix every verifier this module derives carries.
pub const CLIENT_SECRET_VERIFIER_PREFIX: &str = "hmac-sha256:";

/// The least estimated entropy, in bits, a configured client secret must carry.
pub const CLIENT_SECRET_ENTROPY_FLOOR_BITS: u32 = 128;

/// The least number of bytes a [`VerifierKey`] must carry: one SHA-256 output.
pub const VERIFIER_KEY_MIN_BYTES: usize = 32;

const BLOCK: usize = 64;

/// Why a client secret or a verifier key is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientSecretError {
    /// The configured secret's estimated entropy is under
    /// [`CLIENT_SECRET_ENTROPY_FLOOR_BITS`].
    BelowEntropyFloor {
        /// The estimate, in whole bits.
        estimated_bits: u32,
        /// The floor it had to reach.
        floor_bits: u32,
    },
    /// The verifier key is shorter than [`VERIFIER_KEY_MIN_BYTES`].
    KeyTooShort {
        /// The key's length, in bytes.
        length: usize,
        /// The least admitted length.
        minimum: usize,
    },
}

impl core::fmt::Display for ClientSecretError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BelowEntropyFloor {
                estimated_bits,
                floor_bits,
            } => write!(
                formatter,
                "client secret carries an estimated {estimated_bits} bits of entropy, under the \
                 floor of {floor_bits}; generate one with `openssl rand -base64 32`"
            ),
            Self::KeyTooShort { length, minimum } => write!(
                formatter,
                "verifier key is {length} bytes, under the minimum of {minimum}"
            ),
        }
    }
}

impl std::error::Error for ClientSecretError {}

/// The deployment key every client-secret verifier is derived under (the F2 "pepper").
pub struct VerifierKey(Vec<u8>);

impl VerifierKey {
    /// Admit key material.
    ///
    /// # Errors
    ///
    /// [`ClientSecretError::KeyTooShort`] under [`VERIFIER_KEY_MIN_BYTES`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ClientSecretError> {
        if bytes.len() < VERIFIER_KEY_MIN_BYTES {
            return Err(ClientSecretError::KeyTooShort {
                length: bytes.len(),
                minimum: VERIFIER_KEY_MIN_BYTES,
            });
        }
        Ok(Self(bytes))
    }
}

impl core::fmt::Debug for VerifierKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "VerifierKey({REDACTED})")
    }
}

/// A confidential client's secret, in flight: read from a secret file at start, or presented
/// at the token endpoint. Never recorded; only its [verifier](Self::verifier) is.
pub struct OAuthClientSecret(Vec<u8>);

impl OAuthClientSecret {
    /// A secret a deployment configures, admitted only above the entropy floor.
    ///
    /// The estimate is the number of the secret's *novel* positions times `log2` of the number
    /// of distinct bytes it uses. A step is a byte's difference from the byte before it,
    /// modulo 256. The first three positions are novel; a later one is novel unless the three
    /// steps ending at it already ended at an earlier position. A repeated pattern, shifted or
    /// not, so counts its first period and three positions more however often it repeats, and
    /// a run of constant step such as `abc…z` or `0123…9` counts four positions however long
    /// it is. That is a generous upper bound for random material over that alphabet, where a
    /// repeated step triple is rare, and a low one for a repeated, sequential or short value.
    /// `openssl rand -base64 32` and `openssl rand -hex 32` clear the floor; a word, a short
    /// hex string, a repeated pattern or a run does not.
    ///
    /// # Errors
    ///
    /// [`ClientSecretError::BelowEntropyFloor`] when the estimate is under
    /// [`CLIENT_SECRET_ENTROPY_FLOOR_BITS`].
    pub fn configured(bytes: Vec<u8>) -> Result<Self, ClientSecretError> {
        let estimated_bits = estimated_entropy_bits(&bytes);
        if estimated_bits < CLIENT_SECRET_ENTROPY_FLOOR_BITS {
            return Err(ClientSecretError::BelowEntropyFloor {
                estimated_bits,
                floor_bits: CLIENT_SECRET_ENTROPY_FLOOR_BITS,
            });
        }
        Ok(Self(bytes))
    }

    /// A secret a client presents. No floor: a weak presented value simply matches nothing.
    #[must_use]
    pub fn presented(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The verifier this secret derives under `key`.
    #[must_use]
    pub fn verifier(&self, key: &VerifierKey) -> CredentialVerifier {
        let mac = hmac_sha256(&key.0, &[CLIENT_SECRET_DOMAIN.as_bytes(), &[0], &self.0]);
        let mut rendered = String::with_capacity(CLIENT_SECRET_VERIFIER_PREFIX.len() + 64);
        rendered.push_str(CLIENT_SECRET_VERIFIER_PREFIX);
        for byte in mac {
            rendered.push(hex_digit(byte >> 4));
            rendered.push(hex_digit(byte & 0x0f));
        }
        CredentialVerifier::new(rendered)
    }
}

impl core::fmt::Debug for OAuthClientSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "OAuthClientSecret({REDACTED})")
    }
}

/// Whether `presented` derives any of the `recorded` verifiers under `key`.
///
/// Every recorded verifier is compared, in constant time, and the results are folded without
/// a short circuit. An empty list authenticates nothing.
#[must_use]
pub fn client_secret_presents(
    key: &VerifierKey,
    recorded: &[CredentialVerifier],
    presented: &OAuthClientSecret,
) -> bool {
    let derived = presented.verifier(key);
    let mut matched = 0u8;
    for verifier in recorded {
        matched |= u8::from(constant_time_eq(
            verifier.as_str().as_bytes(),
            derived.as_str().as_bytes(),
        ));
    }
    matched == 1
}

/// Whether two byte strings are equal, in a time that depends on their lengths alone.
///
/// Both values are read to the end of the longer one, a byte past the end reads as zero, and
/// the length difference is folded into the same accumulator rather than branched on.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = (left.len() ^ right.len()) as u64;
    let width = left.len().max(right.len());
    for index in 0..width {
        let one = left.get(index).copied().unwrap_or(0);
        let other = right.get(index).copied().unwrap_or(0);
        difference |= u64::from(one ^ other);
    }
    difference == 0
}

fn estimated_entropy_bits(bytes: &[u8]) -> u32 {
    let mut seen = [false; 256];
    for byte in bytes {
        seen[usize::from(*byte)] = true;
    }
    let distinct = seen.iter().filter(|present| **present).count();
    if distinct < 2 {
        return 0;
    }
    let mut ended = std::collections::HashSet::new();
    let novel = bytes.len().min(3)
        + bytes
            .windows(4)
            .filter(|window| {
                ended.insert([
                    window[1].wrapping_sub(window[0]),
                    window[2].wrapping_sub(window[1]),
                    window[3].wrapping_sub(window[2]),
                ])
            })
            .count();
    // `distinct` is at most 256 and a configured secret is a file's content, so the product
    // fits an f64 exactly enough for a floor comparison.
    #[allow(clippy::cast_precision_loss)]
    let bits = (novel as f64) * (distinct as f64).log2();
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let whole = bits.min(f64::from(u32::MAX)) as u32;
    whole
}

fn hex_digit(nibble: u8) -> char {
    char::from(if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + nibble - 10
    })
}

/// HMAC-SHA-256 (RFC 2104) over the concatenation of `parts`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{constant_time_eq, hmac_sha256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 4231, test cases 1, 2 and 6 (a key longer than the block).
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn constant_time_eq_decides_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abc\0", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
