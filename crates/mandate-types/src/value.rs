//! Builtin scalar carriers shared by the accepted `mandate.core` types.
//!
//! The ESS projection in `generated/schema/types` decides what each builtin looks like
//! on the wire: `Uuid` is a string with a declared `pattern`, `Bytes` is base64 with a
//! declared `pattern`, and `Timestamp` and `Duration` are strings with a declared
//! `format` and no pattern. Every declared pattern is enforced here. A `format` with no
//! pattern is a runtime obligation this milestone does not discharge, which is the same
//! position `ess generate types --target rust` takes in its own report.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A lexical form the contract declares and this crate refused.
///
/// The offending value is deliberately absent: a rejected `CredentialSecret` must not
/// reach a log through an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ParseError {
    /// Not the hyphenated lexical form declared for `Uuid`.
    Uuid,
    /// Not the padded base64 lexical form declared for `Bytes`.
    Base64,
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Uuid => "value is not the UUID lexical form declared by the contract",
            Self::Base64 => "value is not the base64 lexical form declared by the contract",
        })
    }
}

impl std::error::Error for ParseError {}

/// The `Uuid` builtin: sixteen bytes, rendered in the declared hyphenated form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; 16]);

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl Uuid {
    /// Wrap sixteen bytes that are already a UUID value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse the hyphenated lexical form declared by the contract.
    ///
    /// Upper-case input is accepted, as the declared pattern allows; the rendered form
    /// is always lower case, so serialization is canonical rather than input-shaped.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::Uuid`] when `text` is not that lexical form.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let source = text.as_bytes();
        if source.len() != 36 {
            return Err(ParseError::Uuid);
        }
        let mut bytes = [0u8; 16];
        let mut index = 0;
        let mut position = 0;
        while position < source.len() {
            if matches!(position, 8 | 13 | 18 | 23) {
                if source[position] != b'-' {
                    return Err(ParseError::Uuid);
                }
                position += 1;
                continue;
            }
            let high = hex_value(source[position]).ok_or(ParseError::Uuid)?;
            let low = hex_value(source[position + 1]).ok_or(ParseError::Uuid)?;
            bytes[index] = (high << 4) | low;
            index += 1;
            position += 2;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Uuid {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Render bytes in the padded base64 form declared for the `Bytes` builtin.
#[must_use]
pub fn encode_base64(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(chunk.get(1).copied().unwrap_or_default());
        let third = u32::from(chunk.get(2).copied().unwrap_or_default());
        let packed = (first << 16) | (second << 8) | third;
        encoded.push(char::from(BASE64_ALPHABET[((packed >> 18) & 63) as usize]));
        encoded.push(char::from(BASE64_ALPHABET[((packed >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            encoded.push(char::from(BASE64_ALPHABET[((packed >> 6) & 63) as usize]));
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(char::from(BASE64_ALPHABET[(packed & 63) as usize]));
        } else {
            encoded.push('=');
        }
    }
    encoded
}

/// Decode the padded base64 form declared for the `Bytes` builtin.
///
/// Trailing bits that the length does not account for are refused, so decoding and
/// rendering are inverse: a value has exactly one accepted wire form.
///
/// # Errors
///
/// Returns [`ParseError::Base64`] when `text` is not that lexical form.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, ParseError> {
    let source = text.as_bytes();
    if !source.len().is_multiple_of(4) {
        return Err(ParseError::Base64);
    }
    let padding = source
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count();
    if padding > 2 {
        return Err(ParseError::Base64);
    }
    let body = &source[..source.len() - padding];
    if body.contains(&b'=') {
        return Err(ParseError::Base64);
    }
    let mut decoded = Vec::with_capacity(body.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in body {
        let value = base64_value(*byte).ok_or(ParseError::Base64)?;
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if accumulator & ((1 << bits) - 1) != 0 {
        return Err(ParseError::Base64);
    }
    Ok(decoded)
}

macro_rules! lexical_builtin {
    ($name:ident, $format:literal, $summary:literal) => {
        #[doc = $summary]
        #[doc = ""]
        #[doc = concat!("The projection declares `format: ", $format, "` and no pattern.")]
        #[doc = "The lexical form is carried verbatim; validating it, and any arithmetic"]
        #[doc = "over it, are runtime obligations this milestone does not discharge."]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[doc = "Carry a lexical form."]
            #[must_use]
            pub fn new(text: impl Into<String>) -> Self {
                Self(text.into())
            }

            #[doc = "The carried lexical form."]
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl crate::PersistedValue for $name {}
    };
}

lexical_builtin!(Timestamp, "date-time", "The `Timestamp` builtin.");
lexical_builtin!(Duration, "duration", "The `Duration` builtin.");

/// Read an optional field that is present, refusing an explicit JSON `null`.
///
/// The projection declares an optional field as a `$ref` to a non-nullable type and
/// leaves it out of `required`. Absent is therefore the only declared way to say "no
/// value"; `null` is a form the contract does not declare. Paired with
/// `#[serde(default, skip_serializing_if = "Option::is_none")]`, this makes absence the
/// only accepted spelling, so decoding and re-encoding are inverse for every field.
///
/// # Errors
///
/// Returns the deserializer's error when the value present is not the declared form,
/// including when it is `null`.
pub fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
