use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::convert::From;
use std::fmt;

/// The max size of the secret is 256 bits, but this is a soft limit so it
/// can be increased if necessary. Note that the underlying array length will
/// also have to be increased.
pub const MAX_LENGTH_BYTES: usize = 32;

// -------------------------------------------------------------------------------------------------
// Main struct & implementations.

/// Secret data type: a 256-bit data packet.
///
/// It is a wrapper around a byte array that is used to hold secret
/// data such as a nonce or the blinding factor for a Pedersen commitment.
///
/// The main purpose for this struct is to abstract away the [u8; 32] storage
/// array and offer functions for moving data as opposed to copying.
///
/// Currently there is no need for the functionality provided by something like
/// [primitive_types][U256] or [num256][Uint256] but those are options for
/// later need be.
#[derive(Debug, Clone, PartialEq, SerializeDisplay, DeserializeFromStr)]
pub struct Secret([u8; 32]);

impl Secret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// -------------------------------------------------------------------------------------------------
// Display (used for serialization).

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0);
        write!(f, "{}", s)
    }
}

// -------------------------------------------------------------------------------------------------
// From for KDF key.

use crate::kdf;

impl From<kdf::Key> for Secret {
    fn from(key: kdf::Key) -> Self {
        let bytes: [u8; 32] = key.into();
        Secret(bytes)
    }
}

// -------------------------------------------------------------------------------------------------
// From for u64.

impl From<u64> for Secret {
    /// Constructor that takes in a u64.
    fn from(num: u64) -> Self {
        let bytes = num.to_le_bytes();
        let mut arr = [0u8; 32];
        arr[..8].copy_from_slice(&bytes[..8]);
        Secret(arr)
    }
}

// -------------------------------------------------------------------------------------------------
// From for str.

use std::str::FromStr;

impl FromStr for Secret {
    type Err = SecretParserError;

    /// Constructor that takes in a string slice.
    /// If the length of the str is greater than the max then [Err] is returned.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_LENGTH_BYTES {
            Err(SecretParserError::StringTooLongError)
        } else {
            let mut arr = [0u8; 32];
            // this works because string slices are stored fundamentally as u8 arrays
            arr[..s.len()].copy_from_slice(s.as_bytes());
            Ok(Secret(arr))
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Into for raw bytes.

impl From<Secret> for [u8; 32] {
    fn from(item: Secret) -> Self {
        item.0
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when parsing [Secret].
#[derive(Debug, thiserror::Error)]
pub enum SecretParserError {
    #[error("The given string has more than the max allowed bytes of {MAX_LENGTH_BYTES}")]
    StringTooLongError,
}
