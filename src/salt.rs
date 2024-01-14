use logging_timer::time;
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};
use serde::Serialize;
use serde_with::DeserializeFromStr;
use std::convert::From;

/// The max size of the salt is 256 bits, but this is a soft limit so it
/// can be increased if necessary. Note that the underlying array length will
/// also have to be increased.
pub const MAX_LENGTH_BYTES: usize = 32;

const STRING_CONVERSION_ERR_MSG: &str = "A failure should not be possible here because the length of the random string exactly matches the max allowed length";

// -------------------------------------------------------------------------------------------------
// Main struct & implementations.

/// Salt data type: a 256-bit data packet.
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
#[derive(Debug, Clone, PartialEq, Serialize, DeserializeFromStr)]
pub struct Salt([u8; 32]);

impl Salt {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Use a cryptographic PRNG to produce a random salt value.
    #[time("debug", "NdmSmt::NdmSmtSalts::{}")]
    pub fn generate_random() -> Self {
        let mut rng = thread_rng();
        let random_str = Alphanumeric.sample_string(&mut rng, MAX_LENGTH_BYTES);
        Salt::from_str(&random_str).expect(STRING_CONVERSION_ERR_MSG)
    }
}

// -------------------------------------------------------------------------------------------------
// From for KDF key.

use crate::kdf;

impl From<kdf::Key> for Salt {
    fn from(key: kdf::Key) -> Self {
        let bytes: [u8; 32] = key.into();
        Salt(bytes)
    }
}

// -------------------------------------------------------------------------------------------------
// From for str.

use std::str::FromStr;

impl FromStr for Salt {
    type Err = SaltParserError;

    /// Constructor that takes in a string slice.
    /// If the length of the str is greater than the max then [Err] is returned.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_LENGTH_BYTES {
            Err(SaltParserError::StringTooLongError)
        } else {
            let mut arr = [0u8; 32];
            // this works because string slices are stored fundamentally as u8 arrays
            // STENT TODO so if I give it "0x4563412" then are the underlying bytes what I expect?
            //   we are probably going to have to support bytes & strings :/
            arr[..s.len()].copy_from_slice(s.as_bytes());
            Ok(Salt(arr))
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Into for raw bytes.

impl From<Salt> for [u8; 32] {
    fn from(item: Salt) -> Self {
        item.0
    }
}

// -------------------------------------------------------------------------------------------------
// From for u64.

impl From<u64> for Salt {
    /// Constructor that takes in a u64.
    fn from(num: u64) -> Self {
        let bytes = num.to_le_bytes();
        let mut arr = [0u8; 32];
        arr[..8].copy_from_slice(&bytes[..8]);
        Salt(arr)
    }
}

// -------------------------------------------------------------------------------------------------
// From for OsStr (for the CLI).

use clap::builder::OsStr;

impl From<Salt> for OsStr {
    // https://stackoverflow.com/questions/19076719/how-do-i-convert-a-vector-of-bytes-u8-to-a-string
    fn from(salt: Salt) -> OsStr {
        OsStr::from(String::from_utf8_lossy(&salt.0).into_owned())
    }
}

// -------------------------------------------------------------------------------------------------
// Default.

impl Default for Salt {
    fn default() -> Self {
        Salt::generate_random()
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when parsing [Salt].
#[derive(Debug, thiserror::Error)]
pub enum SaltParserError {
    #[error("The given string has more than the max allowed bytes of {MAX_LENGTH_BYTES}")]
    StringTooLongError,
}

// STENT TODO tests
