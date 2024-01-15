use log::error;
use serde::{Deserialize, Serialize};

/// The default max liability.
///
/// We would like to accommodate as high a value as possible while still being
/// able to add $N$ of these together without overflow (where $N$ is the number).
/// A reasonable expectation is that $N < 1_000_000_000$ which gives us
/// $L_{\text{max}} = 2^{64} / 1_000_000_000$. But things are simpler and
/// computationally easier if we stick to powers of $2$, so we rather use:
/// $L_{\text{max}} = 2^{64} / 2^{30} = 2^{34}$.
pub const DEFAULT_MAX_LIABILITY: u64 = 2u64.pow(DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH as u32);

/// Default upper bound for the range proof in the inclusion proof.
///
/// This value is determined by the max liability since we want to produce
/// proofs of liabilities being within the range $[0, L_{\text{max}}]$.
pub const DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH: u8 = 34u8;
// STENT TODO make sure that we are using the max_liability value to determine range proof bounds, as opposed to this default range proof upper bound bit length value

/// Abstraction for the max liabilty value.
///
#[doc = include_str!("./shared_docs/max_liability.md")]
///
/// Example:
/// ```
/// use dapol::MaxLiability;
/// use std::str::FromStr;
///
/// let max_liability = MaxLiability::default();
/// let max_liability = MaxLiability::from(1000u64);
/// let max_liability = MaxLiability::from_str("1000").unwrap();
/// ```
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
pub struct MaxLiability(u64);

impl MaxLiability {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

// -------------------------------------------------------------------------------------------------
// From for u64

impl From<u64> for MaxLiability {
    fn from(max_liability: u64) -> Self {
        Self(max_liability)
    }
}

// -------------------------------------------------------------------------------------------------
// Default.

impl Default for MaxLiability {
    fn default() -> Self {
        Self(DEFAULT_MAX_LIABILITY)
    }
}

// -------------------------------------------------------------------------------------------------
// From for str.

use std::str::FromStr;

impl FromStr for MaxLiability {
    type Err = MaxLiabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(MaxLiability(u64::from_str(s)?))
    }
}

// -------------------------------------------------------------------------------------------------
// Into for OsStr.

use clap::builder::{OsStr, Str};

impl From<MaxLiability> for OsStr {
    fn from(max_liability: MaxLiability) -> OsStr {
        OsStr::from(Str::from(max_liability.as_u64().to_string()))
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

#[derive(thiserror::Error, Debug)]
pub enum MaxLiabilityError {
    #[error("Malformed string input for u64 type")]
    MalformedString(#[from] std::num::ParseIntError),
}
