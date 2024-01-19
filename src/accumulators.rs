//! Various accumulator variants of the DAPOL+ protocol.
//!
//! An accumulator defines how the binary tree is built. There are different
//! types of accumulators, which can all be found under this module.

use clap::ValueEnum;
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::fmt;

mod ndm_smt;
pub use ndm_smt::{NdmSmt, NdmSmtError, RandomXCoordGenerator};

use crate::Height;

/// Supported accumulators, with their linked data.
#[derive(Debug, Serialize, Deserialize)]
pub enum Accumulator {
    NdmSmt(ndm_smt::NdmSmt),
    // TODO add other accumulators..
}

impl Accumulator {
    /// Height of the binary tree.
    pub fn height(&self) -> &Height {
        match self {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.height(),
        }
    }

    /// Return the accumulator type.
    pub fn get_type(&self) -> AccumulatorType {
        match self {
            Self::NdmSmt(_) => AccumulatorType::NdmSmt,
        }
    }

    #[doc = include_str!("./shared_docs/root_hash.md")]
    pub fn root_hash(&self) -> &H256 {
        match self {
            Self::NdmSmt(ndm_smt) => ndm_smt.root_hash(),
        }
    }

    #[doc = include_str!("./shared_docs/root_commitment.md")]
    pub fn root_commitment(&self) -> &RistrettoPoint {
        match self {
            Self::NdmSmt(ndm_smt) => ndm_smt.root_commitment(),
        }
    }

    #[doc = include_str!("./shared_docs/root_liability.md")]
    pub fn root_liability(&self) -> u64 {
        match self {
            Self::NdmSmt(ndm_smt) => ndm_smt.root_liability(),
        }
    }

    #[doc = include_str!("./shared_docs/root_blinding_factor.md")]
    pub fn root_blinding_factor(&self) -> &Scalar {
        match self {
            Self::NdmSmt(ndm_smt) => ndm_smt.root_blinding_factor(),
        }
    }
}

/// Various supported accumulator types.
#[derive(Clone, Deserialize, Debug, ValueEnum, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AccumulatorType {
    NdmSmt,
    // TODO add other accumulators..
}

impl fmt::Display for AccumulatorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccumulatorType::NdmSmt => write!(f, "NDM-SMT")
        }
    }
}
