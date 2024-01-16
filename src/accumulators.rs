//! Various accumulator variants of the DAPOL+ protocol.
//!
//! An accumulator defines how the binary tree is built. There are different
//! types of accumulators, which can all be found under this module.

use clap::ValueEnum;
use primitive_types::H256;
use serde::{Deserialize, Serialize};

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

    /// Return the hash digest/bytes of the root node for the binary tree.
    pub fn root_hash(&self) -> H256 {
        match self {
            Self::NdmSmt(ndm_smt) => ndm_smt.root_hash(),
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
