// STENT TODO change docs, they are stale
//! Various accumulator variants of the DAPOL+ protocol.
//!
//! An accumulator defines how the binary tree is built. There are different
//! types of accumulators, which can all be found under this module. Each
//! accumulator has different configuration requirements, which are detailed in
//! each of the sub-modules. The currently supported accumulator types are:
//! - [Non-Deterministic Mapping Sparse Merkle Tree]
//!
//! Accumulators can be constructed via the configuration parsers:
//! - [AccumulatorConfig] is used to deserialize config from a file (the
//! specific type of accumulator is determined from the config file). After
//! parsing the config the accumulator can be constructed.
//! - [NdmSmtConfigBuilder] is used to construct the
//! config for the NDM-SMT accumulator type using a builder pattern. The config
//! can then be parsed to construct an NDM-SMT.
//!
//! [Non-Deterministic Mapping Sparse Merkle Tree]: crate::accumulators::NdmSmt

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
