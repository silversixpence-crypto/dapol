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

mod config;
pub use config::{AccumulatorConfig, AccumulatorConfigError, AccumulatorParserError};

mod ndm_smt;
pub use ndm_smt::{
    NdmSmt, NdmSmtConfig, NdmSmtConfigBuilder, NdmSmtConfigParserError, NdmSmtError, NdmSmtSecrets,
    NdmSmtSecretsParser, RandomXCoordGenerator,
};

use serde::{Deserialize, Serialize};

use crate::Height;

/// Supported accumulators, with their linked data.
#[derive(Serialize, Deserialize)]
pub enum Accumulator {
    NdmSmt(ndm_smt::NdmSmt),
    // TODO add other accumulators..
}

impl Accumulator {
    pub fn height(&self) -> &Height {
        match self {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.height()
        }
    }
}

/// Various supported accumulator types.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum AccumulatorType {
    NdmSmt,
    // TODO add other accumulators..
}
