// legacy

mod dapol;
pub use crate::dapol::{Dapol, DapolNode};

mod proof;
pub use proof::{DapolProof, DapolProofNode};

mod range;
pub use range::{RangeProofPadding, RangeProofSplitting, RangeProvable, RangeVerifiable};

pub mod errors;
pub mod utils;

#[cfg(test)]
mod tests;

// new

pub mod binary_tree;
mod kdf;
mod node_content;

mod inclusion_proof;
pub use inclusion_proof::{InclusionProof, InclusionProofError};

mod primitives;
pub use primitives::D256;

mod user;
pub use user::{User, UserId};

mod accumulators;
pub use accumulators::NdmSmt;

#[cfg(test)]
mod testing_utils;
