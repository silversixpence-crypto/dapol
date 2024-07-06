// Copyright ⓒ 2023 SilverSixpence
// Licensed under the MIT license
// (see LICENSE or <http://opensource.org/licenses/MIT>) All files in the project carrying such
// notice may not be copied, modified, or distributed except according to those
// terms.

//! # Proof of Liabilities protocol implemented in Rust
//!
//! Implementation of the DAPOL+ protocol introduced in the "Generalized Proof of Liabilities" by Yan Ji and Konstantinos Chalkias ACM CCS 2021 paper, available [here](https://eprint.iacr.org/2021/1350).
//!
//! See the [top-level doc for the project](https://hackmd.io/p0dy3R0RS5qpm3sX-_zreA) if you would like to know more about Proof of Liabilities.
//!
//! ## What is contained in this code
//!
//! This library offers an efficient build algorithm for constructing a binary Merkle Sum Tree representing the liabilities of an organization. Efficiency is achieved through parallelization. Details on the algorithm used can be found in [the multi-threaded builder file](https://github.com/silversixpence-crypto/dapol/blob/main/src/binary_tree/tree_builder/multi_threaded.rs).
//!
//! The paper describes a few different accumulator variants. The Sparse Merkle
//! Sum Tree is the DAPOL+ accumulator, but there are a few different axes of
//! variation, such as how the list of entities is embedded within the tree. The
//! 4 accumulator variants are simply slightly different versions of the Sparse
//! Merkle Sum Tree. Only the Non-Deterministic Mapping Sparse Merkle Tree
//! variant has been implemented so far.
//!
//! The code offers inclusion proof generation & verification using the
//! Bulletproofs protocol for the range proofs.
//!
//! ## Still to be done
//!
//! This project is currently still a work in progress, but is ready for
//! use as is. The code has _not_ been audited yet (as of Nov 2023). Progress can be tracked [here](https://github.com/silversixpence-crypto/dapol/issues/91).
//!
//! Important tasks still to be done:
//! - [Write a spec](https://github.com/silversixpence-crypto/dapol/issues/17)
//! - [Support the Deterministic mapping SMT accumulator type](https://github.com/silversixpence-crypto/dapol/issues/9)
//! - [Sort out version issues with dependencies](https://github.com/silversixpence-crypto/dapol/issues/11)
//! - [Allow the tree to be updatable](https://github.com/silversixpence-crypto/dapol/issues/109)
//! - [Finish integration tests](https://github.com/silversixpence-crypto/dapol/issues/42)
//! - [Use a database as the backend storage system](https://github.com/silversixpence-crypto/dapol/issues/44)
//!   (as opposed to memory)
//!
//! Performance can be [improved](https://github.com/silversixpence-crypto/dapol/issues/44).
//!
//! Alternate accumulators mentioned in the paper should be built:
//! - [Deterministic mapping SMT](https://github.com/silversixpence-crypto/dapol/issues/9)
//! - [ORAM-based SMT](https://github.com/silversixpence-crypto/dapol/issues/8)
//! - [Hierarchical SMTs](https://github.com/silversixpence-crypto/dapol/issues/7)
//!
//! Other than the above there are a few minor tasks to do, each of which has an
//! issue for tracking.
//!
//! ## How this code can be used
//!
//! There is both a Rust API and a CLI. Details for the API can be found below, and details for the CLI can be found [here](https://github.com/silversixpence-crypto/dapol#cli).
//!
//! ### Rust API
//!
//! The API has the following capabilities:
//! - build a tree using the builder pattern or a configuration file
//! - generate inclusion proofs from a list of entity IDs (tree required)
//! - verify an inclusion proof using a root hash (no tree required)
//!
//! ```
#![doc = include_str!("../examples/main.rs")]
//! ```
//!
//! ### Features
//!
//! #### Fuzzing
//!
//! This feature includes the libraries & features required to run the fuzzing tests.
//!
//! ### Testing
//!
//! This feature opens up additional functions for use withing the library, for usage in tests. One such functionality is the seeding of the NDM-SMT random mapping mechanism. During tests it's useful to be able to get deterministic tree builds, which cannot be done with plain NDM-SMT because the entities are randomly mapped to bottom-layer nodes. So adding the `testing` feature exposes functions that allow calling code to provide seeds for the PRNG from [rand].

mod kdf;

pub mod cli;
pub mod percentage;
pub mod read_write_utils;
pub mod utils;

mod dapol_tree;
pub use dapol_tree::{
    DapolTree, DapolTreeError, RootPublicData, RootSecretData, SERIALIZED_ROOT_PUB_FILE_PREFIX,
    SERIALIZED_ROOT_PVT_FILE_PREFIX, SERIALIZED_TREE_EXTENSION, SERIALIZED_TREE_FILE_PREFIX,
};

pub use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

mod dapol_config;
pub use dapol_config::{
    DapolConfig, DapolConfigBuilder, DapolConfigBuilderError, DapolConfigError,
};

mod accumulators;
pub use accumulators::AccumulatorType;

mod salt;
pub use salt::Salt;

mod hasher;
pub use hasher::Hasher;

mod max_thread_count;
pub use max_thread_count::{initialize_machine_parallelism, MaxThreadCount, MACHINE_PARALLELISM};

mod max_liability;
pub use max_liability::{
    MaxLiability, DEFAULT_MAX_LIABILITY, DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH,
};

mod binary_tree;
pub use binary_tree::{Height, HeightError, MAX_HEIGHT, MIN_HEIGHT};

mod secret;
pub use secret::{Secret, SecretParserError};

mod inclusion_proof;
pub use inclusion_proof::{AggregationFactor, InclusionProof, InclusionProofError, InclusionProofFileType};

mod entity;
pub use entity::{Entity, EntityId, EntityIdsParser, EntityIdsParserError};

/// Used for surfacing fuzzing tests to the fuzzing module in the ./fuzz
/// directory.
#[cfg(fuzzing)]
pub mod fuzz {
    pub use super::binary_tree::multi_threaded::tests::fuzz_max_nodes_to_store;
}
