use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    accumulators::{Accumulator, NdmSmtError, AccumulatorType, self, NdmSmt},
    read_write_utils::{self, ReadWriteError},
    utils::LogOnErr,
    AggregationFactor, Entity, Height, InclusionProof, Salt, Secret, MaxThreadCount,
};

// STENT TODO should we change the extension to 'dapol'?
const SERIALIZED_TREE_EXTENSION: &str = "dapoltree";
// STENT TODO we should change this 'cause it's from the old accumulator code, but not sure to what, maybe 'proof_of_liabilities_merkle_sum_tree'
const SERIALIZED_TREE_FILE_PREFIX: &str = "accumulator_";

/// Proof of Liabilities Sparse Merkle Sum Tree.
///
/// This is the top-most module in the hierarchy of the [dapol] crate.
///
// STENT TODO this doc stuff needs to change
/// Trees can be constructed via the configuration parsers:
/// - [AccumulatorConfig] is used to deserialize config from a file (the
/// specific type of accumulator is determined from the config file). After
/// parsing the config the accumulator can be constructed.
/// - [NdmSmtConfigBuilder] is used to construct the
/// config for the NDM-SMT accumulator type using a builder pattern. The config
/// can then be parsed to construct an NDM-SMT.
///
// STENT TODO give example usage
#[derive(Serialize, Deserialize)]
pub struct DapolTree {
    accumulator: Accumulator,
    master_secret: Secret,
    salt_s: Salt,
    salt_b: Salt,
    max_liability: u64,
}

// -------------------------------------------------------------------------------------------------
// Construction.

impl DapolTree {
    pub fn new(
        accumulator_type: AccumulatorType,
        master_secret: Secret,
        salt_s: Salt,
        salt_b: Salt,
        max_liability: u64,
        max_thread_count: MaxThreadCount,
        height: Height,
        entities: Vec<Entity>
    ) -> Result<Self, DapolTreeError> {
        let accumulator = match accumulator_type {
            AccumulatorType::NdmSmt => {
                NdmSmt::new(secrets, height, max_thread_count, entities)
            }
        };

        DapolTree {
            accumulator,
            master_secret,
            salt_s,
            salt_b,
            max_liability,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Accessor methods.

impl DapolTree {
    /// Return the height of the tree.
    pub fn height(&self) -> &Height {
        self.accumulator.height()
    }

    /// Tree generator's singular secret value.
    ///
    /// This value is known only to the tree generator, and is used to
    /// determine all other secret values needed in the tree.
    pub fn master_secret(&self) -> &Secret {
        &self.master_secret
    }

    /// Return the hash function salt value.
    ///
    /// This is a public value that is used to aid the KDF when generating secret
    /// salt values, which are in turn used in the hash function when generating
    /// node hashes.
    pub fn salt_s(&self) -> &Salt {
        &self.salt_s
    }

    /// Return the Pedersen commitment blinding factor salt value.
    ///
    /// This is a public value that is used to aid the KDF when generating secret
    /// blinding factors for the Pedersen commitments
    pub fn salt_b(&self) -> &Salt {
        &self.salt_b
    }

    /// Return the maximum singular liability.
    ///
    /// This is a public value representing the maximum amount that any
    /// single entity's liability can be, and is used in the range proofs:
    /// $[0, 2^{\text{height}} \times \text{max_liability}]$
    pub fn max_liability(&self) -> u64 {
        self.max_liability
    }
}

// -------------------------------------------------------------------------------------------------
// Serialization & deserialization.

impl DapolTree {
    /// Try deserialize from the given file path.
    ///
    /// The file is assumed to be in [bincode] format.
    ///
    /// An error is logged and returned if
    /// 1. The file cannot be opened.
    /// 2. The [bincode] deserializer fails.
    pub fn deserialize(path: PathBuf) -> Result<DapolTree, DapolTreeError> {
        debug!(
            "Deserializing accumulator from file {:?}",
            path.clone().into_os_string()
        );

        match path.extension() {
            Some(ext) => {
                if ext != SERIALIZED_TREE_EXTENSION {
                    Err(ReadWriteError::UnsupportedFileExtension {
                        expected: SERIALIZED_TREE_EXTENSION.to_owned(),
                        actual: ext.to_os_string(),
                    })?;
                }
            }
            None => Err(ReadWriteError::NotAFile(path.clone().into_os_string()))?,
        }

        let dapol_tree: DapolTree =
            read_write_utils::deserialize_from_bin_file(path.clone()).log_on_err()?;

        let root_hash = match &dapol_tree.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.root_hash(),
        };

        info!(
            "Successfully deserialized dapol tree from file {:?} with root hash {:?}",
            path.clone().into_os_string(),
            root_hash
        );

        Ok(dapol_tree)
    }

    /// Parse `path` as one that points to a serialized dapol tree file.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// [SERIALIZED_TREE_EXTENSION], then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_TREE_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::DapolTree;
    /// use std::path::PathBuf;
    ///
    /// let dir = PathBuf::from("./");
    /// let path = DapolTree::parse_serialization_path(dir).unwrap();
    /// ```
    pub fn parse_serialization_path(path: PathBuf) -> Result<PathBuf, ReadWriteError> {
        read_write_utils::parse_serialization_path(
            path,
            SERIALIZED_TREE_EXTENSION,
            SERIALIZED_TREE_FILE_PREFIX,
        )
    }

    /// Serialize to a file.
    ///
    /// Serialization is done using [bincode]
    ///
    /// An error is returned if
    /// 1. [bincode] fails to serialize the file.
    /// 2. There is an issue opening or writing the file.
    pub fn serialize(&self, path: PathBuf) -> Result<(), DapolTreeError> {
        info!(
            "Serializing accumulator to file {:?}",
            path.clone().into_os_string()
        );

        read_write_utils::serialize_to_bin_file(self, path).log_on_err()?;
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------
// Proof generation.

impl DapolTree {
    /// Generate an inclusion proof for the given `entity_id`.
    ///
    /// `aggregation_factor` is used to determine how many of the range proofs
    /// are aggregated. Those that do not form part of the aggregated proof
    /// are just proved individually. The aggregation is a feature of the
    /// Bulletproofs protocol that improves efficiency.
    ///
    /// `upper_bound_bit_length` is used to determine the upper bound for the
    /// range proof, which is set to `2^upper_bound_bit_length` i.e. the
    /// range proof shows `0 <= liability <= 2^upper_bound_bit_length` for
    /// some liability. The type is set to `u8` because we are not expected
    /// to require bounds higher than $2^256$. Note that if the value is set
    /// to anything other than 8, 16, 32 or 64 the Bulletproofs code will return
    /// an Err.
    pub fn generate_inclusion_proof_with(
        &self,
        entity_id: &EntityId,
        aggregation_factor: AggregationFactor,
        upper_bound_bit_length: u8,
    ) -> Result<InclusionProof, NdmSmtError> {
        match self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.generate_inclusion_proof_with(
                entity_id,
                aggregation_factor,
                upper_bound_bit_length,
            ),
        }
    }

    /// Generate an inclusion proof for the given `entity_id`.
    pub fn generate_inclusion_proof(
        &self,
        entity_id: &EntityId,
    ) -> Result<InclusionProof, NdmSmtError> {
        match self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.generate_inclusion_proof(entity_id),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when handling an [Accumulator].
#[derive(thiserror::Error, Debug)]
pub enum DapolTreeError {
    #[error("Error serializing/deserializing file")]
    SerdeError(#[from] ReadWriteError),
}

// -------------------------------------------------------------------------------------------------
// NOTE no unit tests here because this code is tested in the integration tests.
