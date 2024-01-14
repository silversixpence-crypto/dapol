use log::{debug, info};
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    accumulators::{Accumulator, AccumulatorType, NdmSmt, NdmSmtError},
    read_write_utils::{self, ReadWriteError},
    utils::LogOnErr,
    AggregationFactor, Entity, EntityId, Height, InclusionProof, MaxThreadCount, Salt, Secret,
};

// STENT TODO should we change the extension to 'dapol'?
const SERIALIZED_TREE_EXTENSION: &str = "dapoltree";
// STENT TODO we should change this 'cause it's from the old accumulator code,
// but not sure to what, maybe 'proof_of_liabilities_merkle_sum_tree'
const SERIALIZED_TREE_FILE_PREFIX: &str = "accumulator_";

/// Proof of Liabilities Sparse Merkle Sum Tree.
///
/// This is the top-most module in the hierarchy of the [dapol] crate.
// STENT TODO this doc stuff needs to change
/// Trees can be constructed via the configuration parsers:
/// - [AccumulatorConfig] is used to deserialize config from a file (the
/// specific type of accumulator is determined from the config file). After
/// parsing the config the accumulator can be constructed.
/// - [NdmSmtConfigBuilder] is used to construct the
/// config for the NDM-SMT accumulator type using a builder pattern. The config
/// can then be parsed to construct an NDM-SMT.
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
// Construction & proof generation.

impl DapolTree {
    /// Construct a new tree.
    ///
    /// An error is returned if the underlying accumulator type construction
    /// fails.
    ///
    /// - `accumulator_type`: This value must be set.
    #[doc = include_str!("./shared_docs/accumulator_type.md")]
    /// - `master_secret`: This value is known only to the tree generator, and
    ///   is used to determine all other secret values needed in the tree. This
    ///   value must be set.
    /// - `salt_b`: If not set then it will be randomly generated.
    #[doc = include_str!("./shared_docs/salt_b.md")]
    /// - `salt_s`: If not set then it will be
    ///   randomly generated.
    #[doc = include_str!("./shared_docs/salt_s.md")]
    /// - `max_liability`: If not set then a default value is used.
    #[doc = include_str!("./shared_docs/max_liability.md")]
    /// - `height`: If not set the [default height] will be used [crate][Height].
    #[doc = include_str!("./shared_docs/height.md")]
    /// - `max_thread_count`: If not set the max parallelism of the
    ///   underlying machine will be used.
    #[doc = include_str!("./shared_docs/max_thread_count.md")]
    /// - `secrets_file_path`: Path to the secrets file. If not present the
    ///   secrets will be generated randomly.
    /// - `entities`:
    #[doc = include_str!("./shared_docs/entities_vector.md")]
    ///
    /// [default height]: crate::Height::default
    // STENT TODO give example
    pub fn new(
        accumulator_type: AccumulatorType,
        master_secret: Secret,
        salt_s: Salt,
        salt_b: Salt,
        max_liability: u64,
        max_thread_count: MaxThreadCount,
        height: Height,
        entities: Vec<Entity>,
    ) -> Result<Self, DapolTreeError> {
        let accumulator = match accumulator_type {
            AccumulatorType::NdmSmt => {
                let ndm_smt = NdmSmt::new(
                    master_secret.clone(),
                    salt_b.clone(),
                    salt_s.clone(),
                    height,
                    max_thread_count,
                    entities,
                )?;
                Accumulator::NdmSmt(ndm_smt)
            }
        };

        Ok(DapolTree {
            accumulator,
            master_secret,
            salt_s,
            salt_b,
            max_liability,
        })
    }

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
    // STENT TODO use the max_liability value to calculate upper_bound_bit_length
    pub fn generate_inclusion_proof_with(
        &self,
        entity_id: &EntityId,
        aggregation_factor: AggregationFactor,
        upper_bound_bit_length: u8,
    ) -> Result<InclusionProof, NdmSmtError> {
        match &self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.generate_inclusion_proof_with(
                &self.master_secret,
                &self.salt_b,
                &self.salt_s,
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
        match &self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.generate_inclusion_proof(
                &self.master_secret,
                &self.salt_b,
                &self.salt_s,
                entity_id,
            ),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Accessor methods.

impl DapolTree {
    #[doc = include_str!("./shared_docs/accumulator_type.md")]
    pub fn accumulator_type(&self) -> AccumulatorType {
        self.accumulator.get_type()
    }

    #[doc = include_str!("./shared_docs/master_secret.md")]
    pub fn master_secret(&self) -> &Secret {
        &self.master_secret
    }

    #[doc = include_str!("./shared_docs/salt_b.md")]
    pub fn salt_b(&self) -> &Salt {
        &self.salt_b
    }

    #[doc = include_str!("./shared_docs/salt_s.md")]
    pub fn salt_s(&self) -> &Salt {
        &self.salt_s
    }

    #[doc = include_str!("./shared_docs/max_liability.md")]
    pub fn max_liability(&self) -> u64 {
        self.max_liability
    }

    #[doc = include_str!("./shared_docs/height.md")]
    pub fn height(&self) -> &Height {
        self.accumulator.height()
    }

    /// Return the hash digest/bytes of the root node for the binary tree.
    pub fn root_hash(&self) -> H256 {
        self.accumulator.root_hash()
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
        let path = DapolTree::parse_serialization_path(path)?;

        info!(
            "Serializing accumulator to file {:?}",
            path.clone().into_os_string()
        );

        read_write_utils::serialize_to_bin_file(self, path).log_on_err()?;
        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when handling an [Accumulator].
#[derive(thiserror::Error, Debug)]
pub enum DapolTreeError {
    #[error("Error serializing/deserializing file")]
    SerdeError(#[from] ReadWriteError),
    #[error("Error constructing a new NDM-SMT")]
    NdmSmtConstructionError(#[from] NdmSmtError),
}

// -------------------------------------------------------------------------------------------------
// NOTE no unit tests here because this code is tested in the integration tests.
