use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use log::{debug, info};
use primitive_types::H256;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    accumulators::{Accumulator, AccumulatorType, NdmSmt, NdmSmtError},
    read_write_utils::{self},
    secret,
    utils::LogOnErr,
    AggregationFactor, Entity, EntityId, Height, InclusionProof, MaxLiability, MaxThreadCount,
    Salt, Secret,
};

const SERIALIZED_TREE_EXTENSION: &str = "dapoltree";
const SERIALIZED_TREE_FILE_PREFIX: &str = "proof_of_liabilities_merkle_sum_tree_";

const SERIALIZED_ROOT_PUB_FILE_PREFIX: &str = "public_root_data_";
const SERIALIZED_ROOT_PVT_FILE_PREFIX: &str = "secret_root_data_";

// -------------------------------------------------------------------------------------------------
// Main struct.

/// Proof of Liabilities Sparse Merkle Sum Tree.
///
/// This is the top-most module in the hierarchy of the [dapol] crate.
///
/// It is recommended that one use [crate][DapolConfig] to construct the
/// tree, which has extra sanity checks on the inputs and more ways to set
/// the parameters. But there is also a `new` function for direct construction.
#[derive(Debug, Serialize, Deserialize)]
pub struct DapolTree {
    accumulator: Accumulator,
    master_secret: Secret,
    salt_s: Salt,
    salt_b: Salt,
    max_liability: MaxLiability,
}

// -------------------------------------------------------------------------------------------------
// Periphery structs.

/// The public values of the root node.
///
/// These values should be put on a Public Bulletin Board (such as a blockchain)
/// to legitimize the proof of liabilities. Without doing this there is no
/// guarantee to the user that their inclusion proof is checked against the same
/// data as other users' inclusion proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootPublicData {
    pub hash: H256,
    pub commitment: RistrettoPoint,
}

/// The secret values of the root node.
///
/// These are the values that are used to construct the Pedersen commitment.
/// These values should not be shared if the tree owner does not want to
/// disclose their total liability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootSecretData {
    pub liability: u64,
    pub blinding_factor: Scalar,
}

// -------------------------------------------------------------------------------------------------
// Construction & proof generation.

impl DapolTree {
    /// Construct a new tree.
    ///
    /// It is recommended to rather use [crate][DapolConfig] to construct the
    /// tree, which has extra sanity checks on the inputs and more ways to set
    /// the parameters.
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
    /// - `salt_s`: If not set then it will be randomly generated.
    #[doc = include_str!("./shared_docs/salt_s.md")]
    /// - `max_liability`: If not set then a default value is used.
    #[doc = include_str!("./shared_docs/max_liability.md")]
    /// - `height`: If not set the [default height] will be used
    ///   [crate][Height].
    #[doc = include_str!("./shared_docs/height.md")]
    /// - `max_thread_count`: If not set the max parallelism of the underlying
    ///   machine will be used.
    #[doc = include_str!("./shared_docs/max_thread_count.md")]
    /// - `secrets_file_path`: Path to the secrets file. If not present the
    ///   secrets will be generated randomly.
    /// - `entities`:
    #[doc = include_str!("./shared_docs/entities_vector.md")]
    ///
    /// Example of how to use the construtor:
    /// ```
    /// use std::str::FromStr;
    /// use dapol::{
    ///     AccumulatorType, DapolTree, Entity, EntityId, Height, MaxLiability,
    ///     MaxThreadCount, Salt, Secret,
    /// };
    ///
    /// let accumulator_type = AccumulatorType::NdmSmt;
    /// let height = Height::expect_from(8);
    /// let salt_b = Salt::from_str("salt_b").unwrap();
    /// let salt_s = Salt::from_str("salt_s").unwrap();
    /// let master_secret = Secret::from_str("master_secret").unwrap();
    /// let max_liability = MaxLiability::from(10_000_000);
    /// let max_thread_count = MaxThreadCount::from(8);
    ///
    /// let entity = Entity {
    ///     liability: 1u64,
    ///     id: EntityId::from_str("id").unwrap(),
    /// };
    /// let entities = vec![entity];
    ///
    /// let dapol_tree = DapolTree::new(
    ///     accumulator_type,
    ///     master_secret,
    ///     salt_b,
    ///     salt_s,
    ///     max_liability,
    ///     max_thread_count,
    ///     height,
    ///     entities,
    /// ).unwrap();
    /// ```
    ///
    /// [default height]: crate::Height::default
    pub fn new(
        accumulator_type: AccumulatorType,
        master_secret: Secret,
        salt_b: Salt,
        salt_s: Salt,
        max_liability: MaxLiability,
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

        let tree = DapolTree {
            accumulator,
            master_secret,
            salt_b: salt_b.clone(),
            salt_s: salt_s.clone(),
            max_liability,
        };

        tree.log_successful_tree_creation();

        Ok(tree)
    }

    /// Generate an inclusion proof for the given `entity_id`.
    ///
    /// Parameters:
    /// - `entity_id`: unique ID for the entity that the proof will be generated
    ///   for.
    /// - `aggregation_factor`:
    #[doc = include_str!("./shared_docs/aggregation_factor.md")]
    pub fn generate_inclusion_proof_with(
        &self,
        entity_id: &EntityId,
        aggregation_factor: AggregationFactor,
    ) -> Result<InclusionProof, NdmSmtError> {
        match &self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => ndm_smt.generate_inclusion_proof(
                &self.master_secret,
                &self.salt_b,
                &self.salt_s,
                entity_id,
                aggregation_factor,
                self.max_liability.as_range_proof_upper_bound_bit_length(),
            ),
        }
    }

    /// Generate an inclusion proof for the given `entity_id`.
    ///
    /// Parameters:
    /// - `entity_id`: unique ID for the entity that the proof will be generated
    ///   for.
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
                AggregationFactor::default(),
                self.max_liability.as_range_proof_upper_bound_bit_length(),
            ),
        }
    }

    /// Check that the public Pedersen commitment corresponds to the secret
    /// values of the root.
    ///
    /// If the secret data does not match the commitment then false is returned,
    /// otherwise true.
    pub fn verify_root_commitment(
        public_commitment: &RistrettoPoint,
        secret_root_data: &RootSecretData,
    ) -> Result<(), DapolTreeError> {
        let commitment = PedersenGens::default().commit(
            Scalar::from(secret_root_data.liability),
            secret_root_data.blinding_factor,
        );

        if commitment == *public_commitment {
            Ok(())
        } else {
            Err(DapolTreeError::RootVerificationError)
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
    pub fn max_liability(&self) -> &MaxLiability {
        &self.max_liability
    }

    #[doc = include_str!("./shared_docs/height.md")]
    pub fn height(&self) -> &Height {
        self.accumulator.height()
    }

    /// Mapping of [crate][EntityId] to x-coord on the bottom layer of the tree.
    ///
    /// If the underlying accumulator is an NDM-SMT then a hashmap is returned
    /// otherwise None is returned.
    pub fn entity_mapping(&self) -> Option<&std::collections::HashMap<EntityId, u64>> {
        match &self.accumulator {
            Accumulator::NdmSmt(ndm_smt) => Some(ndm_smt.entity_mapping()),
            _ => None,
        }
    }

    /// Hash & Pedersen commitment for the root node of the Merkle Sum Tree.
    ///
    /// These values can be made public and do not disclose secret information
    /// about the tree such as the number of leaf nodes or their liabilities.
    pub fn public_root_data(&self) -> RootPublicData {
        RootPublicData {
            hash: self.root_hash().clone(),
            commitment: self.root_commitment().clone(),
        }
    }

    /// Liability & blinding factor that make up the Pederesen commitment of
    /// the Merkle Sum Tree.
    ///
    /// Neither of these values should be made public if the owner of the tree
    /// does not want to disclose the total liability sum of their users.
    pub fn secret_root_data(&self) -> RootSecretData {
        RootSecretData {
            liability: self.root_liability(),
            blinding_factor: self.root_blinding_factor().clone(),
        }
    }

    #[doc = include_str!("./shared_docs/root_hash.md")]
    pub fn root_hash(&self) -> &H256 {
        self.accumulator.root_hash()
    }

    #[doc = include_str!("./shared_docs/root_commitment.md")]
    pub fn root_commitment(&self) -> &RistrettoPoint {
        self.accumulator.root_commitment()
    }

    #[doc = include_str!("./shared_docs/root_liability.md")]
    pub fn root_liability(&self) -> u64 {
        self.accumulator.root_liability()
    }

    #[doc = include_str!("./shared_docs/root_blinding_factor.md")]
    pub fn root_blinding_factor(&self) -> &Scalar {
        self.accumulator.root_blinding_factor()
    }
}

// -------------------------------------------------------------------------------------------------
// Serialization & deserialization.

impl DapolTree {
    fn log_successful_tree_creation(&self) {
        info!(
            "\nDAPOL tree has been constructed. Public data:\n \
             - accumulator type: {}\n \
             - height: {}\n \
             - salt_b: 0x{}\n \
             - salt_s: 0x{}\n \
             - root hash: 0x{}\n \
             - root commitment: {:?}",
            self.accumulator_type(),
            self.height().as_u32(),
            self.salt_b
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            self.salt_s
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            self.root_hash()
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            self.root_commitment().compress()
        );
    }

    /// Parse `path` as one that points to a serialized dapol tree file.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".[SERIALIZED_TREE_EXTENSION]", then `path` is returned.
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
    /// let path = DapolTree::parse_tree_serialization_path(dir).unwrap();
    /// ```
    pub fn parse_tree_serialization_path(
        path: PathBuf,
    ) -> Result<PathBuf, read_write_utils::ReadWriteError> {
        read_write_utils::parse_serialization_path(
            path,
            SERIALIZED_TREE_EXTENSION,
            SERIALIZED_TREE_FILE_PREFIX,
        )
    }

    /// Parse `path` as one that points to a json file containing the public
    /// data of the root node.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".json", then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_ROOT_PUB_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::DapolTree;
    /// use std::path::PathBuf;
    ///
    /// let dir = PathBuf::from("./");
    /// let path = DapolTree::parse_public_root_data_serialization_path(dir).unwrap();
    /// ```
    pub fn parse_public_root_data_serialization_path(
        path: PathBuf,
    ) -> Result<PathBuf, read_write_utils::ReadWriteError> {
        read_write_utils::parse_serialization_path(path, "json", SERIALIZED_ROOT_PUB_FILE_PREFIX)
    }

    /// Parse `path` as one that points to a json file containing the secret
    /// data of the root node.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".json", then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_ROOT_PVT_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::DapolTree;
    /// use std::path::PathBuf;
    ///
    /// let dir = PathBuf::from("./");
    /// let path = DapolTree::parse_secret_root_data_serialization_path(dir).unwrap();
    /// ```
    pub fn parse_secret_root_data_serialization_path(
        path: PathBuf,
    ) -> Result<PathBuf, read_write_utils::ReadWriteError> {
        read_write_utils::parse_serialization_path(path, "json", SERIALIZED_ROOT_PVT_FILE_PREFIX)
    }

    /// Serialize the whole tree to a file.
    ///
    /// Serialization is done using [bincode].
    ///
    /// An error is returned if
    /// 1. [bincode] fails to serialize the file.
    /// 2. There is an issue opening or writing the file.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".[SERIALIZED_TREE_EXTENSION]", then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_TREE_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::{DapolTree, DapolConfig};
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    ///
    /// let config_file_path = examples_dir.join("dapol_config_example.toml");
    /// let dapol_config = DapolConfig::deserialize(config_file_path).unwrap();
    /// let dapol_tree = dapol_config.parse().unwrap();
    ///
    /// let tree_path = examples_dir.join("my_serialized_tree_for_testing.dapoltree");
    /// let _ = dapol_tree.serialize(tree_path).unwrap();
    /// ```
    pub fn serialize(&self, path: PathBuf) -> Result<PathBuf, DapolTreeError> {
        let path = DapolTree::parse_tree_serialization_path(path)?;

        info!(
            "Serializing accumulator to file {:?}",
            path.clone().into_os_string()
        );

        read_write_utils::serialize_to_bin_file(&self, path.clone()).log_on_err()?;

        Ok(path)
    }

    /// Serialize the public root node data to a file.
    ///
    /// The data that will be serialized to a json file:
    /// - Pedersen commitment
    /// - hash
    ///
    /// An error is returned if
    /// 1. [serde_json] fails to serialize the file.
    /// 2. There is an issue opening or writing to the file.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".json", then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_ROOT_PUB_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::{DapolTree, DapolConfig};
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    /// let config_file_path = examples_dir.join("dapol_config_example.toml");
    /// let dapol_config = DapolConfig::deserialize(config_file_path).unwrap();
    /// let dapol_tree = dapol_config.parse().unwrap();
    ///
    /// let public_root_path = examples_dir.join("public_root_data.json");
    /// let _ = dapol_tree.serialize_public_root_data(public_root_path).unwrap();
    /// ```
    pub fn serialize_public_root_data(&self, path: PathBuf) -> Result<PathBuf, DapolTreeError> {
        let public_root_data: RootPublicData = self.public_root_data();
        let path = DapolTree::parse_public_root_data_serialization_path(path.clone())?;
        read_write_utils::serialize_to_json_file(&public_root_data, path.clone())?;

        Ok(path)
    }

    /// Serialize the public root node data to a file.
    ///
    /// The data that will be serialized to a json file:
    /// - Pedersen commitment
    /// - hash
    /// - secret data (liability & blinding factor for Pedersen commitment)
    ///
    /// An error is returned if
    /// 1. [serde_json] fails to serialize any of the files.
    /// 2. There is an issue opening or writing to any of the files.
    ///
    /// `path` can be either of the following:
    /// 1. Existing directory: in this case a default file name is appended to
    /// `path`. 2. Non-existing directory: in this case all dirs in the path
    /// are created, and a default file name is appended.
    /// 3. File in existing dir: in this case the extension is checked to be
    /// ".json", then `path` is returned.
    /// 4. File in non-existing dir: dirs in the path are created and the file
    /// extension is checked.
    ///
    /// The file prefix is [SERIALIZED_ROOT_PVT_FILE_PREFIX].
    ///
    /// Example:
    /// ```
    /// use dapol::{DapolTree, DapolConfig};
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    /// let config_file_path = examples_dir.join("dapol_config_example.toml");
    /// let dapol_config = DapolConfig::deserialize(config_file_path).unwrap();
    /// let dapol_tree = dapol_config.parse().unwrap();
    ///
    /// let secret_root_path = examples_dir.join("secret_root_data.json");
    /// let _ = dapol_tree.serialize_secret_root_data(secret_root_path).unwrap();
    /// ```
    pub fn serialize_secret_root_data(&self, dir: PathBuf) -> Result<PathBuf, DapolTreeError> {
        let secret_root_data: RootSecretData = self.secret_root_data();
        let path = DapolTree::parse_secret_root_data_serialization_path(dir.clone())?;
        read_write_utils::serialize_to_json_file(&secret_root_data, path.clone())?;

        Ok(path)
    }

    /// Deserialize the tree from the given file path.
    ///
    /// The file is assumed to be in [bincode] format.
    ///
    /// An error is logged and returned if
    /// 1. The file cannot be opened.
    /// 2. The [bincode] deserializer fails.
    /// 3. The file extension is not ".[SERIALIZED_TREE_EXTENSION]"
    ///
    /// Example:
    /// ```
    /// use dapol::{DapolTree, DapolConfig};
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    /// let tree_path = examples_dir.join("my_serialized_tree_for_testing.dapoltree");
    /// let _ = DapolTree::deserialize(tree_path).unwrap();
    /// ```
    pub fn deserialize(path: PathBuf) -> Result<DapolTree, DapolTreeError> {
        debug!(
            "Deserializing DapolTree from file {:?}",
            path.clone().into_os_string()
        );

        read_write_utils::check_deserialization_path(&path, SERIALIZED_TREE_EXTENSION)?;

        let dapol_tree: DapolTree =
            read_write_utils::deserialize_from_bin_file(path.clone()).log_on_err()?;

        dapol_tree.log_successful_tree_creation();

        Ok(dapol_tree)
    }

    /// Deserialize the public root data from the given file path.
    ///
    /// The file is assumed to be in json format.
    ///
    /// An error is logged and returned if
    /// 1. The file cannot be opened.
    /// 2. The [serde_json] deserializer fails.
    /// 3. The file extension is not ".[SERIALIZED_ROOT_PUB_FILE_PREFIX]"
    ///
    /// Example:
    /// ```
    /// use dapol::DapolTree;
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    /// let public_root_path = examples_dir.join("public_root_data.json");
    ///
    /// let public_root_data = DapolTree::deserialize_public_root_data(public_root_path).unwrap();
    /// ```
    pub fn deserialize_public_root_data(path: PathBuf) -> Result<RootPublicData, DapolTreeError> {
        read_write_utils::check_deserialization_path(&path, "json")?;

        let public_root_data: RootPublicData =
            read_write_utils::deserialize_from_json_file(path.clone()).log_on_err()?;

        Ok(public_root_data)
    }

    /// Deserialize the secret root data from the given file path.
    ///
    /// The file is assumed to be in json format.
    ///
    /// An error is logged and returned if
    /// 1. The file cannot be opened.
    /// 2. The [serde_json] deserializer fails.
    /// 3. The file extension is not ".[SERIALIZED_ROOT_PUB_FILE_PREFIX]"
    ///
    /// Example:
    /// ```
    /// use dapol::DapolTree;
    /// use std::path::Path;
    ///
    /// let src_dir = env!("CARGO_MANIFEST_DIR");
    /// let examples_dir = Path::new(&src_dir).join("examples");
    /// let secret_root_path = examples_dir.join("secret_root_data.json");
    ///
    /// let secret_root_data = DapolTree::deserialize_secret_root_data(secret_root_path).unwrap();
    /// ```
    pub fn deserialize_secret_root_data(path: PathBuf) -> Result<RootSecretData, DapolTreeError> {
        read_write_utils::check_deserialization_path(&path, "json")?;

        let secret_root_data: RootSecretData =
            read_write_utils::deserialize_from_json_file(path.clone()).log_on_err()?;

        Ok(secret_root_data)
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when handling an [Accumulator].
#[derive(thiserror::Error, Debug)]
pub enum DapolTreeError {
    #[error("Error serializing/deserializing file")]
    SerdeError(#[from] read_write_utils::ReadWriteError),
    #[error("Error constructing a new NDM-SMT")]
    NdmSmtConstructionError(#[from] NdmSmtError),
    #[error("Verification of root data failed")]
    RootVerificationError,
}

// -------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::assert_err;
    use crate::{
        accumulators, AccumulatorType, DapolTree, Entity, EntityId, Height, MaxLiability,
        MaxThreadCount, Salt, Secret,
    };
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    #[test]
    fn constructor_and_getters_work() {
        let accumulator_type = AccumulatorType::NdmSmt;
        let height = Height::expect_from(8);
        let salt_b = Salt::from_str("salt_b").unwrap();
        let salt_s = Salt::from_str("salt_s").unwrap();
        let master_secret = Secret::from_str("master_secret").unwrap();
        let max_liability = MaxLiability::from(10_000_000);
        let max_thread_count = MaxThreadCount::from(8);

        let entity = Entity {
            liability: 1u64,
            id: EntityId::from_str("id").unwrap(),
        };
        let entities = vec![entity.clone()];

        let tree = DapolTree::new(
            accumulator_type.clone(),
            master_secret.clone(),
            salt_b.clone(),
            salt_s.clone(),
            max_liability.clone(),
            max_thread_count.clone(),
            height.clone(),
            entities,
        )
        .unwrap();

        assert_eq!(tree.master_secret(), &master_secret);
        assert_eq!(tree.height(), &height);
        assert_eq!(tree.max_liability(), &max_liability);
        assert_eq!(tree.salt_b(), &salt_b);
        assert_eq!(tree.salt_s(), &salt_s);
        assert_eq!(tree.accumulator_type(), accumulator_type);

        assert!(tree.entity_mapping().is_some());
        assert!(tree.entity_mapping().unwrap().get(&entity.id).is_some());
    }

    fn new_tree() -> DapolTree {
        let accumulator_type = AccumulatorType::NdmSmt;
        let height = Height::expect_from(8);
        let salt_b = Salt::from_str("salt_b").unwrap();
        let salt_s = Salt::from_str("salt_s").unwrap();
        let master_secret = Secret::from_str("master_secret").unwrap();
        let max_liability = MaxLiability::from(10_000_000);
        let max_thread_count = MaxThreadCount::from(8);

        let entity = Entity {
            liability: 1u64,
            id: EntityId::from_str("id").unwrap(),
        };
        let entities = vec![entity.clone()];

        DapolTree::new(
            accumulator_type.clone(),
            master_secret.clone(),
            salt_b.clone(),
            salt_s.clone(),
            max_liability.clone(),
            max_thread_count.clone(),
            height.clone(),
            entities,
        )
        .unwrap()
    }

    #[test]
    fn serde_does_not_change_tree() {
        let tree = new_tree();

        let src_dir = env!("CARGO_MANIFEST_DIR");
        let examples_dir = Path::new(&src_dir).join("examples");
        let path = examples_dir.join("my_serialized_tree_for_testing.dapoltree");
        let path_2 = tree.serialize(path.clone()).unwrap();
        assert_eq!(path, path_2);

        let tree_2 = DapolTree::deserialize(path).unwrap();

        assert_eq!(tree.master_secret(), tree_2.master_secret());
        assert_eq!(tree.height(), tree_2.height());
        assert_eq!(tree.max_liability(), tree_2.max_liability());
        assert_eq!(tree.salt_b(), tree_2.salt_b());
        assert_eq!(tree.salt_s(), tree_2.salt_s());
        assert_eq!(tree.accumulator_type(), tree_2.accumulator_type());
        assert_eq!(tree.entity_mapping(), tree_2.entity_mapping());
    }

    #[test]
    fn serialization_path_parser_fails_for_unsupported_extensions() {
        let path = PathBuf::from_str("./mytree.myext").unwrap();

        let res = DapolTree::parse_tree_serialization_path(path);
        assert_err!(
            res,
            Err(read_write_utils::ReadWriteError::UnsupportedFileExtension {
                expected: _,
                actual: _
            })
        );
    }

    #[test]
    fn serialization_path_parser_gives_correct_file_prefix() {
        let path = PathBuf::from_str("./").unwrap();
        let path = DapolTree::parse_tree_serialization_path(path).unwrap();
        assert!(path
            .to_str()
            .unwrap()
            .contains("proof_of_liabilities_merkle_sum_tree_"));
    }

    #[test]
    fn generate_inclusion_proof_works() {
        let tree = new_tree();
        assert!(tree
            .generate_inclusion_proof(&EntityId::from_str("id").unwrap())
            .is_ok());
    }

    #[test]
    fn generate_inclusion_proof_with_aggregation_factor_works() {
        let tree = new_tree();
        let agg = AggregationFactor::Divisor(2u8);
        assert!(tree
            .generate_inclusion_proof_with(&EntityId::from_str("id").unwrap(), agg)
            .is_ok());
    }
}
