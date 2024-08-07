use primitive_types::H256;
use serde::{Deserialize, Serialize};

use std::{fmt::Debug, path::PathBuf};

use log::info;

use crate::binary_tree::{Coordinate, Height, Node, PathSiblings};
use crate::binary_tree::{FullNodeContent, HiddenNodeContent};
use crate::{read_write_utils, EntityId};

mod individual_range_proof;
use individual_range_proof::IndividualRangeProof;

mod aggregated_range_proof;
use aggregated_range_proof::AggregatedRangeProof;

mod aggregation_factor;
pub use aggregation_factor::AggregationFactor;

/// The file extension used when writing serialized binary files.
const SERIALIZED_PROOF_EXTENSION: &str = "dapolproof";

// -------------------------------------------------------------------------------------------------
// Main struct & implementation.

/// Inclusion proof for a PoL Merkle Tree.
///
/// The inclusion proof generation and verification algorithms are very closely
/// related to the node content type, and so the main inclusion proof struct was
/// not made generic for node content type. Instead specific node content types
/// were chosen. If other node contents are to be supported then new inclusion
/// proof structs and methods will need to be written.
///
/// There are 2 parts to an inclusion proof:
/// - the path in the tree
/// - the range proofs for the Pedersen commitments
///
/// The tree path is taken to be of type [hidden node content] because
/// sharing a [full node content] type with entities would leak secret
/// information such as other entity's liabilities and the total sum of
/// liabilities.
///
/// The Bulletproofs protocol is used for the range proofs. Bulletproofs allows
/// aggregating multiple range proofs into 1 proof, which is more efficient to
/// produce & verify than doing them individually. Both aggregated and
/// individual range proofs are supported, and a mixture of both can be used.
///
/// There are 2 adjustable parameters that have an affect on the Bulletproofs
/// algorithm:
/// - `aggregation_factor` is used to determine how many of the range proofs
/// are aggregated. Those that do not form part of the aggregated proof
/// are just proved individually. The aggregation is a feature of the
/// Bulletproofs protocol that improves efficiency.
/// - `upper_bound_bit_length` is used to determine the upper bound for the
/// range proof, which is set to `2^upper_bound_bit_length` i.e. the
/// range proof shows `0 <= liability <= 2^upper_bound_bit_length` for
/// some liability. The type is set to `u8` because we are not expected
/// to require bounds higher than $2^256$. Note that if the value is set
/// to anything other than 8, 16, 32 or 64 the Bulletproofs code will return
/// an Err.
///
/// [hidden node content]: crate::node_content::HiddenNodeContent
/// [full node content]: crate::node_content::FullNodeContent
#[derive(Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    path_siblings: PathSiblings<HiddenNodeContent>,
    leaf_node: Node<FullNodeContent>,
    individual_range_proofs: Option<Vec<IndividualRangeProof>>,
    aggregated_range_proof: Option<AggregatedRangeProof>,
    aggregation_factor: AggregationFactor,
    upper_bound_bit_length: u8,
}

impl InclusionProof {
    /// Generate an inclusion proof from the tree path siblings.
    ///
    /// Parameters:
    /// - `leaf_node`: node for which the inclusion proof must be generated for.
    /// - `path_siblings`: the sibling nodes of the nodes that form the path
    /// from leaf to root.
    /// - `aggregation_factor`:
    #[doc = include_str!("./shared_docs/aggregation_factor.md")]
    /// - `upper_bound_bit_length`:
    #[doc = include_str!("./shared_docs/upper_bound_bit_length.md")]
    pub fn generate(
        leaf_node: Node<FullNodeContent>,
        path_siblings: PathSiblings<FullNodeContent>,
        aggregation_factor: AggregationFactor,
        upper_bound_bit_length: u8,
    ) -> Result<Self, InclusionProofError> {
        // Is this cast safe? Yes because the tree height (which is the same as the
        // length of the input) is also stored as a u8, and so there would never
        // be more siblings than max(u8). TODO might be worth using a bounded
        // vector for siblings. If the tree height changes type for some
        // reason then this code would fail silently.
        let tree_height = Height::from_y_coord(path_siblings.len() as u8);
        let aggregation_index = aggregation_factor.apply_to(&tree_height);

        let mut nodes_for_aggregation = path_siblings.construct_path(leaf_node.clone())?;
        let nodes_for_individual_proofs =
            nodes_for_aggregation.split_off(aggregation_index as usize);

        let aggregated_range_proof = match aggregation_factor.is_zero(&tree_height) {
            false => {
                let aggregation_tuples = nodes_for_aggregation
                    .into_iter()
                    .map(|node| (node.content.liability, node.content.blinding_factor))
                    .collect();
                Some(AggregatedRangeProof::generate(
                    &aggregation_tuples,
                    upper_bound_bit_length,
                )?)
            }
            true => None,
        };

        let individual_range_proofs = match aggregation_factor.is_max(&tree_height) {
            false => Some(
                nodes_for_individual_proofs
                    .into_iter()
                    .map(|node| {
                        IndividualRangeProof::generate(
                            node.content.liability,
                            &node.content.blinding_factor,
                            upper_bound_bit_length,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            true => None,
        };

        Ok(InclusionProof {
            path_siblings: path_siblings.convert(),
            leaf_node,
            individual_range_proofs,
            aggregated_range_proof,
            aggregation_factor,
            upper_bound_bit_length,
        })
    }

    /// Verify that an inclusion proof matches a the root hash.
    pub fn verify(&self, root_hash: H256) -> Result<(), InclusionProofError> {
        info!("Verifying inclusion proof..");

        // Is this cast safe? Yes because the tree height (which is the same as the
        // length of the input) is also stored as a u8, and so there would never
        // be more siblings than max(u8).
        let tree_height = Height::from_y_coord(self.path_siblings.len() as u8);

        let hidden_leaf_node: Node<HiddenNodeContent> = self.leaf_node.clone().convert();
        let constructed_path = self.path_siblings.construct_path(hidden_leaf_node)?;

        self.verify_merkle_path(root_hash, tree_height, &constructed_path)?;
        self.verify_range_proofs(tree_height, &constructed_path)?;

        info!("Succesfully verified proof");

        Ok(())
    }

    /// Verify that an inclusion proof matches the root hash, and show path info.
    ///
    /// The path information is printed to stdout, and written to a json file
    /// in the given location.
    pub fn verify_and_show_path_info(
        self,
        root_hash: H256,
        dir: PathBuf,
        mut file_name: OsString,
    ) -> Result<(), InclusionProofError> {
        info!("Verifying inclusion proof..");

        // Is this cast safe? Yes because the tree height (which is the same as the
        // length of the input) is also stored as a u8, and so there would never
        // be more siblings than max(u8).
        let tree_height = Height::from_y_coord(self.path_siblings.len() as u8);

        let hidden_leaf_node: Node<HiddenNodeContent> = self.leaf_node.clone().convert();
        let constructed_path = self.path_siblings.construct_path(hidden_leaf_node)?;

        self.verify_merkle_path(root_hash, tree_height, &constructed_path)?;
        self.verify_range_proofs(tree_height, &constructed_path)?;

        info!("Succesfully verified proof");

        let path_str = self.path_siblings.path_to_str(&constructed_path);
        info!("{}", path_str);

        self.path_siblings
            .write_path_to_json(constructed_path, dir, file_name)?;

        Ok(())
    }

    /// Merkle tree path verification.
    fn verify_merkle_path(
        &self,
        root_hash: H256,
        tree_height: Height,
        path_nodes: &Vec<Node<HiddenNodeContent>>,
    ) -> Result<(), InclusionProofError> {
        use bulletproofs::PedersenGens;
        use curve25519_dalek::scalar::Scalar;

        // PartialEq for HiddenNodeContent does not depend on the commitment so we can
        // make this whatever we like
        let dummy_commitment = PedersenGens::default().commit(Scalar::from(0u8), Scalar::from(0u8));

        let root = Node {
            content: HiddenNodeContent::new(dummy_commitment, root_hash),
            coord: Coordinate {
                x: 0,
                y: tree_height.as_y_coord(),
            },
        };

        // this should never panic because the path construction checks for min length
        let constructed_root = path_nodes.last().expect(
            "[Bug in proof verification] there should have been at least 1 node in the path",
        );

        if constructed_root != &root {
            Err(InclusionProofError::RootMismatch)
        } else {
            Ok(())
        }
    }

    /// Range proof verification.
    fn verify_range_proofs(
        &self,
        tree_height: Height,
        path_nodes: &Vec<Node<HiddenNodeContent>>,
    ) -> Result<(), InclusionProofError> {
        use curve25519_dalek::ristretto::CompressedRistretto;

        let aggregation_index = self.aggregation_factor.apply_to(&tree_height) as usize;

        let mut commitments_for_aggregated_proofs: Vec<CompressedRistretto> = path_nodes
            .iter()
            .map(|node| node.content.commitment.compress())
            .collect();

        let commitments_for_individual_proofs =
            commitments_for_aggregated_proofs.split_off(aggregation_index);

        let mut at_least_one_checked = false;

        if let Some(proofs) = &self.individual_range_proofs {
            commitments_for_individual_proofs
                .iter()
                .zip(proofs.iter())
                .map(|(com, proof)| proof.verify(com, self.upper_bound_bit_length))
                .collect::<Result<Vec<_>, _>>()?;

            at_least_one_checked = true;
        }

        if let Some(proof) = &self.aggregated_range_proof {
            proof.verify(
                &commitments_for_aggregated_proofs,
                self.upper_bound_bit_length,
            )?;
            at_least_one_checked = true;
        }

        if !at_least_one_checked {
            Err(InclusionProofError::MissingRangeProof)
        } else {
            Ok(())
        }
    }

    /// Serialize the [InclusionProof] structure to a binary file.
    ///
    /// An error is returned if
    /// 1. [bincode] fails to serialize the file.
    /// 2. There is an issue opening or writing the file.
    pub fn serialize(
        &self,
        entity_id: &EntityId,
        dir: PathBuf,
        file_type: InclusionProofFileType,
    ) -> Result<PathBuf, InclusionProofError> {
        let mut file_name = entity_id.to_string();
        file_name.push('.');
        file_name.push_str(match file_type {
            InclusionProofFileType::Binary => SERIALIZED_PROOF_EXTENSION,
            InclusionProofFileType::Json => "json",
        });

        let path = dir.join(file_name);
        info!("Serializing inclusion proof to path {:?}", path);

        match file_type {
            InclusionProofFileType::Binary => {
                read_write_utils::serialize_to_bin_file(&self, path.clone())?
            }
            InclusionProofFileType::Json => {
                read_write_utils::serialize_to_json_file(&self, path.clone())?
            }
        }

        Ok(path)
    }

    /// Deserialize the [InclusionProof] structure from a binary file.
    ///
    /// The file is assumed to be in [bincode] format.
    ///
    /// An error is logged and returned if
    /// 1. The file cannot be opened.
    /// 2. The deserializer fails.
    /// 3. The file extension is not supported.
    pub fn deserialize(file_path: PathBuf) -> Result<InclusionProof, InclusionProofError> {
        let ext = file_path.extension().and_then(|s| s.to_str()).ok_or(
            InclusionProofError::UnknownFileType(file_path.clone().into_os_string()),
        )?;

        info!("Deserializing inclusion proof from file {:?}", file_path);

        match ext {
            SERIALIZED_PROOF_EXTENSION => {
                Ok(read_write_utils::deserialize_from_bin_file(file_path)?)
            }
            "json" => Ok(read_write_utils::deserialize_from_json_file(file_path)?),
            _ => Err(InclusionProofError::UnsupportedFileType { ext: ext.into() }),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Supported (de)serialization file types.

/// Supported file types for serialization.
#[derive(Debug, Clone)]
pub enum InclusionProofFileType {
    /// Binary file format.
    ///
    /// Most efficient but not human readable, unless you have the gift.
    Binary,

    /// JSON file format.
    ///
    /// Not the most efficient but is human readable.
    Json,
}

use std::str::FromStr;

impl FromStr for InclusionProofFileType {
    type Err = InclusionProofError;

    fn from_str(ext: &str) -> Result<InclusionProofFileType, Self::Err> {
        match ext.to_lowercase().as_str() {
            "binary" => Ok(InclusionProofFileType::Binary),
            "json" => Ok(InclusionProofFileType::Json),
            _ => Err(InclusionProofError::UnsupportedFileType { ext: ext.into() }),
        }
    }
}

use clap::builder::{OsStr, Str};

// From for OsStr (for the CLI).
impl From<InclusionProofFileType> for OsStr {
    fn from(file_type: InclusionProofFileType) -> OsStr {
        OsStr::from(Str::from(file_type.to_string()))
    }
}

impl std::fmt::Display for InclusionProofFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for InclusionProofFileType {
    fn default() -> Self {
        InclusionProofFileType::Binary
    }
}

// -------------------------------------------------------------------------------------------------
// Errors

use std::ffi::OsString;

/// Errors encountered when handling [InclusionProof].
#[derive(thiserror::Error, Debug)]
pub enum InclusionProofError {
    #[error("Siblings path verification failed")]
    TreePathSiblingsError(#[from] crate::binary_tree::PathSiblingsError),
    #[error("Calculated root content does not match provided root content")]
    RootMismatch,
    #[error("Issues with range proof")]
    RangeProofError(#[from] RangeProofError),
    #[error("No range proofs detected")]
    MissingRangeProof,
    #[error("Error serializing/deserializing file")]
    SerdeError(#[from] crate::read_write_utils::ReadWriteError),
    #[error("The file type with extension {ext:?} is not supported")]
    UnsupportedFileType { ext: String },
    #[error("Unable to find file extension for path {0:?}")]
    UnknownFileType(OsString),
    #[error("Error writing path info to file")]
    PathWriteError(#[from] crate::binary_tree::PathSiblingsWriteError),
}

#[derive(thiserror::Error, Debug)]
pub enum RangeProofError {
    #[error("Bulletproofs generation failed")]
    BulletproofGenerationError(bulletproofs::ProofError),
    #[error("Bulletproofs verification failed")]
    BulletproofVerificationError(bulletproofs::ProofError),
    #[error("The length of the Pedersen commitments vector did not match the length of the input used to generate the proof")]
    InputVectorLengthMismatch,
}

// -------------------------------------------------------------------------------------------------
// Unit tests

// TODO should we mock out the inclusion proof layer for these tests?

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary_tree::Coordinate;
    use crate::hasher::Hasher;

    use bulletproofs::PedersenGens;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use primitive_types::H256;

    // The tree that is built, with path highlighted.
    ///////////////////////////////////////////////////////
    //    |                   [root]                     //
    //  3 |                     224                      //
    //    |                    //\                       //
    //    |                   //  \                      //
    //    |                  //    \                     //
    //    |                 //      \                    //
    //    |                //        \                   //
    //    |               //          \                  //
    //    |              //            \                 //
    //    |             //              \                //
    //    |            //                \               //
    //    |           //                  \              //
    //    |          //                    \             //
    //  2 |         80                      144          //
    //    |         /\\                     /\           //
    //    |        /  \\                   /  \          //
    //    |       /    \\                 /    \         //
    //    |      /      \\               /      \        //
    //    |     /        \\             /        \       //
    //  1 |   30          50          84          60     //
    //    |   /\         //\          /\          /\     //
    //    |  /  \       //  \        /  \        /  \    //
    //  0 |13    17    27    23    41    43    07    53  //
    //  _            [leaf]                              //
    //  y  --------------------------------------------  //
    //  x| 0     1     2     3     4     5     6     7   //
    //                                                   //
    ///////////////////////////////////////////////////////
    fn build_test_path() -> (
        Node<FullNodeContent>,
        PathSiblings<FullNodeContent>,
        RistrettoPoint,
        H256,
    ) {
        // leaf at (2,0)
        let liability = 27u64;
        let blinding_factor = Scalar::from_bytes_mod_order(*b"11112222333344445555666677778888");
        let commitment = PedersenGens::default().commit(Scalar::from(liability), blinding_factor);
        let mut hasher = Hasher::new();
        hasher.update("leaf".as_bytes());
        let hash = hasher.finalize();
        let leaf = Node {
            coord: Coordinate { x: 2u64, y: 0u8 },
            content: FullNodeContent::new(liability, blinding_factor, commitment, hash),
        };

        // sibling at (3,0)
        let liability = 23u64;
        let blinding_factor = Scalar::from_bytes_mod_order(*b"22223333444455556666777788881111");
        let commitment = PedersenGens::default().commit(Scalar::from(liability), blinding_factor);
        let mut hasher = Hasher::new();
        hasher.update("sibling1".as_bytes());
        let hash = hasher.finalize();
        let sibling1 = Node {
            coord: Coordinate { x: 3u64, y: 0u8 },
            content: FullNodeContent::new(liability, blinding_factor, commitment, hash),
        };

        // we need to construct the root hash & commitment for verification testing
        let (parent_hash, parent_commitment) = build_parent(
            leaf.content.commitment,
            sibling1.content.commitment,
            leaf.content.hash,
            sibling1.content.hash,
        );

        // sibling at (0,1)
        let liability = 30u64;
        let blinding_factor = Scalar::from_bytes_mod_order(*b"33334444555566667777888811112222");
        let commitment = PedersenGens::default().commit(Scalar::from(liability), blinding_factor);
        let mut hasher = Hasher::new();
        hasher.update("sibling2".as_bytes());
        let hash = hasher.finalize();
        let sibling2 = Node {
            coord: Coordinate { x: 0u64, y: 1u8 },
            content: FullNodeContent::new(liability, blinding_factor, commitment, hash),
        };

        // we need to construct the root hash & commitment for verification testing
        let (parent_hash, parent_commitment) = build_parent(
            sibling2.content.commitment,
            parent_commitment,
            sibling2.content.hash,
            parent_hash,
        );

        // sibling at (1,2)
        let liability = 144u64;
        let blinding_factor = Scalar::from_bytes_mod_order(*b"44445555666677778888111122223333");
        let commitment = PedersenGens::default().commit(Scalar::from(liability), blinding_factor);
        let mut hasher = Hasher::new();
        hasher.update("sibling3".as_bytes());
        let hash = hasher.finalize();
        let sibling3 = Node {
            coord: Coordinate { x: 1u64, y: 2u8 },
            content: FullNodeContent::new(liability, blinding_factor, commitment, hash),
        };

        // we need to construct the root hash & commitment for verification testing
        let (root_hash, root_commitment) = build_parent(
            parent_commitment,
            sibling3.content.commitment,
            parent_hash,
            sibling3.content.hash,
        );

        (
            leaf,
            PathSiblings(vec![sibling1, sibling2, sibling3]),
            root_commitment,
            root_hash,
        )
    }

    fn build_parent(
        left_commitment: RistrettoPoint,
        right_commitment: RistrettoPoint,
        left_hash: H256,
        right_hash: H256,
    ) -> (H256, RistrettoPoint) {
        let parent_commitment = left_commitment + right_commitment;

        // `H(parent) = Hash(C(L) | C(R) | H(L) | H(R))`
        let parent_hash = {
            let mut hasher = Hasher::new();
            hasher.update(left_commitment.compress().as_bytes());
            hasher.update(right_commitment.compress().as_bytes());
            hasher.update(left_hash.as_bytes());
            hasher.update(right_hash.as_bytes());
            hasher.finalize()
        };

        (parent_hash, parent_commitment)
    }

    // TODO fuzz on the aggregation factor
    #[test]
    fn generate_works() {
        let aggregation_factor = AggregationFactor::Divisor(2u8);
        let upper_bound_bit_length = 64u8;

        let (leaf, path, _, _) = build_test_path();
        InclusionProof::generate(leaf, path, aggregation_factor, upper_bound_bit_length).unwrap();
    }

    #[test]
    fn verify_works() {
        let aggregation_factor = AggregationFactor::Divisor(2u8);
        let upper_bound_bit_length = 64u8;

        let (leaf, path, _root_commitment, root_hash) = build_test_path();

        let proof =
            InclusionProof::generate(leaf, path, aggregation_factor, upper_bound_bit_length)
                .unwrap();

        proof.verify(root_hash).unwrap();
    }

    // TODO test correct error translation from lower layers (probably should
    // mock the error responses rather than triggering them from the code in the
    // lower layers)
}
