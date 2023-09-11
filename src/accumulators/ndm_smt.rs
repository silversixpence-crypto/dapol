//! Non-deterministic mapping sparse Merkle tree (NDM_SMT).

use rand::rngs::ThreadRng;
use rand::{distributions::Uniform, thread_rng, Rng}; // TODO double check this is cryptographically safe randomness
use std::collections::HashMap;
use thiserror::Error;

use crate::binary_tree::{Coordinate, InputLeafNode, SparseBinaryTree, SparseBinaryTreeError, PathError};
use crate::kdf::generate_key;
use crate::node_content::FullNodeContent;
use crate::primitives::D256;
use crate::user::{User, UserId};
use crate::inclusion_proof::InclusionProof;
use crate::{RangeProofPadding, RangeVerifiable, RangeProvable};

// -------------------------------------------------------------------------------------------------
// NDM-SMT struct and methods

type Content = FullNodeContent<blake3::Hasher>;

/// Main struct containing tree object, master secret and the salts.
/// The user mapping structure is required because it is non-deterministic.
#[allow(dead_code)]
pub struct NdmSmt {
    master_secret: D256,
    salt_b: D256,
    salt_s: D256,
    tree: SparseBinaryTree<Content>,
    user_mapping: HashMap<UserId, u64>,
}

impl NdmSmt {
    /// Constructor.
    // TODO we should probably do a check to make sure the UserIDs are all unique, but not sure if this check should be here or in calling code
    #[allow(dead_code)]
    pub fn new(
        master_secret: D256,
        salt_b: D256,
        salt_s: D256,
        height: u8,
        users: Vec<User>,
    ) -> Result<Self, NdmSmtError> {
        let master_secret_bytes = master_secret.as_bytes();
        let salt_b_bytes = salt_b.as_bytes();
        let salt_s_bytes = salt_s.as_bytes();

        // closure that is used to create new padding nodes
        // TODO check how much copying is going on in this closure, maybe we can optimize
        let new_padding_node_content = |coord: &Coordinate| {
            let coord_bytes = coord.as_bytes();
            // pad_secret_bytes is given as 'w' in the DAPOL+ paper
            let pad_secret = generate_key(master_secret_bytes, &coord_bytes);
            let pad_secret_bytes: [u8; 32] = pad_secret.into();
            let blinding_factor = generate_key(&pad_secret_bytes, salt_b_bytes);
            let salt = generate_key(&pad_secret_bytes, salt_s_bytes);
            Content::new_pad(blinding_factor.into(), coord, salt.into())
        };

        let mut x_coord_generator = RandomXCoordGenerator::new(height);
        let mut leaves = Vec::new();
        let mut user_mapping = HashMap::new();
        let mut i = 0;

        for user in users.into_iter() {
            let x_coord = x_coord_generator.new_unique_x_coord(i as u64)?;
            i = i + 1;

            let w = generate_key(master_secret_bytes, &x_coord.to_le_bytes());
            let w_bytes: [u8; 32] = w.into();
            let blinding_factor = generate_key(&w_bytes, salt_b_bytes);
            let user_salt = generate_key(&w_bytes, salt_s_bytes);

            leaves.push(InputLeafNode {
                content: Content::new_leaf(
                    user.liability,
                    blinding_factor.into(),
                    user.id.clone(),
                    user_salt.into(),
                ),
                x_coord,
            });

            user_mapping.insert(user.id, x_coord);
        }

        let tree = SparseBinaryTree::new(leaves, height, &new_padding_node_content)?;

        Ok(NdmSmt {
            tree,
            master_secret,
            salt_b,
            salt_s,
            user_mapping,
        })
    }

    // STENT TODO why have the proof generation logic here?
    //   Because the range proof is specific to the node content, which is selected for in this file
    pub fn generate_inclusion_proof(&self, user_id: &UserId) -> Result<InclusionProof<Content>, NdmSmtError> {
        let leaf_x_coord = self.user_mapping.get(user_id).ok_or(NdmSmtError::UserIdNotFound)?;

        let nodes = self.tree.get_path_nodes(*leaf_x_coord)?;

        let secrets: Vec<u64> = nodes.0.iter().map(|node| {
           node.get_content().get_liability()
        }).collect();
        let blindings: Vec<curve25519_dalek_ng::scalar::Scalar> = nodes.0.iter().map(|node| {
            node.get_content().get_blinding_factor()
        }).collect();
        let aggregation_factor = 2usize; // STENT TODO make generic

        let siblings = self.tree.get_siblings_for_path(*leaf_x_coord)?;
        let range_proof = RangeProofPadding::generate_proof(&secrets, &blindings, aggregation_factor);

        // STENT TODO the sibling nodes should be converted to the compressed node type, otherwise they give away information
        Ok(InclusionProof::new(siblings, range_proof))
    }
}

#[derive(Error, Debug)]
pub enum NdmSmtError {
    #[error("Problem constructing the tree")]
    TreeError(#[from] SparseBinaryTreeError),
    #[error("Number of users cannot be bigger than 2^height")]
    HeightTooSmall(#[from] OutOfBoundsError),
    #[error("Inclusion proof generation failed when trying to produce the siblings for the tree path")]
    InclusionProofPathGenerationError(#[from] PathError),
    #[error("User ID not found in the user mapping")]
    UserIdNotFound,
}

// -------------------------------------------------------------------------------------------------
// Random shuffle algorithm

/// Used for generating x-coordinate values on the bottom layer of the tree.
///
/// A struct is needed is because the algorithm used to generate new values keeps a memory of
/// previously used values so that it can generate new ones randomly different from previous ones.
///
/// The map is necessary for the algorithm used to get new unique values.
struct RandomXCoordGenerator {
    map: HashMap<u64, u64>,
    max_value: u64,
    rng: ThreadRng,
}

impl RandomXCoordGenerator {
    /// Constructor.
    ///
    /// The max value is the max number of bottom-layer leaves for the given height because we are trying to
    /// generate x-coords on the bottom layer of the tree.
    fn new(height: u8) -> Self {
        use crate::binary_tree::num_bottom_layer_nodes;

        RandomXCoordGenerator {
            map: HashMap::<u64, u64>::new(),
            max_value: num_bottom_layer_nodes(height),
            rng: thread_rng(),
        }
    }

    /// Durstenfeld’s shuffle algorithm optimized by HashMap.
    ///
    /// TODO put this into latex
    /// Iterate over i:
    /// - pick random k in range [i, max_value]
    /// - if k in map then set v = map[k]
    ///   - while v = map[v] exists
    ///   - result = v
    /// - else result = k
    /// - set map[k] = i
    ///
    /// This algorithm provides a constant-time random mapping of all i's without chance of
    /// collision, as long as i <= max_value.
    fn new_unique_x_coord(&mut self, i: u64) -> Result<u64, OutOfBoundsError> {
        if i > self.max_value {
            return Err(OutOfBoundsError {
                max_value: self.max_value,
            });
        }

        let range = Uniform::from(i..self.max_value);
        let k = self.rng.sample(range);

        let x = match self.map.get(&k) {
            Some(mut existing_x) => {
                // follow the full chain of linked numbers until we find the leaf
                while self.map.contains_key(existing_x) {
                    existing_x = self.map.get(existing_x).unwrap();
                }
                existing_x.clone()
            }
            None => k,
        };

        self.map.insert(k, i);
        Ok(x)
    }
}

#[derive(Error, Debug)]
#[error("Counter i cannot exceed max value {max_value:?}")]
pub struct OutOfBoundsError {
    max_value: u64,
}

// -------------------------------------------------------------------------------------------------
// Unit tests

// TODO test that the tree error propagates correctly (how do we mock in rust?)
// TODO we should fuzz on these tests because the code utilizes a random number generator
#[cfg(test)]
mod tests {
    mod ndm_smt {
        use std::str::FromStr;

        use super::super::*;

        #[test]
        fn constructor_works() {
            let master_secret: D256 = 1u64.into();
            let salt_b: D256 = 2u64.into();
            let salt_s: D256 = 3u64.into();
            let height = 4u8;
            let users = vec![User {
                liability: 5u64,
                id: UserId::from_str("some user").unwrap(),
            }];

            NdmSmt::new(master_secret, salt_b, salt_s, height, users).unwrap();
        }
    }

    mod random_x_coord_generator {
        use std::collections::HashSet;

        use super::super::{OutOfBoundsError, RandomXCoordGenerator};
        use crate::binary_tree::num_bottom_layer_nodes;

        #[test]
        fn constructor_works() {
            let height = 4u8;
            RandomXCoordGenerator::new(height);
        }

        #[test]
        fn new_unique_value_works() {
            let height = 4u8;
            let mut rxcg = RandomXCoordGenerator::new(height);
            for i in 0..num_bottom_layer_nodes(height) {
                rxcg.new_unique_x_coord(i).unwrap();
            }
        }

        #[test]
        fn generated_values_all_unique() {
            let height = 4u8;
            let mut rxcg = RandomXCoordGenerator::new(height);
            let mut set = HashSet::<u64>::new();
            for i in 0..num_bottom_layer_nodes(height) {
                let x = rxcg.new_unique_x_coord(i).unwrap();
                if set.contains(&x) {
                    panic!("{:?} was generated twice!", x);
                }
                set.insert(x);
            }
        }

        #[test]
        fn new_unique_value_fails_for_large_i() {
            use crate::testing_utils::assert_err;

            let height = 4u8;
            let max = num_bottom_layer_nodes(height);
            let mut rxcg = RandomXCoordGenerator::new(height);
            let res = rxcg.new_unique_x_coord(max + 1);

            assert_err!(res, Err(OutOfBoundsError { max_value: max }));
        }
    }
}
