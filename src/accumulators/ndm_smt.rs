use std::collections::HashMap;

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use primitive_types::H256;
use serde::{Deserialize, Serialize};

use log::{error, info};
use logging_timer::{timer, Level};

use rayon::prelude::*;

use crate::{
    binary_tree::{
        BinaryTree, BinaryTreeBuilder, Coordinate, FullNodeContent, Height, InputLeafNode,
        PathSiblings,
    },
    entity::{Entity, EntityId},
    inclusion_proof::{AggregationFactor, InclusionProof},
    kdf, MaxThreadCount, Salt, Secret,
};

mod x_coord_generator;
pub use x_coord_generator::RandomXCoordGenerator;

// -------------------------------------------------------------------------------------------------
// Main struct and implementation.

type Content = FullNodeContent;

/// Non-Deterministic Mapping Sparse Merkle Tree (NDM-SMT) accumulator type.
///
/// This accumulator variant is the simplest. Each entity is randomly mapped to
/// a bottom-layer node in the tree. The algorithm used to determine the mapping
/// uses a variation of Durstenfeld’s shuffle algorithm (see
/// [RandomXCoordGenerator]) and will not produce the same mapping for the same
/// inputs, hence the "non-deterministic" term in the title.
///
/// Construction of this tree can be done via [NdmSmtConfigBuilder].
///
/// The struct contains a tree object, secrets used for construction, and an
/// entity mapping.
///
/// The entity mapping structure is required because each entity is randomly
/// mapped to a leaf node, and this assignment is non-deterministic. The map
/// keeps track of which entity is assigned to which leaf node.

#[derive(Debug, Serialize, Deserialize)]
pub struct NdmSmt {
    binary_tree: BinaryTree<Content>,
    entity_mapping: HashMap<EntityId, u64>,
}

impl NdmSmt {
    /// Constructor.
    ///
    /// Parameters:
    /// - `master_secret`:
    #[doc = include_str!("../shared_docs/master_secret.md")]
    /// - `salt_b`:
    #[doc = include_str!("../shared_docs/salt_b.md")]
    /// - `salt_s`:
    #[doc = include_str!("../shared_docs/salt_s.md")]
    /// - `height`:
    #[doc = include_str!("../shared_docs/height.md")]
    /// - `max_thread_count`:
    #[doc = include_str!("../shared_docs/max_thread_count.md")]
    /// - `entities`:
    #[doc = include_str!("../shared_docs/entities_vector.md")]
    /// Each element in `entities` is converted to an
    /// [input leaf node] and randomly assigned a position on the
    /// bottom layer of the tree.
    ///
    /// An [NdmSmtError] is returned if:
    /// 1. There are more entities than the height allows i.e. more entities
    /// than would fit on the bottom layer.
    /// 2. The tree build fails for some reason.
    /// 3. There are duplicate entity IDs.
    ///
    /// The function will panic if there is a problem joining onto a spawned
    /// thread, or if concurrent variables are not able to be locked. It's not
    /// clear how to recover from these scenarios because variables may be in
    /// an unknown state, so rather panic.
    ///
    /// [input leaf node]: crate::binary_tree::InputLeafNode
    pub fn new(
        master_secret: Secret,
        salt_b: Salt,
        salt_s: Salt,
        height: Height,
        max_thread_count: MaxThreadCount,
        entities: Vec<Entity>,
    ) -> Result<Self, NdmSmtError> {
        let master_secret_bytes = master_secret.as_bytes();
        let salt_b_bytes = salt_b.as_bytes();
        let salt_s_bytes = salt_s.as_bytes();

        info!(
            "\nCreating NDM-SMT with the following configuration:\n \
             - height: {}\n \
             - number of entities: {}\n \
             - master secret: <REDACTED>\n \
             - salt b: 0x{}\n \
             - salt s: 0x{}",
            height.as_u32(),
            entities.len(),
            salt_b_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
            salt_s_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
        );

        let (leaf_nodes, entity_coord_tuples) = {
            // Map the entities to bottom-layer leaf nodes.

            let tmr = timer!(Level::Debug; "Entity to leaf node conversion");

            let mut x_coord_generator = RandomXCoordGenerator::new(&height);
            let mut x_coords = Vec::<u64>::with_capacity(entities.len());

            for _i in 0..entities.len() {
                x_coords.push(x_coord_generator.new_unique_x_coord()?);
            }

            let entity_coord_tuples = entities
                .into_iter()
                .zip(x_coords.into_iter())
                .collect::<Vec<(Entity, u64)>>();

            let leaf_nodes = entity_coord_tuples
                .par_iter()
                .map(|(entity, x_coord)| {
                    // `w` is the letter used in the DAPOL+ paper.
                    let entity_secret: [u8; 32] =
                        kdf::generate_key(None, master_secret_bytes, Some(&x_coord.to_le_bytes()))
                            .into();
                    let blinding_factor =
                        kdf::generate_key(Some(salt_b_bytes), &entity_secret, None);
                    let entity_salt = kdf::generate_key(Some(salt_s_bytes), &entity_secret, None);

                    InputLeafNode {
                        content: Content::new_leaf(
                            entity.liability,
                            blinding_factor.into(),
                            entity.id.clone(),
                            entity_salt.into(),
                        ),
                        x_coord: *x_coord,
                    }
                })
                .collect::<Vec<InputLeafNode<Content>>>();

            logging_timer::finish!(
                tmr,
                "Leaf nodes have length {} and size {} bytes",
                leaf_nodes.len(),
                std::mem::size_of_val(&*leaf_nodes)
            );

            (leaf_nodes, entity_coord_tuples)
        };

        // Create a map of EntityId -> XCoord, return an error if a duplicate
        // entity ID is found.
        let mut entity_mapping = HashMap::with_capacity(entity_coord_tuples.len());
        for (entity, x_coord) in entity_coord_tuples.into_iter() {
            if entity_mapping.contains_key(&entity.id) {
                return Err(NdmSmtError::DuplicateEntityIds(entity.id));
            }
            entity_mapping.insert(entity.id, x_coord);
        }

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .with_max_thread_count(max_thread_count)
            .build_using_multi_threaded_algorithm(new_padding_node_content_closure(
                *master_secret_bytes,
                *salt_b_bytes,
                *salt_s_bytes,
            ))?;

        Ok(NdmSmt {
            binary_tree: tree,
            entity_mapping,
        })
    }

    /// Generate an inclusion proof for the given `entity_id`.
    ///
    /// The NdmSmt struct defines the content type that is used, and so must
    /// define how to extract the secret value (liability) and blinding
    /// factor for the range proof, which are both required for the range
    /// proof that is done in the [InclusionProof] constructor.
    ///
    /// Parameters:
    /// - `master_secret`:
    #[doc = include_str!("../shared_docs/master_secret.md")]
    /// - `salt_b`:
    #[doc = include_str!("../shared_docs/salt_b.md")]
    /// - `salt_s`:
    #[doc = include_str!("../shared_docs/salt_s.md")]
    /// - `entity_id`: unique ID for the entity that the proof will be generated for.
    /// - `aggregation_factor` is used to determine how many of the range proofs
    /// are aggregated. Those that do not form part of the aggregated proof
    /// are just proved individually. The aggregation is a feature of the
    /// Bulletproofs protocol that improves efficiency.
    /// - `upper_bound_bit_length`:
    #[doc = include_str!("../shared_docs/upper_bound_bit_length.md")]
    pub fn generate_inclusion_proof(
        &self,
        master_secret: &Secret,
        salt_b: &Salt,
        salt_s: &Salt,
        entity_id: &EntityId,
        aggregation_factor: AggregationFactor,
        upper_bound_bit_length: u8,
    ) -> Result<InclusionProof, NdmSmtError> {
        let master_secret_bytes = master_secret.as_bytes();
        let salt_b_bytes = salt_b.as_bytes();
        let salt_s_bytes = salt_s.as_bytes();
        let new_padding_node_content =
            new_padding_node_content_closure(*master_secret_bytes, *salt_b_bytes, *salt_s_bytes);

        let leaf_node = self
            .entity_mapping
            .get(entity_id)
            .and_then(|leaf_x_coord| self.binary_tree.get_leaf_node(*leaf_x_coord))
            .ok_or(NdmSmtError::EntityIdNotFound)?;

        let path_siblings = PathSiblings::build_using_multi_threaded_algorithm(
            &self.binary_tree,
            &leaf_node,
            new_padding_node_content,
        )?;

        Ok(InclusionProof::generate(
            leaf_node,
            path_siblings,
            aggregation_factor,
            upper_bound_bit_length,
        )?)
    }

    #[doc = include_str!("../shared_docs/root_hash.md")]
    pub fn root_hash(&self) -> &H256 {
        &self.binary_tree.root().content.hash
    }

    #[doc = include_str!("../shared_docs/root_hash.md")]
    pub fn root_commitment(&self) -> &RistrettoPoint {
        &self.binary_tree.root().content.commitment
    }

    #[doc = include_str!("../shared_docs/root_liability.md")]
    pub fn root_liability(&self) -> u64 {
        self.binary_tree.root().content.liability
    }

    #[doc = include_str!("../shared_docs/root_blinding_factor.md")]
    pub fn root_blinding_factor(&self) -> &Scalar {
        &self.binary_tree.root().content.blinding_factor
    }

    /// Hash map giving the x-coord that each entity is mapped to.
    pub fn entity_mapping(&self) -> &HashMap<EntityId, u64> {
        &self.entity_mapping
    }

    #[doc = include_str!("../shared_docs/height.md")]
    pub fn height(&self) -> &Height {
        self.binary_tree.height()
    }
}

// -------------------------------------------------------------------------------------------------
// Helper functions.

/// Create a new closure that generates padding node content using the secret
/// values.
fn new_padding_node_content_closure(
    master_secret_bytes: [u8; 32],
    salt_b_bytes: [u8; 32],
    salt_s_bytes: [u8; 32],
) -> impl Fn(&Coordinate) -> Content {
    // closure that is used to create new padding nodes
    move |coord: &Coordinate| {
        // TODO unfortunately we copy data here, maybe there is a way to do without
        // copying
        let coord_bytes = coord.to_bytes();
        // pad_secret is given as 'w' in the DAPOL+ paper
        let pad_secret = kdf::generate_key(None, &master_secret_bytes, Some(&coord_bytes));
        let pad_secret_bytes: [u8; 32] = pad_secret.into();
        let blinding_factor = kdf::generate_key(Some(&salt_b_bytes), &pad_secret_bytes, None);
        let salt = kdf::generate_key(Some(&salt_s_bytes), &pad_secret_bytes, None);
        Content::new_pad(blinding_factor.into(), coord, salt.into())
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when handling [NdmSmt].
#[derive(thiserror::Error, Debug)]
pub enum NdmSmtError {
    #[error("Problem constructing the tree")]
    TreeError(#[from] crate::binary_tree::TreeBuildError),
    #[error("Number of entities cannot be bigger than 2^(height-1)")]
    HeightTooSmall(#[from] x_coord_generator::OutOfBoundsError),
    #[error("Inclusion proof generation failed when trying to build the path in the tree")]
    InclusionProofPathSiblingsGenerationError(#[from] crate::binary_tree::PathSiblingsBuildError),
    #[error("Inclusion proof generation failed")]
    InclusionProofGenerationError(#[from] crate::inclusion_proof::InclusionProofError),
    #[error("Entity ID not found in the entity mapping")]
    EntityIdNotFound,
    #[error("Entity ID {0:?} was duplicated")]
    DuplicateEntityIds(EntityId),
}

// -------------------------------------------------------------------------------------------------
// Unit tests.

// TODO test that the tree error propagates correctly (how do we mock in rust?)
// TODO we should fuzz on these tests because the code utilizes a random number
// generator
// TODO test that duplicate entity IDs gives an error on NdmSmt::new
// TODO test serialization & deserialization
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use std::str::FromStr;

    #[test]
    fn constructor_works() {
        let master_secret: Secret = 1u64.into();
        let salt_b: Salt = 2u64.into();
        let salt_s: Salt = 3u64.into();

        let height = Height::expect_from(4u8);
        let max_thread_count = MaxThreadCount::default();
        let entities = vec![Entity {
            liability: 5u64,
            id: EntityId::from_str("some entity").unwrap(),
        }];

        NdmSmt::new(
            master_secret,
            salt_b,
            salt_s,
            height,
            max_thread_count,
            entities,
        )
        .unwrap();
    }
}
