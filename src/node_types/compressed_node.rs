//! An implementation of the content generic type required for [crate][binary_tree][`Node<C>`].
//!
//! This implementation contains only the Pedersen commitment and the hash as fields in the struct.

use curve25519_dalek_ng::{ristretto:: RistrettoPoint, scalar::Scalar };
use bulletproofs::PedersenGens;
use digest::Digest;
use std::marker::PhantomData;
use primitive_types::H256;

use crate::binary_tree::Mergeable;

#[derive(Default, Clone, Debug)]
pub struct CompressedNodeContent<H> {
    commitment: RistrettoPoint,
    hash: H256,
    _phantom_hash_function: PhantomData<H>,
}

impl<H: Digest + H256Convertable> CompressedNodeContent<H> {
    /// Constructor.
    // STENT TODO why have value as u64 and blinding factor as scalar? As apposed to both Scalar
    pub fn new(value: u64, blinding_factor: Scalar) -> CompressedNodeContent<H> {
        // compute the Pedersen commitment to the value
        let commitment = PedersenGens::default().commit(Scalar::from(value), blinding_factor);

        // compute the hash as the hashing of the commitment
        // STENT TODO this hash is not correct, it needs to contain the id and s values
        //   this will be the same as the full node so probably useful to have this functionality shared
        let mut hasher = H::new();
        hasher.update("leaf".as_bytes());
        hasher.update(&(commitment.compress().as_bytes()));
        let hash = hasher.finalize_as_h256();

        CompressedNodeContent {
            commitment,
            hash,
            _phantom_hash_function: PhantomData,
        }
    }
}

// STENT TODO why not just have this be derived? Would the phantom data be an issue?
impl<H> PartialEq for CompressedNodeContent<H> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment && self.hash == other.hash
    }
}

// STENT TODO is this the best method for doing this?
pub trait H256Convertable {
    fn finalize_as_h256(&self) -> H256;
}

impl H256Convertable for blake3::Hasher {
    fn finalize_as_h256(&self) -> H256 {
        H256(self.finalize().as_bytes().clone())
    }
}

impl<H: Digest + H256Convertable> Mergeable for CompressedNodeContent<H> {
    fn merge(left_sibling: &Self, right_sibling: &Self) -> Self {
        // C(parent) = C(L) + C(R)
        let parent_commitment = left_sibling.commitment + right_sibling.commitment;

        // H(parent) = Hash(C(L) | C(R) | H(L) | H(R))
        let parent_hash = {
            let mut hasher = H::new();
            hasher.update(left_sibling.commitment.compress().as_bytes());
            hasher.update(right_sibling.commitment.compress().as_bytes());
            hasher.update(left_sibling.hash.as_bytes());
            hasher.update(right_sibling.hash.as_bytes());
            hasher.finalize_as_h256() // STENT TODO double check the output of this thing
        };

        CompressedNodeContent {
            commitment: parent_commitment,
            hash: parent_hash,
            _phantom_hash_function: PhantomData,
        }
    }
}


// #[cfg(test)]
// mod tests {
//     use bulletproofs::PedersenGens;
//     use curve25519_dalek_ng::scalar::Scalar;

//     use super::*;

//     #[test]
//     pub fn stent_tree_test() {
//         let height = 4;
//         let v_blinding = Scalar::from(8_u32);

//         let new_padding_node_content = |coord: &Coordinate| -> CompressedNodeContent<blake3::Hasher> {
//             CompressedNodeContent {
//                 commitment: PedersenGens::default()
//                     .commit(Scalar::from(3_u32), Scalar::from(0_u32)),
//                 hash: H256::default(),
//                 _phantom_hash_function: PhantomData,
//             }
//         };

//         let leaf_1 = InputLeafNode::<CompressedNodeContent<blake3::Hasher>> {
//             x_coord: 0,
//             content: CompressedNodeContent {
//                 hash: H256::default(),
//                 commitment: PedersenGens::default().commit(Scalar::from(0_u32), v_blinding),
//                 _phantom_hash_function: PhantomData,
//             },
//         };
//         let leaf_2 = InputLeafNode::<CompressedNodeContent<blake3::Hasher>> {
//             x_coord: 4,
//             content: CompressedNodeContent {
//                 hash: H256::default(),
//                 commitment: PedersenGens::default().commit(Scalar::from(2_u32), v_blinding),
//                 _phantom_hash_function: PhantomData,
//             },
//         };
//         let leaf_3 = InputLeafNode::<CompressedNodeContent<blake3::Hasher>> {
//             x_coord: 7,
//             content: CompressedNodeContent {
//                 hash: H256::default(),
//                 commitment: PedersenGens::default().commit(Scalar::from(3_u32), v_blinding),
//                 _phantom_hash_function: PhantomData,
//             },
//         };
//         let input = vec![leaf_1, leaf_2, leaf_3];
//         let tree = SparseSummationMerkleTree::new(input, height, &new_padding_node_content);
//         for item in &tree.store {
//             println!("coord {:?} hash {:?}", item.1.coord, item.1.content.hash);
//         }

//         println!("\n");

//         let proof = tree.create_inclusion_proof(0);
//         for item in &proof.siblings {
//             println!(
//                 "coord {:?} value {:?} hash {:?}",
//                 item.coord, item.content.commitment, item.content.hash
//             );
//         }

//         println!("\n");
//         proof.verify();
//     }
// }
