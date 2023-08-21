//! An implementation of the content generic type required for [crate][binary_tree][`Node<C>`].
//!
//! This implementation contains the values in the [super][TODO link to compressed] implementation
//! (Pedersen commitment & hash) plus the additional private values (blinding factor and plain text
//! liability). The private values are included so that the total blinding factor & liability sum
//! can be accessed after tree construction. This node type should ideally not be used in
//! the serialization process since it will increase the final byte size and expose the secret
//! values.

use crate::binary_tree::Mergeable;

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::Digest;
use std::marker::PhantomData;
use primitive_types::H256;

use super::compressed_node::H256Convertable;

// DAPOL NODE
// ================================================================================================

/// A node of the DAPOL tree, consisting of the value, the blinding factor,
/// the Pedersen commitment and the hash.
#[derive(Default, Clone, Debug)]
pub struct FullNodeContent<H> {
    liability: u64,
    blinding_factor: Scalar,
    commitment: RistrettoPoint,
    hash: H256,
    _phantom_hash_function: PhantomData<H>, // STENT TODO is this needed?
}

impl<H: Digest + H256Convertable> FullNodeContent<H> {
    /// Constructor.
    ///
    /// The secret `value` realistically does not need more space than 64 bits because it is
    /// generally used for monetary value or head count, also the Bulletproofs library requires
    /// the value to be u64.
    /// The `blinding_factor` needs to have a larger sized storage space (256 bits) ensure promised
    /// n-bit security of the commitments; it can be enlarged to 512 bits if need be as this size
    /// is supported by the underlying `Scalar` constructors.
    pub fn new_leaf(value: u64, blinding_factor: [u8; 32], user_id: [u8; 32], user_salt: [u8; 32]) -> FullNodeContent<H> {
        use bulletproofs::PedersenGens;

        let blinding_factor_scalar = Scalar::from_bytes_mod_order(blinding_factor);

        // Compute the Pedersen commitment to the value `P = g_1^value * g_2^blinding_factor`
        let commitment = PedersenGens::default().commit(Scalar::from(value), Scalar::from_bytes_mod_order(blinding_factor));

        // Compute the hash: `H("leaf" | user_id | user_salt)`
        let mut hasher = H::new();
        hasher.update("leaf".as_bytes());
        hasher.update(user_id);
        hasher.update(user_salt);
        let hash = hasher.finalize_as_h256();

        FullNodeContent {
            liability: value,
            blinding_factor: blinding_factor_scalar,
            commitment,
            hash,
            _phantom_hash_function: PhantomData,
        }
    }

    /// Returns the liability of this node.
    pub fn get_liability(&self) -> u64 {
        self.liability
    }

    /// Returns the blinding factor of this node.
    pub fn get_blinding_factor(&self) -> Scalar {
        self.blinding_factor
    }
}

impl<H: Digest + H256Convertable> Mergeable for FullNodeContent<H> {
    /// Returns the parent node content by merging two child nodes.
    ///
    /// The value and blinding factor of the parent are the sums of the two children respectively.
    /// The commitment of the parent is the homomorphic sum of the two children.
    /// The hash of the parent is computed by hashing the concatenated commitments and hashes of two children.
    fn merge(lch: &FullNodeContent<H>, rch: &FullNodeContent<H>) -> FullNodeContent<H> {
        // H(parent) = Hash(C(L) || C(R) || H(L) || H(R))
        let mut hasher = H::new();
        hasher.update(lch.commitment.compress().as_bytes());
        hasher.update(rch.commitment.compress().as_bytes());
        hasher.update(&lch.hash);
        hasher.update(&rch.hash);

        FullNodeContent {
            liability: lch.liability + rch.liability,
            blinding_factor: lch.blinding_factor + rch.blinding_factor,
            commitment: lch.commitment + rch.commitment,
            hash: hasher.finalize_as_h256(),
            _phantom_hash_function: PhantomData,
        }
    }
}

// STENT TODO should fuzz the values instead of hard-coding
#[cfg(test)]
mod tests {
    use super::*;

    // STENT TODO this seems a bit hacky, maybe there is a better way?
    // NOTE this is only for little endian bytes, which Scalar uses
    fn extend_bytes(bytes: [u8; 8]) -> [u8; 32] {
        let mut new_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        for i in 0..bytes.len() {
            new_bytes[i] = bytes[i];
        }
        new_bytes
    }

    #[test]
    fn constructor_works() {
        let liability = 11u64;
        let mut blinding_factor = 7u64;
        FullNodeContent::<blake3::Hasher>::new(
            liability,
            extend_bytes(blinding_factor.to_le_bytes()),
        );
    }

    #[test]
    fn merge_works() {
        let liability_1 = 11u64;
        let mut blinding_factor_1 = 7u64;
        let node_1 = FullNodeContent::<blake3::Hasher>::new(
            liability_1,
            extend_bytes(blinding_factor_1.to_le_bytes()),
        );

        let liability_2 = 11u64;
        let mut blinding_factor_2 = 7u64;
        let node_2 = FullNodeContent::<blake3::Hasher>::new(
            liability_2,
            extend_bytes(blinding_factor_2.to_le_bytes()),
        );

        FullNodeContent::merge(&node_1, &node_2);
    }
}

// =================================================
// can probably remove all this

// use smtree::{
//     index::TreeIndex,
//     pad_secret::Secret,
//     traits::{Paddable, ProofExtractable, Rand, TypeName},
// };
// use rand::{thread_rng, Rng};

// STENT TODO this is not needed anymore, the padding function definition should live somewhere else
// impl<H: Digest> Paddable for FullNodeContent<H> {
//     /// Returns a padding node with value 0 and a random blinding factor.
//     /// TODO: check with Kostas if this padding is ok.
//     fn padding(_idx: &TreeIndex, _secret: &Secret) -> FullNodeContent<H> {
//         FullNodeContent::<H>::new(0, Scalar::random(&mut thread_rng()))
//     }
// }

// STENT TODO this conversion does need to happen but not sure how I want to do it yet
//   most likely the tree code will have a conversion function that takes a generic C' type
//   that implements the convert_node trait or something, then can define convert_node here
// impl<H> ProofExtractable for FullNodeContent<H> {
//     type ProofNode = DapolProofNode<H>;
//     fn get_proof_node(&self) -> Self::ProofNode {
//         DapolProofNode::new(self.commitment, self.hash.clone())
//     }
// }

// STENT TODO not sure we need this anymore, seems to only be used for testing
// impl<H: Digest> Rand for FullNodeContent<H> {
//     /// Randomly generates a DAPOL node with random value and random blinding factor.
//     fn randomize(&mut self) {
//         // The value shouldn't be generated as u64 to prevent overflow of sums.
//         let tmp: u32 = thread_rng().gen();
//         *self = FullNodeContent::<H>::new(tmp as u64, Scalar::random(&mut thread_rng()));
//     }
// }

// // STENT TODO why do we need this?
// impl<H: TypeName> TypeName for FullNodeContent<H> {
//     /// Returns the type name of DAPOL nodes with corresponding hash function (for logging purpose).
//     fn get_name() -> String {
//         format!("DAPOL Node ({})", D::get_name())
//     }
// }

// // STENT TODO why partial eq defined like this? what is partial eq actually supposed to do?
// impl<H> PartialEq for FullNodeContent<H> {
//     /// Two DAPOL nodes are considered equal iff the values are equal.
//     fn eq(&self, other: &Self) -> bool {
//         self.liability == other.liability
//     }
// }
