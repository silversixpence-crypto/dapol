//! An implementation of the content generic type required for [crate][binary_tree][`Node<C>`].
//! This implementation contains the values in the [super][TODO link to compressed] implementation
//! (Pedersen commitment & hash) plus the additional private values (blinding factor and plain text
//! liability). The private values are included so that the total blinding factor & liability sum
//! can be accessed after tree construction. This node type should ideally not be used in
//! the serialization process since it will increase the final byte size and expose the secret
//! values.

use crate::binary_tree::Mergeable;

use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::Digest;
use std::marker::PhantomData;

// DAPOL NODE
// ================================================================================================

/// A node of the DAPOL tree, consisting of the value, the blinding factor,
/// the Pedersen commitment and the hash.
#[derive(Default, Clone, Debug)]
pub struct FullNodeContent<D> {
    liability: u64,
    blinding_factor: Scalar,
    commitment: RistrettoPoint,
    hash: Vec<u8>, // STENT TODO this will need to change to H256 or whatever
    _phantom_hash_function: PhantomData<D>, // STENT TODO is this needed?
}

impl<D: Digest> FullNodeContent<D> {
    /// Constructor.
    pub fn new(value: u64, blinding_factor: Scalar) -> FullNodeContent<D> {
        // compute the Pedersen commitment to the value
        let commitment = PedersenGens::default().commit(Scalar::from(value), blinding_factor);

        // compute the hash as the hashing of the commitment
        let mut hasher = D::new();
        hasher.update(&(commitment.compress().as_bytes()));
        let hash = hasher.finalize().to_vec(); // STENT TODO change to below
                                               //hasher.finalize_as_h256() // STENT TODO double check the output of this thing

        FullNodeContent {
            liability: value,
            blinding_factor,
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

impl<D: Digest> Mergeable for FullNodeContent<D> {
    /// Returns the parent node content by merging two child nodes.
    ///
    /// The value and blinding factor of the parent are the sums of the two children respectively.
    /// The commitment of the parent is the homomorphic sum of the two children.
    /// The hash of the parent is computed by hashing the concatenated commitments and hashes of two children.
    fn merge(lch: &FullNodeContent<D>, rch: &FullNodeContent<D>) -> FullNodeContent<D> {
        // H(parent) = Hash(C(L) || C(R) || H(L) || H(R))
        let mut hasher = D::new();
        hasher.update(lch.commitment.compress().as_bytes());
        hasher.update(rch.commitment.compress().as_bytes());
        hasher.update(&lch.hash);
        hasher.update(&rch.hash);

        FullNodeContent {
            liability: lch.liability + rch.liability,
            blinding_factor: lch.blinding_factor + rch.blinding_factor,
            commitment: lch.commitment + rch.commitment,
            hash: hasher.finalize().to_vec(),
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
            Scalar::from_canonical_bytes(extend_bytes(blinding_factor.to_le_bytes())).unwrap(),
        );
    }

    #[test]
    fn merge_works() {
        let liability_1 = 11u64;
        let mut blinding_factor_1 = 7u64;
        let node_1 = FullNodeContent::<blake3::Hasher>::new(
            liability_1,
            Scalar::from_canonical_bytes(extend_bytes(blinding_factor_1.to_le_bytes())).unwrap(),
        );

        let liability_2 = 11u64;
        let mut blinding_factor_2 = 7u64;
        let node_2 = FullNodeContent::<blake3::Hasher>::new(
            liability_2,
            Scalar::from_canonical_bytes(extend_bytes(blinding_factor_2.to_le_bytes())).unwrap(),
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
// impl<D: Digest> Paddable for FullNodeContent<D> {
//     /// Returns a padding node with value 0 and a random blinding factor.
//     /// TODO: check with Kostas if this padding is ok.
//     fn padding(_idx: &TreeIndex, _secret: &Secret) -> FullNodeContent<D> {
//         FullNodeContent::<D>::new(0, Scalar::random(&mut thread_rng()))
//     }
// }

// STENT TODO this conversion does need to happen but not sure how I want to do it yet
//   most likely the tree code will have a conversion function that takes a generic C' type
//   that implements the convert_node trait or something, then can define convert_node here
// impl<D> ProofExtractable for FullNodeContent<D> {
//     type ProofNode = DapolProofNode<D>;
//     fn get_proof_node(&self) -> Self::ProofNode {
//         DapolProofNode::new(self.commitment, self.hash.clone())
//     }
// }

// STENT TODO not sure we need this anymore, seems to only be used for testing
// impl<D: Digest> Rand for FullNodeContent<D> {
//     /// Randomly generates a DAPOL node with random value and random blinding factor.
//     fn randomize(&mut self) {
//         // The value shouldn't be generated as u64 to prevent overflow of sums.
//         let tmp: u32 = thread_rng().gen();
//         *self = FullNodeContent::<D>::new(tmp as u64, Scalar::random(&mut thread_rng()));
//     }
// }

// // STENT TODO why do we need this?
// impl<D: TypeName> TypeName for FullNodeContent<D> {
//     /// Returns the type name of DAPOL nodes with corresponding hash function (for logging purpose).
//     fn get_name() -> String {
//         format!("DAPOL Node ({})", D::get_name())
//     }
// }

// // STENT TODO why partial eq defined like this? what is partial eq actually supposed to do?
// impl<D> PartialEq for FullNodeContent<D> {
//     /// Two DAPOL nodes are considered equal iff the values are equal.
//     fn eq(&self, other: &Self) -> bool {
//         self.liability == other.liability
//     }
// }
