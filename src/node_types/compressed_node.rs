//! An implementation of the content generic type required for [crate][binary_tree][`Node<C>`].
//!
//! This implementation contains only the Pedersen commitment and the hash as fields in the struct.

use curve25519_dalek_ng::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::Digest;
use primitive_types::H256;
use std::marker::PhantomData;

use crate::binary_tree::Mergeable;

/// Main struct containing the Pedersen commitment & hash.
///
/// The hash function needs to be a generic parameter because when implementing
/// [crate][binary_tree][`Mergeable`] one needs to define the merge function, is not generic
/// and the merge function in this case needs to use a generic hash function. One way to
/// solve this is to have a generic parameter on this struct and a phantom field.
#[derive(Default, Clone, Debug)]
pub struct CompressedNodeContent<H> {
    commitment: RistrettoPoint,
    hash: H256,
    _phantom_hash_function: PhantomData<H>,
}

impl<H: Digest + H256Convertable> CompressedNodeContent<H> {
    /// Constructor.
    ///
    /// The secret `value` realistically does not need more space than 64 bits because it is
    /// generally used for monetary value or head count, also the Bulletproofs library requires
    /// the value to be u64.
    /// The `blinding_factor` needs to have a larger sized storage space (256 bits) ensure promised
    /// n-bit security of the commitments; it can be enlarged to 512 bits if need be as this size
    /// is supported by the underlying `Scalar` constructors.
    pub fn new_leaf(
        value: u64,
        blinding_factor: [u8; 32],
        user_id: [u8; 32],
        user_salt: [u8; 32],
    ) -> CompressedNodeContent<H> {
        use bulletproofs::PedersenGens;

        // Compute the Pedersen commitment to the value `P = g_1^value * g_2^blinding_factor`
        let commitment = PedersenGens::default().commit(
            Scalar::from(value),
            Scalar::from_bytes_mod_order(blinding_factor),
        );

        // Compute the hash: `H("leaf" | user_id | user_salt)`
        let mut hasher = H::new();
        hasher.update("leaf".as_bytes());
        hasher.update(user_id);
        hasher.update(user_salt);
        let hash = hasher.finalize_as_h256();

        CompressedNodeContent {
            commitment,
            hash,
            _phantom_hash_function: PhantomData,
        }
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
        // `C(parent) = C(L) + C(R)`
        let parent_commitment = left_sibling.commitment + right_sibling.commitment;

        // `H(parent) = Hash(C(L) | C(R) | H(L) | H(R))`
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

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

    /// This is only for little endian bytes, which `Scalar` uses.
    fn extend_to_u8_32<const A: usize, const B: usize>(arr: [u8; A]) -> [u8; B] {
        assert!(B >= A); //just for a nicer error message, adding #[track_caller] to the function may also be desirable
        let mut b = [0; B];
        b[..A].copy_from_slice(&arr);
        b
    }

    // https://stackoverflow.com/questions/71642583/rust-convert-str-to-fixedslices-array-of-u8
    fn str_to_u8_32(str: &str) -> [u8; 32] {
        let mut arr = [0u8; 32];
        arr[..str.len()].copy_from_slice(str.as_bytes());
        arr
    }

    #[test]
    fn constructor_works() {
        let liability = 11u64;
        let blinding_factor = extend_to_u8_32(7u64.to_le_bytes());
        let user_id = str_to_u8_32("some user");
        let user_salt = str_to_u8_32("some salt");

        CompressedNodeContent::<blake3::Hasher>::new_leaf(
            liability,
            blinding_factor,
            user_id,
            user_salt,
        );
    }

    #[test]
    fn merge_works() {
        let liability_1 = 11u64;
        let blinding_factor_1 = extend_to_u8_32(7u64.to_le_bytes());
        let user_id_1 = str_to_u8_32("some user 1");
        let user_salt_1 = str_to_u8_32("some salt 1");
        let node_1 = CompressedNodeContent::<blake3::Hasher>::new_leaf(
            liability_1,
            blinding_factor_1,
            user_id_1,
            user_salt_1,
        );

        let liability_2 = 11u64;
        let blinding_factor_2 = extend_to_u8_32(7u64.to_le_bytes());
        let user_id_2 = str_to_u8_32("some user 1");
        let user_salt_2 = str_to_u8_32("some salt 1");
        let node_2 = CompressedNodeContent::<blake3::Hasher>::new_leaf(
            liability_2,
            blinding_factor_2,
            user_id_2,
            user_salt_2,
        );

        CompressedNodeContent::merge(&node_1, &node_2);
    }
}
