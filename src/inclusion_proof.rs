use crate::binary_tree::{PathSiblings, Node, PathError, Mergeable};
use crate::{RangeProofPadding, RangeVerifiable};

use ::std::fmt::Debug;
use thiserror::Error;
use curve25519_dalek_ng::{ristretto::CompressedRistretto};

#[derive(Debug)]
pub struct InclusionProof<C: Clone> {
    path_siblings: PathSiblings<C>,
    range_proof: RangeProofPadding, // TODO make generic
}

impl<C: Mergeable + Clone + PartialEq + Debug> InclusionProof<C> {
    pub fn new(path_siblings: PathSiblings<C>, range_proof: RangeProofPadding) -> Self {
        InclusionProof{
            path_siblings,
            range_proof,
        }
    }

    pub fn verify(&self, root: &Node<C>, commitments: &[CompressedRistretto]) -> Result<(), InclusionProofError> {
        self.path_siblings.verify(root)?;
        self.range_proof.verify(commitments);
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum InclusionProofError {
    #[error("Siblings path verification failed")]
    TreePathError(#[from] PathError),
    #[error("Range proof verification failed")]
    RangeProofError,
}
