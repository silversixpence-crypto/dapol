use bulletproofs::{PedersenGens, RangeProof};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar};
use smtree::{
    error::DecodingError,
    traits::{Serializable, TypeName},
    utils::usize_to_bytes,
};
use std::cmp::Ordering;

// STENT what is 'super'?
use super::{
    deserialize_aggregated_proof, deserialize_individual_proofs, generate_aggregated_range_proof,
    generate_single_range_proof, verify_aggregated_range_proof, verify_single_range_proof,
    RangeProvable, RangeVerifiable, INDIVIDUAL_NUM_BYTE_NUM, PROOF_SIZE_BYTE_NUM,
};

// RANGE PROOF PADDING
// ================================================================================================

// STENT seems the 2 values here have the same data but one has all individual proofs and the other has them aggregated into 1 proof.
//
//   We likely want to have functionality that allows a certain % of the top of the tree to be individual proofs
//   and the rest individual, where the % is set by the exchange in order to get the sweet spot of proving time VS proof size.
//
//   Also we probably don't want to be computing both range and individual proofs at the same time like this
//   (see generate_proof function further down to see that both fields are populated)
//   NVM! That is exactly what the 'aggregation_factor' param is for

#[derive(Debug, Clone)]
pub struct RangeProofPadding {
    aggregated: Vec<RangeProof>,
    individual: Vec<RangeProof>,
}

impl RangeProofPadding {
    // STENT what is the point of this function? It just returns the first element, but why?
    //   there is also an interesting thing to note in splitting.rs: get_aggregated returns the whole vec
    pub fn get_aggregated(&self) -> &RangeProof {
        if self.aggregated.is_empty() {
            panic!(); // TODO
        }
        &self.aggregated[0]
    }

    // STENT this also seems pointless; if the struct is public can't the fields be accessed with dot notation?
    pub fn get_individual(&self) -> &Vec<RangeProof> {
        &self.individual
    }
}

// STENT should look at other impl for Serializable to get an idea of what good code looks like
//   this code uses a lot of mut refs and I don't know if that is good rust
impl Serializable for RangeProofPadding {
    /// (aggregated_size || aggregated_proof) || (individual_num || proof_1 || ...)
    fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        let mut bytes = self.get_aggregated().to_bytes();

        result.append(&mut usize_to_bytes(bytes.len(), PROOF_SIZE_BYTE_NUM));
        result.append(&mut bytes);
        result.append(&mut usize_to_bytes(
            self.get_individual().len(),
            INDIVIDUAL_NUM_BYTE_NUM,
        ));
        for proof in self.get_individual() {
            result.append(&mut proof.to_bytes());
        }
        result
    }

    fn deserialize_as_a_unit(bytes: &[u8], begin: &mut usize) -> Result<Self, DecodingError> {
        let aggregated = deserialize_aggregated_proof(&bytes, begin)?;
        let individual = deserialize_individual_proofs(bytes, begin)?;
        Ok(RangeProofPadding {
            aggregated: vec![aggregated],
            individual,
        })
    }

    /// (aggregated_size || aggregated_proof) || (individual_num || proof_1 || ...)
    fn deserialize(bytes: &[u8]) -> Result<Self, DecodingError> {
        let mut begin = 0;
        Self::deserialize_as_a_unit(bytes, &mut begin)
    }
}

impl TypeName for RangeProofPadding {
    fn get_name() -> String {
        "Rang Proof by Padding".to_owned()
    }
}

impl RangeProvable for RangeProofPadding {
    fn new(aggregated: &[RangeProof], individual: &[RangeProof]) -> Self {
        if aggregated.len() > 1 {
            panic!(); //TODO
        }
        RangeProofPadding {
            aggregated: aggregated.to_vec(),
            individual: individual.to_vec(),
        }
    }

    // STENT note that the proofs are split up: [0..aggregated] are aggregated and [aggregated..-1] are individual
    //   what is interesting is that the order matters here so maybe best to adjust the code so that there is not
    //   this implicit dependency on the ordering, which could easily be messed up by other code not expecting that ordering
    fn generate_proof(
        _secrets: &[u64],
        _blindings: &[Scalar],
        aggregated: usize,
    ) -> RangeProofPadding {
        // STENT why use a vector when you can use an array because you can work out the length?
        let mut secrets = Vec::<u64>::new();
        let mut blindings = Vec::<Scalar>::new();
        // STENT surely this can be done better by using a map function? Then no mut needed.
        // STENT why is the loop over 'aggregated'? from the 'new' function this value should be <=1
        for _i in 0..aggregated {
            // STENT there is no check for the sizes of the arrays to be the same
            secrets.push(_secrets[_i]);
            blindings.push(_blindings[_i]);
        }
        let power = aggregated.next_power_of_two();
        for _i in aggregated..power {
            secrets.push(0);
            blindings.push(Scalar::one()); // STENT why 'one' and not the actual blindings? Is this not a security concern? Would it even work in verification?
        }
        // STENT so basically all that the above code does is keep the first secrets&blindings then add more as padding till the length of the vector reaches the next power of 2.
        //   Does this mean that the input _secrets&_blindings is expected not to be a power of 2?
        let aggregated_proof =
            generate_aggregated_range_proof(&secrets[0..power], &blindings[0..power]);

        let mut individual_proofs: Vec<RangeProof> = Vec::new();
        // STENT surely can have a for-loop rather and then no mut needed?
        let mut pos = aggregated;
        while pos < _secrets.len() {
            individual_proofs.push(generate_single_range_proof(_secrets[pos], &_blindings[pos]));
            pos += 1;
        }

        RangeProofPadding {
            aggregated: vec![aggregated_proof],
            individual: individual_proofs,
        }
    }

    // STENT this function seems odd:
    //   - why only produce a proof for 1 item (last item in array) if len > aggregation_factor?
    //   - why do an aggregated proof for all items if len == aggregation_factor?
    //   also, why must the proof struct exist already? i.e. not creating a new struct
    //   need to see how it's used, it seems to just append proofs
    fn generate_proof_by_new_com(
        &mut self,
        secrets: &[u64],
        blindings: &[Scalar],
        aggregation_factor: usize,
    ) {
        let len = secrets.len();
        match len.cmp(&aggregation_factor) {
            Ordering::Greater => {
                self.individual.push(generate_single_range_proof(
                    secrets[len - 1],
                    &blindings[len - 1],
                ));
            }
            Ordering::Equal => {
                let base = aggregation_factor.next_power_of_two();
                let mut _secrets = Vec::<u64>::new();
                let mut _blindings = Vec::<Scalar>::new();
                for _i in 0..len {
                    _secrets.push(secrets[_i]);
                    _blindings.push(blindings[_i]);
                }
                for _i in len..base {
                    _secrets.push(0);
                    _blindings.push(Scalar::one());
                }
                self.aggregated.push(generate_aggregated_range_proof(
                    &_secrets[..],
                    &_blindings[..],
                ));
            }
            _ => {}
        }
    }

    fn remove_proof_by_last_com(&mut self, len: usize, aggregation_factor: usize) {
        match len.cmp(&aggregation_factor) {
            Ordering::Greater => {
                self.individual.pop();
            }
            Ordering::Equal => {
                self.aggregated.pop();
            }
            _ => {}
        }
    }
}

impl RangeVerifiable for RangeProofPadding {
    fn verify(&self, _commitments: &[CompressedRistretto]) -> bool {
        let mut commitments = Vec::<CompressedRistretto>::new();
        let aggregated = _commitments.len() - self.individual.len(); // STENT could be negative
                                                                     // STENT is there not a better way to do this with slice types?
        for item in _commitments.iter().take(aggregated) {
            // STENT what is the asterisk for? Is it a memory de-reference?
            commitments.push(*item);
        }
        let power = aggregated.next_power_of_two();
        let pc_gens = PedersenGens::default();
        let com_padding = pc_gens.commit(Scalar::from(0u64), Scalar::one()).compress(); // STENT are we sure these should all have blinding factor 1? Yes because they were constructed that way in generate_proof
        for _i in aggregated..power {
            commitments.push(com_padding);
        }
        if !verify_aggregated_range_proof(&self.get_aggregated(), &commitments[0..power]) {
            return false;
        }

        let mut idx = 0;
        let mut pos = aggregated;
        while pos < _commitments.len() {
            if !verify_single_range_proof(&self.individual[idx], &_commitments[pos]) {
                return false;
            }
            idx += 1;
            pos += 1;
        }

        true
    }
}
