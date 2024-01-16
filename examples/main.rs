//! Example of a full PoL workflow.
//!
//! 1. Build a tree
//! 2. Generate an inclusion proof
//! 3. Verify an inclusion proof
//!
//! At the time of writing (Nov 2023) only the NDM-SMT accumulator is supported
//! so this is the only type of tree that is used in this example.

use std::path::Path;
use std::str::FromStr;

extern crate clap_verbosity_flag;
extern crate csv;
extern crate dapol;

use dapol::utils::LogOnErrUnwrap;

fn main() {
    let log_level = clap_verbosity_flag::LevelFilter::Debug;
    dapol::utils::activate_logging(log_level);

    // =========================================================================
    // Tree building.

    let accumulator_type = dapol::AccumulatorType::NdmSmt;

    let dapol_tree_1 = build_dapol_tree_using_config_builder(accumulator_type);
    let dapol_tree_2 = build_dapol_tree_using_config_file();

    // The above 2 builder methods produce a different tree because the entities
    // are mapped randomly to points on the bottom layer for NDM-SMT, but the
    // entity mapping of one tree should simply be a permutation of the other.
    // Let's check this:
    match (dapol_tree_1.accumultor(), dapol_tree_2.accumultor()) {
        (dapol::Accumulator::NdmSmt(ndm_smt_1), dapol::Accumulator::NdmSmt(ndm_smt_2)) => {
            assert_ne!(ndm_smt_1.root_hash(), ndm_smt_2.root_hash());

            for (entity, _) in ndm_smt_1.entity_mapping() {
                assert!(ndm_smt_2.entity_mapping().contains_key(&entity));
            }
        }
        _ => panic!("Expected both trees to be NDM-SMT"),
    };

    // =========================================================================
    // Inclusion proof generation & verification.

    let entity_id = dapol::EntityId::from_str("john.doe@example.com").unwrap();
    simple_inclusion_proof_generation_and_verification(&dapol_tree_1, entity_id.clone());
    advanced_inclusion_proof_generation_and_verification(&dapol_tree_1, entity_id);
}

/// Example on how to construct a DAPOL tree.
///
/// Build the tree via the config builder.
pub fn build_dapol_tree_using_config_builder(
    accumulator_type: dapol::AccumulatorType,
) -> dapol::DapolTree {
    let src_dir = env!("CARGO_MANIFEST_DIR");
    let resources_dir = Path::new(&src_dir).join("examples");

    let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
    let entities_file_path = resources_dir.join("entities_example.csv");

    let height = dapol::Height::expect_from(16u8);
    let salt_b = dapol::Salt::from_str("salt_b").unwrap();
    let salt_s = dapol::Salt::from_str("salt_s").unwrap();
    let max_liability = dapol::MaxLiability::from(10_000_000u64);
    let max_thread_count = dapol::MaxThreadCount::from(8u8);
    let master_secret = dapol::Secret::from_str("master_secret").unwrap();
    let num_entities = 100u64;

    // The builder requires at least the following to be given:
    // - accumulator_type
    // - entities
    // - secrets
    // The rest can be left to be default.
    let mut config_builder = dapol::DapolConfigBuilder::default();
    config_builder
        .accumulator_type(accumulator_type)
        .height(height.clone())
        .salt_b(salt_b.clone())
        .salt_s(salt_s.clone())
        .max_liability(max_liability.clone())
        .max_thread_count(max_thread_count.clone());

    // You only need to specify 1 of the following secret input methods.
    config_builder
        .secrets_file_path(secrets_file_path.clone())
        .master_secret(master_secret.clone());

    // You only need to specify 1 of the following entity input methods.
    config_builder
        .entities_file_path(entities_file_path.clone())
        .num_random_entities(num_entities);

    config_builder.build().unwrap().parse().unwrap()
}

/// Example on how to construct a DAPOL tree.
///
/// Build the tree using a config file.
///
/// This is also an example usage of [dapol][utils][LogOnErrUnwrap].
pub fn build_dapol_tree_using_config_file() -> dapol::DapolTree {
    let src_dir = env!("CARGO_MANIFEST_DIR");
    let resources_dir = Path::new(&src_dir).join("examples");
    let config_file = resources_dir.join("dapol_config_example.toml");

    dapol::DapolConfig::deserialize(config_file)
        .log_on_err_unwrap()
        .parse()
        .log_on_err_unwrap()
}

/// Example on how to generate and verify inclusion proofs.
///
/// An inclusion proof can be generated from only a tree + entity ID.
pub fn simple_inclusion_proof_generation_and_verification(
    dapol_tree: &dapol::DapolTree,
    entity_id: dapol::EntityId,
) {
    let inclusion_proof = dapol_tree.generate_inclusion_proof(&entity_id).unwrap();
    inclusion_proof.verify(dapol_tree.root_hash()).unwrap();
}

/// Example on how to generate and verify inclusion proofs.
///
/// The inclusion proof generation algorithm can be customized via some
/// parameters. See [dapol][InclusionProof] for more details.
pub fn advanced_inclusion_proof_generation_and_verification(
    dapol_tree: &dapol::DapolTree,
    entity_id: dapol::EntityId,
) {
    // Determines how many of the range proofs in the inclusion proof are
    // aggregated together. The ones that are not aggregated are proved
    // individually. The more that are aggregated the faster the proving
    // and verification times.
    let aggregation_percentage = dapol::percentage::ONE_HUNDRED_PERCENT;
    let aggregation_factor = dapol::AggregationFactor::Percent(aggregation_percentage);
    let aggregation_factor = dapol::AggregationFactor::default();

    // 2^upper_bound_bit_length is the upper bound used in the range proof i.e.
    // the secret value is shown to reside in the range [0, 2^upper_bound_bit_length].
    let upper_bound_bit_length = 32u8;
    let upper_bound_bit_length = dapol::DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH;

    let inclusion_proof = dapol_tree
        .generate_inclusion_proof_with(&entity_id, aggregation_factor, upper_bound_bit_length)
        .unwrap();

    inclusion_proof.verify(dapol_tree.root_hash()).unwrap();
}
