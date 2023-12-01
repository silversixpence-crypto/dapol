use std::fs::{self};
use std::path::PathBuf;
use dapol::accumulators::{NdmSmt, NdmSmtConfigBuilder};
use dapol::read_write_utils;
use dapol::{EntityId, Height, InclusionProof, MaxThreadCount};

// CONSTANTS
// ================================================================================================

pub const TREE_HEIGHTS: [u8; 3] = [16, 32, 64];
pub const NUM_USERS: [u64; 35] = [
    10_000,
    20_000,
    30_000,
    40_000,
    50_000,
    60_000,
    70_000,
    80_000,
    90_000,
    100_000,
    200_000,
    300_000,
    400_000,
    500_000,
    600_000,
    700_000,
    800_000,
    900_000,
    1_000_000,
    2_000_000,
    3_000_000,
    4_000_000,
    5_000_000,
    6_000_000,
    7_000_000,
    8_000_000,
    9_000_000,
    10_000_000,
    30_000_000,
    50_000_000,
    70_000_000,
    90_000_000,
    100_000_000,
    125_000_000,
    250_000_000,
];

// HELPER FUNCTIONS
// ================================================================================================

pub fn build_ndm_smt(tup: (Height, MaxThreadCount, u64)) -> NdmSmt {
    NdmSmtConfigBuilder::default()
        .height(tup.0)
        .max_thread_count(tup.1)
        .num_entities(tup.2)
        .secrets_file_path(PathBuf::from("examples/ndm_smt_secrets_example.toml"))
        .build()
        .expect("Unable to build NdmSmtConfig")
        .parse()
        .expect("Unable to build NdmSmt")
}

pub fn generate_proof(ndm_smt: &NdmSmt, entity_id: &EntityId) -> InclusionProof {
    NdmSmt::generate_inclusion_proof(ndm_smt, entity_id).expect("Unable to generate proof")
}

pub fn serialize_tree(tree: &NdmSmt, dir: PathBuf) -> String {
    let mut file_name = tree.root_hash().to_string();
    file_name.push('.');
    file_name.push_str("dapoltree");

    let path = dir.join(file_name);

    read_write_utils::serialize_to_bin_file(&tree, path.clone()).expect("Unable to serialize tree");

    let file_size = fs::metadata(path)
        .expect("Unable to get tree metadata for {tree.root_hash()}")
        .len();

    let bytes_scaled = bytes_as_string(file_size as usize);

    bytes_scaled
}

pub fn serialize_proof(proof: &InclusionProof, entity_id: &EntityId, dir: PathBuf) -> String {
    let mut file_name = entity_id.to_string();
    file_name.push('.');
    file_name.push_str("dapolproof");

    let path = dir.join(file_name);

    read_write_utils::serialize_to_bin_file(&proof, path.clone())
        .expect("Unable to serialize proof");

    let file_size = fs::metadata(path)
        .expect("Unable to get proof metadata for {entity_id}")
        .len();

    let bytes_scaled = bytes_as_string(file_size as usize);

    bytes_scaled
}

pub fn bytes_as_string(num_bytes: usize) -> String {
    if num_bytes < 1024 {
        format!("{} bytes", num_bytes)
    } else if num_bytes >= 1024 && num_bytes < 1024usize.pow(2) {
        format!("{} kB", num_bytes / 1024)
    } else if num_bytes >= 1024usize.pow(2) && num_bytes < 1024usize.pow(3) {
        // scale to get accurate decimal values
        format!(
            "{:.2} MB",
            ((num_bytes as f32 / 1024u64.pow(2) as f32) * 1000.0).round() / 1000.0
        )
    } else if num_bytes >= 1024usize.pow(3) && num_bytes < 1024usize.pow(4) {
        format!(
            "{:.2} GB",
            ((num_bytes as f32 / 1024u64.pow(3) as f32) * 1000000.0).round() / 1000000.0
        )
    } else {
        format!(
            "{:.2} TB",
            ((num_bytes as f32 / 1024u64.pow(4) as f32) * 1000000000.0).round() / 1000000000.0
        )
    }
}
