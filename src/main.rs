use std::path::PathBuf;

use clap::Parser;
use log::debug;

use dapol::{
    cli::{BuildKindCommand, Cli, Command},
    initialize_machine_parallelism,
    utils::{activate_logging, Consume, IfNoneThen, LogOnErr, LogOnErrUnwrap},
    AggregationFactor, DapolConfig, DapolConfigBuilder, DapolTree, EntityIdsParser, InclusionProof,
};
use patharg::InputArg;

fn main() {
    let args = Cli::parse();

    activate_logging(args.verbose.log_level_filter());

    match args.command {
        Command::BuildTree {
            build_kind,
            gen_proofs,
            serialize,
        } => {
            initialize_machine_parallelism();

            let serialization_path =
                // Do not try serialize if the command is Deserialize because
                // this means there already is a serialized file.
                if !build_kind_is_deserialize(&build_kind) {
                    // Do path checks before building so that the build does not have to be
                    // repeated for problems with file names etc.
                    match serialize {
                        Some(patharg) => {
                            let path = patharg.into_path().expect("Expected a file path, not stdout");
                            DapolTree::parse_serialization_path(path).log_on_err().ok()
                        }
                        None => None,
                    }
                } else {
                    None
                };

            let dapol_tree: DapolTree = match build_kind {
                BuildKindCommand::New {
                    accumulator_type: accumulator,
                    height,
                    max_thread_count,
                    secrets_file,
                    salt_b,
                    salt_s,
                    entity_source,
                } => DapolConfigBuilder::default()
                    .height(height)
                    .max_thread_count(max_thread_count)
                    .secrets_file_path_opt(secrets_file.and_then(|arg| arg.into_path()))
                    .salt_b(salt_b)
                    .salt_s(salt_s)
                    .entities_file_path_opt(
                        entity_source.entities_file.and_then(|arg| arg.into_path()),
                    )
                    .num_random_entities_opt(entity_source.random_entities)
                    .build()
                    .log_on_err_unwrap()
                    .parse()
                    .log_on_err_unwrap(),
                BuildKindCommand::Deserialize { path } => DapolTree::deserialize(
                    path.into_path().expect("Expected file path, not stdout"),
                )
                .log_on_err_unwrap(),
                BuildKindCommand::ConfigFile { file_path } => DapolConfig::deserialize(
                    file_path
                        .into_path()
                        .expect("Expected file path, not stdin"),
                )
                .log_on_err_unwrap()
                .parse()
                .log_on_err_unwrap(),
            };

            serialization_path
                .if_none_then(|| {
                    debug!("No serialization path set, skipping serialization of the tree");
                })
                .consume(|path| dapol_tree.serialize(path).unwrap());

            if let Some(patharg) = gen_proofs {
                let entity_ids = EntityIdsParser::from(
                    patharg.into_path().expect("Expected file path, not stdin"),
                )
                .parse()
                .log_on_err_unwrap();

                let dir = PathBuf::from("./inclusion_proofs/");
                std::fs::create_dir(dir.as_path()).log_on_err_unwrap();

                for entity_id in entity_ids {
                    let proof = dapol_tree
                        .generate_inclusion_proof(&entity_id)
                        .log_on_err_unwrap();

                    proof.serialize(&entity_id, dir.clone()).log_on_err_unwrap();
                }
            }
        }
        Command::GenProofs {
            entity_ids,
            tree_file,
            range_proof_aggregation,
            upper_bound_bit_length,
        } => {
            let dapol_tree = DapolTree::deserialize(
                tree_file
                    .into_path()
                    .expect("Expected file path, not stdout"),
            )
            .log_on_err_unwrap();

            // TODO for entity IDs: accept either path or stdin
            let entity_ids = EntityIdsParser::from(
                entity_ids
                    .into_path()
                    .expect("Expected file path, not stdin"),
            )
            .parse()
            .log_on_err_unwrap();

            let dir = PathBuf::from("./inclusion_proofs/");
            std::fs::create_dir(dir.as_path()).log_on_err_unwrap();

            let aggregation_factor = AggregationFactor::Percent(range_proof_aggregation);

            for entity_id in entity_ids {
                let proof = dapol_tree
                    .generate_inclusion_proof_with(
                        &entity_id,
                        aggregation_factor.clone(),
                        upper_bound_bit_length,
                    )
                    .log_on_err_unwrap();

                proof.serialize(&entity_id, dir.clone()).log_on_err_unwrap();
            }
        }
        Command::VerifyProof {
            file_path,
            root_hash,
        } => {
            let proof = InclusionProof::deserialize(
                file_path
                    .into_path()
                    .expect("Expected file path, not stdin"),
            )
            .log_on_err_unwrap();

            proof.verify(root_hash).log_on_err_unwrap();
        }
    }
}

fn build_kind_is_deserialize(build_kind: &BuildKindCommand) -> bool {
    let dummy = BuildKindCommand::Deserialize {
        path: InputArg::default(),
    };
    std::mem::discriminant(build_kind) == std::mem::discriminant(&dummy)
}
