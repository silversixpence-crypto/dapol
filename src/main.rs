use std::{path::PathBuf, str::FromStr};

use clap::Parser;
use log::debug;

use dapol::{
    cli::{BuildKindCommand, Cli, Command},
    initialize_machine_parallelism,
    utils::{activate_logging, Consume, IfNoneThen, LogOnErr, LogOnErrUnwrap},
    AggregationFactor, DapolConfig, DapolConfigBuilder, DapolTree, EntityIdsParser, InclusionProof,
    InclusionProofFileType,
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
            root_serialize,
        } => {
            initialize_machine_parallelism();

            // It's not necessary to do this first, but it allows fast-failure
            // for bad paths.
            let serialization_path =
                // Do not try serialize if the command is Deserialize because
                // this means there already is a serialized file.
                if !build_kind_is_deserialize(&build_kind) {
                    // Do path checks before building so that the build does not have to be
                    // repeated for problems with file names etc.
                    match serialize {
                        Some(patharg) => {
                            let path = patharg.into_path().expect("Expected a file path, not stdout");
                            DapolTree::parse_tree_serialization_path(path).log_on_err().ok()
                        }
                        None => None,
                    }
                } else {
                    None
                };

            let dapol_tree: DapolTree = match build_kind {
                BuildKindCommand::New {
                    accumulator_type,
                    salt_b,
                    salt_s,
                    height,
                    max_liability,
                    max_thread_count,
                    secrets_file,
                    entity_source,
                } => DapolConfigBuilder::default()
                    .accumulator_type(accumulator_type)
                    .salt_b_opt(salt_b)
                    .salt_s_opt(salt_s)
                    .max_liability(max_liability)
                    .height(height)
                    .max_thread_count(max_thread_count)
                    .entities_file_path_opt(
                        entity_source.entities_file.and_then(|arg| arg.into_path()),
                    )
                    .num_random_entities_opt(entity_source.random_entities)
                    .secrets_file_path_opt(secrets_file.into_path())
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
                .consume(|path| {
                    dapol_tree.serialize(path).unwrap();
                });

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

                    proof
                        .serialize(&entity_id, dir.clone(), InclusionProofFileType::Json)
                        .log_on_err_unwrap();
                }
            }

            if let Some(patharg) = root_serialize {
                let path = patharg
                    .into_path()
                    .expect("Expected a file path, not stdout");
                if path.is_dir() {
                    panic!("Root serialization path must be a directory so multiple files can be created");
                }
                dapol_tree
                    .serialize_public_root_data(path.clone())
                    .log_on_err_unwrap();
                dapol_tree
                    .serialize_secret_root_data(path)
                    .log_on_err_unwrap();
            }
        }
        Command::GenProofs {
            entity_ids,
            tree_file,
            range_proof_aggregation,
            file_type,
        } => {
            let dapol_tree = DapolTree::deserialize(
                tree_file
                    .into_path()
                    .expect("Expected file path, not stdout"),
            )
            .log_on_err_unwrap();

            let entity_ids = if entity_ids.is_path() {
                EntityIdsParser::from(
                    entity_ids
                        .into_path()
                        .expect("Expected file path, not stdin"),
                )
            } else {
                EntityIdsParser::from_str(
                    &entity_ids
                        .read_to_string()
                        .expect("Problem reading from stdin"),
                )
                .log_on_err_unwrap()
            }
            .parse()
            .log_on_err_unwrap();

            let dir = PathBuf::from("./inclusion_proofs/");
            if !dir.exists() {
                std::fs::create_dir(dir.as_path()).log_on_err_unwrap();
            }

            let aggregation_factor = AggregationFactor::Percent(range_proof_aggregation);

            for entity_id in entity_ids {
                let proof = dapol_tree
                    .generate_inclusion_proof_with(&entity_id, aggregation_factor.clone())
                    .log_on_err_unwrap();

                proof
                    .serialize(&entity_id, dir.clone(), file_type.clone())
                    .log_on_err_unwrap();
            }
        }
        Command::VerifyInclusionProof {
            file_path,
            root_hash,
            show_path,
        } => {
            let file_path = file_path
                .into_path()
                .expect("Expected file path, not stdin");

            let proof = InclusionProof::deserialize(file_path.clone()).log_on_err_unwrap();

            if show_path {
                proof
                    .verify_and_show_path_info(
                        root_hash,
                        file_path
                            .parent()
                            .expect("Expected file_path to have a parent")
                            .to_path_buf(),
                        file_path
                            .file_name()
                            .expect("Expected file_path to have a file name")
                            .to_os_string(),
                    )
                    .log_on_err_unwrap();
            } else {
                proof.verify(root_hash).log_on_err_unwrap();
            }
        }
        Command::VerifyRoot { root_pub, root_pvt } => {
            let public_root_data = DapolTree::deserialize_public_root_data(
                root_pub.into_path().expect("Expected file path, not stdin"),
            )
            .log_on_err_unwrap();
            let secret_root_data = DapolTree::deserialize_secret_root_data(
                root_pvt.into_path().expect("Expected file path, not stdin"),
            )
            .log_on_err_unwrap();

            DapolTree::verify_root_commitment(&public_root_data.commitment, &secret_root_data)
                .log_on_err_unwrap();
        }
    }
}

fn build_kind_is_deserialize(build_kind: &BuildKindCommand) -> bool {
    let dummy = BuildKindCommand::Deserialize {
        path: InputArg::default(),
    };
    std::mem::discriminant(build_kind) == std::mem::discriminant(&dummy)
}
