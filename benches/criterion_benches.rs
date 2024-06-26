//! Benchmarks using Criterion.
//!
//! Criterion has a minimum of 10 samples that it takes for a benchmark, which
//! can be an obstacle if each bench takes multiple hours to run. So there is
//! a) an env var `MAX_ENTITIES_FOR_CRITERION_BENCHES` to change how many
//! benches are run using Criterion,
//! b) a different framework that is used to benchmark the runs that take really
//! long (see large_input_benches.rs).

use std::path::Path;
use std::str::FromStr;

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion, SamplingMode};
use statistical::*;

use dapol::{DapolConfigBuilder, DapolTree, InclusionProof, Secret, InclusionProofFileType};

mod inputs;
use inputs::{max_thread_counts_greater_than, num_entities_in_range, tree_heights_in_range};

mod memory_usage_estimation;
use memory_usage_estimation::estimated_total_memory_usage_mb;

mod utils;
use utils::{abs_diff, bytes_to_string, system_total_memory_mb};

mod env_vars;
use env_vars::{
    LOG_VERBOSITY, MAX_ENTITIES, MAX_HEIGHT, MIN_ENTITIES, MIN_HEIGHT, MIN_TOTAL_THREAD_COUNT,
};

/// This is required to get jemalloc_ctl to work properly.
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

// -------------------------------------------------------------------------------------------------
// Benchmarks

/// Loop over height, max thread counts, and number of entities.
pub fn bench_build_tree<T: Measurement>(c: &mut Criterion<T>) {
    let epoch = jemalloc_ctl::epoch::mib().unwrap();
    let allocated = jemalloc_ctl::stats::allocated::mib().unwrap();

    let master_secret = Secret::from_str("secret").unwrap();

    dapol::initialize_machine_parallelism();
    dapol::utils::activate_logging(*LOG_VERBOSITY);

    let mut group = c.benchmark_group("build_tree");
    // `SamplingMode::Flat` is used here as that is what Criterion recommends for long-running benches
    // https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html#sampling-mode
    group.sampling_mode(SamplingMode::Flat);

    for h in tree_heights_in_range(*MIN_HEIGHT, *MAX_HEIGHT).into_iter() {
        for t in max_thread_counts_greater_than(*MIN_TOTAL_THREAD_COUNT).into_iter() {
            for n in num_entities_in_range(*MIN_ENTITIES, *MAX_ENTITIES).into_iter() {
                println!("=============================================================\n");

                // =============================================================
                // Input validation.

                {
                    // TODO the python script needs to be run again.
                    // see memory_usage_estimation.rs for more info.

                    // // We attempt to guess the amount of memory that the tree
                    // // build will require, and if that is greater than the
                    // // amount of memory available on the machine then we skip
                    // // the input tuple.

                    // let total_mem = system_total_memory_mb();
                    // let expected_mem = estimated_total_memory_usage_mb(&h, &n);

                    // if total_mem < expected_mem {
                    //     println!(
                    //         "Skipping input height_{}/num_entities_{} since estimated memory \
                    //               usage {} is greater than the system max {}",
                    //         h.as_u32(),
                    //         n,
                    //         expected_mem,
                    //         total_mem
                    //     );

                    //     continue;
                    // }
                }

                // Do not try build the tree if the number of entities exceeds
                // the maximum number allowed. If this check is not done then
                // we would get an error on tree build.
                if n > h.max_bottom_layer_nodes() {
                    println!(
                        "Skipping input height_{}/num_entities_{} since number of entities is \
                              greater than max allowed",
                        h.as_u32(),
                        n
                    );

                    continue;
                }

                // =============================================================
                // Tree build.

                let mut memory_readings = vec![];
                let mut dapol_tree = Option::<DapolTree>::None;

                group.bench_with_input(
                    BenchmarkId::new(
                        "build_tree",
                        format!(
                            "height_{}/max_thread_count_{}/num_entities_{}",
                            h.as_u32(),
                            t.as_u8(),
                            n
                        ),
                    ),
                    &(h, t, n),
                    |bench, tup| {
                        bench.iter(|| {
                            // this is necessary for the memory readings to work
                            dapol_tree = None;

                            epoch.advance().unwrap();
                            let before = allocated.read().unwrap();

                            dapol_tree = Some(
                                DapolConfigBuilder::default()
                                    .accumulator_type(dapol::AccumulatorType::NdmSmt)
                                    .height(tup.0)
                                    .max_thread_count(tup.1)
                                    .num_random_entities(tup.2)
                                    .master_secret(master_secret.clone())
                                    .build()
                                    .expect("Unable to build DapolConfig")
                                    .parse()
                                    .expect("Unable to parse NdmSmtConfig"),
                            );

                            epoch.advance().unwrap();
                            memory_readings
                                .push(abs_diff(allocated.read().unwrap(), before) as f64);
                        });
                    },
                );

                memory_readings = memory_readings
                    .into_iter()
                    .map(|m| m / 1024u64.pow(2) as f64)
                    .collect();

                let mean = mean(&memory_readings);
                println!(
                    "\nMemory usage (MB): {:.2} +/- {:.4} ({:.2})\n",
                    mean,
                    standard_deviation(&memory_readings, Some(mean)),
                    median(&memory_readings)
                );

                // =============================================================
                // Tree serialization.

                let src_dir = env!("CARGO_MANIFEST_DIR");
                let target_dir = Path::new(&src_dir).join("target");
                let dir = target_dir.join("serialized_trees");
                let path = DapolTree::parse_tree_serialization_path(dir).unwrap();
                let tree = dapol_tree.expect("Tree should have been built");

                group.bench_function(
                    BenchmarkId::new(
                        "serialize_tree",
                        format!(
                            "height_{}/max_thread_count_{}/num_entities_{}",
                            h.as_u32(),
                            t.as_u8(),
                            n
                        ),
                    ),
                    |bench| {
                        bench.iter(|| tree.serialize(path.clone()).unwrap());
                    },
                );

                let file_size = std::fs::metadata(path)
                    .expect("Unable to get serialized tree metadata for {path}")
                    .len();

                println!(
                    "\nSerialized tree file size: {}\n",
                    bytes_to_string(file_size as usize)
                );
            }
        }
    }
}

/// We only loop through `tree_heights` & `num_entities` because we want proof
/// generation to have maximum threads.
pub fn bench_generate_proof<T: Measurement>(c: &mut Criterion<T>) {
    let mut group = c.benchmark_group("proofs");

    let master_secret = Secret::from_str("secret").unwrap();

    dapol::initialize_machine_parallelism();
    dapol::utils::activate_logging(*LOG_VERBOSITY);

    for h in tree_heights_in_range(*MIN_HEIGHT, *MAX_HEIGHT).into_iter() {
        for n in num_entities_in_range(*MIN_ENTITIES, *MAX_ENTITIES).into_iter() {
            {
                // TODO the python script needs to be run again.
                // see memory_usage_estimation.rs for more info.

                // // We attempt to guess the amount of memory that the tree
                // // build will require, and if that is greater than the
                // // amount of memory available on the machine then we skip
                // // the input tuple.

                // let total_mem = system_total_memory_mb();
                // let expected_mem = estimated_total_memory_usage_mb(&h, &n);

                // if total_mem < expected_mem {
                //     println!(
                //         "Skipping input height_{}/num_entities_{} since estimated memory \
                //                   usage {} is greater than the system max {}",
                //         h.as_u32(),
                //         n,
                //         expected_mem,
                //         total_mem
                //     );

                //     continue;
                // }
            }

            // Do not try build the tree if the number of entities exceeds
            // the maximum number allowed. If this check is not done then
            // we would get an error on tree build.
            if n > h.max_bottom_layer_nodes() {
                println!(
                    "Skipping input height_{}/num_entities_{} since number of entities is \
                              greater than max allowed",
                    h.as_u32(),
                    n
                );

                continue;
            }

            let dapol_tree = DapolConfigBuilder::default()
                .accumulator_type(dapol::AccumulatorType::NdmSmt)
                .master_secret(master_secret.clone())
                .height(h)
                .num_random_entities(n)
                .build()
                .expect("Unable to build DapolConfig")
                .parse()
                .expect("Unable to parse NdmSmtConfig");

            let entity_id = dapol_tree
                .entity_mapping()
                .unwrap()
                .keys()
                .next()
                .expect("Tree should have at least 1 entity");

            let mut proof = Option::<InclusionProof>::None;

            group.bench_function(
                BenchmarkId::new(
                    "generate_proof",
                    format!("height_{}/num_entities_{}", h.as_u32(), n),
                ),
                |bench| {
                    bench.iter(|| {
                        proof = Some(
                            dapol_tree
                                .generate_inclusion_proof(entity_id)
                                .expect("Proof should have been generated successfully"),
                        );
                    });
                },
            );

            // =============================================================
            // Proof serialization.

            let src_dir = env!("CARGO_MANIFEST_DIR");
            let target_dir = Path::new(&src_dir).join("target");
            let dir = target_dir.join("serialized_proofs");
            std::fs::create_dir_all(dir.clone()).unwrap();
            let path = proof
                .expect("Proof should be set")
                .serialize(entity_id, dir, InclusionProofFileType::Binary)
                .unwrap();
            let file_size = std::fs::metadata(path)
                .expect("Unable to get serialized tree metadata for {path}")
                .len();

            println!(
                "\nSerialized proof file size: {}\n",
                bytes_to_string(file_size as usize)
            );
        }
    }
}

/// We only loop through `tree_heights` & `num_entities` because proof
/// verification does not depend on number of threads.
pub fn bench_verify_proof<T: Measurement>(c: &mut Criterion<T>) {
    let mut group = c.benchmark_group("proofs");

    let master_secret = Secret::from_str("secret").unwrap();

    dapol::initialize_machine_parallelism();
    dapol::utils::activate_logging(*LOG_VERBOSITY);

    for h in tree_heights_in_range(*MIN_HEIGHT, *MAX_HEIGHT).into_iter() {
        for n in num_entities_in_range(*MIN_ENTITIES, *MAX_ENTITIES).into_iter() {
            {
                // TODO the python script needs to be run again.
                // see memory_usage_estimation.rs for more info.

                // // We attempt to guess the amount of memory that the tree
                // // build will require, and if that is greater than the
                // // amount of memory available on the machine then we skip
                // // the input tuple.

                // let total_mem = system_total_memory_mb();
                // let expected_mem = estimated_total_memory_usage_mb(&h, &n);

                // if total_mem < expected_mem {
                //     println!(
                //         "Skipping input height_{}/num_entities_{} since estimated memory \
                //                   usage {} is greater than the system max {}",
                //         h.as_u32(),
                //         n,
                //         expected_mem,
                //         total_mem
                //     );

                //     continue;
                // }
            }

            // Do not try build the tree if the number of entities exceeds
            // the maximum number allowed. If this check is not done then
            // we would get an error on tree build.
            if n > h.max_bottom_layer_nodes() {
                println!(
                    "Skipping input height_{}/num_entities_{} since number of entities is \
                              greater than max allowed",
                    h.as_u32(),
                    n
                );

                continue;
            }

            let dapol_tree = DapolConfigBuilder::default()
                .accumulator_type(dapol::AccumulatorType::NdmSmt)
                .master_secret(master_secret.clone())
                .height(h)
                .num_random_entities(n)
                .build()
                .expect("Unable to build DapolConfig")
                .parse()
                .expect("Unable to parse NdmSmtConfig");

            let root_hash = dapol_tree.root_hash();

            let entity_id = dapol_tree
                .entity_mapping()
                .unwrap()
                .keys()
                .next()
                .expect("Tree should have at least 1 entity");

            let proof = dapol_tree
                .generate_inclusion_proof(entity_id)
                .expect("Proof should have been generated successfully");

            group.bench_function(
                BenchmarkId::new(
                    "verify_proof",
                    format!("height_{}/num_entities_{}", h.as_u32(), n),
                ),
                |bench| {
                    bench.iter(|| proof.verify(*root_hash));
                },
            );
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Macros.

use std::time::Duration;

criterion_group! {
    name = wall_clock_time;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(600));
    targets = bench_build_tree, bench_generate_proof, bench_verify_proof
}

// Does not work, see memory_measurement.rs
// mod memory_measurement;
// criterion_group! {
//     name = memory_usage;
//     config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(60)).with_measurement(memory_measurement::Memory);
//     targets = bench_build_tree, bench_generate_proof, bench_verify_proof,
// }

criterion_main!(wall_clock_time);
