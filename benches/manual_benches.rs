//! Manual benches that do not use Criterion.
//!
//! Criterion has a minimum of 10 runs per bench, so if the bench takes an hour
//! to run then you suddenly need half a day for running a single bench. These
//! benches just do a single run. The measurements will not be as accurate,
//! unfortunately, but this is the trade-off.

use std::path::Path;
use std::str::FromStr;
use std::time::Instant;

use statistical::*;

use dapol::{DapolConfigBuilder, DapolTree, Secret};

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

fn main() {
    let epoch = jemalloc_ctl::epoch::mib().unwrap();
    let allocated = jemalloc_ctl::stats::allocated::mib().unwrap();

    let total_mem = system_total_memory_mb();

    let master_secret = Secret::from_str("secret").unwrap();

    dapol::initialize_machine_parallelism();
    dapol::utils::activate_logging(*LOG_VERBOSITY);

    println!(
        "==========================================================\n \
              Manual benchmarks"
    );

    for h in tree_heights_in_range(*MIN_HEIGHT, *MAX_HEIGHT).into_iter() {
        for t in max_thread_counts_greater_than(*MIN_TOTAL_THREAD_COUNT).into_iter() {
            for n in num_entities_in_range(*MIN_ENTITIES, *MAX_ENTITIES).into_iter() {
                // ==============================================================
                // Input validation.

                {
                    // TODO the python script needs to be run again.
                    // see memory_usage_estimation.rs for more info.

                    // We attempt to guess the amount of memory that the tree
                    // build will require, and if that is greater than the
                    // amount of memory available on the machine then we skip
                    // the input tuple.

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

                println!(
                    "\nRunning benchmark for input values \
                     (height {}, max_thread_count {}, num_entities {})",
                    h.as_u32(),
                    t.as_u8(),
                    n
                );

                // ==============================================================
                // Tree build.

                let mut dapol_tree = Option::<DapolTree>::None;
                let mut memory_readings = vec![];
                let mut timings = vec![];

                // Do 3 readings (Criterion does 10 minimum).
                for _i in 0..3 {
                    // this is necessary for the memory readings to work
                    dapol_tree = None;

                    println!(
                        "building tree i {} time {}",
                        _i,
                        chrono::Local::now().format("%Y-%m-%d][%H:%M:%S")
                    );

                    epoch.advance().unwrap();
                    let mem_before = allocated.read().unwrap();
                    let time_start = Instant::now();

                    dapol_tree = Some(
                        DapolConfigBuilder::default()
                            .accumulator_type(dapol::AccumulatorType::NdmSmt)
                            .height(h)
                            .max_thread_count(t)
                            .master_secret(master_secret.clone())
                            .num_random_entities(n)
                            .build()
                            .expect("Unable to build DapolConfig")
                            .parse()
                            .expect("Unable to parse DapolConfig"),
                    );

                    let tree_build_time = time_start.elapsed();
                    epoch.advance().unwrap();
                    let mem_after = allocated.read().unwrap();
                    timings.push(tree_build_time.as_secs_f64());
                    memory_readings.push(abs_diff(mem_after, mem_before) as f64);
                }

                // Convert from bytes to GB.
                memory_readings = memory_readings
                    .into_iter()
                    .map(|m| m / 1024u64.pow(3) as f64)
                    .collect();
                let mean_mem = mean(&memory_readings);

                // Convert from seconds to minutes.
                timings = timings.into_iter().map(|m| m / 60f64).collect();
                let mean_time = mean(&timings);

                // ==============================================================
                // Tree serialization.

                println!("seriliazing tree");
                let src_dir = env!("CARGO_MANIFEST_DIR");
                let target_dir = Path::new(&src_dir).join("target");
                let dir = target_dir.join("serialized_trees");
                let path = DapolTree::parse_tree_serialization_path(dir).unwrap();

                let time_start = Instant::now();
                dapol_tree
                    .expect("DapolTree should have been set in loop")
                    .serialize(path.clone())
                    .unwrap();
                let serialization_time = time_start.elapsed();

                let file_size = std::fs::metadata(path)
                    .expect("Unable to get serialized tree metadata for {path}")
                    .len();

                // ==============================================================
                // Print stats.

                println!(
                    "\nTime taken to build tree (minutes): {:.2} +/- {:.4} ({:.2})\n \
                     Memory used to build tree (GB): {:.2} +/- {:.4} ({:.2})\n \
                     Time taken to serialize tree: {:?}\n \
                     Serialized tree file size: {}\n \
                     ========================================================================",
                    mean(&timings),
                    standard_deviation(&timings, Some(mean_time)),
                    median(&timings),
                    mean(&memory_readings),
                    standard_deviation(&memory_readings, Some(mean_mem)),
                    median(&memory_readings),
                    serialization_time,
                    bytes_to_string(file_size as usize)
                );
            }
        }
    }
}
