//! Command Line Interface implementation using [clap].
//!
//! See [MAIN_LONG_ABOUT] for more information.

use clap::{command, Args, Parser, Subcommand};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use patharg::{InputArg, OutputArg};
use primitive_types::H256;

use std::str::FromStr;

use crate::{
    accumulators::AccumulatorType,
    binary_tree::Height,
    percentage::{Percentage, ONE_HUNDRED_PERCENT},
    MaxLiability, MaxThreadCount, Salt,
};

// -------------------------------------------------------------------------------------------------
// Main structs.

// TODO we want a keep-running flag after new or from-file, for doing
// proofs

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = MAIN_LONG_ABOUT)]
pub struct Cli {
    /// Initial command for the program.
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten)]
    pub verbose: Verbosity<WarnLevel>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Construct a tree from the given parameters.
    ///
    /// There are 3 different ways to build a tree:
    /// - new, using CLI options for configuration
    /// - new, using a file for configuration
    /// - existing, deserializing from a .dapoltree file
    ///
    /// Inclusion proofs can be generated, but configuration is not supported.
    /// If you want more config options then use the `gen-proofs` command.
    BuildTree {
        /// Config DAPOL tree.
        #[command(subcommand)]
        build_kind: BuildKindCommand,

        #[arg(short, long, value_name = "ENTITY_IDS_FILE_PATH", global = true, long_help = GEN_PROOFS_HELP)]
        gen_proofs: Option<InputArg>,

        #[arg(short = 'S', long, value_name = "FILE_PATH", global = true, long_help = SERIALIZE_HELP)]
        serialize: Option<OutputArg>,

        /// Serialize the root node to 2 files: one for the public data, and
        /// one for the secret data.
        #[arg(short, long, value_name = "DIR", global = true)]
        root_serialize: Option<OutputArg>,
    },

    /// Generate inclusion proofs for entities.
    ///
    /// The entity IDs file is expected to be a list of entity IDs, each on a
    /// new line. All file formats are accepted. It is also possible to use
    /// the same entity IDs & liabilities file that is accepted by the
    /// `entity-source` option in the `build-tree new` command.
    ///
    /// A tree is required to generate proofs. The only option supported in
    /// in terms of tree input/construction is deserialization of an
    /// already-built tree. More options for building trees can be found in
    /// the `build-tree` command.
    GenProofs {
        /// List of entity IDs to generate proofs for, can be a file path or
        /// simply a comma separated list read from stdin (use "-" to
        /// indicate stdin).
        #[arg(short, long)]
        entity_ids: InputArg,

        /// Path to the tree file that will be deserialized.
        #[arg(short, long, value_name = "FILE_PATH")]
        tree_file: InputArg,

        /// Percentage of the range proofs that
        /// are aggregated using the Bulletproofs protocol.
        #[arg(short, long, value_parser = Percentage::from_str, default_value = ONE_HUNDRED_PERCENT, value_name = "PERCENTAGE")]
        range_proof_aggregation: Percentage,
    },

    /// Verify an inclusion proof.
    ///
    /// Note: the root hash of the tree is logged out on tree creation (an
    /// info-level log).
    VerifyInclusionProof {
        /// File path for the serialized inclusion proof file.
        #[arg(short, long)]
        file_path: InputArg,

        /// Hash digest/bytes for the root node of the tree.
        #[arg(short, long, value_parser = H256::from_str, value_name = "BYTES")]
        root_hash: H256,
    },

    /// Verify the root node of a DAPOL tree.
    ///
    /// Note: the public data (commitment &)
    VerifyRoot {
        /// File path for the serialized public data of the root.
        #[arg(short, long)]
        root_pub: InputArg,

        /// File path for the serialized secret data of the root.
        #[arg(short, long)]
        root_pvt: InputArg,
    },
}

#[derive(Debug, Subcommand)]
pub enum BuildKindCommand {
    /// Create a new tree using CLI options.
    ///
    /// The options available are similar to those
    /// supported by the configuration file format which can be found in the
    ///`build-tree config-file` command.";
    New {
        #[arg(short, long, value_enum, help = include_str!("./shared_docs/accumulator_type.md"))]
        accumulator_type: AccumulatorType,

        #[arg(long, value_parser = Salt::from_str, help = include_str!("./shared_docs/salt_b.md"))]
        salt_b: Option<Salt>,

        #[arg(long, value_parser = Salt::from_str, help = include_str!("./shared_docs/salt_s.md"))]
        salt_s: Option<Salt>,

        #[arg(long, value_parser = Height::from_str, default_value = Height::default(), value_name = "U8_INT", help = include_str!("./shared_docs/height.md"))]
        height: Height,

        #[arg(long, value_parser = MaxLiability::from_str, default_value = MaxLiability::default(), value_name = "U64_INT", help = include_str!("./shared_docs/max_liability.md"))]
        max_liability: MaxLiability,

        #[arg(long, value_parser = MaxThreadCount::from_str, default_value = MaxThreadCount::default(), value_name = "U8_INT", help = include_str!("./shared_docs/max_thread_count.md"))]
        max_thread_count: MaxThreadCount,

        #[arg(short, long, value_name = "FILE_PATH", long_help = SECRETS_HELP)]
        secrets_file: Option<InputArg>,

        #[command(flatten)]
        entity_source: EntitySource,
    },

    #[command(about = COMMAND_CONFIG_FILE_ABOUT, long_about = COMMAND_CONFIG_FILE_LONG_ABOUT)]
    ConfigFile {
        /// Path to the config file (supported file formats: TOML)
        file_path: InputArg,
    },

    /// Deserialize a tree from a .dapoltree file.
    Deserialize { path: InputArg },
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct EntitySource {
    #[arg(short, long, value_name = "FILE_PATH", long_help = ENTITIES_FILE_HELP)]
    pub entities_file: Option<InputArg>,

    /// Randomly generate a number of entities.
    #[arg(short, long, value_name = "NUM_ENTITIES")]
    pub random_entities: Option<u64>,
}

// -------------------------------------------------------------------------------------------------
// Long help texts.

pub const MAIN_LONG_ABOUT: &str = "
DAPOL+ Proof of Liabilities protocol in Rust.

**NOTE** This project is currently still a work in progress, but is ready for
use as is. The code has _not_ been audited yet (as of Nov 2023).

DAPOL+ paper: https://eprint.iacr.org/2021/1350

Top-level doc for the project: https://hackmd.io/p0dy3R0RS5qpm3sX-_zreA

Source code: https://github.com/silversixpence-crypto/dapol/";

const GEN_PROOFS_HELP: &str = "
Generate inclusion proofs for the provided entity IDs, after building the tree.
The entity IDs file is expected to be a list of entity IDs, each on a new line.
All file formats are accepted. It is also possible to use the same entity IDs &
liabilities file that is accepted by the `entity-source` option in the
`build-tree new` command.

Custom configuration of the proofs is not supported here. The `gen-proofs`
command offers more options.";

const SERIALIZE_HELP: &str = "
Serialize the tree to a file. If the path given is a directory then a default
file name will be given. If the path given is a file then that file will be
overwritten (if it exists) or created (if it does not exist). The file
extension must be `.dapoltree`. The serialization option is ignored if
`build-tree deserialize` command is used.";

const SECRETS_HELP: &str = "
TOML file containing secrets. The file format is as follows:
```
master_secret = \"master_secret\"
```
All secrets should have at least 128-bit security, but need not be chosen from a
uniform distribution as they are passed through a key derivation function before
being used.";

const ENTITIES_FILE_HELP: &str = "
Path to file containing entity ID & liability entries (supported file
types: CSV).

CSV file format:
entity_id,liability";

const COMMAND_CONFIG_FILE_ABOUT: &str =
    "Read tree configuration from a file. Supported file formats: TOML.";

const COMMAND_CONFIG_FILE_LONG_ABOUT: &str = concat!(
    "
Read tree configuration from a file.
Supported file formats: TOML.

Config file format (TOML):
```
",
    include_str!("../examples/dapol_config_example.toml"),
    "
```"
);
