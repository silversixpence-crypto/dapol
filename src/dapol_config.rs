use derive_builder::Builder;
use log::{debug, info};
use serde::Deserialize;
use std::{ffi::OsString, fs::File, io::Read, path::PathBuf, str::FromStr};

use crate::{
    accumulators::AccumulatorType,
    entity::{self, EntitiesParser},
    utils::LogOnErr,
    DapolTree, DapolTreeError, Height, MaxThreadCount, Salt, Secret,
    DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH,
};
use crate::{salt, secret};

/// Configuration needed to construct a [crate][DapolTree].
///
/// The config is defined by a struct. A builder pattern is used to construct
/// the config, but it can also be constructed by deserializing a file.
// STENT TODO this doc is wrong now
/// Construction is handled by [crate][AccumulatorConfig] and so have
/// a look there for more details on file format for deserialization or examples
/// on how to use the parser. Currently only toml files are supported, with the
/// following format:
///
/// ```toml,ignore
/// # Accumulator type of the tree.
/// # This value must be set.
/// accumulator_type = "ndm-smt"
///
/// # This value is known only to the tree generator, and is used to
/// # determine all other secret values needed in the tree.
/// # This value must be set.
/// master_secret = "master_secret"
///
/// # This is a public value that is used to aid the KDF when generating secret
/// # blinding factors for the Pedersen commitments.
/// # If it is not set then it will be randomly generated.
/// salt_b = "salt_b"
///
/// # This is a public value that is used to aid the KDF when generating secret
/// # salt values, which are in turn used in the hash function when generating
/// # node hashes.
/// # If it is not set then it will be randomly generated.
/// salt_s = "salt_s"
///
/// # Height of the tree.
/// # If not set the default height will be used.
/// height = 32
///
/// # Max number of threads to be spawned for multi-threading algorithms.
/// # If not set the max parallelism of the underlying machine will be used.
/// max_thread_count = 4
///
/// # Path to the secrets file.
/// # If not present the secrets will be generated randomly.
/// secrets_file_path = "./examples/ndm_smt_secrets_example.toml"
///
/// # At least one of file_path & generate_random must be present.
/// # If both are given then file_path is preferred and generate_random is ignored.
/// [entities]
///
/// # Path to a file containing a list of entity IDs and their liabilities.
/// file_path = "./examples/entities_example.csv"
///
/// # Generate the given number of entities, with random IDs & liabilities.
/// # This is useful for testing.
/// generate_random = 4
/// ```
///
// STENT TODO this is not true anymore
/// Construction of this tree using a config file must be done via
/// [crate][AccumulatorConfig].
///
/// Example how to use the builder:
/// ```
/// use std::path::PathBuf;
/// use dapol::{Height, MaxThreadCount};
/// use dapol::accumulators::DapolConfigBuilder;
///
/// let height = Height::expect_from(8);
/// let max_thread_count = MaxThreadCount::default();
///
/// let config = DapolConfigBuilder::default()
///     .height(height)
///     .secrets_file_path(PathBuf::from("./examples/ndm_smt_secrets_example.toml"))
///     .entities_file_path(PathBuf::from("./examples/entities_example.csv"))
///     .build();
/// ```
// STENT TODO will have 3 ways to build the tree: config builder, config file, just directly pass the values to the new function for dapoltree
#[derive(Deserialize, Debug, Builder)]
#[serde(rename_all = "kebab-case")]
#[builder(build_fn(skip))]
pub struct DapolConfig {
    accumulator_type: AccumulatorType,
    salt_b: Salt,
    salt_s: Salt,
    max_liability: u64,
    height: Height,
    max_thread_count: MaxThreadCount,
    #[builder(private)]
    entities: EntityConfig,
    // STENT TODO in docs & examples we'll have to make this look like entities
    #[builder(private)]
    secrets: SecretsConfig,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct SecretsConfig {
    master_secret: Option<Secret>,
    file_path: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub struct EntityConfig {
    file_path: Option<PathBuf>,
    num_random_entities: Option<u64>,
}

// -------------------------------------------------------------------------------------------------
// Builder.

impl DapolConfigBuilder {
    /// Set the path for the file containing the entity data.
    ///
    /// Wrapped in an option to provide ease of use if the PathBuf is already
    /// an option.
    pub fn entities_file_path_opt(&mut self, path: Option<PathBuf>) -> &mut Self {
        match &mut self.entities {
            None => {
                self.entities = Some(EntityConfig {
                    file_path: path,
                    num_random_entities: None,
                })
            }
            Some(entities) => entities.file_path = path,
        }
        self
    }

    /// Set the path for the file containing the entity data.
    pub fn entities_file_path(&mut self, path: PathBuf) -> &mut Self {
        self.entities_file_path_opt(Some(path))
    }

    /// Set the number of entities that will be generated randomly.
    ///
    /// If a path is also given for the entities then that is used instead,
    /// i.e. they are not combined.
    ///
    /// Wrapped in an option to provide ease of use if the PathBuf is already
    /// an option.
    pub fn num_random_entities_opt(&mut self, num_entities: Option<u64>) -> &mut Self {
        match &mut self.entities {
            None => {
                self.entities = Some(EntityConfig {
                    file_path: None,
                    num_random_entities: num_entities,
                })
            }
            Some(entities) => entities.num_random_entities = num_entities,
        }
        self
    }

    /// Set the number of entities that will be generated randomly.
    ///
    /// If a path is also given for the entities then that is used instead,
    /// i.e. they are not combined.
    pub fn num_random_entities(&mut self, num_entities: u64) -> &mut Self {
        self.num_random_entities_opt(Some(num_entities))
    }

    /// Set the path for the file containing the secrets.
    ///
    /// Wrapped in an option to provide ease of use if the PathBuf is already
    /// an option.
    pub fn secrets_file_path_opt(&mut self, path: Option<PathBuf>) -> &mut Self {
        match &mut self.secrets {
            None => {
                self.secrets = Some(SecretsConfig {
                    file_path: path,
                    master_secret: None,
                })
            }
            Some(secrets) => secrets.file_path = path,
        }
        self
    }

    /// Set the path for the file containing the secrets.
    pub fn secrets_file_path(&mut self, path: PathBuf) -> &mut Self {
        self.secrets_file_path_opt(Some(path))
    }

    /// Set the master secret value directly.
    pub fn master_secret(&mut self, master_secret: Secret) -> &mut Self {
        self.secrets = Some(SecretsConfig {
            file_path: None,
            master_secret: Some(master_secret),
        });
        self
    }

    /// Build the config struct.
    pub fn build(&self) -> Result<DapolConfig, DapolConfigBuilderError> {
        let accumulator_type =
            self.accumulator_type
                .clone()
                .ok_or(DapolConfigBuilderError::UninitializedField(
                    "accumulator_type",
                ))?;

        let max_liability = self
            .max_liability
            .clone()
            .unwrap_or(2u64.pow(DEFAULT_RANGE_PROOF_UPPER_BOUND_BIT_LENGTH as u32));

        let entities = EntityConfig {
            file_path: self.entities.clone().and_then(|e| e.file_path).or(None),
            num_random_entities: self
                .entities
                .clone()
                .and_then(|e| e.num_random_entities)
                .or(None),
        };

        let secrets = SecretsConfig {
            file_path: self.secrets.clone().and_then(|e| e.file_path).or(None),
            master_secret: self.secrets.clone().and_then(|e| e.master_secret).or(None),
        };

        let salt_b = self.salt_b.clone().unwrap_or_default();
        let salt_s = self.salt_s.clone().unwrap_or_default();
        let height = self.height.unwrap_or_default();
        let max_thread_count = self.max_thread_count.unwrap_or_default();

        Ok(DapolConfig {
            accumulator_type,
            salt_b,
            salt_s,
            max_liability,
            height,
            max_thread_count,
            entities,
            secrets,
        })
    }
}

// -------------------------------------------------------------------------------------------------
// Deserialization & parsing.

impl DapolConfig {
    /// Open the file, then try to create the [DapolConfig] struct.
    ///
    /// An error is returned if:
    /// 1. The file cannot be opened.
    /// 2. The file cannot be read.
    /// 3. The file type is not supported.
    ///
    /// Config deserialization example:
    /// ```
    /// use std::path::PathBuf;
    /// use dapol::DapolConfig;
    ///
    /// let file_path = PathBuf::from("./examples/tree_config_example.toml");
    /// let config = DapolConfig::deserialize(file_path).unwrap();
    /// ```
    pub fn deserialize(config_file_path: PathBuf) -> Result<Self, DapolConfigError> {
        debug!(
            "Attempting to deserialize {:?} as a file containing DAPOL config",
            config_file_path.clone().into_os_string()
        );

        let ext = config_file_path
            .extension()
            .and_then(|s| s.to_str())
            .ok_or(DapolConfigError::UnknownFileType(
                config_file_path.clone().into_os_string(),
            ))?;

        let config = match FileType::from_str(ext)? {
            FileType::Toml => {
                let mut buf = String::new();
                File::open(config_file_path)?.read_to_string(&mut buf)?;
                let config: DapolConfig = toml::from_str(&buf)?;
                config
            }
        };

        debug!("Successfully deserialized DAPOL config file");

        Ok(config)
    }

    /// Try to construct a [crate][DapolTree] from the config.
    pub fn parse(self) -> Result<DapolTree, DapolConfigError> {
        debug!("Parsing config to create a new DAPOL tree: {:?}", self);

        let salt_b = self.salt_b;
        let salt_s = self.salt_s;

        let entities = EntitiesParser::new()
            .with_path_opt(self.entities.file_path)
            .with_num_entities_opt(self.entities.num_random_entities)
            .parse_file_or_generate_random()?;

        let master_secret = if let Some(master_secret) = self.secrets.master_secret {
            Ok(master_secret)
        } else if let Some(path) = self.secrets.file_path {
            Ok(DapolConfig::parse_secrets_file(path)?)
        } else {
            Err(DapolConfigError::CannotFindMasterSecret)
        }?;

        let dapol_tree = DapolTree::new(
            self.accumulator_type,
            master_secret,
            salt_b,
            salt_s,
            self.max_liability,
            self.max_thread_count,
            self.height,
            entities,
        )
        .log_on_err()?;

        info!(
            // STENT TODO you must post the root commitment too, and it also needs to get checked when doing inclusion proofs
            "Successfully built DAPOL tree with root hash {:?}",
            dapol_tree.root_hash()
        );

        Ok(dapol_tree)
    }

    /// Open and parse the secrets file, returning a [crate][Secret].
    ///
    /// An error is returned if:
    /// 1. The path is None (i.e. was not set).
    /// 2. The file cannot be opened.
    /// 3. The file cannot be read.
    /// 4. The file type is not supported.
    fn parse_secrets_file(path: PathBuf) -> Result<Secret, SecretsParserError> {
        debug!(
            "Attempting to parse {:?} as a file containing secrets",
            path
        );

        let ext = path.extension().and_then(|s| s.to_str()).ok_or(
            SecretsParserError::UnknownFileType(path.clone().into_os_string()),
        )?;

        let master_secret = match FileType::from_str(ext)? {
            FileType::Toml => {
                let mut buf = String::new();
                File::open(path)?.read_to_string(&mut buf)?;
                let secrets: DapolSecrets = toml::from_str(&buf)?;
                secrets.master_secret
            }
        };

        debug!("Successfully parsed DAPOL secrets file",);

        Ok(master_secret)
    }
}

/// Supported file types for deserialization.
enum FileType {
    Toml,
}

impl FromStr for FileType {
    type Err = SecretsParserError;

    fn from_str(ext: &str) -> Result<FileType, Self::Err> {
        match ext {
            "toml" => Ok(FileType::Toml),
            _ => Err(SecretsParserError::UnsupportedFileType { ext: ext.into() }),
        }
    }
}

#[derive(Deserialize, Debug)]
struct DapolSecrets {
    master_secret: Secret,
}

// -------------------------------------------------------------------------------------------------
// Errors.

/// Errors encountered when parsing [crate][DapolConfig].
#[derive(thiserror::Error, Debug)]
pub enum DapolConfigError {
    #[error("Entities parsing failed while trying to parse DAPOL config")]
    EntitiesError(#[from] entity::EntitiesParserError),
    #[error("Error parsing the master secret string")]
    MasterSecretParseError(#[from] secret::SecretParserError),
    #[error("Error parsing the master secret file")]
    MasterSecretFileParseError(#[from] SecretsParserError),
    #[error("Either master secret must be set directly, or a path to a file containing it must be given")]
    CannotFindMasterSecret,
    #[error("Error parsing the salt string")]
    SaltParseError(#[from] salt::SaltParserError),
    #[error("Tree construction failed after parsing DAPOL config")]
    BuildError(#[from] DapolTreeError),
    #[error("Unable to find file extension for path {0:?}")]
    UnknownFileType(OsString),
    #[error("The file type with extension {ext:?} is not supported")]
    UnsupportedFileType { ext: String },
    #[error("Error reading the file")]
    FileReadError(#[from] std::io::Error),
    #[error("Deserialization process failed")]
    DeserializationError(#[from] toml::de::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum SecretsParserError {
    #[error("Unable to find file extension for path {0:?}")]
    UnknownFileType(OsString),
    #[error("The file type with extension {ext:?} is not supported")]
    UnsupportedFileType { ext: String },
    #[error("Error reading the file")]
    FileReadError(#[from] std::io::Error),
    #[error("Deserialization process failed")]
    DeserializationError(#[from] toml::de::Error),
}

// -------------------------------------------------------------------------------------------------
// Unit tests

// STENT TODO need to fix these
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::assert_err;

    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    #[test]
    fn builder_with_entities_file() {
        let height = Height::expect_from(8);

        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let secrets_file_path = resources_dir.join("ndm_smt_secrets_example.toml");
        let entities_file_path = resources_dir.join("entities_example.csv");

        let entities_file = File::open(entities_file_path.clone()).unwrap();
        // "-1" because we don't include the top line of the csv which defines
        // the column headings.
        let num_entities = BufReader::new(entities_file).lines().count() - 1;

        let ndm_smt = DapolConfigBuilder::default()
            .height(height)
            .secrets_file_path(secrets_file_path)
            .entities_file_path(entities_file_path)
            .build()
            .parse()
            .unwrap();

        assert_eq!(ndm_smt.entity_mapping.len(), num_entities);
        assert_eq!(ndm_smt.height(), &height);
    }

    #[test]
    fn builder_with_random_entities() {
        let height = Height::expect_from(8);
        let num_random_entities = 10;

        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let secrets_file = resources_dir.join("ndm_smt_secrets_example.toml");

        let ndm_smt = DapolConfigBuilder::default()
            .height(height)
            .secrets_file_path(secrets_file)
            .num_random_entities(num_random_entities)
            .build()
            .parse()
            .unwrap();

        assert_eq!(ndm_smt.entity_mapping.len(), num_random_entities as usize);
        assert_eq!(ndm_smt.height(), &height);
    }

    #[test]
    fn builder_without_height_should_give_default() {
        let num_random_entities = 10;

        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let secrets_file = resources_dir.join("ndm_smt_secrets_example.toml");

        let ndm_smt = DapolConfigBuilder::default()
            .secrets_file_path(secrets_file)
            .num_random_entities(num_random_entities)
            .build()
            .parse()
            .unwrap();

        assert_eq!(ndm_smt.entity_mapping.len(), num_random_entities as usize);
        assert_eq!(ndm_smt.height(), &Height::default());
    }

    #[test]
    fn builder_without_any_values_fails() {
        use crate::entity::EntitiesParserError;
        let res = DapolConfigBuilder::default().build().parse();
        assert_err!(
            res,
            Err(DapolConfigError::EntitiesError(
                EntitiesParserError::NumEntitiesNotSet
            ))
        );
    }

    #[test]
    fn builder_with_all_values() {
        let height = Height::expect_from(8);
        let num_random_entities = 10;

        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let secrets_file_path = resources_dir.join("ndm_smt_secrets_example.toml");
        let entities_file_path = resources_dir.join("entities_example.csv");

        let entities_file = File::open(entities_file_path.clone()).unwrap();
        // "-1" because we don't include the top line of the csv which defines
        // the column headings.
        let num_entities = BufReader::new(entities_file).lines().count() - 1;

        let ndm_smt = DapolConfigBuilder::default()
            .height(height)
            .secrets_file_path(secrets_file_path)
            .entities_file_path(entities_file_path)
            .num_random_entities(num_random_entities)
            .build()
            .parse()
            .unwrap();

        assert_eq!(ndm_smt.entity_mapping.len(), num_entities);
        assert_eq!(ndm_smt.height(), &height);
    }

    #[test]
    fn builder_without_secrets_file_path() {
        let num_random_entities = 10;

        let _ndm_smt = DapolConfigBuilder::default()
            .num_random_entities(num_random_entities)
            .build()
            .parse()
            .unwrap();
    }
}

// STENT TODO grabbed these from ndm_smt_secrets_parser
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::assert_err;
    use crate::Secret;
    use std::path::Path;

    #[test]
    fn parser_toml_file_happy_case() {
        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let path = resources_dir.join("ndm_smt_secrets_example.toml");

        let secrets = NdmSmtSecretsParser::from(path).parse().unwrap();

        assert_eq!(
            secrets.master_secret,
            Secret::from_str("master_secret").unwrap()
        );
        assert_eq!(secrets.salt_b, Secret::from_str("salt_b").unwrap());
        assert_eq!(secrets.salt_s, Secret::from_str("salt_s").unwrap());
    }

    #[test]
    fn unsupported_file_type() {
        let this_file = std::file!();
        let path = PathBuf::from(this_file);

        assert_err!(
            NdmSmtSecretsParser::from(path).parse(),
            Err(NdmSmtSecretsParserError::UnsupportedFileType { ext: _ })
        );
    }

    #[test]
    fn unknown_file_type() {
        let path = PathBuf::from("./");
        assert_err!(
            NdmSmtSecretsParser::from(path).parse(),
            Err(NdmSmtSecretsParserError::UnknownFileType(_))
        );
    }
}
