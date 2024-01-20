use derive_builder::Builder;
use log::debug;
use serde::Deserialize;
use std::{ffi::OsString, fs::File, io::Read, path::PathBuf, str::FromStr};

use crate::{
    accumulators::AccumulatorType,
    entity::{self, EntitiesParser},
    utils::LogOnErr,
    DapolTree, DapolTreeError, Height, MaxLiability, MaxThreadCount, Salt, Secret,
};
use crate::{salt, secret};

/// Configuration needed to construct a [DapolTree].
///
/// The config is defined by a struct. A builder pattern is used to construct
/// the config, but it can also be constructed by deserializing a file.
/// Currently only toml files are supported, with the following format:
///
/// ```toml,ignore
#[doc = include_str!("../examples/dapol_config_example.toml")]
/// ```
///
/// Example of how to use the builder to construct a [DapolTree]:
/// ```
/// use std::{path::PathBuf, str::FromStr};
/// use dapol::{
///     AccumulatorType, DapolConfigBuilder, DapolTree, Entity, Height,
///     MaxLiability, MaxThreadCount, Salt, Secret,
/// };
///
/// let secrets_file_path =
/// PathBuf::from("./examples/dapol_secrets_example.toml");
/// let entities_file_path = PathBuf::from("./examples/entities_example.csv");
/// let height = Height::expect_from(8);
/// let salt_b = Salt::from_str("salt_b").unwrap();
/// let salt_s = Salt::from_str("salt_s").unwrap();
/// let max_liability = MaxLiability::from(10_000_000);
/// let max_thread_count = MaxThreadCount::from(8);
///
/// // The builder requires at least the following to be given:
/// // - accumulator_type
/// // - entities
/// // - secrets
/// let dapol_config = DapolConfigBuilder::default()
///     .accumulator_type(AccumulatorType::NdmSmt)
///     .height(height.clone())
///     .salt_b(salt_b.clone())
///     .salt_s(salt_s.clone())
///     .max_liability(max_liability.clone())
///     .max_thread_count(max_thread_count.clone())
///     .secrets_file_path(secrets_file_path.clone())
///     .entities_file_path(entities_file_path.clone())
///     .build()
///     .unwrap();
/// ```
///
/// Example of how to use a config file to construct a [DapolTree]:
/// ```
/// use std::{path::PathBuf, str::FromStr};
/// use dapol::DapolConfig;
///
/// let config_file_path =
/// PathBuf::from("./examples/dapol_config_example.toml");
/// let dapol_config_from_file =
/// DapolConfig::deserialize(config_file_path).unwrap();
/// ```
///
/// Note that you can also construct a [DapolTree] by calling the
/// constructor directly (see [DapolTree]).
#[derive(Deserialize, Debug, Builder, PartialEq)]
#[builder(build_fn(skip))]
pub struct DapolConfig {
    #[doc = include_str!("./shared_docs/accumulator_type.md")]
    accumulator_type: AccumulatorType,

    #[doc = include_str!("./shared_docs/salt_b.md")]
    salt_b: Salt,

    #[doc = include_str!("./shared_docs/salt_s.md")]
    salt_s: Salt,

    #[doc = include_str!("./shared_docs/max_liability.md")]
    max_liability: MaxLiability,

    #[doc = include_str!("./shared_docs/height.md")]
    height: Height,

    #[doc = include_str!("./shared_docs/max_thread_count.md")]
    max_thread_count: MaxThreadCount,

    #[builder(setter(custom))]
    random_seed: Option<u64>,

    #[builder(private)]
    entities: EntityConfig,

    #[builder(private)]
    secrets: SecretsConfig,
}

use serde_with::{serde_as, DisplayFromStr};
#[serde_as]
#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
pub struct SecretsConfig {
    file_path: Option<PathBuf>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    master_secret: Option<Secret>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq)]
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
    #[doc = include_str!("./shared_docs/master_secret.md")]
    pub fn master_secret(&mut self, master_secret: Secret) -> &mut Self {
        match &mut self.secrets {
            None => {
                self.secrets = Some(SecretsConfig {
                    file_path: None,
                    master_secret: Some(master_secret),
                })
            }
            Some(secrets) => secrets.master_secret = Some(master_secret),
        }
        self
    }

    #[doc = include_str!("./shared_docs/salt_b.md")]
    ///
    /// Wrapped in an option to provide ease of use if the value is already
    /// an option.
    pub fn salt_b_opt(&mut self, salt_b: Option<Salt>) -> &mut Self {
        self.salt_b = salt_b;
        self
    }

    #[doc = include_str!("./shared_docs/salt_s.md")]
    ///
    /// Wrapped in an option to provide ease of use if the value is already
    /// an option.
    pub fn salt_s_opt(&mut self, salt_s: Option<Salt>) -> &mut Self {
        self.salt_s = salt_s;
        self
    }

    /// For seeding any PRNG to have deterministic output.
    ///
    /// Note: This is **not** cryptographically secure and should only be used
    /// for testing.
    #[cfg(any(test, feature = "testing"))]
    pub fn random_seed(&mut self, random_seed: u64) -> &mut Self {
        self.random_seed = Some(Some(random_seed));
        self
    }

    #[cfg(any(test, feature = "testing"))]
    fn get_random_seed(&self) -> Option<u64> {
        self.random_seed.unwrap_or(None)
    }

    #[cfg(not(any(test, feature = "testing")))]
    fn get_random_seed(&self) -> Option<u64> {
        None
    }

    /// Build the config struct.
    pub fn build(&self) -> Result<DapolConfig, DapolConfigBuilderError> {
        let accumulator_type =
            self.accumulator_type
                .clone()
                .ok_or(DapolConfigBuilderError::UninitializedField(
                    "accumulator_type",
                ))?;

        let entities = EntityConfig {
            file_path: self.entities.clone().and_then(|e| e.file_path).or(None),
            num_random_entities: self
                .entities
                .clone()
                .and_then(|e| e.num_random_entities)
                .or(None),
        };

        if entities.file_path.is_none() && entities.num_random_entities.is_none() {
            return Err(DapolConfigBuilderError::UninitializedField("entities"));
        }

        let secrets = SecretsConfig {
            file_path: self.secrets.clone().and_then(|e| e.file_path).or(None),
            master_secret: self.secrets.clone().and_then(|e| e.master_secret).or(None),
        };

        if secrets.file_path.is_none() && secrets.master_secret.is_none() {
            return Err(DapolConfigBuilderError::UninitializedField("secrets"));
        }

        let salt_b = self.salt_b.clone().unwrap_or_default();
        let salt_s = self.salt_s.clone().unwrap_or_default();
        let height = self.height.unwrap_or_default();
        let max_thread_count = self.max_thread_count.unwrap_or_default();
        let max_liability = self.max_liability.unwrap_or_default();
        let random_seed = self.get_random_seed();

        Ok(DapolConfig {
            accumulator_type,
            salt_b,
            salt_s,
            max_liability,
            height,
            max_thread_count,
            entities,
            secrets,
            random_seed,
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
    /// let file_path = PathBuf::from("./examples/dapol_config_example.toml");
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

        let mut config = match FileType::from_str(ext)? {
            FileType::Toml => {
                let mut buf = String::new();
                File::open(config_file_path.clone())?.read_to_string(&mut buf)?;
                let config: DapolConfig = toml::from_str(&buf)?;
                config
            }
        };

        config.entities.file_path =
            extend_path_if_relative(config_file_path.clone(), config.entities.file_path);
        config.secrets.file_path =
            extend_path_if_relative(config_file_path, config.secrets.file_path);

        debug!("Successfully deserialized DAPOL config file");

        Ok(config)
    }

    /// Try to construct a [DapolTree] from the config.
    // STENT TODO rather call this create_tree
    #[cfg(any(test, feature = "testing"))]
    pub fn parse(self) -> Result<DapolTree, DapolConfigError> {
        debug!("Parsing config to create a new DAPOL tree: {:?}", self);

        let salt_b = self.salt_b;
        let salt_s = self.salt_s;

        let entities = EntitiesParser::new()
            .with_path_opt(self.entities.file_path)
            .with_num_entities_opt(self.entities.num_random_entities)
            .parse_file_or_generate_random()?;

        let master_secret = if let Some(path) = self.secrets.file_path {
            Ok(DapolConfig::parse_secrets_file(path)?)
        } else if let Some(master_secret) = self.secrets.master_secret {
            Ok(master_secret)
        } else {
            Err(DapolConfigError::CannotFindMasterSecret)
        }?;

        let dapol_tree = if let Some(random_seed) = self.random_seed {
            DapolTree::new_with_random_seed(
                self.accumulator_type,
                master_secret,
                salt_b,
                salt_s,
                self.max_liability,
                self.max_thread_count,
                self.height,
                entities,
                random_seed,
            )
            .log_on_err()?
        } else {
            DapolTree::new(
                self.accumulator_type,
                master_secret,
                salt_b,
                salt_s,
                self.max_liability,
                self.max_thread_count,
                self.height,
                entities,
            )
            .log_on_err()?
        };

        Ok(dapol_tree)
    }

    /// Try to construct a [DapolTree] from the config.
    // STENT TODO rather call this create_tree
    #[cfg(not(any(test, feature = "testing")))]
    pub fn parse(self) -> Result<DapolTree, DapolConfigError> {
        debug!("Parsing config to create a new DAPOL tree: {:?}", self);

        let salt_b = self.salt_b;
        let salt_s = self.salt_s;

        let entities = EntitiesParser::new()
            .with_path_opt(self.entities.file_path)
            .with_num_entities_opt(self.entities.num_random_entities)
            .parse_file_or_generate_random()?;

        let master_secret = if let Some(path) = self.secrets.file_path {
            Ok(DapolConfig::parse_secrets_file(path)?)
        } else if let Some(master_secret) = self.secrets.master_secret {
            Ok(master_secret)
        } else {
            Err(DapolConfigError::CannotFindMasterSecret)
        }?;

        Ok(DapolTree::new(
            self.accumulator_type,
            master_secret,
            salt_b,
            salt_s,
            self.max_liability,
            self.max_thread_count,
            self.height,
            entities,
        )
        .log_on_err()?)
    }

    /// Open and parse the secrets file, returning a [Secret].
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

fn extend_path_if_relative(
    leader_path: PathBuf,
    possibly_relative_path: Option<PathBuf>,
) -> Option<PathBuf> {
    match possibly_relative_path {
        Some(path) => Some(
            path.strip_prefix("./")
                .map(|p| p.to_path_buf())
                .ok()
                .and_then(|tail| leader_path.parent().map(|parent| parent.join(tail)))
                .unwrap_or(path.clone()),
        ),
        None => None,
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

/// Errors encountered when parsing [DapolConfig].
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

#[cfg(test)]
mod tests {
    use crate::accumulators::Accumulator;
    use crate::utils::test_utils::assert_err;

    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    // Matches the config found in the dapol_config_example.toml file.
    fn dapol_config_builder_matching_example_file() -> DapolConfigBuilder {
        let src_dir = env!("CARGO_MANIFEST_DIR");
        let resources_dir = Path::new(&src_dir).join("examples");
        let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
        let entities_file_path = resources_dir.join("entities_example.csv");

        let height = Height::expect_from(16u8);
        let salt_b = Salt::from_str("salt_b").unwrap();
        let salt_s = Salt::from_str("salt_s").unwrap();
        let max_liability = MaxLiability::from(10_000_000u64);
        let max_thread_count = MaxThreadCount::from(8u8);
        let master_secret = Secret::from_str("master_secret").unwrap();
        let num_entities = 100u64;

        DapolConfigBuilder::default()
            .accumulator_type(AccumulatorType::NdmSmt)
            .height(height.clone())
            .salt_b(salt_b.clone())
            .salt_s(salt_s.clone())
            .max_liability(max_liability.clone())
            .max_thread_count(max_thread_count.clone())
            .secrets_file_path(secrets_file_path.clone())
            .master_secret(master_secret.clone())
            .entities_file_path(entities_file_path.clone())
            .num_random_entities(num_entities)
            .clone()
    }

    mod creating_config {
        use super::*;

        #[test]
        fn builder_with_all_default_values_gives_correct_config() {
            // The builder requires at least the following to be given:
            // - accumulator_type
            // - entities
            // - secrets
            // The rest are left as default.

            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
            let entities_file_path = resources_dir.join("entities_example.csv");

            let dapol_config = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .secrets_file_path(secrets_file_path.clone())
                .entities_file_path(entities_file_path.clone())
                .build()
                .unwrap();

            // Assert the values that were explicitly set:
            assert_eq!(dapol_config.accumulator_type, AccumulatorType::NdmSmt);
            assert_eq!(dapol_config.entities.file_path, Some(entities_file_path));
            assert_eq!(dapol_config.secrets.file_path, Some(secrets_file_path));

            // Assert the values that were not set:
            assert_eq!(dapol_config.entities.num_random_entities, None);
            assert_eq!(dapol_config.secrets.master_secret, None);
            assert_eq!(dapol_config.max_thread_count, MaxThreadCount::default());
            assert_eq!(dapol_config.height, Height::default());
            assert_eq!(dapol_config.max_liability, MaxLiability::default());

            // Salts should be random bytes. Check that at least one byte is non-zero.
            assert!(dapol_config.salt_b.as_bytes().iter().any(|b| *b != 0u8));
            assert!(dapol_config.salt_s.as_bytes().iter().any(|b| *b != 0u8));
        }

        #[test]
        fn builder_with_no_default_values_gives_correct_config() {
            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
            let entities_file_path = resources_dir.join("entities_example.csv");

            let height = Height::expect_from(16u8);
            let salt_b = Salt::from_str("salt_b").unwrap();
            let salt_s = Salt::from_str("salt_s").unwrap();
            let max_liability = MaxLiability::from(10_000_000u64);
            let max_thread_count = MaxThreadCount::from(8u8);
            let master_secret = Secret::from_str("master_secret").unwrap();
            let num_entities = 100u64;

            let dapol_config = dapol_config_builder_matching_example_file()
                .build()
                .unwrap();

            assert_eq!(dapol_config.accumulator_type, AccumulatorType::NdmSmt);
            assert_eq!(dapol_config.entities.file_path, Some(entities_file_path));
            assert_eq!(dapol_config.secrets.file_path, Some(secrets_file_path));
            assert_eq!(
                dapol_config.entities.num_random_entities,
                Some(num_entities)
            );
            assert_eq!(dapol_config.secrets.master_secret, Some(master_secret));
            assert_eq!(dapol_config.max_thread_count, max_thread_count);
            assert_eq!(dapol_config.max_liability, max_liability);
            assert_eq!(dapol_config.height, height);
            assert_eq!(dapol_config.salt_b, salt_b);
            assert_eq!(dapol_config.salt_s, salt_s);
        }

        #[test]
        fn config_file_gives_same_config_as_builder() {
            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let config_file_path = resources_dir.join("dapol_config_example.toml");

            let dapol_config_from_file = DapolConfig::deserialize(config_file_path).unwrap();
            let dapol_config_from_builder = dapol_config_builder_matching_example_file()
                .build()
                .unwrap();

            assert_eq!(dapol_config_from_file, dapol_config_from_builder);
        }

        #[test]
        fn builder_without_accumulator_type_fails() {
            let master_secret = Secret::from_str("master_secret").unwrap();
            let num_entities = 100u64;

            let res = DapolConfigBuilder::default()
                .master_secret(master_secret)
                .num_random_entities(num_entities)
                .build();

            assert_err!(
                res,
                Err(DapolConfigBuilderError::UninitializedField(
                    "accumulator_type"
                ))
            );
        }

        #[test]
        fn builder_without_secrets_fails() {
            let num_entities = 100u64;

            let res = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .num_random_entities(num_entities)
                .build();

            assert_err!(
                res,
                Err(DapolConfigBuilderError::UninitializedField("secrets"))
            );
        }

        #[test]
        fn builder_without_entities_fails() {
            let master_secret = Secret::from_str("master_secret").unwrap();

            let res = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .master_secret(master_secret)
                .build();

            assert_err!(
                res,
                Err(DapolConfigBuilderError::UninitializedField("entities"))
            );
        }

        #[test]
        fn fail_when_unsupproted_secrets_file_type() {
            let this_file = std::file!();
            let unsupported_path = PathBuf::from(this_file);

            let num_entities = 100u64;

            let res = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .num_random_entities(num_entities)
                .secrets_file_path(unsupported_path)
                .build()
                .unwrap()
                .parse();

            assert_err!(
                res,
                Err(DapolConfigError::MasterSecretFileParseError(
                    SecretsParserError::UnsupportedFileType { ext: _ }
                ))
            );
        }

        #[test]
        fn fail_when_unknown_secrets_file_type() {
            let no_file_ext = PathBuf::from("../LICENSE");

            let num_entities = 100u64;

            let res = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .num_random_entities(num_entities)
                .secrets_file_path(no_file_ext)
                .build()
                .unwrap()
                .parse();

            assert_err!(
                res,
                Err(DapolConfigError::MasterSecretFileParseError(
                    SecretsParserError::UnknownFileType(_)
                ))
            );
        }
    }

    // TODO these are actually integration tests, so move them to tests dir
    mod config_to_tree {
        use super::*;

        #[test]
        fn parsing_config_gives_correct_tree() {
            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let entities_file_path = resources_dir.join("entities_example.csv");

            let entities_file = File::open(entities_file_path.clone()).unwrap();
            // "-1" because we don't include the top line of the csv which defines
            // the column headings.
            let num_entities = BufReader::new(entities_file).lines().count() - 1;

            let height = Height::expect_from(8u8);
            let master_secret = Secret::from_str("master_secret").unwrap();
            let salt_b = Salt::from_str("salt_b").unwrap();
            let salt_s = Salt::from_str("salt_s").unwrap();

            let dapol_tree = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .height(height.clone())
                .salt_b(salt_b.clone())
                .salt_s(salt_s.clone())
                .master_secret(master_secret.clone())
                .entities_file_path(entities_file_path.clone())
                .build()
                .unwrap()
                .parse()
                .unwrap();

            assert_eq!(
                dapol_tree.entity_mapping().unwrap().len(),
                num_entities as usize
            );
            assert_eq!(dapol_tree.accumulator_type(), AccumulatorType::NdmSmt);
            assert_eq!(*dapol_tree.height(), height);
            assert_eq!(*dapol_tree.master_secret(), master_secret);
            assert_eq!(dapol_tree.max_liability(), &MaxLiability::default());
            assert_eq!(*dapol_tree.salt_b(), salt_b);
            assert_eq!(*dapol_tree.salt_s(), salt_s);
        }

        #[test]
        fn config_with_random_entities_gives_correct_tree() {
            let height = Height::expect_from(8);
            let num_random_entities = 10;
            let master_secret = Secret::from_str("master_secret").unwrap();

            let dapol_tree = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .height(height)
                .master_secret(master_secret)
                .num_random_entities(num_random_entities)
                .build()
                .unwrap()
                .parse()
                .unwrap();

            assert_eq!(
                dapol_tree.entity_mapping().unwrap().len(),
                num_random_entities as usize
            );
        }

        #[test]
        fn secrets_file_gives_same_master_secret_as_setting_directly() {
            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
            let entities_file_path = resources_dir.join("entities_example.csv");
            let master_secret = Secret::from_str("master_secret").unwrap();
            let height = Height::expect_from(8u8);

            let tree_from_secrets_file = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .height(height)
                .secrets_file_path(secrets_file_path.clone())
                .entities_file_path(entities_file_path.clone())
                .build()
                .unwrap()
                .parse()
                .unwrap();

            let tree_from_direct_secret = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .height(height)
                .master_secret(master_secret.clone())
                .entities_file_path(entities_file_path.clone())
                .build()
                .unwrap()
                .parse()
                .unwrap();

            assert_eq!(
                tree_from_direct_secret.master_secret(),
                tree_from_secrets_file.master_secret()
            );
        }

        #[test]
        fn secrets_file_preferred_over_setting_directly() {
            let src_dir = env!("CARGO_MANIFEST_DIR");
            let resources_dir = Path::new(&src_dir).join("examples");
            let secrets_file_path = resources_dir.join("dapol_secrets_example.toml");
            let entities_file_path = resources_dir.join("entities_example.csv");
            let master_secret = Secret::from_str("garbage").unwrap();
            let height = Height::expect_from(8u8);

            let dapol_tree = DapolConfigBuilder::default()
                .accumulator_type(AccumulatorType::NdmSmt)
                .height(height)
                .secrets_file_path(secrets_file_path.clone())
                .master_secret(master_secret)
                .entities_file_path(entities_file_path.clone())
                .build()
                .unwrap()
                .parse()
                .unwrap();

            assert_eq!(
                dapol_tree.master_secret(),
                &Secret::from_str("master_secret").unwrap()
            );
        }
    }
}
