use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const CONFIG_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema: u32,
    pub engine: EngineConfig,
    pub strategy: StrategyConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub manifest: PathBuf,
    pub binary: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyConfig {
    pub name: String,
    #[serde(default = "default_strategy_directory")]
    pub directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEnginePaths {
    pub manifest: PathBuf,
    pub binary: PathBuf,
}

impl AppConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&content)
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let content = toml::to_string_pretty(self).map_err(ConfigError::Serialize)?;
        let temp = path.with_extension("toml.new");
        std::fs::write(&temp, content).map_err(|source| ConfigError::Io {
            path: temp.clone(),
            source,
        })?;
        if path.exists() {
            std::fs::remove_file(path).map_err(|source| ConfigError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        std::fs::rename(&temp, path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema != CONFIG_SCHEMA {
            return Err(ConfigError::InvalidConfig(format!(
                "unsupported config schema {}; expected {CONFIG_SCHEMA}",
                self.schema
            )));
        }

        if self.engine.manifest.as_os_str().is_empty() {
            return Err(ConfigError::InvalidConfig(
                "engine.manifest must not be empty".to_owned(),
            ));
        }
        if self.engine.binary.as_os_str().is_empty() {
            return Err(ConfigError::InvalidConfig(
                "engine.binary must not be empty".to_owned(),
            ));
        }

        if !is_safe_identifier(&self.strategy.name) {
            return Err(ConfigError::InvalidConfig(
                "strategy.name may contain only ASCII letters, digits, dash, underscore and dot"
                    .to_owned(),
            ));
        }

        Ok(())
    }

    #[must_use]
    pub fn resolve_engine_paths(&self, config_path: &Path) -> ResolvedEnginePaths {
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        ResolvedEnginePaths {
            manifest: resolve(base, &self.engine.manifest),
            binary: resolve(base, &self.engine.binary),
        }
    }

    #[must_use]
    pub fn resolve_strategy_path(&self, config_path: &Path) -> PathBuf {
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        resolve(base, &self.strategy.directory).join(format!("{}.toml", self.strategy.name))
    }
}

fn default_strategy_directory() -> PathBuf {
    PathBuf::from("strategies")
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug)]
pub enum ConfigError {
    Io { path: PathBuf, source: io::Error },
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    InvalidConfig(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to access {}: {source}", path.display())
            }
            Self::Parse(source) => write!(f, "invalid TOML config: {source}"),
            Self::Serialize(source) => write!(f, "cannot serialize TOML config: {source}"),
            Self::InvalidConfig(message) => write!(f, "invalid config: {message}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::Serialize(source) => Some(source),
            Self::InvalidConfig(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config = AppConfig::parse(
            r#"schema = 1

[engine]
manifest = "engines/zapret.toml"
binary = "runtime/zapret"

[strategy]
name = "general-simple-fake"
"#,
        )
        .expect("valid config must parse");

        assert_eq!(config.strategy.name, "general-simple-fake");
    }

    #[test]
    fn rejects_shell_like_strategy_names() {
        let config = AppConfig {
            schema: 1,
            engine: EngineConfig {
                manifest: PathBuf::from("engine.toml"),
                binary: PathBuf::from("engine"),
            },
            strategy: StrategyConfig {
                name: "general;rm".to_owned(),
                directory: PathBuf::from("strategies"),
            },
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn resolves_relative_engine_paths_from_config_directory() {
        let config = AppConfig {
            schema: 1,
            engine: EngineConfig {
                manifest: PathBuf::from("engine.toml"),
                binary: PathBuf::from("runtime/engine"),
            },
            strategy: StrategyConfig {
                name: "general".to_owned(),
                directory: PathBuf::from("strategies"),
            },
        };

        let resolved = config.resolve_engine_paths(Path::new("/tmp/app/config.toml"));
        assert_eq!(resolved.manifest, PathBuf::from("/tmp/app/engine.toml"));
        assert_eq!(resolved.binary, PathBuf::from("/tmp/app/runtime/engine"));
    }
}
