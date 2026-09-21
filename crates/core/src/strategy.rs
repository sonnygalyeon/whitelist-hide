use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const STRATEGY_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyDefinition {
    pub schema: u32,
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub filters: StrategyFilters,
    #[serde(default)]
    pub desync: Vec<DesyncStage>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyFilters {
    #[serde(default)]
    pub tcp_ports: Vec<PortRange>,
    #[serde(default)]
    pub udp_ports: Vec<PortRange>,
    #[serde(default)]
    pub domain_lists: Vec<PathBuf>,
    #[serde(default)]
    pub ip_lists: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DesyncStage {
    Fake {
        #[serde(default = "default_repeats")]
        repeats: u8,
    },
    MultiSplit {
        positions: Vec<u16>,
    },
    MultiDisorder {
        positions: Vec<u16>,
    },
    FakeSplit {
        position: u16,
    },
    UdpLength {
        increment: u16,
    },
    IpFragment2,
}

impl StrategyDefinition {
    pub fn parse(input: &str) -> Result<Self, StrategyError> {
        let strategy: Self = toml::from_str(input).map_err(StrategyError::Parse)?;
        strategy.validate()?;
        Ok(strategy)
    }

    pub fn load(path: &Path) -> Result<Self, StrategyError> {
        let content = std::fs::read_to_string(path).map_err(|source| StrategyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&content)
    }

    pub fn validate(&self) -> Result<(), StrategyError> {
        if self.schema != STRATEGY_SCHEMA {
            return Err(StrategyError::Invalid(format!(
                "unsupported strategy schema {}; expected {STRATEGY_SCHEMA}",
                self.schema
            )));
        }

        if !safe_identifier(&self.id) {
            return Err(StrategyError::Invalid(
                "strategy id may contain only ASCII letters, digits, dash, underscore and dot"
                    .to_owned(),
            ));
        }

        if self.filters.tcp_ports.is_empty() && self.filters.udp_ports.is_empty() {
            return Err(StrategyError::Invalid(
                "at least one TCP or UDP port range is required".to_owned(),
            ));
        }

        validate_ranges("tcp_ports", &self.filters.tcp_ports)?;
        validate_ranges("udp_ports", &self.filters.udp_ports)?;

        for path in self
            .filters
            .domain_lists
            .iter()
            .chain(self.filters.ip_lists.iter())
        {
            validate_relative_data_path(path)?;
        }

        for stage in &self.desync {
            match stage {
                DesyncStage::Fake { repeats } if *repeats == 0 => {
                    return Err(StrategyError::Invalid(
                        "fake repeats must be greater than zero".to_owned(),
                    ));
                }
                DesyncStage::MultiSplit { positions }
                | DesyncStage::MultiDisorder { positions }
                    if positions.is_empty() || positions.contains(&0) =>
                {
                    return Err(StrategyError::Invalid(
                        "split/disorder positions must contain non-zero offsets".to_owned(),
                    ));
                }
                DesyncStage::FakeSplit { position } if *position == 0 => {
                    return Err(StrategyError::Invalid(
                        "fake-split position must be greater than zero".to_owned(),
                    ));
                }
                DesyncStage::UdpLength { increment } if *increment == 0 => {
                    return Err(StrategyError::Invalid(
                        "udp-length increment must be greater than zero".to_owned(),
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }
}

fn default_repeats() -> u8 {
    1
}

fn validate_ranges(field: &str, ranges: &[PortRange]) -> Result<(), StrategyError> {
    for range in ranges {
        if range.start == 0 || range.end == 0 || range.start > range.end {
            return Err(StrategyError::Invalid(format!(
                "{field} contains invalid range {}-{}",
                range.start, range.end
            )));
        }
    }
    Ok(())
}

fn validate_relative_data_path(path: &Path) -> Result<(), StrategyError> {
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(StrategyError::Invalid(format!(
            "strategy data path must stay relative to the strategy directory: {}",
            path.display()
        )));
    }

    if path.as_os_str().is_empty() {
        return Err(StrategyError::Invalid(
            "strategy data path must not be empty".to_owned(),
        ));
    }

    Ok(())
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug)]
pub enum StrategyError {
    Io { path: PathBuf, source: io::Error },
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for StrategyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read strategy {}: {source}", path.display())
            }
            Self::Parse(source) => write!(f, "invalid strategy TOML: {source}"),
            Self::Invalid(message) => write!(f, "invalid strategy: {message}"),
        }
    }
}

impl Error for StrategyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
schema = 1
id = "general-simple-fake"
description = "Example structured strategy"

[filters]
tcp_ports = [
  { start = 80, end = 80 },
  { start = 443, end = 443 },
]
udp_ports = [
  { start = 443, end = 443 },
]
domain_lists = ["lists/general.txt"]

[[desync]]
mode = "fake"
repeats = 2

[[desync]]
mode = "multi-split"
positions = [1, 2]
"#;

    #[test]
    fn parses_valid_strategy() {
        let strategy = StrategyDefinition::parse(VALID).expect("strategy should parse");
        assert_eq!(strategy.id, "general-simple-fake");
        assert_eq!(strategy.desync.len(), 2);
    }

    #[test]
    fn rejects_parent_directory_data_path() {
        let input = VALID.replace("lists/general.txt", "../private.txt");
        assert!(StrategyDefinition::parse(&input).is_err());
    }

    #[test]
    fn rejects_zero_repeat() {
        let input = VALID.replace("repeats = 2", "repeats = 0");
        assert!(StrategyDefinition::parse(&input).is_err());
    }

    #[test]
    fn rejects_inverted_port_range() {
        let input = VALID.replace("{ start = 80, end = 80 }", "{ start = 443, end = 80 }");
        assert!(StrategyDefinition::parse(&input).is_err());
    }
}
