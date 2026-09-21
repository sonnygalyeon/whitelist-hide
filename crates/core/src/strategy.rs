use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const STRATEGY_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyManifest {
    pub schema: u32,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<StrategyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyRule {
    pub name: String,
    pub protocol: TransportProtocol,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub domains: Vec<String>,
    pub actions: Vec<StrategyAction>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrategyAction {
    Split { position: u16 },
    MultiSplit { positions: Vec<u16> },
    Disorder,
    Fake { template: String },
}

impl StrategyManifest {
    pub fn parse(input: &str) -> Result<Self, StrategyError> {
        let strategy: Self = toml::from_str(input).map_err(StrategyError::Parse)?;
        strategy.validate()?;
        Ok(strategy)
    }

    pub fn load(path: &Path) -> Result<Self, StrategyError> {
        let input = std::fs::read_to_string(path).map_err(|source| StrategyError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&input)
    }

    pub fn validate(&self) -> Result<(), StrategyError> {
        if self.schema != STRATEGY_SCHEMA {
            return Err(StrategyError::Invalid(format!(
                "unsupported strategy schema {}; expected {STRATEGY_SCHEMA}",
                self.schema
            )));
        }
        if !safe_identifier(&self.name) {
            return Err(StrategyError::Invalid("invalid strategy name".to_owned()));
        }
        if self.rules.is_empty() {
            return Err(StrategyError::Invalid(
                "strategy must contain at least one rule".to_owned(),
            ));
        }

        for rule in &self.rules {
            if !safe_identifier(&rule.name) {
                return Err(StrategyError::Invalid(format!(
                    "invalid rule name: {}",
                    rule.name
                )));
            }
            if rule.actions.is_empty() {
                return Err(StrategyError::Invalid(format!(
                    "rule {} has no actions",
                    rule.name
                )));
            }
            for port in &rule.ports {
                if port.start == 0 || port.end == 0 || port.start > port.end {
                    return Err(StrategyError::Invalid(format!(
                        "invalid port range {}-{} in rule {}",
                        port.start, port.end, rule.name
                    )));
                }
            }
            for domain in &rule.domains {
                if !safe_domain(domain) {
                    return Err(StrategyError::Invalid(format!(
                        "invalid domain {domain:?} in rule {}",
                        rule.name
                    )));
                }
            }
            for action in &rule.actions {
                action.validate(&rule.name)?;
            }
        }
        Ok(())
    }
}

impl StrategyAction {
    fn validate(&self, rule: &str) -> Result<(), StrategyError> {
        match self {
            Self::Split { position } if *position == 0 => Err(StrategyError::Invalid(format!(
                "split position must be positive in rule {rule}"
            ))),
            Self::MultiSplit { positions }
                if positions.is_empty() || positions.iter().any(|position| *position == 0) =>
            {
                Err(StrategyError::Invalid(format!(
                    "multisplit positions must be non-empty and positive in rule {rule}"
                )))
            }
            Self::Fake { template } if !safe_identifier(template) => {
                Err(StrategyError::Invalid(format!(
                    "invalid fake template identifier in rule {rule}"
                )))
            }
            _ => Ok(()),
        }
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'*'))
        && !value.contains("..")
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
            Self::Io { path, source } => write!(f, "failed to access {}: {source}", path.display()),
            Self::Parse(source) => write!(f, "invalid strategy TOML: {source}"),
            Self::Invalid(message) => write!(f, "invalid strategy: {message}"),
        }
    }
}

impl Error for StrategyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_strategy() {
        let value = StrategyManifest::parse(
            r#"schema = 1
name = "general"

[[rules]]
name = "https"
protocol = "tcp"
domains = ["youtube.com", "*.googlevideo.com"]

[[rules.ports]]
start = 443
end = 443

[[rules.actions]]
kind = "split"
position = 1
"#,
        )
        .expect("strategy must parse");

        assert_eq!(value.rules.len(), 1);
    }
}
