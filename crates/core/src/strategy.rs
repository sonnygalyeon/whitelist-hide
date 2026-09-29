use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StrategyDefinition {
    pub schema: u32,
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub filters: StrategyFilters,
    #[serde(default)]
    pub desync: Vec<DesyncStage>,
    #[serde(default)]
    pub rules: Vec<ProtocolRule>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
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

/// Packet classification stays inside the pinned zapret engines.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Http,
    Tls,
    Quic,
    DiscordStun,
}

impl Protocol {
    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Http | Self::Tls)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRule {
    pub protocol: Protocol,
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub domain_lists: Vec<PathBuf>,
    #[serde(default)]
    pub ip_lists: Vec<PathBuf>,
    pub desync: Vec<DesyncStage>,
    #[serde(default)]
    pub tcp_fooling: TcpFooling,
    /// Hex text data only; never an executable or a command line fragment.
    #[serde(default)]
    pub fake_payload: Option<PathBuf>,
    #[serde(default)]
    pub split_seqovl: Option<u16>,
    #[serde(default)]
    pub split_pattern: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TcpFooling {
    #[default]
    BadSeq,
    Md5Sig,
    Timestamp,
}

impl TcpFooling {
    pub const fn v1(self) -> &'static str {
        match self {
            Self::BadSeq => "badseq",
            Self::Md5Sig => "md5sig",
            Self::Timestamp => "ts",
        }
    }
    pub const fn lua(self) -> &'static str {
        match self {
            Self::BadSeq => ":tcp_seq=-10000",
            Self::Md5Sig => ":tcp_md5",
            Self::Timestamp => ":tcp_ts=-1000",
        }
    }
}

impl StrategyDefinition {
    pub fn parse(input: &str) -> Result<Self, StrategyError> {
        let mut strategy: Self = toml::from_str(input).map_err(StrategyError::Parse)?;
        if strategy.schema == 2 {
            if strategy.filters != StrategyFilters::default() || !strategy.desync.is_empty() {
                return Err(StrategyError::Invalid(
                    "schema 2 uses only explicit protocol rules".into(),
                ));
            }
            strategy.filters = strategy.capture_filters();
        }
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
        if !matches!(self.schema, 1 | 2) {
            return Err(StrategyError::Invalid(format!(
                "unsupported strategy schema {}; expected 1 or 2",
                self.schema
            )));
        }

        if self.schema == 1 && !self.rules.is_empty() {
            return Err(StrategyError::Invalid(
                "protocol rules require schema 2".into(),
            ));
        }
        if self.schema == 2 {
            if self.rules.is_empty()
                || !self.desync.is_empty()
                || self.filters != self.capture_filters()
            {
                return Err(StrategyError::Invalid(
                    "invalid schema 2 capture rules".into(),
                ));
            }
            for rule in &self.rules {
                rule.validate()?;
            }
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

    fn capture_filters(&self) -> StrategyFilters {
        let mut filters = StrategyFilters::default();
        for rule in &self.rules {
            let ports = if rule.protocol.is_tcp() {
                &mut filters.tcp_ports
            } else {
                &mut filters.udp_ports
            };
            for port in &rule.ports {
                if !ports.contains(port) {
                    ports.push(*port);
                }
            }
            for path in &rule.domain_lists {
                if !filters.domain_lists.contains(path) {
                    filters.domain_lists.push(path.clone());
                }
            }
            for path in &rule.ip_lists {
                if !filters.ip_lists.contains(path) {
                    filters.ip_lists.push(path.clone());
                }
            }
        }
        filters
    }
}

impl ProtocolRule {
    fn validate(&self) -> Result<(), StrategyError> {
        let invalid = |message: &str| StrategyError::Invalid(message.to_owned());
        if self.ports.is_empty() || self.desync.is_empty() {
            return Err(invalid("each protocol rule needs ports and desync stages"));
        }
        validate_ranges("rule ports", &self.ports)?;
        if self.protocol == Protocol::DiscordStun && !self.domain_lists.is_empty() {
            return Err(invalid(
                "Discord/STUN has no hostname: a hostlist would disable voice matching",
            ));
        }
        if self.protocol != Protocol::DiscordStun
            && self.domain_lists.is_empty()
            && self.ip_lists.is_empty()
        {
            return Err(invalid(
                "HTTP/TLS/QUIC rules must be scoped to a domain or IP list",
            ));
        }
        let mut fake = false;
        let mut transform = false;
        for stage in &self.desync {
            match stage {
                DesyncStage::Fake { repeats } => {
                    if fake || transform || *repeats == 0 || *repeats > 20 {
                        return Err(invalid("fake must be first, unique and repeat 1..20 times"));
                    }
                    fake = true;
                }
                _ => {
                    if transform {
                        return Err(invalid(
                            "only one packet transform per rule is supported by all engines",
                        ));
                    }
                    transform = true;
                    match stage {
                        DesyncStage::MultiSplit { positions }
                        | DesyncStage::MultiDisorder { positions } => {
                            if !self.protocol.is_tcp()
                                || positions.is_empty()
                                || positions.contains(&0)
                            {
                                return Err(invalid(
                                    "TCP split/disorder requires non-zero positions",
                                ));
                            }
                        }
                        DesyncStage::FakeSplit { position } => {
                            if !self.protocol.is_tcp() || *position == 0 {
                                return Err(invalid(
                                    "fake-split requires TCP and a non-zero position",
                                ));
                            }
                        }
                        DesyncStage::UdpLength { increment }
                            if self.protocol.is_tcp() || *increment == 0 =>
                        {
                            return Err(invalid(
                                "udp-length requires UDP and a non-zero increment",
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
        for path in self.domain_lists.iter().chain(self.ip_lists.iter()) {
            validate_relative_data_path(path)?;
        }
        for path in self.fake_payload.iter().chain(self.split_pattern.iter()) {
            validate_relative_data_path(path)?;
        }
        if self.fake_payload.is_some() && !fake {
            return Err(invalid("fake payload requires a fake stage"));
        }
        if self.split_pattern.is_some() != self.split_seqovl.is_some() {
            return Err(invalid("sequence overlap requires both length and pattern"));
        }
        if let Some(overlap) = self.split_seqovl
            && (!(1..=2048).contains(&overlap)
                || !self
                    .desync
                    .iter()
                    .any(|s| matches!(s, DesyncStage::MultiSplit { .. })))
        {
            return Err(invalid(
                "sequence overlap requires multi-split and a length of 1..2048",
            ));
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
