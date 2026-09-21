use std::error::Error;
use std::ffi::OsString;
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

        if self.desync.is_empty() {
            return Err(StrategyError::Invalid(
                "at least one desync stage is required".to_owned(),
            ));
        }
        if self.desync.len() > 2 {
            return Err(StrategyError::Invalid(
                "the initial compiler supports at most two desync stages per profile".to_owned(),
            ));
        }

        if self.desync.len() == 2 && !matches!(self.desync[0], DesyncStage::Fake { .. }) {
            return Err(StrategyError::Invalid(
                "two-stage profiles currently require fake as the first stage".to_owned(),
            ));
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

        let second = self.desync.last().filter(|_| self.desync.len() == 2);
        let single = (self.desync.len() == 1).then(|| &self.desync[0]);
        let effective_second = second.or(single);

        if matches!(
            effective_second,
            Some(
                DesyncStage::MultiSplit { .. }
                    | DesyncStage::MultiDisorder { .. }
                    | DesyncStage::FakeSplit { .. }
            )
        ) && !self.filters.udp_ports.is_empty()
        {
            return Err(StrategyError::Invalid(
                "TCP split/disorder modes require an empty UDP filter in this profile".to_owned(),
            ));
        }

        if matches!(effective_second, Some(DesyncStage::UdpLength { .. }))
            && !self.filters.tcp_ports.is_empty()
        {
            return Err(StrategyError::Invalid(
                "udp-length mode requires an empty TCP filter in this profile".to_owned(),
            ));
        }

        Ok(())
    }

    pub fn zapret_arguments(&self, strategy_path: &Path) -> Result<Vec<OsString>, StrategyError> {
        self.validate()?;

        let base = strategy_path.parent().unwrap_or_else(|| Path::new("."));
        let mut args = Vec::new();

        if !self.filters.tcp_ports.is_empty() {
            args.push(OsString::from(format!(
                "--filter-tcp={}",
                engine_port_list(&self.filters.tcp_ports)
            )));
        }
        if !self.filters.udp_ports.is_empty() {
            args.push(OsString::from(format!(
                "--filter-udp={}",
                engine_port_list(&self.filters.udp_ports)
            )));
        }

        for relative in &self.filters.domain_lists {
            args.push(path_argument("--hostlist=@", &base.join(relative)));
        }
        for relative in &self.filters.ip_lists {
            args.push(path_argument("--ipset=@", &base.join(relative)));
        }

        let modes = self
            .desync
            .iter()
            .map(stage_engine_name)
            .collect::<Vec<_>>()
            .join(",");
        args.push(OsString::from(format!("--dpi-desync={modes}")));

        for stage in &self.desync {
            match stage {
                DesyncStage::Fake { repeats } => {
                    args.push(OsString::from(format!("--dpi-desync-repeats={repeats}")));
                }
                DesyncStage::MultiSplit { positions }
                | DesyncStage::MultiDisorder { positions } => {
                    args.push(OsString::from(format!(
                        "--dpi-desync-split-pos={}",
                        positions
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    )));
                }
                DesyncStage::FakeSplit { position } => {
                    args.push(OsString::from(format!(
                        "--dpi-desync-split-pos={position}"
                    )));
                }
                DesyncStage::UdpLength { increment } => {
                    args.push(OsString::from(format!(
                        "--dpi-desync-udplen-increment={increment}"
                    )));
                }
                DesyncStage::IpFragment2 => {}
            }
        }

        Ok(args)
    }
}

pub fn pf_port_list(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}:{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn engine_port_list(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}-{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn path_argument(prefix: &str, path: &Path) -> OsString {
    let mut value = OsString::from(prefix);
    value.push(path.as_os_str());
    value
}

fn stage_engine_name(stage: &DesyncStage) -> &'static str {
    match stage {
        DesyncStage::Fake { .. } => "fake",
        DesyncStage::MultiSplit { .. } => "multisplit",
        DesyncStage::MultiDisorder { .. } => "multidisorder",
        DesyncStage::FakeSplit { .. } => "fakedsplit",
        DesyncStage::UdpLength { .. } => "udplen",
        DesyncStage::IpFragment2 => "ipfrag2",
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
    fn compiles_engine_arguments_without_shell_text() {
        let strategy = StrategyDefinition::parse(VALID).expect("strategy should parse");
        let args = strategy
            .zapret_arguments(Path::new("/tmp/profile/strategy.toml"))
            .expect("arguments should compile");
        let text = args
            .iter()
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>();
        assert!(text.iter().any(|arg| arg.as_ref() == "--filter-tcp=80,443"));
        assert!(
            text.iter()
                .any(|arg| arg.as_ref() == "--dpi-desync=fake,multisplit")
        );
        assert!(
            text.iter()
                .any(|arg| arg.as_ref() == "--dpi-desync-split-pos=1,2")
        );
    }

    #[test]
    fn formats_pf_ranges() {
        assert_eq!(
            pf_port_list(&[
                PortRange { start: 443, end: 443 },
                PortRange {
                    start: 50000,
                    end: 50100,
                },
            ]),
            "443,50000:50100"
        );
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
