use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::strategy::{DesyncStage, PortRange, StrategyDefinition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFlavor {
    Nfqws,
    Utunws,
    Winws,
}

impl EngineFlavor {
    pub fn parse(value: &str) -> Result<Self, CompileError> {
        match value {
            "nfqws" => Ok(Self::Nfqws),
            "utunws" => Ok(Self::Utunws),
            "winws" => Ok(Self::Winws),
            _ => Err(CompileError::UnsupportedEngine(value.to_owned())),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Nfqws => "nfqws",
            Self::Utunws => "utunws",
            Self::Winws => "winws",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledStrategy {
    pub engine: EngineFlavor,
    pub args: Vec<String>,
}

impl CompiledStrategy {
    #[must_use]
    pub fn as_config_text(&self) -> String {
        self.args.join("\n")
    }
}

pub fn compile_strategy(
    strategy: &StrategyDefinition,
    strategy_path: &Path,
    engine: EngineFlavor,
) -> Result<CompiledStrategy, CompileError> {
    strategy
        .validate()
        .map_err(|error| CompileError::InvalidStrategy(error.to_string()))?;

    let base = strategy_path.parent().unwrap_or_else(|| Path::new("."));
    let mut args = Vec::new();

    if !strategy.filters.tcp_ports.is_empty() {
        args.push(format!(
            "--filter-tcp={}",
            format_port_ranges(&strategy.filters.tcp_ports)
        ));
    }

    if !strategy.filters.udp_ports.is_empty() {
        if !args.is_empty() {
            args.push("--new".to_owned());
        }
        args.push(format!(
            "--filter-udp={}",
            format_port_ranges(&strategy.filters.udp_ports)
        ));
    }

    for list in &strategy.filters.domain_lists {
        args.push(format!(
            "--hostlist={}",
            resolve_strategy_data_path(base, list)?.display()
        ));
    }

    for list in &strategy.filters.ip_lists {
        args.push(format!(
            "--ipset={}",
            resolve_strategy_data_path(base, list)?.display()
        ));
    }

    compile_desync(&strategy.desync, &mut args)?;

    Ok(CompiledStrategy { engine, args })
}

fn compile_desync(stages: &[DesyncStage], args: &mut Vec<String>) -> Result<(), CompileError> {
    if stages.is_empty() {
        return Ok(());
    }

    let mut modes = Vec::new();
    let mut repeats: Option<u8> = None;
    let mut split_positions: Vec<u16> = Vec::new();
    let mut udp_increment: Option<u16> = None;

    for stage in stages {
        match stage {
            DesyncStage::Fake { repeats: value } => {
                modes.push("fake");
                repeats = Some(*value);
            }
            DesyncStage::MultiSplit { positions } => {
                modes.push("multisplit");
                split_positions.extend(positions);
            }
            DesyncStage::MultiDisorder { positions } => {
                modes.push("multidisorder");
                split_positions.extend(positions);
            }
            DesyncStage::FakeSplit { position } => {
                modes.push("fakesplit");
                split_positions.push(*position);
            }
            DesyncStage::UdpLength { increment } => {
                modes.push("udplen");
                udp_increment = Some(*increment);
            }
            DesyncStage::IpFragment2 => modes.push("ipfrag2"),
        }
    }

    modes.dedup();
    args.push(format!("--dpi-desync={}", modes.join(",")));

    if let Some(value) = repeats {
        args.push(format!("--dpi-desync-repeats={value}"));
    }

    if !split_positions.is_empty() {
        split_positions.sort_unstable();
        split_positions.dedup();
        let value = split_positions
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        args.push(format!("--dpi-desync-split-pos={value}"));
    }

    if let Some(value) = udp_increment {
        args.push(format!("--dpi-desync-udplen-increment={value}"));
    }

    Ok(())
}

fn format_port_ranges(ranges: &[PortRange]) -> String {
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

fn resolve_strategy_data_path(base: &Path, relative: &Path) -> Result<PathBuf, CompileError> {
    let resolved = base.join(relative);
    if resolved.exists() {
        resolved.canonicalize().map_err(|source| CompileError::Io {
            path: resolved,
            source,
        })
    } else {
        Ok(resolved)
    }
}

#[derive(Debug)]
pub enum CompileError {
    UnsupportedEngine(String),
    InvalidStrategy(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEngine(engine) => {
                write!(f, "unsupported engine flavor: {engine}")
            }
            Self::InvalidStrategy(message) => f.write_str(message),
            Self::Io { path, source } => {
                write!(f, "failed to resolve strategy path {}: {source}", path.display())
            }
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::StrategyDefinition;

    const STRATEGY: &str = r#"
schema = 1
id = "test"

[filters]
tcp_ports = [{ start = 80, end = 80 }, { start = 443, end = 443 }]
udp_ports = [{ start = 443, end = 443 }]
domain_lists = ["lists/general.txt"]

[[desync]]
mode = "fake"
repeats = 2

[[desync]]
mode = "multi-split"
positions = [2, 1]
"#;

    #[test]
    fn compiles_deterministically() {
        let strategy = StrategyDefinition::parse(STRATEGY).expect("valid strategy");
        let compiled = compile_strategy(
            &strategy,
            Path::new("/tmp/whitelist-hide/strategy.toml"),
            EngineFlavor::Nfqws,
        )
        .expect("compile");

        assert_eq!(compiled.args[0], "--filter-tcp=80,443");
        assert!(compiled.args.contains(&"--new".to_owned()));
        assert!(compiled.args.contains(&"--filter-udp=443".to_owned()));
        assert!(
            compiled
                .args
                .contains(&"--dpi-desync=fake,multisplit".to_owned())
        );
        assert!(
            compiled
                .args
                .contains(&"--dpi-desync-split-pos=1,2".to_owned())
        );
    }

    #[test]
    fn rejects_unknown_engine() {
        assert!(EngineFlavor::parse("mystery").is_err());
    }
}
