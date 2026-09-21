use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::strategy::{DesyncStage, PortRange, StrategyDefinition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFlavor {
    Utunws,
    Nfqws,
    Winws,
}

impl EngineFlavor {
    pub fn parse(value: &str) -> Result<Self, CompileError> {
        match value {
            "utunws" => Ok(Self::Utunws),
            "nfqws" => Ok(Self::Nfqws),
            "winws" | "winws.exe" => Ok(Self::Winws),
            _ => Err(CompileError::UnsupportedEngine(value.to_owned())),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Utunws => "utunws",
            Self::Nfqws => "nfqws",
            Self::Winws => "winws",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledStrategy {
    pub engine: EngineFlavor,
    pub args: Vec<String>,
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
    let tcp = format_ports(&strategy.filters.tcp_ports);
    let udp = format_ports(&strategy.filters.udp_ports);
    let mut args = Vec::new();

    match engine {
        EngineFlavor::Winws => {
            if !tcp.is_empty() {
                args.push(format!("--wf-tcp={tcp}"));
            }
            if !udp.is_empty() {
                args.push(format!("--wf-udp={udp}"));
            }
        }
        EngineFlavor::Nfqws => args.push("--qnum=200".to_owned()),
        EngineFlavor::Utunws => {}
    }

    if !tcp.is_empty() {
        args.push(format!("--filter-tcp={tcp}"));
    }
    if !udp.is_empty() {
        args.push(format!("--filter-udp={udp}"));
    }

    for path in &strategy.filters.domain_lists {
        args.push(format!(
            "--hostlist={}",
            display_path(&resolve_strategy_path(base, path))?
        ));
    }
    for path in &strategy.filters.ip_lists {
        args.push(format!(
            "--ipset={}",
            display_path(&resolve_strategy_path(base, path))?
        ));
    }

    if !strategy.desync.is_empty() {
        let modes = strategy
            .desync
            .iter()
            .map(desync_mode)
            .collect::<Vec<_>>()
            .join(",");
        args.push(format!("--dpi-desync={modes}"));

        if let Some(repeats) = strategy.desync.iter().filter_map(|stage| match stage {
            DesyncStage::Fake { repeats } => Some(*repeats),
            _ => None,
        }).max() {
            args.push(format!("--dpi-desync-repeats={repeats}"));
        }

        let positions = strategy
            .desync
            .iter()
            .flat_map(|stage| match stage {
                DesyncStage::MultiSplit { positions }
                | DesyncStage::MultiDisorder { positions } => positions.clone(),
                DesyncStage::FakeSplit { position } => vec![*position],
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        if !positions.is_empty() {
            args.push(format!(
                "--dpi-desync-split-pos={}",
                positions
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }

        if let Some(increment) = strategy.desync.iter().find_map(|stage| match stage {
            DesyncStage::UdpLength { increment } => Some(*increment),
            _ => None,
        }) {
            args.push(format!("--dpi-desync-udplen-increment={increment}"));
        }
    }

    Ok(CompiledStrategy { engine, args })
}

fn desync_mode(stage: &DesyncStage) -> &'static str {
    match stage {
        DesyncStage::Fake { .. } => "fake",
        DesyncStage::MultiSplit { .. } => "multisplit",
        DesyncStage::MultiDisorder { .. } => "multidisorder",
        DesyncStage::FakeSplit { .. } => "fakedsplit",
        DesyncStage::UdpLength { .. } => "udplen",
        DesyncStage::IpFragment2 => "ipfrag2",
    }
}

fn resolve_strategy_path(base: &Path, path: &Path) -> PathBuf {
    base.join(path)
}

fn display_path(path: &Path) -> Result<String, CompileError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| CompileError::NonUtf8Path(path.to_path_buf()))
}

fn format_ports(ranges: &[PortRange]) -> String {
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

#[derive(Debug)]
pub enum CompileError {
    UnsupportedEngine(String),
    InvalidStrategy(String),
    NonUtf8Path(PathBuf),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEngine(engine) => write!(f, "unsupported engine: {engine}"),
            Self::InvalidStrategy(message) => write!(f, "strategy cannot be compiled: {message}"),
            Self::NonUtf8Path(path) => {
                write!(f, "strategy path is not valid UTF-8: {}", path.display())
            }
        }
    }
}

impl Error for CompileError {}

#[cfg(test)]
mod tests {
    use super::*;

    const STRATEGY: &str = r#"
schema = 1
id = "test"

[filters]
tcp_ports = [{ start = 80, end = 80 }, { start = 443, end = 443 }]
udp_ports = [{ start = 443, end = 443 }]
domain_lists = ["lists/general.txt"]

[[desync]]
mode = "fake"
repeats = 6

[[desync]]
mode = "multi-split"
positions = [1, 2]
"#;

    #[test]
    fn compiles_windows_capture_and_desync_args() {
        let strategy = StrategyDefinition::parse(STRATEGY).expect("strategy");
        let compiled = compile_strategy(
            &strategy,
            Path::new("/tmp/strategy.toml"),
            EngineFlavor::Winws,
        )
        .expect("compile");

        assert!(compiled.args.contains(&"--wf-tcp=80,443".to_owned()));
        assert!(compiled.args.contains(&"--wf-udp=443".to_owned()));
        assert!(
            compiled
                .args
                .contains(&"--dpi-desync=fake,multisplit".to_owned())
        );
        assert!(
            compiled
                .args
                .contains(&"--dpi-desync-repeats=6".to_owned())
        );
    }

    #[test]
    fn compiles_linux_queue_number() {
        let strategy = StrategyDefinition::parse(STRATEGY).expect("strategy");
        let compiled = compile_strategy(
            &strategy,
            Path::new("/tmp/strategy.toml"),
            EngineFlavor::Nfqws,
        )
        .expect("compile");
        assert_eq!(compiled.args.first().map(String::as_str), Some("--qnum=200"));
    }
}
