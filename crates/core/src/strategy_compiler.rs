use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::strategy::{DesyncStage, PortRange, StrategyDefinition};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePlan {
    pub strategy_id: String,
    pub arguments: Vec<String>,
    pub referenced_files: Vec<PathBuf>,
}

pub fn compile_strategy(
    strategy: &StrategyDefinition,
    strategy_path: &Path,
) -> Result<EnginePlan, CompileError> {
    strategy
        .validate()
        .map_err(|error| CompileError::InvalidStrategy(error.to_string()))?;

    let base = strategy_path.parent().unwrap_or_else(|| Path::new("."));
    let mut referenced_files = Vec::new();

    let domain_lists = resolve_lists(base, &strategy.filters.domain_lists, &mut referenced_files)?;
    let ip_lists = resolve_lists(base, &strategy.filters.ip_lists, &mut referenced_files)?;

    let mut arguments = Vec::new();

    if !strategy.filters.tcp_ports.is_empty() {
        append_profile(
            &mut arguments,
            "tcp",
            &strategy.filters.tcp_ports,
            &domain_lists,
            &ip_lists,
            &strategy.desync,
        );
    }

    if !strategy.filters.udp_ports.is_empty() {
        if !arguments.is_empty() {
            arguments.push("--new".to_owned());
        }
        append_profile(
            &mut arguments,
            "udp",
            &strategy.filters.udp_ports,
            &domain_lists,
            &ip_lists,
            &strategy.desync,
        );
    }

    Ok(EnginePlan {
        strategy_id: strategy.id.clone(),
        arguments,
        referenced_files,
    })
}

fn resolve_lists(
    base: &Path,
    paths: &[PathBuf],
    referenced: &mut Vec<PathBuf>,
) -> Result<Vec<PathBuf>, CompileError> {
    let mut resolved = Vec::with_capacity(paths.len());

    for relative in paths {
        let path = base.join(relative);
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| CompileError::ListIo {
            path: path.clone(),
            source,
        })?;

        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CompileError::UnsafeList(path));
        }

        let canonical = path.canonicalize().map_err(|source| CompileError::ListIo {
            path: path.clone(),
            source,
        })?;
        resolved.push(canonical.clone());
        referenced.push(canonical);
    }

    Ok(resolved)
}

fn append_profile(
    out: &mut Vec<String>,
    protocol: &str,
    ports: &[PortRange],
    domains: &[PathBuf],
    ipsets: &[PathBuf],
    stages: &[DesyncStage],
) {
    out.push(format!("--filter-{protocol}={}", format_ports(ports)));

    for path in domains {
        out.push(format!("--hostlist={}", path.display()));
    }
    for path in ipsets {
        out.push(format!("--ipset={}", path.display()));
    }

    let mut modes = Vec::new();
    let mut split_positions = Vec::new();
    let mut fake_repeats = None;
    let mut udp_increment = None;

    for stage in stages {
        match stage {
            DesyncStage::Fake { repeats } => {
                modes.push("fake");
                fake_repeats = Some(*repeats);
            }
            DesyncStage::MultiSplit { positions } => {
                modes.push("multisplit");
                split_positions.extend(positions.iter().copied());
            }
            DesyncStage::MultiDisorder { positions } => {
                modes.push("multidisorder");
                split_positions.extend(positions.iter().copied());
            }
            DesyncStage::FakeSplit { position } => {
                modes.push("fakedsplit");
                split_positions.push(*position);
            }
            DesyncStage::UdpLength { increment } => {
                modes.push("udplen");
                udp_increment = Some(*increment);
            }
            DesyncStage::IpFragment2 => modes.push("ipfrag2"),
        }
    }

    if !modes.is_empty() {
        out.push(format!("--dpi-desync={}", modes.join(",")));
    }
    if let Some(repeats) = fake_repeats {
        out.push(format!("--dpi-desync-repeats={repeats}"));
    }
    if !split_positions.is_empty() {
        split_positions.sort_unstable();
        split_positions.dedup();
        let positions = split_positions
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        out.push(format!("--dpi-desync-split-pos={positions}"));
    }
    if let Some(increment) = udp_increment {
        out.push(format!("--dpi-desync-udplen-increment={increment}"));
    }
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
    InvalidStrategy(String),
    ListIo {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsafeList(PathBuf),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStrategy(message) => f.write_str(message),
            Self::ListIo { path, source } => {
                write!(f, "cannot read strategy list {}: {source}", path.display())
            }
            Self::UnsafeList(path) => write!(
                f,
                "strategy list must be a regular non-symlink file: {}",
                path.display()
            ),
        }
    }
}

impl Error for CompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ListIo { source, .. } => Some(source),
            Self::InvalidStrategy(_) | Self::UnsafeList(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn formats_port_ranges_deterministically() {
        assert_eq!(
            format_ports(&[
                PortRange { start: 80, end: 80 },
                PortRange {
                    start: 443,
                    end: 443,
                },
                PortRange {
                    start: 5000,
                    end: 5010,
                },
            ]),
            "80,443,5000-5010"
        );
    }

    #[test]
    fn compiles_profiles_and_resolves_lists() {
        let root = std::env::temp_dir().join(format!(
            "whitelist-hide-compile-test-{}",
            std::process::id()
        ));
        let lists = root.join("lists");
        fs::create_dir_all(&lists).expect("create test dir");
        fs::write(lists.join("general.txt"), "example.com\n").expect("write list");

        let strategy = StrategyDefinition::parse(
            r#"
schema = 1
id = "test"

[filters]
tcp_ports = [{ start = 443, end = 443 }]
udp_ports = [{ start = 443, end = 443 }]
domain_lists = ["lists/general.txt"]

[[desync]]
mode = "fake"
repeats = 2

[[desync]]
mode = "multi-split"
positions = [2, 1]
"#,
        )
        .expect("parse strategy");

        let plan =
            compile_strategy(&strategy, &root.join("strategy.toml")).expect("compile strategy");

        assert!(plan.arguments.contains(&"--filter-tcp=443".to_owned()));
        assert!(plan.arguments.contains(&"--filter-udp=443".to_owned()));
        assert!(plan.arguments.contains(&"--new".to_owned()));
        assert!(
            plan.arguments
                .contains(&"--dpi-desync-split-pos=1,2".to_owned())
        );

        fs::remove_dir_all(root).expect("cleanup");
    }
}
