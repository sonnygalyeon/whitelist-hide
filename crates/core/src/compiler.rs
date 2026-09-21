use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::strategy::{DesyncStage, PortRange, StrategyDefinition, StrategyError};
use crate::Platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineTarget {
    MacOsUtun,
    LinuxNfqueue { queue_num: u16 },
    WindowsWinDivert,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledStrategy {
    pub args: Vec<String>,
    pub tcp_ports: String,
    pub udp_ports: String,
}

impl CompiledStrategy {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }
}

pub fn compile_strategy(
    strategy: &StrategyDefinition,
    strategy_path: &Path,
    target: EngineTarget,
) -> Result<CompiledStrategy, StrategyError> {
    strategy.validate()?;

    let base = strategy_path.parent().unwrap_or_else(|| Path::new("."));
    validate_lists(strategy, base)?;

    let tcp_ports = format_ranges(&strategy.filters.tcp_ports);
    let udp_ports = format_ranges(&strategy.filters.udp_ports);
    let mut args = Vec::new();

    match target {
        EngineTarget::LinuxNfqueue { queue_num } => {
            if queue_num == 0 {
                return Err(StrategyError::Invalid(
                    "NFQUEUE number must be greater than zero".to_owned(),
                ));
            }
            args.push(format!("--qnum={queue_num}"));
        }
        EngineTarget::WindowsWinDivert => {
            if !tcp_ports.is_empty() {
                args.push(format!("--wf-tcp={tcp_ports}"));
            }
            if !udp_ports.is_empty() {
                args.push(format!("--wf-udp={udp_ports}"));
            }
        }
        EngineTarget::MacOsUtun => {}
    }

    if !tcp_ports.is_empty() {
        args.push(format!("--filter-tcp={tcp_ports}"));
    }
    if !udp_ports.is_empty() {
        args.push(format!("--filter-udp={udp_ports}"));
    }

    for path in &strategy.filters.domain_exclude_lists {
        args.push(format!(
            "--hostlist-exclude={}",
            resolve_list(base, path)?.display()
        ));
    }
    for path in &strategy.filters.ip_exclude_lists {
        args.push(format!(
            "--ipset-exclude={}",
            resolve_list(base, path)?.display()
        ));
    }
    for path in &strategy.filters.domain_lists {
        args.push(format!("--hostlist={}", resolve_list(base, path)?.display()));
    }
    for path in &strategy.filters.ip_lists {
        if matches!(target, EngineTarget::WindowsWinDivert) {
            return Err(StrategyError::Invalid(
                "Windows winws profile rejects file-backed ipsets in v1; use domain lists or kernel port filters"
                    .to_owned(),
            ));
        }
        args.push(format!("--ipset={}", resolve_list(base, path)?.display()));
    }

    let mut modes = Vec::new();
    let mut split_positions: Option<Vec<u16>> = None;
    let mut fake_repeats: Option<u8> = None;
    let mut udp_increment: Option<u16> = None;

    for stage in &strategy.desync {
        match stage {
            DesyncStage::Fake { repeats } => {
                modes.push("fake");
                match fake_repeats {
                    Some(previous) if previous != *repeats => {
                        return Err(StrategyError::Invalid(
                            "multiple fake stages with different repeat counts are ambiguous".to_owned(),
                        ));
                    }
                    _ => fake_repeats = Some(*repeats),
                }
            }
            DesyncStage::MultiSplit { positions } => {
                modes.push("multisplit");
                merge_positions(&mut split_positions, positions)?;
            }
            DesyncStage::MultiDisorder { positions } => {
                modes.push("multidisorder");
                merge_positions(&mut split_positions, positions)?;
            }
            DesyncStage::FakeSplit { position } => {
                modes.push("fakedsplit");
                merge_positions(&mut split_positions, &[*position])?;
            }
            DesyncStage::UdpLength { increment } => {
                modes.push("udplen");
                match udp_increment {
                    Some(previous) if previous != *increment => {
                        return Err(StrategyError::Invalid(
                            "multiple udp-length stages with different increments are ambiguous"
                                .to_owned(),
                        ));
                    }
                    _ => udp_increment = Some(*increment),
                }
            }
            DesyncStage::IpFragment2 => modes.push("ipfrag2"),
        }
    }

    if !modes.is_empty() {
        args.push(format!("--dpi-desync={}", modes.join(",")));
    }
    if let Some(repeats) = fake_repeats {
        args.push(format!("--dpi-desync-repeats={repeats}"));
    }
    if let Some(positions) = split_positions {
        args.push(format!(
            "--dpi-desync-split-pos={}",
            positions
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(increment) = udp_increment {
        args.push(format!("--dpi-desync-udplen-increment={increment}"));
    }

    Ok(CompiledStrategy {
        args,
        tcp_ports,
        udp_ports,
    })
}

#[must_use]
pub fn target_for_current_platform(queue_num: u16) -> Option<EngineTarget> {
    match Platform::detect() {
        Platform::MacOS => Some(EngineTarget::MacOsUtun),
        Platform::Linux => Some(EngineTarget::LinuxNfqueue { queue_num }),
        Platform::Windows => Some(EngineTarget::WindowsWinDivert),
        Platform::Unsupported => None,
    }
}

fn merge_positions(
    current: &mut Option<Vec<u16>>,
    positions: &[u16],
) -> Result<(), StrategyError> {
    match current {
        Some(existing) if existing.as_slice() != positions => Err(StrategyError::Invalid(
            "desync stages require different split positions and cannot share one zapret profile"
                .to_owned(),
        )),
        Some(_) => Ok(()),
        None => {
            *current = Some(positions.to_vec());
            Ok(())
        }
    }
}

fn format_ranges(ranges: &[PortRange]) -> String {
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

fn resolve_list(base: &Path, relative: &Path) -> Result<PathBuf, StrategyError> {
    let path = base.join(relative);
    path.canonicalize().map_err(|source| StrategyError::Io {
        path,
        source,
    })
}

fn validate_lists(strategy: &StrategyDefinition, base: &Path) -> Result<(), StrategyError> {
    for path in strategy
        .filters
        .domain_lists
        .iter()
        .chain(strategy.filters.domain_exclude_lists.iter())
    {
        validate_domain_list(&base.join(path))?;
    }

    for path in strategy
        .filters
        .ip_lists
        .iter()
        .chain(strategy.filters.ip_exclude_lists.iter())
    {
        validate_ip_list(&base.join(path))?;
    }

    Ok(())
}

fn validate_domain_list(path: &Path) -> Result<(), StrategyError> {
    let text = fs::read_to_string(path).map_err(|source| StrategyError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    for (index, raw) in text.lines().enumerate() {
        let value = raw.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let domain = value.strip_prefix('^').unwrap_or(value);
        let valid = !domain.is_empty()
            && domain.len() <= 253
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && domain.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
            });

        if !valid {
            return Err(StrategyError::Invalid(format!(
                "invalid domain list entry at {}:{}",
                path.display(),
                index + 1
            )));
        }
    }

    Ok(())
}

fn validate_ip_list(path: &Path) -> Result<(), StrategyError> {
    let text = fs::read_to_string(path).map_err(|source| StrategyError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    for (index, raw) in text.lines().enumerate() {
        let value = raw.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }

        if !valid_ip_or_cidr(value) {
            return Err(StrategyError::Invalid(format!(
                "invalid IP/CIDR entry at {}:{}",
                path.display(),
                index + 1
            )));
        }
    }

    Ok(())
}

fn valid_ip_or_cidr(value: &str) -> bool {
    let Some((ip_text, prefix_text)) = value.split_once('/') else {
        return value.parse::<IpAddr>().is_ok();
    };

    let Ok(ip) = ip_text.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix_text.parse::<u8>() else {
        return false;
    };

    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::{StrategyFilters, StrategyDefinition};

    #[test]
    fn formats_ranges_deterministically() {
        let ranges = [
            PortRange { start: 80, end: 80 },
            PortRange {
                start: 443,
                end: 445,
            },
        ];
        assert_eq!(format_ranges(&ranges), "80,443-445");
    }

    #[test]
    fn rejects_bad_cidr() {
        assert!(valid_ip_or_cidr("1.2.3.4/24"));
        assert!(!valid_ip_or_cidr("1.2.3.4/99"));
        assert!(valid_ip_or_cidr("2001:db8::/32"));
    }

    #[test]
    fn windows_compiler_adds_windivert_filters() {
        let strategy = StrategyDefinition {
            schema: 1,
            id: "test".to_owned(),
            description: String::new(),
            filters: StrategyFilters {
                tcp_ports: vec![PortRange { start: 443, end: 443 }],
                udp_ports: vec![PortRange { start: 443, end: 443 }],
                domain_lists: Vec::new(),
                domain_exclude_lists: Vec::new(),
                ip_lists: Vec::new(),
                ip_exclude_lists: Vec::new(),
            },
            desync: vec![DesyncStage::Fake { repeats: 2 }],
        };

        let compiled = compile_strategy(
            &strategy,
            Path::new("strategy.toml"),
            EngineTarget::WindowsWinDivert,
        )
        .expect("strategy should compile");

        assert!(compiled.args.contains(&"--wf-tcp=443".to_owned()));
        assert!(compiled.args.contains(&"--wf-udp=443".to_owned()));
        assert!(compiled.args.contains(&"--dpi-desync=fake".to_owned()));
        assert!(compiled.args.contains(&"--dpi-desync-repeats=2".to_owned()));
    }
}
