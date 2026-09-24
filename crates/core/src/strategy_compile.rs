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
            Self::Winws => "winws2",
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
    let args = match engine {
        EngineFlavor::Winws => compile_winws2(strategy, base)?,
        EngineFlavor::Nfqws | EngineFlavor::Utunws => compile_v1(strategy, base)?,
    };

    Ok(CompiledStrategy { engine, args })
}

fn compile_v1(strategy: &StrategyDefinition, base: &Path) -> Result<Vec<String>, CompileError> {
    let common = compile_list_args(strategy, base)?;
    let mut args = Vec::new();
    if !strategy.filters.tcp_ports.is_empty() {
        args.push(format!(
            "--filter-tcp={}",
            format_port_ranges(&strategy.filters.tcp_ports)
        ));
        args.extend(common.iter().cloned());
        let stages: Vec<_> = strategy
            .desync
            .iter()
            .filter(|s| !matches!(s, DesyncStage::UdpLength { .. }))
            .cloned()
            .collect();
        compile_v1_desync(&stages, &mut args);
        if stages
            .iter()
            .any(|s| matches!(s, DesyncStage::Fake { .. } | DesyncStage::FakeSplit { .. }))
        {
            args.push("--dpi-desync-fooling=badseq".to_owned());
        }
    }
    for (ports, domain_filter) in [
        (
            if contains_port(&strategy.filters.udp_ports, 443) {
                vec![PortRange {
                    start: 443,
                    end: 443,
                }]
            } else {
                vec![]
            },
            true,
        ),
        (without_port(&strategy.filters.udp_ports, 443), false),
    ] {
        if ports.is_empty() {
            continue;
        }
        push_new_if_needed(&mut args);
        args.push(format!("--filter-udp={}", format_port_ranges(&ports)));
        if domain_filter {
            args.extend(common.iter().cloned());
        } else {
            args.push("--filter-l7=discord,stun".to_owned());
        }
        let stages: Vec<_> = strategy
            .desync
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    DesyncStage::Fake { .. }
                        | DesyncStage::UdpLength { .. }
                        | DesyncStage::IpFragment2
                )
            })
            .cloned()
            .collect();
        compile_v1_desync(&stages, &mut args);
    }
    Ok(args)
}

fn compile_winws2(strategy: &StrategyDefinition, base: &Path) -> Result<Vec<String>, CompileError> {
    let mut args = Vec::new();

    if !strategy.filters.tcp_ports.is_empty() {
        args.push(format!(
            "--wf-tcp-out={}",
            format_port_ranges(&strategy.filters.tcp_ports)
        ));
    }
    if !strategy.filters.udp_ports.is_empty() {
        args.push(format!(
            "--wf-udp-out={}",
            format_port_ranges(&strategy.filters.udp_ports)
        ));
    }

    args.push("--lua-init=@zapret-lib.lua".to_owned());
    args.push("--lua-init=@zapret-antidpi.lua".to_owned());

    let common = compile_list_args(strategy, base)?;

    if contains_port(&strategy.filters.tcp_ports, 80) {
        push_winws2_profile(
            &mut args,
            "--filter-tcp=80".to_owned(),
            Some("--filter-l7=http"),
            Some("--payload=http_req"),
            &common,
            &strategy.desync,
            WinwsPayload::Http,
        );
    }

    let tls_ports = without_port(&strategy.filters.tcp_ports, 80);
    if !tls_ports.is_empty() {
        push_winws2_profile(
            &mut args,
            format!("--filter-tcp={}", format_port_ranges(&tls_ports)),
            Some("--filter-l7=tls"),
            Some("--payload=tls_client_hello"),
            &common,
            &strategy.desync,
            WinwsPayload::Tls,
        );
    }

    if contains_port(&strategy.filters.udp_ports, 443) {
        push_winws2_profile(
            &mut args,
            "--filter-udp=443".to_owned(),
            Some("--filter-l7=quic"),
            Some("--payload=quic_initial"),
            &common,
            &strategy.desync,
            WinwsPayload::Quic,
        );
    }

    let other_udp = without_port(&strategy.filters.udp_ports, 443);
    if !other_udp.is_empty() {
        push_winws2_profile(
            &mut args,
            format!("--filter-udp={}", format_port_ranges(&other_udp)),
            Some("--filter-l7=stun,discord"),
            Some("--payload=stun,discord_ip_discovery"),
            &[],
            &strategy.desync,
            WinwsPayload::GenericUdp,
        );
    }

    Ok(args)
}

fn push_winws2_profile(
    args: &mut Vec<String>,
    filter: String,
    l7: Option<&str>,
    payload: Option<&str>,
    common: &[String],
    stages: &[DesyncStage],
    kind: WinwsPayload,
) {
    if args.iter().any(|arg| arg.starts_with("--filter-")) {
        args.push("--new".to_owned());
    }
    args.push(filter);
    if let Some(l7) = l7 {
        args.push(l7.to_owned());
    }
    args.extend(common.iter().cloned());
    if let Some(payload) = payload {
        args.push(payload.to_owned());
    }
    compile_winws2_desync(stages, kind, args);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WinwsPayload {
    Http,
    Tls,
    Quic,
    GenericUdp,
}

impl WinwsPayload {
    const fn fake_blob(self) -> &'static str {
        match self {
            Self::Http => "fake_default_http",
            Self::Tls => "fake_default_tls",
            Self::Quic => "fake_default_quic",
            Self::GenericUdp => "0x00000000000000000000000000000000",
        }
    }

    const fn is_tcp(self) -> bool {
        matches!(self, Self::Http | Self::Tls)
    }

    const fn is_udp(self) -> bool {
        matches!(self, Self::Quic | Self::GenericUdp)
    }
}

fn compile_winws2_desync(stages: &[DesyncStage], kind: WinwsPayload, args: &mut Vec<String>) {
    for stage in stages {
        match stage {
            DesyncStage::Fake { repeats } => args.push(format!(
                "--lua-desync=fake:blob={}:repeats={repeats}{}",
                kind.fake_blob(),
                if kind.is_tcp() { ":tcp_seq=-10000" } else { "" }
            )),
            DesyncStage::MultiSplit { positions } if kind.is_tcp() => args.push(format!(
                "--lua-desync=multisplit:pos={}",
                format_positions(positions)
            )),
            DesyncStage::MultiDisorder { positions } if kind.is_tcp() => args.push(format!(
                "--lua-desync=multidisorder:pos={}",
                format_positions(positions)
            )),
            DesyncStage::FakeSplit { position } if kind.is_tcp() => {
                args.push(format!(
                    "--lua-desync=fakedsplit:pos={position}:tcp_seq=-10000"
                ));
            }
            DesyncStage::UdpLength { increment } if kind.is_udp() => {
                args.push(format!("--lua-desync=udplen:increment={increment}"));
            }
            DesyncStage::IpFragment2 => {
                args.push("--lua-desync=send:ipfrag".to_owned());
                args.push("--lua-desync=drop".to_owned());
            }
            _ => {}
        }
    }
}

fn compile_list_args(
    strategy: &StrategyDefinition,
    base: &Path,
) -> Result<Vec<String>, CompileError> {
    let mut args = Vec::new();

    for list in &strategy.filters.domain_lists {
        args.push(format!(
            "--hostlist={}",
            format_engine_data_path(&resolve_strategy_data_path(base, list)?)
        ));
    }

    for list in &strategy.filters.ip_lists {
        args.push(format!(
            "--ipset={}",
            format_engine_data_path(&resolve_strategy_data_path(base, list)?)
        ));
    }

    Ok(args)
}

fn format_engine_data_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        windows_engine_path(&path.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        path.display().to_string()
    }
}

#[cfg(any(windows, test))]
fn windows_engine_path(path: &str) -> String {
    // Cygwin interprets backslashes as escapes in arguments from native callers.
    // Rust canonical paths also have a Win32 verbatim prefix it cannot consume.
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!("//{}", unc.replace('\\', "/"))
    } else {
        path.strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('\\', "/")
    }
}

fn compile_v1_desync(stages: &[DesyncStage], args: &mut Vec<String>) {
    if stages.is_empty() {
        return;
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
        args.push(format!(
            "--dpi-desync-split-pos={}",
            format_positions(&split_positions)
        ));
    }

    if let Some(value) = udp_increment {
        args.push(format!("--dpi-desync-udplen-increment={value}"));
    }
}

fn push_new_if_needed(args: &mut Vec<String>) {
    if !args.is_empty() {
        args.push("--new".to_owned());
    }
}

fn contains_port(ranges: &[PortRange], port: u16) -> bool {
    ranges
        .iter()
        .any(|range| range.start <= port && port <= range.end)
}

fn without_port(ranges: &[PortRange], port: u16) -> Vec<PortRange> {
    let mut output = Vec::new();
    for range in ranges {
        if port < range.start || port > range.end {
            output.push(*range);
            continue;
        }

        if range.start < port {
            output.push(PortRange {
                start: range.start,
                end: port - 1,
            });
        }
        if port < range.end {
            output.push(PortRange {
                start: port + 1,
                end: range.end,
            });
        }
    }
    output
}

fn format_positions(positions: &[u16]) -> String {
    let mut positions = positions.to_vec();
    positions.sort_unstable();
    positions.dedup();
    positions
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
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
                write!(
                    f,
                    "failed to resolve strategy path {}: {source}",
                    path.display()
                )
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
    fn compiles_v1_deterministically() {
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
        assert_eq!(
            compiled
                .args
                .iter()
                .filter(|arg| *arg == "--dpi-desync=fake,multisplit")
                .count(),
            1
        );
    }

    #[test]
    fn compiles_winws2_capture_and_lua_profiles() {
        let strategy = StrategyDefinition::parse(STRATEGY).expect("valid strategy");
        let compiled = compile_strategy(&strategy, Path::new("strategy.toml"), EngineFlavor::Winws)
            .expect("compile");

        assert_eq!(compiled.args[0], "--wf-tcp-out=80,443");
        assert_eq!(compiled.args[1], "--wf-udp-out=443");
        assert!(
            compiled
                .args
                .contains(&"--lua-init=@zapret-lib.lua".to_owned())
        );
        assert!(compiled.args.contains(
            &"--lua-desync=fake:blob=fake_default_http:repeats=2:tcp_seq=-10000".to_owned()
        ));
        assert!(compiled.args.contains(
            &"--lua-desync=fake:blob=fake_default_tls:repeats=2:tcp_seq=-10000".to_owned()
        ));
        assert!(
            compiled
                .args
                .contains(&"--lua-desync=fake:blob=fake_default_quic:repeats=2".to_owned())
        );
        assert!(
            !compiled
                .args
                .iter()
                .any(|arg| arg.starts_with("--dpi-desync"))
        );
    }

    #[test]
    fn splits_capture_profiles_around_http_and_quic_ports() {
        let ranges = vec![PortRange { start: 79, end: 81 }];
        assert_eq!(
            without_port(&ranges, 80),
            vec![
                PortRange { start: 79, end: 79 },
                PortRange { start: 81, end: 81 }
            ]
        );
    }

    #[test]
    fn rejects_unknown_engine() {
        assert!(EngineFlavor::parse("mystery").is_err());
    }

    #[test]
    fn bundled_voice_profiles_do_not_require_a_hostname() {
        let strategy = StrategyDefinition::parse(include_str!(
            "../../../apps/desktop/resources/default/strategy.toml"
        ))
        .expect("valid bundled strategy");
        for engine in [
            EngineFlavor::Nfqws,
            EngineFlavor::Utunws,
            EngineFlavor::Winws,
        ] {
            let compiled = compile_strategy(&strategy, Path::new("strategy.toml"), engine)
                .expect("compile bundled strategy");
            let profiles: Vec<_> = compiled.args.split(|arg| arg == "--new").collect();
            let voice = profiles
                .iter()
                .find(|profile| {
                    profile
                        .iter()
                        .any(|arg| arg.starts_with("--filter-l7=") && arg.contains("discord"))
                })
                .expect("Discord voice profile");
            assert!(voice.iter().any(|arg| arg.contains("stun")));
            assert!(!voice.iter().any(|arg| arg.starts_with("--hostlist=")));
            let quic = profiles
                .iter()
                .find(|profile| profile.iter().any(|arg| arg == "--filter-udp=443"))
                .expect("QUIC profile");
            assert!(quic.iter().any(|arg| arg.starts_with("--hostlist=")));
        }
    }

    #[test]
    fn windows_engine_paths_preserve_spaces_and_unc_shares() {
        for (input, expected) in [
            (
                r"C:\Program Files\White Hide\list.txt",
                "C:/Program Files/White Hide/list.txt",
            ),
            (r"\\?\C:\White Hide\list.txt", "C:/White Hide/list.txt"),
            (r"\\?\UNC\server\share\list.txt", "//server/share/list.txt"),
            (r"\\server\share\list.txt", "//server/share/list.txt"),
        ] {
            assert_eq!(windows_engine_path(input), expected);
        }
    }
}
