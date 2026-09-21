use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_core::Platform;
use whitelist_hide_core::artifact::{ArtifactManifest, verify_file};
use whitelist_hide_core::config::AppConfig;
use whitelist_hide_core::strategy::StrategyDefinition;
use whitelist_hide_core::strategy_compiler::{EnginePlan, compile_strategy};
use whitelist_hide_runtime::{
    EngineRuntimeError, RuntimePhase, StateStore, launch_verified_engine,
    launch_verified_engine_with_env, stop_recorded_engine,
};

const LINUX_QUEUE: u16 = 200;
const MACOS_ANCHOR: &str = "com.whitelisthide";
const MACOS_UTUN: &str = "utun50";

#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub config_path: PathBuf,
    pub strategy_path: PathBuf,
    pub state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub platform: Platform,
    pub strategy_id: String,
    pub engine_pid: u32,
    pub firewall_scope: Option<String>,
    pub interface: Option<String>,
}

pub fn start_session(spec: &SessionSpec) -> Result<SessionReport, SessionError> {
    let config = AppConfig::load(&spec.config_path)
        .map_err(|error| SessionError::Config(error.to_string()))?;
    let paths = config.resolve_engine_paths(&spec.config_path);

    verify_dependencies(&paths.dependencies)?;
    if Platform::detect() == Platform::Windows {
        require_windows_dependencies(&paths.dependencies)?;
    }

    let strategy = StrategyDefinition::load(&spec.strategy_path)
        .map_err(|error| SessionError::Strategy(error.to_string()))?;
    let plan = compile_strategy(&strategy, &spec.strategy_path)
        .map_err(|error| SessionError::Strategy(error.to_string()))?;

    let store = StateStore::new(&spec.state_path);
    let session_id = format!("session-{}", std::process::id());

    match Platform::detect() {
        Platform::Linux => start_linux(&paths.manifest, &paths.binary, &plan, &store, &session_id),
        Platform::MacOS => start_macos(&paths.manifest, &paths.binary, &plan, &store, &session_id),
        Platform::Windows => {
            start_windows(&paths.manifest, &paths.binary, &plan, &store, &session_id)
        }
        Platform::Unsupported => Err(SessionError::UnsupportedPlatform),
    }
}

pub fn stop_session(state_path: &Path) -> Result<bool, SessionError> {
    let store = StateStore::new(state_path);
    let state = store
        .load()
        .map_err(|error| SessionError::Runtime(error.to_string()))?;

    let Some(state) = state else {
        return Ok(false);
    };

    match Platform::detect() {
        Platform::Linux => {
            let _ = run("nft", &["delete", "table", "inet", "whitelist_hide"]);
        }
        Platform::MacOS => {
            let _ = run("/sbin/pfctl", &["-a", MACOS_ANCHOR, "-F", "all"]);
            if let Some(token) = state.backend_token.as_deref() {
                let _ = run("/sbin/pfctl", &["-X", token]);
            }
        }
        Platform::Windows | Platform::Unsupported => {}
    }

    stop_recorded_engine(&store).map_err(SessionError::Engine)
}

fn verify_dependencies(
    dependencies: &[whitelist_hide_core::config::ResolvedArtifactPaths],
) -> Result<(), SessionError> {
    for dependency in dependencies {
        let manifest = ArtifactManifest::load(&dependency.manifest)
            .map_err(|error| SessionError::Artifact(error.to_string()))?;
        let report = verify_file(&manifest, &dependency.binary)
            .map_err(|error| SessionError::Artifact(error.to_string()))?;
        if !report.trusted() {
            return Err(SessionError::Artifact(format!(
                "dependency {} rejected: sha/platform mismatch",
                dependency.binary.display()
            )));
        }
    }
    Ok(())
}

fn require_windows_dependencies(
    dependencies: &[whitelist_hide_core::config::ResolvedArtifactPaths],
) -> Result<(), SessionError> {
    let has_dll = dependencies.iter().any(|dependency| {
        dependency
            .binary
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("dll"))
    });
    let has_sys = dependencies.iter().any(|dependency| {
        dependency
            .binary
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("sys"))
    });

    if has_dll && has_sys {
        Ok(())
    } else {
        Err(SessionError::Artifact(
            "Windows engine requires trusted .dll and .sys driver dependencies".to_owned(),
        ))
    }
}

fn start_linux(
    manifest: &Path,
    binary: &Path,
    plan: &EnginePlan,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, SessionError> {
    ensure_root_unix()?;

    let mut args = vec![format!("--qnum={LINUX_QUEUE}")];
    args.extend(plan.arguments.clone());

    let launched = launch_verified_engine(manifest, binary, &args, store, session_id)
        .map_err(SessionError::Engine)?;

    let rules = linux_nft_rules(plan);
    if let Err(error) = run_with_stdin("nft", &["-f", "-"], &rules) {
        let _ = stop_recorded_engine(store);
        return Err(error);
    }

    if let Err(error) = run("nft", &["list", "table", "inet", "whitelist_hide"]) {
        let _ = run("nft", &["delete", "table", "inet", "whitelist_hide"]);
        let _ = stop_recorded_engine(store);
        return Err(error);
    }

    let mut state = store
        .load()
        .map_err(|error| SessionError::Runtime(error.to_string()))?
        .ok_or_else(|| {
            SessionError::Runtime("runtime state disappeared after launch".to_owned())
        })?;
    state.owned_firewall_scope = Some("inet:whitelist_hide".to_owned());
    state.phase = RuntimePhase::Running;
    store
        .save(&state)
        .map_err(|error| SessionError::Runtime(error.to_string()))?;

    Ok(SessionReport {
        platform: Platform::Linux,
        strategy_id: plan.strategy_id.clone(),
        engine_pid: launched.pid,
        firewall_scope: state.owned_firewall_scope,
        interface: None,
    })
}

fn start_macos(
    manifest: &Path,
    binary: &Path,
    plan: &EnginePlan,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, SessionError> {
    ensure_root_unix()?;

    let route = run("/sbin/route", &["-n", "get", "default"])?;
    let interface = route_field(&route.stdout, "interface:")
        .ok_or_else(|| SessionError::Health("default interface not found".to_owned()))?;
    let gateway = route_field(&route.stdout, "gateway:")
        .ok_or_else(|| SessionError::Health("default gateway not found".to_owned()))?;

    let _ = run("/sbin/ping", &["-c", "1", "-t", "1", &gateway]);
    let arp = run("/usr/sbin/arp", &["-n", &gateway])?;
    let gateway_mac = parse_mac(&arp.stdout)
        .ok_or_else(|| SessionError::Health("gateway MAC not found".to_owned()))?;

    let env = vec![
        ("ZAPRET_IFACE".to_owned(), interface.clone()),
        ("ZAPRET_GATEWAY_MAC".to_owned(), gateway_mac),
        ("ZAPRET_GATEWAY6_MAC".to_owned(), String::new()),
        ("ZAPRET_UTUN_UNIT".to_owned(), "51".to_owned()),
    ];

    let launched =
        launch_verified_engine_with_env(manifest, binary, &plan.arguments, &env, store, session_id)
            .map_err(SessionError::Engine)?;

    if !wait_for_interface(MACOS_UTUN, 40) {
        let _ = stop_recorded_engine(store);
        return Err(SessionError::Health(format!(
            "{MACOS_UTUN} was not created by the engine"
        )));
    }

    if let Err(error) = run(
        "/sbin/ifconfig",
        &[
            MACOS_UTUN,
            "10.77.0.1",
            "10.77.0.2",
            "netmask",
            "255.255.255.255",
            "up",
        ],
    ) {
        let _ = stop_recorded_engine(store);
        return Err(error);
    }

    let mut pf_token = None;
    let pf_info = run("/sbin/pfctl", &["-s", "info"])?;
    if pf_info
        .stdout
        .lines()
        .any(|line| line.starts_with("Status: Disabled"))
    {
        let enabled = run("/sbin/pfctl", &["-E"])?;
        pf_token = parse_pf_token(&format!("{}\n{}", enabled.stdout, enabled.stderr));
    }

    let rules = macos_pf_rules(plan);
    if let Err(error) = run_with_stdin("/sbin/pfctl", &["-a", MACOS_ANCHOR, "-f", "-"], &rules) {
        if let Some(token) = pf_token.as_deref() {
            let _ = run("/sbin/pfctl", &["-X", token]);
        }
        let _ = stop_recorded_engine(store);
        return Err(error);
    }

    let anchor = run("/sbin/pfctl", &["-a", MACOS_ANCHOR, "-sr"])?;
    if anchor.stdout.trim().is_empty() {
        let _ = run("/sbin/pfctl", &["-a", MACOS_ANCHOR, "-F", "all"]);
        if let Some(token) = pf_token.as_deref() {
            let _ = run("/sbin/pfctl", &["-X", token]);
        }
        let _ = stop_recorded_engine(store);
        return Err(SessionError::Health(
            "pf anchor contains no active rules".to_owned(),
        ));
    }

    let mut state = store
        .load()
        .map_err(|error| SessionError::Runtime(error.to_string()))?
        .ok_or_else(|| {
            SessionError::Runtime("runtime state disappeared after launch".to_owned())
        })?;
    state.owned_interface = Some(MACOS_UTUN.to_owned());
    state.owned_firewall_scope = Some(MACOS_ANCHOR.to_owned());
    state.backend_token = pf_token;
    state.phase = RuntimePhase::Running;
    store
        .save(&state)
        .map_err(|error| SessionError::Runtime(error.to_string()))?;

    Ok(SessionReport {
        platform: Platform::MacOS,
        strategy_id: plan.strategy_id.clone(),
        engine_pid: launched.pid,
        firewall_scope: state.owned_firewall_scope,
        interface: state.owned_interface,
    })
}

fn start_windows(
    manifest: &Path,
    binary: &Path,
    plan: &EnginePlan,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, SessionError> {
    let mut args = Vec::new();
    if let Some(tcp) = extract_filter(&plan.arguments, "--filter-tcp=") {
        args.push(format!("--wf-tcp={tcp}"));
    }
    if let Some(udp) = extract_filter(&plan.arguments, "--filter-udp=") {
        args.push(format!("--wf-udp={udp}"));
    }
    args.extend(plan.arguments.clone());

    let launched = launch_verified_engine(manifest, binary, &args, store, session_id)
        .map_err(SessionError::Engine)?;

    let mut state = store
        .load()
        .map_err(|error| SessionError::Runtime(error.to_string()))?
        .ok_or_else(|| {
            SessionError::Runtime("runtime state disappeared after launch".to_owned())
        })?;
    state.owned_firewall_scope = Some("windivert:engine-owned".to_owned());
    state.phase = RuntimePhase::Running;
    store
        .save(&state)
        .map_err(|error| SessionError::Runtime(error.to_string()))?;

    Ok(SessionReport {
        platform: Platform::Windows,
        strategy_id: plan.strategy_id.clone(),
        engine_pid: launched.pid,
        firewall_scope: state.owned_firewall_scope,
        interface: None,
    })
}

fn extract_filter(arguments: &[String], prefix: &str) -> Option<String> {
    arguments
        .iter()
        .find_map(|arg| arg.strip_prefix(prefix).map(str::to_owned))
}

fn linux_nft_rules(plan: &EnginePlan) -> String {
    let tcp = extract_filter(&plan.arguments, "--filter-tcp=");
    let udp = extract_filter(&plan.arguments, "--filter-udp=");

    let mut rules = String::from(
        "table inet whitelist_hide {\n  chain output {\n    type filter hook output priority mangle; policy accept;\n",
    );

    if let Some(ports) = tcp {
        rules.push_str(&format!(
            "    meta mark != 0x40000000 tcp dport {{ {} }} queue num {} bypass\n",
            ports, LINUX_QUEUE
        ));
    }
    if let Some(ports) = udp {
        rules.push_str(&format!(
            "    meta mark != 0x40000000 udp dport {{ {} }} queue num {} bypass\n",
            ports, LINUX_QUEUE
        ));
    }

    rules.push_str("  }\n}\n");
    rules
}

fn macos_pf_rules(plan: &EnginePlan) -> String {
    let mut rules = String::new();
    if let Some(tcp) = extract_filter(&plan.arguments, "--filter-tcp=") {
        rules.push_str(&format!(
            "pass out quick route-to ({MACOS_UTUN} 10.77.0.2) inet proto tcp from any to any port {{ {} }} user {{ >root }} no state\n",
            pf_ports(&tcp)
        ));
    }
    if let Some(udp) = extract_filter(&plan.arguments, "--filter-udp=") {
        rules.push_str(&format!(
            "pass out quick route-to ({MACOS_UTUN} 10.77.0.2) inet proto udp from any to any port {{ {} }} user {{ >root }} no state\n",
            pf_ports(&udp)
        ));
    }
    rules
}

fn pf_ports(value: &str) -> String {
    value.replace('-', ":")
}

fn wait_for_interface(name: &str, attempts: usize) -> bool {
    for _ in 0..attempts {
        if run("/sbin/ifconfig", &[name]).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn ensure_root_unix() -> Result<(), SessionError> {
    let output = run("/usr/bin/id", &["-u"])?;
    if output.stdout.trim() == "0" {
        Ok(())
    } else {
        Err(SessionError::Privilege(
            "network session requires root privileges".to_owned(),
        ))
    }
}

fn route_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix(key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn parse_mac(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|token| {
        let value = token.trim_matches(|c: char| c == '(' || c == ')');
        let groups = value.split(':').collect::<Vec<_>>();
        (groups.len() == 6
            && groups.iter().all(|group| {
                !group.is_empty()
                    && group.len() <= 2
                    && group.chars().all(|c| c.is_ascii_hexdigit())
            }))
        .then(|| value.to_owned())
    })
}

fn parse_pf_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some("Token"), Some(":"), Some(token)) if !token.is_empty() => Some(token.to_owned()),
            _ => None,
        }
    })
}

#[derive(Debug)]
struct Output {
    stdout: String,
    stderr: String,
}

fn run(program: &str, args: &[&str]) -> Result<Output, SessionError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| SessionError::CommandIo {
            program: program.to_owned(),
            source,
        })?;

    if !output.status.success() {
        return Err(SessionError::CommandFailed {
            program: program.to_owned(),
            args: args.iter().map(|value| (*value).to_owned()).collect(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(Output {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn run_with_stdin(program: &str, args: &[&str], input: &str) -> Result<Output, SessionError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| SessionError::CommandIo {
            program: program.to_owned(),
            source,
        })?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| SessionError::CommandFailed {
            program: program.to_owned(),
            args: args.iter().map(|value| (*value).to_owned()).collect(),
            code: None,
            stderr: "stdin was not available".to_owned(),
        })?
        .write_all(input.as_bytes())
        .map_err(|source| SessionError::CommandIo {
            program: program.to_owned(),
            source,
        })?;

    let output = child
        .wait_with_output()
        .map_err(|source| SessionError::CommandIo {
            program: program.to_owned(),
            source,
        })?;

    if !output.status.success() {
        return Err(SessionError::CommandFailed {
            program: program.to_owned(),
            args: args.iter().map(|value| (*value).to_owned()).collect(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(Output {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[derive(Debug)]
pub enum SessionError {
    Config(String),
    Strategy(String),
    Artifact(String),
    Runtime(String),
    Engine(EngineRuntimeError),
    Privilege(String),
    Health(String),
    CommandIo {
        program: String,
        source: io::Error,
    },
    CommandFailed {
        program: String,
        args: Vec<String>,
        code: Option<i32>,
        stderr: String,
    },
    UnsupportedPlatform,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "config error: {message}"),
            Self::Strategy(message) => write!(f, "strategy error: {message}"),
            Self::Artifact(message) => write!(f, "artifact error: {message}"),
            Self::Runtime(message) => write!(f, "runtime error: {message}"),
            Self::Engine(error) => write!(f, "engine error: {error}"),
            Self::Privilege(message) => f.write_str(message),
            Self::Health(message) => write!(f, "health check failed: {message}"),
            Self::CommandIo { program, source } => {
                write!(f, "failed to execute {program}: {source}")
            }
            Self::CommandFailed {
                program,
                args,
                code,
                stderr,
            } => write!(
                f,
                "{program} {} failed with {code:?}: {stderr}",
                args.join(" ")
            ),
            Self::UnsupportedPlatform => f.write_str("unsupported platform"),
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::CommandIo { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_port_ranges_for_pf() {
        assert_eq!(pf_ports("80,443,5000-5010"), "80,443,5000:5010");
    }

    #[test]
    fn parses_route_fields() {
        let input = "gateway: 192.168.1.1\ninterface: en0\n";
        assert_eq!(route_field(input, "interface:"), Some("en0".to_owned()));
    }

    #[test]
    fn parses_mac_address() {
        let input = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0";
        assert_eq!(parse_mac(input), Some("aa:bb:cc:dd:ee:ff".to_owned()));
    }
}
