use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use whitelist_hide_core::artifact::{ArtifactManifest, verify_file};
use whitelist_hide_core::config::AppConfig;
use whitelist_hide_core::strategy::{StrategyDefinition, pf_port_list};
use whitelist_hide_runtime::{RuntimePhase, RuntimeState, StateStore};
use whitelist_hide_service::{
    ActionResult, BackendAction, ManagedPlatformBackend, StartRequest, StopRequest,
};

use crate::{
    CommandRunner, MacOsBackend, MacOsError, PF_ANCHOR, SystemCommandRunner, parse_pf_status,
    parse_utun_interfaces, route_value,
};

const UTUN_UNIT_START: u32 = 201;
const UTUN_UNIT_END: u32 = 240;
const UTUN_LOCAL: &str = "10.77.0.1";
const UTUN_PEER: &str = "10.77.0.2";

impl ManagedPlatformBackend for MacOsBackend<SystemCommandRunner> {
    fn start_managed(&self, request: &StartRequest) -> Result<ActionResult, Self::Error> {
        self.ensure_macos()?;
        self.require_root()?;

        let store = StateStore::new(&request.state_path);
        if store.load().map_err(runtime_error)?.is_some() {
            return Err(MacOsError::Lifecycle(
                "runtime state already exists; stop or recover the existing session first"
                    .to_owned(),
            ));
        }

        let config = AppConfig::load(&request.config_path)
            .map_err(|error| MacOsError::Lifecycle(error.to_string()))?;
        let paths = config.resolve_engine_paths(&request.config_path);

        let manifest = ArtifactManifest::load(&paths.manifest)
            .map_err(|error| MacOsError::Lifecycle(error.to_string()))?;
        let verification = verify_file(&manifest, &paths.binary)
            .map_err(|error| MacOsError::Lifecycle(error.to_string()))?;
        if !verification.trusted() {
            return Err(MacOsError::Lifecycle(format!(
                "engine trust verification failed: checksum_ok={} platform_ok={}",
                verification.integrity_ok(),
                verification.platform_ok()
            )));
        }

        let engine_binary = paths.binary.canonicalize().map_err(|source| {
            MacOsError::Lifecycle(format!(
                "cannot canonicalize verified engine {}: {source}",
                paths.binary.display()
            ))
        })?;

        let strategy = StrategyDefinition::load(&request.strategy_path)
            .map_err(|error| MacOsError::Lifecycle(error.to_string()))?;
        if strategy.id != config.strategy.name {
            return Err(MacOsError::Lifecycle(format!(
                "config selects strategy '{}' but strategy file declares '{}'",
                config.strategy.name, strategy.id
            )));
        }
        validate_strategy_files(&strategy, &request.strategy_path)?;

        let engine_args = strategy
            .zapret_arguments(&request.strategy_path)
            .map_err(|error| MacOsError::Lifecycle(error.to_string()))?;

        let route = self.run_checked("/sbin/route", &["-n", "get", "default"])?;
        let physical_interface = route_value(&route, "interface:").ok_or_else(|| {
            MacOsError::Lifecycle("default route does not expose an interface".to_owned())
        })?;
        let gateway = route_value(&route, "gateway:").ok_or_else(|| {
            MacOsError::Lifecycle("default route does not expose an IPv4 gateway".to_owned())
        })?;
        if gateway.contains(':') {
            return Err(MacOsError::Lifecycle(
                "initial macOS lifecycle requires an IPv4 default gateway".to_owned(),
            ));
        }

        let gateway_mac = self.gateway_mac(&gateway)?;

        let interfaces = self.run_checked("/sbin/ifconfig", &["-l"])?;
        let existing = parse_utun_interfaces(&interfaces);
        let utun_unit = choose_utun_unit(&existing).ok_or_else(|| {
            MacOsError::Lifecycle(format!(
                "no free utun unit in reserved range {UTUN_UNIT_START}..={UTUN_UNIT_END}"
            ))
        })?;
        let utun_name = format!("utun{}", utun_unit - 1);

        let session_id = new_session_id()?;
        let mut state = RuntimeState::new(session_id.clone(), "macos");
        state.engine_binary = Some(engine_binary.clone());
        state.owned_interface = Some(utun_name.clone());
        state.utun_unit = Some(utun_unit);
        state.owned_firewall_scope = Some(PF_ANCHOR.to_owned());
        store.save(&state).map_err(runtime_error)?;

        let log_path = request
            .state_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(format!("engine-{session_id}.log"));

        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)
            .map_err(|source| {
                MacOsError::Lifecycle(format!(
                    "cannot create engine log {}: {source}",
                    log_path.display()
                ))
            })?;
        let log_err = log.try_clone().map_err(|source| {
            MacOsError::Lifecycle(format!("cannot clone engine log handle: {source}"))
        })?;

        let mut child = spawn_engine(
            &engine_binary,
            &engine_args,
            &physical_interface,
            &gateway_mac,
            utun_unit,
            log,
            log_err,
        )?;

        state.engine_pid = Some(child.id());
        if let Err(error) = store.save(&state) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = store.clear();
            return Err(runtime_error(error));
        }

        let result = self.finish_start(&strategy, &store, &mut state, &mut child, &utun_name);

        if let Err(error) = result {
            self.rollback_start(&store, &mut state, &mut child);
            return Err(error);
        }

        Ok(ActionResult {
            action: BackendAction::Start,
            changed: true,
            message: format!(
                "macOS backend started: pid={} interface={} anchor={PF_ANCHOR}",
                state.engine_pid.unwrap_or_default(),
                utun_name
            ),
        })
    }

    fn stop_managed(&self, request: &StopRequest) -> Result<ActionResult, Self::Error> {
        self.ensure_macos()?;
        self.require_root()?;

        let store = StateStore::new(&request.state_path);
        let Some(mut state) = store.load().map_err(runtime_error)? else {
            return Ok(ActionResult {
                action: BackendAction::Stop,
                changed: false,
                message: "no managed macOS runtime state exists".to_owned(),
            });
        };

        if state.platform != "macos" {
            return Err(MacOsError::Lifecycle(format!(
                "runtime journal belongs to platform '{}', not macOS",
                state.platform
            )));
        }
        if state.owned_firewall_scope.as_deref() != Some(PF_ANCHOR) {
            return Err(MacOsError::Lifecycle(
                "runtime journal does not own the expected pf anchor".to_owned(),
            ));
        }

        state.phase = RuntimePhase::Stopping;
        store.save(&state).map_err(runtime_error)?;

        if let Err(error) = self.flush_anchor() {
            state.phase = RuntimePhase::Failed;
            let _ = store.save(&state);
            return Err(error);
        }

        let process_result = self.stop_recorded_process(&state);

        if let Some(token) = state.pf_enable_token.as_deref() {
            let _ = self.release_pf_token(token);
        }

        match process_result {
            Ok(()) => {
                store.clear().map_err(runtime_error)?;
                Ok(ActionResult {
                    action: BackendAction::Stop,
                    changed: true,
                    message: "macOS backend stopped and owned resources were released".to_owned(),
                })
            }
            Err(error) => {
                state.phase = RuntimePhase::Failed;
                let _ = store.save(&state);
                Err(error)
            }
        }
    }
}

impl MacOsBackend<SystemCommandRunner> {
    fn finish_start(
        &self,
        strategy: &StrategyDefinition,
        store: &StateStore,
        state: &mut RuntimeState,
        child: &mut Child,
        utun_name: &str,
    ) -> Result<(), MacOsError> {
        wait_for_interface(child, utun_name)?;

        self.run_checked(
            "/sbin/ifconfig",
            &[
                utun_name,
                UTUN_LOCAL,
                UTUN_PEER,
                "netmask",
                "255.255.255.255",
                "up",
            ],
        )?;

        let pf_info = self.run_checked("/sbin/pfctl", &["-s", "info"])?;
        let pf_status = parse_pf_status(&pf_info)
            .unwrap_or_else(|| "Unknown".to_owned())
            .to_ascii_lowercase();

        if pf_status.starts_with("disabled") {
            let token = self.enable_pf()?;
            state.pf_enable_token = Some(token);
            store.save(state).map_err(runtime_error)?;
        }

        let rules = build_pf_rules(strategy, utun_name)?;
        let args = ["-a", PF_ANCHOR, "-f", "-"];
        let output = self
            .runner
            .run_with_input("/sbin/pfctl", &args, rules.as_bytes())?;
        if !output.success() {
            return Err(MacOsError::CommandFailed {
                program: "/sbin/pfctl".to_owned(),
                args: args.iter().map(|value| (*value).to_owned()).collect(),
                code: output.code,
                stderr: output.stderr.trim().to_owned(),
            });
        }

        if let Some(status) = child
            .try_wait()
            .map_err(|source| MacOsError::Lifecycle(format!("engine wait failed: {source}")))?
        {
            return Err(MacOsError::Lifecycle(format!(
                "engine exited during startup with status {status}"
            )));
        }

        self.run_checked("/sbin/ifconfig", &[utun_name])?;
        let active_rules = self.run_checked("/sbin/pfctl", &["-a", PF_ANCHOR, "-sr"])?;
        if active_rules.lines().all(|line| line.trim().is_empty()) {
            return Err(MacOsError::Lifecycle(
                "pf anchor health check found no active rules".to_owned(),
            ));
        }

        state.phase = RuntimePhase::Running;
        store.save(state).map_err(runtime_error)?;
        Ok(())
    }

    fn rollback_start(&self, store: &StateStore, state: &mut RuntimeState, child: &mut Child) {
        state.phase = RuntimePhase::Failed;
        let _ = store.save(state);

        let anchor_clean = self.flush_anchor().is_ok();

        let _ = child.kill();
        let _ = child.wait();

        let token_clean = if let Some(token) = state.pf_enable_token.as_deref() {
            self.release_pf_token(token).is_ok()
        } else {
            true
        };

        if anchor_clean && token_clean {
            let _ = store.clear();
        }
    }

    fn require_root(&self) -> Result<(), MacOsError> {
        let uid = self.run_checked("/usr/bin/id", &["-u"])?;
        if uid.trim() == "0" {
            Ok(())
        } else {
            Err(MacOsError::Lifecycle(
                "managed macOS start/stop must run through the privileged helper or as root"
                    .to_owned(),
            ))
        }
    }

    fn run_checked(&self, program: &str, args: &[&str]) -> Result<String, MacOsError> {
        let output = self.runner.run(program, args)?;
        if output.success() {
            Ok(output.stdout)
        } else {
            Err(MacOsError::CommandFailed {
                program: program.to_owned(),
                args: args.iter().map(|value| (*value).to_owned()).collect(),
                code: output.code,
                stderr: output.stderr.trim().to_owned(),
            })
        }
    }

    fn enable_pf(&self) -> Result<String, MacOsError> {
        let args = ["-E"];
        let output = self.runner.run("/sbin/pfctl", &args)?;
        if !output.success() {
            return Err(MacOsError::CommandFailed {
                program: "/sbin/pfctl".to_owned(),
                args: vec!["-E".to_owned()],
                code: output.code,
                stderr: output.stderr.trim().to_owned(),
            });
        }

        let combined = format!("{}\n{}", output.stdout, output.stderr);
        parse_pf_token(&combined).ok_or_else(|| {
            MacOsError::Lifecycle(
                "pf was enabled but pfctl returned no release token; refusing to continue"
                    .to_owned(),
            )
        })
    }

    fn gateway_mac(&self, gateway: &str) -> Result<String, MacOsError> {
        let output = self.run_checked("/usr/sbin/arp", &["-n", gateway])?;
        parse_arp_mac(&output).ok_or_else(|| {
            MacOsError::Lifecycle(format!(
                "ARP table has no complete MAC address for default gateway {gateway}; generate normal gateway traffic and retry"
            ))
        })
    }

    fn flush_anchor(&self) -> Result<(), MacOsError> {
        self.run_checked("/sbin/pfctl", &["-a", PF_ANCHOR, "-F", "all"])?;
        Ok(())
    }

    fn release_pf_token(&self, token: &str) -> Result<(), MacOsError> {
        if !safe_pf_token(token) {
            return Err(MacOsError::Lifecycle(
                "recorded pf token contains unsupported characters".to_owned(),
            ));
        }
        self.run_checked("/sbin/pfctl", &["-X", token])?;
        Ok(())
    }

    fn stop_recorded_process(&self, state: &RuntimeState) -> Result<(), MacOsError> {
        let Some(pid) = state.engine_pid else {
            return Ok(());
        };
        let Some(binary) = state.engine_binary.as_ref() else {
            return Err(MacOsError::Lifecycle(
                "runtime state contains an engine pid but no verified binary path".to_owned(),
            ));
        };

        let pid_text = pid.to_string();
        let ps = self
            .runner
            .run("/bin/ps", &["-p", pid_text.as_str(), "-o", "command="])?;
        if !ps.success() || ps.stdout.trim().is_empty() {
            return Ok(());
        }

        let expected = binary.to_string_lossy();
        if !ps.stdout.contains(expected.as_ref()) {
            return Err(MacOsError::Lifecycle(format!(
                "pid {pid} no longer belongs to the recorded engine binary; refusing to kill it"
            )));
        }

        self.run_checked("/bin/kill", &["-TERM", pid_text.as_str()])?;
        for _ in 0..30 {
            thread::sleep(Duration::from_millis(100));
            let check = self
                .runner
                .run("/bin/ps", &["-p", pid_text.as_str(), "-o", "command="])?;
            if !check.success() || check.stdout.trim().is_empty() {
                return Ok(());
            }
        }

        let check = self
            .runner
            .run("/bin/ps", &["-p", pid_text.as_str(), "-o", "command="])?;
        if check.success() && check.stdout.contains(expected.as_ref()) {
            self.run_checked("/bin/kill", &["-KILL", pid_text.as_str()])?;
        }
        Ok(())
    }
}

fn validate_strategy_files(
    strategy: &StrategyDefinition,
    strategy_path: &std::path::Path,
) -> Result<(), MacOsError> {
    let base = strategy_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    for relative in strategy
        .filters
        .domain_lists
        .iter()
        .chain(strategy.filters.ip_lists.iter())
    {
        let path = base.join(relative);
        File::open(&path).map_err(|source| {
            MacOsError::Lifecycle(format!(
                "strategy data file {} is not readable: {source}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn spawn_engine(
    binary: &std::path::Path,
    args: &[OsString],
    physical_interface: &str,
    gateway_mac: &str,
    utun_unit: u32,
    stdout: File,
    stderr: File,
) -> Result<Child, MacOsError> {
    Command::new(binary)
        .args(args)
        .env("ZAPRET_IFACE", physical_interface)
        .env("ZAPRET_GATEWAY_MAC", gateway_mac)
        .env("ZAPRET_GATEWAY6_MAC", gateway_mac)
        .env("ZAPRET_UTUN_UNIT", utun_unit.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|source| {
            MacOsError::Lifecycle(format!(
                "cannot start verified engine {}: {source}",
                binary.display()
            ))
        })
}

fn wait_for_interface(child: &mut Child, expected: &str) -> Result<(), MacOsError> {
    for _ in 0..50 {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| MacOsError::Lifecycle(format!("engine wait failed: {source}")))?
        {
            return Err(MacOsError::Lifecycle(format!(
                "engine exited before {expected} appeared: {status}"
            )));
        }

        let status = Command::new("/sbin/ifconfig")
            .arg(expected)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|source| {
                MacOsError::Lifecycle(format!("cannot inspect {expected}: {source}"))
            })?;
        if status.success() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(MacOsError::Lifecycle(format!(
        "timed out waiting for engine-owned interface {expected}"
    )))
}

fn choose_utun_unit(existing: &[String]) -> Option<u32> {
    (UTUN_UNIT_START..=UTUN_UNIT_END).find(|unit| {
        let name = format!("utun{}", unit - 1);
        !existing.iter().any(|current| current == &name)
    })
}

fn new_session_id() -> Result<String, MacOsError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| MacOsError::Lifecycle(format!("system clock error: {error}")))?
        .as_secs();
    Ok(format!("macos-{seconds}-{}", std::process::id()))
}

fn parse_arp_mac(text: &str) -> Option<String> {
    let after = text.split(" at ").nth(1)?;
    let candidate = after.split_whitespace().next()?.trim();
    if valid_mac(candidate) {
        Some(candidate.to_ascii_lowercase())
    } else {
        None
    }
}

fn valid_mac(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn parse_pf_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let token = line.strip_prefix("Token :")?.trim();
        safe_pf_token(token).then(|| token.to_owned())
    })
}

fn safe_pf_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn build_pf_rules(strategy: &StrategyDefinition, utun_name: &str) -> Result<String, MacOsError> {
    if !utun_name.starts_with("utun") || !utun_name[4..].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MacOsError::Lifecycle(
            "refusing to build pf rules for an invalid utun name".to_owned(),
        ));
    }

    let mut rules = Vec::new();
    if !strategy.filters.tcp_ports.is_empty() {
        rules.push(format!(
            "pass out quick route-to ({utun_name} {UTUN_PEER}) inet proto tcp from any to any port {{ {} }} user {{ >root }} no state",
            pf_port_list(&strategy.filters.tcp_ports)
        ));
    }
    if !strategy.filters.udp_ports.is_empty() {
        rules.push(format!(
            "pass out quick route-to ({utun_name} {UTUN_PEER}) inet proto udp from any to any port {{ {} }} user {{ >root }} no state",
            pf_port_list(&strategy.filters.udp_ports)
        ));
    }

    if rules.is_empty() {
        return Err(MacOsError::Lifecycle(
            "strategy produced no pf routing rules".to_owned(),
        ));
    }
    Ok(format!("{}\n", rules.join("\n")))
}

fn runtime_error(error: impl std::fmt::Display) -> MacOsError {
    MacOsError::Lifecycle(format!("runtime journal error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use whitelist_hide_core::strategy::{PortRange, StrategyFilters};

    #[test]
    fn parses_gateway_mac_from_arp() {
        let line = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n";
        assert_eq!(parse_arp_mac(line), Some("aa:bb:cc:dd:ee:ff".to_owned()));
    }

    #[test]
    fn chooses_unused_reserved_utun() {
        assert_eq!(
            choose_utun_unit(&["utun200".to_owned(), "utun201".to_owned()]),
            Some(203)
        );
    }

    #[test]
    fn parses_pf_enable_token() {
        assert_eq!(
            parse_pf_token("pf enabled\nToken : 1234abcd\n"),
            Some("1234abcd".to_owned())
        );
    }

    #[test]
    fn pf_rules_are_scoped_to_selected_ports() {
        let strategy = StrategyDefinition {
            schema: 1,
            id: "test".to_owned(),
            description: String::new(),
            filters: StrategyFilters {
                tcp_ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                udp_ports: Vec::new(),
                domain_lists: Vec::new(),
                ip_lists: Vec::new(),
            },
            desync: vec![whitelist_hide_core::strategy::DesyncStage::Fake { repeats: 1 }],
        };
        let rules = build_pf_rules(&strategy, "utun200").expect("rules");
        assert!(rules.contains("proto tcp"));
        assert!(rules.contains("port { 443 }"));
        assert!(rules.contains("user { >root }"));
    }
}
