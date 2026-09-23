use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::process::{Command, Stdio};

use whitelist_hide_core::Platform;
use whitelist_hide_core::strategy::PortRange;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub const PF_ANCHOR: &str = "com.apple/whitelist-hide";

pub const UTUN_INTERFACE: &str = "utun50";
pub const UTUN_LOCAL: &str = "10.77.0.1";
pub const UTUN_PEER: &str = "10.77.0.2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacNetworkSnapshot {
    pub interface: String,
    pub gateway: String,
    pub gateway_mac: String,
    pub pf_was_enabled: bool,
}

pub fn inspect_network_snapshot() -> Result<MacNetworkSnapshot, MacOsError> {
    if Platform::detect() != Platform::MacOS {
        return Err(MacOsError::ActionUnavailable(
            "macOS network snapshot can only be collected on macOS".to_owned(),
        ));
    }

    let route = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/route".to_owned(),
            source,
        })?;
    if !route.status.success() {
        return Err(MacOsError::ActionUnavailable(
            "cannot determine macOS default route".to_owned(),
        ));
    }
    let route_text = String::from_utf8_lossy(&route.stdout);
    let interface = route_value(&route_text, "interface:")
        .ok_or_else(|| MacOsError::ActionUnavailable("default interface missing".to_owned()))?;
    let gateway = route_value(&route_text, "gateway:")
        .ok_or_else(|| MacOsError::ActionUnavailable("default gateway missing".to_owned()))?;

    let _ = Command::new("/sbin/ping")
        .args(["-c", "1", "-t", "1", &gateway])
        .output();

    let arp = Command::new("/usr/sbin/arp")
        .args(["-n", &gateway])
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/usr/sbin/arp".to_owned(),
            source,
        })?;
    let arp_text = String::from_utf8_lossy(&arp.stdout);
    let gateway_mac = parse_gateway_mac(&arp_text)
        .ok_or_else(|| MacOsError::ActionUnavailable("gateway MAC unavailable".to_owned()))?;

    let pf = Command::new("/sbin/pfctl")
        .args(["-s", "info"])
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;
    let pf_text = String::from_utf8_lossy(&pf.stdout);
    let pf_was_enabled =
        parse_pf_status(&pf_text).is_some_and(|status| status.starts_with("Enabled"));

    Ok(MacNetworkSnapshot {
        interface,
        gateway,
        gateway_mac,
        pf_was_enabled,
    })
}

pub fn wait_for_owned_utun(attempts: u32) -> Result<(), MacOsError> {
    for _ in 0..attempts {
        if Command::new("/sbin/ifconfig")
            .arg(UTUN_INTERFACE)
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(MacOsError::ActionUnavailable(format!(
        "{UTUN_INTERFACE} did not appear"
    )))
}

pub fn configure_owned_utun() -> Result<(), MacOsError> {
    run_checked(
        "/sbin/ifconfig",
        &[
            UTUN_INTERFACE,
            UTUN_LOCAL,
            UTUN_PEER,
            "netmask",
            "255.255.255.255",
            "up",
        ],
    )
}

pub fn enable_pf_if_needed(was_enabled: bool) -> Result<Option<String>, MacOsError> {
    if was_enabled {
        return Ok(None);
    }

    let output = Command::new("/sbin/pfctl")
        .arg("-E")
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(MacOsError::CommandFailed {
            program: "/sbin/pfctl".to_owned(),
            args: vec!["-E".to_owned()],
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_pf_token(&combined))
}

pub fn release_pf_token(token: &str) -> Result<(), MacOsError> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MacOsError::ActionUnavailable(
            "invalid pf enable token".to_owned(),
        ));
    }
    run_checked("/sbin/pfctl", &["-X", token])
}

pub fn install_pf_routes(
    tcp_ports: &[PortRange],
    udp_ports: &[PortRange],
) -> Result<(), MacOsError> {
    // The default macOS ruleset evaluates com.apple/* anchors. An orphan
    // top-level anchor can contain rules without ever seeing packets.
    let root = Command::new("/sbin/pfctl")
        .arg("-sr")
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;
    if !root.status.success()
        || !String::from_utf8_lossy(&root.stdout).contains("anchor \"com.apple/*\"")
    {
        return Err(MacOsError::ActionUnavailable("PF root ruleset does not evaluate com.apple/*; custom firewall configuration requires manual integration".to_owned()));
    }
    if owned_pf_anchor_has_rules()? {
        return Err(MacOsError::ActionUnavailable(
            "project PF anchor is already occupied".to_owned(),
        ));
    }
    let rules = pf_rules(tcp_ports, udp_ports);
    let mut child = Command::new("/sbin/pfctl")
        .args(["-a", PF_ANCHOR, "-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| MacOsError::ActionUnavailable("pfctl stdin unavailable".to_owned()))?
        .write_all(rules.as_bytes())
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;

    let output = child
        .wait_with_output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(MacOsError::CommandFailed {
            program: "/sbin/pfctl".to_owned(),
            args: vec![
                "-a".to_owned(),
                PF_ANCHOR.to_owned(),
                "-f".to_owned(),
                "-".to_owned(),
            ],
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

pub fn owned_pf_anchor_has_rules() -> Result<bool, MacOsError> {
    if Platform::detect() != Platform::MacOS {
        return Ok(false);
    }
    let output = Command::new("/sbin/pfctl")
        .args(["-a", PF_ANCHOR, "-sr"])
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: "/sbin/pfctl".to_owned(),
            source,
        })?;
    Ok(output.status.success()
        && output
            .stdout
            .split(|byte| *byte == b'\n')
            .any(|line| !line.iter().all(u8::is_ascii_whitespace)))
}

pub fn clear_owned_pf_anchor() -> Result<(), MacOsError> {
    run_checked("/sbin/pfctl", &["-a", PF_ANCHOR, "-F", "all"])
}

fn run_checked(program: &str, args: &[&str]) -> Result<(), MacOsError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| MacOsError::CommandIo {
            program: program.to_owned(),
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(MacOsError::CommandFailed {
            program: program.to_owned(),
            args: args.iter().map(|value| (*value).to_owned()).collect(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

fn pf_rules(tcp_ports: &[PortRange], udp_ports: &[PortRange]) -> String {
    let mut rules = String::new();
    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            "pass out quick route-to ({UTUN_INTERFACE} {UTUN_PEER}) inet proto tcp from any to any port {{ {} }} user {{ >root }} no state\n",
            pf_ports(tcp_ports)
        ));
    }
    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            "pass out quick route-to ({UTUN_INTERFACE} {UTUN_PEER}) inet proto udp from any to any port {{ {} }} user {{ >root }} no state\n",
            pf_ports(udp_ports)
        ));
    }
    rules
}

fn pf_ports(ranges: &[PortRange]) -> String {
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

fn parse_gateway_mac(text: &str) -> Option<String> {
    let fields = text.split_whitespace().collect::<Vec<_>>();
    fields.windows(2).find_map(|pair| {
        if pair[0] == "at" && pair[1].matches(':').count() == 5 {
            Some(pair[1].to_owned())
        } else {
            None
        }
    })
}

fn parse_pf_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "Token" {
                let next = parts.next()?;
                if next == ":" {
                    return parts.next().map(str::to_owned);
                }
                if let Some(value) = next.strip_prefix(':') {
                    return (!value.is_empty()).then(|| value.to_owned());
                }
            }
        }
        None
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, MacOsError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, MacOsError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|source| MacOsError::CommandIo {
                program: program.to_owned(),
                source,
            })?;

        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub struct MacOsBackend<R = SystemCommandRunner> {
    runner: R,
}

impl MacOsBackend<SystemCommandRunner> {
    #[must_use]
    pub const fn system() -> Self {
        Self {
            runner: SystemCommandRunner,
        }
    }
}

impl<R> MacOsBackend<R>
where
    R: CommandRunner,
{
    #[must_use]
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    fn inspect_command(
        &self,
        program: &str,
        args: &[&str],
        key: &str,
        label: &str,
        parser: impl FnOnce(&str) -> Option<String>,
    ) -> (DiagnosticItem, bool) {
        match self.runner.run(program, args) {
            Ok(output) if output.success() => match parser(&output.stdout) {
                Some(value) => (
                    DiagnosticItem {
                        key: key.to_owned(),
                        label: label.to_owned(),
                        value,
                        level: DiagnosticLevel::Ok,
                        detail: None,
                    },
                    false,
                ),
                None => (
                    DiagnosticItem {
                        key: key.to_owned(),
                        label: label.to_owned(),
                        value: "unknown".to_owned(),
                        level: DiagnosticLevel::Warning,
                        detail: Some(
                            "command succeeded but expected data was not found".to_owned(),
                        ),
                    },
                    true,
                ),
            },
            Ok(output) => (
                DiagnosticItem {
                    key: key.to_owned(),
                    label: label.to_owned(),
                    value: "unavailable".to_owned(),
                    level: DiagnosticLevel::Warning,
                    detail: Some(command_failure_detail(program, args, &output)),
                },
                true,
            ),
            Err(error) => (
                DiagnosticItem {
                    key: key.to_owned(),
                    label: label.to_owned(),
                    value: "unavailable".to_owned(),
                    level: DiagnosticLevel::Warning,
                    detail: Some(error.to_string()),
                },
                true,
            ),
        }
    }

    fn ensure_macos(&self) -> Result<(), MacOsError> {
        if Platform::detect() == Platform::MacOS {
            Ok(())
        } else {
            Err(MacOsError::ActionUnavailable(
                "macOS backend can only execute on macOS".to_owned(),
            ))
        }
    }

    fn cleanup_anchor(&self) -> Result<ActionResult, MacOsError> {
        self.ensure_macos()?;

        let args = ["-a", PF_ANCHOR, "-F", "all"];
        let output = self.runner.run("/sbin/pfctl", &args)?;

        if !output.success() {
            return Err(MacOsError::CommandFailed {
                program: "/sbin/pfctl".to_owned(),
                args: args.iter().map(|value| (*value).to_owned()).collect(),
                code: output.code,
                stderr: output.stderr.trim().to_owned(),
            });
        }

        Ok(ActionResult {
            action: BackendAction::Cleanup,
            changed: true,
            message: format!("cleared project-owned pf anchor {PF_ANCHOR}"),
        })
    }
}

impl<R> PlatformBackend for MacOsBackend<R>
where
    R: CommandRunner,
{
    type Error = MacOsError;

    fn platform(&self) -> Platform {
        Platform::MacOS
    }

    fn status(&self) -> Result<BackendStatus, Self::Error> {
        if Platform::detect() != Platform::MacOS {
            return Ok(BackendStatus {
                platform: Platform::detect().to_string(),
                available: false,
                state: BackendState::Unsupported,
                diagnostics: vec![DiagnosticItem {
                    key: "platform".to_owned(),
                    label: "macOS backend".to_owned(),
                    value: "unsupported on this host".to_owned(),
                    level: DiagnosticLevel::Info,
                    detail: None,
                }],
            });
        }

        let mut diagnostics = Vec::new();
        let mut degraded = false;

        let (default_interface, bad) = self.inspect_command(
            "/sbin/route",
            &["-n", "get", "default"],
            "default_interface",
            "Default interface",
            |text| route_value(text, "interface:"),
        );
        diagnostics.push(default_interface);
        degraded |= bad;

        let (gateway, bad) = self.inspect_command(
            "/sbin/route",
            &["-n", "get", "default"],
            "default_gateway",
            "Default gateway",
            |text| route_value(text, "gateway:"),
        );
        diagnostics.push(gateway);
        degraded |= bad;

        let (pf, bad) = self.inspect_command(
            "/sbin/pfctl",
            &["-s", "info"],
            "pf_status",
            "Packet Filter",
            parse_pf_status,
        );
        diagnostics.push(pf);
        degraded |= bad;

        let (keepinit, bad) = self.inspect_command(
            "/usr/sbin/sysctl",
            &["-n", "net.inet.tcp.keepinit"],
            "tcp_keepinit",
            "TCP keepinit",
            |text| nonempty_trimmed(text).map(|value| format!("{value} ms")),
        );
        diagnostics.push(keepinit);
        degraded |= bad;

        let (interfaces, bad) = self.inspect_command(
            "/sbin/ifconfig",
            &["-l"],
            "utun_interfaces",
            "Existing utun interfaces",
            |text| Some(parse_utun_interfaces(text).join(", ")).filter(|value| !value.is_empty()),
        );
        diagnostics.push(interfaces);
        degraded |= bad;

        let (anchor, bad) = self.inspect_command(
            "/sbin/pfctl",
            &["-a", PF_ANCHOR, "-sr"],
            "anchor_rules",
            "whitelist-hide pf anchor",
            |text| Some(format!("{} rule(s)", nonempty_line_count(text))),
        );
        diagnostics.push(anchor);
        degraded |= bad;

        let (privilege, bad) = self.inspect_command(
            "/usr/bin/id",
            &["-u"],
            "privilege",
            "Current privileges",
            |text| {
                let uid = nonempty_trimmed(text)?;
                Some(if uid == "0" {
                    "root".to_owned()
                } else {
                    format!("user (uid {uid})")
                })
            },
        );
        diagnostics.push(privilege);
        degraded |= bad;

        Ok(BackendStatus {
            platform: "macos".to_owned(),
            available: true,
            state: if degraded {
                BackendState::Degraded
            } else {
                BackendState::Ready
            },
            diagnostics,
        })
    }

    fn plan(&self, action: BackendAction) -> Result<ActionPlan, Self::Error> {
        self.ensure_macos()?;

        match action {
            BackendAction::Start => Ok(ActionPlan {
                id: "macos.start".to_owned(),
                title: "Start macOS packet-processing backend".to_owned(),
                requires_admin: true,
                mutates_network: true,
                executable_now: false,
                steps: vec![
                    step(
                        "verify",
                        "Verify the selected engine manifest, platform and SHA-256.",
                        None,
                    ),
                    step(
                        "snapshot",
                        "Capture the default route, pf state and every setting the backend may change.",
                        Some("/sbin/route -n get default"),
                    ),
                    step(
                        "engine",
                        "Start only the verified userspace engine and wait for its project-owned utun interface.",
                        None,
                    ),
                    step(
                        "utun",
                        "Configure only the project-owned utun interface after the engine reports it ready.",
                        None,
                    ),
                    step(
                        "pf",
                        "Load routing rules only into the dedicated whitelist-hide pf anchor.",
                        Some("/sbin/pfctl -a com.whitelisthide -f -"),
                    ),
                    step(
                        "health",
                        "Run connectivity and engine health checks; rollback all completed steps on failure.",
                        None,
                    ),
                ],
            }),
            BackendAction::Stop => Ok(ActionPlan {
                id: "macos.stop".to_owned(),
                title: "Stop macOS packet-processing backend".to_owned(),
                requires_admin: true,
                mutates_network: true,
                executable_now: false,
                steps: vec![
                    step(
                        "pf",
                        "Remove only rules owned by whitelist-hide.",
                        Some("/sbin/pfctl -a com.whitelisthide -F all"),
                    ),
                    step(
                        "engine",
                        "Stop only the engine process owned by the privileged helper.",
                        None,
                    ),
                    step(
                        "restore",
                        "Restore settings captured by whitelist-hide before start.",
                        None,
                    ),
                ],
            }),
            BackendAction::Cleanup => Ok(ActionPlan {
                id: "macos.cleanup".to_owned(),
                title: "Clear the whitelist-hide pf anchor".to_owned(),
                requires_admin: true,
                mutates_network: true,
                executable_now: true,
                steps: vec![step(
                    "pf",
                    "Flush only the dedicated whitelist-hide pf anchor. Global pf state is not disabled or reset.",
                    Some("/sbin/pfctl -a com.whitelisthide -F all"),
                )],
            }),
        }
    }

    fn execute(&self, action: BackendAction) -> Result<ActionResult, Self::Error> {
        match action {
            BackendAction::Cleanup => self.cleanup_anchor(),
            BackendAction::Start => Err(MacOsError::ActionUnavailable(
                "start is intentionally disabled until the utun engine lifecycle is implemented"
                    .to_owned(),
            )),
            BackendAction::Stop => Err(MacOsError::ActionUnavailable(
                "stop is intentionally disabled until engine ownership/state tracking is implemented"
                    .to_owned(),
            )),
        }
    }
}

fn step(id: &str, description: &str, command_preview: Option<&str>) -> ActionStep {
    ActionStep {
        id: id.to_owned(),
        description: description.to_owned(),
        command_preview: command_preview.map(str::to_owned),
    }
}

fn command_failure_detail(program: &str, args: &[&str], output: &CommandOutput) -> String {
    let stderr = output.stderr.trim();
    if stderr.is_empty() {
        format!("{program} {} exited with {:?}", args.join(" "), output.code)
    } else {
        format!(
            "{program} {} exited with {:?}: {stderr}",
            args.join(" "),
            output.code
        )
    }
}

fn route_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(key)
            .and_then(nonempty_trimmed)
            .map(str::to_owned)
    })
}

fn parse_pf_status(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("Status:")
            .and_then(nonempty_trimmed)
            .map(str::to_owned)
    })
}

fn parse_utun_interfaces(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|name| name.starts_with("utun"))
        .map(str::to_owned)
        .collect()
}

fn nonempty_trimmed(text: &str) -> Option<&str> {
    let value = text.trim();
    (!value.is_empty()).then_some(value)
}

fn nonempty_line_count(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

#[derive(Debug)]
pub enum MacOsError {
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
    ActionUnavailable(String),
}

impl fmt::Display for MacOsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandIo { program, source } => {
                write!(f, "failed to execute {program}: {source}")
            }
            Self::CommandFailed {
                program,
                args,
                code,
                stderr,
            } => {
                write!(f, "{program} {} failed with {code:?}", args.join(" "))?;
                if !stderr.is_empty() {
                    write!(f, ": {stderr}")?;
                }
                Ok(())
            }
            Self::ActionUnavailable(message) => f.write_str(message),
        }
    }
}

impl Error for MacOsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CommandIo { source, .. } => Some(source),
            Self::CommandFailed { .. } | Self::ActionUnavailable(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route_fields() {
        let route =
            "route to: default\ndestination: default\ngateway: 192.168.1.1\ninterface: en0\n";
        assert_eq!(
            route_value(route, "gateway:"),
            Some("192.168.1.1".to_owned())
        );
        assert_eq!(route_value(route, "interface:"), Some("en0".to_owned()));
    }

    #[test]
    fn parses_pf_status() {
        assert_eq!(
            parse_pf_status("Status: Enabled for 0 days\n"),
            Some("Enabled for 0 days".to_owned())
        );
    }

    #[test]
    fn extracts_only_utun_interfaces() {
        assert_eq!(
            parse_utun_interfaces("lo0 gif0 en0 utun0 utun4 bridge0"),
            vec!["utun0".to_owned(), "utun4".to_owned()]
        );
    }

    #[test]
    fn pf_plan_is_scoped_to_owned_utun() {
        let rules = pf_rules(
            &[
                PortRange { start: 80, end: 80 },
                PortRange {
                    start: 443,
                    end: 443,
                },
            ],
            &[PortRange {
                start: 443,
                end: 443,
            }],
        );
        assert!(rules.contains("route-to (utun50 10.77.0.2)"));
        assert!(rules.contains("proto tcp"));
        assert!(rules.contains("proto udp"));
    }

    #[test]
    fn parses_enable_token() {
        assert_eq!(
            parse_pf_token("pf enabled\nToken : 0123abcd\n"),
            Some("0123abcd".to_owned())
        );
    }

    #[test]
    fn cleanup_plan_is_scoped_to_our_anchor() {
        if Platform::detect() != Platform::MacOS {
            return;
        }

        let backend = MacOsBackend::new(SystemCommandRunner);
        let plan = backend
            .plan(BackendAction::Cleanup)
            .expect("cleanup plan should build");
        assert!(plan.executable_now);
        assert_eq!(plan.steps.len(), 1);
        assert!(
            plan.steps[0]
                .command_preview
                .as_deref()
                .is_some_and(|command| command.contains(PF_ANCHOR))
        );
    }
}
