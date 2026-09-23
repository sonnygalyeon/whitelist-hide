use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

use whitelist_hide_core::Platform;
use whitelist_hide_core::strategy::PortRange;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub const NFT_TABLE: &str = "inet whitelist_hide";

pub const NFQUEUE_NUM: u16 = 200;

pub fn owned_table_exists() -> Result<bool, LinuxError> {
    ensure_linux()?;
    match Command::new("nft")
        .args(["list", "table", "inet", "whitelist_hide"])
        .output()
    {
        Ok(output) => Ok(output.status.success()),
        Err(source) => Err(LinuxError::CommandIo(source)),
    }
}

pub fn install_nfqueue_rules(
    tcp_ports: &[PortRange],
    udp_ports: &[PortRange],
    queue: u16,
) -> Result<(), LinuxError> {
    ensure_linux()?;

    if owned_table_exists()? {
        return Err(LinuxError::ActionUnavailable(
            "refusing to overwrite existing inet whitelist_hide table without owned runtime state"
                .to_owned(),
        ));
    }

    let rules = nft_rules(tcp_ports, udp_ports, queue);
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(LinuxError::CommandIo)?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| LinuxError::ActionUnavailable("nft stdin is unavailable".to_owned()))?
        .write_all(rules.as_bytes())
        .map_err(LinuxError::CommandIo)?;

    let output = child.wait_with_output().map_err(LinuxError::CommandIo)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

pub fn remove_owned_table() -> Result<bool, LinuxError> {
    ensure_linux()?;
    if !owned_table_exists()? {
        return Ok(false);
    }

    let output = Command::new("nft")
        .args(["delete", "table", "inet", "whitelist_hide"])
        .output()
        .map_err(LinuxError::CommandIo)?;

    if output.status.success() {
        Ok(true)
    } else {
        Err(LinuxError::CommandFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

fn nft_rules(tcp_ports: &[PortRange], udp_ports: &[PortRange], queue: u16) -> String {
    let mut rules = String::from(
        "table inet whitelist_hide {\n  chain output {\n    type filter hook output priority mangle; policy accept;\n    meta mark & 0x40000000 != 0 return\n",
    );

    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            "    tcp dport {{ {} }} queue num {queue} bypass\n",
            nft_ports(tcp_ports)
        ));
    }
    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            "    udp dport {{ {} }} queue num {queue} bypass\n",
            nft_ports(udp_ports)
        ));
    }

    rules.push_str("  }\n}\n");
    rules
}

fn nft_ports(ranges: &[PortRange]) -> String {
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
        .join(", ")
}

pub struct LinuxBackend;

impl LinuxBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for LinuxBackend {
    type Error = LinuxError;

    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn status(&self) -> Result<BackendStatus, Self::Error> {
        if Platform::detect() != Platform::Linux {
            return Ok(unsupported());
        }

        let diagnostics = vec![
            run_diag(
                "ip",
                &["route", "show", "default"],
                "default_route",
                "Default route",
            ),
            run_diag("nft", &["list", "tables"], "nftables", "nftables"),
            run_diag("id", &["-u"], "privilege", "Current uid"),
            run_diag("uname", &["-r"], "kernel", "Kernel"),
        ];

        let degraded = diagnostics
            .iter()
            .any(|item| item.level == DiagnosticLevel::Warning);

        Ok(BackendStatus {
            platform: "linux".to_owned(),
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
        ensure_linux()?;
        Ok(match action {
            BackendAction::Start => plan(
                "linux.start",
                "Start Linux NFQUEUE backend",
                false,
                vec![
                    step(
                        "verify",
                        "Verify the userspace packet engine and configuration.",
                    ),
                    step(
                        "table",
                        "Create only the dedicated inet whitelist_hide nftables table.",
                    ),
                    step("queue", "Attach only project-owned chains to NFQUEUE."),
                    step("engine", "Start the owned userspace engine."),
                    step(
                        "health",
                        "Verify queue and engine health; rollback on failure.",
                    ),
                ],
            ),
            BackendAction::Stop => plan(
                "linux.stop",
                "Stop Linux NFQUEUE backend",
                false,
                vec![
                    step(
                        "rules",
                        "Remove only the inet whitelist_hide nftables table.",
                    ),
                    step("engine", "Stop only the recorded engine process."),
                    step("state", "Clear runtime state after cleanup."),
                ],
            ),
            BackendAction::Cleanup => plan(
                "linux.cleanup",
                "Clean owned Linux resources",
                false,
                vec![step(
                    "table",
                    "Delete only the inet whitelist_hide nftables table if it is owned by this project.",
                )],
            ),
        })
    }

    fn execute(&self, _action: BackendAction) -> Result<ActionResult, Self::Error> {
        Err(LinuxError::ActionUnavailable(
            "Linux mutation is disabled until NFQUEUE ownership/state tracking is implemented"
                .to_owned(),
        ))
    }
}

fn run_diag(program: &str, args: &[&str], key: &str, label: &str) -> DiagnosticItem {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: first_nonempty(&String::from_utf8_lossy(&output.stdout))
                .unwrap_or("available")
                .to_owned(),
            level: DiagnosticLevel::Ok,
            detail: None,
        },
        Ok(output) => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: "not active / unavailable".to_owned(),
            level: DiagnosticLevel::Warning,
            detail: first_nonempty(&String::from_utf8_lossy(&output.stderr)).map(str::to_owned),
        },
        Err(error) => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: "unavailable".to_owned(),
            level: DiagnosticLevel::Warning,
            detail: Some(error.to_string()),
        },
    }
}

fn first_nonempty(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

fn unsupported() -> BackendStatus {
    BackendStatus {
        platform: Platform::detect().to_string(),
        available: false,
        state: BackendState::Unsupported,
        diagnostics: vec![DiagnosticItem {
            key: "platform".to_owned(),
            label: "Linux backend".to_owned(),
            value: "unsupported on this host".to_owned(),
            level: DiagnosticLevel::Info,
            detail: None,
        }],
    }
}

fn ensure_linux() -> Result<(), LinuxError> {
    if Platform::detect() == Platform::Linux {
        Ok(())
    } else {
        Err(LinuxError::ActionUnavailable(
            "Linux backend can only execute on Linux".to_owned(),
        ))
    }
}

fn step(id: &str, description: &str) -> ActionStep {
    ActionStep {
        id: id.to_owned(),
        description: description.to_owned(),
        command_preview: None,
    }
}

fn plan(id: &str, title: &str, executable_now: bool, steps: Vec<ActionStep>) -> ActionPlan {
    ActionPlan {
        id: id.to_owned(),
        title: title.to_owned(),
        requires_admin: true,
        mutates_network: true,
        executable_now,
        steps,
    }
}

#[derive(Debug)]
pub enum LinuxError {
    CommandIo(std::io::Error),
    CommandFailed(String),
    ActionUnavailable(String),
}

impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandIo(source) => write!(f, "Linux command failed: {source}"),
            Self::CommandFailed(message) => write!(f, "Linux command returned an error: {message}"),
            Self::ActionUnavailable(message) => f.write_str(message),
        }
    }
}

impl Error for LinuxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CommandIo(source) => Some(source),
            Self::CommandFailed(_) | Self::ActionUnavailable(_) => None,
        }
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;

    #[test]
    fn nft_plan_is_scoped_and_uses_bypass() {
        let rules = nft_rules(
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
            NFQUEUE_NUM,
        );
        assert!(rules.contains("table inet whitelist_hide"));
        assert!(rules.contains("queue num 200 bypass"));
        assert!(!rules.contains("flush ruleset"));
    }
}
