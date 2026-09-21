use std::error::Error;
use std::fmt;
use std::process::Command;

use whitelist_hide_core::Platform;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub const NFT_TABLE: &str = "inet whitelist_hide";

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
            run_diag("ip", &["route", "show", "default"], "default_route", "Default route"),
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
                    step("verify", "Verify the userspace packet engine and configuration."),
                    step("table", "Create only the dedicated inet whitelist_hide nftables table."),
                    step("queue", "Attach only project-owned chains to NFQUEUE."),
                    step("engine", "Start the owned userspace engine."),
                    step("health", "Verify queue and engine health; rollback on failure."),
                ],
            ),
            BackendAction::Stop => plan(
                "linux.stop",
                "Stop Linux NFQUEUE backend",
                false,
                vec![
                    step("rules", "Remove only the inet whitelist_hide nftables table."),
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
    ActionUnavailable(String),
}

impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActionUnavailable(message) => f.write_str(message),
        }
    }
}

impl Error for LinuxError {}
