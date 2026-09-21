use std::error::Error;
use std::fmt;
use std::process::Command;

use whitelist_hide_core::Platform;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub const NFT_TABLE: &str = "whitelist_hide";

pub struct LinuxBackend;

impl LinuxBackend {
    #[must_use]
    pub const fn system() -> Self {
        Self
    }
}

impl PlatformBackend for LinuxBackend {
    type Error = LinuxError;

    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn status(&self) -> Result<BackendStatus, Self::Error> {
        if Platform::detect() != Platform::Linux {
            return Ok(BackendStatus {
                platform: Platform::detect().to_string(),
                available: false,
                state: BackendState::Unsupported,
                diagnostics: vec![],
            });
        }

        let diagnostics = vec![
            diagnostic(
                "default_route",
                "Default route",
                "/usr/sbin/ip",
                &["route", "show", "default"],
            ),
            diagnostic("nftables", "nftables", "/usr/sbin/nft", &["list", "tables"]),
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
        let steps = match action {
            BackendAction::Start => vec![
                step("verify", "Verify the selected userspace engine."),
                step(
                    "queue",
                    "Create only the whitelist-hide nftables table/chains.",
                ),
                step("engine", "Start the engine and record ownership state."),
                step("health", "Validate NFQUEUE flow and rollback on failure."),
            ],
            BackendAction::Stop => vec![
                step("queue", "Remove only the whitelist-hide nftables table."),
                step("engine", "Stop only the recorded engine process."),
            ],
            BackendAction::Cleanup => vec![step(
                "queue",
                "Reconcile runtime state and remove only the whitelist-hide nftables table.",
            )],
        };

        Ok(ActionPlan {
            id: format!("linux.{action:?}").to_ascii_lowercase(),
            title: format!("{action:?} Linux backend"),
            requires_admin: true,
            mutates_network: true,
            executable_now: false,
            steps,
        })
    }

    fn execute(&self, _action: BackendAction) -> Result<ActionResult, Self::Error> {
        Err(LinuxError(
            "Linux mutations are disabled until NFQUEUE integration is complete".to_owned(),
        ))
    }
}

fn diagnostic(key: &str, label: &str, program: &str, args: &[&str]) -> DiagnosticItem {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            level: DiagnosticLevel::Ok,
            detail: None,
        },
        Ok(output) => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: "not ready".to_owned(),
            level: DiagnosticLevel::Warning,
            detail: Some(String::from_utf8_lossy(&output.stderr).trim().to_owned()),
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

fn ensure_linux() -> Result<(), LinuxError> {
    (Platform::detect() == Platform::Linux)
        .then_some(())
        .ok_or_else(|| LinuxError("not running on Linux".to_owned()))
}

fn step(id: &str, description: &str) -> ActionStep {
    ActionStep {
        id: id.to_owned(),
        description: description.to_owned(),
        command_preview: None,
    }
}

#[derive(Debug)]
pub struct LinuxError(String);

impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for LinuxError {}
