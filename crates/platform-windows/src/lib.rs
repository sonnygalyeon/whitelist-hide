use std::error::Error;
use std::fmt;
use std::process::Command;

use whitelist_hide_core::Platform;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub const SERVICE_NAME: &str = "WhitelistHide";

pub struct WindowsBackend;

impl WindowsBackend {
    #[must_use]
    pub const fn system() -> Self {
        Self
    }
}

impl PlatformBackend for WindowsBackend {
    type Error = WindowsError;

    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn status(&self) -> Result<BackendStatus, Self::Error> {
        if Platform::detect() != Platform::Windows {
            return Ok(BackendStatus {
                platform: Platform::detect().to_string(),
                available: false,
                state: BackendState::Unsupported,
                diagnostics: vec![],
            });
        }

        let diagnostics = vec![
            diagnostic(
                "interfaces",
                "Network interfaces",
                "netsh.exe",
                &["interface", "show", "interface"],
            ),
            diagnostic(
                "windivert_service",
                "WinDivert service",
                "sc.exe",
                &["query", "WinDivert"],
            ),
        ];

        let degraded = diagnostics
            .iter()
            .any(|item| item.level == DiagnosticLevel::Warning);

        Ok(BackendStatus {
            platform: "windows".to_owned(),
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
        ensure_windows()?;
        let steps = match action {
            BackendAction::Start => vec![
                step(
                    "verify",
                    "Verify engine and WinDivert artifacts before loading them.",
                ),
                step(
                    "driver",
                    "Install/start only the pinned WinDivert driver version.",
                ),
                step("engine", "Start the verified engine and record its PID."),
                step("health", "Run health checks and rollback on failure."),
            ],
            BackendAction::Stop => vec![
                step("engine", "Stop only the process recorded in runtime state."),
                step("driver", "Release only project-owned driver/service state."),
            ],
            BackendAction::Cleanup => vec![
                step("state", "Reconcile recorded runtime ownership."),
                step("driver", "Remove only project-owned service/driver state."),
            ],
        };

        Ok(ActionPlan {
            id: format!("windows.{action:?}").to_ascii_lowercase(),
            title: format!("{action:?} Windows backend"),
            requires_admin: true,
            mutates_network: true,
            executable_now: false,
            steps,
        })
    }

    fn execute(&self, _action: BackendAction) -> Result<ActionResult, Self::Error> {
        Err(WindowsError(
            "Windows mutations are disabled until WinDivert artifact lifecycle is pinned"
                .to_owned(),
        ))
    }
}

fn diagnostic(key: &str, label: &str, program: &str, args: &[&str]) -> DiagnosticItem {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => DiagnosticItem {
            key: key.to_owned(),
            label: label.to_owned(),
            value: "available".to_owned(),
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

fn ensure_windows() -> Result<(), WindowsError> {
    (Platform::detect() == Platform::Windows)
        .then_some(())
        .ok_or_else(|| WindowsError("not running on Windows".to_owned()))
}

fn step(id: &str, description: &str) -> ActionStep {
    ActionStep {
        id: id.to_owned(),
        description: description.to_owned(),
        command_preview: None,
    }
}

#[derive(Debug)]
pub struct WindowsError(String);

impl fmt::Display for WindowsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for WindowsError {}
