use std::error::Error;
use std::fmt;
use std::io;
use std::process::Command;

use whitelist_hide_core::Platform;
use whitelist_hide_service::{
    ActionPlan, ActionResult, ActionStep, BackendAction, BackendState, BackendStatus,
    DiagnosticItem, DiagnosticLevel, PlatformBackend,
};

pub fn windivert_service_running() -> Result<bool, WindowsError> {
    ensure_windows()?;
    let output = Command::new("sc")
        .args(["query", "WinDivert"])
        .output()
        .map_err(WindowsError::CommandIo)?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().any(|line| {
        let line = line.trim();
        line.starts_with("STATE") && line.contains("RUNNING")
    }))
}

pub struct WindowsBackend;

impl WindowsBackend {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformBackend for WindowsBackend {
    type Error = WindowsError;

    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn status(&self) -> Result<BackendStatus, Self::Error> {
        if Platform::detect() != Platform::Windows {
            return Ok(unsupported());
        }

        let diagnostics = vec![
            run_diag("whoami", &["/user"], "identity", "Current Windows identity"),
            run_diag(
                "route",
                &["print", "0.0.0.0"],
                "default_route",
                "IPv4 default route",
            ),
            run_diag(
                "sc",
                &["query", "WinDivert"],
                "windivert",
                "WinDivert service",
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
        Ok(match action {
            BackendAction::Start => plan(
                "windows.start",
                "Start Windows packet-processing backend",
                false,
                vec![
                    step(
                        "verify",
                        "Verify engine and WinDivert artifacts before loading them.",
                    ),
                    step(
                        "driver",
                        "Load only the pinned WinDivert driver required by this session.",
                    ),
                    step(
                        "engine",
                        "Start the owned packet engine with a structured strategy.",
                    ),
                    step(
                        "health",
                        "Verify process health and packet path; rollback on failure.",
                    ),
                ],
            ),
            BackendAction::Stop => plan(
                "windows.stop",
                "Stop Windows packet-processing backend",
                false,
                vec![
                    step(
                        "engine",
                        "Stop only the engine process recorded in runtime state.",
                    ),
                    step(
                        "driver",
                        "Release only project-owned driver/service state where applicable.",
                    ),
                    step("state", "Clear runtime state after verified cleanup."),
                ],
            ),
            BackendAction::Cleanup => plan(
                "windows.cleanup",
                "Clean owned Windows resources",
                false,
                vec![step(
                    "owned",
                    "Remove only resources recorded as owned by whitelist-hide; no Winsock/TCP reset.",
                )],
            ),
        })
    }

    fn execute(&self, _action: BackendAction) -> Result<ActionResult, Self::Error> {
        Err(WindowsError::ActionUnavailable(
            "Windows mutation is disabled until verified WinDivert ownership is implemented"
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
            label: "Windows backend".to_owned(),
            value: "unsupported on this host".to_owned(),
            level: DiagnosticLevel::Info,
            detail: None,
        }],
    }
}

fn ensure_windows() -> Result<(), WindowsError> {
    if Platform::detect() == Platform::Windows {
        Ok(())
    } else {
        Err(WindowsError::ActionUnavailable(
            "Windows backend can only execute on Windows".to_owned(),
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
pub enum WindowsError {
    CommandIo(io::Error),
    ActionUnavailable(String),
}

impl fmt::Display for WindowsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandIo(source) => write!(f, "Windows command failed: {source}"),
            Self::ActionUnavailable(message) => f.write_str(message),
        }
    }
}

impl Error for WindowsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CommandIo(source) => Some(source),
            Self::ActionUnavailable(_) => None,
        }
    }
}
