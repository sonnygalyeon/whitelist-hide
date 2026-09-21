use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Serialize;
use whitelist_hide_controller::{
    SessionStatus, status as controller_status, system_config_path,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UiStatus {
    platform: String,
    running: bool,
    healthy: bool,
    engine_pid: Option<u32>,
    strategy: Option<String>,
    detail: String,
    system_config: String,
}

impl From<SessionStatus> for UiStatus {
    fn from(value: SessionStatus) -> Self {
        Self {
            platform: value.platform.to_string(),
            running: value.running,
            healthy: value.healthy,
            engine_pid: value.engine_pid,
            strategy: value.strategy,
            detail: value.detail,
            system_config: system_config_path().display().to_string(),
        }
    }
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn session_status() -> Result<UiStatus, String> {
    controller_status().map(UiStatus::from).map_err(|error| error.to_string())
}

#[tauri::command]
fn session_start() -> Result<UiStatus, String> {
    run_privileged_helper("start")?;
    session_status()
}

#[tauri::command]
fn session_stop() -> Result<UiStatus, String> {
    run_privileged_helper("stop")?;
    session_status()
}

fn run_privileged_helper(action: &str) -> Result<(), String> {
    if !matches!(action, "start" | "stop") {
        return Err("unsupported helper action".to_owned());
    }

    let helper = helper_path()?;
    let output = elevated_output(&helper, action)?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "privileged helper failed (code {:?}): {}{}",
            output.status.code(),
            stdout.trim(),
            if stderr.trim().is_empty() {
                String::new()
            } else {
                format!(" {}", stderr.trim())
            }
        ))
    }
}

fn helper_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let directory = executable
        .parent()
        .ok_or_else(|| "application executable has no parent directory".to_owned())?;

    let filename = if cfg!(target_os = "windows") {
        "whitelist-hide-helper.exe"
    } else {
        "whitelist-hide-helper"
    };
    let helper = directory.join(filename);

    if helper.is_file() {
        Ok(helper)
    } else {
        Err(format!(
            "privileged helper sidecar is missing: {}",
            helper.display()
        ))
    }
}

#[cfg(target_os = "linux")]
fn elevated_output(helper: &Path, action: &str) -> Result<Output, String> {
    Command::new("pkexec")
        .arg(helper)
        .arg(action)
        .output()
        .map_err(|error| format!("cannot start pkexec: {error}"))
}

#[cfg(target_os = "macos")]
fn elevated_output(helper: &Path, action: &str) -> Result<Output, String> {
    let command = format!("{} {}", shell_single_quote(helper), action);
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&command)
    );

    Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|error| format!("cannot start macOS authorization prompt: {error}"))
}

#[cfg(target_os = "windows")]
fn elevated_output(helper: &Path, action: &str) -> Result<Output, String> {
    let helper = powershell_single_quote(&helper.display().to_string());
    let action = powershell_single_quote(action);
    let script = format!(
        "$p=Start-Process -FilePath {helper} -ArgumentList {action} -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
    );

    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|error| format!("cannot start Windows elevation prompt: {error}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn elevated_output(_helper: &Path, _action: &str) -> Result<Output, String> {
    Err("unsupported platform".to_owned())
}

#[cfg(target_os = "macos")]
fn shell_single_quote(path: &Path) -> String {
    let value = path.display().to_string().replace("'", "'\\''");
    format!("'{value}'")
}

#[cfg(target_os = "macos")]
fn applescript_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "windows")]
fn powershell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace("'", "''"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_version,
            session_status,
            session_start,
            session_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
