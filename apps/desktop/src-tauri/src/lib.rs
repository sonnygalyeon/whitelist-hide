use std::env;
use std::path::PathBuf;
use std::process::Command;

use whitelist_hide_core::Platform;
use whitelist_hide_linux::LinuxBackend;
use whitelist_hide_macos::MacOsBackend;
use whitelist_hide_service::{AppService, BackendStatus};
use whitelist_hide_windows::WindowsBackend;

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn backend_status() -> Result<BackendStatus, String> {
    match Platform::detect() {
        Platform::MacOS => AppService::new(MacOsBackend::system())
            .status()
            .map_err(|error| error.to_string()),
        Platform::Windows => AppService::new(WindowsBackend::new())
            .status()
            .map_err(|error| error.to_string()),
        Platform::Linux => AppService::new(LinuxBackend::new())
            .status()
            .map_err(|error| error.to_string()),
        Platform::Unsupported => Err("unsupported platform".to_owned()),
    }
}

#[tauri::command]
fn session_start(config: String, strategy: String) -> Result<String, String> {
    invoke_helper(&["start", &config, &strategy], false)
}

#[tauri::command]
fn session_stop() -> Result<String, String> {
    invoke_helper(&["stop"], false)
}

#[tauri::command]
fn session_health() -> Result<String, String> {
    invoke_helper(&["health"], true)
}

fn invoke_helper(args: &[&str], allow_not_running: bool) -> Result<String, String> {
    let helper = helper_path()?;
    let output = Command::new(&helper)
        .args(args)
        .output()
        .map_err(|error| format!("failed to start {}: {error}", helper.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    if output.status.success() || (allow_not_running && output.status.code() == Some(6)) {
        if stdout.is_empty() {
            Ok("ok".to_owned())
        } else {
            Ok(stdout)
        }
    } else {
        let detail = if stderr.is_empty() { stdout } else { stderr };
        Err(format!(
            "privileged helper failed with status {:?}: {detail}",
            output.status.code()
        ))
    }
}

fn helper_path() -> Result<PathBuf, String> {
    if let Some(explicit) = env::var_os("WHITELIST_HIDE_HELPER") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "WHITELIST_HIDE_HELPER does not point to a file: {}",
            path.display()
        ));
    }

    let current = env::current_exe().map_err(|error| error.to_string())?;
    let directory = current
        .parent()
        .ok_or_else(|| "application executable has no parent directory".to_owned())?;

    #[cfg(target_os = "windows")]
    let helper_name = "whitelist-hide-helper.exe";
    #[cfg(not(target_os = "windows"))]
    let helper_name = "whitelist-hide-helper";

    let candidate = directory.join(helper_name);
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(format!(
            "bundled privileged helper was not found at {}",
            candidate.display()
        ))
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_version,
            backend_status,
            session_start,
            session_stop,
            session_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
