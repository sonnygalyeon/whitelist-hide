use std::path::Path;

use whitelist_hide_controller::{HealthReport, SessionController, SessionReport, default_state_path};
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
fn session_start(config: String, strategy: String) -> Result<SessionReport, String> {
    SessionController::new(default_state_path())
        .start(Path::new(&config), Path::new(&strategy))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn session_stop() -> Result<bool, String> {
    SessionController::new(default_state_path())
        .stop()
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn session_health() -> Result<HealthReport, String> {
    SessionController::new(default_state_path())
        .health()
        .map_err(|error| error.to_string())
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
