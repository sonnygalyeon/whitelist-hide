use tauri_plugin_shell::ShellExt;
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
async fn session_start(
    app: tauri::AppHandle,
    config: String,
    strategy: String,
) -> Result<String, String> {
    invoke_helper(
        &app,
        vec!["start".to_owned(), config, strategy],
        false,
    )
    .await
}

#[tauri::command]
async fn session_stop(app: tauri::AppHandle) -> Result<String, String> {
    invoke_helper(&app, vec!["stop".to_owned()], false).await
}

#[tauri::command]
async fn session_health(app: tauri::AppHandle) -> Result<String, String> {
    invoke_helper(&app, vec!["health".to_owned()], true).await
}

async fn invoke_helper(
    app: &tauri::AppHandle,
    args: Vec<String>,
    allow_not_running: bool,
) -> Result<String, String> {
    let command = app
        .shell()
        .sidecar("whitelist-hide-helper")
        .map_err(|error| format!("failed to resolve bundled privileged helper: {error}"))?
        .args(args);

    let output = command
        .output()
        .await
        .map_err(|error| format!("failed to execute bundled privileged helper: {error}"))?;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
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
