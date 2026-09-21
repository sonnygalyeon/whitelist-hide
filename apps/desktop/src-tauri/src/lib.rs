use std::path::PathBuf;

use serde::Serialize;
use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use whitelist_hide_core::Platform;
use whitelist_hide_linux::LinuxBackend;
use whitelist_hide_macos::MacOsBackend;
use whitelist_hide_service::{AppService, BackendStatus};
use whitelist_hide_windows::WindowsBackend;

#[derive(Debug, Clone, Serialize)]
struct ProfileInfo {
    id: &'static str,
    name: &'static str,
    platform: String,
    available: bool,
    config_path: String,
    strategy_path: String,
}

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
fn default_profile(app: tauri::AppHandle) -> Result<ProfileInfo, String> {
    let (config, strategy) = bundled_profile_paths(&app)?;
    Ok(ProfileInfo {
        id: "standard",
        name: "Standard",
        platform: Platform::detect().backend_name().to_owned(),
        available: config.is_file() && strategy.is_file(),
        config_path: config.display().to_string(),
        strategy_path: strategy.display().to_string(),
    })
}

#[tauri::command]
async fn session_start_default(app: tauri::AppHandle) -> Result<String, String> {
    let (config, strategy) = bundled_profile_paths(&app)?;
    if !config.is_file() || !strategy.is_file() {
        return Err(
            "Встроенный профиль не найден. Переустановите приложение из полного desktop-пакета."
                .to_owned(),
        );
    }

    invoke_helper(
        &app,
        vec![
            "start".to_owned(),
            config.display().to_string(),
            strategy.display().to_string(),
        ],
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

fn bundled_profile_paths(app: &tauri::AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("не удалось определить каталог ресурсов: {error}"))?;
    let root = resource_dir.join("whitelist-hide");
    Ok((
        root.join("default").join("config.toml"),
        root.join("default").join("strategy.toml"),
    ))
}

async fn invoke_helper(
    app: &tauri::AppHandle,
    args: Vec<String>,
    allow_not_running: bool,
) -> Result<String, String> {
    let command = app
        .shell()
        .sidecar("whitelist-hide-helper")
        .map_err(|error| format!("не удалось найти системный helper: {error}"))?
        .args(args);

    let output = command
        .output()
        .await
        .map_err(|error| format!("не удалось запустить системный helper: {error}"))?;

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
            "системный helper завершился с кодом {:?}: {detail}",
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
            default_profile,
            session_start_default,
            session_stop,
            session_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
