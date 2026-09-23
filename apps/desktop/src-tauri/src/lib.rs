use std::path::PathBuf;

use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Emitter, Manager};

static SESSION_BUSY: AtomicBool = AtomicBool::new(false);

struct OperationGuard;
impl Drop for OperationGuard {
    fn drop(&mut self) {
        SESSION_BUSY.store(false, Ordering::Release);
    }
}
fn operation_guard() -> Result<OperationGuard, String> {
    SESSION_BUSY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| OperationGuard)
        .map_err(|_| "Другая операция ещё выполняется".to_owned())
}
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
async fn session_start_default(
    app: tauri::AppHandle,
    profile: Option<String>,
) -> Result<String, String> {
    let _guard = operation_guard()?;
    let (config, strategy) =
        selected_profile_paths(&app, profile.as_deref().unwrap_or("standard"))?;
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
    let _guard = operation_guard()?;
    invoke_helper(&app, vec!["stop".to_owned()], false).await
}

#[tauri::command]
async fn session_health(app: tauri::AppHandle) -> Result<String, String> {
    invoke_helper(&app, vec!["health".to_owned()], false).await
}

fn bundled_profile_paths(app: &tauri::AppHandle) -> Result<(PathBuf, PathBuf), String> {
    selected_profile_paths(app, "standard")
}

fn selected_profile_paths(
    app: &tauri::AppHandle,
    profile: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let (config_name, strategy_name) = match profile {
        "standard" => ("config.toml", "strategy.toml"),
        "split" => ("config-split.toml", "split.toml"),
        "disorder" => ("config-disorder.toml", "disorder.toml"),
        _ => return Err("Неизвестный встроенный профиль".to_owned()),
    };
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("не удалось определить каталог ресурсов: {error}"))?;
    let root = resource_dir.join("whitelist-hide");
    Ok((
        root.join("default").join(config_name),
        root.join("default").join(strategy_name),
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

#[tauri::command]
async fn engine_logs(app: tauri::AppHandle) -> Result<String, String> {
    invoke_helper(&app, vec!["logs".to_owned()], false).await
}

#[tauri::command]
async fn export_report(app: tauri::AppHandle, activity: String) -> Result<String, String> {
    if activity.len() > 256_000 {
        return Err("Журнал слишком большой".to_owned());
    }
    let dir = app.path().download_dir().map_err(|e| e.to_string())?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let path = dir.join(format!("whitelist-hide-diagnostics-{timestamp}.txt"));
    let health = session_health(app.clone()).await.unwrap_or_else(|e| e);
    let logs = engine_logs(app).await.unwrap_or_else(|e| e);
    let body = format!(
        "whitelist-hide {}\nPlatform: {}\n\n{health}\n\nActivity\n{activity}\n\nEngine log\n{logs}\n",
        app_version(),
        Platform::detect()
    );
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::TrayIconBuilder;
            let show =
                MenuItem::with_id(app, "show", "Открыть whitelist-hide", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Выйти…", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            if let Some(icon) = app.default_window_icon().cloned() {
                // Tray availability must not prevent the main window from opening.
                let _ = TrayIconBuilder::new()
                    .icon(icon)
                    .tooltip("whitelist-hide")
                    .menu(&menu)
                    .on_menu_event(|app, event| {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                        if event.id().as_ref() == "quit" {
                            let _ = app.emit("close-requested", ());
                        }
                    })
                    .build(app);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.emit("close-requested", ());
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_version,
            backend_status,
            default_profile,
            session_start_default,
            session_stop,
            session_health,
            engine_logs,
            export_report,
            quit_app
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
