use std::fs;
use std::path::{Path, PathBuf};

use tauri::path::BaseDirectory;
use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use whitelist_hide_core::config::AppConfig;
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
fn runtime_info(app: tauri::AppHandle) -> Result<String, String> {
    let paths = ensure_bundled_runtime(&app)?;
    Ok(format!(
        "ready=true\nprofile=balanced-default\nplatform={}\nconfig={}\nstrategy={}",
        Platform::detect(),
        paths.config.display(),
        paths.strategy.display()
    ))
}

#[tauri::command]
async fn session_start(app: tauri::AppHandle) -> Result<String, String> {
    let paths = ensure_bundled_runtime(&app)?;
    invoke_helper(
        &app,
        vec![
            "start".to_owned(),
            paths.config.to_string_lossy().into_owned(),
            paths.strategy.to_string_lossy().into_owned(),
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

struct RuntimePaths {
    config: PathBuf,
    strategy: PathBuf,
}

fn ensure_bundled_runtime(app: &tauri::AppHandle) -> Result<RuntimePaths, String> {
    let source = app
        .path()
        .resolve("default", BaseDirectory::Resource)
        .map_err(|error| format!("cannot resolve bundled runtime resources: {error}"))?;

    let destination = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("cannot resolve application data directory: {error}"))?
        .join("runtime")
        .join(env!("CARGO_PKG_VERSION"));

    let config = destination.join("config.toml");
    let strategy = destination.join("strategy.toml");

    if !config.is_file() || !strategy.is_file() {
        if destination.exists() {
            fs::remove_dir_all(&destination)
                .map_err(|error| format!("cannot reset partial runtime install: {error}"))?;
        }
        copy_tree(&source, &destination)?;
    }

    let parsed = AppConfig::load(&config)
        .map_err(|error| format!("bundled runtime config is invalid: {error}"))?;
    let resolved = parsed.resolve_engine_paths(&config);

    if !resolved.binary.is_file() {
        return Err(format!(
            "bundled engine is missing after installation: {}",
            resolved.binary.display()
        ));
    }

    #[cfg(unix)]
    make_executable(&resolved.binary)?;

    Ok(RuntimePaths { config, strategy })
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!(
            "bundled runtime resource directory is missing: {}",
            source.display()
        ));
    }

    fs::create_dir_all(destination)
        .map_err(|error| format!("cannot create runtime directory: {error}"))?;

    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot read bundled runtime directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read bundled runtime entry: {error}"))?;
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect bundled runtime entry: {error}"))?;

        if kind.is_dir() {
            copy_tree(&source_path, &target_path)?;
        } else if kind.is_file() {
            fs::copy(&source_path, &target_path).map_err(|error| {
                format!(
                    "cannot install bundled runtime file {}: {error}",
                    source_path.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("cannot inspect engine permissions: {error}"))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot make bundled engine executable: {error}"))
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
            runtime_info,
            session_start,
            session_stop,
            session_health
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
