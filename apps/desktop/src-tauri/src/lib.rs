use std::env;
use std::path::{Path, PathBuf};

use serde::Serialize;
use whitelist_hide_core::Platform;
use whitelist_hide_core::strategy::StrategyDefinition;
use whitelist_hide_core::strategy_compiler::compile_strategy;
use whitelist_hide_orchestrator::{SessionSpec, start_session, stop_session};
use whitelist_hide_runtime::StateStore;

#[derive(Serialize)]
struct RuntimeView {
    running: bool,
    platform: String,
    phase: String,
    engine_pid: Option<u32>,
    strategy_hint: Option<String>,
}

#[derive(Serialize)]
struct StrategyPreview {
    id: String,
    arguments: Vec<String>,
    referenced_files: Vec<String>,
}

#[derive(Serialize)]
struct SessionView {
    platform: String,
    strategy: String,
    engine_pid: u32,
    firewall_scope: Option<String>,
    interface: Option<String>,
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn runtime_status() -> Result<RuntimeView, String> {
    let store = StateStore::new(runtime_state_path());
    match store.load().map_err(|error| error.to_string())? {
        Some(state) => Ok(RuntimeView {
            running: matches!(state.phase, whitelist_hide_runtime::RuntimePhase::Running),
            platform: state.platform,
            phase: format!("{:?}", state.phase),
            engine_pid: state.engine_pid,
            strategy_hint: None,
        }),
        None => Ok(RuntimeView {
            running: false,
            platform: Platform::detect().to_string(),
            phase: "Stopped".to_owned(),
            engine_pid: None,
            strategy_hint: None,
        }),
    }
}

#[tauri::command]
fn strategy_preview(path: String) -> Result<StrategyPreview, String> {
    let path = PathBuf::from(path);
    let strategy = StrategyDefinition::load(&path).map_err(|error| error.to_string())?;
    let plan = compile_strategy(&strategy, &path).map_err(|error| error.to_string())?;
    Ok(StrategyPreview {
        id: plan.strategy_id,
        arguments: plan.arguments,
        referenced_files: plan
            .referenced_files
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
    })
}

#[tauri::command]
fn session_start(config_path: String, strategy_path: String) -> Result<SessionView, String> {
    let spec = SessionSpec {
        config_path: PathBuf::from(config_path),
        strategy_path: PathBuf::from(strategy_path),
        state_path: runtime_state_path(),
    };
    let report = start_session(&spec).map_err(|error| error.to_string())?;
    Ok(SessionView {
        platform: report.platform.to_string(),
        strategy: report.strategy_id,
        engine_pid: report.engine_pid,
        firewall_scope: report.firewall_scope,
        interface: report.interface,
    })
}

#[tauri::command]
fn session_stop() -> Result<bool, String> {
    stop_session(&runtime_state_path()).map_err(|error| error.to_string())
}

fn runtime_state_path() -> PathBuf {
    match Platform::detect() {
        Platform::Windows => env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whitelist-hide")
            .join("runtime-state.json"),
        Platform::MacOS => Path::new("/var/run/whitelist-hide/runtime-state.json").to_path_buf(),
        Platform::Linux => Path::new("/run/whitelist-hide/runtime-state.json").to_path_buf(),
        Platform::Unsupported => PathBuf::from("runtime-state.json"),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_version,
            runtime_status,
            strategy_preview,
            session_start,
            session_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
