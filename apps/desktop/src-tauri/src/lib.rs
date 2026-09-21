use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use whitelist_hide_core::Platform;
use whitelist_hide_core::strategy::StrategyDefinition;
use whitelist_hide_core::strategy_compiler::compile_strategy;
use whitelist_hide_runtime::StateStore;

#[derive(Serialize)]
struct RuntimeView {
    running: bool,
    platform: String,
    phase: String,
    engine_pid: Option<u32>,
}

#[derive(Serialize)]
struct StrategyPreview {
    id: String,
    arguments: Vec<String>,
    referenced_files: Vec<String>,
}

#[derive(Serialize)]
struct HelperRequest {
    schema: u32,
    action: HelperAction,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperAction {
    Start {
        config_path: PathBuf,
        strategy_path: PathBuf,
        state_path: PathBuf,
    },
    Stop {
        state_path: PathBuf,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct HelperResponse {
    schema: u32,
    ok: bool,
    message: String,
    engine_pid: Option<u32>,
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
        }),
        None => Ok(RuntimeView {
            running: false,
            platform: Platform::detect().to_string(),
            phase: "Stopped".to_owned(),
            engine_pid: None,
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
fn session_start(config_path: String, strategy_path: String) -> Result<HelperResponse, String> {
    let config_path = absolute_existing_file(&config_path)?;
    let strategy_path = absolute_existing_file(&strategy_path)?;

    invoke_helper(&HelperRequest {
        schema: 1,
        action: HelperAction::Start {
            config_path,
            strategy_path,
            state_path: runtime_state_path(),
        },
    })
}

#[tauri::command]
fn session_stop() -> Result<HelperResponse, String> {
    invoke_helper(&HelperRequest {
        schema: 1,
        action: HelperAction::Stop {
            state_path: runtime_state_path(),
        },
    })
}

fn invoke_helper(request: &HelperRequest) -> Result<HelperResponse, String> {
    let helper = helper_path()?;
    let payload = serde_json::to_vec(request).map_err(|error| error.to_string())?;

    let mut child = Command::new(&helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start {}: {error}", helper.display()))?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| "helper stdin unavailable".to_owned())?
        .write_all(&payload)
        .map_err(|error| format!("failed to write helper request: {error}"))?;

    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for helper: {error}"))?;

    let response: HelperResponse =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            format!(
                "invalid helper response: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
        })?;

    if response.ok {
        Ok(response)
    } else {
        Err(response.message)
    }
}

fn helper_path() -> Result<PathBuf, String> {
    let executable = env::current_exe().map_err(|error| error.to_string())?;
    let directory = executable
        .parent()
        .ok_or_else(|| "application executable has no parent directory".to_owned())?;

    #[cfg(target_os = "windows")]
    let filename = "whitelist-hide-helper.exe";
    #[cfg(not(target_os = "windows"))]
    let filename = "whitelist-hide-helper";

    Ok(directory.join(filename))
}

fn absolute_existing_file(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", path.display()))?;
    if !canonical.is_file() {
        return Err(format!("not a file: {}", canonical.display()));
    }
    Ok(canonical)
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
