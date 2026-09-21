use whitelist_hide_linux::LinuxBackend;
use whitelist_hide_macos::MacOsBackend;
use whitelist_hide_service::{ActionPlan, AppService, BackendAction, BackendStatus, PlatformBackend};
use whitelist_hide_windows::WindowsBackend;

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn current_platform() -> String {
    whitelist_hide_core::Platform::detect().to_string()
}

#[tauri::command]
fn backend_status(platform: String) -> Result<BackendStatus, String> {
    match platform.as_str() {
        "macos" => status(AppService::new(MacOsBackend::system())),
        "windows" => status(AppService::new(WindowsBackend::new())),
        "linux" => status(AppService::new(LinuxBackend::new())),
        _ => Err(format!("unsupported platform: {platform}")),
    }
}

#[tauri::command]
fn backend_plan(platform: String, action: String) -> Result<ActionPlan, String> {
    let action = parse_action(&action)?;
    match platform.as_str() {
        "macos" => plan(AppService::new(MacOsBackend::system()), action),
        "windows" => plan(AppService::new(WindowsBackend::new()), action),
        "linux" => plan(AppService::new(LinuxBackend::new()), action),
        _ => Err(format!("unsupported platform: {platform}")),
    }
}

fn parse_action(value: &str) -> Result<BackendAction, String> {
    match value {
        "start" => Ok(BackendAction::Start),
        "stop" => Ok(BackendAction::Stop),
        "cleanup" => Ok(BackendAction::Cleanup),
        _ => Err(format!("unsupported action: {value}")),
    }
}

fn status<B>(service: AppService<B>) -> Result<BackendStatus, String>
where
    B: PlatformBackend,
{
    service.status().map_err(|error| error.to_string())
}

fn plan<B>(service: AppService<B>, action: BackendAction) -> Result<ActionPlan, String>
where
    B: PlatformBackend,
{
    service.plan(action).map_err(|error| error.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_version,
            current_platform,
            backend_status,
            backend_plan
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide desktop");
}
