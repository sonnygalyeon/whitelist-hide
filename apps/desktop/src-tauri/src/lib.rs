use whitelist_hide_core::Platform;
use whitelist_hide_linux::LinuxBackend;
use whitelist_hide_macos::MacOsBackend;
use whitelist_hide_service::{
    ActionPlan, AppService, BackendAction, BackendStatus, PlatformBackend,
};
use whitelist_hide_windows::WindowsBackend;

#[tauri::command]
fn platform() -> String {
    Platform::detect().to_string()
}

#[tauri::command]
fn backend_status() -> Result<BackendStatus, String> {
    match Platform::detect() {
        Platform::MacOS => status(AppService::new(MacOsBackend::system())),
        Platform::Windows => status(AppService::new(WindowsBackend::system())),
        Platform::Linux => status(AppService::new(LinuxBackend::system())),
        Platform::Unsupported => Err("unsupported platform".to_owned()),
    }
}

#[tauri::command]
fn backend_plan(action: String) -> Result<ActionPlan, String> {
    let action = match action.as_str() {
        "start" => BackendAction::Start,
        "stop" => BackendAction::Stop,
        "cleanup" => BackendAction::Cleanup,
        _ => return Err("unknown action".to_owned()),
    };

    match Platform::detect() {
        Platform::MacOS => plan(AppService::new(MacOsBackend::system()), action),
        Platform::Windows => plan(AppService::new(WindowsBackend::system()), action),
        Platform::Linux => plan(AppService::new(LinuxBackend::system()), action),
        Platform::Unsupported => Err("unsupported platform".to_owned()),
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
            platform,
            backend_status,
            backend_plan
        ])
        .run(tauri::generate_context!())
        .expect("error while running whitelist-hide");
}
