use std::env;
use std::fmt::Display;
use std::path::{Path, PathBuf};

use whitelist_hide_core::artifact::{ArtifactManifest, VerificationReport, verify_file};
use whitelist_hide_core::config::AppConfig;
use whitelist_hide_core::strategy::StrategyManifest;
use whitelist_hide_core::{DoctorReport, Platform};
use whitelist_hide_linux::LinuxBackend;
use whitelist_hide_macos::MacOsBackend;
use whitelist_hide_service::runtime::RuntimeState;
use whitelist_hide_service::{
    ActionPlan, AppService, BackendAction, BackendState, BackendStatus, DiagnosticLevel,
    PlatformBackend,
};
use whitelist_hide_windows::WindowsBackend;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let exit_code = match args.as_slice() {
        [] => {
            help();
            0
        }
        [command] if command == "doctor" => {
            doctor();
            0
        }
        [command] if command == "status" => status(),
        [command] if command == "config-path" => {
            println!("{}", config_path().display());
            0
        }
        [command] if matches!(command.as_str(), "help" | "--help" | "-h") => {
            help();
            0
        }
        [command] if matches!(command.as_str(), "version" | "--version" | "-V") => {
            println!("whitelist-hide {}", env!("CARGO_PKG_VERSION"));
            0
        }
        [group, action] if group == "config" && action == "validate" => {
            config_validate(&config_path())
        }
        [group, action, path] if group == "config" && action == "validate" => {
            config_validate(Path::new(path))
        }
        [group, action] if group == "config" && action == "verify" => config_verify(&config_path()),
        [group, action, path] if group == "config" && action == "verify" => {
            config_verify(Path::new(path))
        }
        [group, action, path] if group == "strategy" && action == "validate" => {
            strategy_validate(Path::new(path))
        }
        [group, action, manifest, binary] if group == "engine" && action == "verify" => {
            engine_verify(Path::new(manifest), Path::new(binary))
        }
        [group, platform, action] if group == "backend" && action == "inspect" => {
            backend_inspect(platform)
        }
        [group, platform, plan, action] if group == "backend" && plan == "plan" => {
            backend_plan(platform, action)
        }
        [group, platform, action]
            if group == "backend" && platform == "macos" && action == "cleanup" =>
        {
            backend_plan("macos", "cleanup")
        }
        [group, platform, action, flag]
            if group == "backend"
                && platform == "macos"
                && action == "cleanup"
                && flag == "--apply" =>
        {
            macos_cleanup_apply()
        }
        _ => {
            eprintln!("invalid command or arguments\n");
            help();
            2
        }
    };

    std::process::exit(exit_code);
}

fn doctor() {
    let report = DoctorReport::collect();

    println!("whitelist-hide doctor");
    println!("platform: {}", report.platform);
    println!("architecture: {}", report.architecture);
    println!("planned interceptor: {}", report.interceptor);
    println!("network changes: guarded by platform backend plans");
}

fn status() -> i32 {
    let path = runtime_state_path();
    match RuntimeState::load(&path) {
        Ok(state) => {
            println!("state: recorded");
            println!("session: {}", state.session_id);
            println!("platform: {}", state.platform);
            match state.engine {
                Some(engine) => {
                    println!("engine pid: {}", engine.pid);
                    println!("engine: {}", engine.executable.display());
                }
                None => println!("engine: none"),
            }
            if let Some(interface) = state.network.utun_interface {
                println!("utun: {interface}");
            }
            if let Some(anchor) = state.network.pf_anchor {
                println!("pf anchor: {anchor}");
            }
            if let Some(table) = state.network.nft_table {
                println!("nft table: {table}");
            }
            if let Some(service) = state.network.windows_service {
                println!("windows service: {service}");
            }
            0
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("state: stopped");
            println!("runtime journal: {}", path.display());
            0
        }
        Err(error) => {
            eprintln!("runtime state is unreadable: {error}");
            2
        }
    }
}

fn backend_inspect(platform: &str) -> i32 {
    match platform {
        "macos" => inspect_backend(AppService::new(MacOsBackend::system())),
        "windows" => inspect_backend(AppService::new(WindowsBackend::system())),
        "linux" => inspect_backend(AppService::new(LinuxBackend::system())),
        _ => {
            eprintln!("unknown platform: {platform}");
            2
        }
    }
}

fn inspect_backend<B>(service: AppService<B>) -> i32
where
    B: PlatformBackend,
    B::Error: Display,
{
    match service.status() {
        Ok(status) => {
            print_backend_status(&status);
            if status.state == BackendState::Unsupported {
                4
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!("backend inspection failed: {error}");
            2
        }
    }
}

fn backend_plan(platform: &str, action: &str) -> i32 {
    let action = match parse_backend_action(action) {
        Some(action) => action,
        None => {
            eprintln!("unknown backend action: {action}");
            return 2;
        }
    };

    match platform {
        "macos" => plan_backend(AppService::new(MacOsBackend::system()), action),
        "windows" => plan_backend(AppService::new(WindowsBackend::system()), action),
        "linux" => plan_backend(AppService::new(LinuxBackend::system()), action),
        _ => {
            eprintln!("unknown platform: {platform}");
            2
        }
    }
}

fn plan_backend<B>(service: AppService<B>, action: BackendAction) -> i32
where
    B: PlatformBackend,
    B::Error: Display,
{
    match service.plan(action) {
        Ok(plan) => {
            print_action_plan(&plan);
            0
        }
        Err(error) => {
            eprintln!("cannot build backend plan: {error}");
            4
        }
    }
}

fn macos_cleanup_apply() -> i32 {
    let service = AppService::new(MacOsBackend::system());
    match service.execute(BackendAction::Cleanup) {
        Ok(result) => {
            println!("action: {:?}", result.action);
            println!("changed: {}", result.changed);
            println!("{}", result.message);
            0
        }
        Err(error) => {
            eprintln!("cleanup failed: {error}");
            eprintln!("hint: this operation requires sufficient privileges to run pfctl");
            5
        }
    }
}

fn parse_backend_action(action: &str) -> Option<BackendAction> {
    match action {
        "start" => Some(BackendAction::Start),
        "stop" => Some(BackendAction::Stop),
        "cleanup" => Some(BackendAction::Cleanup),
        _ => None,
    }
}

fn print_backend_status(status: &BackendStatus) {
    println!("platform: {}", status.platform);
    println!("available: {}", status.available);
    println!("state: {:?}", status.state);

    for item in &status.diagnostics {
        let level = match item.level {
            DiagnosticLevel::Ok => "ok",
            DiagnosticLevel::Info => "info",
            DiagnosticLevel::Warning => "warn",
            DiagnosticLevel::Error => "error",
        };
        println!("[{level}] {}: {}", item.label, item.value);
        if let Some(detail) = &item.detail {
            println!("       {detail}");
        }
    }
}

fn print_action_plan(plan: &ActionPlan) {
    println!("plan: {}", plan.id);
    println!("title: {}", plan.title);
    println!("requires admin: {}", plan.requires_admin);
    println!("mutates network: {}", plan.mutates_network);
    println!("executable now: {}", plan.executable_now);

    for (index, step) in plan.steps.iter().enumerate() {
        println!("{}. {}", index + 1, step.description);
        if let Some(command) = &step.command_preview {
            println!("   command: {command}");
        }
    }
}

fn strategy_validate(path: &Path) -> i32 {
    match StrategyManifest::load(path) {
        Ok(strategy) => {
            println!("strategy: OK");
            println!("name: {}", strategy.name);
            println!("rules: {}", strategy.rules.len());
            0
        }
        Err(error) => {
            eprintln!("strategy: INVALID");
            eprintln!("reason: {error}");
            2
        }
    }
}

fn config_validate(path: &Path) -> i32 {
    match AppConfig::load(path) {
        Ok(config) => {
            let resolved = config.resolve_engine_paths(path);
            println!("config: OK");
            println!("path: {}", path.display());
            println!("strategy: {}", config.strategy.name);
            println!("engine manifest: {}", resolved.manifest.display());
            println!("engine binary: {}", resolved.binary.display());
            0
        }
        Err(error) => {
            eprintln!("config: INVALID");
            eprintln!("reason: {error}");
            2
        }
    }
}

fn config_verify(path: &Path) -> i32 {
    let config = match AppConfig::load(path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("config: INVALID");
            eprintln!("reason: {error}");
            return 2;
        }
    };

    let resolved = config.resolve_engine_paths(path);
    println!("config: OK");
    println!("strategy: {}", config.strategy.name);
    verify_paths(&resolved.manifest, &resolved.binary)
}

fn engine_verify(manifest_path: &Path, binary_path: &Path) -> i32 {
    verify_paths(manifest_path, binary_path)
}

fn verify_paths(manifest_path: &Path, binary_path: &Path) -> i32 {
    let manifest = match ArtifactManifest::load(manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("manifest: INVALID");
            eprintln!("reason: {error}");
            return 2;
        }
    };

    match verify_file(&manifest, binary_path) {
        Ok(report) => print_verification(&report),
        Err(error) => {
            eprintln!("artifact: ERROR");
            eprintln!("reason: {error}");
            2
        }
    }
}

fn print_verification(report: &VerificationReport) -> i32 {
    println!("engine: {} {}", report.name, report.version);
    println!("size: {} bytes", report.size_bytes);
    println!("expected platform: {}", report.expected_platform);
    println!("actual platform:   {}", report.actual_platform);
    println!("expected SHA-256: {}", report.expected_sha256);
    println!("actual SHA-256:   {}", report.actual_sha256);
    println!(
        "integrity: {}",
        if report.integrity_ok() {
            "OK"
        } else {
            "FAILED"
        }
    );
    println!(
        "platform: {}",
        if report.platform_ok() {
            "OK"
        } else {
            "MISMATCH"
        }
    );

    if report.trusted() {
        println!("trust: VERIFIED");
        0
    } else if !report.integrity_ok() {
        eprintln!("trust: REJECTED (checksum mismatch)");
        3
    } else {
        eprintln!("trust: REJECTED (artifact is for another platform)");
        4
    }
}

fn runtime_state_path() -> PathBuf {
    config_path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("runtime.json")
}

fn config_path() -> PathBuf {
    match Platform::detect() {
        Platform::Windows => env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::MacOS => env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library")
            .join("Application Support")
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::Linux => env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::Unsupported => PathBuf::from("config.toml"),
    }
}

fn help() {
    println!(
        "whitelist-hide {}\n\nUSAGE:\n    whitelist-hide <COMMAND>\n\nCOMMANDS:\n    doctor\n    status\n    config-path\n    config validate [PATH]\n    config verify [PATH]\n    strategy validate <PATH>\n    engine verify <MANIFEST> <BINARY>\n    backend <macos|windows|linux> inspect\n    backend <macos|windows|linux> plan <start|stop|cleanup>\n    backend macos cleanup [--apply]\n    version\n    help",
        env!("CARGO_PKG_VERSION")
    );
}
