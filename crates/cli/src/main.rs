use std::env;
use std::path::{Path, PathBuf};

use whitelist_hide_core::artifact::{ArtifactManifest, VerificationReport, verify_file};
use whitelist_hide_core::config::AppConfig;
use whitelist_hide_core::{DoctorReport, Platform};

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
        [command] if command == "status" => {
            status();
            0
        }
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
        [group, action, manifest, binary] if group == "engine" && action == "verify" => {
            engine_verify(Path::new(manifest), Path::new(binary))
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
    println!("network changes: disabled (safe bootstrap stage)");

    match report.platform {
        Platform::Windows => {
            println!("next backend milestone: driver provenance + WinDivert adapter")
        }
        Platform::MacOS => println!("next backend milestone: reversible pf anchor + utun adapter"),
        Platform::Linux => println!("next backend milestone: reversible nftables/NFQUEUE adapter"),
        Platform::Unsupported => println!("backend: unsupported platform"),
    }
}

fn status() {
    println!("state: stopped");
    println!("engine: not configured");
    println!("system modifications: none");
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
        "whitelist-hide {}\n\nUSAGE:\n    whitelist-hide <COMMAND>\n\nCOMMANDS:\n    doctor\n        Read-only platform diagnostics\n\n    status\n        Show current engine state\n\n    config-path\n        Show the default configuration path\n\n    config validate [PATH]\n        Validate a TOML configuration without touching the network\n\n    config verify [PATH]\n        Validate configuration and verify its engine artifact\n\n    engine verify <MANIFEST> <BINARY>\n        Verify an artifact SHA-256 and platform against its manifest\n\n    version\n        Show version\n\n    help\n        Show this help",
        env!("CARGO_PKG_VERSION")
    );
}
