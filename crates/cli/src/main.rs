use std::env;
use std::path::PathBuf;

use whitelist_hide_core::{DoctorReport, Platform};

fn main() {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());

    let exit_code = match command.as_str() {
        "doctor" => {
            doctor();
            0
        }
        "status" => {
            status();
            0
        }
        "config-path" => {
            println!("{}", config_path().display());
            0
        }
        "help" | "--help" | "-h" => {
            help();
            0
        }
        "version" | "--version" | "-V" => {
            println!("whitelist-hide {}", env!("CARGO_PKG_VERSION"));
            0
        }
        unknown => {
            eprintln!("unknown command: {unknown}\n");
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
        "whitelist-hide {}\n\nUSAGE:\n    whitelist-hide <COMMAND>\n\nCOMMANDS:\n    doctor       Read-only platform diagnostics\n    status       Show current engine state\n    config-path  Show the default configuration path\n    version      Show version\n    help         Show this help",
        env!("CARGO_PKG_VERSION")
    );
}
