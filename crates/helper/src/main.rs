use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_controller::{SessionController, default_state_path};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if requires_elevation(&args) && !is_elevated() {
        std::process::exit(reexec_elevated(&args));
    }

    let controller = SessionController::new(default_state_path());

    let code = match args.as_slice() {
        [command, config, strategy] if command == "start" => {
            match controller.start(Path::new(config), Path::new(strategy)) {
                Ok(report) => {
                    println!("running");
                    println!("pid={}", report.engine_pid);
                    match spawn_watchdog() {
                        Ok(pid) => {
                            println!("watchdog_pid={pid}");
                            0
                        }
                        Err(error) => {
                            eprintln!("failed to start watchdog: {error}");
                            let _ = controller.stop();
                            5
                        }
                    }
                }
                Err(error) => {
                    eprintln!("{error}");
                    5
                }
            }
        }
        [command] if command == "stop" => match controller.stop() {
            Ok(_) => {
                println!("stopped");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                5
            }
        },
        [command] if command == "watchdog" => watchdog(&controller),
        [command] if command == "health" => match controller.health() {
            Ok(report) => {
                println!("running={}", report.running);
                println!("engine_alive={}", report.engine_alive);
                println!("network_resource={}", report.owned_network_resource_present);
                if report.running { 0 } else { 6 }
            }
            Err(error) => {
                eprintln!("{error}");
                6
            }
        },
        _ => {
            eprintln!("usage: whitelist-hide-helper start <CONFIG> <STRATEGY> | stop | health");
            2
        }
    };

    std::process::exit(code);
}

fn requires_elevation(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("start" | "stop"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_elevated() -> bool {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .is_ok_and(|output| output.status.success() && output.stdout == b"0\n")
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
fn reexec_elevated(args: &[String]) -> i32 {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("cannot resolve helper path for elevation: {error}");
            return 7;
        }
    };

    match Command::new("pkexec").arg(executable).args(args).output() {
        Ok(output) => forward_elevated_output(output),
        Err(error) => {
            eprintln!("cannot start pkexec: {error}");
            eprintln!("Install a PolicyKit authentication agent and try again.");
            7
        }
    }
}

#[cfg(target_os = "macos")]
fn reexec_elevated(args: &[String]) -> i32 {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("cannot resolve helper path for elevation: {error}");
            return 7;
        }
    };

    let mut command = shell_quote(&executable.display().to_string());
    for arg in args {
        command.push(' ');
        command.push_str(&shell_quote(arg));
    }

    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges",
        escape_applescript_string(&command)
    );

    match Command::new("/usr/bin/osascript")
        .args(["-e", &apple_script])
        .output()
    {
        Ok(output) => forward_elevated_output(output),
        Err(error) => {
            eprintln!("cannot request macOS administrator authorization: {error}");
            7
        }
    }
}

#[cfg(target_os = "windows")]
fn reexec_elevated(args: &[String]) -> i32 {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("cannot resolve helper path for UAC: {error}");
            return 7;
        }
    };

    let quoted_args = args
        .iter()
        .map(|arg| format!("\"{}\"", arg.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");

    let script = concat!(
        "$p = Start-Process -FilePath $env:WHITELIST_HIDE_HELPER ",
        "-ArgumentList $env:WHITELIST_HIDE_ARGS -Verb RunAs -Wait -PassThru; ",
        "exit $p.ExitCode"
    );

    match Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("WHITELIST_HIDE_HELPER", executable)
        .env("WHITELIST_HIDE_ARGS", quoted_args)
        .output()
    {
        Ok(output) => forward_elevated_output(output),
        Err(error) => {
            eprintln!("cannot request Windows administrator authorization: {error}");
            7
        }
    }
}

fn forward_elevated_output(output: Output) -> i32 {
    let _ = io::stdout().write_all(&output.stdout);
    let _ = io::stderr().write_all(&output.stderr);
    output.status.code().unwrap_or(7)
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(target_os = "macos")]
fn escape_applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn spawn_watchdog() -> Result<u32, std::io::Error> {
    let executable = env::current_exe()?;
    let child = Command::new(executable)
        .arg("watchdog")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child.id())
}

fn watchdog(controller: &SessionController) -> i32 {
    loop {
        match controller.health() {
            Ok(report) if report.running => thread::sleep(Duration::from_secs(2)),
            Ok(report) if !report.engine_alive && !report.owned_network_resource_present => {
                return 0;
            }
            Ok(_) => {
                let _ = controller.stop();
                return 6;
            }
            Err(_) => {
                let _ = controller.stop();
                return 6;
            }
        }
    }
}
