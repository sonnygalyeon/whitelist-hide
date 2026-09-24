mod health;
#[cfg(windows)]
mod windows_stdio;

use fs2::FileExt;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_controller::{SessionController, default_state_path};

fn main() {
    #[cfg(windows)]
    if let Err(error) = windows_stdio::prevent_inheritance() {
        eprintln!("cannot isolate helper output handles: {error}");
        std::process::exit(5);
    }

    let args: Vec<String> = env::args().skip(1).collect();

    if requires_elevation(&args) && !is_elevated() {
        std::process::exit(reexec_elevated(&args));
    }

    let controller = SessionController::new(default_state_path());

    if args.as_slice() == ["health"] {
        match health::read(controller.state_path()) {
            Ok(text) => print!("{text}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(5);
            }
        }
        return;
    }
    if args.as_slice() == ["logs"] {
        match fs::read_to_string(controller.state_path().with_extension("log")) {
            Ok(text) => print!(
                "{}",
                text.lines()
                    .rev()
                    .take(150)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(5);
            }
        }
        return;
    }
    if let [command, session] = args.as_slice() {
        if command == "watchdog" && is_elevated() {
            std::process::exit(watchdog(&controller, session));
        }
    }
    let _lock = match operation_lock(controller.state_path()) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("cannot lock runtime: {error}");
            std::process::exit(5);
        }
    };
    let code = match args.as_slice() {
        [command, config, strategy] if command == "start" => {
            match controller.start(Path::new(config), Path::new(strategy)) {
                Ok(report) => {
                    println!("running");
                    println!("pid={}", report.engine_pid);
                    match spawn_watchdog(&controller) {
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
                let _ = fs::remove_file(controller.state_path().with_extension("health"));
                println!("stopped");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                5
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
    const SCRIPT: &str = concat!(
        "$principal = New-Object Security.Principal.WindowsPrincipal(",
        "[Security.Principal.WindowsIdentity]::GetCurrent()); ",
        "if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) ",
        "{ exit 0 } else { exit 1 }"
    );

    Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
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

fn spawn_watchdog(controller: &SessionController) -> Result<u32, std::io::Error> {
    health::publish(controller).map_err(|e| io::Error::other(e.to_string()))?;
    let session = controller
        .session_id()
        .map_err(|e| io::Error::other(e.to_string()))?
        .ok_or_else(|| io::Error::other("missing session"))?;
    let executable = env::current_exe()?;
    let child = Command::new(executable)
        .arg("watchdog")
        .arg(session)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child.id())
}

fn operation_lock(state: &Path) -> io::Result<File> {
    let parent = state
        .parent()
        .ok_or_else(|| io::Error::other("invalid state path"))?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.with_extension("lock"))?;
    file.lock_exclusive()?;
    Ok(file)
}

fn watchdog(controller: &SessionController, session: &str) -> i32 {
    loop {
        {
            let Ok(_lock) = operation_lock(controller.state_path()) else {
                return 5;
            };
            // A watchdog from a previous session must never stop a new session.
            if controller.session_id().ok().flatten().as_deref() != Some(session) {
                return 0;
            }
            match controller.health() {
                Ok(report) if report.running => {
                    if health::publish(controller).is_err() {
                        let _ = controller.stop();
                        return 5;
                    }
                }
                _ => {
                    let _ = controller.stop();
                    let _ = fs::remove_file(controller.state_path().with_extension("health"));
                    return 6;
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}
