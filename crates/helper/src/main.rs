use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_controller::{SessionController, default_state_path};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
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
            Ok(_) => 0,
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
                println!(
                    "network_resource={}",
                    report.owned_network_resource_present
                );
                if report.running { 0 } else { 6 }
            }
            Err(error) => {
                eprintln!("{error}");
                6
            }
        },
        _ => {
            eprintln!(
                "usage: whitelist-hide-helper start <CONFIG> <STRATEGY> | stop | health"
            );
            2
        }
    };

    std::process::exit(code);
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
            Ok(report) if !report.engine_alive && !report.owned_network_resource_present => return 0,
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
