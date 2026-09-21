use std::env;
use std::path::Path;

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
                    0
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
