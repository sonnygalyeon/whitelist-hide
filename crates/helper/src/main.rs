use std::path::Path;

use whitelist_hide_controller::{
    install_bundle, select_strategy, start, status, stop, system_config_path,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [command] if command == "start" => match start(&system_config_path()) {
            Ok(report) => {
                println!(
                    "started platform={} strategy={} pid={}",
                    report.platform, report.strategy, report.engine_pid
                );
                0
            }
            Err(error) => fail("start", &error.to_string()),
        },
        [command] if command == "stop" => match stop() {
            Ok(changed) => {
                println!("stopped changed={changed}");
                0
            }
            Err(error) => fail("stop", &error.to_string()),
        },
        [command] if command == "status" => match status() {
            Ok(state) => {
                println!(
                    "platform={} running={} healthy={} pid={} strategy={} detail={}",
                    state.platform,
                    state.running,
                    state.healthy,
                    state
                        .engine_pid
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_owned()),
                    state.strategy.as_deref().unwrap_or("none"),
                    state.detail
                );
                if state.healthy { 0 } else { 6 }
            }
            Err(error) => fail("status", &error.to_string()),
        },
        [command, bundle] if command == "install" => match install_bundle(Path::new(bundle)) {
            Ok(config) => {
                println!("installed config={}", config.display());
                0
            }
            Err(error) => fail("install", &error.to_string()),
        },
        [command, strategy] if command == "select" => match select_strategy(strategy) {
            Ok(()) => {
                println!("selected strategy={strategy}");
                0
            }
            Err(error) => fail("select", &error.to_string()),
        },
        _ => {
            eprintln!(
                "usage: whitelist-hide-helper <start|stop|status|install PATH|select ID>"
            );
            2
        }
    };

    std::process::exit(code);
}

fn fail(action: &str, detail: &str) -> i32 {
    eprintln!("{action} failed: {detail}");
    5
}
