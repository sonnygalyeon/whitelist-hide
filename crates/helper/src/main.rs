use whitelist_hide_controller::{start, status, stop, system_config_path};

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
            Err(error) => {
                eprintln!("start failed: {error}");
                5
            }
        },
        [command] if command == "stop" => match stop() {
            Ok(changed) => {
                println!("stopped changed={changed}");
                0
            }
            Err(error) => {
                eprintln!("stop failed: {error}");
                5
            }
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
            Err(error) => {
                eprintln!("status failed: {error}");
                5
            }
        },
        _ => {
            eprintln!("usage: whitelist-hide-helper <start|stop|status>");
            2
        }
    };

    std::process::exit(code);
}
