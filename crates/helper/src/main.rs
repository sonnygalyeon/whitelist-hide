use std::io::{self, BufRead};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use whitelist_hide_orchestrator::{SessionSpec, start_session, stop_session};

const SCHEMA: u32 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u32,
    action: Action,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Start {
        config_path: PathBuf,
        strategy_path: PathBuf,
        state_path: PathBuf,
    },
    Stop {
        state_path: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct Response {
    schema: u32,
    ok: bool,
    message: String,
    engine_pid: Option<u32>,
}

fn main() {
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);

    let response = match read {
        Ok(0) => error_response("empty request"),
        Ok(_) => handle(&line),
        Err(error) => error_response(&format!("failed to read request: {error}")),
    };

    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(_) => println!(r#"{"schema":1,"ok":false,"message":"serialization failed","engine_pid":null}"#),
    }

    if !response.ok {
        std::process::exit(2);
    }
}

fn handle(line: &str) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        Err(error) => return error_response(&format!("invalid request: {error}")),
    };

    if request.schema != SCHEMA {
        return error_response("unsupported request schema");
    }

    match request.action {
        Action::Start {
            config_path,
            strategy_path,
            state_path,
        } => {
            if let Err(message) = validate_path(&config_path)
                .and_then(|_| validate_path(&strategy_path))
                .and_then(|_| validate_path(&state_path))
            {
                return error_response(&message);
            }

            let spec = SessionSpec {
                config_path,
                strategy_path,
                state_path,
            };

            match start_session(&spec) {
                Ok(report) => Response {
                    schema: SCHEMA,
                    ok: true,
                    message: format!(
                        "running {} strategy {}",
                        report.platform, report.strategy_id
                    ),
                    engine_pid: Some(report.engine_pid),
                },
                Err(error) => error_response(&error.to_string()),
            }
        }
        Action::Stop { state_path } => {
            if let Err(message) = validate_path(&state_path) {
                return error_response(&message);
            }

            match stop_session(&state_path) {
                Ok(changed) => Response {
                    schema: SCHEMA,
                    ok: true,
                    message: if changed {
                        "session stopped".to_owned()
                    } else {
                        "session was not running".to_owned()
                    },
                    engine_pid: None,
                },
                Err(error) => error_response(&error.to_string()),
            }
        }
    }
}

fn validate_path(path: &std::path::Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("helper accepts only absolute paths: {}", path.display()));
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("parent traversal is forbidden: {}", path.display()));
    }

    Ok(())
}

fn error_response(message: &str) -> Response {
    Response {
        schema: SCHEMA,
        ok: false,
        message: message.to_owned(),
        engine_pid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_json_fields() {
        let request = r#"{"schema":1,"action":{"type":"stop","state_path":"/tmp/state","command":"rm"}}"#;
        assert!(!handle(request).ok);
    }

    #[test]
    fn rejects_relative_paths() {
        let request =
            r#"{"schema":1,"action":{"type":"stop","state_path":"relative/state.json"}}"#;
        assert!(!handle(request).ok);
    }
}
