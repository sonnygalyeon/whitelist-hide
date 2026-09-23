use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use whitelist_hide_controller::SessionController;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn publish(controller: &SessionController) -> Result<(), Box<dyn std::error::Error>> {
    let report = controller.health()?;
    let text = format!(
        "timestamp={}\nsession_present={}\nrunning={}\nengine_alive={}\nnetwork_resource={}\n",
        now(),
        controller.state_path().exists(),
        report.running,
        report.engine_alive,
        report.owned_network_resource_present,
    );
    let path = controller.state_path().with_extension("health");
    let tmp = path.with_extension("health.new");
    fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn read(state: &Path) -> io::Result<String> {
    if !state.exists() {
        return Ok(
            "session_present=false\nrunning=false\nengine_alive=false\nnetwork_resource=false\n"
                .to_owned(),
        );
    }
    let text = match fs::read_to_string(state.with_extension("health")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    Ok(validate_snapshot(&text, now()))
}

fn validate_snapshot(text: &str, time: u64) -> String {
    let timestamp = text
        .lines()
        .find_map(|line| line.strip_prefix("timestamp="))
        .and_then(|s| s.parse::<u64>().ok());
    if timestamp.is_some_and(|t| t <= time && time - t <= 15) {
        text.to_owned()
    } else {
        "session_present=true\nrunning=false\nengine_alive=false\nnetwork_resource=false\nstale=true\n".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_or_future_heartbeat_cannot_report_running() {
        for timestamp in [1, 101] {
            let text = format!("timestamp={timestamp}\nrunning=true\n");
            assert!(validate_snapshot(&text, 100).contains("running=false"));
        }
    }
    #[test]
    fn fresh_heartbeat_preserves_report() {
        let text = "timestamp=90\nrunning=true\n";
        assert_eq!(validate_snapshot(text, 100), text);
    }
}
