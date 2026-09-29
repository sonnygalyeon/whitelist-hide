use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SelectionCache {
    entries: Vec<Entry>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    network: String,
    catalog: String,
    strategy: String,
    checked_at: u64,
}

impl SelectionCache {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .filter(|b| b.len() <= 16_384)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    pub fn get(&self, network: &str, catalog: &str, now: u64) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| {
                e.network == network
                    && e.catalog == catalog
                    && now >= e.checked_at
                    && now - e.checked_at < 7 * 24 * 3600
            })
            .map(|e| e.strategy.as_str())
    }
    pub fn invalidate(&mut self, network: &str) {
        self.entries.retain(|e| e.network != network);
    }
    pub fn record(&mut self, network: &str, catalog: &str, strategy: &str, now: u64) {
        self.invalidate(network);
        self.entries.insert(
            0,
            Entry {
                network: network.into(),
                catalog: catalog.into(),
                strategy: strategy.into(),
                checked_at: now,
            },
        );
        self.entries.truncate(8);
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        write_json(path, self)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&temp, path).map_err(|e| e.to_string())
}

/// No ISP lookup or external telemetry. Only a hash of the local address and
/// default route is persisted. If discovery fails, reuse is disabled.
pub fn network_key() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // UDP connect selects a route without sending a packet (TEST-NET address).
    socket.connect("192.0.2.1:9").ok()?;
    let local = socket.local_addr().ok()?.ip();
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut c = Command::new("ip");
        c.args(["-4", "route", "show", "default"]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = Command::new("/sbin/route");
        c.args(["-n", "get", "default"]);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("powershell.exe");
        c.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object InterfaceIndex,NextHop | Select-Object InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json -Compress"]);
        c
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return None;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        let output = child.wait_with_output().ok()?;
        if !output.status.success() || output.stdout.is_empty() {
            return None;
        }
        let mut digest = Sha256::new();
        digest.update(std::env::consts::OS);
        digest.update(local.to_string());
        digest.update(output.stdout);
        Some(format!("{:x}", digest.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_requires_same_network_catalog_and_recent_success() {
        let mut cache = SelectionCache::default();
        cache.record("network1", "catalog1", "split", 1000);
        assert_eq!(cache.get("network1", "catalog1", 1001), Some("split"));
        for (network, catalog, now) in [
            ("network2", "catalog1", 1001),
            ("network1", "catalog2", 1001),
            ("network1", "catalog1", 999),
            ("network1", "catalog1", 700000),
        ] {
            assert_eq!(cache.get(network, catalog, now), None);
        }
        cache.invalidate("network1");
        assert_eq!(cache.get("network1", "catalog1", 1001), None);
    }
}
