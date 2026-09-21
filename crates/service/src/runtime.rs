use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use whitelist_hide_core::Platform;

const RUNTIME_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeState {
    pub schema: u32,
    pub session_id: String,
    pub platform: String,
    pub started_at_unix: u64,
    pub engine: Option<OwnedEngine>,
    pub network: NetworkOwnership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedEngine {
    pub pid: u32,
    pub executable: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkOwnership {
    pub pf_anchor: Option<String>,
    pub utun_interface: Option<String>,
    pub nft_table: Option<String>,
    pub windows_service: Option<String>,
}

impl RuntimeState {
    pub fn new(platform: Platform) -> io::Result<Self> {
        let started_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();

        Ok(Self {
            schema: RUNTIME_SCHEMA,
            session_id: format!("{}-{started_at_unix}-{}", platform, std::process::id()),
            platform: platform.to_string(),
            started_at_unix,
            engine: None,
            network: NetworkOwnership::default(),
        })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if self.schema != RUNTIME_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported runtime schema",
            ));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let temporary = path.with_extension("tmp");
        let content = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(&temporary, content)?;
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(temporary, path)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let content = fs::read(path)?;
        let state: Self = serde_json::from_slice(&content).map_err(io::Error::other)?;
        if state.schema != RUNTIME_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported runtime schema",
            ));
        }
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_state_round_trips() {
        let mut state = RuntimeState::new(Platform::Linux).expect("state should build");
        state.network.nft_table = Some("whitelist_hide".to_owned());
        let path = std::env::temp_dir().join(format!(
            "whitelist-hide-runtime-test-{}.json",
            std::process::id()
        ));
        state.save(&path).expect("state should save");
        let loaded = RuntimeState::load(&path).expect("state should load");
        let _ = fs::remove_file(path);
        assert_eq!(state, loaded);
    }
}
