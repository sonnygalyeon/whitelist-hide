use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RUNTIME_STATE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePhase {
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeState {
    pub schema: u32,
    pub session_id: String,
    pub platform: String,
    pub phase: RuntimePhase,
    pub controller_pid: u32,
    pub engine_pid: Option<u32>,
    #[serde(default)]
    pub engine_binary: Option<PathBuf>,
    pub owned_interface: Option<String>,
    #[serde(default)]
    pub utun_unit: Option<u32>,
    pub owned_firewall_scope: Option<String>,
    #[serde(default)]
    pub pf_enable_token: Option<String>,
    pub previous_tcp_keepinit: Option<u32>,
}

impl RuntimeState {
    pub fn new(session_id: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            schema: RUNTIME_STATE_SCHEMA,
            session_id: session_id.into(),
            platform: platform.into(),
            phase: RuntimePhase::Starting,
            controller_pid: std::process::id(),
            engine_pid: None,
            engine_binary: None,
            owned_interface: None,
            utun_unit: None,
            owned_firewall_scope: None,
            pf_enable_token: None,
            previous_tcp_keepinit: None,
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeStateError> {
        if self.schema != RUNTIME_STATE_SCHEMA {
            return Err(RuntimeStateError::InvalidState(format!(
                "unsupported runtime state schema {}; expected {RUNTIME_STATE_SCHEMA}",
                self.schema
            )));
        }

        if !safe_token(&self.session_id) {
            return Err(RuntimeStateError::InvalidState(
                "session_id contains unsupported characters".to_owned(),
            ));
        }

        if !safe_token(&self.platform) {
            return Err(RuntimeStateError::InvalidState(
                "platform contains unsupported characters".to_owned(),
            ));
        }

        if let Some(interface) = &self.owned_interface {
            if !safe_token(interface) {
                return Err(RuntimeStateError::InvalidState(
                    "owned_interface contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(scope) = &self.owned_firewall_scope {
            if !safe_firewall_scope(scope) {
                return Err(RuntimeStateError::InvalidState(
                    "owned_firewall_scope contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(token) = &self.pf_enable_token {
            if !safe_token(token) {
                return Err(RuntimeStateError::InvalidState(
                    "pf_enable_token contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(unit) = self.utun_unit {
            if !(1..=1024).contains(&unit) {
                return Err(RuntimeStateError::InvalidState(
                    "utun_unit must be within 1..=1024".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Option<RuntimeState>, RuntimeStateError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RuntimeStateError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        let state: RuntimeState =
            serde_json::from_slice(&bytes).map_err(RuntimeStateError::Parse)?;
        state.validate()?;
        Ok(Some(state))
    }

    pub fn save(&self, state: &RuntimeState) -> Result<(), RuntimeStateError> {
        state.validate()?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| RuntimeStateError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let bytes = serde_json::to_vec_pretty(state).map_err(RuntimeStateError::Serialize)?;
        let temp = temp_path(&self.path);

        fs::write(&temp, bytes).map_err(|source| RuntimeStateError::Io {
            path: temp.clone(),
            source,
        })?;

        #[cfg(windows)]
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|source| RuntimeStateError::Io {
                path: self.path.clone(),
                source,
            })?;
        }

        fs::rename(&temp, &self.path).map_err(|source| RuntimeStateError::Io {
            path: self.path.clone(),
            source,
        })
    }

    pub fn clear(&self) -> Result<(), RuntimeStateError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(RuntimeStateError::Io {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "runtime-state".into());
    name.push(format!(".{}.new", std::process::id()));
    path.with_file_name(name)
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn safe_firewall_scope(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[derive(Debug)]
pub enum RuntimeStateError {
    Io { path: PathBuf, source: io::Error },
    Parse(serde_json::Error),
    Serialize(serde_json::Error),
    InvalidState(String),
}

impl fmt::Display for RuntimeStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    f,
                    "runtime state I/O failed at {}: {source}",
                    path.display()
                )
            }
            Self::Parse(source) => write!(f, "invalid runtime state JSON: {source}"),
            Self::Serialize(source) => write!(f, "cannot serialize runtime state: {source}"),
            Self::InvalidState(message) => write!(f, "invalid runtime state: {message}"),
        }
    }
}

impl Error for RuntimeStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) | Self::Serialize(source) => Some(source),
            Self::InvalidState(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

    fn test_store() -> StateStore {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "whitelist-hide-runtime-test-{}-{id}.json",
            std::process::id()
        ));
        StateStore::new(path)
    }

    #[test]
    fn state_round_trip() {
        let store = test_store();
        let mut state = RuntimeState::new("session-1", "macos");
        state.phase = RuntimePhase::Running;
        state.engine_pid = Some(4242);
        state.engine_binary = Some(PathBuf::from("/opt/whitelist-hide/utunws"));
        state.owned_interface = Some("utun200".to_owned());
        state.utun_unit = Some(201);
        state.owned_firewall_scope = Some("com.apple/whitelist-hide".to_owned());
        state.pf_enable_token = Some("abc123".to_owned());

        store.save(&state).expect("state should save");
        let loaded = store
            .load()
            .expect("state should load")
            .expect("state should exist");

        assert_eq!(loaded, state);
        store.clear().expect("cleanup should succeed");
    }

    #[test]
    fn rejects_unsafe_resource_names() {
        let mut state = RuntimeState::new("session-1", "macos");
        state.owned_interface = Some("utun0;rm".to_owned());
        assert!(state.validate().is_err());
    }

    #[test]
    fn accepts_scoped_pf_anchor() {
        let mut state = RuntimeState::new("session-1", "macos");
        state.owned_firewall_scope = Some("com.apple/whitelist-hide".to_owned());
        assert!(state.validate().is_ok());
    }
}
