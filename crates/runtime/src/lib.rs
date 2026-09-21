use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_core::artifact::{
    ArtifactError, ArtifactManifest, verify_companions, verify_file,
};

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
    #[serde(default)]
    pub strategy_id: Option<String>,
    pub owned_interface: Option<String>,
    pub owned_firewall_scope: Option<String>,
    #[serde(default)]
    pub pf_token: Option<String>,
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
            strategy_id: None,
            owned_interface: None,
            owned_firewall_scope: None,
            pf_token: None,
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

        if let Some(binary) = &self.engine_binary {
            if !binary.is_absolute() {
                return Err(RuntimeStateError::InvalidState(
                    "engine_binary must be an absolute path".to_owned(),
                ));
            }
        }

        if let Some(strategy_id) = &self.strategy_id {
            if !safe_token(strategy_id) {
                return Err(RuntimeStateError::InvalidState(
                    "strategy_id contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(token) = &self.pf_token {
            if !safe_token(token) {
                return Err(RuntimeStateError::InvalidState(
                    "pf_token contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(interface) = &self.owned_interface {
            if !safe_token(interface) {
                return Err(RuntimeStateError::InvalidState(
                    "owned_interface contains unsupported characters".to_owned(),
                ));
            }
        }

        if let Some(scope) = &self.owned_firewall_scope {
            if !safe_token(scope) {
                return Err(RuntimeStateError::InvalidState(
                    "owned_firewall_scope contains unsupported characters".to_owned(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLaunchReport {
    pub pid: u32,
    pub session_id: String,
    pub engine_name: String,
    pub engine_version: String,
    pub sha256: String,
    pub binary: PathBuf,
}

pub fn launch_verified_engine(
    manifest_path: &Path,
    binary_path: &Path,
    args: &[String],
    store: &StateStore,
    session_id: &str,
) -> Result<EngineLaunchReport, EngineRuntimeError> {
    launch_verified_engine_with_env(manifest_path, binary_path, args, &[], store, session_id)
}

pub fn launch_verified_engine_with_env(
    manifest_path: &Path,
    binary_path: &Path,
    args: &[String],
    env: &[(String, String)],
    store: &StateStore,
    session_id: &str,
) -> Result<EngineLaunchReport, EngineRuntimeError> {
    if let Some(existing) = store.load()? {
        if existing.engine_pid.is_some()
            && matches!(
                existing.phase,
                RuntimePhase::Starting | RuntimePhase::Running | RuntimePhase::Stopping
            )
        {
            return Err(EngineRuntimeError::ActiveSession(existing.session_id));
        }
    }

    let manifest = ArtifactManifest::load(manifest_path)?;
    let binary = binary_path
        .canonicalize()
        .map_err(|source| EngineRuntimeError::Io {
            path: binary_path.to_path_buf(),
            source,
        })?;

    let expected_name = manifest.artifact.filename.as_str();
    let actual_name = binary
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| EngineRuntimeError::InvalidBinaryPath(binary.clone()))?;

    if actual_name != expected_name {
        return Err(EngineRuntimeError::FilenameMismatch {
            expected: expected_name.to_owned(),
            actual: actual_name.to_owned(),
        });
    }

    let verification = verify_file(&manifest, &binary)?;
    if !verification.trusted() {
        return Err(EngineRuntimeError::UntrustedArtifact {
            expected_sha256: verification.expected_sha256,
            actual_sha256: verification.actual_sha256,
            expected_platform: verification.expected_platform,
            actual_platform: verification.actual_platform,
        });
    }

    let companion_reports = verify_companions(&manifest, &binary)?;
    if let Some(report) = companion_reports.iter().find(|report| !report.trusted()) {
        return Err(EngineRuntimeError::UntrustedCompanion {
            filename: report.name.clone(),
            expected_sha256: report.expected_sha256.clone(),
            actual_sha256: report.actual_sha256.clone(),
            expected_platform: report.expected_platform.clone(),
            actual_platform: report.actual_platform.clone(),
        });
    }

    let mut state = RuntimeState::new(session_id, verification.actual_platform.clone());
    state.engine_binary = Some(binary.clone());
    store.save(&state)?;

    let mut command = Command::new(&binary);
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }

    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(source) => {
            state.phase = RuntimePhase::Failed;
            let _ = store.save(&state);
            return Err(EngineRuntimeError::Io {
                path: binary.clone(),
                source,
            });
        }
    };

    thread::sleep(Duration::from_millis(150));
    if let Some(status) = child.try_wait().map_err(|source| EngineRuntimeError::Io {
        path: binary.clone(),
        source,
    })? {
        state.phase = RuntimePhase::Failed;
        let _ = store.save(&state);
        return Err(EngineRuntimeError::ExitedEarly(status.code()));
    }

    state.engine_pid = Some(child.id());
    state.phase = RuntimePhase::Running;

    if let Err(error) = store.save(&state) {
        let _ = child.kill();
        return Err(EngineRuntimeError::State(error));
    }

    Ok(EngineLaunchReport {
        pid: child.id(),
        session_id: state.session_id,
        engine_name: manifest.name,
        engine_version: manifest.version,
        sha256: verification.actual_sha256,
        binary,
    })
}

pub fn recorded_engine_alive(state: &RuntimeState) -> Result<bool, EngineRuntimeError> {
    let Some(pid) = state.engine_pid else {
        return Ok(false);
    };
    let Some(binary) = &state.engine_binary else {
        return Ok(false);
    };
    process_matches(pid, binary)
}

pub fn stop_recorded_engine(store: &StateStore) -> Result<bool, EngineRuntimeError> {
    let Some(mut state) = store.load()? else {
        return Ok(false);
    };

    let Some(pid) = state.engine_pid else {
        store.clear()?;
        return Ok(false);
    };

    let binary = state
        .engine_binary
        .clone()
        .ok_or(EngineRuntimeError::MissingEngineIdentity)?;

    if !process_matches(pid, &binary)? {
        return Err(EngineRuntimeError::ProcessIdentityMismatch { pid, binary });
    }

    state.phase = RuntimePhase::Stopping;
    store.save(&state)?;
    terminate_pid(pid)?;
    store.clear()?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn process_matches(pid: u32, expected: &Path) -> Result<bool, EngineRuntimeError> {
    let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
    match fs::read_link(&proc_exe) {
        Ok(actual) => {
            let actual = actual.canonicalize().unwrap_or(actual);
            let expected = expected
                .canonicalize()
                .unwrap_or_else(|_| expected.to_path_buf());
            Ok(actual == expected)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(EngineRuntimeError::Io {
            path: proc_exe,
            source,
        }),
    }
}

#[cfg(target_os = "macos")]
fn process_matches(pid: u32, expected: &Path) -> Result<bool, EngineRuntimeError> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .map_err(|source| EngineRuntimeError::Io {
            path: PathBuf::from("/bin/ps"),
            source,
        })?;

    if !output.status.success() {
        return Ok(false);
    }

    let actual = String::from_utf8_lossy(&output.stdout);
    let actual_name = Path::new(actual.trim()).file_name();
    Ok(actual_name == expected.file_name())
}

#[cfg(target_os = "windows")]
fn process_matches(pid: u32, expected: &Path) -> Result<bool, EngineRuntimeError> {
    let filter = format!("PID eq {pid}");
    let output = Command::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output()
        .map_err(|source| EngineRuntimeError::Io {
            path: PathBuf::from("tasklist"),
            source,
        })?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first = stdout.trim().split(',').next().unwrap_or_default();
    let image = first.trim().trim_matches('"');
    let expected_name = expected
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    Ok(image.eq_ignore_ascii_case(expected_name))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_matches(_pid: u32, _expected: &Path) -> Result<bool, EngineRuntimeError> {
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn terminate_pid(pid: u32) -> Result<(), EngineRuntimeError> {
    let output = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .output()
        .map_err(|source| EngineRuntimeError::Io {
            path: PathBuf::from("/bin/kill"),
            source,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(EngineRuntimeError::TerminateFailed {
            pid,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[cfg(target_os = "windows")]
fn terminate_pid(pid: u32) -> Result<(), EngineRuntimeError> {
    let output = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .output()
        .map_err(|source| EngineRuntimeError::Io {
            path: PathBuf::from("taskkill"),
            source,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(EngineRuntimeError::TerminateFailed {
            pid,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn terminate_pid(pid: u32) -> Result<(), EngineRuntimeError> {
    Err(EngineRuntimeError::TerminateFailed {
        pid,
        detail: "unsupported platform".to_owned(),
    })
}

#[derive(Debug)]
pub enum EngineRuntimeError {
    Artifact(ArtifactError),
    State(RuntimeStateError),
    Io {
        path: PathBuf,
        source: io::Error,
    },
    ActiveSession(String),
    InvalidBinaryPath(PathBuf),
    FilenameMismatch {
        expected: String,
        actual: String,
    },
    UntrustedArtifact {
        expected_sha256: String,
        actual_sha256: String,
        expected_platform: String,
        actual_platform: String,
    },
    UntrustedCompanion {
        filename: String,
        expected_sha256: String,
        actual_sha256: String,
        expected_platform: String,
        actual_platform: String,
    },
    ExitedEarly(Option<i32>),
    MissingEngineIdentity,
    ProcessIdentityMismatch {
        pid: u32,
        binary: PathBuf,
    },
    TerminateFailed {
        pid: u32,
        detail: String,
    },
}

impl fmt::Display for EngineRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => write!(f, "artifact verification failed: {error}"),
            Self::State(error) => write!(f, "runtime state failed: {error}"),
            Self::Io { path, source } => {
                write!(f, "engine I/O failed at {}: {source}", path.display())
            }
            Self::ActiveSession(session) => {
                write!(f, "another runtime session is already active: {session}")
            }
            Self::InvalidBinaryPath(path) => {
                write!(f, "engine path has no valid filename: {}", path.display())
            }
            Self::FilenameMismatch { expected, actual } => {
                write!(
                    f,
                    "engine filename mismatch: expected {expected}, got {actual}"
                )
            }
            Self::UntrustedArtifact {
                expected_sha256,
                actual_sha256,
                expected_platform,
                actual_platform,
            } => write!(
                f,
                "engine rejected: expected sha256={expected_sha256} platform={expected_platform}; actual sha256={actual_sha256} platform={actual_platform}"
            ),
            Self::UntrustedCompanion {
                filename,
                expected_sha256,
                actual_sha256,
                expected_platform,
                actual_platform,
            } => write!(
                f,
                "runtime companion {filename} rejected: expected sha256={expected_sha256} platform={expected_platform}; actual sha256={actual_sha256} platform={actual_platform}"
            ),
            Self::ExitedEarly(code) => {
                write!(
                    f,
                    "engine exited before runtime ownership was established: {code:?}"
                )
            }
            Self::MissingEngineIdentity => {
                f.write_str("runtime state has a PID but no recorded engine binary identity")
            }
            Self::ProcessIdentityMismatch { pid, binary } => write!(
                f,
                "refusing to terminate pid {pid}: it no longer matches {}",
                binary.display()
            ),
            Self::TerminateFailed { pid, detail } => {
                write!(f, "failed to terminate engine pid {pid}: {detail}")
            }
        }
    }
}

impl Error for EngineRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::State(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ArtifactError> for EngineRuntimeError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<RuntimeStateError> for EngineRuntimeError {
    fn from(value: RuntimeStateError) -> Self {
        Self::State(value)
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
        state.engine_binary = Some(
            std::env::current_exe()
                .expect("current executable")
                .canonicalize()
                .expect("canonical current executable"),
        );
        state.strategy_id = Some("general".to_owned());
        state.owned_interface = Some("utun51".to_owned());
        state.owned_firewall_scope = Some("com.whitelisthide".to_owned());

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
}
