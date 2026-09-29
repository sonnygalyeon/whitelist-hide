pub mod connection;

use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use whitelist_hide_core::Platform;
use whitelist_hide_core::artifact::{ArtifactManifest, verify_file};
use whitelist_hide_core::config::AppConfig;
use whitelist_hide_core::strategy::StrategyDefinition;
use whitelist_hide_core::strategy_compile::{EngineFlavor, compile_strategy};
use whitelist_hide_linux::{
    NFQUEUE_NUM, install_nfqueue_rules, owned_table_exists, remove_owned_table,
};
use whitelist_hide_macos::{
    PF_ANCHOR, UTUN_INTERFACE, clear_owned_pf_anchor, configure_owned_utun, enable_pf_if_needed,
    inspect_network_snapshot, install_pf_routes, owned_pf_anchor_has_rules, release_pf_token,
    wait_for_owned_utun,
};
use whitelist_hide_runtime::{
    EngineLaunchOptions, EngineRuntimeError, RuntimePhase, StateStore,
    launch_verified_engine_with_options, recorded_engine_alive, stop_recorded_engine,
};
use whitelist_hide_windows::windivert_service_running;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionReport {
    pub platform: Platform,
    pub strategy: String,
    pub engine_pid: u32,
    pub state_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthReport {
    pub running: bool,
    pub engine_alive: bool,
    pub owned_network_resource_present: bool,
}

#[must_use]
pub fn default_state_path() -> PathBuf {
    match Platform::detect() {
        Platform::Windows => std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("whitelist-hide")
            .join("runtime-state.json"),
        Platform::MacOS => PathBuf::from("/var/run/whitelist-hide/runtime-state.json"),
        Platform::Linux => PathBuf::from("/run/whitelist-hide/runtime-state.json"),
        Platform::Unsupported => PathBuf::from("runtime-state.json"),
    }
}

pub struct SessionController {
    state: StateStore,
}

impl SessionController {
    #[must_use]
    pub fn new(state_path: impl Into<PathBuf>) -> Self {
        Self {
            state: StateStore::new(state_path),
        }
    }

    #[must_use]
    pub fn state_path(&self) -> &Path {
        self.state.path()
    }

    pub fn session_id(&self) -> Result<Option<String>, ControllerError> {
        Ok(self.state.load()?.map(|state| state.session_id))
    }

    pub fn start(
        &self,
        config_path: &Path,
        strategy_path: &Path,
    ) -> Result<SessionReport, ControllerError> {
        if self.state.load()?.is_some() {
            return Err(ControllerError::ActiveState);
        }

        let config = AppConfig::load(config_path)
            .map_err(|error| ControllerError::Configuration(error.to_string()))?;
        let resolved = config.resolve_engine_paths(config_path);
        verify_binding(&resolved.manifest, &resolved.binary)?;

        for dependency in &resolved.dependencies {
            verify_binding(&dependency.manifest, &dependency.binary)?;
            ensure_same_bundle_directory(&resolved.binary, &dependency.binary)?;
        }

        let strategy = StrategyDefinition::load(strategy_path)
            .map_err(|error| ControllerError::Strategy(error.to_string()))?;
        if strategy.id != config.strategy.name {
            return Err(ControllerError::Strategy(format!(
                "config selects {}, but strategy file id is {}",
                config.strategy.name, strategy.id
            )));
        }

        let platform = Platform::detect();
        let flavor = match platform {
            Platform::Linux => EngineFlavor::Nfqws,
            Platform::MacOS => EngineFlavor::Utunws,
            Platform::Windows => EngineFlavor::Winws,
            Platform::Unsupported => return Err(ControllerError::UnsupportedPlatform),
        };
        let compiled = compile_strategy(&strategy, strategy_path, flavor)
            .map_err(|error| ControllerError::Strategy(error.to_string()))?;

        let session_id = format!(
            "session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        match platform {
            Platform::Linux => self.start_linux(
                &resolved.manifest,
                &resolved.binary,
                &strategy,
                compiled.args,
                &session_id,
            )?,
            Platform::MacOS => self.start_macos(
                &resolved.manifest,
                &resolved.binary,
                &strategy,
                compiled.args,
                &session_id,
            )?,
            Platform::Windows => self.start_windows(
                &resolved.manifest,
                &resolved.binary,
                compiled.args,
                &session_id,
            )?,
            Platform::Unsupported => unreachable!(),
        }

        let state = self
            .state
            .load()?
            .ok_or_else(|| ControllerError::Rollback("runtime state disappeared".to_owned()))?;
        let pid = state.engine_pid.ok_or_else(|| {
            ControllerError::Rollback("engine pid missing after start".to_owned())
        })?;

        let mut health = match self.health() {
            Ok(health) => health,
            Err(error) => {
                let _ = self.stop();
                return Err(error);
            }
        };
        for _ in 0..50 {
            if health.running || !health.engine_alive {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            health = match self.health() {
                Ok(health) => health,
                Err(error) => {
                    let _ = self.stop();
                    return Err(error);
                }
            };
        }
        if !health.running {
            let _ = self.stop();
            return Err(ControllerError::HealthCheck(
                "session failed its immediate health check and was rolled back".to_owned(),
            ));
        }

        Ok(SessionReport {
            platform,
            strategy: strategy.id,
            engine_pid: pid,
            state_path: self.state.path().to_path_buf(),
        })
    }

    pub fn stop(&self) -> Result<bool, ControllerError> {
        let Some(state) = self.state.load()? else {
            return Ok(false);
        };

        let platform = Platform::detect();
        if state.platform.split('-').next() != Some(platform.backend_name()) {
            return Err(ControllerError::StatePlatformMismatch {
                recorded: state.platform,
                actual: platform.backend_name().to_owned(),
            });
        }

        let engine_alive = recorded_engine_alive(&self.state)?;

        match platform {
            Platform::Linux => {
                let _ = remove_owned_table()?;
            }
            Platform::MacOS => {
                clear_owned_pf_anchor()?;
                if let Some(token) = state.owned_firewall_token.as_deref() {
                    release_pf_token(token)?;
                }
            }
            Platform::Windows => {}
            Platform::Unsupported => return Err(ControllerError::UnsupportedPlatform),
        }

        if engine_alive {
            stop_recorded_engine(&self.state)?;
        } else {
            self.state.clear()?;
        }

        if platform == Platform::MacOS {
            cleanup_macos_data_files(self.state.path(), &state.session_id)?;
        }

        Ok(true)
    }

    pub fn health(&self) -> Result<HealthReport, ControllerError> {
        let Some(state) = self.state.load()? else {
            return Ok(HealthReport {
                running: false,
                engine_alive: false,
                owned_network_resource_present: false,
            });
        };

        let engine_alive = recorded_engine_alive(&self.state)?;
        let network = match Platform::detect() {
            Platform::Linux => owned_table_exists()?,
            Platform::MacOS => {
                let utun = std::process::Command::new("/sbin/ifconfig")
                    .arg(UTUN_INTERFACE)
                    .output()
                    .is_ok_and(|output| output.status.success());
                utun && owned_pf_anchor_has_rules().unwrap_or(false)
            }
            Platform::Windows => windivert_service_running().unwrap_or(false),
            Platform::Unsupported => false,
        };

        Ok(HealthReport {
            running: state.phase == RuntimePhase::Running && engine_alive && network,
            engine_alive,
            owned_network_resource_present: network,
        })
    }

    fn start_linux(
        &self,
        manifest: &Path,
        binary: &Path,
        strategy: &StrategyDefinition,
        mut args: Vec<String>,
        session_id: &str,
    ) -> Result<(), ControllerError> {
        install_nfqueue_rules(
            &strategy.filters.tcp_ports,
            &strategy.filters.udp_ports,
            NFQUEUE_NUM,
        )?;

        args.insert(0, format!("--qnum={NFQUEUE_NUM}"));
        let options = EngineLaunchOptions {
            args,
            env: Vec::new(),
        };

        if let Err(error) =
            launch_verified_engine_with_options(manifest, binary, &options, &self.state, session_id)
        {
            let _ = remove_owned_table();
            return Err(error.into());
        }

        if let Err(error) = self.patch_owned_state(None, Some("inet.whitelist_hide"), None) {
            let _ = remove_owned_table();
            let _ = stop_recorded_engine(&self.state);
            return Err(error);
        }

        Ok(())
    }

    fn start_macos(
        &self,
        manifest: &Path,
        binary: &Path,
        strategy: &StrategyDefinition,
        args: Vec<String>,
        session_id: &str,
    ) -> Result<(), ControllerError> {
        if owned_pf_anchor_has_rules()?
            || std::process::Command::new("/sbin/ifconfig")
                .arg(UTUN_INTERFACE)
                .output()
                .is_ok_and(|o| o.status.success())
        {
            return Err(ControllerError::HealthCheck(
                "macOS project interface or anchor is already occupied".to_owned(),
            ));
        }
        let snapshot = inspect_network_snapshot()?;
        let (args, staged_data) = stage_macos_data_files(&args, self.state.path(), session_id)?;
        let options = EngineLaunchOptions {
            args,
            env: vec![
                ("ZAPRET_IFACE".to_owned(), snapshot.interface),
                ("ZAPRET_GATEWAY_MAC".to_owned(), snapshot.gateway_mac),
                ("ZAPRET_UTUN_UNIT".to_owned(), "51".to_owned()),
            ],
        };

        if let Err(error) =
            launch_verified_engine_with_options(manifest, binary, &options, &self.state, session_id)
        {
            let _ = fs::remove_dir_all(&staged_data);
            return Err(error.into());
        }

        let result = (|| -> Result<Option<String>, ControllerError> {
            wait_for_owned_utun(100)?;
            configure_owned_utun()?;
            let token = enable_pf_if_needed(snapshot.pf_was_enabled)?;
            if let Err(error) =
                install_pf_routes(&strategy.filters.tcp_ports, &strategy.filters.udp_ports)
            {
                if let Some(token) = token.as_deref() {
                    let _ = release_pf_token(token);
                }
                return Err(error.into());
            }
            Ok(token)
        })();

        match result {
            Ok(token) => {
                if let Err(error) =
                    self.patch_owned_state(Some(UTUN_INTERFACE), Some(PF_ANCHOR), token.as_deref())
                {
                    let _ = clear_owned_pf_anchor();
                    if let Some(token) = token.as_deref() {
                        let _ = release_pf_token(token);
                    }
                    let _ = stop_recorded_engine(&self.state);
                    let _ = fs::remove_dir_all(&staged_data);
                    return Err(error);
                }
                Ok(())
            }
            Err(error) => {
                let _ = clear_owned_pf_anchor();
                let _ = stop_recorded_engine(&self.state);
                let _ = fs::remove_dir_all(&staged_data);
                Err(error)
            }
        }
    }

    fn start_windows(
        &self,
        manifest: &Path,
        binary: &Path,
        args: Vec<String>,
        session_id: &str,
    ) -> Result<(), ControllerError> {
        let options = EngineLaunchOptions {
            args,
            env: Vec::new(),
        };
        launch_verified_engine_with_options(manifest, binary, &options, &self.state, session_id)?;
        if let Err(error) = self.patch_owned_state(None, Some("windivert.session"), None) {
            let _ = stop_recorded_engine(&self.state);
            return Err(error);
        }

        Ok(())
    }

    fn patch_owned_state(
        &self,
        interface: Option<&str>,
        firewall_scope: Option<&str>,
        token: Option<&str>,
    ) -> Result<(), ControllerError> {
        let mut state = self
            .state
            .load()?
            .ok_or_else(|| ControllerError::Rollback("runtime state missing".to_owned()))?;
        state.owned_interface = interface.map(str::to_owned);
        state.owned_firewall_scope = firewall_scope.map(str::to_owned);
        state.owned_firewall_token = token.map(str::to_owned);
        self.state.save(&state)?;
        Ok(())
    }
}

const MACOS_DATA_ARGUMENTS: [&str; 2] = ["--hostlist=", "--ipset="];

fn stage_macos_data_files(
    args: &[String],
    state_path: &Path,
    session_id: &str,
) -> Result<(Vec<String>, PathBuf), ControllerError> {
    let state_parent = state_path.parent().unwrap_or_else(|| Path::new("."));
    let data_parent = state_parent.join("session-data");
    create_public_directory(&data_parent)?;
    let session_data = data_parent.join(session_id);
    fs::create_dir(&session_data).map_err(|source| ControllerError::RuntimeData {
        path: session_data.clone(),
        source,
    })?;
    set_runtime_permissions(&session_data, 0o755)?;

    let mut staged_args = Vec::with_capacity(args.len());
    let mut index = 0usize;
    for arg in args {
        let Some((prefix, source)) = MACOS_DATA_ARGUMENTS
            .iter()
            .find_map(|prefix| arg.strip_prefix(prefix).map(|source| (*prefix, source)))
        else {
            staged_args.push(arg.clone());
            continue;
        };

        let kind = prefix.trim_start_matches("--").trim_end_matches('=');
        let target = session_data.join(format!("{kind}-{index}.txt"));
        if let Err(source_error) = fs::copy(source, &target) {
            let _ = fs::remove_dir_all(&session_data);
            return Err(ControllerError::RuntimeData {
                path: PathBuf::from(source),
                source: source_error,
            });
        }
        if let Err(error) = set_runtime_permissions(&target, 0o644) {
            let _ = fs::remove_dir_all(&session_data);
            return Err(error);
        }
        staged_args.push(format!("{prefix}{}", target.display()));
        index += 1;
    }

    Ok((staged_args, session_data))
}

fn cleanup_macos_data_files(state_path: &Path, session_id: &str) -> Result<(), ControllerError> {
    let state_parent = state_path.parent().unwrap_or_else(|| Path::new("."));
    let session_data = state_parent.join("session-data").join(session_id);
    match fs::remove_dir_all(&session_data) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ControllerError::RuntimeData {
            path: session_data,
            source,
        }),
    }
}

fn create_public_directory(path: &Path) -> Result<(), ControllerError> {
    fs::create_dir_all(path).map_err(|source| ControllerError::RuntimeData {
        path: path.to_path_buf(),
        source,
    })?;
    set_runtime_permissions(path, 0o755)
}

#[cfg(unix)]
fn set_runtime_permissions(path: &Path, mode: u32) -> Result<(), ControllerError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|source| {
        ControllerError::RuntimeData {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_runtime_permissions(_path: &Path, _mode: u32) -> Result<(), ControllerError> {
    Ok(())
}

fn verify_binding(manifest_path: &Path, binary_path: &Path) -> Result<(), ControllerError> {
    let manifest = ArtifactManifest::load(manifest_path)
        .map_err(|error| ControllerError::Artifact(error.to_string()))?;
    let report = verify_file(&manifest, binary_path)
        .map_err(|error| ControllerError::Artifact(error.to_string()))?;

    if report.trusted() {
        Ok(())
    } else {
        Err(ControllerError::Artifact(format!(
            "untrusted artifact {}: expected {} on {}, got {} on {}",
            binary_path.display(),
            report.expected_sha256,
            report.expected_platform,
            report.actual_sha256,
            report.actual_platform
        )))
    }
}

fn ensure_same_bundle_directory(primary: &Path, dependency: &Path) -> Result<(), ControllerError> {
    let primary_parent = primary.parent().unwrap_or_else(|| Path::new("."));
    let dependency_parent = dependency.parent().unwrap_or_else(|| Path::new("."));
    if primary_parent == dependency_parent {
        Ok(())
    } else {
        Err(ControllerError::Artifact(format!(
            "dependency {} must be installed beside engine {}",
            dependency.display(),
            primary.display()
        )))
    }
}

#[derive(Debug)]
pub enum ControllerError {
    ActiveState,
    UnsupportedPlatform,
    Configuration(String),
    Strategy(String),
    Artifact(String),
    Runtime(EngineRuntimeError),
    RuntimeState(whitelist_hide_runtime::RuntimeStateError),
    Linux(whitelist_hide_linux::LinuxError),
    MacOs(whitelist_hide_macos::MacOsError),
    StatePlatformMismatch { recorded: String, actual: String },
    HealthCheck(String),
    Rollback(String),
    RuntimeData { path: PathBuf, source: io::Error },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveState => {
                f.write_str("runtime state already exists; refusing a second start")
            }
            Self::UnsupportedPlatform => f.write_str("unsupported platform"),
            Self::Configuration(message) => write!(f, "configuration error: {message}"),
            Self::Strategy(message) => write!(f, "strategy error: {message}"),
            Self::Artifact(message) => write!(f, "artifact error: {message}"),
            Self::Runtime(error) => write!(f, "engine runtime error: {error}"),
            Self::RuntimeState(error) => write!(f, "runtime state error: {error}"),
            Self::Linux(error) => write!(f, "Linux backend error: {error}"),
            Self::MacOs(error) => write!(f, "macOS backend error: {error}"),
            Self::StatePlatformMismatch { recorded, actual } => {
                write!(
                    f,
                    "runtime state belongs to {recorded}, current platform is {actual}"
                )
            }
            Self::HealthCheck(message) => write!(f, "health check failed: {message}"),
            Self::Rollback(message) => write!(f, "rollback error: {message}"),
            Self::RuntimeData { path, source } => {
                write!(f, "runtime data error at {}: {source}", path.display())
            }
        }
    }
}

impl Error for ControllerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RuntimeData { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<EngineRuntimeError> for ControllerError {
    fn from(value: EngineRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<whitelist_hide_runtime::RuntimeStateError> for ControllerError {
    fn from(value: whitelist_hide_runtime::RuntimeStateError) -> Self {
        Self::RuntimeState(value)
    }
}

impl From<whitelist_hide_linux::LinuxError> for ControllerError {
    fn from(value: whitelist_hide_linux::LinuxError) -> Self {
        Self::Linux(value)
    }
}

impl From<whitelist_hide_macos::MacOsError> for ControllerError {
    fn from(value: whitelist_hide_macos::MacOsError) -> Self {
        Self::MacOs(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_macos_lists_for_unprivileged_engine_access() {
        let root = std::env::temp_dir().join(format!(
            "whitelist-hide-controller-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let private = root.join("private bundle");
        fs::create_dir_all(&private).unwrap();
        let source = private.join("general.txt");
        fs::write(&source, "youtube.com\ndiscord.com\n").unwrap();
        let state_path = root.join("run/runtime-state.json");
        let args = vec![
            "--dpi-desync=fake".to_owned(),
            format!("--hostlist={}", source.display()),
        ];

        let (staged, session_dir) =
            stage_macos_data_files(&args, &state_path, "session-test").unwrap();
        assert_eq!(staged[0], args[0]);
        let staged_path = PathBuf::from(staged[1].strip_prefix("--hostlist=").unwrap());
        assert_ne!(staged_path, source);
        assert_eq!(
            fs::read_to_string(&staged_path).unwrap(),
            "youtube.com\ndiscord.com\n"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&session_dir).unwrap().permissions().mode() & 0o777,
                0o755
            );
            assert_eq!(
                fs::metadata(&staged_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }

        cleanup_macos_data_files(&state_path, "session-test").unwrap();
        assert!(!session_dir.exists());
        let _ = fs::remove_dir_all(root);
    }
}
