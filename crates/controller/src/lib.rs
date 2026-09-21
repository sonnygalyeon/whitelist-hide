use std::error::Error;
use std::fmt;
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
            .unwrap_or_else(|| PathBuf::from("."))
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

        let session_id = format!("session-{}", std::process::id());
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

        let health = self.health()?;
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
            },
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

        self.patch_owned_state(None, Some("inet.whitelist_hide"), None)
    }

    fn start_macos(
        &self,
        manifest: &Path,
        binary: &Path,
        strategy: &StrategyDefinition,
        args: Vec<String>,
        session_id: &str,
    ) -> Result<(), ControllerError> {
        let snapshot = inspect_network_snapshot()?;
        let options = EngineLaunchOptions {
            args,
            env: vec![
                ("ZAPRET_IFACE".to_owned(), snapshot.interface),
                ("ZAPRET_GATEWAY_MAC".to_owned(), snapshot.gateway_mac),
                ("ZAPRET_UTUN_UNIT".to_owned(), "51".to_owned()),
            ],
        };

        launch_verified_engine_with_options(manifest, binary, &options, &self.state, session_id)?;

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
                self.patch_owned_state(Some(UTUN_INTERFACE), Some(PF_ANCHOR), token.as_deref())
            }
            Err(error) => {
                let _ = clear_owned_pf_anchor();
                let _ = stop_recorded_engine(&self.state);
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
        self.patch_owned_state(None, Some("windivert.session"), None)
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
        }
    }
}

impl Error for ControllerError {}

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
