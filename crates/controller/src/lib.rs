use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whitelist_hide_core::Platform;
use whitelist_hide_core::artifact::{
    ArtifactError, ArtifactManifest, verify_companions, verify_file,
};
use whitelist_hide_core::compiler::{
    CompiledStrategy, compile_strategy, target_for_current_platform,
};
use whitelist_hide_core::config::{
    AppConfig, EngineConfig, StrategyConfig,
};
use whitelist_hide_core::strategy::{PortRange, StrategyDefinition, StrategyError};
use whitelist_hide_runtime::{
    EngineRuntimeError, RuntimePhase, RuntimeState, RuntimeStateError, StateStore,
    launch_verified_engine, launch_verified_engine_with_env, recorded_engine_alive,
    stop_recorded_engine,
};

pub const NFQUEUE_NUM: u16 = 200;
pub const MACOS_UTUN_UNIT: u16 = 51;
pub const MACOS_UTUN_INTERFACE: &str = "utun50";
pub const MACOS_PF_ANCHOR: &str = "com.apple/whitelist-hide";
pub const LINUX_NFT_TABLE: &str = "whitelist_hide";
pub const DEFAULT_STRATEGY: &str = "general-simple-fake";

const MACOS_ENGINE_SHA256: &str =
    "bbf125e40feedbf5cbb5e7b93c62f5647f1da6d6ecb646206c661b7788b4344c";
const LINUX_ENGINE_SHA256: &str =
    "b83836cd66db3470d6d2a1c14ecea2576925e14ab873d2686318125d505ecb30";
const WINDOWS_ENGINE_SHA256: &str =
    "c80191fa814aafea7e6ef9b7d72e21603c0f7e668b5c066f78ef0f8eea7e083c";
const CYGWIN1_SHA256: &str =
    "d66788fce4ef1ce787fc1a83f2dd1e063e58bbf0d48ad93164ee195a983c035e";
const WINDIVERT_DLL_SHA256: &str =
    "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2";
const WINDIVERT_SYS_SHA256: &str =
    "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReport {
    pub platform: Platform,
    pub strategy: String,
    pub engine_pid: u32,
    pub runtime_state: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    pub platform: Platform,
    pub running: bool,
    pub healthy: bool,
    pub engine_pid: Option<u32>,
    pub strategy: Option<String>,
    pub detail: String,
}

struct PreparedSession {
    config: AppConfig,
    strategy: StrategyDefinition,
    compiled: CompiledStrategy,
    manifest: PathBuf,
    binary: PathBuf,
}

pub fn default_config_path() -> PathBuf {
    match Platform::detect() {
        Platform::Windows => std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::MacOS => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library")
            .join("Application Support")
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::Linux => std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|home| home.join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
            .join("whitelist-hide")
            .join("config.toml"),
        Platform::Unsupported => PathBuf::from("config.toml"),
    }
}

pub fn system_data_dir() -> PathBuf {
    match Platform::detect() {
        Platform::Windows => std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("whitelist-hide"),
        Platform::MacOS => PathBuf::from("/Library/Application Support/whitelist-hide"),
        Platform::Linux => PathBuf::from("/var/lib/whitelist-hide"),
        Platform::Unsupported => PathBuf::from("whitelist-hide"),
    }
}

pub fn system_config_path() -> PathBuf {
    system_data_dir().join("config.toml")
}

pub fn runtime_state_path() -> PathBuf {
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


pub fn install_bundle(bundle_dir: &Path) -> Result<PathBuf, ControllerError> {
    ensure_privileges()?;

    let store = StateStore::new(runtime_state_path());
    if let Some(state) = store.load()? {
        if recorded_engine_alive(&state)? {
            return Err(ControllerError::State(
                "stop the active session before installing runtime assets".to_owned(),
            ));
        }
    }

    let source = bundle_dir
        .canonicalize()
        .map_err(|source| ControllerError::Io {
            path: bundle_dir.to_path_buf(),
            source,
        })?;
    let manifest_path = source.join("engine.toml");
    let manifest = ArtifactManifest::load(&manifest_path)?;
    validate_trusted_manifest(&manifest)?;

    let binary = source.join("runtime").join(&manifest.artifact.filename);
    let primary = verify_file(&manifest, &binary)?;
    if !primary.trusted() {
        return Err(ControllerError::State(format!(
            "bundled engine failed trust verification: expected {}, got {}",
            primary.expected_sha256, primary.actual_sha256
        )));
    }
    for report in verify_companions(&manifest, &binary)? {
        if !report.trusted() {
            return Err(ControllerError::State(format!(
                "bundled companion {} failed trust verification",
                report.name
            )));
        }
    }

    let strategies = source.join("strategies");
    validate_strategy_bundle(&strategies)?;
    if !strategies.join(format!("{DEFAULT_STRATEGY}.toml")).is_file() {
        return Err(ControllerError::State(format!(
            "runtime bundle is missing default strategy {DEFAULT_STRATEGY}"
        )));
    }

    let target = system_data_dir();
    let parent = target.parent().ok_or_else(|| {
        ControllerError::State("system data directory has no parent".to_owned())
    })?;
    fs::create_dir_all(parent).map_err(|source| ControllerError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let stage = parent.join(format!(
        ".whitelist-hide-stage-{}",
        std::process::id()
    ));
    let backup = parent.join(format!(
        ".whitelist-hide-backup-{}",
        std::process::id()
    ));
    remove_dir_if_present(&stage)?;
    remove_dir_if_present(&backup)?;
    fs::create_dir_all(stage.join("runtime")).map_err(|source| ControllerError::Io {
        path: stage.clone(),
        source,
    })?;

    copy_regular_file(&manifest_path, &stage.join("engine.toml"), false)?;
    copy_regular_file(
        &binary,
        &stage.join("runtime").join(&manifest.artifact.filename),
        true,
    )?;
    for companion in &manifest.companions {
        copy_regular_file(
            &source.join("runtime").join(&companion.filename),
            &stage.join("runtime").join(&companion.filename),
            companion.filename.ends_with(".exe"),
        )?;
    }
    copy_tree_regular(&strategies, &stage.join("strategies"))?;

    let config = AppConfig {
        schema: 1,
        engine: EngineConfig {
            manifest: PathBuf::from("engine.toml"),
            binary: PathBuf::from("runtime").join(&manifest.artifact.filename),
        },
        strategy: StrategyConfig {
            name: DEFAULT_STRATEGY.to_owned(),
            directory: PathBuf::from("strategies"),
        },
    };
    config.save(&stage.join("config.toml"))?;

    if target.exists() {
        fs::rename(&target, &backup).map_err(|source| ControllerError::Io {
            path: target.clone(),
            source,
        })?;
    }

    if let Err(source) = fs::rename(&stage, &target) {
        if backup.exists() {
            let _ = fs::rename(&backup, &target);
        }
        return Err(ControllerError::Io {
            path: target.clone(),
            source,
        });
    }

    remove_dir_if_present(&backup)?;
    Ok(target.join("config.toml"))
}

pub fn available_strategies() -> Result<Vec<String>, ControllerError> {
    let directory = system_data_dir().join("strategies");
    let mut result = Vec::new();
    let entries = fs::read_dir(&directory).map_err(|source| ControllerError::Io {
        path: directory.clone(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| ControllerError::Io {
            path: directory.clone(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let strategy = StrategyDefinition::load(&path)?;
        result.push(strategy.id);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

pub fn select_strategy(id: &str) -> Result<(), ControllerError> {
    ensure_privileges()?;
    if !safe_identifier(id) {
        return Err(ControllerError::State(
            "strategy id contains unsupported characters".to_owned(),
        ));
    }

    let store = StateStore::new(runtime_state_path());
    if let Some(state) = store.load()? {
        if recorded_engine_alive(&state)? {
            return Err(ControllerError::State(
                "stop the active session before changing strategy".to_owned(),
            ));
        }
    }

    let path = system_data_dir()
        .join("strategies")
        .join(format!("{id}.toml"));
    let strategy = StrategyDefinition::load(&path)?;
    if strategy.id != id {
        return Err(ControllerError::State(
            "strategy filename and embedded id do not match".to_owned(),
        ));
    }
    let target =
        target_for_current_platform(NFQUEUE_NUM).ok_or(ControllerError::UnsupportedPlatform)?;
    compile_strategy(&strategy, &path, target)?;

    let config_path = system_config_path();
    let mut config = AppConfig::load(&config_path)?;
    config.strategy.name = id.to_owned();
    config.save(&config_path)?;
    Ok(())
}

fn validate_trusted_manifest(manifest: &ArtifactManifest) -> Result<(), ControllerError> {
    let expected = match Platform::detect() {
        Platform::MacOS => (
            "utunws",
            MACOS_ENGINE_SHA256,
            Vec::<(&str, &str)>::new(),
        ),
        Platform::Linux => (
            "nfqws",
            LINUX_ENGINE_SHA256,
            Vec::<(&str, &str)>::new(),
        ),
        Platform::Windows => (
            "winws.exe",
            WINDOWS_ENGINE_SHA256,
            vec![
                ("cygwin1.dll", CYGWIN1_SHA256),
                ("WinDivert.dll", WINDIVERT_DLL_SHA256),
                ("WinDivert64.sys", WINDIVERT_SYS_SHA256),
            ],
        ),
        Platform::Unsupported => return Err(ControllerError::UnsupportedPlatform),
    };

    if manifest.artifact.filename != expected.0
        || !manifest.artifact.sha256.eq_ignore_ascii_case(expected.1)
    {
        return Err(ControllerError::State(
            "runtime manifest does not match the engine pinned in this release".to_owned(),
        ));
    }

    if manifest.companions.len() != expected.2.len() {
        return Err(ControllerError::State(
            "runtime manifest companion set does not match this release".to_owned(),
        ));
    }

    for (filename, sha256) in expected.2 {
        let Some(spec) = manifest
            .companions
            .iter()
            .find(|spec| spec.filename.eq_ignore_ascii_case(filename))
        else {
            return Err(ControllerError::State(format!(
                "runtime manifest is missing trusted companion {filename}"
            )));
        };
        if !spec.sha256.eq_ignore_ascii_case(sha256) {
            return Err(ControllerError::State(format!(
                "runtime manifest hash mismatch for {filename}"
            )));
        }
    }

    Ok(())
}

fn validate_strategy_bundle(directory: &Path) -> Result<(), ControllerError> {
    let entries = fs::read_dir(directory).map_err(|source| ControllerError::Io {
        path: directory.to_path_buf(),
        source,
    })?;
    let target =
        target_for_current_platform(NFQUEUE_NUM).ok_or(ControllerError::UnsupportedPlatform)?;
    let mut count = 0_usize;

    for entry in entries {
        let entry = entry.map_err(|source| ControllerError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|source| ControllerError::Io {
            path: path.clone(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ControllerError::State(format!(
                "runtime bundle contains a symlink: {}",
                path.display()
            )));
        }
        if path.extension().and_then(|value| value.to_str()) != Some("toml") {
            continue;
        }
        let strategy = StrategyDefinition::load(&path)?;
        compile_strategy(&strategy, &path, target)?;
        count += 1;
    }

    if count == 0 {
        return Err(ControllerError::State(
            "runtime bundle contains no strategies".to_owned(),
        ));
    }
    Ok(())
}

fn copy_tree_regular(source: &Path, target: &Path) -> Result<(), ControllerError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| ControllerError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControllerError::State(format!(
            "expected a regular directory: {}",
            source.display()
        )));
    }
    fs::create_dir_all(target).map_err(|source_error| ControllerError::Io {
        path: target.to_path_buf(),
        source: source_error,
    })?;

    for entry in fs::read_dir(source).map_err(|source_error| ControllerError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })? {
        let entry = entry.map_err(|source_error| ControllerError::Io {
            path: source.to_path_buf(),
            source: source_error,
        })?;
        let from = entry.path();
        let to = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&from).map_err(|source_error| ControllerError::Io {
            path: from.clone(),
            source: source_error,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ControllerError::State(format!(
                "runtime bundle contains a symlink: {}",
                from.display()
            )));
        }
        if metadata.is_dir() {
            copy_tree_regular(&from, &to)?;
        } else if metadata.is_file() {
            copy_regular_file(&from, &to, false)?;
        } else {
            return Err(ControllerError::State(format!(
                "runtime bundle contains a non-regular entry: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

fn copy_regular_file(source: &Path, target: &Path, executable: bool) -> Result<(), ControllerError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| ControllerError::Io {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ControllerError::State(format!(
            "expected a regular file: {}",
            source.display()
        )));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|source_error| ControllerError::Io {
            path: parent.to_path_buf(),
            source: source_error,
        })?;
    }
    fs::copy(source, target).map_err(|source_error| ControllerError::Io {
        path: target.to_path_buf(),
        source: source_error,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(target, fs::Permissions::from_mode(mode)).map_err(
            |source_error| ControllerError::Io {
                path: target.to_path_buf(),
                source: source_error,
            },
        )?;
    }

    let _ = executable;
    Ok(())
}

fn remove_dir_if_present(path: &Path) -> Result<(), ControllerError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ControllerError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}


pub fn start(config_path: &Path) -> Result<SessionReport, ControllerError> {
    let prepared = prepare(config_path)?;
    let store = StateStore::new(runtime_state_path());
    ensure_privileges()?;

    let session_id = format!("session-{}", std::process::id());
    let launch = match Platform::detect() {
        Platform::Linux => start_linux(&prepared, &store, &session_id),
        Platform::Windows => start_windows(&prepared, &store, &session_id),
        Platform::MacOS => start_macos(&prepared, &store, &session_id),
        Platform::Unsupported => Err(ControllerError::UnsupportedPlatform),
    };

    let report = match launch {
        Ok(report) => report,
        Err(error) => {
            let state = store.load().ok().flatten();
            let _ = cleanup_network(state.as_ref());
            let _ = stop_if_owned(&store);
            return Err(error);
        }
    };

    if let Err(error) = spawn_watchdog() {
        let state = store.load().ok().flatten();
        let _ = cleanup_network(state.as_ref());
        let _ = stop_if_owned(&store);
        return Err(error);
    }

    Ok(report)
}

pub fn stop() -> Result<bool, ControllerError> {
    let store = StateStore::new(runtime_state_path());
    let Some(state) = store.load()? else {
        return Ok(false);
    };

    cleanup_network(Some(&state))?;

    if recorded_engine_alive(&state)? {
        stop_recorded_engine(&store)?;
    } else {
        store.clear()?;
    }

    Ok(true)
}

pub fn status() -> Result<SessionStatus, ControllerError> {
    let store = StateStore::new(runtime_state_path());
    let Some(state) = store.load()? else {
        return Ok(SessionStatus {
            platform: Platform::detect(),
            running: false,
            healthy: true,
            engine_pid: None,
            strategy: None,
            detail: "stopped".to_owned(),
        });
    };

    let alive = recorded_engine_alive(&state)?;
    let network_ok = network_health(&state).unwrap_or(false);
    let healthy = alive && network_ok;

    Ok(SessionStatus {
        platform: Platform::detect(),
        running: alive,
        healthy,
        engine_pid: state.engine_pid,
        strategy: state.strategy_id.clone(),
        detail: if healthy {
            "engine and owned packet path are healthy".to_owned()
        } else if !alive {
            "engine process is not alive".to_owned()
        } else {
            "engine is alive but owned packet path is unhealthy".to_owned()
        },
    })
}

pub fn watchdog_loop() -> Result<(), ControllerError> {
    let store = StateStore::new(runtime_state_path());

    loop {
        let Some(mut state) = store.load()? else {
            return Ok(());
        };

        if recorded_engine_alive(&state)? {
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        match cleanup_network(Some(&state)) {
            Ok(()) => {
                store.clear()?;
                return Ok(());
            }
            Err(_) => {
                state.phase = RuntimePhase::Failed;
                store.save(&state)?;
                thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn prepare(config_path: &Path) -> Result<PreparedSession, ControllerError> {
    let config = AppConfig::load(config_path)?;
    let strategy_path = config.resolve_strategy_path(config_path);
    let strategy = StrategyDefinition::load(&strategy_path)?;
    let target =
        target_for_current_platform(NFQUEUE_NUM).ok_or(ControllerError::UnsupportedPlatform)?;
    let compiled = compile_strategy(&strategy, &strategy_path, target)?;
    let engine = config.resolve_engine_paths(config_path);

    Ok(PreparedSession {
        config,
        strategy,
        compiled,
        manifest: engine.manifest,
        binary: engine.binary,
    })
}

fn start_linux(
    prepared: &PreparedSession,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, ControllerError> {
    let launch = launch_verified_engine(
        &prepared.manifest,
        &prepared.binary,
        &prepared.compiled.args,
        store,
        session_id,
    )?;

    apply_linux_nft(&prepared.strategy)?;

    let mut state = store.load()?.ok_or_else(|| {
        ControllerError::State("runtime journal disappeared after launch".to_owned())
    })?;
    state.owned_firewall_scope = Some(format!("inet:{LINUX_NFT_TABLE}"));
    state.strategy_id = Some(prepared.config.strategy.name.clone());
    store.save(&state)?;

    Ok(SessionReport {
        platform: Platform::Linux,
        strategy: prepared.config.strategy.name.clone(),
        engine_pid: launch.pid,
        runtime_state: store.path().to_path_buf(),
    })
}

fn start_windows(
    prepared: &PreparedSession,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, ControllerError> {
    verify_windows_companions(&prepared.binary)?;

    let launch = launch_verified_engine(
        &prepared.manifest,
        &prepared.binary,
        &prepared.compiled.args,
        store,
        session_id,
    )?;

    let mut state = store.load()?.ok_or_else(|| {
        ControllerError::State("runtime journal disappeared after launch".to_owned())
    })?;
    state.strategy_id = Some(prepared.config.strategy.name.clone());
    store.save(&state)?;

    Ok(SessionReport {
        platform: Platform::Windows,
        strategy: prepared.config.strategy.name.clone(),
        engine_pid: launch.pid,
        runtime_state: store.path().to_path_buf(),
    })
}

fn start_macos(
    prepared: &PreparedSession,
    store: &StateStore,
    session_id: &str,
) -> Result<SessionReport, ControllerError> {
    let route = command_text("/sbin/route", &["-n", "get", "default"])?;
    let interface = field_value(&route, "interface:")
        .ok_or_else(|| ControllerError::State("default route interface not found".to_owned()))?;
    let gateway = field_value(&route, "gateway:")
        .ok_or_else(|| ControllerError::State("default route gateway not found".to_owned()))?;

    let _ = Command::new("/sbin/ping")
        .args(["-c", "1", "-t", "1", &gateway])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let arp = command_text("/usr/sbin/arp", &["-n", &gateway])?;
    let gateway_mac = parse_arp_mac(&arp)
        .ok_or_else(|| ControllerError::State("default gateway MAC was not resolved".to_owned()))?;

    let env = vec![
        ("ZAPRET_IFACE".to_owned(), interface),
        ("ZAPRET_GATEWAY_MAC".to_owned(), gateway_mac),
        ("ZAPRET_GATEWAY6_MAC".to_owned(), String::new()),
        ("ZAPRET_UTUN_UNIT".to_owned(), MACOS_UTUN_UNIT.to_string()),
    ];

    let launch = launch_verified_engine_with_env(
        &prepared.manifest,
        &prepared.binary,
        &prepared.compiled.args,
        &env,
        store,
        session_id,
    )?;

    wait_for_macos_utun(store)?;

    command_ok(
        "/sbin/ifconfig",
        &[
            MACOS_UTUN_INTERFACE,
            "10.77.0.1",
            "10.77.0.2",
            "netmask",
            "255.255.255.255",
            "up",
        ],
    )?;

    let mut state = store.load()?.ok_or_else(|| {
        ControllerError::State("runtime journal disappeared after launch".to_owned())
    })?;
    state.owned_interface = Some(MACOS_UTUN_INTERFACE.to_owned());
    state.owned_firewall_scope = Some(MACOS_PF_ANCHOR.to_owned());
    state.strategy_id = Some(prepared.config.strategy.name.clone());

    let pf_info = command_text("/sbin/pfctl", &["-s", "info"])?;
    if pf_info
        .lines()
        .any(|line| line.trim().starts_with("Status: Disabled"))
    {
        let enabled = command_text_combined("/sbin/pfctl", &["-E"])?;
        state.pf_token = parse_pf_token(&enabled);
        if state.pf_token.is_none() {
            return Err(ControllerError::State(
                "pf was disabled and enabling it returned no ownership token".to_owned(),
            ));
        }
    }

    store.save(&state)?;

    let rules = macos_pf_rules(&prepared.strategy);
    run_with_input(
        "/sbin/pfctl",
        &["-a", MACOS_PF_ANCHOR, "-f", "-"],
        rules.as_bytes(),
    )?;

    Ok(SessionReport {
        platform: Platform::MacOS,
        strategy: prepared.config.strategy.name.clone(),
        engine_pid: launch.pid,
        runtime_state: store.path().to_path_buf(),
    })
}

fn wait_for_macos_utun(store: &StateStore) -> Result<(), ControllerError> {
    for _ in 0..100 {
        let present = Command::new("/sbin/ifconfig")
            .arg(MACOS_UTUN_INTERFACE)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if present {
            return Ok(());
        }

        if let Some(state) = store.load()? {
            if !recorded_engine_alive(&state)? {
                return Err(ControllerError::State(
                    "utun engine exited before its interface became ready".to_owned(),
                ));
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    Err(ControllerError::State(format!(
        "{} did not appear within 10 seconds",
        MACOS_UTUN_INTERFACE
    )))
}

fn cleanup_network(state: Option<&RuntimeState>) -> Result<(), ControllerError> {
    match Platform::detect() {
        Platform::Linux => cleanup_linux_nft(),
        Platform::MacOS => cleanup_macos_pf(state),
        Platform::Windows => Ok(()),
        Platform::Unsupported => Err(ControllerError::UnsupportedPlatform),
    }
}

fn network_health(state: &RuntimeState) -> Result<bool, ControllerError> {
    match Platform::detect() {
        Platform::Linux => Ok(Command::new("nft")
            .args(["list", "table", "inet", LINUX_NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)),
        Platform::MacOS => {
            let utun = Command::new("/sbin/ifconfig")
                .arg(MACOS_UTUN_INTERFACE)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            let anchor = Command::new("/sbin/pfctl")
                .args(["-a", MACOS_PF_ANCHOR, "-sr"])
                .output()
                .map(|output| output.status.success() && !output.stdout.is_empty())
                .unwrap_or(false);
            Ok(utun && anchor)
        }
        Platform::Windows => Ok(state.engine_pid.is_some()),
        Platform::Unsupported => Ok(false),
    }
}

fn apply_linux_nft(strategy: &StrategyDefinition) -> Result<(), ControllerError> {
    cleanup_linux_nft()?;

    let rules = linux_nft_rules(strategy);
    run_with_input("nft", &["-f", "-"], rules.as_bytes())
}

fn cleanup_linux_nft() -> Result<(), ControllerError> {
    let exists = Command::new("nft")
        .args(["list", "table", "inet", LINUX_NFT_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if exists {
        command_ok("nft", &["delete", "table", "inet", LINUX_NFT_TABLE])?;
    }
    Ok(())
}

fn cleanup_macos_pf(state: Option<&RuntimeState>) -> Result<(), ControllerError> {
    let output = Command::new("/sbin/pfctl")
        .args(["-a", MACOS_PF_ANCHOR, "-F", "all"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| ControllerError::Io {
            path: PathBuf::from("/sbin/pfctl"),
            source,
        })?;

    if !output.status.success() {
        return Err(ControllerError::Command {
            program: "/sbin/pfctl".to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    if let Some(token) = state.and_then(|value| value.pf_token.as_deref()) {
        command_ok("/sbin/pfctl", &["-X", token])?;
    }

    Ok(())
}

fn verify_windows_companions(binary: &Path) -> Result<(), ControllerError> {
    let base = binary.parent().unwrap_or_else(|| Path::new("."));
    for filename in ["cygwin1.dll", "WinDivert.dll", "WinDivert64.sys"] {
        let path = base.join(filename);
        if !path.is_file() {
            return Err(ControllerError::State(format!(
                "required Windows runtime companion is missing: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn spawn_watchdog() -> Result<(), ControllerError> {
    let current = std::env::current_exe().map_err(|source| ControllerError::Io {
        path: PathBuf::from("<current-exe>"),
        source,
    })?;
    let directory = current.parent().unwrap_or_else(|| Path::new("."));
    let filename = if cfg!(target_os = "windows") {
        "whitelist-hide-watchdog.exe"
    } else {
        "whitelist-hide-watchdog"
    };
    let watchdog = directory.join(filename);
    if !watchdog.is_file() {
        return Err(ControllerError::State(format!(
            "watchdog sidecar is missing: {}",
            watchdog.display()
        )));
    }

    Command::new(&watchdog)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| ControllerError::Io {
            path: watchdog,
            source,
        })?;

    Ok(())
}

fn stop_if_owned(store: &StateStore) -> Result<(), ControllerError> {
    if let Some(state) = store.load()? {
        if recorded_engine_alive(&state)? {
            let _ = stop_recorded_engine(store)?;
        } else {
            store.clear()?;
        }
    }
    Ok(())
}

fn ensure_privileges() -> Result<(), ControllerError> {
    match Platform::detect() {
        Platform::Linux | Platform::MacOS => {
            let uid =
                command_text("/usr/bin/id", &["-u"]).or_else(|_| command_text("id", &["-u"]))?;
            if uid.trim() != "0" {
                return Err(ControllerError::PrivilegeRequired);
            }
            Ok(())
        }
        Platform::Windows => Ok(()),
        Platform::Unsupported => Err(ControllerError::UnsupportedPlatform),
    }
}

fn linux_nft_rules(strategy: &StrategyDefinition) -> String {
    let mut lines = vec![
        format!("table inet {LINUX_NFT_TABLE} {{"),
        "  chain output {".to_owned(),
        "    type filter hook output priority mangle; policy accept;".to_owned(),
    ];

    if !strategy.filters.tcp_ports.is_empty() {
        lines.push(format!(
            "    meta mark != 0x40000000 tcp dport {{ {} }} queue num {NFQUEUE_NUM} bypass",
            nft_ports(&strategy.filters.tcp_ports)
        ));
    }
    if !strategy.filters.udp_ports.is_empty() {
        lines.push(format!(
            "    meta mark != 0x40000000 udp dport {{ {} }} queue num {NFQUEUE_NUM} bypass",
            nft_ports(&strategy.filters.udp_ports)
        ));
    }

    lines.push("  }".to_owned());
    lines.push("}".to_owned());
    lines.push(String::new());
    lines.join("\n")
}

fn macos_pf_rules(strategy: &StrategyDefinition) -> String {
    let mut rules = Vec::new();

    if !strategy.filters.tcp_ports.is_empty() {
        rules.push(format!(
            "pass out quick route-to ({MACOS_UTUN_INTERFACE} 10.77.0.2) inet proto tcp from any to any port {{ {} }} user {{ >root }} no state",
            pf_ports(&strategy.filters.tcp_ports)
        ));
    }
    if !strategy.filters.udp_ports.is_empty() {
        rules.push(format!(
            "pass out quick route-to ({MACOS_UTUN_INTERFACE} 10.77.0.2) inet proto udp from any to any port {{ {} }} user {{ >root }} no state",
            pf_ports(&strategy.filters.udp_ports)
        ));
    }

    rules.push(String::new());
    rules.join("\n")
}

fn nft_ports(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}-{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn pf_ports(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|range| {
            if range.start == range.end {
                range.start.to_string()
            } else {
                format!("{}:{}", range.start, range.end)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn field_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix(key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn parse_arp_mac(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (_, after) = line.split_once(" at ")?;
        let mac = after.split_whitespace().next()?;
        let valid = mac.split(':').count() == 6
            && mac.split(':').all(|part| {
                !part.is_empty() && part.len() <= 2 && part.chars().all(|c| c.is_ascii_hexdigit())
            });
        valid.then(|| mac.to_owned())
    })
}

fn parse_pf_token(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let (_, value) = line.split_once("Token :")?;
        let token = value.trim();
        (!token.is_empty()).then(|| token.to_owned())
    })
}

fn command_text(program: &str, args: &[&str]) -> Result<String, ControllerError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| ControllerError::Io {
            path: PathBuf::from(program),
            source,
        })?;

    if !output.status.success() {
        return Err(ControllerError::Command {
            program: program.to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn command_text_combined(program: &str, args: &[&str]) -> Result<String, ControllerError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| ControllerError::Io {
            path: PathBuf::from(program),
            source,
        })?;

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if !output.status.success() {
        return Err(ControllerError::Command {
            program: program.to_owned(),
            detail: combined.trim().to_owned(),
        });
    }

    Ok(combined)
}

fn command_ok(program: &str, args: &[&str]) -> Result<(), ControllerError> {
    command_text_combined(program, args).map(|_| ())
}

fn run_with_input(program: &str, args: &[&str], input: &[u8]) -> Result<(), ControllerError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ControllerError::Io {
            path: PathBuf::from(program),
            source,
        })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(input)
            .map_err(|source| ControllerError::Io {
                path: PathBuf::from(program),
                source,
            })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|source| ControllerError::Io {
            path: PathBuf::from(program),
            source,
        })?;

    if output.status.success() {
        Ok(())
    } else {
        Err(ControllerError::Command {
            program: program.to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

#[derive(Debug)]
pub enum ControllerError {
    UnsupportedPlatform,
    PrivilegeRequired,
    Config(whitelist_hide_core::config::ConfigError),
    Strategy(StrategyError),
    Runtime(EngineRuntimeError),
    RuntimeState(RuntimeStateError),
    Artifact(ArtifactError),
    State(String),
    Command { program: String, detail: String },
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => f.write_str("unsupported platform"),
            Self::PrivilegeRequired => {
                f.write_str("administrator/root privileges are required for network changes")
            }
            Self::Config(error) => write!(f, "{error}"),
            Self::Strategy(error) => write!(f, "{error}"),
            Self::Runtime(error) => write!(f, "{error}"),
            Self::RuntimeState(error) => write!(f, "{error}"),
            Self::Artifact(error) => write!(f, "{error}"),
            Self::State(message) => f.write_str(message),
            Self::Command { program, detail } => write!(f, "{program} failed: {detail}"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl Error for ControllerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Strategy(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::RuntimeState(error) => Some(error),
            Self::Artifact(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<whitelist_hide_core::config::ConfigError> for ControllerError {
    fn from(value: whitelist_hide_core::config::ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<StrategyError> for ControllerError {
    fn from(value: StrategyError) -> Self {
        Self::Strategy(value)
    }
}

impl From<EngineRuntimeError> for ControllerError {
    fn from(value: EngineRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<RuntimeStateError> for ControllerError {
    fn from(value: RuntimeStateError) -> Self {
        Self::RuntimeState(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_rules_are_scoped_and_bypass_safe() {
        let strategy = sample_strategy();
        let rules = linux_nft_rules(&strategy);
        assert!(rules.contains("table inet whitelist_hide"));
        assert!(rules.contains("queue num 200 bypass"));
        assert!(rules.contains("meta mark != 0x40000000"));
    }

    #[test]
    fn pf_rules_use_default_macos_anchor_compatible_path() {
        let strategy = sample_strategy();
        let rules = macos_pf_rules(&strategy);
        assert!(MACOS_PF_ANCHOR.starts_with("com.apple/"));
        assert!(rules.contains("route-to (utun50 10.77.0.2)"));
        assert!(rules.contains("user { >root }"));
    }

    #[test]
    fn parses_gateway_mac() {
        let arp = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        assert_eq!(parse_arp_mac(arp), Some("aa:bb:cc:dd:ee:ff".to_owned()));
    }

    fn sample_strategy() -> StrategyDefinition {
        StrategyDefinition {
            schema: 1,
            id: "test".to_owned(),
            description: String::new(),
            filters: whitelist_hide_core::strategy::StrategyFilters {
                tcp_ports: vec![
                    PortRange { start: 80, end: 80 },
                    PortRange {
                        start: 443,
                        end: 445,
                    },
                ],
                udp_ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                domain_lists: Vec::new(),
                domain_exclude_lists: Vec::new(),
                ip_lists: Vec::new(),
                ip_exclude_lists: Vec::new(),
            },
            desync: Vec::new(),
        }
    }
}

impl From<ArtifactError> for ControllerError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}
