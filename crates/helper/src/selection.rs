use std::path::{Path, PathBuf};
use whitelist_hide_controller::{
    SessionController,
    connection::{
        self, Outcome, SelectionReport, StrategyRuntime,
        cache::{SelectionCache, network_key, now, write_json},
        catalog::Catalog,
        probe::HttpsProber,
    },
};

fn report_path(controller: &SessionController) -> PathBuf {
    controller.state_path().with_extension("selection.json")
}

pub fn read(controller: &SessionController) -> Result<String, String> {
    match std::fs::read_to_string(report_path(controller)) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("null".into()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn connect(
    controller: &SessionController,
    root: &Path,
    selected: &str,
    request_id: &str,
) -> Result<SelectionReport, String> {
    if request_id.is_empty()
        || request_id.len() > 100
        || !request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid connection request id".into());
    }
    if controller
        .session_id()
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(
            "An active session already exists. Stop it before selecting a strategy.".into(),
        );
    }
    let catalog = Catalog::load(root)?;
    let fingerprint = catalog.fingerprint(root)?;
    let automatic = selected == "auto";
    let candidates: Vec<_> = catalog
        .candidates
        .iter()
        .filter(|c| automatic || c.id == selected)
        .map(|c| c.id.clone())
        .collect();
    if candidates.is_empty() {
        return Err("Неизвестная стратегия".into());
    }
    let network = network_key();
    let cache_path = controller
        .state_path()
        .with_extension("selection-cache.json");
    let mut cache = SelectionCache::load(&cache_path);
    let cached = network
        .as_deref()
        .and_then(|key| cache.get(key, &fingerprint, now()))
        .map(str::to_owned);
    let mut runtime = OwnedRuntime {
        controller,
        root,
        catalog: &catalog,
        keep: false,
    };
    let mut report = connection::select_strategy(
        &mut runtime,
        &mut HttpsProber,
        &candidates,
        cached.as_deref(),
        |report| {
            let mut report = report.clone();
            report.request_id = request_id.into();
            let _ = write_json(&report_path(controller), &report);
        },
    );
    report.request_id = request_id.into();
    if report.outcome == Outcome::Connected {
        if let Err(error) = super::spawn_watchdog(controller) {
            report.outcome = Outcome::Failed;
            report.message = format!("Не удалось запустить контроль сессии: {error}");
            if let Err(e) = runtime.stop() {
                report.message.push_str(&format!("; очистка: {e}"));
            }
        } else {
            report.session_id = controller.session_id().map_err(|e| e.to_string())?;
            runtime.keep = true;
        }
    }
    if let Some(key) = network.as_deref() {
        cache.invalidate(key);
        if report.outcome == Outcome::Connected
            && !report.baseline.as_ref().is_some_and(|r| r.successful())
            && network_key().as_deref() == Some(key)
            && let Some(id) = &report.strategy
        {
            cache.record(key, &fingerprint, id, now());
        }
        if let Err(error) = cache.save(&cache_path) {
            report
                .message
                .push_str(&format!(" Рабочий вариант не сохранён: {error}"));
        }
    }
    if let Err(error) = write_json(&report_path(controller), &report) {
        runtime.keep = false;
        return Err(format!(
            "Не удалось сохранить результат подключения: {error}"
        ));
    }
    Ok(report)
}

struct OwnedRuntime<'a> {
    controller: &'a SessionController,
    root: &'a Path,
    catalog: &'a Catalog,
    keep: bool,
}
impl StrategyRuntime for OwnedRuntime<'_> {
    fn start(&mut self, id: &str) -> Result<(), String> {
        let candidate = self
            .catalog
            .candidates
            .iter()
            .find(|c| c.id == id)
            .ok_or("unknown strategy")?;
        self.controller
            .start(
                &self.root.join(&candidate.config),
                &self.root.join(&candidate.strategy),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn stop(&mut self) -> Result<(), String> {
        self.controller.stop().map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(self.controller.state_path().with_extension("health"));
        Ok(())
    }
    fn healthy(&mut self) -> Result<bool, String> {
        self.controller
            .health()
            .map(|r| r.running)
            .map_err(|e| e.to_string())
    }
}
impl Drop for OwnedRuntime<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = self.stop();
        }
    }
}
