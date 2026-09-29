pub mod cache;
pub mod catalog;
pub mod probe;

use probe::{ProbeReport, Prober};
use serde::{Deserialize, Serialize};

/// Kept separate from the privileged transport so selection is deterministic
/// and testable without changing the machine's network.
pub trait StrategyRuntime {
    fn start(&mut self, id: &str) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
    fn healthy(&mut self) -> Result<bool, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Checking,
    Connected,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub strategy: String,
    pub probes: Option<ProbeReport>,
    pub confirmation: Option<ProbeReport>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionReport {
    #[serde(default)]
    pub request_id: String,
    pub outcome: Outcome,
    pub phase: String,
    pub strategy: Option<String>,
    pub baseline: Option<ProbeReport>,
    pub attempts: Vec<Attempt>,
    pub message: String,
    pub coverage: String,
    pub session_id: Option<String>,
}

impl Default for SelectionReport {
    fn default() -> Self {
        Self { request_id: String::new(), outcome: Outcome::Checking, phase: "baseline".into(), strategy: None, baseline: None,
            attempts: Vec::new(), message: "Проверяем доступность YouTube и Discord…".into(),
            coverage: "Проверяются HTTPS и CDN по IPv4. Воспроизведение видео, QUIC и голос Discord требуют отдельной проверки.".into(),
            session_id: None }
    }
}

/// The caller holds the process-wide session lock and refuses pre-existing
/// sessions. A cached candidate is a hint and always gets two fresh probes.
pub fn select_strategy<R: StrategyRuntime, P: Prober>(
    runtime: &mut R,
    prober: &mut P,
    candidates: &[String],
    cached: Option<&str>,
    mut progress: impl FnMut(&SelectionReport),
) -> SelectionReport {
    let mut report = SelectionReport::default();
    progress(&report);
    report.baseline = Some(prober.probe());
    // HTTPS alone cannot prove that video or voice already works. Even when
    // baseline passes, honour Connect and try the selected filtering strategy.
    let mut ordered = Vec::new();
    if let Some(id) = cached.filter(|id| candidates.iter().any(|c| c == id)) {
        ordered.push(id.to_owned());
    }
    for id in candidates {
        if !ordered.contains(id) {
            ordered.push(id.clone());
        }
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    for (index, id) in ordered.iter().take(8).enumerate() {
        if std::time::Instant::now() >= deadline {
            break;
        }
        report.phase = "testing".into();
        report.strategy = Some(id.clone());
        report.message = format!(
            "Проверяем стратегию {id} ({}/{})…",
            index + 1,
            ordered.len()
        );
        progress(&report);
        let mut attempt = Attempt {
            strategy: id.clone(),
            probes: None,
            confirmation: None,
            error: None,
        };
        match runtime.start(id) {
            Err(error) => attempt.error = Some(error),
            Ok(()) => {
                let first = prober.probe();
                if first.successful() {
                    attempt.confirmation = Some(prober.probe());
                }
                attempt.probes = Some(first);
                if attempt
                    .confirmation
                    .as_ref()
                    .is_some_and(ProbeReport::successful)
                {
                    match runtime.healthy() {
                        Ok(true) => {
                            report.attempts.push(attempt);
                            report.outcome = Outcome::Connected;
                            report.phase = "complete".into();
                            report.message = format!(
                                "Стратегия {id}: HTTPS YouTube и Discord подтверждён двумя проверками."
                            );
                            if report
                                .baseline
                                .as_ref()
                                .is_some_and(ProbeReport::successful)
                            {
                                report.message.push_str(" HTTPS был доступен и до подключения; эффект для видео и голоса ещё не проверен.");
                            }
                            progress(&report);
                            return report;
                        }
                        Ok(false) => {
                            attempt.error = Some(
                                "Движок или сетевой фильтр остановился во время проверки.".into(),
                            )
                        }
                        Err(e) => attempt.error = Some(e),
                    }
                }
            }
        }
        report.attempts.push(attempt);
        // No next candidate may start before complete cleanup of this one.
        if let Err(e) = runtime.stop() {
            report.outcome = Outcome::Failed;
            report.phase = "cleanup_failed".into();
            report.message =
                format!("Очистка сессии не завершена: {e}. Нажмите восстановление сети.");
            progress(&report);
            return report;
        }
        progress(&report);
    }
    report.outcome = Outcome::Failed;
    report.phase = "complete".into();
    report.strategy = None;
    report.message = "Подходящая стратегия не найдена; фильтр остановлен. Проверьте результаты HTTPS/DNS в отчёте. Строгий IP-белый список этим методом может не обходиться.".into();
    progress(&report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use probe::{ProbeResult, REQUIRED_TARGETS};
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Runtime {
        calls: Vec<String>,
        active: bool,
        fail_start: bool,
        fail_stop: bool,
        died: bool,
    }
    impl StrategyRuntime for Runtime {
        fn start(&mut self, id: &str) -> Result<(), String> {
            assert!(!self.active, "overlapping sessions");
            self.calls.push(format!("start:{id}"));
            self.active = true;
            if self.fail_start {
                self.fail_start = false;
                Err("engine rejected strategy".into())
            } else {
                Ok(())
            }
        }
        fn stop(&mut self) -> Result<(), String> {
            self.calls.push("stop".into());
            if self.fail_stop {
                Err("resource still owned".into())
            } else {
                self.active = false;
                Ok(())
            }
        }
        fn healthy(&mut self) -> Result<bool, String> {
            Ok(self.active && !self.died)
        }
    }
    struct Probes(VecDeque<bool>);
    impl Prober for Probes {
        fn probe(&mut self) -> ProbeReport {
            let ok = self.0.pop_front().expect("unexpected extra probe");
            ProbeReport {
                results: REQUIRED_TARGETS
                    .iter()
                    .map(|id| ProbeResult {
                        target: (*id).into(),
                        ok,
                        elapsed_ms: 1,
                        detail: String::new(),
                    })
                    .collect(),
            }
        }
    }
    fn select(runtime: &mut Runtime, results: &[bool], cached: Option<&str>) -> SelectionReport {
        select_strategy(
            runtime,
            &mut Probes(results.iter().copied().collect()),
            &["first".into(), "second".into()],
            cached,
            |_| {},
        )
    }
    #[test]
    fn failed_candidate_is_stopped_before_next_and_success_needs_confirmation() {
        let mut runtime = Runtime::default();
        let report = select(&mut runtime, &[false, true, false, true, true], None);
        assert_eq!(report.outcome, Outcome::Connected);
        assert_eq!(report.strategy.as_deref(), Some("second"));
        assert_eq!(runtime.calls, ["start:first", "stop", "start:second"]);
        assert_eq!(report.attempts.len(), 2);
        assert!(runtime.active);
    }
    #[test]
    fn cached_strategy_is_tested_again_and_can_fail() {
        let mut runtime = Runtime::default();
        let report = select(&mut runtime, &[false, false, true, true], Some("second"));
        assert_eq!(report.strategy.as_deref(), Some("first"));
        assert_eq!(runtime.calls, ["start:second", "stop", "start:first"]);
    }
    #[test]
    fn startup_failure_and_complete_failure_leave_no_session() {
        let mut runtime = Runtime {
            fail_start: true,
            ..Default::default()
        };
        let report = select(&mut runtime, &[false, false], None);
        assert_eq!(report.outcome, Outcome::Failed);
        assert_eq!(
            runtime.calls,
            ["start:first", "stop", "start:second", "stop"]
        );
        assert!(report.attempts[0].error.is_some());
        assert!(!runtime.active);
    }
    #[test]
    fn cleanup_error_aborts_selection_before_next_candidate() {
        let mut runtime = Runtime {
            fail_stop: true,
            ..Default::default()
        };
        let report = select(&mut runtime, &[false, false], None);
        assert_eq!(report.outcome, Outcome::Failed);
        assert_eq!(report.phase, "cleanup_failed");
        assert_eq!(runtime.calls, ["start:first", "stop"]);
    }
    #[test]
    fn engine_dying_after_good_network_probes_is_not_connected() {
        let mut runtime = Runtime {
            died: true,
            ..Default::default()
        };
        let report = select(&mut runtime, &[false, true, true, true, true], None);
        assert_eq!(report.outcome, Outcome::Failed);
        assert!(!runtime.active);
    }
    #[test]
    fn reachable_https_does_not_skip_filter_or_prove_video_access() {
        let mut runtime = Runtime::default();
        let report = select(&mut runtime, &[true, true, true], None);
        assert_eq!(report.outcome, Outcome::Connected);
        assert_eq!(runtime.calls, ["start:first"]);
        assert!(report.message.contains("до подключения"));
    }
    #[test]
    fn manual_selection_never_tries_another_candidate() {
        let mut runtime = Runtime::default();
        let mut prober = Probes([false, false].into());
        let report = select_strategy(
            &mut runtime,
            &mut prober,
            &["manual".into()],
            Some("other"),
            |_| {},
        );
        assert_eq!(report.outcome, Outcome::Failed);
        assert_eq!(runtime.calls, ["start:manual", "stop"]);
    }
}
