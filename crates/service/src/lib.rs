pub mod runtime;

use std::error::Error;

use serde::{Deserialize, Serialize};
use whitelist_hide_core::Platform;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendAction {
    Start,
    Stop,
    Cleanup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendState {
    Unsupported,
    Ready,
    Degraded,
    Starting,
    Running,
    Stopping,
    Stopped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Ok,
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticItem {
    pub key: String,
    pub label: String,
    pub value: String,
    pub level: DiagnosticLevel,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendStatus {
    pub platform: String,
    pub available: bool,
    pub state: BackendState,
    pub diagnostics: Vec<DiagnosticItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionStep {
    pub id: String,
    pub description: String,
    pub command_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionPlan {
    pub id: String,
    pub title: String,
    pub requires_admin: bool,
    pub mutates_network: bool,
    pub executable_now: bool,
    pub steps: Vec<ActionStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionResult {
    pub action: BackendAction,
    pub changed: bool,
    pub message: String,
}

pub trait PlatformBackend {
    type Error: Error;

    fn platform(&self) -> Platform;
    fn status(&self) -> Result<BackendStatus, Self::Error>;
    fn plan(&self, action: BackendAction) -> Result<ActionPlan, Self::Error>;
    fn execute(&self, action: BackendAction) -> Result<ActionResult, Self::Error>;
}

pub struct AppService<B> {
    backend: B,
}

impl<B> AppService<B>
where
    B: PlatformBackend,
{
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn status(&self) -> Result<BackendStatus, B::Error> {
        self.backend.status()
    }

    pub fn plan(&self, action: BackendAction) -> Result<ActionPlan, B::Error> {
        self.backend.plan(action)
    }

    pub fn execute(&self, action: BackendAction) -> Result<ActionResult, B::Error> {
        self.backend.execute(action)
    }
}
