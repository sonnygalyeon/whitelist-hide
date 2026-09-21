//! Platform-neutral control-plane types for whitelist-hide.

pub mod artifact;
pub mod config;
pub mod strategy;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    MacOS,
    Linux,
    Unsupported,
}

impl Platform {
    #[must_use]
    pub const fn detect() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOS
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unsupported
        }
    }

    #[must_use]
    pub const fn backend_name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOS => "macos",
            Self::Linux => "linux",
            Self::Unsupported => "unsupported",
        }
    }

    #[must_use]
    pub const fn planned_interceptor(self) -> &'static str {
        match self {
            Self::Windows => "WinDivert-compatible packet interception",
            Self::MacOS => "utun + pf",
            Self::Linux => "netfilter/NFQUEUE",
            Self::Unsupported => "none",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.backend_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub platform: Platform,
    pub architecture: &'static str,
    pub interceptor: &'static str,
    pub network_changes_enabled: bool,
}

impl DoctorReport {
    #[must_use]
    pub fn collect() -> Self {
        let platform = Platform::detect();
        Self {
            platform,
            architecture: std::env::consts::ARCH,
            interceptor: platform.planned_interceptor(),
            network_changes_enabled: false,
        }
    }
}
