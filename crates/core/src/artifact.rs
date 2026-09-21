use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::Platform;

const MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema: u32,
    pub name: String,
    pub version: String,
    pub source: String,
    pub license: String,
    pub artifact: ArtifactSpec,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub platform: String,
    pub filename: String,
    pub sha256: String,
}

impl ArtifactManifest {
    pub fn parse(input: &str) -> Result<Self, ArtifactError> {
        let manifest: Self = toml::from_str(input).map_err(ArtifactError::Parse)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn load(path: &Path) -> Result<Self, ArtifactError> {
        let content = std::fs::read_to_string(path).map_err(|source| ArtifactError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&content)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(ArtifactError::InvalidManifest(format!(
                "unsupported manifest schema {}; expected {MANIFEST_SCHEMA}",
                self.schema
            )));
        }

        for (field, value) in [
            ("name", self.name.as_str()),
            ("version", self.version.as_str()),
            ("source", self.source.as_str()),
            ("license", self.license.as_str()),
            ("artifact.filename", self.artifact.filename.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ArtifactError::InvalidManifest(format!(
                    "{field} must not be empty"
                )));
            }
        }

        if !is_supported_target(&self.artifact.platform) {
            return Err(ArtifactError::InvalidManifest(format!(
                "unsupported artifact platform: {}",
                self.artifact.platform
            )));
        }

        let digest = self.artifact.sha256.trim();
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ArtifactError::InvalidManifest(
                "artifact.sha256 must contain exactly 64 hexadecimal characters".to_owned(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub name: String,
    pub version: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub size_bytes: u64,
    pub expected_platform: String,
    pub actual_platform: String,
}

impl VerificationReport {
    #[must_use]
    pub fn integrity_ok(&self) -> bool {
        self.expected_sha256.eq_ignore_ascii_case(&self.actual_sha256)
    }

    #[must_use]
    pub fn platform_ok(&self) -> bool {
        self.expected_platform == self.actual_platform
    }

    #[must_use]
    pub fn trusted(&self) -> bool {
        self.integrity_ok() && self.platform_ok()
    }
}

pub fn verify_file(
    manifest: &ArtifactManifest,
    path: &Path,
) -> Result<VerificationReport, ArtifactError> {
    manifest.validate()?;

    let file = File::open(path).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let (actual_sha256, size_bytes) = sha256_reader(file).map_err(|source| ArtifactError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(VerificationReport {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        expected_sha256: manifest.artifact.sha256.to_ascii_lowercase(),
        actual_sha256,
        size_bytes,
        expected_platform: manifest.artifact.platform.clone(),
        actual_platform: current_artifact_target(),
    })
}

pub fn sha256_reader<R: Read>(mut reader: R) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        hex.push(DIGITS[(byte >> 4) as usize] as char);
        hex.push(DIGITS[(byte & 0x0f) as usize] as char);
    }

    Ok((hex, size))
}

#[must_use]
pub fn current_artifact_target() -> String {
    let os = match Platform::detect() {
        Platform::Windows => "windows",
        Platform::MacOS => "macos",
        Platform::Linux => "linux",
        Platform::Unsupported => "unsupported",
    };

    format!("{os}-{}", std::env::consts::ARCH)
}

fn is_supported_target(target: &str) -> bool {
    matches!(
        target,
        "windows-x86_64"
            | "windows-aarch64"
            | "macos-x86_64"
            | "macos-aarch64"
            | "linux-x86_64"
            | "linux-aarch64"
    )
}

#[derive(Debug)]
pub enum ArtifactError {
    Io { path: PathBuf, source: io::Error },
    Parse(toml::de::Error),
    InvalidManifest(String),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to access {}: {source}", path.display())
            }
            Self::Parse(source) => write!(f, "invalid TOML manifest: {source}"),
            Self::InvalidManifest(message) => write!(f, "invalid artifact manifest: {message}"),
        }
    }
}

impl Error for ArtifactError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse(source) => Some(source),
            Self::InvalidManifest(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn valid_manifest() -> ArtifactManifest {
        ArtifactManifest {
            schema: 1,
            name: "demo".to_owned(),
            version: "1.0.0".to_owned(),
            source: "https://example.invalid/demo".to_owned(),
            license: "MIT".to_owned(),
            artifact: ArtifactSpec {
                platform: current_artifact_target(),
                filename: "demo.bin".to_owned(),
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_owned(),
            },
        }
    }

    #[test]
    fn hashes_known_input() {
        let (digest, size) = sha256_reader(Cursor::new(b"abc")).expect("hashing must succeed");
        assert_eq!(size, 3);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn manifest_validation_rejects_bad_digest() {
        let mut manifest = valid_manifest();
        manifest.artifact.sha256 = "not-a-digest".to_owned();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn verification_report_requires_hash_and_platform() {
        let manifest = valid_manifest();
        let (digest, size) = sha256_reader(Cursor::new(b"abc")).expect("hashing must succeed");
        let report = VerificationReport {
            name: manifest.name,
            version: manifest.version,
            expected_sha256: manifest.artifact.sha256,
            actual_sha256: digest,
            size_bytes: size,
            expected_platform: manifest.artifact.platform,
            actual_platform: current_artifact_target(),
        };
        assert!(report.trusted());
    }
}
