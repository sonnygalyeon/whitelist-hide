use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whitelist_hide_core::{config::AppConfig, strategy::StrategyDefinition};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub name: String,
    pub config: PathBuf,
    pub strategy: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub revision: String,
    pub region: String,
    pub source: String,
    pub candidates: Vec<Candidate>,
}

impl Catalog {
    pub fn load(root: &Path) -> Result<Self, String> {
        let catalog: Self = toml::from_str(
            &std::fs::read_to_string(root.join("catalog.toml")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if catalog.schema != 1 || catalog.candidates.is_empty() || catalog.candidates.len() > 8 {
            return Err("unsupported or empty strategy catalog".into());
        }
        let mut ids = std::collections::HashSet::new();
        for candidate in &catalog.candidates {
            if !ids.insert(&candidate.id) {
                return Err("duplicate strategy id".into());
            }
            for path in [&candidate.config, &candidate.strategy] {
                if path.components().count() != 1
                    || !matches!(
                        path.components().next(),
                        Some(std::path::Component::Normal(_))
                    )
                {
                    return Err("catalog paths must be plain filenames".into());
                }
            }
            let config =
                AppConfig::load(&root.join(&candidate.config)).map_err(|e| e.to_string())?;
            let strategy = StrategyDefinition::load(&root.join(&candidate.strategy))
                .map_err(|e| e.to_string())?;
            if config.strategy.name != candidate.id || strategy.id != candidate.id {
                return Err("catalog, configuration and strategy ids disagree".into());
            }
        }
        Ok(catalog)
    }

    pub fn fingerprint(&self, root: &Path) -> Result<String, String> {
        let mut digest = Sha256::new();
        digest.update(std::fs::read(root.join("catalog.toml")).map_err(|e| e.to_string())?);
        for candidate in &self.candidates {
            for path in [&candidate.config, &candidate.strategy] {
                digest.update(std::fs::read(root.join(path)).map_err(|e| e.to_string())?);
            }
            let config_path = root.join(&candidate.config);
            let config = AppConfig::load(&config_path).map_err(|e| e.to_string())?;
            let binding = config.resolve_engine_paths(&config_path);
            digest.update(std::fs::read(binding.manifest).map_err(|e| e.to_string())?);
            let strategy = StrategyDefinition::load(&root.join(&candidate.strategy))
                .map_err(|e| e.to_string())?;
            for list in strategy
                .filters
                .domain_lists
                .iter()
                .chain(&strategy.filters.ip_lists)
            {
                digest.update(std::fs::read(root.join(list)).map_err(|e| e.to_string())?);
            }
            for rule in &strategy.rules {
                for payload in rule.fake_payload.iter().chain(rule.split_pattern.iter()) {
                    digest.update(std::fs::read(root.join(payload)).map_err(|e| e.to_string())?);
                }
            }
        }
        Ok(format!("{:x}", digest.finalize()))
    }
}
