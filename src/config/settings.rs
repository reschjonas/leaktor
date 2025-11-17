use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration for Leaktor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Entropy threshold for high-entropy detection
    pub entropy_threshold: f64,

    /// Minimum confidence score to report
    pub min_confidence: f64,

    /// Enable validation of detected secrets
    pub enable_validation: bool,

    /// Scan git history
    pub scan_git_history: bool,

    /// Maximum depth for git history scan
    pub max_git_depth: Option<usize>,

    /// Respect .gitignore files
    pub respect_gitignore: bool,

    /// Maximum file size to scan (in bytes)
    pub max_file_size: u64,

    /// Exclude test files from scanning
    pub exclude_tests: bool,

    /// Exclude documentation from scanning
    pub exclude_docs: bool,

    /// Custom patterns to detect
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    /// Severity levels to report
    #[serde(default = "default_severities")]
    pub report_severities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub confidence: f64,
}

fn default_severities() -> Vec<String> {
    vec![
        "CRITICAL".to_string(),
        "HIGH".to_string(),
        "MEDIUM".to_string(),
        "LOW".to_string(),
    ]
}

impl Default for Config {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            min_confidence: 0.6,
            enable_validation: false,
            scan_git_history: true,
            max_git_depth: None,
            respect_gitignore: true,
            max_file_size: 1024 * 1024, // 1MB
            exclude_tests: false,
            exclude_docs: false,
            custom_patterns: Vec::new(),
            report_severities: default_severities(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_toml_file(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Save configuration to a YAML file
    pub fn to_yaml_file(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Try to load config from current directory or parent directories
    pub fn load_from_current_dir() -> Result<Self> {
        let config_names = [".leaktor.toml", ".leaktor.yaml", ".leaktor.yml"];

        for name in &config_names {
            let path = Path::new(name);
            if path.exists() {
                if name.ends_with(".toml") {
                    return Self::from_toml_file(path);
                } else {
                    return Self::from_yaml_file(path);
                }
            }
        }

        // No config file found, use defaults
        Ok(Self::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.entropy_threshold, 3.5);
        assert_eq!(config.min_confidence, 0.6);
        assert!(config.scan_git_history);
    }

    #[test]
    fn test_config_serialization() -> Result<()> {
        let config = Config::default();
        let toml_str = toml::to_string(&config)?;
        assert!(toml_str.contains("entropy_threshold"));
        Ok(())
    }

    #[test]
    fn test_config_save_and_load() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test.toml");

        let config = Config::default();
        config.to_toml_file(&config_path)?;

        let loaded = Config::from_toml_file(&config_path)?;
        assert_eq!(loaded.entropy_threshold, config.entropy_threshold);

        Ok(())
    }
}
