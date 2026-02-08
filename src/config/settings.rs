use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration for Leaktor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

    /// Allowlist rules -- suppress findings that match any of these rules
    #[serde(default)]
    pub allowlist: Vec<AllowlistRule>,

    /// Severity levels to report
    #[serde(default = "default_severities")]
    pub report_severities: Vec<String>,
}

/// A user-defined detection pattern.
///
/// Define custom patterns in `.leaktor.toml`:
///
/// ```toml
/// [[custom_patterns]]
/// name = "Internal API Key"
/// regex = "internal_api_[0-9a-f]{32}"
/// severity = "HIGH"
/// confidence = 0.85
/// description = "Internal API key for our backend services"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Display name for this pattern (e.g. "Internal API Key")
    pub name: String,
    /// Regex to match (Rust regex syntax)
    pub regex: String,
    /// Severity: CRITICAL, HIGH, MEDIUM, or LOW
    pub severity: String,
    /// Base confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Optional description for documentation
    #[serde(default)]
    pub description: Option<String>,
}

/// A rule to suppress (allowlist) certain findings.
///
/// All fields are optional; a finding must match **every** specified field
/// to be suppressed.
///
/// ```toml
/// [[allowlist]]
/// description = "Test Sentry DSN"
/// secret_types = ["Sentry DSN"]
///
/// [[allowlist]]
/// description = "All findings in test fixtures"
/// paths = ["tests/fixtures/*", "*.test.*"]
///
/// [[allowlist]]
/// description = "Example AWS key from documentation"
/// value_regex = "AKIAIOSFODNN7EXAMPLE"
///
/// [[allowlist]]
/// description = "Low-risk public Mapbox tokens"
/// secret_types = ["Mapbox Token"]
/// severities = ["LOW", "MEDIUM"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistRule {
    /// Human-readable description of why this rule exists
    #[serde(default)]
    pub description: Option<String>,

    /// Match findings whose secret type name is in this list (case-sensitive).
    /// If empty/absent, matches any type.
    #[serde(default)]
    pub secret_types: Vec<String>,

    /// Match findings whose file path matches any of these glob patterns.
    /// If empty/absent, matches any path.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Match findings whose secret value matches this regex.
    /// If absent, matches any value.
    #[serde(default)]
    pub value_regex: Option<String>,

    /// Match findings whose severity is in this list.
    /// If empty/absent, matches any severity.
    #[serde(default)]
    pub severities: Vec<String>,
}

impl AllowlistRule {
    /// Check whether a finding matches this rule.
    /// A finding must match **all** non-empty criteria to be suppressed.
    pub fn matches(
        &self,
        secret_type_name: &str,
        file_path: &str,
        secret_value: &str,
        severity_name: &str,
    ) -> bool {
        // Check secret_types (if specified)
        if !self.secret_types.is_empty() && !self.secret_types.iter().any(|t| t == secret_type_name)
        {
            return false;
        }

        // Check paths (if specified) -- match against the full path and also
        // against just the filename / relative tail so that user-specified
        // patterns like "tests/fixtures/*" work with absolute file paths.
        if !self.paths.is_empty() {
            let matches_any = self.paths.iter().any(|p| {
                // Direct match
                if glob_match(file_path, p) {
                    return true;
                }
                // Try matching the tail of the path (handles absolute vs relative)
                // e.g. "/tmp/proj/tests/fixtures/fake.env" should match "tests/fixtures/*"
                if let Some(idx) = file_path.find(p.trim_end_matches('*').trim_end_matches('/')) {
                    let tail = &file_path[idx..];
                    if glob_match(tail, p) {
                        return true;
                    }
                }
                false
            });
            if !matches_any {
                return false;
            }
        }

        // Check value_regex (if specified)
        if let Some(ref re_str) = self.value_regex {
            match regex::Regex::new(re_str) {
                Ok(re) => {
                    if !re.is_match(secret_value) {
                        return false;
                    }
                }
                Err(_) => return false, // invalid regex never matches
            }
        }

        // Check severities (if specified)
        if !self.severities.is_empty()
            && !self
                .severities
                .iter()
                .any(|s| s.eq_ignore_ascii_case(severity_name))
        {
            return false;
        }

        true
    }
}

/// Simple glob matching (supports `*` and `**`).
fn glob_match(text: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return false;
        }

        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if i == 0 && !part.is_empty() {
                if !text[pos..].starts_with(part) {
                    return false;
                }
                pos += part.len();
            } else if i == parts.len() - 1 && !part.is_empty() {
                return text.ends_with(part);
            } else if !part.is_empty() {
                if let Some(found_pos) = text[pos..].find(part) {
                    pos += found_pos + part.len();
                } else {
                    return false;
                }
            }
        }
        true
    } else {
        text.contains(pattern)
    }
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
            allowlist: Vec::new(),
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

    /// Compile the allowlist rules into a list for efficient matching.
    /// Returns the list of rules (cheap -- just borrows).
    pub fn compiled_allowlist(&self) -> &[AllowlistRule] {
        &self.allowlist
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
        assert!(config.allowlist.is_empty());
        assert!(config.custom_patterns.is_empty());
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

    #[test]
    fn test_custom_patterns_round_trip() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test.toml");

        let mut config = Config::default();
        config.custom_patterns.push(CustomPattern {
            name: "Internal Key".to_string(),
            regex: "int_key_[a-f0-9]{32}".to_string(),
            severity: "HIGH".to_string(),
            confidence: 0.85,
            description: Some("Company internal key".to_string()),
        });
        config.to_toml_file(&config_path)?;

        let loaded = Config::from_toml_file(&config_path)?;
        assert_eq!(loaded.custom_patterns.len(), 1);
        assert_eq!(loaded.custom_patterns[0].name, "Internal Key");
        assert_eq!(loaded.custom_patterns[0].confidence, 0.85);
        Ok(())
    }

    #[test]
    fn test_allowlist_round_trip() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test.toml");

        let mut config = Config::default();
        config.allowlist.push(AllowlistRule {
            description: Some("Skip Sentry DSN".to_string()),
            secret_types: vec!["Sentry DSN".to_string()],
            paths: vec![],
            value_regex: None,
            severities: vec![],
        });
        config.to_toml_file(&config_path)?;

        let loaded = Config::from_toml_file(&config_path)?;
        assert_eq!(loaded.allowlist.len(), 1);
        assert_eq!(loaded.allowlist[0].secret_types, vec!["Sentry DSN"]);
        Ok(())
    }

    #[test]
    fn test_allowlist_rule_matches_type() {
        let rule = AllowlistRule {
            description: None,
            secret_types: vec!["Sentry DSN".to_string()],
            paths: vec![],
            value_regex: None,
            severities: vec![],
        };

        assert!(rule.matches("Sentry DSN", "any/path", "any_value", "MEDIUM"));
        assert!(!rule.matches("GitHub PAT", "any/path", "any_value", "CRITICAL"));
    }

    #[test]
    fn test_allowlist_rule_matches_path() {
        let rule = AllowlistRule {
            description: None,
            secret_types: vec![],
            paths: vec!["tests/fixtures/*".to_string()],
            value_regex: None,
            severities: vec![],
        };

        assert!(rule.matches("Any", "tests/fixtures/secrets.env", "val", "HIGH"));
        assert!(!rule.matches("Any", "src/main.rs", "val", "HIGH"));
    }

    #[test]
    fn test_allowlist_rule_matches_value_regex() {
        let rule = AllowlistRule {
            description: None,
            secret_types: vec![],
            paths: vec![],
            value_regex: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
            severities: vec![],
        };

        assert!(rule.matches("AWS", "file.env", "AKIAIOSFODNN7EXAMPLE", "CRITICAL"));
        assert!(!rule.matches("AWS", "file.env", "AKIAREALKEY12345678", "CRITICAL"));
    }

    #[test]
    fn test_allowlist_rule_matches_severity() {
        let rule = AllowlistRule {
            description: None,
            secret_types: vec![],
            paths: vec![],
            value_regex: None,
            severities: vec!["LOW".to_string(), "MEDIUM".to_string()],
        };

        assert!(rule.matches("Any", "any", "val", "LOW"));
        assert!(rule.matches("Any", "any", "val", "MEDIUM"));
        assert!(!rule.matches("Any", "any", "val", "CRITICAL"));
    }

    #[test]
    fn test_allowlist_rule_multi_criteria() {
        let rule = AllowlistRule {
            description: None,
            secret_types: vec!["Sentry DSN".to_string()],
            paths: vec!["tests/*".to_string()],
            value_regex: None,
            severities: vec![],
        };

        // Both criteria must match
        assert!(rule.matches("Sentry DSN", "tests/fixtures/env", "val", "MEDIUM"));
        // Only type matches, path doesn't
        assert!(!rule.matches("Sentry DSN", "src/main.rs", "val", "MEDIUM"));
        // Only path matches, type doesn't
        assert!(!rule.matches("GitHub PAT", "tests/foo", "val", "CRITICAL"));
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("tests/fixtures/secret.env", "tests/*"));
        assert!(glob_match("src/main.test.rs", "*.test.*"));
        assert!(glob_match("foo/bar/baz.js", "**/baz.js"));
        assert!(!glob_match("src/main.rs", "*.py"));
    }
}
