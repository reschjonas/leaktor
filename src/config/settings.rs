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

    /// Maximum number of concurrent API validation requests.
    /// Prevents hammering external APIs when scanning large repos.
    /// Set to 0 to disable API-based validation entirely.
    #[serde(default = "default_max_concurrent_validations")]
    pub max_concurrent_validations: usize,

    /// Minimum delay between API requests to the same host (in milliseconds).
    /// Spreads out requests to avoid triggering service rate limits.
    #[serde(default = "default_validation_delay_ms")]
    pub validation_delay_ms: u64,

    /// Maximum number of retries when an API returns 429 Too Many Requests.
    #[serde(default = "default_validation_max_retries")]
    pub validation_max_retries: u32,
}

fn default_max_concurrent_validations() -> usize {
    10
}

fn default_validation_delay_ms() -> u64 {
    100
}

fn default_validation_max_retries() -> u32 {
    3
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
#[serde(deny_unknown_fields)]
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
    /// Returns true if all filtering criteria are empty, meaning this rule
    /// has no constraints and would incorrectly suppress every finding.
    pub fn has_no_criteria(&self) -> bool {
        self.secret_types.is_empty()
            && self.paths.is_empty()
            && self.value_regex.is_none()
            && self.severities.is_empty()
    }

    /// Check whether a finding matches this rule.
    /// A finding must match **all** non-empty criteria to be suppressed.
    /// A rule with zero criteria never matches (defense against misconfiguration).
    pub fn matches(
        &self,
        secret_type_name: &str,
        file_path: &str,
        secret_value: &str,
        severity_name: &str,
    ) -> bool {
        // A rule with no criteria at all is a misconfiguration -- it should
        // never act as a wildcard that suppresses every finding.
        if self.has_no_criteria() {
            return false;
        }

        // Check secret_types (if specified)
        if !self.secret_types.is_empty() && !self.secret_types.iter().any(|t| t == secret_type_name)
        {
            return false;
        }

        // Check paths (if specified).
        // `glob_match` already handles:
        //   - Patterns without `/` are matched against the filename
        //   - Patterns with `/` are tried against every suffix of the path
        //   - `**/` anchoring
        if !self.paths.is_empty() {
            let matches_any = self.paths.iter().any(|p| glob_match(file_path, p));
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

/// Glob matching for allowlist paths.
///
/// Supported syntax:
///   - `*`    matches any sequence of non-`/` characters (single segment)
///   - `**`   matches any sequence of characters including `/` (multiple segments)
///   - `?`    matches exactly one non-`/` character
///   - `!pat` negation — returns the inverse of matching `pat`
///   - All other characters match literally (case-sensitive)
///
/// Follows `.gitignore` conventions:
///   - A pattern *without* a `/` separator (e.g. `*.rs`) is matched against the
///     filename only (last path component), so `*.rs` matches `src/main.rs`.
///   - A pattern *with* a `/` (or starting with `**/`) is matched against the
///     full path, with `**/` anchoring allowed anywhere.
pub fn glob_match(text: &str, pattern: &str) -> bool {
    // Handle negation: !pattern
    if let Some(inner) = pattern.strip_prefix('!') {
        return !glob_match(text, inner);
    }

    // If pattern starts with **/, allow matching anywhere in the path
    if let Some(suffix) = pattern.strip_prefix("**/") {
        // Try matching against every possible tail of the path
        if glob_match_inner(text, suffix) {
            return true;
        }
        for (i, c) in text.char_indices() {
            if c == '/' && glob_match_inner(&text[i + 1..], suffix) {
                return true;
            }
        }
        return false;
    }

    // .gitignore convention: if the pattern contains no `/`, match it against
    // the filename (last component) rather than requiring a full-path match.
    // This means `*.rs` matches `src/main.rs` just like `.gitignore`.
    if !pattern.contains('/') {
        let filename = text.rsplit('/').next().unwrap_or(text);
        return glob_match_inner(filename, pattern);
    }

    // Pattern contains `/` — try full-path match first, then try matching
    // against any suffix of the path (handles absolute vs relative paths).
    if glob_match_inner(text, pattern) {
        return true;
    }
    for (i, c) in text.char_indices() {
        if c == '/' && glob_match_inner(&text[i + 1..], pattern) {
            return true;
        }
    }

    false
}

/// Core recursive glob matcher. Matches `text` against `pattern` where:
///   - `**` matches zero or more path segments (including separators)
///   - `*`  matches zero or more non-`/` characters
///   - `?`  matches exactly one non-`/` character
pub(crate) fn glob_match_inner(text: &str, pattern: &str) -> bool {
    // Use iterative approach with backtracking positions for `*` and `**`
    let text_bytes = text.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let (tlen, plen) = (text_bytes.len(), pat_bytes.len());

    let mut ti = 0usize; // text index
    let mut pi = 0usize; // pattern index

    // Backtrack positions for single `*`
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    // Backtrack positions for `**`
    let mut dstar_pi: Option<usize> = None;
    let mut dstar_ti: usize = 0;

    while ti < tlen || pi < plen {
        if pi < plen {
            // Check for `**`
            if pi + 1 < plen && pat_bytes[pi] == b'*' && pat_bytes[pi + 1] == b'*' {
                // Skip all consecutive `*`
                let mut pp = pi;
                while pp < plen && pat_bytes[pp] == b'*' {
                    pp += 1;
                }
                // Skip optional trailing `/` after `**`
                if pp < plen && pat_bytes[pp] == b'/' {
                    pp += 1;
                }
                dstar_pi = Some(pp);
                dstar_ti = ti;
                pi = pp;
                // Reset single-star backtrack since ** is more powerful
                star_pi = None;
                continue;
            }

            // Check for single `*`
            if pat_bytes[pi] == b'*' {
                star_pi = Some(pi + 1);
                star_ti = ti;
                pi += 1;
                continue;
            }

            if ti < tlen {
                // `?` matches any single char except `/`
                if pat_bytes[pi] == b'?' && text_bytes[ti] != b'/' {
                    ti += 1;
                    pi += 1;
                    continue;
                }

                // Literal match
                if pat_bytes[pi] == text_bytes[ti] {
                    ti += 1;
                    pi += 1;
                    continue;
                }
            }
        }

        // Mismatch — try backtracking to single `*` (no `/` crossing)
        if let Some(sp) = star_pi {
            if star_ti < tlen && text_bytes[star_ti] != b'/' {
                star_ti += 1;
                ti = star_ti;
                pi = sp;
                continue;
            }
        }

        // Mismatch — try backtracking to `**` (crosses `/`)
        if let Some(dp) = dstar_pi {
            dstar_ti += 1;
            if dstar_ti <= tlen {
                ti = dstar_ti;
                pi = dp;
                star_pi = None; // reset single-star
                continue;
            }
        }

        return false;
    }

    true
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
            max_concurrent_validations: default_max_concurrent_validations(),
            validation_delay_ms: default_validation_delay_ms(),
            validation_max_retries: default_validation_max_retries(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.warn_empty_allowlist_rules();
        Ok(config)
    }

    /// Load configuration from a YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.warn_empty_allowlist_rules();
        Ok(config)
    }

    /// Emit a warning for any allowlist rule that has no filtering criteria.
    /// Such rules are ignored at match time to prevent silent suppression of
    /// all findings (a common misconfiguration).
    fn warn_empty_allowlist_rules(&self) {
        for (i, rule) in self.allowlist.iter().enumerate() {
            if rule.has_no_criteria() {
                let desc = rule
                    .description
                    .as_deref()
                    .unwrap_or("<no description>");
                eprintln!(
                    "warning: allowlist rule #{} ({}) has no criteria (secret_types, paths, \
                     value_regex, severities are all empty) -- this rule will be ignored. \
                     Specify at least one criterion.",
                    i + 1,
                    desc,
                );
            }
        }
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
            paths: vec!["tests/**/*".to_string()],
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
    fn test_glob_match_single_star() {
        // Single `*` matches within one segment (no `/`)
        assert!(glob_match("tests/fixtures/secret.env", "tests/fixtures/*.env"));
        assert!(glob_match("secret.env", "*.env"));
        assert!(!glob_match("tests/fixtures/secret.env", "tests/*.env")); // * doesn't cross /
        assert!(!glob_match("src/main.rs", "*.py"));
    }

    #[test]
    fn test_glob_match_double_star() {
        // `**` matches across directory boundaries
        assert!(glob_match("foo/bar/baz.js", "**/baz.js"));
        assert!(glob_match("baz.js", "**/baz.js"));
        assert!(glob_match("a/b/c/d/e.txt", "a/**/e.txt"));
        assert!(glob_match("a/e.txt", "a/**/e.txt"));
        assert!(glob_match("tests/fixtures/secret.env", "tests/**/*.env"));
        assert!(glob_match("tests/deep/nested/secret.env", "tests/**/*.env"));
    }

    #[test]
    fn test_glob_match_question_mark() {
        assert!(glob_match("test.rs", "test.?s"));
        assert!(glob_match("test.js", "test.?s"));
        assert!(!glob_match("test.rs", "test.??s"));
    }

    #[test]
    fn test_glob_match_negation() {
        assert!(!glob_match("secret.env", "!*.env"));
        assert!(glob_match("secret.txt", "!*.env"));
    }

    #[test]
    fn test_glob_match_exact() {
        // Full path matches exactly
        assert!(glob_match("src/main.rs", "src/main.rs"));
        // Pattern without `/` matches the filename (gitignore convention)
        assert!(glob_match("src/main.rs", "main.rs"));
        // Pattern with `/` requires path match
        assert!(!glob_match("src/main.rs", "lib/main.rs"));
    }

    #[test]
    fn test_allowlist_empty_rule_never_matches() {
        // A rule with no criteria at all should never suppress anything.
        // This prevents misconfigured rules from acting as wildcards.
        let rule = AllowlistRule {
            description: None,
            secret_types: vec![],
            paths: vec![],
            value_regex: None,
            severities: vec![],
        };
        assert!(rule.has_no_criteria());
        assert!(!rule.matches("AWS Access Key", "src/config.rs", "AKIAIOSFODNN7REAL", "CRITICAL"));
        assert!(!rule.matches("GitHub PAT", "any/path", "any_value", "HIGH"));
    }

    #[test]
    fn test_deny_unknown_fields_rejects_typos() {
        // If a user writes `secret_type` (singular) instead of `secret_types`,
        // deserialization must fail rather than silently ignoring the field.
        let bad_toml = r#"
            [[allowlist]]
            secret_type = "Generic High Entropy"
            file_path = "*.lock"
        "#;
        let result: std::result::Result<Config, _> = toml::from_str(bad_toml);
        assert!(
            result.is_err(),
            "Config with unknown fields should fail to parse"
        );
    }
}
