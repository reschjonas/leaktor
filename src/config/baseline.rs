use crate::models::Finding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// A fingerprint uniquely identifying a finding across scans.
/// Based on: secret type + file path + secret value hash.
/// This is stable even when line numbers shift due to edits.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    /// Generate a deterministic fingerprint for a finding.
    pub fn from_finding(finding: &Finding) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(finding.secret.secret_type.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(finding.location.file_path.to_string_lossy().as_bytes());
        hasher.update(b":");
        hasher.update(finding.secret.value.as_bytes());
        let hash = hasher.finalize();
        Self(format!("{:x}", hash))
    }
}

/// An entry in the baseline file representing a known finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: Fingerprint,
    pub secret_type: String,
    pub file_path: String,
    pub line_number: usize,
    pub redacted_value: String,
    /// Optional reason for why this is in the baseline (e.g. "false positive", "will rotate")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The baseline file: a record of known findings to suppress in future scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version for forward compatibility
    pub version: String,
    /// ISO 8601 timestamp of when the baseline was created/updated
    pub generated_at: String,
    /// Total number of entries
    pub count: usize,
    /// The known findings
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    /// Create a new baseline from a set of findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: Fingerprint::from_finding(f),
                secret_type: f.secret.secret_type.as_str().to_string(),
                file_path: f.location.file_path.to_string_lossy().to_string(),
                line_number: f.location.line_number,
                redacted_value: f.secret.redacted_value.clone(),
                reason: None,
            })
            .collect();

        Self {
            version: "1.0".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            count: entries.len(),
            entries,
        }
    }

    /// Load a baseline from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read baseline file: {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse baseline file: {}", path.display()))?;
        Ok(baseline)
    }

    /// Save the baseline to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
            .with_context(|| format!("Failed to write baseline file: {}", path.display()))?;
        Ok(())
    }

    /// Get the set of all fingerprints in this baseline.
    pub fn fingerprints(&self) -> HashSet<Fingerprint> {
        self.entries.iter().map(|e| e.fingerprint.clone()).collect()
    }

    /// Filter findings, removing any that match the baseline.
    /// Returns only the *new* findings not present in the baseline.
    pub fn filter_findings(&self, findings: Vec<Finding>) -> Vec<Finding> {
        let known = self.fingerprints();
        findings
            .into_iter()
            .filter(|f| !known.contains(&Fingerprint::from_finding(f)))
            .collect()
    }

    /// Update the baseline by merging new findings into it.
    /// Existing entries are kept; new entries are appended.
    pub fn update(&mut self, findings: &[Finding]) {
        let known = self.fingerprints();
        for finding in findings {
            let fp = Fingerprint::from_finding(finding);
            if !known.contains(&fp) {
                self.entries.push(BaselineEntry {
                    fingerprint: fp,
                    secret_type: finding.secret.secret_type.as_str().to_string(),
                    file_path: finding.location.file_path.to_string_lossy().to_string(),
                    line_number: finding.location.line_number,
                    redacted_value: finding.secret.redacted_value.clone(),
                    reason: None,
                });
            }
        }
        self.count = self.entries.len();
        self.generated_at = chrono::Utc::now().to_rfc3339();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Context as FindingContext, Location, Secret, SecretType, Severity};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_finding(file: &str, line: usize, value: &str) -> Finding {
        Finding::new(
            Secret::new(
                SecretType::AwsAccessKey,
                value.to_string(),
                4.0,
                Severity::Critical,
                0.95,
            ),
            Location {
                file_path: PathBuf::from(file),
                line_number: line,
                column_start: 0,
                column_end: value.len(),
                commit_hash: None,
                commit_author: None,
                commit_date: None,
            },
            FindingContext {
                line_before: None,
                line_content: format!("AWS_KEY={}", value),
                line_after: None,
                is_test_file: false,
                is_config_file: false,
                is_documentation: false,
                file_extension: Some("rs".to_string()),
            },
        )
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let f2 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(
            Fingerprint::from_finding(&f1),
            Fingerprint::from_finding(&f2)
        );
    }

    #[test]
    fn test_fingerprint_different_for_different_values() {
        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let f2 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7OTHERTK");
        assert_ne!(
            Fingerprint::from_finding(&f1),
            Fingerprint::from_finding(&f2)
        );
    }

    #[test]
    fn test_fingerprint_stable_across_line_changes() {
        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let f2 = make_finding("src/main.rs", 42, "AKIAIOSFODNN7EXAMPLE");
        // Same file + same value = same fingerprint (line number is NOT part of fingerprint)
        assert_eq!(
            Fingerprint::from_finding(&f1),
            Fingerprint::from_finding(&f2)
        );
    }

    #[test]
    fn test_baseline_save_and_load() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("baseline.json");

        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let baseline = Baseline::from_findings(&[f1]);
        baseline.save(&path)?;

        let loaded = Baseline::load(&path)?;
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.version, "1.0");
        Ok(())
    }

    #[test]
    fn test_baseline_filters_known_findings() {
        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let f2 = make_finding("src/config.rs", 5, "AKIAZ52HGXYRN4WBTEST");

        let baseline = Baseline::from_findings(&[f1.clone()]);

        let remaining = baseline.filter_findings(vec![f1, f2]);
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].location.file_path,
            PathBuf::from("src/config.rs")
        );
    }

    #[test]
    fn test_baseline_update_merges() {
        let f1 = make_finding("src/main.rs", 10, "AKIAIOSFODNN7EXAMPLE");
        let f2 = make_finding("src/config.rs", 5, "AKIAZ52HGXYRN4WBTEST");

        let mut baseline = Baseline::from_findings(&[f1.clone()]);
        assert_eq!(baseline.entries.len(), 1);

        baseline.update(&[f1, f2]);
        assert_eq!(baseline.entries.len(), 2);
    }
}
