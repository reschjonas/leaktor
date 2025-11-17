use crate::models::Finding;
use crate::output::OutputFormatter;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub version: String,
    pub scan_date: String,
    pub total_findings: usize,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub validated: usize,
    pub false_positives: usize,
}

pub struct JsonOutput {
    pretty: bool,
}

impl JsonOutput {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }

    fn create_report(&self, findings: &[Finding]) -> JsonReport {
        let summary = self.create_summary(findings);

        JsonReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scan_date: chrono::Utc::now().to_rfc3339(),
            total_findings: findings.len(),
            findings: findings.to_vec(),
            summary,
        }
    }

    fn create_summary(&self, findings: &[Finding]) -> ScanSummary {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut validated = 0;
        let mut false_positives = 0;

        for finding in findings {
            match finding.severity() {
                crate::models::Severity::Critical => critical += 1,
                crate::models::Severity::High => high += 1,
                crate::models::Severity::Medium => medium += 1,
                crate::models::Severity::Low => low += 1,
            }

            if finding.secret.validated == Some(true) {
                validated += 1;
            }

            if finding.is_likely_false_positive() {
                false_positives += 1;
            }
        }

        ScanSummary {
            critical,
            high,
            medium,
            low,
            validated,
            false_positives,
        }
    }
}

impl OutputFormatter for JsonOutput {
    fn format(&self, findings: &[Finding]) -> Result<String> {
        let report = self.create_report(findings);

        let json = if self.pretty {
            serde_json::to_string_pretty(&report)?
        } else {
            serde_json::to_string(&report)?
        };

        Ok(json)
    }

    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()> {
        let json = self.format(findings)?;
        fs::write(path, json)?;
        Ok(())
    }
}

impl Default for JsonOutput {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;
    use std::path::PathBuf;

    fn create_test_finding() -> Finding {
        let secret = Secret::new(
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            4.0,
            Severity::Critical,
            0.9,
        );

        let location = Location {
            file_path: PathBuf::from("test.txt"),
            line_number: 1,
            column_start: 0,
            column_end: 20,
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        };

        let context = Context {
            line_before: None,
            line_content: "AWS_KEY=AKIAIOSFODNN7EXAMPLE".to_string(),
            line_after: None,
            is_test_file: false,
            is_config_file: false,
            is_documentation: false,
            file_extension: Some("txt".to_string()),
        };

        Finding::new(secret, location, context)
    }

    #[test]
    fn test_json_output_format() {
        let output = JsonOutput::new(true);
        let findings = vec![create_test_finding()];
        let result = output.format(&findings);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("total_findings"));
        assert!(json.contains("AWS Access Key"));
    }

    #[test]
    fn test_summary_creation() {
        let output = JsonOutput::new(true);
        let findings = vec![create_test_finding()];
        let summary = output.create_summary(&findings);

        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 0);
    }
}
