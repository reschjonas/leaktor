use crate::models::{Finding, Severity};
use crate::output::OutputFormatter;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// SARIF (Static Analysis Results Interchange Format) v2.1.0
/// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifReport {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    #[serde(rename = "endColumn")]
    pub end_column: usize,
}

pub struct SarifOutput;

impl SarifOutput {
    pub fn new() -> Self {
        Self
    }

    fn severity_to_level(severity: Severity) -> String {
        match severity {
            Severity::Critical | Severity::High => "error".to_string(),
            Severity::Medium => "warning".to_string(),
            Severity::Low => "note".to_string(),
        }
    }

    fn create_rules(findings: &[Finding]) -> Vec<SarifRule> {
        let mut rules = std::collections::HashMap::new();

        for finding in findings {
            let rule_id = format!(
                "leaktor/{}",
                finding.secret.secret_type.as_str().replace(' ', "-")
            );

            rules.entry(rule_id.clone()).or_insert_with(|| SarifRule {
                id: rule_id.clone(),
                name: finding.secret.secret_type.as_str().to_string(),
                short_description: SarifMessage {
                    text: format!("Detected {}", finding.secret.secret_type.as_str()),
                },
                full_description: SarifMessage {
                    text: format!(
                        "A {} was detected in the code. This could lead to unauthorized access if exposed.",
                        finding.secret.secret_type.as_str()
                    ),
                },
                default_configuration: SarifConfiguration {
                    level: Self::severity_to_level(finding.severity()),
                },
            });
        }

        rules.into_values().collect()
    }

    fn create_report(&self, findings: &[Finding]) -> SarifReport {
        let rules = Self::create_rules(findings);

        let results: Vec<SarifResult> = findings
            .iter()
            .map(|finding| {
                let rule_id = format!(
                    "leaktor/{}",
                    finding.secret.secret_type.as_str().replace(' ', "-")
                );

                SarifResult {
                    rule_id,
                    level: Self::severity_to_level(finding.severity()),
                    message: SarifMessage {
                        text: format!(
                            "Detected {} with confidence {:.0}%",
                            finding.secret.secret_type.as_str(),
                            finding.secret.confidence * 100.0
                        ),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: finding.location.file_path.to_string_lossy().to_string(),
                            },
                            region: SarifRegion {
                                start_line: finding.location.line_number,
                                start_column: finding.location.column_start + 1,
                                end_column: finding.location.column_end + 1,
                            },
                        },
                    }],
                }
            })
            .collect();

        SarifReport {
            version: "2.1.0".to_string(),
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Leaktor".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        information_uri: "https://github.com/reschjonas/leaktor".to_string(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

impl OutputFormatter for SarifOutput {
    fn format(&self, findings: &[Finding]) -> Result<String> {
        let report = self.create_report(findings);
        let json = serde_json::to_string_pretty(&report)?;
        Ok(json)
    }

    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()> {
        let sarif = self.format(findings)?;
        fs::write(path, sarif)?;
        Ok(())
    }
}

impl Default for SarifOutput {
    fn default() -> Self {
        Self::new()
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
    fn test_sarif_output() {
        let output = SarifOutput::new();
        let findings = vec![create_test_finding()];
        let result = output.format(&findings);

        assert!(result.is_ok());
        let sarif = result.unwrap();
        assert!(sarif.contains("2.1.0"));
        assert!(sarif.contains("Leaktor"));
    }
}
