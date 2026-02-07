use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Context, Finding, Location};
use anyhow::Result;
use std::io::{self, Read};
use std::path::PathBuf;

/// Scanner that reads from standard input (piped content).
pub struct StdinScanner {
    entropy_threshold: f64,
    /// Optional label for the source (e.g. a filename hint from the user).
    source_label: String,
    custom_patterns: Vec<crate::config::settings::CustomPattern>,
}

impl StdinScanner {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 3.5,
            source_label: "<stdin>".to_string(),
            custom_patterns: Vec::new(),
        }
    }

    pub fn with_custom_patterns(mut self, patterns: Vec<crate::config::settings::CustomPattern>) -> Self {
        self.custom_patterns = patterns;
        self
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    pub fn with_source_label(mut self, label: String) -> Self {
        self.source_label = label;
        self
    }

    pub fn scan(&self) -> Result<Vec<Finding>> {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        self.scan_content(&input)
    }

    /// Scan arbitrary string content (useful for testing without actual stdin).
    pub fn scan_content(&self, content: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let detector = if self.custom_patterns.is_empty() {
            PatternDetector::new()
        } else {
            PatternDetector::with_custom_patterns(&self.custom_patterns)
        };
        let file_path = PathBuf::from(&self.source_label);
        let file_context = ContextAnalyzer::analyze_file(&file_path);
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if ContextAnalyzer::is_placeholder(line) {
                continue;
            }

            if line.len() > 5000 {
                continue;
            }

            let is_comment = ContextAnalyzer::is_comment(line);
            let pattern_matches = detector.scan_line_with_positions(line, self.entropy_threshold);

            for pattern_match in pattern_matches {
                let mut secret = pattern_match.secret;

                if is_comment {
                    secret.confidence *= 0.75;
                }

                let line_before = if line_num > 0 {
                    Some(lines[line_num - 1].to_string())
                } else {
                    None
                };
                let line_after = if line_num + 1 < lines.len() {
                    Some(lines[line_num + 1].to_string())
                } else {
                    None
                };

                secret.severity = ContextAnalyzer::adjust_severity(
                    secret.severity,
                    &Context {
                        line_before: line_before.clone(),
                        line_content: line.to_string(),
                        line_after: line_after.clone(),
                        is_test_file: file_context.is_test_file,
                        is_config_file: file_context.is_config_file,
                        is_documentation: file_context.is_documentation,
                        file_extension: file_context.file_extension.clone(),
                    },
                );

                let location = Location {
                    file_path: file_path.clone(),
                    line_number: line_num + 1,
                    column_start: pattern_match.column_start,
                    column_end: pattern_match.column_end,
                    commit_hash: None,
                    commit_author: None,
                    commit_date: None,
                };

                let context = ContextAnalyzer::build_context(
                    line.to_string(),
                    line_before,
                    line_after,
                    &file_context,
                );

                findings.push(Finding::new(secret, location, context));
            }
        }

        Ok(findings)
    }
}

impl Default for StdinScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdin_scanner_finds_secrets() -> Result<()> {
        let scanner = StdinScanner::new().with_entropy_threshold(3.0);
        let content = "AWS_ACCESS_KEY=AKIAZ52HGXYRN4WBTEST\nsome safe line\n";
        let findings = scanner.scan_content(content)?;
        assert!(!findings.is_empty(), "Should find AWS key in piped content");
        Ok(())
    }

    #[test]
    fn test_stdin_scanner_empty_input() -> Result<()> {
        let scanner = StdinScanner::new();
        let findings = scanner.scan_content("")?;
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn test_stdin_scanner_custom_label() {
        let scanner = StdinScanner::new().with_source_label("piped-file.env".to_string());
        assert_eq!(scanner.source_label, "piped-file.env");
    }
}
