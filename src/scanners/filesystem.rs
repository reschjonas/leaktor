use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Finding, Location};
use anyhow::{Context as AnyhowContext, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

pub struct FilesystemScanner {
    root_path: PathBuf,
    entropy_threshold: f64,
    max_file_size: u64,
    respect_gitignore: bool,
}

impl FilesystemScanner {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            entropy_threshold: 3.5,
            max_file_size: 1024 * 1024, // 1MB
            respect_gitignore: true,
        }
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn with_gitignore(mut self, respect: bool) -> Self {
        self.respect_gitignore = respect;
        self
    }

    pub fn scan(&self) -> Result<Vec<Finding>> {
        let files = self.collect_files()?;

        // Scan files in parallel using rayon
        let findings: Vec<Finding> = files
            .par_iter()
            .flat_map(|file_path| self.scan_file(file_path).unwrap_or_default())
            .collect();

        Ok(findings)
    }

    fn collect_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        let walker = WalkBuilder::new(&self.root_path)
            .git_ignore(self.respect_gitignore)
            .git_global(self.respect_gitignore)
            .git_exclude(self.respect_gitignore)
            .hidden(false)
            .build();

        for entry in walker {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Check file size
            if let Ok(metadata) = fs::metadata(path) {
                if metadata.len() > self.max_file_size {
                    continue;
                }
            }

            // Skip binary files (basic check)
            if self.is_likely_binary(path) {
                continue;
            }

            // Skip vendor directories
            let file_context = ContextAnalyzer::analyze_file(path);
            if file_context.is_vendor {
                continue;
            }

            files.push(path.to_path_buf());
        }

        Ok(files)
    }

    fn scan_file(&self, file_path: &PathBuf) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        let lines: Vec<&str> = content.lines().collect();
        let detector = PatternDetector::new();
        let file_context = ContextAnalyzer::analyze_file(file_path);

        for (line_num, line) in lines.iter().enumerate() {
            // Skip obvious placeholders
            if ContextAnalyzer::is_placeholder(line) {
                continue;
            }

            // Check if line is a comment (but don't skip - just flag it)
            let is_comment = ContextAnalyzer::is_comment(line);

            let secrets = detector.scan_line(line, self.entropy_threshold);

            for mut secret in secrets {
                // Lower confidence for secrets in comments (but still report them)
                if is_comment {
                    secret.confidence *= 0.75;
                }
                // Adjust severity based on context
                secret.severity = ContextAnalyzer::adjust_severity(
                    secret.severity,
                    &Context {
                        line_before: if line_num > 0 {
                            Some(lines[line_num - 1].to_string())
                        } else {
                            None
                        },
                        line_content: line.to_string(),
                        line_after: if line_num + 1 < lines.len() {
                            Some(lines[line_num + 1].to_string())
                        } else {
                            None
                        },
                        is_test_file: file_context.is_test_file,
                        is_config_file: file_context.is_config_file,
                        is_documentation: file_context.is_documentation,
                        file_extension: file_context.file_extension.clone(),
                    },
                );

                let location = Location {
                    file_path: file_path.clone(),
                    line_number: line_num + 1,
                    column_start: 0,
                    column_end: line.len(),
                    commit_hash: None,
                    commit_author: None,
                    commit_date: None,
                };

                let context = ContextAnalyzer::build_context(
                    line.to_string(),
                    if line_num > 0 {
                        Some(lines[line_num - 1].to_string())
                    } else {
                        None
                    },
                    if line_num + 1 < lines.len() {
                        Some(lines[line_num + 1].to_string())
                    } else {
                        None
                    },
                    &file_context,
                );

                let finding = Finding::new(secret, location, context);
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn is_likely_binary(&self, path: &Path) -> bool {
        let binary_extensions = [
            "exe", "dll", "so", "dylib", "bin", "dat", "db", "sqlite", "jpg", "jpeg", "png", "gif",
            "bmp", "ico", "pdf", "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "mp3", "mp4", "avi",
            "mov", "woff", "woff2", "ttf", "eot", "otf", "class", "pyc", "o", "a", "lib", "obj",
        ];

        if let Some(ext) = path.extension() {
            if let Some(ext_str) = ext.to_str() {
                return binary_extensions.contains(&ext_str.to_lowercase().as_str());
            }
        }

        false
    }

    /// Get statistics about the scan
    pub fn get_stats(&self) -> Result<ScanStats> {
        let files = self.collect_files()?;
        let total_size: u64 = files
            .iter()
            .filter_map(|f| fs::metadata(f).ok())
            .map(|m| m.len())
            .sum();

        Ok(ScanStats {
            total_files: files.len(),
            total_size,
        })
    }
}

// Need to import Context for the adjust_severity call
use crate::models::Context;

#[derive(Debug)]
pub struct ScanStats {
    pub total_files: usize,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_filesystem_scanner_creation() {
        let scanner = FilesystemScanner::new(PathBuf::from("."));
        assert_eq!(scanner.entropy_threshold, 3.5);
        assert!(scanner.respect_gitignore);
    }

    #[test]
    fn test_scan_file_with_secret() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")?;

        let scanner = FilesystemScanner::new(temp_dir.path().to_path_buf());
        let findings = scanner.scan()?;

        assert!(!findings.is_empty());
        Ok(())
    }

    #[test]
    fn test_skip_binary_files() {
        let scanner = FilesystemScanner::new(PathBuf::from("."));
        assert!(scanner.is_likely_binary(&PathBuf::from("test.exe")));
        assert!(scanner.is_likely_binary(&PathBuf::from("image.png")));
        assert!(!scanner.is_likely_binary(&PathBuf::from("code.rs")));
    }
}
