//! S3 bucket scanner -- list objects in a bucket and scan text content for secrets.
//!
//! Requires the `s3` feature flag (enabled by default).
//!
//! Authentication uses the standard AWS credential chain:
//!   - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//!   - AWS config files (~/.aws/credentials, ~/.aws/config)
//!   - IAM instance roles / ECS task roles
//!
//! Usage:
//!   leaktor scan-s3 my-bucket --prefix config/ --region us-east-1

use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Context, Finding, Location};
use crate::scan_warn;
use anyhow::Result;
use std::path::PathBuf;

/// Scanner for S3 bucket objects.
pub struct S3Scanner {
    bucket: String,
    prefix: Option<String>,
    region: Option<String>,
    entropy_threshold: f64,
    max_object_size: u64,
    custom_patterns: Vec<crate::config::settings::CustomPattern>,
}

/// File extensions that are always skipped (binary / non-text).
const BINARY_EXTENSIONS: &[&str] = &[
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "zst", "lz4", "exe", "dll", "so", "dylib",
    "bin", "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "tiff", "avif", "mp3",
    "mp4", "avi", "mov", "mkv", "flac", "wav", "ogg", "webm", "woff", "woff2", "ttf", "eot",
    "otf", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "dat", "db", "sqlite", "sqlite3",
    "parquet", "arrow", "iso", "img", "dmg", "vmdk", "map", "o", "a", "lib", "obj", "class",
    "pyc",
];

impl S3Scanner {
    pub fn new(bucket: String) -> Self {
        Self {
            bucket,
            prefix: None,
            region: None,
            entropy_threshold: 3.5,
            max_object_size: 5 * 1024 * 1024, // 5 MB
            custom_patterns: Vec::new(),
        }
    }

    pub fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }

    pub fn with_region(mut self, region: String) -> Self {
        self.region = Some(region);
        self
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    pub fn with_max_object_size(mut self, size: u64) -> Self {
        self.max_object_size = size;
        self
    }

    pub fn with_custom_patterns(
        mut self,
        patterns: Vec<crate::config::settings::CustomPattern>,
    ) -> Self {
        self.custom_patterns = patterns;
        self
    }

    /// Scan the S3 bucket and return findings.
    pub async fn scan(&self) -> Result<Vec<Finding>> {
        let aws_config = self.build_aws_config().await;
        let client = aws_sdk_s3::Client::new(&aws_config);

        let detector = if self.custom_patterns.is_empty() {
            PatternDetector::new()
        } else {
            PatternDetector::with_custom_patterns(&self.custom_patterns)
        };

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut req = client
                .list_objects_v2()
                .bucket(&self.bucket)
                .max_keys(1000);

            if let Some(ref prefix) = self.prefix {
                req = req.prefix(prefix);
            }
            if let Some(ref token) = continuation_token {
                req = req.continuation_token(token);
            }

            let response = req.send().await.map_err(|e| {
                anyhow::anyhow!(
                    "Failed to list objects in s3://{}: {}",
                    self.bucket,
                    e
                )
            })?;

            let contents = response.contents();
            for obj in contents {
                let key = match obj.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };

                // Skip binary / non-text files by extension
                if self.is_binary_key(&key) {
                    continue;
                }

                // Skip objects that are too large
                let size = obj.size().unwrap_or(0) as u64;
                if size > self.max_object_size || size == 0 {
                    continue;
                }

                // Skip "directory markers" (keys ending in /)
                if key.ends_with('/') {
                    continue;
                }

                match self
                    .scan_object(&client, &key, &detector)
                    .await
                {
                    Ok(findings) => all_findings.extend(findings),
                    Err(e) => {
                        scan_warn!("s3", "failed to scan s3://{}/{}: {}", self.bucket, key, e);
                    }
                }
            }

            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(all_findings)
    }

    /// Download and scan a single S3 object.
    async fn scan_object(
        &self,
        client: &aws_sdk_s3::Client,
        key: &str,
        detector: &PatternDetector,
    ) -> Result<Vec<Finding>> {
        let resp = client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;

        let body_bytes = resp.body.collect().await?.into_bytes();

        // Skip binary content (null bytes in first 512 bytes)
        if body_bytes.len() >= 2 && body_bytes[..body_bytes.len().min(512)].contains(&0u8) {
            return Ok(Vec::new());
        }

        let content = match String::from_utf8(body_bytes.to_vec()) {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()), // not UTF-8 → binary
        };

        let virtual_path = PathBuf::from(format!("s3://{}/{}", self.bucket, key));
        self.scan_text_content(&content, &virtual_path, detector)
    }

    /// Core text scanning -- shared logic with other scanners.
    fn scan_text_content(
        &self,
        content: &str,
        virtual_path: &std::path::Path,
        detector: &PatternDetector,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let file_context = ContextAnalyzer::analyze_file(virtual_path);
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if ContextAnalyzer::is_placeholder(line) || line.len() > 5000 {
                continue;
            }

            let is_comment = ContextAnalyzer::is_comment(line);
            let pattern_matches =
                detector.scan_line_with_positions(line, self.entropy_threshold);

            for pm in pattern_matches {
                let mut secret = pm.secret;
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
                    file_path: virtual_path.to_path_buf(),
                    line_number: line_num + 1,
                    column_start: pm.column_start,
                    column_end: pm.column_end,
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

    fn is_binary_key(&self, key: &str) -> bool {
        if let Some(dot_pos) = key.rfind('.') {
            let ext = &key[dot_pos + 1..];
            BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str())
        } else {
            false
        }
    }

    /// Return the number of objects that would be scanned (for progress display).
    pub async fn count_objects(&self) -> Result<usize> {
        let aws_config = self.build_aws_config().await;
        let client = aws_sdk_s3::Client::new(&aws_config);

        let mut count = 0usize;
        let mut continuation_token: Option<String> = None;

        loop {
            let mut req = client
                .list_objects_v2()
                .bucket(&self.bucket)
                .max_keys(1000);
            if let Some(ref prefix) = self.prefix {
                req = req.prefix(prefix);
            }
            if let Some(ref token) = continuation_token {
                req = req.continuation_token(token);
            }
            let response = req.send().await?;

            let contents = response.contents();
            count += contents
                .iter()
                .filter(|o| {
                    let key = o.key().unwrap_or("");
                    let size = o.size().unwrap_or(0) as u64;
                    !key.ends_with('/')
                        && size > 0
                        && size <= self.max_object_size
                        && !self.is_binary_key(key)
                })
                .count();

            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(count)
    }

    /// Build the shared AWS SDK config with optional region override.
    async fn build_aws_config(&self) -> aws_config::SdkConfig {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(ref region) = self.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        loader.load().await
    }
}
