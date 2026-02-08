//! Docker image scanner -- pull an image, export its filesystem, and scan for secrets.
//!
//! Requires the `docker` feature flag (enabled by default) and a running Docker daemon.
//!
//! The scanner:
//!   1. Pulls the image (or uses a locally available one)
//!   2. Creates a temporary container (never started)
//!   3. Exports the container filesystem as a tar stream
//!   4. Extracts text files from the tar and scans them
//!   5. Cleans up the temporary container
//!
//! Usage:
//!   leaktor scan-docker myapp:latest
//!   leaktor scan-docker ghcr.io/org/repo:v1.2.3

use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Context, Finding, Location};
use crate::scan_warn;
use anyhow::Result;
use std::path::PathBuf;

/// Maximum individual file size to scan inside a Docker image (2 MB).
const MAX_FILE_SIZE: usize = 2 * 1024 * 1024;

/// File extensions that are always skipped (binary / non-text).
const BINARY_EXTENSIONS: &[&str] = &[
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "zst", "lz4", "exe", "dll", "so", "dylib",
    "bin", "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "tiff", "avif", "mp3",
    "mp4", "avi", "mov", "mkv", "flac", "wav", "ogg", "webm", "woff", "woff2", "ttf", "eot",
    "otf", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "dat", "db", "sqlite", "sqlite3",
    "parquet", "arrow", "iso", "img", "dmg", "vmdk", "map", "o", "a", "lib", "obj", "class",
    "pyc",
];

/// Paths inside container images that almost never contain user secrets.
const SKIP_PREFIXES: &[&str] = &[
    "usr/share/doc/",
    "usr/share/man/",
    "usr/share/locale/",
    "usr/share/zoneinfo/",
    "usr/share/i18n/",
    "usr/share/terminfo/",
    "usr/lib/",
    "usr/lib64/",
    "lib/",
    "lib64/",
    "proc/",
    "sys/",
    "dev/",
    "run/",
    "var/cache/",
    "var/log/",
];

/// Scanner for Docker container images.
pub struct DockerScanner {
    image: String,
    entropy_threshold: f64,
    custom_patterns: Vec<crate::config::settings::CustomPattern>,
    /// If true, attempt to pull the image before scanning (default: true).
    pull: bool,
}

impl DockerScanner {
    pub fn new(image: String) -> Self {
        Self {
            image,
            entropy_threshold: 3.5,
            custom_patterns: Vec::new(),
            pull: true,
        }
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    pub fn with_custom_patterns(
        mut self,
        patterns: Vec<crate::config::settings::CustomPattern>,
    ) -> Self {
        self.custom_patterns = patterns;
        self
    }

    pub fn with_pull(mut self, pull: bool) -> Self {
        self.pull = pull;
        self
    }

    /// Scan the Docker image and return findings.
    pub async fn scan(&self) -> Result<Vec<Finding>> {
        use bollard::Docker;
        use futures_util::StreamExt;

        let docker = Docker::connect_with_local_defaults()
            .map_err(|e| anyhow::anyhow!("Cannot connect to Docker daemon: {}\nMake sure Docker is running.", e))?;

        // ── 1. Pull image (optional) ────────────────────────────────────────
        if self.pull {
            use bollard::image::CreateImageOptions;
            let (repo, tag) = parse_image_ref(&self.image);
            let opts = CreateImageOptions {
                from_image: repo.clone(),
                tag: tag.clone(),
                ..Default::default()
            };

            let mut stream = docker.create_image(Some(opts), None, None);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(_) => {} // progress info, ignore
                    Err(e) => {
                        // If pull fails and image exists locally, continue anyway
                        scan_warn!("docker", "pull failed for {}: {} (trying local)", self.image, e);
                        break;
                    }
                }
            }
        }

        // ── 2. Create temporary container ───────────────────────────────────
        let container_config = bollard::container::Config {
            image: Some(self.image.clone()),
            // Override entrypoint so create doesn't need to validate CMD
            entrypoint: Some(vec!["/bin/true".to_string()]),
            ..Default::default()
        };

        let container = docker
            .create_container::<String, String>(None, container_config)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Cannot create container from image {}: {}\nIs the image available locally or pullable?",
                    self.image,
                    e
                )
            })?;

        let container_id = container.id.clone();

        // ── 3. Export filesystem and scan ────────────────────────────────────
        let result = self
            .scan_container_export(&docker, &container_id)
            .await;

        // ── 4. Clean up container ───────────────────────────────────────────
        let _ = docker
            .remove_container(
                &container_id,
                Some(bollard::container::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;

        result
    }

    /// Export a container's filesystem as tar and scan each text file entry.
    async fn scan_container_export(
        &self,
        docker: &bollard::Docker,
        container_id: &str,
    ) -> Result<Vec<Finding>> {
        use futures_util::StreamExt;

        let detector = if self.custom_patterns.is_empty() {
            PatternDetector::new()
        } else {
            PatternDetector::with_custom_patterns(&self.custom_patterns)
        };

        // Collect the export stream into a single byte buffer.
        // Docker export produces a tar archive of the full filesystem.
        let mut tar_bytes: Vec<u8> = Vec::new();
        let mut stream = docker.export_container(container_id);
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => tar_bytes.extend_from_slice(&bytes),
                Err(e) => {
                    scan_warn!("docker", "error reading export stream: {}", e);
                    break;
                }
            }
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut archive = tar::Archive::new(tar_bytes.as_slice());

        for entry_result in archive.entries()? {
            let mut entry = match entry_result {
                Ok(e) => e,
                Err(e) => {
                    scan_warn!("docker", "tar entry error: {}", e);
                    continue;
                }
            };

            // Only process regular files
            if entry.header().entry_type() != tar::EntryType::Regular {
                continue;
            }

            let entry_path = match entry.path() {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };

            let path_str = entry_path.to_string_lossy().to_string();

            // Skip known non-interesting system paths
            if SKIP_PREFIXES.iter().any(|pfx| path_str.starts_with(pfx)) {
                continue;
            }

            // Skip binary extensions
            if is_binary_path(&path_str) {
                continue;
            }

            // Skip large files
            let size = entry.header().size().unwrap_or(0) as usize;
            if size > MAX_FILE_SIZE || size == 0 {
                continue;
            }

            // Read content
            use std::io::Read;
            let mut content_bytes = Vec::with_capacity(size);
            if entry.read_to_end(&mut content_bytes).is_err() {
                continue;
            }

            // Skip binary content (null bytes)
            if content_bytes[..content_bytes.len().min(512)].contains(&0u8) {
                continue;
            }

            let content = match String::from_utf8(content_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Build virtual path: docker://image/path/inside/container
            let virtual_path = PathBuf::from(format!("docker://{}/{}", self.image, path_str));

            match self.scan_text_content(&content, &virtual_path, &detector) {
                Ok(file_findings) => findings.extend(file_findings),
                Err(e) => {
                    scan_warn!("docker", "scan error for {}: {}", path_str, e);
                }
            }
        }

        Ok(findings)
    }

    /// Core text scanning logic.
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
}

/// Parse `image:tag` into (image, tag). Defaults tag to "latest".
fn parse_image_ref(image: &str) -> (String, String) {
    // Handle images with digests (image@sha256:...)
    if image.contains('@') {
        return (image.to_string(), String::new());
    }

    // Handle images with registry port (registry:5000/image:tag)
    // Split on the last colon that's not part of a port number
    if let Some(colon_pos) = image.rfind(':') {
        let after = &image[colon_pos + 1..];
        // If the part after : contains a /, it's a registry port, not a tag
        if !after.contains('/') {
            return (
                image[..colon_pos].to_string(),
                after.to_string(),
            );
        }
    }

    (image.to_string(), "latest".to_string())
}

fn is_binary_path(path: &str) -> bool {
    if let Some(dot_pos) = path.rfind('.') {
        let ext = &path[dot_pos + 1..];
        BINARY_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_image_ref_simple() {
        let (repo, tag) = parse_image_ref("nginx:1.25");
        assert_eq!(repo, "nginx");
        assert_eq!(tag, "1.25");
    }

    #[test]
    fn test_parse_image_ref_latest() {
        let (repo, tag) = parse_image_ref("nginx");
        assert_eq!(repo, "nginx");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_parse_image_ref_registry() {
        let (repo, tag) = parse_image_ref("ghcr.io/org/app:v2");
        assert_eq!(repo, "ghcr.io/org/app");
        assert_eq!(tag, "v2");
    }

    #[test]
    fn test_parse_image_ref_registry_port() {
        let (repo, tag) = parse_image_ref("registry:5000/myapp:latest");
        assert_eq!(repo, "registry:5000/myapp");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn test_binary_path_detection() {
        assert!(is_binary_path("usr/bin/app.exe"));
        assert!(is_binary_path("opt/data/image.png"));
        assert!(!is_binary_path("etc/nginx/nginx.conf"));
        assert!(!is_binary_path("app/config.yaml"));
    }
}
