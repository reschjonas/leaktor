use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Finding, Location};
use crate::scan_warn;
use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

pub struct FilesystemScanner {
    root_path: PathBuf,
    entropy_threshold: f64,
    max_file_size: u64,
    respect_gitignore: bool,
    include_deps: bool,
    single_file: bool,
    max_fs_depth: Option<usize>,
    custom_patterns: Vec<crate::config::settings::CustomPattern>,
}

impl FilesystemScanner {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            root_path,
            entropy_threshold: 3.5,
            max_file_size: 1024 * 1024, // 1MB
            respect_gitignore: true,
            include_deps: false,
            single_file: false,
            max_fs_depth: None,
            custom_patterns: Vec::new(),
        }
    }

    pub fn with_custom_patterns(
        mut self,
        patterns: Vec<crate::config::settings::CustomPattern>,
    ) -> Self {
        self.custom_patterns = patterns;
        self
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

    /// Include dependency directories (node_modules, vendor, .venv, etc.)
    pub fn with_include_deps(mut self, include: bool) -> Self {
        self.include_deps = include;
        self
    }

    /// Scan a single file instead of a directory tree
    pub fn with_single_file(mut self, single: bool) -> Self {
        self.single_file = single;
        self
    }

    /// Set maximum filesystem recursion depth (0 = only files in root directory)
    pub fn with_max_fs_depth(mut self, depth: usize) -> Self {
        self.max_fs_depth = Some(depth);
        self
    }

    pub fn scan(&self) -> Result<Vec<Finding>> {
        let files = self.collect_files()?;

        // Pre-build the detector (with custom patterns) for all threads to clone
        let detector = if self.custom_patterns.is_empty() {
            PatternDetector::new()
        } else {
            PatternDetector::with_custom_patterns(&self.custom_patterns)
        };

        // Scan files in parallel using rayon
        let findings: Vec<Finding> = files
            .par_iter()
            .flat_map(|file_path| {
                match self.scan_file(file_path, &detector) {
                    Ok(f) => f,
                    Err(e) => {
                        scan_warn!("fs", "failed to scan {}: {}", file_path.display(), e);
                        Vec::new()
                    }
                }
            })
            .collect();

        Ok(findings)
    }

    fn collect_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        // Single file mode: just return the one file
        if self.single_file && self.root_path.is_file() {
            match fs::metadata(&self.root_path) {
                Ok(metadata) => {
                    if metadata.len() <= self.max_file_size
                        && !self.is_likely_binary(&self.root_path)
                    {
                        files.push(self.root_path.clone());
                    }
                }
                Err(e) => {
                    scan_warn!(
                        "fs",
                        "cannot stat {}: {}",
                        self.root_path.display(),
                        e
                    );
                }
            }
            return Ok(files);
        }

        if self.include_deps {
            // When scanning deps, use walkdir directly to bypass all gitignore filtering.
            // The `ignore` crate's WalkBuilder can filter node_modules/vendor via
            // global rules or built-in heuristics, so we avoid it entirely.
            let mut walk = walkdir::WalkDir::new(&self.root_path);
            if let Some(depth) = self.max_fs_depth {
                walk = walk.max_depth(depth + 1); // +1 because walkdir counts root as depth 0
            }
            for entry in walk
                .into_iter()
                .filter_entry(|e| {
                    // Always skip .git and Rust/build artefact directories
                    let name = e.file_name().to_string_lossy();
                    name != ".git" && name != "target"
                })
            {
                let entry = entry?;
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                match fs::metadata(path) {
                    Ok(metadata) => {
                        if metadata.len() > self.max_file_size {
                            continue;
                        }
                    }
                    Err(e) => {
                        scan_warn!("fs", "cannot stat {}: {}", path.display(), e);
                        continue;
                    }
                }

                if self.is_likely_binary(path) {
                    continue;
                }

                // Don't skip vendor directories (that's the whole point of --include-deps)
                files.push(path.to_path_buf());
            }
        } else {
            let mut builder = WalkBuilder::new(&self.root_path);
            builder
                .git_ignore(self.respect_gitignore)
                .git_global(self.respect_gitignore)
                .git_exclude(self.respect_gitignore)
                .hidden(false);
            if let Some(depth) = self.max_fs_depth {
                builder.max_depth(Some(depth + 1)); // +1 because root is depth 0
            }
            let walker = builder.build();

            for entry in walker {
                let entry = entry?;
                let path = entry.path();

                if !path.is_file() {
                    continue;
                }

                match fs::metadata(path) {
                    Ok(metadata) => {
                        if metadata.len() > self.max_file_size {
                            continue;
                        }
                    }
                    Err(e) => {
                        scan_warn!("fs", "cannot stat {}: {}", path.display(), e);
                        continue;
                    }
                }

                if self.is_likely_binary(path) {
                    continue;
                }

                let file_context = ContextAnalyzer::analyze_file(path);
                if file_context.is_vendor {
                    continue;
                }

                files.push(path.to_path_buf());
            }
        }

        Ok(files)
    }

    fn scan_file(&self, file_path: &PathBuf, detector: &PatternDetector) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Skip files that can't be read as UTF-8 (likely binary)
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                // Distinguish between encoding errors (expected for binary) and
                // real I/O errors (permissions, missing files, etc.)
                if e.kind() == std::io::ErrorKind::PermissionDenied
                    || e.kind() == std::io::ErrorKind::NotFound
                {
                    scan_warn!(
                        "fs",
                        "cannot read {}: {}",
                        file_path.display(),
                        e
                    );
                }
                // InvalidData (UTF-8 decode) is expected for binary files -- skip silently
                return Ok(findings);
            }
        };

        // Skip lockfiles, minified files, and scan output files (high false-positive sources)
        if self.is_lockfile(file_path) || self.is_minified(&content) || self.is_scan_output(file_path) {
            return Ok(findings);
        }

        // Multi-format scanning: decode structured files (K8s secrets, Terraform state, etc.)
        let mut multiformat_findings = Vec::new();
        if let Some(fmt) = super::multiformat::detect_format(file_path, &content) {
            match super::multiformat::scan_structured_file(
                file_path,
                &content,
                fmt,
                detector,
                self.entropy_threshold,
            ) {
                Ok(extra) => multiformat_findings = extra,
                Err(e) => {
                    scan_warn!(
                        "parse",
                        "failed to parse {} as {}: {}",
                        file_path.display(),
                        super::multiformat::format_label(fmt),
                        e
                    );
                }
            }
        }

        let lines: Vec<&str> = content.lines().collect();
        let file_context = ContextAnalyzer::analyze_file(file_path);

        for (line_num, line) in lines.iter().enumerate() {
            // Skip obvious placeholders
            if ContextAnalyzer::is_placeholder(line) {
                continue;
            }

            // Skip extremely long lines (likely minified/generated)
            if line.len() > 5000 {
                continue;
            }

            // Check if line is a comment (but don't skip - just flag it)
            let is_comment = ContextAnalyzer::is_comment(line);

            let pattern_matches = detector.scan_line_with_positions(line, self.entropy_threshold);

            for pattern_match in pattern_matches {
                let mut secret = pattern_match.secret;

                // Lower confidence for secrets in comments (but still report them)
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

                // Adjust severity based on context
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

                let finding = Finding::new(secret, location, context);
                findings.push(finding);
            }
        }

        // Deduplicate: merge multi-format findings with line-by-line findings.
        // If a multi-format finding has the same secret value as a line-by-line finding
        // in the same file, keep the one with richer context (multi-format) and drop the
        // line-by-line duplicate. If no overlap, add the multi-format finding.
        for mf in multiformat_findings {
            let is_duplicate = findings.iter().any(|f| {
                f.secret.value == mf.secret.value
                    && f.location.file_path == mf.location.file_path
            });
            if !is_duplicate {
                findings.push(mf);
            }
        }

        Ok(findings)
    }

    fn is_lockfile(&self, path: &Path) -> bool {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let lockfiles = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "Gemfile.lock",
            "poetry.lock",
            "Pipfile.lock",
            "composer.lock",
            "go.sum",
            "flake.lock",
            "pubspec.lock",
            "packages.lock.json",
            "bun.lockb",
        ];
        lockfiles.contains(&filename)
    }

    /// Check if file is a scan output file (HTML reports, SARIF results, etc.)
    /// that should be excluded to prevent re-scanning previous scan results.
    fn is_scan_output(&self, path: &Path) -> bool {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Skip by extension
        if ext == "sarif" {
            return true;
        }

        // Skip known scan output filenames
        let output_filenames = [
            "leaktor-report.html",
            "report.html",
            "results.json",
            "results.sarif",
            "scan.json",
            "scan-results.json",
            "leaktor-results.json",
        ];
        if output_filenames.contains(&filename) {
            return true;
        }

        // Detect leaktor JSON output files by content signature.
        // Leaktor JSON output starts with `{"version": "X.Y.Z", ...` and
        // contains `"total_findings"` and `"findings"` in the header, which
        // is a schema combination unlikely to appear in user source files.
        if ext == "json" {
            if let Ok(content) = fs::read_to_string(path) {
                // Check the first 300 bytes for the leaktor schema signature
                let header: String = content.chars().take(300).collect();
                if header.contains("\"version\"")
                    && header.contains("\"total_findings\"")
                    && header.contains("\"findings\"")
                {
                    return true;
                }
            }
        }

        false
    }

    fn is_minified(&self, content: &str) -> bool {
        // Check if first non-empty line is extremely long (likely minified)
        if let Some(first_line) = content.lines().next() {
            if first_line.len() > 10_000 {
                return true;
            }
        }
        // Check average line length - minified files have very long lines
        let line_count = content.lines().count();
        if line_count > 0 && line_count < 10 && content.len() > 50_000 {
            return true;
        }
        false
    }

    fn is_likely_binary(&self, path: &Path) -> bool {
        let binary_extensions = [
            // Executables & Libraries
            "exe", "dll", "so", "dylib", "bin", "com", "msi", // Object files
            "o", "a", "lib", "obj", "class", "pyc", "pyo", "elc", "beam", // Archives
            "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "zst", "lz4", "lzma",
            // Images
            "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp", "tiff", "avif",
            // Audio/Video
            "mp3", "mp4", "avi", "mov", "mkv", "flac", "wav", "ogg", "webm", // Fonts
            "woff", "woff2", "ttf", "eot", "otf", // Documents
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", // Data
            "dat", "db", "sqlite", "sqlite3", "mdb", "parquet", "arrow", // Disk images
            "iso", "img", "dmg", "vmdk", // Source maps (high false-positive)
            "map",
        ];

        if let Some(ext) = path.extension() {
            if let Some(ext_str) = ext.to_str() {
                if binary_extensions.contains(&ext_str.to_lowercase().as_str()) {
                    return true;
                }
            }
        }

        // Content sniffing: read first 512 bytes and check for null bytes
        match fs::File::open(path) {
            Ok(file) => {
                use std::io::Read;
                let mut buffer = [0u8; 512];
                let mut reader = std::io::BufReader::new(file);
                match reader.read(&mut buffer) {
                    Ok(n) => {
                        if buffer[..n].contains(&0) {
                            return true;
                        }
                    }
                    Err(e) => {
                        scan_warn!("fs", "cannot read {}: {}", path.display(), e);
                    }
                }
            }
            Err(e) => {
                scan_warn!("fs", "cannot open {}: {}", path.display(), e);
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
        // Use a realistic-looking (but still fake) key, not the AWS documentation example
        fs::write(&file_path, "AWS_ACCESS_KEY=AKIAZ52HGXYRN4WBTEST")?;

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
