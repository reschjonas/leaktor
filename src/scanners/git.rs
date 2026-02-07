use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Finding, Location};
use anyhow::{Context, Result};
use git2::{Commit, Diff, DiffOptions, Repository};
use std::path::{Path, PathBuf};

pub struct GitScanner {
    repo_path: PathBuf,
    scan_history: bool,
    max_depth: Option<usize>,
    entropy_threshold: f64,
    /// Only scan commits after this commit hash (exclusive).
    since_commit: Option<String>,
    /// Only scan commits in this range: "from..to" (from is exclusive, to is inclusive).
    commit_range: Option<(String, String)>,
    custom_patterns: Vec<crate::config::settings::CustomPattern>,
    include_deps: bool,
}

impl GitScanner {
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            scan_history: true,
            max_depth: None,
            entropy_threshold: 3.5,
            since_commit: None,
            commit_range: None,
            custom_patterns: Vec::new(),
            include_deps: false,
        }
    }

    pub fn with_include_deps(mut self, include: bool) -> Self {
        self.include_deps = include;
        self
    }

    pub fn with_custom_patterns(mut self, patterns: Vec<crate::config::settings::CustomPattern>) -> Self {
        self.custom_patterns = patterns;
        self
    }

    pub fn with_history(mut self, scan_history: bool) -> Self {
        self.scan_history = scan_history;
        self
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    pub fn with_entropy_threshold(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self
    }

    /// Only scan commits after this commit hash (exclusive).
    /// When set, the working directory is still scanned, but git history
    /// only includes commits newer than the specified one.
    pub fn with_since_commit(mut self, commit: String) -> Self {
        self.since_commit = Some(commit);
        self
    }

    /// Only scan commits in a specific range (from_commit..to_commit).
    /// `from` is exclusive, `to` is inclusive. Working directory scan is skipped.
    pub fn with_commit_range(mut self, from: String, to: String) -> Self {
        self.commit_range = Some((from, to));
        self
    }

    pub fn scan(&self) -> Result<Vec<Finding>> {
        let repo = Repository::open(&self.repo_path).context("Failed to open git repository")?;

        let mut findings = Vec::new();

        // When a commit range is specified, only scan that range (no working dir)
        if let Some((ref from, ref to)) = self.commit_range {
            let range_findings = self.scan_commit_range(&repo, from, to)?;
            findings.extend(range_findings);
            return Ok(findings);
        }

        // Always scan current working directory files
        findings.extend(self.scan_working_directory(&repo)?);

        // Additionally scan git history if enabled
        if self.scan_history {
            let history_findings = self.scan_git_history(&repo)?;

            // Deduplicate: only add history findings that aren't already found in current files
            for hf in history_findings {
                let dominated = findings.iter().any(|f: &Finding| {
                    f.location.file_path == hf.location.file_path
                        && f.location.line_number == hf.location.line_number
                        && f.secret.value == hf.secret.value
                });
                if !dominated {
                    findings.push(hf);
                }
            }
        }

        Ok(findings)
    }

    fn scan_git_history(&self, repo: &Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;

        let max_commits = self.max_depth.unwrap_or(usize::MAX);

        // Resolve the --since-commit boundary OID if provided
        let since_oid = if let Some(ref since) = self.since_commit {
            let obj = repo
                .revparse_single(since)
                .with_context(|| format!("Could not resolve commit: {}", since))?;
            Some(obj.id())
        } else {
            None
        };

        for (commit_count, oid) in revwalk.enumerate() {
            if commit_count >= max_commits {
                break;
            }

            let oid = oid?;

            // Stop when we reach the --since-commit boundary
            if let Some(boundary) = since_oid {
                if oid == boundary {
                    break;
                }
            }

            let commit = repo.find_commit(oid)?;
            findings.extend(self.scan_commit(repo, &commit)?);
        }

        Ok(findings)
    }

    /// Scan only the commits in a specific range (from..to).
    /// `from` is exclusive, `to` is inclusive.
    fn scan_commit_range(
        &self,
        repo: &Repository,
        from: &str,
        to: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let from_obj = repo
            .revparse_single(from)
            .with_context(|| format!("Could not resolve commit: {}", from))?;
        let to_obj = repo
            .revparse_single(to)
            .with_context(|| format!("Could not resolve commit: {}", to))?;

        let mut revwalk = repo.revwalk()?;
        revwalk.push(to_obj.id())?;
        revwalk.hide(from_obj.id())?;

        let max_commits = self.max_depth.unwrap_or(usize::MAX);

        for (commit_count, oid) in revwalk.enumerate() {
            if commit_count >= max_commits {
                break;
            }

            let oid = oid?;
            let commit = repo.find_commit(oid)?;
            findings.extend(self.scan_commit(repo, &commit)?);
        }

        Ok(findings)
    }

    fn scan_commit(&self, repo: &Repository, commit: &Commit) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get the commit's tree
        let tree = commit.tree()?;

        // Compare with parent (or empty tree if first commit)
        let parent_tree = if commit.parent_count() > 0 {
            Some(commit.parent(0)?.tree()?)
        } else {
            None
        };

        let mut diff_opts = DiffOptions::new();
        let diff = if let Some(parent_tree) = parent_tree {
            repo.diff_tree_to_tree(Some(&parent_tree), Some(&tree), Some(&mut diff_opts))?
        } else {
            repo.diff_tree_to_tree(None, Some(&tree), Some(&mut diff_opts))?
        };

        // Scan each diff
        findings.extend(self.scan_diff(repo, &diff, commit)?);

        Ok(findings)
    }

    fn scan_diff(&self, _repo: &Repository, diff: &Diff, commit: &Commit) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let detector = if self.custom_patterns.is_empty() {
            PatternDetector::new()
        } else {
            PatternDetector::with_custom_patterns(&self.custom_patterns)
        };

        diff.foreach(
            &mut |delta, _progress| {
                let file_path = delta.new_file().path().unwrap_or(Path::new("unknown"));

                // Skip binary files and files in vendor directories
                let file_context = ContextAnalyzer::analyze_file(file_path);
                if file_context.is_vendor {
                    return true;
                }

                true
            },
            None,
            None,
            Some(&mut |_delta, _hunk, line| {
                let content = String::from_utf8_lossy(line.content());

                // Only scan added lines
                if line.origin() == '+' {
                    let secrets = detector.scan_line(&content, self.entropy_threshold);

                    for secret in secrets {
                        if let Some(path) = _delta.new_file().path() {
                            let file_context = ContextAnalyzer::analyze_file(path);

                            let location = Location {
                                file_path: path.to_path_buf(),
                                line_number: line.new_lineno().unwrap_or(0) as usize,
                                column_start: 0,
                                column_end: content.len(),
                                commit_hash: Some(commit.id().to_string()),
                                commit_author: commit.author().name().map(|s| s.to_string()),
                                commit_date: Some(
                                    chrono::DateTime::from_timestamp(commit.time().seconds(), 0)
                                        .unwrap_or_default(),
                                ),
                            };

                            let context = ContextAnalyzer::build_context(
                                content.to_string(),
                                None,
                                None,
                                &file_context,
                            );

                            let finding = Finding::new(secret, location, context);
                            findings.push(finding);
                        }
                    }
                }

                true
            }),
        )?;

        Ok(findings)
    }

    fn scan_working_directory(&self, repo: &Repository) -> Result<Vec<Finding>> {
        let workdir = repo
            .workdir()
            .context("Repository doesn't have a working directory")?;

        let mut filesystem_scanner = crate::scanners::FilesystemScanner::new(workdir.to_path_buf())
            .with_entropy_threshold(self.entropy_threshold)
            .with_include_deps(self.include_deps);

        if !self.custom_patterns.is_empty() {
            filesystem_scanner = filesystem_scanner.with_custom_patterns(self.custom_patterns.clone());
        }

        filesystem_scanner.scan()
    }

    /// Get list of all commits in the repository
    pub fn get_commits(&self) -> Result<Vec<CommitInfo>> {
        let repo = Repository::open(&self.repo_path)?;
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;

        let mut commits = Vec::new();
        for oid in revwalk {
            let oid = oid?;
            let commit = repo.find_commit(oid)?;

            commits.push(CommitInfo {
                hash: commit.id().to_string(),
                author: commit.author().name().unwrap_or("Unknown").to_string(),
                message: commit.message().unwrap_or("").to_string(),
                timestamp: chrono::DateTime::from_timestamp(commit.time().seconds(), 0)
                    .unwrap_or_default(),
            });
        }

        Ok(commits)
    }
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_repo() -> Result<(TempDir, Repository)> {
        let temp_dir = TempDir::new()?;
        let repo = Repository::init(temp_dir.path())?;

        // Create a test file with a secret (non-example key)
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "AWS_KEY=AKIAZ52HGXYRN4WBTEST")?;

        // Add and commit
        let mut index = repo.index()?;
        index.add_path(Path::new("test.txt"))?;
        index.write()?;

        let tree_id = index.write_tree()?;
        let sig = git2::Signature::now("Test", "test@example.com")?;

        {
            let tree = repo.find_tree(tree_id)?;
            repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])?;
        }

        Ok((temp_dir, repo))
    }

    #[test]
    fn test_git_scanner_creation() {
        let scanner = GitScanner::new(PathBuf::from("."));
        assert!(scanner.scan_history);
    }

    #[test]
    fn test_git_scanner_finds_secrets_in_repo() -> Result<()> {
        let (temp_dir, _repo) = create_test_repo()?;
        let scanner = GitScanner::new(temp_dir.path().to_path_buf())
            .with_history(true)
            .with_entropy_threshold(3.0);
        let findings = scanner.scan()?;
        assert!(!findings.is_empty(), "Should find secrets in git repo");
        Ok(())
    }

    #[test]
    fn test_git_scanner_without_history() -> Result<()> {
        let (temp_dir, _repo) = create_test_repo()?;
        let scanner = GitScanner::new(temp_dir.path().to_path_buf())
            .with_history(false)
            .with_entropy_threshold(3.0);
        let findings = scanner.scan()?;
        assert!(!findings.is_empty(), "Should find secrets in working directory even without history scanning");
        Ok(())
    }

    #[test]
    fn test_git_scanner_with_max_depth() {
        let scanner = GitScanner::new(PathBuf::from("."))
            .with_max_depth(10);
        assert_eq!(scanner.max_depth, Some(10));
    }
}
