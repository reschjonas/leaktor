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
}

impl GitScanner {
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            scan_history: true,
            max_depth: None,
            entropy_threshold: 3.5,
        }
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

    pub fn scan(&self) -> Result<Vec<Finding>> {
        let repo = Repository::open(&self.repo_path).context("Failed to open git repository")?;

        let mut findings = Vec::new();

        if self.scan_history {
            findings.extend(self.scan_git_history(&repo)?);
        } else {
            findings.extend(self.scan_working_directory(&repo)?);
        }

        Ok(findings)
    }

    fn scan_git_history(&self, repo: &Repository) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head()?;

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
        let detector = PatternDetector::new();

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

        let filesystem_scanner = crate::scanners::FilesystemScanner::new(workdir.to_path_buf())
            .with_entropy_threshold(self.entropy_threshold);

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

        // Create a test file with a secret
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "AWS_KEY=AKIAIOSFODNN7EXAMPLE")?;

        // Add and commit
        let mut index = repo.index()?;
        index.add_path(Path::new("test.txt"))?;
        index.write()?;

        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = git2::Signature::now("Test", "test@example.com")?;

        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])?;

        Ok((temp_dir, repo))
    }

    #[test]
    fn test_git_scanner_creation() {
        let scanner = GitScanner::new(PathBuf::from("."));
        assert!(scanner.scan_history);
    }
}
