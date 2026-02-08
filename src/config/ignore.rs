use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Manages ignore patterns similar to .gitignore, with fingerprint allowlisting.
pub struct IgnoreManager {
    patterns: HashSet<String>,
    path_patterns: HashSet<PathBuf>,
    /// SHA-256 fingerprint hashes to allowlist (from baseline or .leaktorignore).
    fingerprints: HashSet<String>,
}

impl IgnoreManager {
    pub fn new() -> Self {
        Self {
            patterns: HashSet::new(),
            path_patterns: HashSet::new(),
            fingerprints: HashSet::new(),
        }
    }

    /// Load ignore patterns from a .leaktorignore file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let mut manager = Self::new();

        if path.exists() {
            let content = fs::read_to_string(path)?;
            for line in content.lines() {
                let line = line.trim();

                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // Fingerprint allowlist: lines starting with "fingerprint:" or hex-only 64-char strings
                if let Some(fp) = line.strip_prefix("fingerprint:") {
                    let fp = fp.trim();
                    if !fp.is_empty() {
                        manager.fingerprints.insert(fp.to_string());
                    }
                } else if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
                    // A bare 64-character hex string is treated as a fingerprint
                    manager.fingerprints.insert(line.to_string());
                } else {
                    manager.add_pattern(line.to_string());
                }
            }
        }

        Ok(manager)
    }

    /// Add an ignore pattern
    pub fn add_pattern(&mut self, pattern: String) {
        self.patterns.insert(pattern);
    }

    /// Add a specific path to ignore
    pub fn add_path(&mut self, path: PathBuf) {
        self.path_patterns.insert(path);
    }

    /// Add a fingerprint to the allowlist
    pub fn add_fingerprint(&mut self, fingerprint: String) {
        self.fingerprints.insert(fingerprint);
    }

    /// Check if a finding should be ignored based on file patterns or inline comments.
    pub fn should_ignore(&self, file_path: &Path, line_content: &str) -> bool {
        // Check if file path matches any pattern
        let path_str = file_path.to_string_lossy();
        for pattern in &self.patterns {
            if self.matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        // Check if path is specifically ignored
        if self.path_patterns.contains(file_path) {
            return true;
        }

        // Check for inline ignore comments
        if self.has_inline_ignore(line_content) {
            return true;
        }

        false
    }

    /// Check if a fingerprint is in the allowlist.
    pub fn should_ignore_fingerprint(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Check if line has an inline ignore comment
    fn has_inline_ignore(&self, line: &str) -> bool {
        line.contains("leaktor:ignore")
            || line.contains("leaktor-ignore")
            || line.contains("@leaktor-ignore")
    }

    /// Simple pattern matching (basic wildcard support)
    fn matches_pattern(&self, text: &str, pattern: &str) -> bool {
        if pattern.contains('*') {
            // Simple wildcard matching
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.is_empty() {
                return false;
            }

            let mut pos = 0;
            for (i, part) in parts.iter().enumerate() {
                if i == 0 && !part.is_empty() {
                    // First part must match the beginning
                    if !text[pos..].starts_with(part) {
                        return false;
                    }
                    pos += part.len();
                } else if i == parts.len() - 1 && !part.is_empty() {
                    // Last part must match the end
                    return text.ends_with(part);
                } else if !part.is_empty() {
                    // Middle parts must exist somewhere
                    if let Some(found_pos) = text[pos..].find(part) {
                        pos += found_pos + part.len();
                    } else {
                        return false;
                    }
                }
            }
            true
        } else {
            // Exact match
            text.contains(pattern)
        }
    }

    /// Save ignore patterns to a file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut content = String::new();
        content.push_str("# Leaktor ignore patterns\n");
        content.push_str("# Patterns support wildcards (*)\n");
        content.push_str("# Lines starting with # are comments\n");
        content.push_str(
            "# Use fingerprint:<hash> or a bare 64-char hex hash to allowlist by fingerprint\n\n",
        );

        for pattern in &self.patterns {
            content.push_str(pattern);
            content.push('\n');
        }

        if !self.fingerprints.is_empty() {
            content.push_str("\n# Allowlisted fingerprints\n");
            for fp in &self.fingerprints {
                content.push_str(&format!("fingerprint:{}\n", fp));
            }
        }

        fs::write(path, content)?;
        Ok(())
    }
}

impl Default for IgnoreManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_ignore() {
        let manager = IgnoreManager::new();
        assert!(manager.has_inline_ignore("const key = 'secret'; // leaktor:ignore"));
        assert!(manager.has_inline_ignore("# leaktor-ignore"));
        assert!(!manager.has_inline_ignore("const key = 'secret';"));
    }

    #[test]
    fn test_pattern_matching() {
        let manager = IgnoreManager::new();

        assert!(manager.matches_pattern("test/file.txt", "test/*"));
        assert!(manager.matches_pattern("src/main.rs", "*.rs"));
        assert!(manager.matches_pattern("path/to/file.test.js", "*.test.js"));
        assert!(!manager.matches_pattern("src/main.rs", "*.py"));
    }

    #[test]
    fn test_should_ignore() {
        let mut manager = IgnoreManager::new();
        manager.add_pattern("*.test.js".to_string());

        assert!(manager.should_ignore(Path::new("src/auth.test.js"), "const secret = 'test';"));
        assert!(!manager.should_ignore(Path::new("src/auth.js"), "const secret = 'test';"));
    }

    #[test]
    fn test_inline_ignore_detection() {
        let manager = IgnoreManager::new();

        assert!(manager.should_ignore(
            Path::new("test.js"),
            "const key = 'secret'; // leaktor:ignore"
        ));
        assert!(!manager.should_ignore(Path::new("test.js"), "const key = 'secret';"));
    }

    #[test]
    fn test_fingerprint_allowlist() {
        let mut manager = IgnoreManager::new();
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        manager.add_fingerprint(fp.to_string());

        assert!(manager.should_ignore_fingerprint(fp));
        assert!(!manager.should_ignore_fingerprint("deadbeef"));
    }

    #[test]
    fn test_load_fingerprints_from_file() -> Result<()> {
        use tempfile::TempDir;
        let dir = TempDir::new()?;
        let path = dir.path().join(".leaktorignore");

        let content = "# patterns\n*.test.js\n\n# fingerprints\nfingerprint:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\ndeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n";
        fs::write(&path, content)?;

        let manager = IgnoreManager::load_from_file(&path)?;
        assert!(manager.should_ignore_fingerprint(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        ));
        assert!(manager.should_ignore_fingerprint(
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ));
        assert!(manager.should_ignore(Path::new("foo.test.js"), "anything"));
        Ok(())
    }
}
