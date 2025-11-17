use crate::models::{Context, Severity};
use std::path::Path;

/// Analyzer for understanding the context of a finding
pub struct ContextAnalyzer;

impl ContextAnalyzer {
    /// Analyze file context to determine if it's a test, config, or documentation file
    pub fn analyze_file(file_path: &Path) -> FileContext {
        let path_str = file_path.to_string_lossy().to_lowercase();
        let extension = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let is_test_file = Self::is_test_file(&path_str, &extension);
        let is_config_file = Self::is_config_file(&path_str, &extension);
        let is_documentation = Self::is_documentation(&path_str, &extension);
        let is_example = Self::is_example(&path_str);
        let is_vendor = Self::is_vendor(&path_str);

        FileContext {
            is_test_file,
            is_config_file,
            is_documentation,
            is_example,
            is_vendor,
            file_extension: if extension.is_empty() {
                None
            } else {
                Some(extension)
            },
        }
    }

    fn is_test_file(path: &str, extension: &str) -> bool {
        // Check if in test directories
        let in_test_dir = path.contains("/test/")
            || path.contains("/tests/")
            || path.contains("/spec/")
            || path.contains("/__tests__/")
            || path.contains("/testing/")
            || path.contains("/fixtures/")
            || path.contains("/mocks/");

        // Check filename patterns only (not full path)
        let filename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let test_filename = filename.contains("_test.")
            || filename.contains(".test.")
            || filename.ends_with("_test")
            || filename.starts_with("test_")
            || filename.contains("_spec.")
            || filename.contains(".spec.")
            || extension == "test"
            || extension == "spec";

        in_test_dir || test_filename
    }

    fn is_config_file(path: &str, extension: &str) -> bool {
        matches!(
            extension,
            "yml" | "yaml" | "toml" | "ini" | "conf" | "config" | "properties" | "env" | "json"
        ) || path.contains("/.env")
            || path.contains("config")
            || path.ends_with(".npmrc")
            || path.ends_with(".dockerignore")
            || path.contains("dockerfile")
    }

    fn is_documentation(path: &str, extension: &str) -> bool {
        matches!(extension, "md" | "markdown" | "txt" | "rst" | "adoc")
            || path.contains("/docs/")
            || path.contains("/doc/")
            || path.contains("readme")
            || path.contains("changelog")
            || path.contains("license")
            || path.contains("/examples/")
    }

    fn is_example(path: &str) -> bool {
        path.contains("/example")
            || path.contains("/sample")
            || path.contains("/demo")
            || path.contains("example.")
            || path.contains("sample.")
    }

    fn is_vendor(path: &str) -> bool {
        path.contains("/vendor/")
            || path.contains("/node_modules/")
            || path.contains("/third_party/")
            || path.contains("/external/")
            || path.contains("/.cargo/")
            || path.contains("/target/")
            || path.contains("/build/")
            || path.contains("/dist/")
    }

    /// Build a context object from line information
    pub fn build_context(
        line_content: String,
        line_before: Option<String>,
        line_after: Option<String>,
        file_context: &FileContext,
    ) -> Context {
        Context {
            line_before,
            line_content,
            line_after,
            is_test_file: file_context.is_test_file,
            is_config_file: file_context.is_config_file,
            is_documentation: file_context.is_documentation,
            file_extension: file_context.file_extension.clone(),
        }
    }

    /// Adjust severity based on context
    pub fn adjust_severity(base_severity: Severity, context: &Context) -> Severity {
        // Only lower severity for documentation files
        // Test files can still contain real secrets, so don't downgrade as aggressively
        if context.is_documentation {
            match base_severity {
                Severity::Critical => Severity::High,
                Severity::High => Severity::Medium,
                Severity::Medium => Severity::Low,
                Severity::Low => Severity::Low,
            }
        } else {
            // Don't adjust severity for test files - just flag them in the output
            base_severity
        }
    }

    /// Check if line appears to be a comment
    pub fn is_comment(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("<!--")
    }

    /// Check if line appears to be example/placeholder data
    pub fn is_placeholder(line: &str) -> bool {
        let lower = line.to_lowercase();

        // Strong placeholder indicators - if these appear, it's likely a placeholder
        // But we need to be more careful about partial matches
        let strong_indicators = [
            "your_api_key_here",
            "your_secret_here",
            "your_token_here",
            "your_key_here",
            "your_password_here",
            "replace_with_your",
            "replace_me",
            "replaceme",
            "changeme",
            "change_me",
            "enter_your",
            "insert_your",
            "add_your",
            "<your",
            "todo:",
            "fixme:",
            "placeholder",
        ];

        for indicator in &strong_indicators {
            if lower.contains(indicator) {
                return true;
            }
        }

        // Check for obvious example/dummy patterns in the actual value part
        // Extract potential secret value (after = or : or in quotes)
        let value_part = if let Some(eq_pos) = line.find('=') {
            &line[eq_pos + 1..].trim()
        } else if let Some(colon_pos) = line.find(':') {
            &line[colon_pos + 1..].trim()
        } else {
            line
        };

        let value_lower = value_part.to_lowercase();

        // Only flag as placeholder if the VALUE itself looks like an example
        // Not just if it contains these substrings
        let example_values = [
            "example",
            "sample",
            "dummy",
            "fake",
            "test123",
            "password123",
            "qwerty",
            "xxxxxxxx",
            "00000000",
        ];

        // Check if the value is primarily one of these example patterns
        for example in &example_values {
            // If value is exactly or mostly the example pattern
            if value_lower == *example
                || value_lower.starts_with(&format!("\"{example}"))
                || value_lower.starts_with(&format!("'{example}"))
                || (value_lower.len() < 20 && value_lower.contains(example))
            {
                return true;
            }
        }

        // Check for repeated characters (like "xxxxxx" or "000000")
        // But only in the value part, not the whole line
        Self::has_repeated_pattern(value_part)
    }

    /// Check if string has obvious repeated patterns
    fn has_repeated_pattern(text: &str) -> bool {
        if text.len() < 8 {
            return false;
        }

        // Check for strings with the same character repeated
        let chars: Vec<char> = text.chars().collect();
        let mut same_char_count = 1;
        for i in 1..chars.len() {
            if chars[i] == chars[i - 1] {
                same_char_count += 1;
                if same_char_count >= 5 {
                    return true;
                }
            } else {
                same_char_count = 1;
            }
        }

        // Check for repeated short patterns like "123412341234"
        if text.len() >= 12 {
            for pattern_len in 2..=4 {
                if let Some(pattern) = text.get(0..pattern_len) {
                    let mut matches = 0;
                    for i in (pattern_len..text.len()).step_by(pattern_len) {
                        if text.get(i..i + pattern_len) == Some(pattern) {
                            matches += 1;
                        }
                    }
                    if matches >= 2 {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
pub struct FileContext {
    pub is_test_file: bool,
    pub is_config_file: bool,
    pub is_documentation: bool,
    pub is_example: bool,
    pub is_vendor: bool,
    pub file_extension: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_detect_test_file() {
        let path = PathBuf::from("src/auth/login_test.rs");
        let ctx = ContextAnalyzer::analyze_file(&path);
        assert!(ctx.is_test_file);
    }

    #[test]
    fn test_detect_config_file() {
        let path = PathBuf::from("config/database.yml");
        let ctx = ContextAnalyzer::analyze_file(&path);
        assert!(ctx.is_config_file);
    }

    #[test]
    fn test_detect_documentation() {
        let path = PathBuf::from("docs/README.md");
        let ctx = ContextAnalyzer::analyze_file(&path);
        assert!(ctx.is_documentation);
    }

    #[test]
    fn test_detect_vendor() {
        let path = PathBuf::from("node_modules/package/index.js");
        let ctx = ContextAnalyzer::analyze_file(&path);
        assert!(ctx.is_vendor);
    }

    #[test]
    fn test_is_comment() {
        assert!(ContextAnalyzer::is_comment("// This is a comment"));
        assert!(ContextAnalyzer::is_comment("# This is a comment"));
        assert!(ContextAnalyzer::is_comment("/* Block comment */"));
        assert!(!ContextAnalyzer::is_comment("const value = 123"));
    }

    #[test]
    fn test_is_placeholder() {
        assert!(ContextAnalyzer::is_placeholder("API_KEY=your_api_key_here"));
        assert!(ContextAnalyzer::is_placeholder("password: replace_me"));
        assert!(ContextAnalyzer::is_placeholder("TOKEN=xxxxxxxxxxxxxxxx"));
        assert!(!ContextAnalyzer::is_placeholder(
            "const value = 'actual_secret'"
        ));
    }
}
