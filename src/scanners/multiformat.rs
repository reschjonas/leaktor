//! Multi-format scanning: decode and scan secrets in structured files.
//!
//! Supported formats:
//!   - Terraform state files (`.tfstate`) -- base64-encoded values
//!   - Kubernetes secrets (`kind: Secret`)  -- base64 `.data` values
//!   - Docker Compose / docker-compose.yml -- `environment:` values
//!   - AWS CloudFormation templates        -- `Parameters`/`Default` secrets
//!
//! The scanner operates on a single file and returns additional findings that
//! would normally be hidden inside base64 blobs or nested YAML/JSON.

use crate::detectors::{ContextAnalyzer, PatternDetector};
use crate::models::{Context, Finding, Location};
use anyhow::Result;
use std::path::Path;

/// Identifies the structured format of a file (if any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuredFormat {
    TerraformState,
    KubernetesSecret,
    DockerCompose,
    CloudFormation,
}

/// Detect the structured format of a file based on filename and content peek.
pub fn detect_format(path: &Path, content: &str) -> Option<StructuredFormat> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Terraform state
    if name.ends_with(".tfstate") || name.ends_with(".tfstate.backup") {
        return Some(StructuredFormat::TerraformState);
    }

    // Kubernetes Secret manifest
    if (ext == "yaml" || ext == "yml" || ext == "json")
        && content.contains("kind:")
        && content.contains("Secret")
        && content.contains("data:")
    {
        return Some(StructuredFormat::KubernetesSecret);
    }

    // Docker Compose
    if (name.starts_with("docker-compose") || name.starts_with("compose"))
        && (ext == "yml" || ext == "yaml")
    {
        return Some(StructuredFormat::DockerCompose);
    }

    // CloudFormation
    if (ext == "yaml" || ext == "yml" || ext == "json" || ext == "template")
        && (content.contains("AWSTemplateFormatVersion")
            || content.contains("aws-template-format-version")
            || (content.contains("Resources")
                && (content.contains("AWS::") || content.contains("aws::"))))
    {
        return Some(StructuredFormat::CloudFormation);
    }

    None
}

/// Scan a structured file, returning additional findings from decoded values.
pub fn scan_structured_file(
    path: &Path,
    content: &str,
    format: StructuredFormat,
    detector: &PatternDetector,
    entropy_threshold: f64,
) -> Result<Vec<Finding>> {
    match format {
        StructuredFormat::TerraformState => scan_terraform_state(path, content, detector, entropy_threshold),
        StructuredFormat::KubernetesSecret => scan_kubernetes_secret(path, content, detector, entropy_threshold),
        StructuredFormat::DockerCompose => scan_docker_compose(path, content, detector, entropy_threshold),
        StructuredFormat::CloudFormation => scan_cloudformation(path, content, detector, entropy_threshold),
    }
}

// ── Terraform state ──────────────────────────────────────────────────────────

fn scan_terraform_state(
    path: &Path,
    content: &str,
    detector: &PatternDetector,
    entropy_threshold: f64,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Parse as JSON
    let value: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return Ok(findings),
    };

    // Recursively walk all string values looking for secrets
    let file_context = ContextAnalyzer::analyze_file(path);
    walk_json_values(&value, path, &file_context, detector, entropy_threshold, &mut findings, "");

    // Also look for base64-encoded blobs and decode them
    walk_json_decode_base64(&value, path, &file_context, detector, entropy_threshold, &mut findings);

    Ok(findings)
}

fn walk_json_values(
    value: &serde_json::Value,
    path: &Path,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
    json_path: &str,
) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() < 8 || s.len() > 5000 {
                return;
            }
            let matches = detector.scan_line_with_positions(s, entropy_threshold);
            for m in matches {
                let context = Context {
                    line_before: Some(format!("JSON path: {}", json_path)),
                    line_content: truncate_for_context(s),
                    line_after: None,
                    is_test_file: file_context.is_test_file,
                    is_config_file: true,
                    is_documentation: false,
                    file_extension: file_context.file_extension.clone(),
                };
                let location = Location {
                    file_path: path.to_path_buf(),
                    line_number: 1,
                    column_start: m.column_start,
                    column_end: m.column_end,
                    commit_hash: None,
                    commit_author: None,
                    commit_date: None,
                };
                findings.push(Finding::new(m.secret, location, context));
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let child_path = if json_path.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", json_path, k)
                };
                walk_json_values(v, path, file_context, detector, entropy_threshold, findings, &child_path);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", json_path, i);
                walk_json_values(v, path, file_context, detector, entropy_threshold, findings, &child_path);
            }
        }
        _ => {}
    }
}

fn walk_json_decode_base64(
    value: &serde_json::Value,
    path: &Path,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
) {
    use base64::Engine as _;
    match value {
        serde_json::Value::String(s) => {
            // Try base64 decode
            if s.len() >= 16 && looks_like_base64(s) {
                if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
                    if let Ok(decoded) = String::from_utf8(decoded_bytes) {
                        if decoded.len() >= 8 {
                            let matches = detector.scan_line_with_positions(&decoded, entropy_threshold);
                            for m in matches {
                                let context = Context {
                                    line_before: Some("[base64 decoded]".to_string()),
                                    line_content: truncate_for_context(&decoded),
                                    line_after: None,
                                    is_test_file: file_context.is_test_file,
                                    is_config_file: true,
                                    is_documentation: false,
                                    file_extension: file_context.file_extension.clone(),
                                };
                                let location = Location {
                                    file_path: path.to_path_buf(),
                                    line_number: 1,
                                    column_start: m.column_start,
                                    column_end: m.column_end,
                                    commit_hash: None,
                                    commit_author: None,
                                    commit_date: None,
                                };
                                findings.push(Finding::new(m.secret, location, context));
                            }
                        }
                    }
                }
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                walk_json_decode_base64(v, path, file_context, detector, entropy_threshold, findings);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                walk_json_decode_base64(v, path, file_context, detector, entropy_threshold, findings);
            }
        }
        _ => {}
    }
}

// ── Kubernetes Secret ────────────────────────────────────────────────────────

fn scan_kubernetes_secret(
    path: &Path,
    content: &str,
    detector: &PatternDetector,
    entropy_threshold: f64,
) -> Result<Vec<Finding>> {
    use base64::Engine as _;
    let mut findings = Vec::new();
    let file_context = ContextAnalyzer::analyze_file(path);

    // Parse as YAML (may have multiple documents)
    for doc in serde_yaml::Deserializer::from_str(content) {
        let value: serde_yaml::Value = match serde_yaml::Value::deserialize(doc) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check if this doc is a K8s Secret
        let kind = value.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if kind != "Secret" {
            continue;
        }

        // Decode .data values
        if let Some(data) = value.get("data").and_then(|d| d.as_mapping()) {
            for (key, val) in data {
                let key_str = key.as_str().unwrap_or("unknown");
                let val_str = match val.as_str() {
                    Some(s) => s,
                    None => continue,
                };

                // Decode base64
                let decoded = match base64::engine::general_purpose::STANDARD.decode(val_str.trim()) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                if decoded.len() < 4 {
                    continue;
                }

                let matches = detector.scan_line_with_positions(&decoded, entropy_threshold);
                for m in matches {
                    let line_num = find_line_number(content, val_str);
                    let context = Context {
                        line_before: Some(format!("K8s Secret .data.{} [base64 decoded]", key_str)),
                        line_content: truncate_for_context(&decoded),
                        line_after: None,
                        is_test_file: file_context.is_test_file,
                        is_config_file: true,
                        is_documentation: false,
                        file_extension: file_context.file_extension.clone(),
                    };
                    let location = Location {
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                        column_start: m.column_start,
                        column_end: m.column_end,
                        commit_hash: None,
                        commit_author: None,
                        commit_date: None,
                    };
                    findings.push(Finding::new(m.secret, location, context));
                }
            }
        }

        // Also check .stringData (plaintext, no decoding needed -- already handled by normal scan)
    }

    Ok(findings)
}

// ── Docker Compose ───────────────────────────────────────────────────────────

fn scan_docker_compose(
    path: &Path,
    content: &str,
    detector: &PatternDetector,
    entropy_threshold: f64,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let file_context = ContextAnalyzer::analyze_file(path);

    let value: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(v) => v,
        Err(_) => return Ok(findings),
    };

    // Walk services -> each service -> environment
    if let Some(services) = value.get("services").and_then(|s| s.as_mapping()) {
        for (_svc_name, svc_val) in services {
            if let Some(env) = svc_val.get("environment") {
                scan_compose_environment(path, content, env, &file_context, detector, entropy_threshold, &mut findings);
            }
        }
    }

    Ok(findings)
}

fn scan_compose_environment(
    path: &Path,
    content: &str,
    env: &serde_yaml::Value,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
) {
    match env {
        // Mapping style: environment: { KEY: value }
        serde_yaml::Value::Mapping(map) => {
            for (key, val) in map {
                let key_str = key.as_str().unwrap_or("unknown");
                let val_str = match val.as_str() {
                    Some(s) => s,
                    None => continue,
                };

                // Combine key=value for scanning (catches patterns like 'AWS_KEY=AKIA...')
                let combined = format!("{}={}", key_str, val_str);
                let matches = detector.scan_line_with_positions(&combined, entropy_threshold);
                for m in matches {
                    let line_num = find_line_number(content, val_str);
                    let context = Context {
                        line_before: Some(format!("Docker Compose environment: {}", key_str)),
                        line_content: truncate_for_context(&combined),
                        line_after: None,
                        is_test_file: file_context.is_test_file,
                        is_config_file: true,
                        is_documentation: false,
                        file_extension: file_context.file_extension.clone(),
                    };
                    let location = Location {
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                        column_start: m.column_start,
                        column_end: m.column_end,
                        commit_hash: None,
                        commit_author: None,
                        commit_date: None,
                    };
                    findings.push(Finding::new(m.secret, location, context));
                }
            }
        }
        // List style: environment: [ "KEY=value" ]
        serde_yaml::Value::Sequence(list) => {
            for item in list {
                let val_str = match item.as_str() {
                    Some(s) => s,
                    None => continue,
                };
                let matches = detector.scan_line_with_positions(val_str, entropy_threshold);
                for m in matches {
                    let line_num = find_line_number(content, val_str);
                    let context = Context {
                        line_before: Some("Docker Compose environment list".to_string()),
                        line_content: truncate_for_context(val_str),
                        line_after: None,
                        is_test_file: file_context.is_test_file,
                        is_config_file: true,
                        is_documentation: false,
                        file_extension: file_context.file_extension.clone(),
                    };
                    let location = Location {
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                        column_start: m.column_start,
                        column_end: m.column_end,
                        commit_hash: None,
                        commit_author: None,
                        commit_date: None,
                    };
                    findings.push(Finding::new(m.secret, location, context));
                }
            }
        }
        _ => {}
    }
}

// ── CloudFormation ───────────────────────────────────────────────────────────

fn scan_cloudformation(
    path: &Path,
    content: &str,
    detector: &PatternDetector,
    entropy_threshold: f64,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let file_context = ContextAnalyzer::analyze_file(path);

    // Try JSON first, then YAML
    let value: serde_json::Value = if let Ok(v) = serde_json::from_str(content) {
        v
    } else if let Ok(yaml_val) = serde_yaml::from_str::<serde_yaml::Value>(content) {
        // Convert YAML to JSON for uniform handling
        match serde_json::to_value(yaml_val) {
            Ok(v) => v,
            Err(_) => return Ok(findings),
        }
    } else {
        return Ok(findings);
    };

    // Scan Parameters for Default values
    if let Some(params) = value.get("Parameters").and_then(|p| p.as_object()) {
        for (param_name, param_val) in params {
            if let Some(default) = param_val.get("Default").and_then(|d| d.as_str()) {
                let matches = detector.scan_line_with_positions(default, entropy_threshold);
                for m in matches {
                    let line_num = find_line_number(content, default);
                    let context = Context {
                        line_before: Some(format!("CloudFormation Parameter: {}", param_name)),
                        line_content: truncate_for_context(default),
                        line_after: None,
                        is_test_file: file_context.is_test_file,
                        is_config_file: true,
                        is_documentation: false,
                        file_extension: file_context.file_extension.clone(),
                    };
                    let location = Location {
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                        column_start: m.column_start,
                        column_end: m.column_end,
                        commit_hash: None,
                        commit_author: None,
                        commit_date: None,
                    };
                    findings.push(Finding::new(m.secret, location, context));
                }
            }
        }
    }

    // Recursively scan Resources for hardcoded secrets in properties
    if let Some(resources) = value.get("Resources") {
        walk_json_values(resources, path, &file_context, detector, entropy_threshold, &mut findings, "Resources");
    }

    Ok(findings)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn truncate_for_context(s: &str) -> String {
    if s.len() <= 120 {
        s.to_string()
    } else {
        format!("{}...", &s[..117])
    }
}

fn find_line_number(content: &str, needle: &str) -> usize {
    if let Some(pos) = content.find(needle) {
        content[..pos].lines().count() + 1
    } else {
        1
    }
}

fn looks_like_base64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    let trimmed = s.trim();
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r')
}

use serde::Deserialize;

// Re-export for other modules
pub fn format_label(fmt: StructuredFormat) -> &'static str {
    match fmt {
        StructuredFormat::TerraformState => "Terraform state",
        StructuredFormat::KubernetesSecret => "Kubernetes Secret",
        StructuredFormat::DockerCompose => "Docker Compose",
        StructuredFormat::CloudFormation => "CloudFormation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_terraform_state() {
        let path = Path::new("terraform.tfstate");
        assert_eq!(detect_format(path, "{}"), Some(StructuredFormat::TerraformState));
    }

    #[test]
    fn test_detect_kubernetes_secret() {
        let path = Path::new("secret.yaml");
        let content = "apiVersion: v1\nkind: Secret\ndata:\n  password: cGFzc3dvcmQ=";
        assert_eq!(detect_format(path, content), Some(StructuredFormat::KubernetesSecret));
    }

    #[test]
    fn test_detect_docker_compose() {
        let path = Path::new("docker-compose.yml");
        assert_eq!(detect_format(path, "services:"), Some(StructuredFormat::DockerCompose));
    }

    #[test]
    fn test_detect_cloudformation() {
        let path = Path::new("template.yaml");
        let content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:";
        assert_eq!(detect_format(path, content), Some(StructuredFormat::CloudFormation));
    }

    #[test]
    fn test_detect_normal_file() {
        let path = Path::new("main.rs");
        assert_eq!(detect_format(path, "fn main() {}"), None);
    }

    #[test]
    fn test_k8s_secret_base64_decode() {
        let content = r#"apiVersion: v1
kind: Secret
metadata:
  name: test-secret
data:
  aws_key: QUtJQVo1MkhHWFlSTjRXQlRFU1Q=
"#;
        let path = Path::new("secret.yaml");
        let detector = PatternDetector::new();
        let findings = scan_kubernetes_secret(path, content, &detector, 3.0).unwrap();
        assert!(!findings.is_empty(), "Should find AWS key in base64-encoded K8s secret");
    }

    #[test]
    fn test_docker_compose_env() {
        let content = r#"
services:
  app:
    image: myapp
    environment:
      AWS_ACCESS_KEY_ID: AKIAZ52HGXYRN4WBTEST
      SAFE_VAR: hello
"#;
        let path = Path::new("docker-compose.yml");
        let detector = PatternDetector::new();
        let findings = scan_docker_compose(path, content, &detector, 3.0).unwrap();
        assert!(!findings.is_empty(), "Should find AWS key in docker-compose environment");
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("QUtJQVo1MkhHWFlSTjRXQlRFU1Q="));
        assert!(!looks_like_base64("short"));
        assert!(!looks_like_base64("this has spaces and symbols!@#"));
    }
}
