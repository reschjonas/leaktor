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
use crate::scan_warn;
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
        StructuredFormat::TerraformState => {
            scan_terraform_state(path, content, detector, entropy_threshold)
        }
        StructuredFormat::KubernetesSecret => {
            scan_kubernetes_secret(path, content, detector, entropy_threshold)
        }
        StructuredFormat::DockerCompose => {
            scan_docker_compose(path, content, detector, entropy_threshold)
        }
        StructuredFormat::CloudFormation => {
            scan_cloudformation(path, content, detector, entropy_threshold)
        }
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
        Err(e) => {
            scan_warn!(
                "parse",
                "failed to parse {} as Terraform state JSON: {}",
                path.display(),
                e
            );
            return Ok(findings);
        }
    };

    let file_context = ContextAnalyzer::analyze_file(path);

    // Walk resources with type-aware context enrichment.
    // Terraform resources have a `type` field (e.g. "aws_iam_access_key") that
    // provides critical context for pattern matching.  When the JSON key is
    // generic (like "secret"), combining just `secret=<value>` isn't enough for
    // patterns that require a provider keyword (e.g. `aws...secret`).
    //
    // Here we extract the resource type and prepend it to attribute keys, so
    // `"secret": "wJalr..."` inside an `aws_iam_access_key` resource becomes
    // `aws_iam_access_key_secret=wJalr...` for scanning.
    if let Some(resources) = value.get("resources").and_then(|r| r.as_array()) {
        for resource in resources {
            let resource_type = resource
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("");

            if let Some(instances) = resource.get("instances").and_then(|i| i.as_array()) {
                for instance in instances {
                    if let Some(attrs) = instance.get("attributes").and_then(|a| a.as_object()) {
                        for (key, val) in attrs {
                            if let Some(s) = val.as_str() {
                                if s.len() < 8 || s.len() > 5000 {
                                    continue;
                                }
                                scan_terraform_attribute(
                                    path,
                                    content,
                                    s,
                                    key,
                                    resource_type,
                                    &file_context,
                                    detector,
                                    entropy_threshold,
                                    &mut findings,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Generic recursive walk for any values outside the resources array
    // (outputs, data sources, etc.)
    walk_json_values(
        &value,
        path,
        &file_context,
        detector,
        entropy_threshold,
        &mut findings,
        "",
    );

    // Also look for base64-encoded blobs and decode them
    walk_json_decode_base64(
        &value,
        path,
        &file_context,
        detector,
        entropy_threshold,
        &mut findings,
    );

    // Deduplicate: the generic walk may re-find secrets already found by the
    // resource-aware pass. Remove duplicates by (value, file_path).
    findings.dedup_by(|a, b| {
        a.secret.value == b.secret.value && a.location.file_path == b.location.file_path
    });

    Ok(findings)
}

/// Scan a single Terraform resource attribute with enriched context.
///
/// Tries multiple context constructions so that patterns requiring provider
/// keywords (e.g. `aws...secret`) can match:
///   1. `resource_type + "_" + key + "=" + value`  (e.g. `aws_iam_access_key_secret=wJalr...`)
///   2. `key + "=" + value`  (e.g. `secret=wJalr...`)
///   3. The raw value itself (for self-identifying patterns like `AKIA...`)
#[allow(clippy::too_many_arguments)]
fn scan_terraform_attribute(
    path: &Path,
    content: &str,
    value: &str,
    key: &str,
    resource_type: &str,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
) {
    // Build candidate scan lines from most specific to least specific
    let mut candidates: Vec<String> = Vec::with_capacity(3);

    // 1. resource_type + key + value  (most context)
    if !resource_type.is_empty() {
        candidates.push(format!("{}_{} = \"{}\"", resource_type, key, value));
    }

    // 2. key=value
    candidates.push(format!("{}={}", key, value));

    // 3. raw value (self-identifying patterns like AKIA prefix)
    candidates.push(value.to_string());

    let mut found = false;
    for candidate in &candidates {
        let matches = detector.scan_line_with_positions(candidate, entropy_threshold);
        for m in matches {
            // Avoid duplicates from multiple candidate constructions
            if found && findings.iter().any(|f| {
                f.secret.value == m.secret.value && f.location.file_path == path
            }) {
                continue;
            }
            found = true;

            let line_num = find_line_number(content, value);
            let context = Context {
                line_before: Some(format!(
                    "Terraform {} .attributes.{}",
                    if resource_type.is_empty() {
                        "resource"
                    } else {
                        resource_type
                    },
                    key
                )),
                line_content: truncate_for_context(value),
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

fn walk_json_values(
    value: &serde_json::Value,
    path: &Path,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
    json_path: &str,
) {
    walk_json_values_inner(
        value, path, file_context, detector, entropy_threshold, findings, json_path, None,
    );
}

#[allow(clippy::too_many_arguments)]
/// Inner recursive walker that also receives the parent JSON key name.
/// When a string value is encountered under an object key, the key name is
/// combined with the value (`key=value`) before scanning so that
/// context-dependent patterns (e.g. `aws_secret_access_key=...`) can match.
/// This mirrors the approach used by the Docker Compose scanner.
fn walk_json_values_inner(
    value: &serde_json::Value,
    path: &Path,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
    json_path: &str,
    parent_key: Option<&str>,
) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() < 8 || s.len() > 5000 {
                return;
            }

            // Combine key=value so context-dependent patterns can match
            // (e.g. "secret": "wJalr..." becomes "secret=wJalr..." for scanning)
            let combined = if let Some(key) = parent_key {
                format!("{}={}", key, s)
            } else {
                s.clone()
            };

            let matches = detector.scan_line_with_positions(&combined, entropy_threshold);
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
                walk_json_values_inner(
                    v,
                    path,
                    file_context,
                    detector,
                    entropy_threshold,
                    findings,
                    &child_path,
                    Some(k),
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", json_path, i);
                walk_json_values_inner(
                    v,
                    path,
                    file_context,
                    detector,
                    entropy_threshold,
                    findings,
                    &child_path,
                    None,
                );
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
                            let matches =
                                detector.scan_line_with_positions(&decoded, entropy_threshold);
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
                walk_json_decode_base64(
                    v,
                    path,
                    file_context,
                    detector,
                    entropy_threshold,
                    findings,
                );
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                walk_json_decode_base64(
                    v,
                    path,
                    file_context,
                    detector,
                    entropy_threshold,
                    findings,
                );
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
            Err(e) => {
                scan_warn!(
                    "parse",
                    "failed to parse YAML document in {}: {}",
                    path.display(),
                    e
                );
                continue;
            }
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
                let decoded = match base64::engine::general_purpose::STANDARD.decode(val_str.trim())
                {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => continue, // binary data, not a text secret
                    },
                    Err(e) => {
                        scan_warn!(
                            "parse",
                            "invalid base64 in K8s Secret .data.{} in {}: {}",
                            key_str,
                            path.display(),
                            e
                        );
                        continue;
                    }
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
        Err(e) => {
            // Provide a friendlier diagnostic when the YAML contains mixed
            // list/mapping syntax in environment blocks (a common mistake
            // where users combine `- KEY=val` and `KEY: val` in the same block).
            let err_str = e.to_string();
            if err_str.contains("did not find expected")
                || err_str.contains("mapping values are not allowed")
            {
                scan_warn!(
                    "parse",
                    "{}: YAML parse error ({}). \
                     Tip: mixing list-style (- KEY=val) and mapping-style (KEY: val) \
                     in the same `environment:` block is invalid YAML. \
                     Use one style consistently. Falling back to line-based scanning.",
                    path.display(),
                    e
                );
            } else {
                scan_warn!(
                    "parse",
                    "failed to parse {} as Docker Compose YAML: {}. \
                     Falling back to line-based scanning.",
                    path.display(),
                    e
                );
            }
            // Fall back to line-based environment extraction instead of giving up
            scan_compose_environment_lines(
                path,
                content,
                &file_context,
                detector,
                entropy_threshold,
                &mut findings,
            );
            return Ok(findings);
        }
    };

    // Walk services -> each service -> environment
    if let Some(services) = value.get("services").and_then(|s| s.as_mapping()) {
        for (_svc_name, svc_val) in services {
            if let Some(env) = svc_val.get("environment") {
                scan_compose_environment(
                    path,
                    content,
                    env,
                    &file_context,
                    detector,
                    entropy_threshold,
                    &mut findings,
                );
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

/// Line-based fallback for Docker Compose environment scanning.
///
/// When YAML parsing fails (e.g. due to mixed list/mapping syntax), this
/// function extracts `KEY=value` and `KEY: value` pairs from lines that look
/// like environment variable definitions and scans them for secrets.
fn scan_compose_environment_lines(
    path: &Path,
    content: &str,
    file_context: &crate::detectors::context::FileContext,
    detector: &PatternDetector,
    entropy_threshold: f64,
    findings: &mut Vec<Finding>,
) {
    let env_kv_re =
        regex::Regex::new(r#"^\s*-?\s*([A-Z][A-Z0-9_]+)\s*[=:]\s*['"]?(.+?)['"]?\s*$"#).unwrap();

    for (line_num_0, line) in content.lines().enumerate() {
        if let Some(caps) = env_kv_re.captures(line) {
            let key = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if val.is_empty() || val.len() < 8 {
                continue;
            }

            let combined = format!("{}={}", key, val);
            let matches = detector.scan_line_with_positions(&combined, entropy_threshold);
            for m in matches {
                let context = Context {
                    line_before: Some(format!(
                        "Docker Compose environment (line fallback): {}",
                        key
                    )),
                    line_content: truncate_for_context(&combined),
                    line_after: None,
                    is_test_file: file_context.is_test_file,
                    is_config_file: true,
                    is_documentation: false,
                    file_extension: file_context.file_extension.clone(),
                };
                let location = Location {
                    file_path: path.to_path_buf(),
                    line_number: line_num_0 + 1,
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
    } else {
        match serde_yaml::from_str::<serde_yaml::Value>(content) {
            Ok(yaml_val) => match serde_json::to_value(yaml_val) {
                Ok(v) => v,
                Err(e) => {
                    scan_warn!(
                        "parse",
                        "failed to convert CloudFormation YAML to JSON in {}: {}",
                        path.display(),
                        e
                    );
                    return Ok(findings);
                }
            },
            Err(e) => {
                scan_warn!(
                    "parse",
                    "failed to parse {} as CloudFormation (JSON/YAML): {}",
                    path.display(),
                    e
                );
                return Ok(findings);
            }
        }
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
        walk_json_values(
            resources,
            path,
            &file_context,
            detector,
            entropy_threshold,
            &mut findings,
            "Resources",
        );
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
    trimmed.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r'
    })
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
        assert_eq!(
            detect_format(path, "{}"),
            Some(StructuredFormat::TerraformState)
        );
    }

    #[test]
    fn test_detect_kubernetes_secret() {
        let path = Path::new("secret.yaml");
        let content = "apiVersion: v1\nkind: Secret\ndata:\n  password: cGFzc3dvcmQ=";
        assert_eq!(
            detect_format(path, content),
            Some(StructuredFormat::KubernetesSecret)
        );
    }

    #[test]
    fn test_detect_docker_compose() {
        let path = Path::new("docker-compose.yml");
        assert_eq!(
            detect_format(path, "services:"),
            Some(StructuredFormat::DockerCompose)
        );
    }

    #[test]
    fn test_detect_cloudformation() {
        let path = Path::new("template.yaml");
        let content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:";
        assert_eq!(
            detect_format(path, content),
            Some(StructuredFormat::CloudFormation)
        );
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
        assert!(
            !findings.is_empty(),
            "Should find AWS key in base64-encoded K8s secret"
        );
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
        assert!(
            !findings.is_empty(),
            "Should find AWS key in docker-compose environment"
        );
    }

    #[test]
    fn test_terraform_state_context_dependent_secret() {
        let content = r#"{
  "version": 4,
  "resources": [
    {
      "type": "aws_iam_access_key",
      "name": "deploy",
      "instances": [
        {
          "attributes": {
            "id": "AKIAZ52HGXYRN4WBTEST",
            "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCY0123456789"
          }
        }
      ]
    }
  ]
}"#;
        let path = Path::new("terraform.tfstate");
        let detector = PatternDetector::new();
        let findings = scan_terraform_state(path, content, &detector, 3.0).unwrap();
        // Should find both: the self-identifying AKIA access key AND the
        // context-dependent secret key (which requires `aws...secret` keyword)
        let has_access_key = findings
            .iter()
            .any(|f| f.secret.value.starts_with("AKIA"));
        let has_secret_key = findings
            .iter()
            .any(|f| f.secret.value.starts_with("wJalr"));
        assert!(
            has_access_key,
            "Should find AWS access key (self-identifying via AKIA prefix)"
        );
        assert!(
            has_secret_key,
            "Should find AWS secret key via resource type context enrichment"
        );
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("QUtJQVo1MkhHWFlSTjRXQlRFU1Q="));
        assert!(!looks_like_base64("short"));
        assert!(!looks_like_base64("this has spaces and symbols!@#"));
    }
}
