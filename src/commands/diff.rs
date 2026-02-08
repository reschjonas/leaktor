use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Minimal struct for deserializing scan result JSON
#[derive(Debug, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<DiffFinding>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DiffFinding {
    pub secret: serde_json::Value,
    pub location: serde_json::Value,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

pub fn diff_fingerprint(f: &DiffFinding) -> String {
    let secret_type = f
        .secret
        .get("secret_type")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let value = f.secret.get("value").and_then(|s| s.as_str()).unwrap_or("");
    let file = f
        .location
        .get("file_path")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let line = f
        .location
        .get("line_number")
        .and_then(|l| l.as_u64())
        .unwrap_or(0);
    format!("{}|{}|{}|{}", secret_type, value, file, line)
}

pub fn diff_command(old_path: PathBuf, new_path: PathBuf, format: String) -> Result<()> {
    // Load both scan results
    let old_content = std::fs::read_to_string(&old_path)?;
    let new_content = std::fs::read_to_string(&new_path)?;

    let old_report: ScanReport = serde_json::from_str(&old_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", old_path.display(), e))?;
    let new_report: ScanReport = serde_json::from_str(&new_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", new_path.display(), e))?;

    // Build fingerprint sets for comparison
    let old_fingerprints: HashMap<String, &DiffFinding> = old_report
        .findings
        .iter()
        .map(|f| (diff_fingerprint(f), f))
        .collect();

    let new_fingerprints: HashMap<String, &DiffFinding> = new_report
        .findings
        .iter()
        .map(|f| (diff_fingerprint(f), f))
        .collect();

    let mut added: Vec<&DiffFinding> = Vec::new();
    let mut removed: Vec<&DiffFinding> = Vec::new();
    let mut unchanged: Vec<&DiffFinding> = Vec::new();

    for (fp, finding) in &new_fingerprints {
        if old_fingerprints.contains_key(fp) {
            unchanged.push(finding);
        } else {
            added.push(finding);
        }
    }
    for (fp, finding) in &old_fingerprints {
        if !new_fingerprints.contains_key(fp) {
            removed.push(finding);
        }
    }

    if format == "json" {
        let output = serde_json::json!({
            "added": added.len(),
            "removed": removed.len(),
            "unchanged": unchanged.len(),
            "findings_added": added,
            "findings_removed": removed,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", "Scan Diff Report".bold());
        println!();
        println!(
            "  Comparing {} -> {}",
            old_path.display().to_string().dimmed(),
            new_path.display().to_string().dimmed()
        );
        println!();

        // Summary
        let total_change = added.len() as i64 - removed.len() as i64;
        let change_label = if total_change > 0 {
            format!("+{}", total_change).red().to_string()
        } else if total_change < 0 {
            format!("{}", total_change).green().to_string()
        } else {
            "±0".to_string()
        };

        println!(
            "  {} {} new  {} {} fixed  {} {} unchanged  ({} net)",
            "+".dimmed(),
            added.len().to_string().red().bold(),
            "-".dimmed(),
            removed.len().to_string().green().bold(),
            "=".dimmed(),
            unchanged.len().to_string().dimmed(),
            change_label
        );
        println!();

        // New findings
        if !added.is_empty() {
            println!("  {}", "New findings:".red().bold());
            for f in &added {
                let sev = f
                    .secret
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let stype = f
                    .secret
                    .get("secret_type")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown");
                let file = f
                    .location
                    .get("file_path")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let line = f
                    .location
                    .get("line_number")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(0);
                println!(
                    "    {} [{}] {} at {}:{}",
                    "+".red(),
                    sev.to_uppercase(),
                    stype,
                    file,
                    line
                );
            }
            println!();
        }

        // Fixed findings
        if !removed.is_empty() {
            println!("  {}", "Fixed findings:".green().bold());
            for f in &removed {
                let stype = f
                    .secret
                    .get("secret_type")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown");
                let file = f
                    .location
                    .get("file_path")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let line = f
                    .location
                    .get("line_number")
                    .and_then(|l| l.as_u64())
                    .unwrap_or(0);
                println!("    {} {} at {}:{}", "-".green(), stype, file, line);
            }
            println!();
        }

        if added.is_empty() && removed.is_empty() {
            println!("  {} No changes between the two scans.", "[OK]".green());
        }
    }

    Ok(())
}
