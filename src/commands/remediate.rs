use anyhow::Result;
use colored::*;
use std::path::PathBuf;

use super::diff::ScanReport;

pub fn remediate_command(input: PathBuf, output: Option<PathBuf>, format: String) -> Result<()> {
    let content = std::fs::read_to_string(&input)?;
    let report: ScanReport = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", input.display(), e))?;

    if report.findings.is_empty() {
        println!("{}", "[OK] No findings to remediate.".green());
        return Ok(());
    }

    let mut remediation_text = String::new();

    match format.as_str() {
        "script" => {
            remediation_text.push_str("#!/bin/bash\n");
            remediation_text.push_str("# Leaktor Remediation Script\n");
            remediation_text.push_str(&format!("# Generated from: {}\n", input.display()));
            remediation_text.push_str(&format!("# Findings: {}\n\n", report.findings.len()));
            remediation_text.push_str("set -e\n\n");

            for (i, f) in report.findings.iter().enumerate() {
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
                let value = f
                    .secret
                    .get("value")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");

                remediation_text.push_str(&format!("# --- Finding {} ---\n", i + 1));
                remediation_text.push_str(&format!("# Type: {}\n", stype));
                remediation_text.push_str(&format!("# File: {}\n", file));
                remediation_text.push_str(&format!(
                    "echo \"[{}/{}] Remediating {} in {}\"\n\n",
                    i + 1,
                    report.findings.len(),
                    stype,
                    file
                ));

                // Add provider-specific rotation commands
                let rotation_cmd = get_rotation_command(stype);
                if !rotation_cmd.is_empty() {
                    remediation_text.push_str("# Step 1: Rotate the key\n");
                    remediation_text.push_str(&format!("# {}\n\n", rotation_cmd));
                }

                // Add git history cleanup
                if !value.is_empty() && value.len() > 8 {
                    let short_val = &value[..value.len().min(20)];
                    remediation_text.push_str("# Step 2: Remove from git history\n");
                    remediation_text.push_str(&format!(
                        "# git filter-repo --replace-text <(echo '{}==>***REMOVED***')\n\n",
                        short_val
                    ));
                }

                // Add to .leaktorignore
                remediation_text.push_str("# Step 3: Add to ignore (if false positive)\n");
                remediation_text.push_str(&format!("# echo '{}' >> .leaktorignore\n\n", file));
            }
        }
        "markdown" | "md" => {
            remediation_text.push_str("# Leaktor Remediation Report\n\n");
            remediation_text.push_str(&format!("**Source:** `{}`  \n", input.display()));
            remediation_text
                .push_str(&format!("**Findings:** {}  \n\n", report.findings.len()));
            remediation_text.push_str("---\n\n");

            for (i, f) in report.findings.iter().enumerate() {
                let stype = f
                    .secret
                    .get("secret_type")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown");
                let sev = f
                    .secret
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
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

                remediation_text.push_str(&format!(
                    "## {}. {} [{}]\n\n",
                    i + 1,
                    stype,
                    sev.to_uppercase()
                ));
                remediation_text.push_str(&format!("- **File:** `{}:{}`\n", file, line));
                remediation_text.push_str("- **Action Required:**\n");

                let rotation = get_rotation_command(stype);
                if !rotation.is_empty() {
                    remediation_text.push_str(&format!("  1. **Rotate:** {}\n", rotation));
                } else {
                    remediation_text.push_str("  1. **Rotate:** Revoke and regenerate this credential via the provider dashboard\n");
                }
                remediation_text.push_str("  2. **Clean history:** `git filter-repo --replace-text` to remove from all commits\n");
                remediation_text.push_str("  3. **Prevent recurrence:** Add to `.leaktorignore` or use environment variables\n\n");
            }
        }
        _ => {
            // Console output
            println!("{}", "Remediation Report".bold().underline());
            println!();
            println!(
                "  {} finding(s) from {}",
                report.findings.len().to_string().yellow().bold(),
                input.display().to_string().dimmed()
            );
            println!();

            for (i, f) in report.findings.iter().enumerate() {
                let stype = f
                    .secret
                    .get("secret_type")
                    .and_then(|s| s.as_str())
                    .unwrap_or("Unknown");
                let sev = f
                    .secret
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
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

                let sev_colored = match sev.to_uppercase().as_str() {
                    "CRITICAL" => sev.to_uppercase().red().bold().to_string(),
                    "HIGH" => sev.to_uppercase().red().to_string(),
                    "MEDIUM" => sev.to_uppercase().yellow().to_string(),
                    _ => sev.to_uppercase().dimmed().to_string(),
                };

                println!(
                    "  {}. {} [{}]",
                    (i + 1).to_string().bold(),
                    stype.cyan(),
                    sev_colored
                );
                println!("     {} {}:{}", "Location:".dimmed(), file, line);

                let rotation = get_rotation_command(stype);
                if !rotation.is_empty() {
                    println!("     {} {}", "Rotate:".yellow(), rotation);
                } else {
                    println!(
                        "     {} Revoke and regenerate via provider dashboard",
                        "Rotate:".yellow()
                    );
                }
                println!(
                    "     {} git filter-repo --replace-text ...",
                    "Clean:".yellow()
                );
                println!(
                    "     {} Add to .leaktorignore or use env vars",
                    "Prevent:".yellow()
                );
                println!();
            }
        }
    }

    if let Some(output_path) = output {
        std::fs::write(&output_path, &remediation_text)?;
        println!(
            "{}",
            format!("[OK] Remediation written to {}", output_path.display()).green()
        );
    } else if format == "script" || format == "markdown" || format == "md" {
        print!("{}", remediation_text);
    }

    Ok(())
}

/// Get provider-specific key rotation command
pub fn get_rotation_command(secret_type: &str) -> &'static str {
    match secret_type {
        "AWS Access Key" | "AWS Secret Key" => {
            "aws iam create-access-key && aws iam delete-access-key --access-key-id <OLD_KEY>"
        }
        "GitHub Personal Access Token" | "GitHub Token" => {
            "gh auth refresh-token  (or regenerate at github.com/settings/tokens)"
        }
        "GitLab Personal Access Token" => {
            "Regenerate at gitlab.com/-/profile/personal_access_tokens"
        }
        "Stripe API Key" => "Regenerate at dashboard.stripe.com/apikeys (roll key)",
        "SendGrid API Key" => "Regenerate at app.sendgrid.com/settings/api_keys",
        "Slack Token" => "Regenerate at api.slack.com/apps (reinstall app)",
        "OpenAI API Key" => "Regenerate at platform.openai.com/api-keys",
        "Anthropic API Key" => "Regenerate at console.anthropic.com/settings/keys",
        "HuggingFace Token" => "Regenerate at huggingface.co/settings/tokens",
        "DigitalOcean Token" => {
            "Regenerate at cloud.digitalocean.com/account/api/tokens"
        }
        "NPM Token" => "npm token revoke <TOKEN> && npm token create",
        "Docker Hub Token" => "Regenerate at hub.docker.com/settings/security",
        "HashiCorp Vault Token" => "vault token revoke <TOKEN> && vault token create",
        "Datadog API Key" => {
            "Regenerate at app.datadoghq.com/organization-settings/api-keys"
        }
        "RSA Private Key" | "SSH Private Key" | "EC Private Key" | "PKCS8 Private Key"
        | "DSA Private Key" => "Generate new key pair: ssh-keygen -t ed25519",
        "Discord Bot Token" => "Regenerate at discord.com/developers/applications",
        "Telegram Bot Token" => "Regenerate via @BotFather on Telegram",
        "Twilio API Key" => "Regenerate at twilio.com/console",
        _ => "",
    }
}
