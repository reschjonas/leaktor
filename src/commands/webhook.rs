use anyhow::Result;

pub async fn send_webhook(url: &str, findings: &[leaktor::Finding]) -> Result<u16> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    // Detect webhook type from URL and format payload accordingly
    let payload = if url.contains("hooks.slack.com") {
        // Slack webhook format
        let summary = format!(
            ":rotating_light: *Leaktor Security Scan*\n{} secret(s) detected",
            findings.len()
        );

        let mut blocks = vec![
            serde_json::json!({
                "type": "header",
                "text": { "type": "plain_text", "text": "Leaktor Security Scan" }
            }),
            serde_json::json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!(":rotating_light: *{} finding(s)* detected", findings.len()) }
            }),
        ];

        // Add top 10 findings as details
        for (i, f) in findings.iter().take(10).enumerate() {
            let sev = format!("{:?}", f.secret.severity).to_uppercase();
            let line = format!(
                "{}. *[{}]* {} at `{}:{}`",
                i + 1,
                sev,
                f.secret.secret_type.as_str(),
                f.location.file_path.display(),
                f.location.line_number
            );
            blocks.push(serde_json::json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": line }
            }));
        }

        if findings.len() > 10 {
            blocks.push(serde_json::json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!("_...and {} more_", findings.len() - 10) }
            }));
        }

        serde_json::json!({ "text": summary, "blocks": blocks })
    } else if url.contains("office.com") || url.contains("webhook.office") {
        // Microsoft Teams webhook format
        let mut text = format!(
            "**Leaktor Security Scan**\n\n{} finding(s) detected:\n\n",
            findings.len()
        );
        for (i, f) in findings.iter().take(20).enumerate() {
            let sev = format!("{:?}", f.secret.severity).to_uppercase();
            text.push_str(&format!(
                "{}. **[{}]** {} at `{}:{}`\n",
                i + 1,
                sev,
                f.secret.secret_type.as_str(),
                f.location.file_path.display(),
                f.location.line_number
            ));
        }
        serde_json::json!({
            "@type": "MessageCard",
            "summary": format!("Leaktor: {} secrets found", findings.len()),
            "text": text
        })
    } else {
        // Generic JSON webhook
        let finding_summaries: Vec<serde_json::Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "type": f.secret.secret_type.as_str(),
                    "severity": format!("{:?}", f.secret.severity).to_uppercase(),
                    "file": f.location.file_path.display().to_string(),
                    "line": f.location.line_number,
                    "confidence": f.secret.confidence,
                    "redacted_value": f.secret.redacted_value,
                })
            })
            .collect();

        serde_json::json!({
            "source": "leaktor",
            "event": "scan_complete",
            "total_findings": findings.len(),
            "findings": finding_summaries
        })
    };

    let response = client.post(url).json(&payload).send().await?;
    let status = response.status().as_u16();

    if !response.status().is_success() && status != 400 {
        anyhow::bail!("Webhook returned HTTP {}", status);
    }

    Ok(status)
}
