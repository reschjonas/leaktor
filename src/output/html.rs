use crate::models::{Finding, Severity};
use crate::output::OutputFormatter;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub struct HtmlOutput;

impl HtmlOutput {
    pub fn new() -> Self {
        Self
    }

    fn create_html(&self, findings: &[Finding]) -> String {
        let mut html = String::new();

        // HTML header
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Leaktor Security Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0f1419;
            color: #e6edf3;
            padding: 2rem;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        h1 {
            color: #58a6ff;
            margin-bottom: 0.5rem;
            font-size: 2.5rem;
        }
        .subtitle {
            color: #8b949e;
            margin-bottom: 2rem;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1.5rem;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        .stat-label {
            color: #8b949e;
            font-size: 0.875rem;
        }
        .critical { color: #f85149; }
        .high { color: #ff7b72; }
        .medium { color: #d29922; }
        .low { color: #58a6ff; }
        .finding {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-title {
            font-weight: 600;
            font-size: 1.1rem;
        }
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical {
            background: #f851491a;
            color: #f85149;
            border: 1px solid #f85149;
        }
        .severity-high {
            background: #ff7b721a;
            color: #ff7b72;
            border: 1px solid #ff7b72;
        }
        .severity-medium {
            background: #d299221a;
            color: #d29922;
            border: 1px solid #d29922;
        }
        .severity-low {
            background: #58a6ff1a;
            color: #58a6ff;
            border: 1px solid #58a6ff;
        }
        .finding-body {
            padding: 1.5rem;
        }
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .meta-item {
            font-size: 0.875rem;
        }
        .meta-label {
            color: #8b949e;
            display: block;
            margin-bottom: 0.25rem;
        }
        .code-block {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.875rem;
        }
        .code-line {
            margin: 0.25rem 0;
        }
        .code-highlight {
            background: #bb800926;
            padding: 0.125rem 0;
        }
        .validated {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: #238636;
            color: #fff;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-left: 0.5rem;
        }
        .not-validated {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: #6e7681;
            color: #fff;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-left: 0.5rem;
        }
        footer {
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #30363d;
            text-align: center;
            color: #8b949e;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Leaktor Security Scan</h1>
        <p class="subtitle">Secrets Detection Report</p>
"#);

        // Summary statistics
        let (critical, high, medium, low) = self.count_by_severity(findings);
        let validated = findings
            .iter()
            .filter(|f| f.secret.validated == Some(true))
            .count();

        html.push_str(&format!(
            r#"
        <div class="summary">
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value low">{}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Validated</div>
            </div>
        </div>
"#,
            findings.len(),
            critical,
            high,
            medium,
            low,
            validated
        ));

        // Findings
        html.push_str("<h2 style='margin: 2rem 0 1rem 0; color: #e6edf3;'>Findings</h2>");

        for finding in findings {
            let severity_class = match finding.severity() {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
            };

            let validated_badge = match finding.secret.validated {
                Some(true) => "<span class='validated'>✓ VALIDATED</span>",
                Some(false) => "<span class='not-validated'>✗ INVALID</span>",
                None => "",
            };

            html.push_str(&format!(
                r#"
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">{}{}</div>
                <span class="severity-badge severity-{}">{}</span>
            </div>
            <div class="finding-body">
                <div class="finding-meta">
                    <div class="meta-item">
                        <span class="meta-label">File</span>
                        {}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Location</span>
                        Line {}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Confidence</span>
                        {:.0}%
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Entropy</span>
                        {:.2}
                    </div>
                </div>
                <div class="code-block">
"#,
                finding.secret.secret_type.as_str(),
                validated_badge,
                severity_class,
                finding.severity().as_str(),
                html_escape(&finding.location.file_path.to_string_lossy()),
                finding.location.line_number,
                finding.secret.confidence * 100.0,
                finding.secret.entropy
            ));

            // Code context
            if let Some(ref before) = finding.context.line_before {
                html.push_str(&format!(
                    "<div class='code-line'>{}</div>",
                    html_escape(before)
                ));
            }
            html.push_str(&format!(
                "<div class='code-line code-highlight'>{}</div>",
                html_escape(&finding.context.line_content)
            ));
            if let Some(ref after) = finding.context.line_after {
                html.push_str(&format!(
                    "<div class='code-line'>{}</div>",
                    html_escape(after)
                ));
            }

            html.push_str(
                r#"
                </div>
            </div>
        </div>
"#,
            );
        }

        // Footer
        html.push_str(&format!(
            r#"
        <footer>
            Generated by Leaktor v{} on {}<br>
            <a href="https://github.com/reschjonas/leaktor" style="color: #58a6ff;">github.com/reschjonas/leaktor</a>
        </footer>
    </div>
</body>
</html>
"#,
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        html
    }

    fn count_by_severity(&self, findings: &[Finding]) -> (usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for finding in findings {
            match finding.severity() {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
            }
        }

        (critical, high, medium, low)
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

impl OutputFormatter for HtmlOutput {
    fn format(&self, findings: &[Finding]) -> Result<String> {
        Ok(self.create_html(findings))
    }

    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()> {
        let html = self.format(findings)?;
        fs::write(path, html)?;
        Ok(())
    }
}

impl Default for HtmlOutput {
    fn default() -> Self {
        Self::new()
    }
}
