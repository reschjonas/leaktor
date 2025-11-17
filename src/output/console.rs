use crate::models::{Finding, Severity};
use crate::output::OutputFormatter;
use anyhow::Result;
use colored::*;
use std::path::Path;

pub struct ConsoleOutput {
    verbose: bool,
    show_context: bool,
}

impl ConsoleOutput {
    pub fn new(verbose: bool, show_context: bool) -> Self {
        Self {
            verbose,
            show_context,
        }
    }

    fn severity_color(&self, severity: Severity) -> Color {
        match severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::BrightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        }
    }

    fn severity_icon(&self, severity: Severity) -> &str {
        match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
        }
    }

    fn print_banner(&self) {
        println!(
            "{}",
            "╔═══════════════════════════════════════════════╗".bright_cyan()
        );
        println!(
            "{}",
            "║           🔒 LEAKTOR SECURITY SCAN            ║".bright_cyan()
        );
        println!(
            "{}",
            "╚═══════════════════════════════════════════════╝".bright_cyan()
        );
        println!();
    }

    fn print_summary(&self, findings: &[Finding]) {
        let (critical, high, medium, low) = self.count_by_severity(findings);
        let validated = findings
            .iter()
            .filter(|f| f.secret.validated == Some(true))
            .count();
        let false_positives = findings
            .iter()
            .filter(|f| f.is_likely_false_positive())
            .count();

        println!("{}", "Summary".bold().underline());
        println!("{} {}", "Total Findings:".bold(), findings.len());
        println!(
            "{} {}",
            "  Critical:".color(Color::Red).bold(),
            critical.to_string().color(Color::Red)
        );
        println!(
            "{} {}",
            "  High:".color(Color::BrightRed).bold(),
            high.to_string().color(Color::BrightRed)
        );
        println!(
            "{} {}",
            "  Medium:".color(Color::Yellow).bold(),
            medium.to_string().color(Color::Yellow)
        );
        println!(
            "{} {}",
            "  Low:".color(Color::Blue).bold(),
            low.to_string().color(Color::Blue)
        );
        println!();
        println!("{} {}", "Validated Secrets:".bold(), validated);
        println!("{} {}", "Likely False Positives:".bold(), false_positives);
        println!();
    }

    fn print_finding(&self, finding: &Finding, index: usize) {
        let severity_color = self.severity_color(finding.severity());
        let severity_icon = self.severity_icon(finding.severity());

        // Header
        println!(
            "{} {} {} {}",
            format!("[{}]", index + 1).dimmed(),
            severity_icon,
            finding
                .secret
                .secret_type
                .as_str()
                .color(severity_color)
                .bold(),
            format!("[{}]", finding.severity().as_str())
                .color(severity_color)
                .bold()
        );

        // Validated status
        if let Some(validated) = finding.secret.validated {
            if validated {
                println!("  {} {}", "Status:".bold(), "✓ VALIDATED".green().bold());
            } else {
                println!("  {} {}", "Status:".bold(), "✗ INVALID".red());
            }
        }

        // Location
        println!(
            "  {} {}:{}",
            "Location:".bold(),
            finding.location.file_path.display().to_string().cyan(),
            finding.location.line_number.to_string().yellow()
        );

        // Metadata
        if self.verbose {
            println!(
                "  {} {:.0}%",
                "Confidence:".bold(),
                finding.secret.confidence * 100.0
            );
            println!("  {} {:.2}", "Entropy:".bold(), finding.secret.entropy);

            if let Some(ref commit_hash) = finding.location.commit_hash {
                println!("  {} {}", "Commit:".bold(), commit_hash.dimmed());
            }
            if let Some(ref author) = finding.location.commit_author {
                println!("  {} {}", "Author:".bold(), author.dimmed());
            }
        }

        // Code context
        if self.show_context {
            println!("  {}:", "Context".bold());
            if let Some(ref before) = finding.context.line_before {
                println!("    {}", before.dimmed());
            }
            println!(
                "    {}",
                finding.context.line_content.replace(
                    &finding.secret.value,
                    &finding.secret.redacted_value.red().to_string()
                )
            );
            if let Some(ref after) = finding.context.line_after {
                println!("    {}", after.dimmed());
            }
        }

        // Flags
        if finding.context.is_test_file {
            println!("  {} {}", "⚠".yellow(), "Found in test file".yellow());
        }
        if finding.is_likely_false_positive() {
            println!(
                "  {} {}",
                "ℹ".blue(),
                "Likely false positive".blue().dimmed()
            );
        }

        println!();
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

    pub fn print_scan_complete(&self, findings_count: usize) {
        println!("{}", "═".repeat(50).bright_cyan());
        if findings_count == 0 {
            println!(
                "{}",
                "✓ No secrets detected! Your code looks clean."
                    .green()
                    .bold()
            );
        } else {
            println!(
                "{}",
                format!("⚠ Scan complete. {} secrets detected.", findings_count)
                    .yellow()
                    .bold()
            );
        }
        println!("{}", "═".repeat(50).bright_cyan());
    }
}

impl OutputFormatter for ConsoleOutput {
    fn format(&self, findings: &[Finding]) -> Result<String> {
        // For console output, we'll capture to a string
        // In practice, this would just print to stdout
        let mut output = String::new();

        output.push_str("Leaktor Security Scan Report\n");
        output.push_str(&format!("Total Findings: {}\n", findings.len()));

        for (index, finding) in findings.iter().enumerate() {
            output.push_str(&format!(
                "\n[{}] {} - {}:{}\n",
                index + 1,
                finding.secret.secret_type.as_str(),
                finding.location.file_path.display(),
                finding.location.line_number
            ));
        }

        Ok(output)
    }

    fn write_to_file(&self, findings: &[Finding], path: &Path) -> Result<()> {
        let output = self.format(findings)?;
        std::fs::write(path, output)?;
        Ok(())
    }
}

impl ConsoleOutput {
    /// Display findings to stdout with colors and formatting
    pub fn display(&self, findings: &[Finding]) {
        self.print_banner();
        self.print_summary(findings);

        if !findings.is_empty() {
            println!("{}", "Findings".bold().underline());
            println!();

            for (index, finding) in findings.iter().enumerate() {
                self.print_finding(finding, index);
            }
        }

        self.print_scan_complete(findings.len());
    }
}

impl Default for ConsoleOutput {
    fn default() -> Self {
        Self::new(false, true)
    }
}
