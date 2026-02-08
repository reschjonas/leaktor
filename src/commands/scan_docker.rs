use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use leaktor::*;
use std::path::PathBuf;
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub async fn scan_docker_command(
    image: String,
    format: String,
    output_path: Option<PathBuf>,
    entropy: f64,
    validate: bool,
    verbose: bool,
    quiet: bool,
    context: bool,
    min_confidence: f64,
    fail_on_found: bool,
    only_verified: bool,
    no_pull: bool,
) -> Result<()> {
    if !["console", "json", "sarif", "html"].contains(&format.as_str()) {
        anyhow::bail!(
            "{} Invalid output format: {}\n{} Supported formats: console, json, sarif, html",
            "Error:".red().bold(),
            format.yellow(),
            "Hint:".yellow().bold()
        );
    }

    let start = Instant::now();

    // Load configuration file if present
    let config = Config::load_from_current_dir().unwrap_or_default();
    let custom_patterns = config.custom_patterns.clone();

    let structured_to_stdout = (format == "json" || format == "sarif") && output_path.is_none();

    if !quiet && !structured_to_stdout {
        println!(
            "{} {}",
            "Scanning Docker image:".bold(),
            image.cyan()
        );
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );

    if !no_pull {
        spinner.set_message(format!("Pulling image {}...", image));
    }

    let scanner = DockerScanner::new(image.clone())
        .with_entropy_threshold(entropy)
        .with_custom_patterns(custom_patterns)
        .with_pull(!no_pull);

    spinner.set_message("Exporting and scanning image filesystem...");
    let mut findings = scanner.scan().await?;
    spinner.finish_and_clear();

    // ── Filter findings ──────────────────────────────────────────────────

    findings.retain(|f| f.secret.confidence >= min_confidence);

    // Deduplicate
    findings.sort_by(|a, b| {
        a.location
            .file_path
            .cmp(&b.location.file_path)
            .then(a.location.line_number.cmp(&b.location.line_number))
    });
    findings.dedup_by(|a, b| {
        a.location.file_path == b.location.file_path
            && a.location.line_number == b.location.line_number
            && a.secret.value == b.secret.value
    });

    // ── Validate ─────────────────────────────────────────────────────────

    let should_validate = validate || config.enable_validation;
    if should_validate && !findings.is_empty() {
        let rate_limiter = leaktor::validators::ValidationRateLimiter::from_config(&config);
        let mut secrets: Vec<_> = findings.iter().map(|f| f.secret.clone()).collect();
        leaktor::validators::validate_secrets_parallel_with_limiter(&mut secrets, &rate_limiter)
            .await?;
        for (finding, secret) in findings.iter_mut().zip(secrets.into_iter()) {
            finding.secret.validated = secret.validated;
        }
    }

    if only_verified {
        if !should_validate {
            anyhow::bail!(
                "{} --only-verified requires --validate",
                "Error:".red().bold()
            );
        }
        findings.retain(|f| f.secret.validated == Some(true));
    }

    let duration = start.elapsed();

    // ── Output ───────────────────────────────────────────────────────────

    match format.as_str() {
        "json" => {
            let out = JsonOutput::new(true);
            if let Some(p) = output_path {
                out.write_to_file(&findings, &p)?;
                if !quiet {
                    println!("{}", format!("[OK] Results written to {}", p.display()).green());
                }
            } else {
                println!("{}", out.format(&findings)?);
            }
        }
        "sarif" => {
            let out = SarifOutput::new();
            if let Some(p) = output_path {
                out.write_to_file(&findings, &p)?;
                if !quiet {
                    println!("{}", format!("[OK] Results written to {}", p.display()).green());
                }
            } else {
                println!("{}", out.format(&findings)?);
            }
        }
        "html" => {
            let out = HtmlOutput::new();
            let p = output_path.unwrap_or_else(|| PathBuf::from("leaktor-report.html"));
            out.write_to_file(&findings, &p)?;
            if !quiet {
                println!("{}", format!("[OK] HTML report written to {}", p.display()).green());
            }
        }
        _ => {
            if !quiet {
                let console_output = ConsoleOutput::new(verbose, context);
                console_output.display(&findings);
            }
        }
    }

    if !quiet {
        let stats = format!(
            "\nScan completed in {:.2}s | docker://{} | {} findings",
            duration.as_secs_f64(),
            image,
            findings.len()
        );
        if structured_to_stdout {
            eprintln!("{}", stats.dimmed());
        } else {
            println!("{}", stats.dimmed());
        }
    }

    if fail_on_found && !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
