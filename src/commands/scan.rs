use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use leaktor::*;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::webhook::send_webhook;

#[allow(clippy::too_many_arguments)]
pub async fn scan_command(
    path: PathBuf,
    format: String,
    output_path: Option<PathBuf>,
    git_history: bool,
    max_depth: Option<usize>,
    max_fs_depth: Option<usize>,
    entropy: f64,
    validate: bool,
    verbose: bool,
    quiet: bool,
    context: bool,
    min_confidence: f64,
    exclude_tests: bool,
    fail_on_found: bool,
    stdin_mode: bool,
    since_commit: Option<String>,
    commit_range: Option<String>,
    baseline_path: Option<PathBuf>,
    create_baseline: Option<PathBuf>,
    update_baseline: Option<PathBuf>,
    only_verified: bool,
    include_deps: bool,
    webhook_url: Option<String>,
) -> Result<()> {
    // ── Validate inputs ──────────────────────────────────────────────────

    if !stdin_mode {
        if !path.exists() {
            anyhow::bail!(
                "{} Path does not exist: {}\n{} Please provide a valid directory or file path.",
                "Error:".red().bold(),
                path.display(),
                "Hint:".yellow().bold()
            );
        }

        // Both files and directories are accepted
        if !path.is_dir() && !path.is_file() {
            anyhow::bail!(
                "{} Path is not a file or directory: {}\n{} Provide a valid file or directory path.",
                "Error:".red().bold(),
                path.display(),
                "Hint:".yellow().bold()
            );
        }
    }

    if !["console", "json", "sarif", "html"].contains(&format.as_str()) {
        anyhow::bail!(
            "{} Invalid output format: {}\n{} Supported formats: console, json, sarif, html",
            "Error:".red().bold(),
            format.yellow(),
            "Hint:".yellow().bold()
        );
    }

    if !(0.0..=1.0).contains(&min_confidence) {
        anyhow::bail!(
            "{} Confidence must be between 0.0 and 1.0, got: {}\n{} Try a value like 0.6 (default) or 0.8 for higher precision.",
            "Error:".red().bold(),
            min_confidence,
            "Hint:".yellow().bold()
        );
    }

    if entropy < 0.0 {
        anyhow::bail!(
            "{} Entropy threshold cannot be negative: {}\n{} Try the default value of 3.5 or higher for more random strings.",
            "Error:".red().bold(),
            entropy,
            "Hint:".yellow().bold()
        );
    }

    // Parse commit range if provided (format: FROM..TO)
    let parsed_commit_range = if let Some(ref range_str) = commit_range {
        let parts: Vec<&str> = range_str.splitn(2, "..").collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            anyhow::bail!(
                "{} Invalid commit range format: {}\n{} Use the format: FROM..TO (e.g., abc1234..HEAD)",
                "Error:".red().bold(),
                range_str.yellow(),
                "Hint:".yellow().bold()
            );
        }
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    };

    let start = Instant::now();

    // Load configuration file if present
    let config = match Config::load_from_current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "\x1b[33m[warn:config]\x1b[0m failed to load config file, using defaults: {}",
                e
            );
            Config::default()
        }
    };

    // Merge CLI flags with config file (CLI takes precedence)
    let effective_entropy = if entropy != 3.5 {
        entropy
    } else {
        config.entropy_threshold
    };
    let effective_min_confidence = if min_confidence != 0.6 {
        min_confidence
    } else {
        config.min_confidence
    };
    let effective_git_history = git_history && config.scan_git_history;
    let effective_exclude_tests = exclude_tests || config.exclude_tests;

    // Load ignore manager
    let ignore_base = if path.is_file() {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path.clone()
    };
    let ignore_file = ignore_base.join(".leaktorignore");
    let ignore_manager = if !stdin_mode && ignore_file.exists() {
        IgnoreManager::load_from_file(&ignore_file)?
    } else {
        IgnoreManager::new()
    };

    // Create progress bar
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );

    // Track whether structured output goes to stdout (so we keep stdout clean)
    let structured_to_stdout = (format == "json" || format == "sarif") && output_path.is_none();

    // ── Scan ─────────────────────────────────────────────────────────────

    let effective_max_depth = max_depth.or(config.max_git_depth);

    // --max-depth also controls filesystem recursion when --max-fs-depth isn't explicitly set
    let effective_fs_depth = max_fs_depth.or(max_depth);

    // Log custom patterns if any
    let custom_patterns = config.custom_patterns.clone();
    if !quiet && !custom_patterns.is_empty() && !structured_to_stdout {
        println!(
            "{}",
            format!(
                "[i] {} custom pattern(s) loaded from config",
                custom_patterns.len()
            )
            .dimmed()
        );
    }

    if !quiet && include_deps && !structured_to_stdout {
        println!(
            "{}",
            "[i] Scanning dependency directories (node_modules, vendor, .venv, ...)".dimmed()
        );
    }

    let is_single_file = !stdin_mode && path.is_file();

    let mut findings = if stdin_mode {
        // ── Stdin scanning ───────────────────────────────────────────────
        spinner.set_message("Scanning stdin...");
        let scanner = StdinScanner::new()
            .with_entropy_threshold(effective_entropy)
            .with_custom_patterns(custom_patterns.clone());
        scanner.scan()?
    } else if is_single_file {
        // ── Single file scanning ─────────────────────────────────────────
        spinner.set_message(format!("Scanning file: {}...", path.display()));
        let mut scanner = FilesystemScanner::new(path.clone())
            .with_entropy_threshold(effective_entropy)
            .with_max_file_size(config.max_file_size)
            .with_custom_patterns(custom_patterns.clone())
            .with_single_file(true);
        if let Some(depth) = effective_fs_depth {
            scanner = scanner.with_max_fs_depth(depth);
        }

        scanner.scan()?
    } else if path.join(".git").exists() {
        // ── Git repository scanning ──────────────────────────────────────
        spinner.set_message("Scanning git repository...");
        let mut scanner = GitScanner::new(path.clone())
            .with_history(effective_git_history)
            .with_entropy_threshold(effective_entropy)
            .with_custom_patterns(custom_patterns.clone())
            .with_include_deps(include_deps);

        if let Some(depth) = effective_max_depth {
            scanner = scanner.with_max_depth(depth);
        }
        if let Some(depth) = effective_fs_depth {
            scanner = scanner.with_max_fs_depth(depth);
        }
        if let Some(ref commit) = since_commit {
            scanner = scanner.with_since_commit(commit.clone());
        }
        if let Some((ref from, ref to)) = parsed_commit_range {
            scanner = scanner.with_commit_range(from.clone(), to.clone());
        }

        scanner.scan()?
    } else {
        // ── Filesystem scanning ──────────────────────────────────────────
        spinner.set_message("Scanning filesystem...");
        let mut scanner = FilesystemScanner::new(path.clone())
            .with_entropy_threshold(effective_entropy)
            .with_max_file_size(config.max_file_size)
            .with_custom_patterns(custom_patterns.clone())
            .with_include_deps(include_deps);
        if let Some(depth) = effective_fs_depth {
            scanner = scanner.with_max_fs_depth(depth);
        }

        scanner.scan()?
    };

    spinner.finish_and_clear();

    // ── Normalize paths to relative (early) ────────────────────────────────
    // Convert absolute paths to paths relative to the scan root so that
    // baseline fingerprints, deduplication, and output are all consistent.
    let base_dir = if path.is_file() {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path.clone()
    };
    let canonical_base = std::fs::canonicalize(&base_dir).unwrap_or(base_dir);
    for f in &mut findings {
        if f.location.file_path.is_absolute() {
            if let Ok(rel) = f.location.file_path.strip_prefix(&canonical_base) {
                f.location.file_path = rel.to_path_buf();
            }
        }
    }

    // Save all findings (with normalized paths) before filtering — used by
    // --update-baseline and --create-baseline so they capture the full
    // picture rather than the display-filtered subset.
    let all_findings = findings.clone();

    // ── Filter findings ──────────────────────────────────────────────────

    findings.retain(|f| {
        // Filter by confidence
        if f.secret.confidence < effective_min_confidence {
            return false;
        }

        // Filter by test files
        if effective_exclude_tests && f.context.is_test_file {
            return false;
        }

        // Check ignore patterns (file path + inline comments)
        if ignore_manager.should_ignore(&f.location.file_path, &f.context.line_content) {
            return false;
        }

        // Check fingerprint-based allowlist
        let fp = leaktor::config::baseline::Fingerprint::from_finding(f);
        if ignore_manager.should_ignore_fingerprint(&fp.0) {
            return false;
        }

        // Check config-based allowlist rules
        let allowlist = config.compiled_allowlist();
        if !allowlist.is_empty() {
            let type_name = f.secret.secret_type.as_str();
            let file_path_str = f.location.file_path.to_string_lossy();
            let severity_name = format!("{:?}", f.secret.severity).to_uppercase();
            for rule in allowlist {
                if rule.matches(type_name, &file_path_str, &f.secret.value, &severity_name) {
                    return false;
                }
            }
        }

        true
    });

    // Deduplicate findings: same file + line + secret value = duplicate
    findings.sort_by(|a, b| {
        a.location
            .file_path
            .cmp(&b.location.file_path)
            .then(a.location.line_number.cmp(&b.location.line_number))
            .then(a.location.column_start.cmp(&b.location.column_start))
    });
    findings.dedup_by(|a, b| {
        a.location.file_path == b.location.file_path
            && a.location.line_number == b.location.line_number
            && a.secret.value == b.secret.value
    });

    // Cross-source dedup: when the same secret appears in both working
    // directory and git history (same file + value, different line numbers),
    // keep only the working directory finding (no commit_hash).
    {
        let mut seen: std::collections::HashSet<(PathBuf, String)> =
            std::collections::HashSet::new();
        // Stable-sort so working directory findings (commit_hash == None) come first
        findings.sort_by(|a, b| {
            a.location
                .file_path
                .cmp(&b.location.file_path)
                .then(
                    a.location
                        .commit_hash
                        .is_some()
                        .cmp(&b.location.commit_hash.is_some()),
                )
                .then(a.location.line_number.cmp(&b.location.line_number))
        });
        findings.retain(|f| {
            let key = (f.location.file_path.clone(), f.secret.value.clone());
            seen.insert(key)
        });
    }

    // ── Baseline: filter out known findings ──────────────────────────────

    let baseline_filtered_count;

    if let Some(ref bp) = baseline_path {
        let baseline = Baseline::load(bp)?;
        let total_before = findings.len();
        findings = baseline.filter_findings(findings);
        baseline_filtered_count = total_before - findings.len();
        if !quiet && baseline_filtered_count > 0 {
            let msg = format!(
                "[i] {} known finding(s) suppressed by baseline",
                baseline_filtered_count
            )
            .dimmed()
            .to_string();
            if structured_to_stdout {
                eprintln!("{}", msg);
            } else {
                println!("{}", msg);
            }
        }
    } else {
        baseline_filtered_count = 0;
    }

    // ── Validate secrets ─────────────────────────────────────────────────

    let should_validate = validate || config.enable_validation;
    if should_validate && !findings.is_empty() {
        let validate_spinner = ProgressBar::new(findings.len() as u64);
        validate_spinner.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Validating secrets...",
                )
                .unwrap()
                .progress_chars("#>-"),
        );

        // Build rate limiter from config
        let rate_limiter = leaktor::validators::ValidationRateLimiter::from_config(&config);

        if !quiet && !structured_to_stdout {
            let msg = format!(
                "[i] Validation: max {} concurrent, {}ms delay, {} retries",
                config.max_concurrent_validations,
                config.validation_delay_ms,
                config.validation_max_retries
            )
            .dimmed()
            .to_string();
            println!("{}", msg);
        }

        // Extract secrets for parallel validation
        let mut secrets: Vec<_> = findings.iter().map(|f| f.secret.clone()).collect();
        leaktor::validators::validate_secrets_parallel_with_limiter(&mut secrets, &rate_limiter)
            .await?;

        // Write results back to findings
        for (finding, secret) in findings.iter_mut().zip(secrets.into_iter()) {
            finding.secret.validated = secret.validated;
            validate_spinner.inc(1);
        }

        // AWS keypair validation: when both an access key and secret key are
        // found in the same file, pair them and validate via STS GetCallerIdentity
        // instead of the format-only check.
        {
            use std::collections::HashMap;

            // Group AWS access keys and secret keys by file path
            let mut access_keys: HashMap<PathBuf, Vec<usize>> = HashMap::new();
            let mut secret_keys: HashMap<PathBuf, Vec<usize>> = HashMap::new();

            for (idx, finding) in findings.iter().enumerate() {
                match &finding.secret.secret_type {
                    SecretType::AwsAccessKey => {
                        access_keys
                            .entry(finding.location.file_path.clone())
                            .or_default()
                            .push(idx);
                    }
                    SecretType::AwsSecretKey => {
                        secret_keys
                            .entry(finding.location.file_path.clone())
                            .or_default()
                            .push(idx);
                    }
                    _ => {}
                }
            }

            // For each file that has both an access key and a secret key,
            // pair the first of each and validate via STS
            for (file_path, ak_indices) in &access_keys {
                if let Some(sk_indices) = secret_keys.get(file_path) {
                    let ak_idx = ak_indices[0];
                    let sk_idx = sk_indices[0];
                    let ak_value = findings[ak_idx].secret.value.clone();
                    let sk_value = findings[sk_idx].secret.value.clone();

                    match leaktor::validators::aws::validate_aws_keypair(&ak_value, &sk_value)
                        .await
                    {
                        Ok(valid) => {
                            findings[ak_idx].secret.validated = Some(valid);
                            findings[sk_idx].secret.validated = Some(valid);
                        }
                        Err(e) => {
                            // STS call failed (rate limit, network, etc.) -- keep
                            // the format-only result rather than overwriting
                            if !quiet && !structured_to_stdout {
                                eprintln!(
                                    "{}",
                                    format!(
                                        "[i] AWS STS validation failed for {}: {}",
                                        file_path.display(),
                                        e
                                    )
                                    .dimmed()
                                );
                            }
                        }
                    }
                }
            }
        }

        validate_spinner.finish_and_clear();
    }

    // ── Only-verified filter ─────────────────────────────────────────────

    if only_verified {
        if !should_validate {
            anyhow::bail!(
                "{} --only-verified requires --validate\n{} Add --validate to enable secret verification.",
                "Error:".red().bold(),
                "Hint:".yellow().bold()
            );
        }
        let before = findings.len();
        findings.retain(|f| f.secret.validated == Some(true));
        let filtered = before - findings.len();
        if !quiet && filtered > 0 && !structured_to_stdout {
            println!(
                "{}",
                format!(
                    "[i] {} unverified finding(s) hidden by --only-verified",
                    filtered
                )
                .dimmed()
            );
        }
    }

    // ── Baseline: create or update ───────────────────────────────────────

    if let Some(ref bp) = create_baseline {
        // Use all_findings (pre-filter) so the baseline captures everything
        let baseline = Baseline::from_findings(&all_findings);
        baseline.save(bp)?;
        if !quiet {
            let msg = format!(
                "[OK] Baseline created at {} ({} entries)",
                bp.display(),
                all_findings.len()
            )
            .green()
            .to_string();
            if structured_to_stdout {
                eprintln!("{}", msg);
            } else {
                println!("{}", msg);
            }
        }
    }

    if let Some(ref bp) = update_baseline {
        let mut baseline = if bp.exists() {
            Baseline::load(bp)?
        } else {
            Baseline::from_findings(&[])
        };
        let before = baseline.entries.len();
        // Use all_findings (pre-filter) so new findings aren't lost
        // to confidence/test/ignore/dedup/baseline filtering
        baseline.update(&all_findings);
        let added = baseline.entries.len() - before;
        baseline.save(bp)?;
        if !quiet {
            let msg = format!(
                "[OK] Baseline updated at {} ({} new entries, {} total)",
                bp.display(),
                added,
                baseline.entries.len()
            )
            .green()
            .to_string();
            if structured_to_stdout {
                eprintln!("{}", msg);
            } else {
                println!("{}", msg);
            }
        }
    }

    // ── Webhook integration ──────────────────────────────────────────────

    if let Some(ref url) = webhook_url {
        if !findings.is_empty() {
            let webhook_result = send_webhook(url, &findings).await;
            if !quiet {
                let msg = match webhook_result {
                    Ok(status) => format!(
                        "[OK] Webhook sent ({} findings, HTTP {})",
                        findings.len(),
                        status
                    )
                    .green()
                    .to_string(),
                    Err(e) => format!("[!] Webhook failed: {}", e).red().to_string(),
                };
                if structured_to_stdout {
                    eprintln!("{}", msg);
                } else {
                    println!("{}", msg);
                }
            }
        }
    }

    let duration = start.elapsed();

    // ── Output results ───────────────────────────────────────────────────

    match format.as_str() {
        "json" => {
            let output_formatter = JsonOutput::new(true);
            if let Some(output_path) = output_path {
                output_formatter.write_to_file(&findings, &output_path)?;
                if !quiet {
                    println!(
                        "{}",
                        format!("[OK] Results written to {}", output_path.display()).green()
                    );
                }
            } else {
                println!("{}", output_formatter.format(&findings)?);
            }
        }
        "sarif" => {
            let output_formatter = SarifOutput::new();
            if let Some(output_path) = output_path {
                output_formatter.write_to_file(&findings, &output_path)?;
                if !quiet {
                    println!(
                        "{}",
                        format!("[OK] Results written to {}", output_path.display()).green()
                    );
                }
            } else {
                println!("{}", output_formatter.format(&findings)?);
            }
        }
        "html" => {
            let output_formatter = HtmlOutput::new();
            let output_path = output_path.unwrap_or_else(|| PathBuf::from("leaktor-report.html"));
            output_formatter.write_to_file(&findings, &output_path)?;
            if !quiet {
                println!(
                    "{}",
                    format!("[OK] HTML report written to {}", output_path.display()).green()
                );
            }
        }
        _ => {
            if !quiet {
                let console_output = ConsoleOutput::new(verbose, context);
                console_output.display(&findings);

                if let Some(output_path) = output_path {
                    console_output.write_to_file(&findings, &output_path)?;
                }
            }
        }
    }

    // ── Print scan statistics ────────────────────────────────────────────

    if !quiet {
        let total_files_scanned = if stdin_mode {
            1 // stdin counts as one "file"
        } else {
            let scanner = FilesystemScanner::new(path.clone());
            scanner.get_stats().map(|s| s.total_files).unwrap_or(0)
        };

        let mut stats_line = format!(
            "Scan completed in {:.2}s | {} files scanned | {} findings",
            duration.as_secs_f64(),
            total_files_scanned,
            findings.len()
        );
        if baseline_filtered_count > 0 {
            stats_line.push_str(&format!(" | {} baselined", baseline_filtered_count));
        }

        // Show warning count in the summary
        let warn_count = leaktor::warning_count();
        if warn_count > 0 {
            stats_line.push_str(&format!(" | {} warnings", warn_count));
        }

        let stats_msg = format!("\n{}", stats_line.dimmed());
        if structured_to_stdout {
            eprintln!("{}", stats_msg);
        } else {
            println!("{}", stats_msg);
        }
    }

    // Exit with error if secrets found and fail_on_found is set
    if fail_on_found && !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}
