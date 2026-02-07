use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use leaktor::*;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "leaktor",
    about = "A secrets scanner with pattern matching, entropy analysis, and live validation",
    version,
    author = "Jonas Resch <reschjonas>"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory or git repository for secrets
    ///
    /// Examples:
    ///   leaktor scan                           # Scan current directory
    ///   leaktor scan /path/to/project          # Scan specific directory
    ///   leaktor scan --validate                # Scan and validate secrets
    ///   leaktor scan --format html -o report.html  # Generate HTML report
    ///   leaktor scan --stdin                   # Scan piped input
    ///   leaktor scan --since-commit abc123     # Only new commits since abc123
    ///   leaktor scan --baseline baseline.json  # Suppress known findings
    Scan {
        /// Path to scan (directory or git repository)
        #[arg(default_value = ".", help = "Path to the directory to scan")]
        path: PathBuf,

        /// Output format: console (default), json, sarif, or html
        #[arg(short, long, default_value = "console", help = "Output format (console|json|sarif|html)")]
        format: String,

        /// Output file path (required for HTML, optional for others)
        #[arg(short, long, help = "Write output to file instead of stdout")]
        output: Option<PathBuf>,

        /// Scan git history for secrets in old commits
        #[arg(long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", help = "Scan git history (true|false)")]
        git_history: bool,

        /// Maximum git history depth to scan
        #[arg(long, help = "Limit git history depth (e.g., 100)")]
        max_depth: Option<usize>,

        /// Entropy threshold for detecting random strings
        #[arg(long, default_value = "3.5", help = "Entropy threshold (higher = more random)")]
        entropy: f64,

        /// Validate detected secrets against their APIs
        #[arg(short, long, help = "Validate secrets are active (requires network)")]
        validate: bool,

        /// Show verbose output with additional details
        #[arg(short, long, help = "Show detailed information")]
        verbose: bool,

        /// Show code context around findings
        #[arg(short, long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", help = "Show code context (true|false)")]
        context: bool,

        /// Minimum confidence score (0.0 to 1.0) for findings
        #[arg(long, default_value = "0.6", help = "Confidence threshold (0.0-1.0)")]
        min_confidence: f64,

        /// Exclude test files from scan results
        #[arg(long, help = "Skip test files")]
        exclude_tests: bool,

        /// Exit with error code 1 if any secrets found (useful for CI/CD)
        #[arg(long, help = "Exit with error if secrets found (for CI/CD)")]
        fail_on_found: bool,

        /// Read input from stdin instead of scanning a directory
        #[arg(long, help = "Scan content from stdin (pipe-friendly)")]
        stdin: bool,

        /// Only scan git commits after this commit (exclusive)
        #[arg(long, help = "Only scan commits after this hash (e.g., abc1234)")]
        since_commit: Option<String>,

        /// Only scan git commits in a range (format: FROM..TO)
        #[arg(long, help = "Scan a commit range (e.g., abc1234..def5678 or abc1234..HEAD)")]
        commit_range: Option<String>,

        /// Path to a baseline file -- suppress findings already in the baseline
        #[arg(long, help = "Baseline file to suppress known findings")]
        baseline: Option<PathBuf>,

        /// Create a baseline file from the current scan results
        #[arg(long, help = "Write a baseline file from this scan's results")]
        create_baseline: Option<PathBuf>,

        /// Update an existing baseline file with new findings from this scan
        #[arg(long, help = "Merge new findings into an existing baseline file")]
        update_baseline: Option<PathBuf>,

        /// Only show secrets that have been verified as active (requires --validate)
        #[arg(long, help = "Only report verified (active) secrets")]
        only_verified: bool,

        /// Include dependency directories (node_modules, vendor, .venv, etc.)
        #[arg(long, help = "Scan dependency dirs (node_modules, vendor, .venv)")]
        include_deps: bool,
    },

    /// Trace where a secret is used across the codebase (blast radius analysis)
    ///
    /// Examples:
    ///   leaktor trace AKIAZ52HGXYRN4WB        # Find all references to this key
    ///   leaktor trace --type "AWS Access Key"  # Find all usage of this secret type
    ///   leaktor trace --file .env              # Find all references to secrets in this file
    Trace {
        /// Secret value (or prefix) to trace
        #[arg(help = "Secret value or prefix to trace across the codebase")]
        query: Option<String>,

        /// Trace by secret type instead of value
        #[arg(long = "type", short = 't', help = "Secret type to trace (e.g., 'AWS Access Key')")]
        secret_type: Option<String>,

        /// Trace secrets found in a specific file
        #[arg(long, short, help = "File containing secrets to trace")]
        file: Option<PathBuf>,

        /// Root path to search
        #[arg(long, default_value = ".", help = "Root directory to search")]
        path: PathBuf,
    },

    /// Compare two scan results to show added, removed, and unchanged findings
    ///
    /// Examples:
    ///   leaktor diff old-scan.json new-scan.json       # Compare two JSON reports
    ///   leaktor diff --baseline old.json --baseline new.json  # Compare baselines
    Diff {
        /// First (older) scan result file (JSON format)
        #[arg(help = "Path to the older scan result (JSON)")]
        old: PathBuf,

        /// Second (newer) scan result file (JSON format)
        #[arg(help = "Path to the newer scan result (JSON)")]
        new: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "console", help = "Output format (console|json)")]
        format: String,
    },

    /// Set up Leaktor for a project: config, ignore file, pre-commit hook, CI, baseline
    ///
    /// This is a one-command setup that creates everything you need:
    ///   - .leaktor.toml  (configuration)
    ///   - .leaktorignore (ignore patterns)
    ///   - Pre-commit git hook
    ///   - GitHub Actions workflow
    ///   - Initial baseline (optional)
    Init {
        /// Root path for the project
        #[arg(default_value = ".", help = "Project root directory")]
        path: PathBuf,

        /// Skip interactive prompts; use defaults
        #[arg(long, help = "Use defaults without prompting")]
        yes: bool,

        /// Also create a baseline from the initial scan
        #[arg(long, help = "Create an initial baseline from current findings")]
        baseline: bool,

        /// Skip GitHub Actions workflow creation
        #[arg(long, help = "Don't create GitHub Actions workflow")]
        no_ci: bool,

        /// Skip pre-commit hook installation
        #[arg(long, help = "Don't install pre-commit hook")]
        no_hook: bool,
    },

    /// Generate a configuration file with default settings
    ///
    /// Create a .leaktor.toml or .leaktor.yaml file to customize
    /// scanning behavior, patterns, and thresholds.
    Config {
        /// Output path for the configuration file
        #[arg(default_value = ".leaktor.toml", help = "Path for config file")]
        path: PathBuf,

        /// Configuration file format
        #[arg(short, long, default_value = "toml", help = "Format (toml|yaml)")]
        format: String,
    },

    /// Install a git pre-commit hook to scan before commits
    ///
    /// This creates a pre-commit hook that automatically scans for secrets
    /// before each commit, preventing accidental secret commits.
    InstallHook {
        /// Path to the git repository
        #[arg(default_value = ".", help = "Path to git repository")]
        path: PathBuf,
    },

    /// List all supported secret types and patterns
    ///
    /// Display all secret types that Leaktor can detect, organized by category.
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            git_history,
            max_depth,
            entropy,
            validate,
            verbose,
            context,
            min_confidence,
            exclude_tests,
            fail_on_found,
            stdin,
            since_commit,
            commit_range,
            baseline,
            create_baseline,
            update_baseline,
            only_verified,
            include_deps,
        } => {
            scan_command(
                path,
                format,
                output,
                git_history,
                max_depth,
                entropy,
                validate,
                verbose,
                context,
                min_confidence,
                exclude_tests,
                fail_on_found,
                stdin,
                since_commit,
                commit_range,
                baseline,
                create_baseline,
                update_baseline,
                only_verified,
                include_deps,
            )
            .await?;
        }
        Commands::Trace {
            query,
            secret_type,
            file,
            path,
        } => {
            trace_command(query, secret_type, file, path)?;
        }
        Commands::Diff { old, new, format } => {
            diff_command(old, new, format)?;
        }
        Commands::Init {
            path,
            yes,
            baseline,
            no_ci,
            no_hook,
        } => {
            init_project_command(path, yes, baseline, no_ci, no_hook)?;
        }
        Commands::Config { path, format } => {
            config_command(path, format)?;
        }
        Commands::InstallHook { path } => {
            install_hook_command(path)?;
        }
        Commands::List => {
            list_command();
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn scan_command(
    path: PathBuf,
    format: String,
    output_path: Option<PathBuf>,
    git_history: bool,
    max_depth: Option<usize>,
    entropy: f64,
    validate: bool,
    verbose: bool,
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

        if !path.is_dir() {
            anyhow::bail!(
                "{} Path must be a directory: {}\n{} Leaktor scans directories, not individual files.",
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
    let config = Config::load_from_current_dir().unwrap_or_default();

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
    let ignore_file = path.join(".leaktorignore");
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
    let structured_to_stdout =
        (format == "json" || format == "sarif") && output_path.is_none();

    // ── Scan ─────────────────────────────────────────────────────────────

    let effective_max_depth = max_depth.or(config.max_git_depth);

    // Log custom patterns if any
    let custom_patterns = config.custom_patterns.clone();
    if !custom_patterns.is_empty() && !structured_to_stdout {
        println!(
            "{}",
            format!(
                "[i] {} custom pattern(s) loaded from config",
                custom_patterns.len()
            )
            .dimmed()
        );
    }

    if include_deps && !structured_to_stdout {
        println!(
            "{}",
            "[i] Scanning dependency directories (node_modules, vendor, .venv, ...)"
                .dimmed()
        );
    }

    let mut findings = if stdin_mode {
        // ── Stdin scanning ───────────────────────────────────────────────
        spinner.set_message("Scanning stdin...");
        let scanner =
            StdinScanner::new()
                .with_entropy_threshold(effective_entropy)
                .with_custom_patterns(custom_patterns.clone());
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
        let scanner = FilesystemScanner::new(path.clone())
            .with_entropy_threshold(effective_entropy)
            .with_max_file_size(config.max_file_size)
            .with_custom_patterns(custom_patterns.clone())
            .with_include_deps(include_deps);

        scanner.scan()?
    };

    spinner.finish_and_clear();

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

    // ── Baseline: filter out known findings ──────────────────────────────

    let baseline_filtered_count;

    if let Some(ref bp) = baseline_path {
        let baseline = Baseline::load(bp)?;
        let total_before = findings.len();
        findings = baseline.filter_findings(findings);
        baseline_filtered_count = total_before - findings.len();
        if baseline_filtered_count > 0 {
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
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Validating secrets...")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Extract secrets for parallel validation
        let mut secrets: Vec<_> = findings.iter().map(|f| f.secret.clone()).collect();
        validators::validate_secrets_parallel(&mut secrets).await?;

        // Write results back to findings
        for (finding, secret) in findings.iter_mut().zip(secrets.into_iter()) {
            finding.secret.validated = secret.validated;
            validate_spinner.inc(1);
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
        if filtered > 0 && !structured_to_stdout {
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
        let baseline = Baseline::from_findings(&findings);
        baseline.save(bp)?;
        let msg = format!(
            "[OK] Baseline created at {} ({} entries)",
            bp.display(),
            findings.len()
        )
        .green()
        .to_string();
        if structured_to_stdout {
            eprintln!("{}", msg);
        } else {
            println!("{}", msg);
        }
    }

    if let Some(ref bp) = update_baseline {
        let mut baseline = if bp.exists() {
            Baseline::load(bp)?
        } else {
            Baseline::from_findings(&[])
        };
        let before = baseline.entries.len();
        baseline.update(&findings);
        let added = baseline.entries.len() - before;
        baseline.save(bp)?;
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

    let duration = start.elapsed();

    // ── Output results ───────────────────────────────────────────────────

    match format.as_str() {
        "json" => {
            let output_formatter = JsonOutput::new(true);
            if let Some(output_path) = output_path {
                output_formatter.write_to_file(&findings, &output_path)?;
                println!(
                    "{}",
                    format!("[OK] Results written to {}", output_path.display()).green()
                );
            } else {
                println!("{}", output_formatter.format(&findings)?);
            }
        }
        "sarif" => {
            let output_formatter = SarifOutput::new();
            if let Some(output_path) = output_path {
                output_formatter.write_to_file(&findings, &output_path)?;
                println!(
                    "{}",
                    format!("[OK] Results written to {}", output_path.display()).green()
                );
            } else {
                println!("{}", output_formatter.format(&findings)?);
            }
        }
        "html" => {
            let output_formatter = HtmlOutput::new();
            let output_path = output_path.unwrap_or_else(|| PathBuf::from("leaktor-report.html"));
            output_formatter.write_to_file(&findings, &output_path)?;
            println!(
                "{}",
                format!("[OK] HTML report written to {}", output_path.display()).green()
            );
        }
        _ => {
            let console_output = ConsoleOutput::new(verbose, context);
            console_output.display(&findings);

            if let Some(output_path) = output_path {
                console_output.write_to_file(&findings, &output_path)?;
            }
        }
    }

    // ── Print scan statistics ────────────────────────────────────────────

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

    let stats_msg = format!("\n{}", stats_line.dimmed());
    if structured_to_stdout {
        eprintln!("{}", stats_msg);
    } else {
        println!("{}", stats_msg);
    }

    // Exit with error if secrets found and fail_on_found is set
    if fail_on_found && !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// leaktor init -- full project setup
// ═══════════════════════════════════════════════════════════════════════════

fn init_project_command(
    path: PathBuf,
    _yes: bool,
    create_baseline: bool,
    no_ci: bool,
    no_hook: bool,
) -> Result<()> {
    println!("{}", "Initializing Leaktor for your project".bold());
    println!();

    let project_root = if path == Path::new(".") {
        std::env::current_dir()?
    } else {
        path.clone()
    };

    // 1. Create .leaktor.toml
    let config_path = project_root.join(".leaktor.toml");
    if config_path.exists() {
        println!("  {} .leaktor.toml already exists", "skip".dimmed());
    } else {
        let config = Config::default();
        config.to_toml_file(&config_path)?;
        println!("  {} Created {}", "[OK]".green(), ".leaktor.toml".bold());
    }

    // 2. Create .leaktorignore
    let ignore_path = project_root.join(".leaktorignore");
    if ignore_path.exists() {
        println!("  {} .leaktorignore already exists", "skip".dimmed());
    } else {
        let ignore_manager = IgnoreManager::new();
        ignore_manager.save_to_file(&ignore_path)?;
        println!("  {} Created {}", "[OK]".green(), ".leaktorignore".bold());
    }

    // 3. Install pre-commit hook
    if !no_hook {
        let git_dir = project_root.join(".git");
        if git_dir.exists() {
            let hooks_dir = git_dir.join("hooks");
            std::fs::create_dir_all(&hooks_dir)?;
            let hook_path = hooks_dir.join("pre-commit");
            if hook_path.exists() {
                println!(
                    "  {} pre-commit hook already exists (skipped)",
                    "skip".dimmed()
                );
            } else {
                let hook_content = r#"#!/bin/sh
# Leaktor pre-commit hook -- auto-installed by `leaktor init`
echo "Running Leaktor security scan on staged files..."

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

for FILE in $STAGED_FILES; do
    DIR=$(dirname "$FILE")
    mkdir -p "$TMPDIR/$DIR"
    git show ":$FILE" > "$TMPDIR/$FILE" 2>/dev/null || continue
done

leaktor scan "$TMPDIR" --git-history=false --fail-on-found --min-confidence 0.7 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "Secrets detected. Commit aborted."
    echo "   Use 'git commit --no-verify' to bypass."
    exit 1
fi
exit 0
"#;
                std::fs::write(&hook_path, hook_content)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(&hook_path)?.permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(&hook_path, perms)?;
                }
                println!("  {} Installed {}", "[OK]".green(), "pre-commit hook".bold());
            }
        } else {
            println!("  {} No .git directory found (skipping hook)", "skip".dimmed());
        }
    }

    // 4. Create GitHub Actions workflow
    if !no_ci {
        let workflow_dir = project_root.join(".github").join("workflows");
        let workflow_path = workflow_dir.join("leaktor.yml");
        if workflow_path.exists() {
            println!(
                "  {} GitHub Actions workflow already exists",
                "skip".dimmed()
            );
        } else {
            std::fs::create_dir_all(&workflow_dir)?;
            let workflow = r#"name: Leaktor Security Scan
on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Leaktor
        run: cargo install leaktor

      - name: Run Leaktor
        run: leaktor scan --fail-on-found --format sarif -o results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
"#;
            std::fs::write(&workflow_path, workflow)?;
            println!(
                "  {} Created {}",
                "[OK]".green(),
                ".github/workflows/leaktor.yml".bold()
            );
        }
    }

    // 5. Create baseline
    if create_baseline {
        println!();
        println!("  {} Running initial scan to create baseline...", "...".dimmed());
        let scanner = FilesystemScanner::new(project_root.clone())
            .with_entropy_threshold(3.5);
        let findings = scanner.scan()?;
        let baseline = Baseline::from_findings(&findings);
        let baseline_path = project_root.join(".leaktor-baseline.json");
        baseline.save(&baseline_path)?;
        println!(
            "  {} Created {} ({} entries)",
            "[OK]".green(),
            ".leaktor-baseline.json".bold(),
            findings.len()
        );
    }

    println!();
    println!("{}", "Setup complete! Next steps:".bold());
    println!(
        "  1. Edit {} to customize patterns and thresholds",
        ".leaktor.toml".cyan()
    );
    println!(
        "  2. Run {} to scan your project",
        "leaktor scan".cyan()
    );
    if create_baseline {
        println!(
            "  3. Use {} to suppress existing findings",
            "leaktor scan --baseline .leaktor-baseline.json".cyan()
        );
    }
    println!();

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// leaktor trace -- blast radius analysis
// ═══════════════════════════════════════════════════════════════════════════

fn trace_command(
    query: Option<String>,
    secret_type: Option<String>,
    file: Option<PathBuf>,
    path: PathBuf,
) -> Result<()> {
    if query.is_none() && secret_type.is_none() && file.is_none() {
        anyhow::bail!(
            "{} Provide a secret value, --type, or --file to trace.\n{} Examples:\n  leaktor trace AKIAZ52HGX...\n  leaktor trace --type \"AWS Access Key\"\n  leaktor trace --file .env",
            "Error:".red().bold(),
            "Hint:".yellow().bold()
        );
    }

    println!("{}", "Blast Radius Analysis".bold());
    println!();

    // Step 1: Identify secrets to trace
    let mut search_terms: Vec<(String, String)> = Vec::new(); // (label, value_or_pattern)

    if let Some(ref q) = query {
        search_terms.push(("Query".to_string(), q.clone()));
    }

    if let Some(ref file_path) = file {
        // Scan the specified file to extract secrets
        let content = std::fs::read_to_string(file_path)?;
        let detector = leaktor::detectors::PatternDetector::new();
        for line in content.lines() {
            let matches = detector.scan_line(line, 3.0);
            for m in matches {
                let label = format!("{} (from {})", m.secret_type.as_str(), file_path.display());
                search_terms.push((label, m.value.clone()));
            }
        }
        if search_terms.is_empty() {
            println!("  {} No secrets found in {}", "[!]".yellow(), file_path.display());
            return Ok(());
        }
    }

    // Step 2: Scan the codebase for all findings
    let scanner = FilesystemScanner::new(path.clone()).with_entropy_threshold(3.0);
    let all_findings = scanner.scan()?;

    // Step 3: For type-based search, find matching findings
    if let Some(ref type_name) = secret_type {
        let type_lower = type_name.to_lowercase();
        let matching: Vec<_> = all_findings
            .iter()
            .filter(|f| f.secret.secret_type.as_str().to_lowercase().contains(&type_lower))
            .collect();

        if matching.is_empty() {
            println!(
                "  {} No findings of type \"{}\" in this codebase",
                "[OK]".green(),
                type_name
            );
            return Ok(());
        }

        // Group by unique secret value
        let mut unique_values: std::collections::HashMap<String, Vec<&leaktor::Finding>> =
            std::collections::HashMap::new();
        for f in &matching {
            unique_values
                .entry(f.secret.value.clone())
                .or_default()
                .push(f);
        }

        println!(
            "  Found {} unique {} secret(s) across {} location(s)",
            unique_values.len().to_string().yellow().bold(),
            type_name.cyan(),
            matching.len().to_string().yellow()
        );
        println!();

        for (i, (value, locations)) in unique_values.iter().enumerate() {
            let display_val = if value.len() > 20 {
                format!("{}...{}", &value[..8], &value[value.len() - 4..])
            } else {
                value.clone()
            };
            println!(
                "  Secret #{}: {} ({} reference{})",
                i + 1,
                display_val.red(),
                locations.len(),
                if locations.len() == 1 { "" } else { "s" }
            );
            for loc in locations {
                println!(
                    "    {} {}:{}",
                    "->".dimmed(),
                    loc.location.file_path.display(),
                    loc.location.line_number
                );
            }
            println!();
        }

        return Ok(());
    }

    // Step 4: For value-based search, search for the string across all files
    for (label, search_value) in &search_terms {
        println!("  {} Tracing: {} ({})", "[*]".dimmed(), &search_value[..search_value.len().min(20)], label);
        println!();

        // Search all text files for this value
        let mut reference_files: Vec<(PathBuf, usize, String)> = Vec::new();

        let walker = ignore::WalkBuilder::new(&path)
            .git_ignore(true)
            .hidden(false)
            .build();

        for entry in walker.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(p) {
                for (line_num, line) in content.lines().enumerate() {
                    if line.contains(search_value.as_str()) {
                        reference_files.push((
                            p.to_path_buf(),
                            line_num + 1,
                            line.trim().to_string(),
                        ));
                    }
                }
            }
        }

        if reference_files.is_empty() {
            println!("    {} No references found in the codebase", "[OK]".green());
        } else {
            println!(
                "    {} {} reference(s) found:",
                "[!]".yellow(),
                reference_files.len().to_string().red().bold()
            );
            println!();
            for (file_path, line_num, line_content) in &reference_files {
                let display_line = if line_content.len() > 80 {
                    format!("{}...", &line_content[..77])
                } else {
                    line_content.clone()
                };
                println!(
                    "    {} {}:{}",
                    "->".dimmed(),
                    file_path.display(),
                    line_num
                );
                println!("      {}", display_line.dimmed());
            }
        }
        println!();
    }

    // Step 5: Show blast radius summary
    if let Some(ref q) = query {
        // Check if this value appears in common sensitive locations
        let sensitive_patterns = [
            ("Environment files", vec![".env", ".env.local", ".env.production"]),
            ("Config files", vec![".toml", ".yaml", ".yml", ".json", ".ini", ".conf"]),
            ("CI/CD", vec!["Jenkinsfile", "Dockerfile", ".github/", ".gitlab-ci", ".circleci"]),
            ("Infrastructure", vec![".tf", ".tfvars", "docker-compose", "k8s", "helm"]),
        ];

        let mut blast_summary: Vec<(&str, usize)> = Vec::new();
        let walker = ignore::WalkBuilder::new(&path)
            .git_ignore(true)
            .hidden(false)
            .build();

        for entry in walker.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let path_str = p.to_string_lossy().to_lowercase();
            if let Ok(content) = std::fs::read_to_string(p) {
                if content.contains(q.as_str()) {
                    for (category, patterns) in &sensitive_patterns {
                        if patterns.iter().any(|pat| path_str.contains(pat)) {
                            if let Some(entry) = blast_summary.iter_mut().find(|(c, _)| c == category) {
                                entry.1 += 1;
                            } else {
                                blast_summary.push((category, 1));
                            }
                        }
                    }
                }
            }
        }

        if !blast_summary.is_empty() {
            println!("{}", "  Blast Radius Summary".bold().underline());
            for (category, count) in &blast_summary {
                let severity_color = if *count > 3 { "[!!]" } else if *count > 1 { "[!]" } else { "[-]" };
                println!("    {} {} ({} file{})", severity_color, category, count, if *count == 1 { "" } else { "s" });
            }
            println!();
        }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// leaktor diff -- compare scan results
// ═══════════════════════════════════════════════════════════════════════════

fn diff_command(old_path: PathBuf, new_path: PathBuf, format: String) -> Result<()> {
    // Load both scan results
    let old_content = std::fs::read_to_string(&old_path)?;
    let new_content = std::fs::read_to_string(&new_path)?;

    let old_report: ScanReport = serde_json::from_str(&old_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", old_path.display(), e))?;
    let new_report: ScanReport = serde_json::from_str(&new_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", new_path.display(), e))?;

    // Build fingerprint sets for comparison
    let old_fingerprints: std::collections::HashMap<String, &DiffFinding> = old_report
        .findings
        .iter()
        .map(|f| (diff_fingerprint(f), f))
        .collect();

    let new_fingerprints: std::collections::HashMap<String, &DiffFinding> = new_report
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
                let sev = f.secret.get("severity").and_then(|s| s.as_str()).unwrap_or("?");
                let stype = f.secret.get("secret_type").and_then(|s| s.as_str()).unwrap_or("Unknown");
                let file = f.location.get("file_path").and_then(|s| s.as_str()).unwrap_or("?");
                let line = f.location.get("line_number").and_then(|l| l.as_u64()).unwrap_or(0);
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
                let stype = f.secret.get("secret_type").and_then(|s| s.as_str()).unwrap_or("Unknown");
                let file = f.location.get("file_path").and_then(|s| s.as_str()).unwrap_or("?");
                let line = f.location.get("line_number").and_then(|l| l.as_u64()).unwrap_or(0);
                println!(
                    "    {} {} at {}:{}",
                    "-".green(),
                    stype,
                    file,
                    line
                );
            }
            println!();
        }

        if added.is_empty() && removed.is_empty() {
            println!("  {} No changes between the two scans.", "[OK]".green());
        }
    }

    Ok(())
}

/// Minimal struct for deserializing scan result JSON
#[derive(Debug, Deserialize)]
struct ScanReport {
    findings: Vec<DiffFinding>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DiffFinding {
    secret: serde_json::Value,
    location: serde_json::Value,
    #[serde(flatten)]
    extra: serde_json::Value,
}

fn diff_fingerprint(f: &DiffFinding) -> String {
    let secret_type = f.secret.get("secret_type").and_then(|s| s.as_str()).unwrap_or("");
    let value = f.secret.get("value").and_then(|s| s.as_str()).unwrap_or("");
    let file = f.location.get("file_path").and_then(|s| s.as_str()).unwrap_or("");
    let line = f.location.get("line_number").and_then(|l| l.as_u64()).unwrap_or(0);
    format!("{}|{}|{}|{}", secret_type, value, file, line)
}

fn config_command(path: PathBuf, format: String) -> Result<()> {
    let config = Config::default();

    match format.as_str() {
        "yaml" | "yml" => {
            config.to_yaml_file(&path)?;
        }
        _ => {
            config.to_toml_file(&path)?;
        }
    }

    println!(
        "{}",
        format!("[OK] Created config file at {}", path.display()).green()
    );
    println!("\nEdit the config file to customize Leaktor's behavior.");

    Ok(())
}

fn install_hook_command(path: PathBuf) -> Result<()> {
    if !path.exists() {
        anyhow::bail!(
            "{} Directory does not exist: {}\n{} Provide a path to a git repository.",
            "Error:".red().bold(),
            path.display(),
            "Hint:".yellow().bold()
        );
    }

    let git_dir = path.join(".git");
    if !git_dir.exists() {
        anyhow::bail!(
            "{} Not a git repository: {}\n{} Run 'git init' first or provide a path to an existing git repository.",
            "Error:".red().bold(),
            path.display(),
            "Hint:".yellow().bold()
        );
    }

    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("pre-commit");
    let hook_content = r#"#!/bin/sh
# Leaktor pre-commit hook
# Scans only staged files for secrets before committing

echo "Running Leaktor security scan on staged files..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No staged files to scan."
    exit 0
fi

# Create a temporary directory for staged content
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Copy staged file contents to temp directory
for FILE in $STAGED_FILES; do
    DIR=$(dirname "$FILE")
    mkdir -p "$TMPDIR/$DIR"
    git show ":$FILE" > "$TMPDIR/$FILE" 2>/dev/null || continue
done

# Scan the staged files
leaktor scan "$TMPDIR" --git-history=false --fail-on-found --format console --min-confidence 0.7

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Secrets detected in staged files. Commit aborted."
    echo "   Review the findings above and remove secrets before committing."
    echo "   Use 'git commit --no-verify' to bypass (not recommended)."
    echo "   Use '// leaktor:ignore' to suppress specific false positives."
    exit 1
fi

echo "No secrets detected in staged files."
exit 0
"#;

    std::fs::write(&hook_path, hook_content)?;

    // Make executable on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    println!(
        "{}",
        format!("[OK] Pre-commit hook installed at {}", hook_path.display()).green()
    );
    println!("\nThe hook will run automatically before each commit.");
    println!(
        "Use {} to bypass the hook if needed.",
        "'git commit --no-verify'".yellow()
    );

    Ok(())
}

fn list_command() {
    println!("{}", "Supported Secret Types".bold().underline());
    println!();

    let patterns = leaktor::detectors::patterns::PATTERNS.iter();

    let mut by_category: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();

    for pattern in patterns {
        let secret_name = pattern.name.as_str();
        let category = if secret_name.contains("AWS") {
            "AWS"
        } else if secret_name.contains("GCP") || secret_name.contains("Firebase") {
            "Google Cloud"
        } else if secret_name.contains("Azure") {
            "Azure"
        } else if secret_name.contains("GitHub") {
            "GitHub"
        } else if secret_name.contains("GitLab") {
            "GitLab"
        } else if secret_name.contains("Private Key") || secret_name.contains("SSH") {
            "Private Keys"
        } else if secret_name.contains("Database")
            || secret_name.contains("Connection")
            || secret_name.contains("PlanetScale")
            || secret_name.contains("Supabase")
        {
            "Databases"
        } else if secret_name.contains("OpenAI")
            || secret_name.contains("Anthropic")
            || secret_name.contains("Cohere")
            || secret_name.contains("HuggingFace")
            || secret_name.contains("Replicate")
        {
            "AI/ML"
        } else if secret_name.contains("NPM")
            || secret_name.contains("PyPI")
            || secret_name.contains("NuGet")
            || secret_name.contains("RubyGems")
            || secret_name.contains("Docker Hub")
        {
            "Package Registries"
        } else if secret_name.contains("Discord")
            || secret_name.contains("Slack")
            || secret_name.contains("Telegram")
        {
            "Communication"
        } else if secret_name.contains("Stripe")
            || secret_name.contains("Shopify")
            || secret_name.contains("Square")
            || secret_name.contains("PayPal")
        {
            "Payment/E-commerce"
        } else if secret_name.contains("Datadog")
            || secret_name.contains("New Relic")
            || secret_name.contains("Sentry")
            || secret_name.contains("Grafana")
            || secret_name.contains("Elastic")
            || secret_name.contains("Algolia")
        {
            "Monitoring/Observability"
        } else if secret_name.contains("CircleCI")
            || secret_name.contains("Travis")
            || secret_name.contains("Vercel")
            || secret_name.contains("Netlify")
            || secret_name.contains("Heroku")
        {
            "CI/CD & Hosting"
        } else if secret_name.contains("Okta")
            || secret_name.contains("Auth0")
            || secret_name.contains("JWT")
            || secret_name.contains("OAuth")
        {
            "Authentication"
        } else if secret_name.contains("Cloudflare")
            || secret_name.contains("DigitalOcean")
            || secret_name.contains("HashiCorp")
            || secret_name.contains("Linear")
            || secret_name.contains("Notion")
            || secret_name.contains("Airtable")
        {
            "Cloud Services"
        } else {
            "Other"
        };

        // Deduplicate within category
        let entries = by_category.entry(category).or_default();
        if !entries.contains(&secret_name.to_string()) {
            entries.push(secret_name.to_string());
        }
    }

    let categories = [
        "AWS",
        "Google Cloud",
        "Azure",
        "GitHub",
        "GitLab",
        "AI/ML",
        "Private Keys",
        "Databases",
        "Package Registries",
        "Communication",
        "Payment/E-commerce",
        "Monitoring/Observability",
        "CI/CD & Hosting",
        "Authentication",
        "Cloud Services",
        "Other",
    ];

    for category in categories {
        if let Some(items) = by_category.get(category) {
            println!("{}", format!("{}:", category).cyan().bold());
            for item in items {
                println!("  - {}", item);
            }
            println!();
        }
    }

    // Deduplicate for unique pattern count
    let mut unique_names: Vec<&str> = leaktor::detectors::patterns::PATTERNS
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    unique_names.sort();
    unique_names.dedup();

    println!(
        "{} {} ({} regex patterns)",
        "Total secret types:".bold(),
        unique_names.len(),
        leaktor::detectors::patterns::PATTERNS.len()
    );
}
