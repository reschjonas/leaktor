use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use leaktor::*;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "leaktor",
    about = "🔒 A blazingly fast secrets scanner with validation capabilities",
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
        #[arg(long, default_value = "true", help = "Scan git history (true|false)")]
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
        #[arg(short, long, default_value = "true", help = "Show code context (true|false)")]
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
    },

    /// Initialize a .leaktorignore file in the current directory
    ///
    /// The .leaktorignore file allows you to specify patterns for files
    /// or content that should be ignored during scans.
    Init {
        /// Output path for the ignore file
        #[arg(default_value = ".leaktorignore", help = "Path for .leaktorignore file")]
        path: PathBuf,
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
            )
            .await?;
        }
        Commands::Init { path } => {
            init_command(path)?;
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
) -> Result<()> {
    // Validate inputs
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

    let start = Instant::now();

    // Load ignore manager
    let ignore_file = path.join(".leaktorignore");
    let ignore_manager = if ignore_file.exists() {
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
    spinner.set_message("Scanning for secrets...");

    // Determine scanner type
    let mut findings = if path.join(".git").exists() {
        spinner.set_message("Scanning git repository...");
        let scanner = GitScanner::new(path.clone())
            .with_history(git_history)
            .with_entropy_threshold(entropy);

        let scanner = if let Some(depth) = max_depth {
            scanner.with_max_depth(depth)
        } else {
            scanner
        };

        scanner.scan()?
    } else {
        spinner.set_message("Scanning filesystem...");
        let scanner = FilesystemScanner::new(path.clone()).with_entropy_threshold(entropy);

        scanner.scan()?
    };

    spinner.finish_and_clear();

    // Filter findings
    findings.retain(|f| {
        // Filter by confidence
        if f.secret.confidence < min_confidence {
            return false;
        }

        // Filter by test files
        if exclude_tests && f.context.is_test_file {
            return false;
        }

        // Check ignore patterns
        if ignore_manager.should_ignore(&f.location.file_path, &f.context.line_content) {
            return false;
        }

        true
    });

    // Validate secrets if requested
    if validate && !findings.is_empty() {
        let validate_spinner = ProgressBar::new(findings.len() as u64);
        validate_spinner.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Validating secrets...")
                .unwrap()
                .progress_chars("#>-"),
        );

        for finding in &mut findings {
            validators::validate_secret(&mut finding.secret).await?;
            validate_spinner.inc(1);
        }

        validate_spinner.finish_and_clear();
    }

    let duration = start.elapsed();

    // Output results
    match format.as_str() {
        "json" => {
            let output_formatter = JsonOutput::new(true);
            if let Some(output_path) = output_path {
                output_formatter.write_to_file(&findings, &output_path)?;
                println!(
                    "{}",
                    format!("✓ Results written to {}", output_path.display()).green()
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
                    format!("✓ Results written to {}", output_path.display()).green()
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
                format!("✓ HTML report written to {}", output_path.display()).green()
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

    println!(
        "\n{} {}",
        "⏱".dimmed(),
        format!("Scan completed in {:.2}s", duration.as_secs_f64()).dimmed()
    );

    // Exit with error if secrets found and fail_on_found is set
    if fail_on_found && !findings.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn init_command(path: PathBuf) -> Result<()> {
    let ignore_manager = IgnoreManager::new();
    ignore_manager.save_to_file(&path)?;

    println!(
        "{}",
        format!("✓ Created .leaktorignore file at {}", path.display()).green()
    );
    println!("\nAdd patterns to ignore specific files or secrets:");
    println!("  {}", "*.test.js".dimmed());
    println!("  {}", "node_modules/*".dimmed());
    println!("  {}", "# Inline comments: // leaktor:ignore".dimmed());

    Ok(())
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
        format!("✓ Created config file at {}", path.display()).green()
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

echo "🔒 Running Leaktor security scan..."

leaktor scan --fail-on-found --format console

if [ $? -ne 0 ]; then
    echo "❌ Secrets detected! Commit aborted."
    echo "   Review the findings above or use 'git commit --no-verify' to bypass."
    exit 1
fi

echo "✓ No secrets detected"
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
        format!("✓ Pre-commit hook installed at {}", hook_path.display()).green()
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
        } else if secret_name.contains("GCP") {
            "Google Cloud"
        } else if secret_name.contains("Azure") {
            "Azure"
        } else if secret_name.contains("GitHub") {
            "GitHub"
        } else if secret_name.contains("GitLab") {
            "GitLab"
        } else if secret_name.contains("Private Key") || secret_name.contains("SSH") {
            "Private Keys"
        } else if secret_name.contains("Database") || secret_name.contains("Connection") {
            "Databases"
        } else {
            "Other"
        };

        by_category
            .entry(category)
            .or_default()
            .push(secret_name.to_string());
    }

    let categories = [
        "AWS",
        "Google Cloud",
        "Azure",
        "GitHub",
        "GitLab",
        "Private Keys",
        "Databases",
        "Other",
    ];

    for category in categories {
        if let Some(items) = by_category.get(category) {
            println!("{}", format!("{}:", category).cyan().bold());
            for item in items {
                println!("  • {}", item);
            }
            println!();
        }
    }

    println!("{}", "Total patterns: ".bold());
    println!("{}", leaktor::detectors::patterns::PATTERNS.len());
}
