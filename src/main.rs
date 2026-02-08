use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

/// Reset the SIGPIPE signal handler to the default (terminate silently).
///
/// By default Rust ignores SIGPIPE, which causes `println!` to panic with
/// "Broken pipe" (exit code 101) when output is piped through truncating
/// commands like `head` or `tail`.  Resetting to SIG_DFL makes the process
/// terminate cleanly, which is the expected behavior for CLI tools.
#[cfg(unix)]
fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

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
    /// Scan a directory, file, or git repository for secrets
    ///
    /// Examples:
    ///   leaktor scan                           # Scan current directory
    ///   leaktor scan /path/to/project          # Scan specific directory
    ///   leaktor scan /path/to/file.env         # Scan a single file
    ///   leaktor scan --validate                # Scan and validate secrets
    ///   leaktor scan --format html -o report.html  # Generate HTML report
    ///   leaktor scan --stdin                   # Scan piped input
    ///   leaktor scan --since-commit abc123     # Only new commits since abc123
    ///   leaktor scan --baseline baseline.json  # Suppress known findings
    Scan {
        /// Path to scan (directory, file, or git repository)
        #[arg(default_value = ".", help = "Path to the directory or file to scan")]
        path: PathBuf,

        /// Output format: console (default), json, sarif, or html
        #[arg(
            short,
            long,
            default_value = "console",
            help = "Output format (console|json|sarif|html)"
        )]
        format: String,

        /// Output file path (required for HTML, optional for others)
        #[arg(short, long, help = "Write output to file instead of stdout")]
        output: Option<PathBuf>,

        /// Scan git history for secrets in old commits
        #[arg(long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", help = "Scan git history (true|false)")]
        git_history: bool,

        /// Maximum git history depth to scan (number of commits)
        #[arg(long, help = "Limit git history depth in commits (e.g., 100)")]
        max_depth: Option<usize>,

        /// Maximum filesystem recursion depth (0 = only files in the root directory)
        #[arg(long, help = "Limit filesystem recursion depth (0 = root only)")]
        max_fs_depth: Option<usize>,

        /// Entropy threshold for detecting random strings
        #[arg(
            long,
            default_value = "3.5",
            help = "Entropy threshold (higher = more random)"
        )]
        entropy: f64,

        /// Validate detected secrets against their APIs
        #[arg(short = 'V', long, help = "Validate secrets are active (requires network)")]
        validate: bool,

        /// Show verbose output with additional details
        #[arg(short, long, help = "Show detailed information")]
        verbose: bool,

        /// Suppress all informational output (only show findings/errors)
        #[arg(short, long, help = "Suppress informational output (for scripting)")]
        quiet: bool,

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
        #[arg(
            long,
            help = "Scan a commit range (e.g., abc1234..def5678 or abc1234..HEAD)"
        )]
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

        /// Send findings to a webhook URL (Slack, Teams, PagerDuty, or generic HTTP POST)
        #[arg(long, help = "POST findings to a webhook URL (Slack/Teams/generic)")]
        webhook_url: Option<String>,
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
        #[arg(
            long = "type",
            short = 't',
            help = "Secret type to trace (e.g., 'AWS Access Key')"
        )]
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
        #[arg(
            short,
            long,
            default_value = "console",
            help = "Output format (console|json)"
        )]
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

        /// Configuration file format (toml or yaml)
        #[arg(short, long, default_value = "toml", help = "Config format (toml|yaml)")]
        format: String,
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

    /// Generate remediation scripts for detected secrets
    ///
    /// For each finding, generates actionable remediation steps:
    ///   - Rotate the key via the provider's CLI
    ///   - Remove from git history (git filter-repo)
    ///   - Add to .leaktorignore
    ///
    /// Examples:
    ///   leaktor remediate scan.json              # Generate remediation for findings
    ///   leaktor remediate scan.json -o fix.sh    # Write remediation script to file
    ///   leaktor remediate scan.json --format md  # Output as markdown
    Remediate {
        /// Path to a JSON scan result file
        #[arg(help = "JSON scan result file to generate remediation for")]
        input: PathBuf,

        /// Output file for remediation script
        #[arg(short, long, help = "Write remediation to file")]
        output: Option<PathBuf>,

        /// Output format: console (default), markdown, or script
        #[arg(
            short,
            long,
            default_value = "console",
            help = "Output format (console|markdown|script)"
        )]
        format: String,
    },

    /// List all supported secret types and patterns
    ///
    /// Display all secret types that Leaktor can detect, organized by category.
    List,

    /// Scan an S3 bucket for secrets
    ///
    /// Requires AWS credentials (env vars, ~/.aws/credentials, or IAM role).
    ///
    /// Examples:
    ///   leaktor scan-s3 my-bucket                        # Scan all objects
    ///   leaktor scan-s3 my-bucket --prefix config/       # Only objects under config/
    ///   leaktor scan-s3 my-bucket --region eu-west-1     # Specify region
    ///   leaktor scan-s3 my-bucket --validate             # Validate found secrets
    #[cfg(feature = "s3")]
    ScanS3 {
        /// S3 bucket name
        #[arg(help = "Name of the S3 bucket to scan")]
        bucket: String,

        /// Only scan objects with this key prefix
        #[arg(long, help = "S3 key prefix to filter objects (e.g., config/)")]
        prefix: Option<String>,

        /// AWS region (uses default provider chain if omitted)
        #[arg(long, help = "AWS region (e.g., us-east-1)")]
        region: Option<String>,

        /// Output format: console (default), json, sarif, or html
        #[arg(short, long, default_value = "console", help = "Output format (console|json|sarif|html)")]
        format: String,

        /// Output file path
        #[arg(short, long, help = "Write output to file instead of stdout")]
        output: Option<PathBuf>,

        /// Entropy threshold
        #[arg(long, default_value = "3.5", help = "Entropy threshold (higher = more random)")]
        entropy: f64,

        /// Validate detected secrets
        #[arg(short = 'V', long, help = "Validate secrets are active (requires network)")]
        validate: bool,

        /// Show verbose output
        #[arg(short, long, help = "Show detailed information")]
        verbose: bool,

        /// Suppress informational output
        #[arg(short, long, help = "Suppress informational output")]
        quiet: bool,

        /// Show code context around findings
        #[arg(short, long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", help = "Show code context (true|false)")]
        context: bool,

        /// Minimum confidence score
        #[arg(long, default_value = "0.6", help = "Confidence threshold (0.0-1.0)")]
        min_confidence: f64,

        /// Exit with error code 1 if any secrets found
        #[arg(long, help = "Exit with error if secrets found (for CI/CD)")]
        fail_on_found: bool,

        /// Only show verified secrets
        #[arg(long, help = "Only report verified (active) secrets")]
        only_verified: bool,
    },

    /// Scan a Docker image for secrets
    ///
    /// Requires a running Docker daemon. Pulls the image (unless --no-pull),
    /// exports the filesystem, and scans text files for secrets.
    ///
    /// Examples:
    ///   leaktor scan-docker myapp:latest                  # Scan a local image
    ///   leaktor scan-docker ghcr.io/org/repo:v1.2         # Pull and scan remote
    ///   leaktor scan-docker myapp:latest --no-pull        # Skip pulling
    ///   leaktor scan-docker myapp:latest --validate       # Validate found secrets
    #[cfg(feature = "docker")]
    ScanDocker {
        /// Docker image reference (e.g., nginx:latest, ghcr.io/org/app:v2)
        #[arg(help = "Docker image to scan (e.g., nginx:latest)")]
        image: String,

        /// Output format: console (default), json, sarif, or html
        #[arg(short, long, default_value = "console", help = "Output format (console|json|sarif|html)")]
        format: String,

        /// Output file path
        #[arg(short, long, help = "Write output to file instead of stdout")]
        output: Option<PathBuf>,

        /// Entropy threshold
        #[arg(long, default_value = "3.5", help = "Entropy threshold (higher = more random)")]
        entropy: f64,

        /// Validate detected secrets
        #[arg(short = 'V', long, help = "Validate secrets are active (requires network)")]
        validate: bool,

        /// Show verbose output
        #[arg(short, long, help = "Show detailed information")]
        verbose: bool,

        /// Suppress informational output
        #[arg(short, long, help = "Suppress informational output")]
        quiet: bool,

        /// Show code context around findings
        #[arg(short, long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", help = "Show code context (true|false)")]
        context: bool,

        /// Minimum confidence score
        #[arg(long, default_value = "0.6", help = "Confidence threshold (0.0-1.0)")]
        min_confidence: f64,

        /// Exit with error code 1 if any secrets found
        #[arg(long, help = "Exit with error if secrets found (for CI/CD)")]
        fail_on_found: bool,

        /// Only show verified secrets
        #[arg(long, help = "Only report verified (active) secrets")]
        only_verified: bool,

        /// Don't pull the image before scanning (use local copy)
        #[arg(long, help = "Skip pulling the image (use local copy)")]
        no_pull: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    reset_sigpipe();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            output,
            git_history,
            max_depth,
            max_fs_depth,
            entropy,
            validate,
            verbose,
            quiet,
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
            webhook_url,
        } => {
            commands::scan::scan_command(
                path,
                format,
                output,
                git_history,
                max_depth,
                max_fs_depth,
                entropy,
                validate,
                verbose,
                quiet,
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
                webhook_url,
            )
            .await?;
        }
        Commands::Trace {
            query,
            secret_type,
            file,
            path,
        } => {
            commands::trace::trace_command(query, secret_type, file, path)?;
        }
        Commands::Diff { old, new, format } => {
            commands::diff::diff_command(old, new, format)?;
        }
        Commands::Init {
            path,
            yes,
            baseline,
            no_ci,
            no_hook,
            format,
        } => {
            commands::init::init_project_command(path, yes, baseline, no_ci, no_hook, format)?;
        }
        Commands::Config { path, format } => {
            commands::config::config_command(path, format)?;
        }
        Commands::InstallHook { path } => {
            commands::config::install_hook_command(path)?;
        }
        Commands::Remediate {
            input,
            output,
            format,
        } => {
            commands::remediate::remediate_command(input, output, format)?;
        }
        Commands::List => {
            commands::list::list_command();
        }

        #[cfg(feature = "s3")]
        Commands::ScanS3 {
            bucket,
            prefix,
            region,
            format,
            output,
            entropy,
            validate,
            verbose,
            quiet,
            context,
            min_confidence,
            fail_on_found,
            only_verified,
        } => {
            commands::scan_s3::scan_s3_command(
                bucket,
                prefix,
                region,
                format,
                output,
                entropy,
                validate,
                verbose,
                quiet,
                context,
                min_confidence,
                fail_on_found,
                only_verified,
            )
            .await?;
        }

        #[cfg(feature = "docker")]
        Commands::ScanDocker {
            image,
            format,
            output,
            entropy,
            validate,
            verbose,
            quiet,
            context,
            min_confidence,
            fail_on_found,
            only_verified,
            no_pull,
        } => {
            commands::scan_docker::scan_docker_command(
                image,
                format,
                output,
                entropy,
                validate,
                verbose,
                quiet,
                context,
                min_confidence,
                fail_on_found,
                only_verified,
                no_pull,
            )
            .await?;
        }
    }

    Ok(())
}
