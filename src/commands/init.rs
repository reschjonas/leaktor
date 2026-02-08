use anyhow::{Context, Result};
use colored::*;
use leaktor::*;
use std::path::PathBuf;

pub fn init_project_command(
    path: PathBuf,
    _yes: bool,
    create_baseline: bool,
    no_ci: bool,
    no_hook: bool,
    config_format: String,
) -> Result<()> {
    // Resolve the project root to an absolute path.
    // `std::fs::canonicalize` resolves symlinks and `.` / `..` components and
    // verifies that the path actually exists, preventing the confusing behaviour
    // where `leaktor init /some/path` silently creates files in the wrong place.
    let project_root = std::fs::canonicalize(&path).with_context(|| {
        format!(
            "Cannot resolve project path: {}\nMake sure the directory exists before running `leaktor init`.",
            path.display()
        )
    })?;

    if !project_root.is_dir() {
        anyhow::bail!(
            "Path is not a directory: {}\n`leaktor init` expects a directory.",
            project_root.display()
        );
    }

    println!(
        "{} {}",
        "Initializing Leaktor for".bold(),
        project_root.display().to_string().cyan()
    );
    println!();

    // 1. Create config file (.leaktor.toml or .leaktor.yaml)
    let use_yaml = matches!(config_format.as_str(), "yaml" | "yml");
    let config_filename = if use_yaml {
        ".leaktor.yaml"
    } else {
        ".leaktor.toml"
    };
    let config_path = project_root.join(config_filename);
    // Also check for the other format existing
    let alt_config = project_root.join(if use_yaml {
        ".leaktor.toml"
    } else {
        ".leaktor.yaml"
    });
    if config_path.exists() || alt_config.exists() {
        println!("  {} config file already exists", "skip".dimmed());
    } else {
        let config = Config::default();
        if use_yaml {
            config.to_yaml_file(&config_path)?;
        } else {
            config.to_toml_file(&config_path)?;
        }
        println!("  {} Created {}", "[OK]".green(), config_filename.bold());
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
                println!(
                    "  {} Installed {}",
                    "[OK]".green(),
                    "pre-commit hook".bold()
                );
            }
        } else {
            println!(
                "  {} No .git directory found (skipping hook)",
                "skip".dimmed()
            );
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
        println!(
            "  {} Running initial scan to create baseline...",
            "...".dimmed()
        );
        let scanner = FilesystemScanner::new(project_root.clone()).with_entropy_threshold(3.5);
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
        config_filename.cyan()
    );
    println!("  2. Run {} to scan your project", "leaktor scan".cyan());
    if create_baseline {
        println!(
            "  3. Use {} to suppress existing findings",
            "leaktor scan --baseline .leaktor-baseline.json".cyan()
        );
    }
    println!();

    Ok(())
}
