use anyhow::Result;
use colored::*;
use leaktor::Config;
use std::path::PathBuf;

pub fn config_command(path: PathBuf, format: String) -> Result<()> {
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

pub fn install_hook_command(path: PathBuf) -> Result<()> {
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
