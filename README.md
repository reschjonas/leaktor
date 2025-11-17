# Leaktor

**A blazingly fast secrets scanner with validation capabilities**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/reschjonas/leaktor)

Leaktor is a modern, high-performance secrets scanner designed for security professionals and developers. Built in Rust, it combines pattern matching, entropy analysis, and live secret validation to help you find and verify exposed credentials in your codebase and git history.

##  Features

### Core Capabilities
-  **Comprehensive Secret Detection** - Detects 40+ types of secrets including AWS keys, GitHub tokens, API keys, private keys, and database credentials
-  **High Accuracy** - Combines regex patterns with entropy analysis to minimize false positives
-  **Blazingly Fast** - Written in Rust with parallel scanning for maximum performance
-  **Secret Validation** - Validates AWS and GitHub credentials to confirm if they're active (optin)
-  **Context-Aware** - Understands test files, documentation, and comments to reduce noise
-  **Git History Scanning** - Scans entire git history to find secrets in old commits

### Developer Experience
-  **Beautiful Console Output** - Colored, formatted output with severity indicators
-  **Multiple Output Formats** - JSON, SARIF (for CI/CD), HTML reports, and console
-  **Flexible Configuration** - YAML/TOML config files with sensible defaults
-  **Smart Ignoring** - `.leaktorignore` file and inline `// leaktor:ignore` comments
-  **Pre-commit Hooks** - Prevent secrets from being committed
-  **Custom Patterns** - Add your own regex patterns for company-specific secrets

##  Installation

### From Source (Current)

```bash
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
sudo cp target/release/leaktor /usr/local/bin/
```

### Using Cargo (Future)

```bash
cargo install leaktor
```

##  Quick Start

### Basic Usage

Scan current directory:
```bash
leaktor scan
```

Scan a specific directory:
```bash
leaktor scan /path/to/project
```

Scan with validation (checks if secrets are active):
```bash
leaktor scan --validate
```

### Output Formats

JSON output:
```bash
leaktor scan --format json --output results.json
```

SARIF output for CI/CD:
```bash
leaktor scan --format sarif --output results.sarif
```

HTML report:
```bash
leaktor scan --format html --output report.html
```

### Advanced Options

```bash
# Scan only working directory (skip git history)
leaktor scan --git-history false

# Limit git history depth
leaktor scan --max-depth 100

# Adjust entropy threshold (default: 3.5)
leaktor scan --entropy 4.0

# Minimum confidence score (0.0 - 1.0)
leaktor scan --min-confidence 0.8

# Exclude test files
leaktor scan --exclude-tests

# Fail with exit code 1 if secrets found (useful for CI/CD)
leaktor scan --fail-on-found
```

##  Usage Examples

### Initialize Ignore File

Create a `.leaktorignore` file:
```bash
leaktor init
```

Example `.leaktorignore`:
```
# Ignore test files
*.test.js
*_test.go
tests/*

# Ignore dependencies
node_modules/*
vendor/*

# Ignore specific files
config/example.env
```

### Inline Ignoring

Add inline comments to ignore specific lines:
```python
# This will be ignored
API_KEY = "test_key_1234567890"  # leaktor:ignore

# This will be detected
PROD_API_KEY = "live_key_abcdefgh"
```

### Create Configuration File

Generate a config file:
```bash
leaktor config
```

Example `.leaktor.toml`:
```toml
entropy_threshold = 3.5
min_confidence = 0.6
enable_validation = false
scan_git_history = true
max_git_depth = 1000
respect_gitignore = true
max_file_size = 1048576  # 1MB
exclude_tests = false
exclude_docs = false
report_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

[[custom_patterns]]
name = "Internal API Key"
regex = "internal_api_[0-9a-f]{32}"
severity = "HIGH"
confidence = 0.85
```

### Install Pre-commit Hook

Automatically scan before each commit:
```bash
leaktor install-hook
```

This creates a pre-commit hook that prevents commits containing secrets.

### List Supported Secret Types

See all detectable secret types:
```bash
leaktor list
```

##  What Secrets Does Leaktor Detect?

### Cloud Provider Credentials
- AWS Access Keys, Secret Keys, Session Tokens
- Google Cloud API Keys, Service Accounts
- Azure Storage Keys, Connection Strings, Client Secrets

### Version Control Platforms
- GitHub Personal Access Tokens, OAuth Tokens
- GitLab Personal Access Tokens
- Bitbucket Tokens

### API Keys & Services
- Stripe API Keys
- SendGrid API Keys
- Twilio API Keys
- Slack Tokens & Webhooks
- Mailgun, Mailchimp, Heroku API Keys

### Private Keys
- RSA Private Keys
- SSH Private Keys
- PGP Private Keys
- EC Private Keys
- OpenSSL Private Keys

### Databases
- MongoDB Connection Strings
- PostgreSQL Connection Strings
- MySQL Connection Strings
- Redis Connection Strings

### Other
- JWT Tokens
- OAuth Tokens
- Generic API Keys
- Passwords in URLs
- High-Entropy Strings

##  How It Works

Leaktor uses a multi-layered approach to detect secrets:

1. **Pattern Matching** - Regex patterns for known secret formats
2. **Entropy Analysis** - Shannon entropy calculation to detect random strings
3. **Context Analysis** - Understands file types and code context
4. **Validation** (Optional) - Tests if secrets are active using their respective APIs

### Detection Flow

```
File → Pattern Match → Entropy Check → Context Analysis → Severity Scoring → Validation (opt-in) → Report
```

##  Output Examples

### Console Output

```
╔═══════════════════════════════════════════════╗
║           🔒 LEAKTOR SECURITY SCAN            ║
╚═══════════════════════════════════════════════╝

Summary
Total Findings: 3
  Critical: 2
  High: 1
  Medium: 0
  Low: 0

Validated Secrets: 1
Likely False Positives: 0

Findings

[1] 🔴 AWS Access Key [CRITICAL]
  Status: ✓ VALIDATED
  Location: src/config.rs:42
  Confidence: 95%
  Entropy: 4.32
  Context:
    const AWS_KEY = process.env.AWS_ACCESS_KEY;
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  // Found here
    AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG

═════════════════════════════════════════════════
⚠ Scan complete. 3 secrets detected.
═════════════════════════════════════════════════
```

### HTML Report

Leaktor generates beautiful, self-contained HTML reports with:
- Summary statistics
- Severity breakdown
- Color-coded findings
- Code context
- Validation status
- Dark theme for easy reading

##  Integration

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full git history

      - name: Install Leaktor
        run: |
          cargo install leaktor

      - name: Scan for secrets
        run: |
          leaktor scan --format sarif --output results.sarif --fail-on-found

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

#### GitLab CI

```yaml
secrets-scan:
  image: rust:latest
  script:
    - cargo install leaktor
    - leaktor scan --format json --output results.json --fail-on-found
  artifacts:
    reports:
      sast: results.json
```

##  Configuration

Leaktor supports configuration files in TOML or YAML format:

- `.leaktor.toml`
- `.leaktor.yaml`
- `.leaktor.yml`

Place in your project root for automatic loading.

##  Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

##  Security

Leaktor is designed for security professionals. Please use responsibly:

- ✅ Scanning your own codebases
- ✅ Authorized security assessments
- ✅ Educational purposes
- ❌ Unauthorized access to systems
- ❌ Using validated credentials without permission

If you find a security issue in Leaktor itself, please report it privately to the maintainer.

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Author

**Jonas Resch** ([@reschjonas](https://github.com/reschjonas))

Pentester and security tools developer. Building practical tools for the security community.

##  Acknowledgments

- Built with [Rust](https://www.rust-lang.org/)

##  Support

-  [Report a bug](https://github.com/reschjonas/leaktor/issues)
-  [Request a feature](https://github.com/reschjonas/leaktor/issues)
-  Contact: Create an issue on GitHub

---

**⭐ If you find Leaktor useful, please star the repository!**
