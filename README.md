# Leaktor

**A blazingly fast secrets scanner with validation capabilities**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
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

### Quick Install (Recommended)

**Using Cargo** (All Platforms)
```bash
cargo install leaktor
```

### Platform-Specific Installation

<details>
<summary><b>🪟 Windows</b></summary>

#### Option 1: Using Cargo (Recommended)
```powershell
# Install Rust from https://rustup.rs if not already installed
cargo install leaktor
```

#### Option 2: Using Scoop
```powershell
scoop bucket add leaktor https://github.com/reschjonas/scoop-leaktor
scoop install leaktor
```

#### Option 3: Download Pre-built Binary
1. Download the latest Windows binary from [Releases](https://github.com/reschjonas/leaktor/releases)
2. Extract `leaktor.exe` to a directory in your PATH (e.g., `C:\Program Files\leaktor\`)
3. Add the directory to your PATH environment variable

#### Option 4: Build from Source
```powershell
# Requires Rust and Git
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
# Binary will be at .\target\release\leaktor.exe
# Move it to a directory in your PATH or add target\release to PATH
```

**Verify Installation:**
```powershell
leaktor --version
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

#### Option 1: Using Homebrew (Recommended)
```bash
brew tap reschjonas/tap
brew install leaktor
```

#### Option 2: Using Cargo
```bash
# Install Rust from https://rustup.rs if not already installed
cargo install leaktor
```

#### Option 3: Download Pre-built Binary
```bash
# Download and install
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-macos.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/
```

#### Option 4: Build from Source
```bash
# Install Rust and Git if not already installed
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
sudo cp target/release/leaktor /usr/local/bin/
```

**Verify Installation:**
```bash
leaktor --version
```

</details>

<details>
<summary><b>🐧 Linux</b></summary>

#### Option 1: Using Cargo (Recommended)
```bash
# Install Rust from https://rustup.rs if not already installed
cargo install leaktor
```

#### Option 2: Download Pre-built Binary
```bash
# For x86_64
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-x86_64.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/

# For ARM64
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-aarch64.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/
```

#### Option 3: Build from Source
```bash
# Install Rust and Git if not already installed
# Debian/Ubuntu:
sudo apt install build-essential git pkg-config libssl-dev
# Fedora/RHEL:
sudo dnf install gcc git pkg-config openssl-devel
# Arch:
sudo pacman -S base-devel git openssl

# Build and install
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
sudo cp target/release/leaktor /usr/local/bin/
```

**Verify Installation:**
```bash
leaktor --version
```

</details>

###  Install from Source (Development)

For contributors or those who want the latest development version:

```bash
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release

# The binary will be at target/release/leaktor
# You can run it directly or copy to your PATH
./target/release/leaktor --version
```

##  Quick Start

### 1️⃣ Basic Scanning

**Scan your current project:**
```bash
leaktor scan
```

**Scan a specific directory:**
```bash
leaktor scan /path/to/project
```

**Scan and validate secrets** (checks if they're actually active):
```bash
leaktor scan --validate
```

### 2️⃣ Generate Reports

**Console output** (default - colored, formatted):
```bash
leaktor scan
```

**JSON report** (for programmatic processing):
```bash
leaktor scan --format json --output results.json
```

**HTML report** (beautiful, interactive web report):
```bash
leaktor scan --format html --output report.html
# Open report.html in your browser
```

**SARIF report** (for GitHub Security tab, IDEs):
```bash
leaktor scan --format sarif --output results.sarif
```

### 3️⃣ Set Up Protection

**Create an ignore file** (exclude false positives):
```bash
leaktor init
# Edit .leaktorignore to add patterns
```

**Install pre-commit hook** (prevent secret commits):
```bash
leaktor install-hook
# Hook will run automatically before each commit
```

**Generate config file** (customize behavior):
```bash
leaktor config
# Edit .leaktor.toml to adjust settings
```

### 4️⃣ Common Use Cases

**Scan before pushing to remote:**
```bash
leaktor scan --fail-on-found
# Exits with code 1 if secrets found - great for CI/CD
```

**Scan only working directory** (skip git history):
```bash
leaktor scan --git-history=false
```

**High-security scan** (strict settings):
```bash
leaktor scan --min-confidence 0.9 --entropy 4.0 --validate
```

**Quick scan** (exclude tests, higher confidence):
```bash
leaktor scan --exclude-tests --min-confidence 0.8
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
