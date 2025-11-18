# Leaktor

**A blazingly fast secrets scanner with validation capabilities**

[![Crates.io](https://img.shields.io/crates/v/leaktor.svg)](https://crates.io/crates/leaktor)
[![Downloads](https://img.shields.io/crates/d/leaktor.svg)](https://crates.io/crates/leaktor)
[![GitHub Release](https://img.shields.io/github/v/release/reschjonas/leaktor)](https://github.com/reschjonas/leaktor/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/reschjonas/leaktor)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Quick Install](#quick-install-recommended)
  - [Platform-Specific](#platform-specific-installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Supported Secrets](#supported-secrets)
- [How It Works](#how-it-works)
- [Output Formats](#output-formats)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Leaktor is a modern, high-performance secrets scanner designed for security professionals and developers. Built in Rust, it combines pattern matching, entropy analysis, and live secret validation to help you find and verify exposed credentials in your codebase and git history.

### Key Highlights

| Feature | Description |
|---------|-------------|
| **40+ Secret Types** | AWS, GitHub, Azure, private keys, database credentials, and more |
| **Validation Support** | Verify if AWS and GitHub secrets are actually active |
| **Git History Scanning** | Find secrets in your entire commit history |
| **Multiple Outputs** | Console, JSON, SARIF, and interactive HTML reports |
| **High Performance** | Parallel scanning with Rust's speed |
| **CI/CD Ready** | SARIF output for GitHub Security, fail-on-found flag |

---

## Features

### Detection Capabilities

- **Comprehensive Pattern Matching** - Regex patterns for 40+ secret types
- **Entropy Analysis** - Shannon entropy calculation to detect random strings and API keys
- **Context-Aware Filtering** - Understands test files, documentation, and comments to reduce false positives
- **Git History Scanning** - Scans entire commit history, not just current files
- **Secret Validation** - Optional live validation for AWS and GitHub credentials
- **Custom Patterns** - Add your own regex patterns for company-specific secrets

### Developer Experience

- **Beautiful Console Output** - Color-coded, formatted output with severity indicators
- **Multiple Output Formats** - Console, JSON, SARIF (for CI/CD), and interactive HTML reports
- **Flexible Configuration** - YAML/TOML config files with sensible defaults
- **Smart Ignoring** - `.leaktorignore` file and inline `// leaktor:ignore` comments
- **Pre-commit Hooks** - Prevent secrets from being committed
- **Fast Performance** - Parallel scanning with minimal resource usage

---

## Installation

### Quick Install (Recommended)

Using Cargo (all platforms):

```bash
cargo install leaktor
```

### Platform-Specific Installation

<details>
<summary><b>Windows</b></summary>

#### Using Scoop

```powershell
scoop bucket add leaktor https://github.com/reschjonas/scoop-leaktor
scoop install leaktor
```

#### Using Cargo

```powershell
cargo install leaktor
```

#### Pre-built Binary

1. Download from [Releases](https://github.com/reschjonas/leaktor/releases)
2. Extract `leaktor.exe` to a directory in your PATH
3. Verify: `leaktor --version`

#### Build from Source

```powershell
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
# Binary at: .\target\release\leaktor.exe
```

</details>

<details>
<summary><b>macOS</b></summary>

#### Using Homebrew

```bash
brew tap reschjonas/tap
brew install leaktor
```

#### Using Cargo

```bash
cargo install leaktor
```

#### Pre-built Binary

```bash
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-macos.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/
```

#### Build from Source

```bash
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
sudo cp target/release/leaktor /usr/local/bin/
```

</details>

<details>
<summary><b>Linux</b></summary>

#### Using Cargo

```bash
cargo install leaktor
```

#### Pre-built Binary

```bash
# x86_64
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-amd64.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/

# ARM64
curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-aarch64.tar.gz | tar xz
sudo mv leaktor /usr/local/bin/
```

#### Build from Source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install build-essential git pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install gcc git pkg-config openssl-devel

# Arch
sudo pacman -S base-devel git openssl

# Build and install
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo build --release
sudo cp target/release/leaktor /usr/local/bin/
```

</details>

---

## Quick Start

### Basic Usage

```bash
# Scan current directory
leaktor scan

# Scan specific directory
leaktor scan /path/to/project

# Scan and validate secrets
leaktor scan --validate

# Generate HTML report
leaktor scan --format html --output report.html
```

### Common Commands

| Command | Description |
|---------|-------------|
| `leaktor scan` | Scan current directory |
| `leaktor init` | Create `.leaktorignore` file |
| `leaktor config` | Generate `.leaktor.toml` config |
| `leaktor install-hook` | Install pre-commit hook |
| `leaktor list` | Show all supported secret types |

---

## Usage

### Scanning Options

```bash
# Basic scan
leaktor scan

# Scan with validation (checks if secrets are active)
leaktor scan --validate

# Output formats
leaktor scan --format json --output results.json
leaktor scan --format sarif --output results.sarif
leaktor scan --format html --output report.html

# Advanced options
leaktor scan --git-history=false           # Skip git history
leaktor scan --max-depth 100                # Limit git history depth
leaktor scan --entropy 4.0                  # Adjust entropy threshold
leaktor scan --min-confidence 0.8           # Set confidence threshold
leaktor scan --exclude-tests                # Skip test files
leaktor scan --fail-on-found                # Exit code 1 if secrets found (CI/CD)
```

### Configuration File

Generate a configuration file:

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

### Ignore Patterns

Create a `.leaktorignore` file:

```bash
leaktor init
```

Example patterns:

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

**Inline ignoring:**

```python
API_KEY = "test_key_1234567890"  # leaktor:ignore
```

### Pre-commit Hook

Install a git hook to prevent committing secrets:

```bash
leaktor install-hook
```

This will automatically scan before each commit. Bypass with:

```bash
git commit --no-verify
```

---

## Configuration

### Configuration Files

Leaktor supports configuration files in TOML or YAML format:

- `.leaktor.toml` (recommended)
- `.leaktor.yaml`
- `.leaktor.yml`

Place in your project root for automatic loading.

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--git-history` | `true` | Scan git commit history |
| `--max-depth` | unlimited | Maximum git history depth |
| `--entropy` | `3.5` | Entropy threshold for random strings |
| `--min-confidence` | `0.6` | Minimum confidence score (0.0-1.0) |
| `--validate` | `false` | Validate secrets against APIs |
| `--exclude-tests` | `false` | Exclude test files from scan |
| `--fail-on-found` | `false` | Exit with code 1 if secrets found |

---

## CI/CD Integration

### GitHub Actions

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
        run: cargo install leaktor

      - name: Scan for secrets
        run: leaktor scan --format sarif --output results.sarif --fail-on-found

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

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

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Scan Secrets') {
            steps {
                sh 'cargo install leaktor'
                sh 'leaktor scan --fail-on-found'
            }
        }
    }
}
```

---

## Supported Secrets

### Cloud Providers

- **AWS** - Access Keys, Secret Keys, Session Tokens, MWS Keys
- **Google Cloud** - API Keys, Service Account credentials
- **Azure** - Storage Keys, Connection Strings, Client Secrets

### Version Control

- **GitHub** - Personal Access Tokens, OAuth Tokens
- **GitLab** - Personal Access Tokens
- **Bitbucket** - API Tokens

### Services & APIs

- **Stripe** - API Keys, Restricted Keys
- **SendGrid** - API Keys
- **Twilio** - API Keys, Auth Tokens
- **Slack** - Tokens, Webhooks
- **Heroku** - API Keys
- **Mailgun** - API Keys
- **Mailchimp** - API Keys

### Private Keys

- **RSA** - Private Keys
- **SSH** - Private Keys
- **PGP** - Private Keys
- **EC** - Elliptic Curve Private Keys
- **OpenSSL** - Private Keys

### Databases

- **MongoDB** - Connection Strings
- **PostgreSQL** - Connection Strings
- **MySQL** - Connection Strings
- **Redis** - Connection Strings

### Other

- **JWT** - JSON Web Tokens
- **OAuth** - OAuth Tokens
- **Generic API Keys** - Pattern-based detection
- **Passwords in URLs** - HTTP/HTTPS URLs with credentials
- **High-Entropy Strings** - Random-looking strings

---

## How It Works

Leaktor uses a multi-layered detection approach:

```
┌─────────────┐
│    File     │
└──────┬──────┘
       │
       ▼
┌─────────────────────┐
│  Pattern Matching   │  ← Regex patterns for known secret formats
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Entropy Analysis   │  ← Shannon entropy to detect random strings
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Context Analysis   │  ← Understand file type, location, comments
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Severity Scoring   │  ← Assign criticality level
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Validation (opt)   │  ← Test if secrets are active
└──────────┬──────────┘
           │
           ▼
      ┌────────┐
      │ Report │
      └────────┘
```

### Detection Methodology

1. **Pattern Matching** - Regex patterns for known secret formats (AWS keys, GitHub tokens, etc.)
2. **Entropy Analysis** - Shannon entropy calculation to identify high-randomness strings
3. **Context Analysis** - Examines file type, path, and surrounding code to reduce false positives
4. **Validation** (Optional) - Makes API calls to verify if credentials are active

---

## Output Formats

### Console (Default)

Colored, formatted output with severity indicators:

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
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
```

### JSON

Structured output for programmatic processing:

```bash
leaktor scan --format json --output results.json
```

### SARIF

Static Analysis Results Interchange Format for CI/CD:

```bash
leaktor scan --format sarif --output results.sarif
```

Compatible with:
- GitHub Security tab
- Azure DevOps
- Visual Studio Code
- Other SARIF-compatible tools

### HTML

Beautiful, interactive web report with:
- Search and filter functionality
- Severity breakdown visualizations
- Code context with syntax highlighting
- Validation status indicators
- Self-contained (no external dependencies)

```bash
leaktor scan --format html --output report.html
```

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open a Pull Request

---

## Security

### Responsible Use

Leaktor is designed for security professionals. Please use responsibly:

| Acceptable Use | Unacceptable Use |
|----------------|------------------|
| ✅ Scanning your own codebases | ❌ Unauthorized access to systems |
| ✅ Authorized security assessments | ❌ Using validated credentials without permission |
| ✅ Educational purposes | ❌ Malicious activities |

### Reporting Security Issues

If you discover a security vulnerability in Leaktor itself, please report it privately to the maintainer. See [SECURITY.md](SECURITY.md) for details.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author

**Jonas Resch** ([@reschjonas](https://github.com/reschjonas))

---

## Acknowledgments

Built with [Rust](https://www.rust-lang.org/) for maximum performance and safety.

---

## Support

- **Documentation**: [Wiki](https://github.com/reschjonas/leaktor/wiki)
- **Bug Reports**: [Issues](https://github.com/reschjonas/leaktor/issues)
- **Feature Requests**: [Issues](https://github.com/reschjonas/leaktor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/reschjonas/leaktor/discussions)

---

**If you find Leaktor useful, please consider starring the repository!**
