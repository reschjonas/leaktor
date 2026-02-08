# Leaktor Usage Examples

This document provides practical examples of using Leaktor to scan for secrets in your codebase.

## Table of Contents
- [Basic Scanning](#basic-scanning)
- [Output Formats](#output-formats)
- [Advanced Scanning](#advanced-scanning)
- [S3 and Docker Scanning](#s3-and-docker-scanning)
- [Blast Radius Analysis](#blast-radius-analysis)
- [Scan Comparison](#scan-comparison)
- [Secret Validation](#validation)
- [CI/CD Integration](#cicd-integration)
- [Ignoring False Positives](#ignoring-false-positives)
- [Configuration](#configuration)
- [Pre-commit Hooks](#pre-commit-hooks)
- [Real-World Scenarios](#real-world-scenarios)

---

## Basic Scanning

### Scan Current Directory
```bash
leaktor scan
```

### Scan Specific Directory
```bash
leaktor scan /path/to/project
```

### Scan Single File
```bash
leaktor scan config.env
```

### Scan with Verbose Output
```bash
leaktor scan --verbose
```
Shows confidence scores, entropy values, and commit information.

---

## Output Formats

### Console Output (Default)
```bash
leaktor scan
```
**Output:**
```
╔═══════════════════════════════════════════════╗
║            LEAKTOR SECURITY SCAN              ║
╚═══════════════════════════════════════════════╝

Summary
Total Findings: 3
  Critical: 2
  High: 1
  Medium: 0
  Low: 0

Findings

[1] [CRITICAL] AWS Access Key
  Location: src/config.rs:42
  Confidence: 95%
  ...
```

### JSON Output
```bash
leaktor scan --format json --output results.json
```
Useful for parsing and automation.

### SARIF Format (for CI/CD)
```bash
leaktor scan --format sarif --output results.sarif
```
Compatible with GitHub Code Scanning and other security tools.

### HTML Report
```bash
leaktor scan --format html --output report.html
```
Self-contained report for sharing with team.

**Example:** Generate all formats at once:
```bash
leaktor scan --format json --output results.json
leaktor scan --format html --output report.html
leaktor scan --format sarif --output results.sarif
```

---

## Advanced Scanning

### Skip Git History (Faster)
```bash
leaktor scan --git-history false
```
Only scans current working directory files.

### Limit Git History Depth
```bash
leaktor scan --max-depth 100
```
Scan only the last 100 commits.

### Adjust Entropy Threshold
```bash
# Lower threshold = more sensitive (more findings)
leaktor scan --entropy 3.0

# Higher threshold = less sensitive (fewer false positives)
leaktor scan --entropy 4.5
```

Default is 3.5, which balances accuracy and coverage.

### Set Minimum Confidence
```bash
leaktor scan --min-confidence 0.8
```
Only report secrets with 80%+ confidence. Reduces false positives.

### Exclude Test Files
```bash
leaktor scan --exclude-tests
```
Skips files matching test patterns (useful for CI/CD).

### Fail on Secrets Found (CI/CD)
```bash
leaktor scan --fail-on-found
```
Exits with code 1 if any secrets are detected.

---

## S3 and Docker Scanning

### Scan an S3 Bucket
```bash
# Scan all objects in a bucket
leaktor scan-s3 my-config-bucket

# Scope to a specific prefix
leaktor scan-s3 my-bucket --prefix config/production/

# Scan with a specific region
leaktor scan-s3 my-bucket --region eu-west-1
```

Uses the standard AWS credential chain (`AWS_PROFILE`, `~/.aws/credentials`, instance roles, etc.). Binary objects and files >5 MB are automatically skipped.

### Scan a Docker Image
```bash
# Scan an image (pulls automatically)
leaktor scan-docker myapp:latest

# Skip pulling (use local image)
leaktor scan-docker myapp:latest --no-pull

# Scan a remote image
leaktor scan-docker ghcr.io/org/app:v2.1.0
```

Requires a running Docker daemon. Exports the container filesystem and scans text files while skipping system directories.

---

## Blast Radius Analysis

### Trace a Secret Across the Codebase
```bash
# Trace by value
leaktor trace --value "AKIAIOSFODNN7EXAMPLE"

# Trace by secret type
leaktor trace --type "AWS Access Key"

# Trace from a findings file
leaktor trace --file results.json
```

Shows every file and line where the secret appears, categorized by usage type (configuration, source code, infrastructure, etc.).

---

## Scan Comparison

### Compare Two Scan Results
```bash
# Run scans at different points in time
leaktor scan --format json --output before.json
# ... make changes ...
leaktor scan --format json --output after.json

# See what changed
leaktor diff before.json after.json

# JSON output for automation
leaktor diff before.json after.json --format json
```

Shows added, removed, and unchanged findings between two scans.

---

## Validation

### Validate Detected Secrets
```bash
leaktor scan --validate
```
**Checks if secrets are active:**
- AWS keys -- Makes AWS API call
- GitHub tokens -- Checks GitHub API
- Other services -- HTTP validation where possible

**Example output:**
```
[1] [CRITICAL] AWS Access Key
  Status: [OK] VALIDATED (Active!)
  Location: config/prod.env:12
```

**Note:** Validation makes API calls. Use responsibly and only when authorized.

---

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full git history

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install Leaktor
        run: cargo install --path .

      - name: Scan for secrets
        run: leaktor scan --format sarif --output results.sarif --fail-on-found

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
secrets-scan:
  image: rust:latest
  script:
    - cargo install --path .
    - leaktor scan --format json --output results.json --fail-on-found
  artifacts:
    reports:
      sast: results.json
    when: always
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'cargo install --path .'
                sh 'leaktor scan --format json --output results.json --fail-on-found'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results.json'
        }
    }
}
```

---

## Ignoring False Positives

### Project Setup with `leaktor init`

```bash
leaktor init
```

Creates config files, ignore file, pre-commit hook, and CI workflow in one command. The generated `.leaktorignore` includes common patterns:

```
# Test files
*.test.js
*_test.go
tests/*
spec/*
__tests__/*

# Dependencies
node_modules/*
vendor/*
target/*
dist/*

# Documentation
docs/*
*.md
README*

# Example/template files
*.example.*
example.*
*.template.*
template.*

# Build artifacts
*.min.js
*.bundle.js
```

### Inline Ignoring

Add `// leaktor:ignore` to specific lines:

```python
# This will be ignored
API_KEY = "test_key_1234567890"  # leaktor:ignore

# This will be detected
PROD_API_KEY = "live_key_abcdefgh"
```

Works with any comment syntax:
```javascript
const test = "secret"; // leaktor:ignore
```

```ruby
password = "test123"  # leaktor:ignore
```

```bash
export TOKEN="fake_token_here"  # leaktor:ignore
```

---

## Configuration

### Generate Config File

```bash
leaktor config
```

Creates `.leaktor.toml`:

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

[[custom_patterns]]
name = "Company Secret Token"
regex = "company_[A-Za-z0-9]{40}"
severity = "CRITICAL"
confidence = 0.90
```

### Custom Patterns

Add company-specific secrets to `.leaktor.toml`:

```toml
[[custom_patterns]]
name = "Acme Corp API Key"
regex = "acme_[0-9a-zA-Z]{32}"
severity = "CRITICAL"
confidence = 0.95

[[custom_patterns]]
name = "Internal Service Token"
regex = "IST-[A-Z0-9]{16}-[A-Z0-9]{16}"
severity = "HIGH"
confidence = 0.90
```

---

## Pre-commit Hooks

### Install Hook

```bash
cd /path/to/your/repo
leaktor install-hook
```

This creates `.git/hooks/pre-commit`:

```bash
#!/bin/sh
# Leaktor pre-commit hook

echo "Running Leaktor security scan..."

leaktor scan --fail-on-found --format console

if [ $? -ne 0 ]; then
    echo "Secrets detected. Commit aborted."
    echo "   Review the findings above or use 'git commit --no-verify' to bypass."
    exit 1
fi

echo "No secrets detected."
exit 0
```

### Bypass Hook (Emergency)

```bash
git commit --no-verify -m "Emergency hotfix"
```

---

## Real-World Scenarios

### Scenario 1: Pre-Deployment Security Check

```bash
# Before deploying to production
leaktor scan \
  --exclude-tests \
  --min-confidence 0.8 \
  --fail-on-found \
  --format html \
  --output pre-deploy-scan.html

# If exit code is 0, safe to deploy
if [ $? -eq 0 ]; then
    echo "Security scan passed. Deploying..."
    ./deploy.sh
fi
```

### Scenario 2: Audit Entire Git History

```bash
# Comprehensive scan of entire repository history
leaktor scan \
  --git-history true \
  --verbose \
  --format html \
  --output security-audit-$(date +%Y%m%d).html

# Email report to security team
mail -s "Security Audit Report" security@company.com < security-audit-*.html
```

### Scenario 3: Quick PR Review

```bash
# Fast scan for pull requests
leaktor scan \
  --git-history false \
  --exclude-tests \
  --format sarif \
  --output pr-scan.sarif
```

### Scenario 4: Find and Validate Live Credentials

```bash
# Scan and check if secrets are actually active
leaktor scan \
  --validate \
  --verbose \
  --format json \
  --output validated-secrets.json

# Parse results to find active secrets
jq '.findings[] | select(.secret.validated == true)' validated-secrets.json
```

### Scenario 5: CI/CD with Custom Thresholds

```bash
# Production-grade CI/CD scan
leaktor scan \
  --entropy 4.0 \
  --min-confidence 0.7 \
  --exclude-tests \
  --max-depth 50 \
  --fail-on-found \
  --format sarif \
  --output results.sarif
```

### Scenario 6: Migration/Legacy Codebase Scan

```bash
# Scan large legacy codebase progressively
leaktor scan \
  --max-depth 10 \
  --min-confidence 0.9 \
  --format json \
  --output legacy-scan-critical.json

# Review critical findings first, then lower threshold
leaktor scan \
  --max-depth 10 \
  --min-confidence 0.7 \
  --format json \
  --output legacy-scan-all.json
```

---

## Troubleshooting

### Too Many False Positives

```bash
# Increase confidence threshold
leaktor scan --min-confidence 0.8

# Increase entropy threshold
leaktor scan --entropy 4.0

# Exclude test and documentation files
leaktor scan --exclude-tests
```

### Missing Secrets

```bash
# Lower entropy threshold
leaktor scan --entropy 3.0

# Lower confidence threshold
leaktor scan --min-confidence 0.5

# Scan full git history
leaktor scan --git-history true
```

### Performance Issues

```bash
# Limit git history
leaktor scan --max-depth 50

# Skip git history entirely
leaktor scan --git-history false

# Exclude large directories via .leaktorignore
echo "node_modules/*" >> .leaktorignore
echo "vendor/*" >> .leaktorignore
```

---

## List Supported Secret Types

```bash
leaktor list
```

**Output shows all 888 detectable secret types across 16 categories:**
- Cloud Providers (AWS, GCP, Azure, Alibaba, Tencent, DigitalOcean, etc.)
- Version Control (GitHub, GitLab, Bitbucket -- PATs, OAuth, App tokens)
- Payment & Finance (Stripe, Square, Coinbase, Flutterwave, etc.)
- Communication (Slack, Twilio, Discord, Telegram, SendGrid, Mailgun, etc.)
- CI/CD & DevOps (CircleCI, Vercel, Railway, Heroku, Scalingo, etc.)
- Monitoring & Observability (Datadog, New Relic, Sentry, Grafana, etc.)
- Databases & Storage (MongoDB, PostgreSQL, MySQL, Redis, PlanetScale, Neon, etc.)
- AI/ML (OpenAI, Anthropic, HuggingFace, Replicate, Cohere)
- Private Keys (RSA, SSH, PGP, EC, DSA, PKCS8, Age)
- Identity & Auth (Okta, Auth0, Firebase, Azure AD, Vault)
- Generic patterns (JWT, API keys, passwords, high-entropy strings)

---

## Tips and Best Practices

1. **Start with defaults** - Leaktor's defaults are tuned for good balance
2. **Use .leaktorignore** - Reduce noise by ignoring known false positives
3. **Validate selectively** - Only use `--validate` when needed (makes API calls)
4. **Review HTML reports** - Easy to share with team and review findings
5. **Integrate early** - Add to CI/CD pipeline from the start
6. **Use pre-commit hooks** - Prevent secrets from being committed
7. **Regular audits** - Scan your codebase monthly with full git history
8. **Custom patterns** - Add company-specific secret patterns to config

---

## Getting Help

```bash
# General help
leaktor --help

# Command-specific help
leaktor scan --help
leaktor config --help
leaktor init --help
```

---

## Support

-  [Report a bug](https://github.com/reschjonas/leaktor/issues)
-  [Request a feature](https://github.com/reschjonas/leaktor/issues)
-  [Documentation](https://github.com/reschjonas/leaktor)

---
