<p align="center">
  <h1 align="center">Leaktor</h1>
  <p align="center">
    Secrets scanner for codebases and git history.
    <br />
    Pattern matching &middot; Entropy analysis &middot; Live validation
    <br /><br />
    <a href="https://crates.io/crates/leaktor"><img src="https://img.shields.io/crates/v/leaktor.svg?style=flat-square" alt="Crates.io"></a>&nbsp;
    <a href="https://crates.io/crates/leaktor"><img src="https://img.shields.io/crates/d/leaktor.svg?style=flat-square" alt="Downloads"></a>&nbsp;
    <a href="https://github.com/reschjonas/leaktor/releases"><img src="https://img.shields.io/github/v/release/reschjonas/leaktor?style=flat-square" alt="Release"></a>&nbsp;
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  </p>
</p>

<br />

```
$ leaktor scan

╔═══════════════════════════════════════════════╗
║           🔒 LEAKTOR SECURITY SCAN            ║
╚═══════════════════════════════════════════════╝

Summary
Total Findings: 3
  Critical: 2    High: 1

[1] 🔴 AWS Access Key [CRITICAL]
  Status: ✓ VALIDATED
  Location: src/config.rs:42
  Context:
    AWS_ACCESS_KEY_ID=AKIA...MPLE

[2] 🔴 GitHub Personal Access Token [CRITICAL]
  Location: .env:7
  Context:
    GITHUB_TOKEN=ghp_...a8f2

[3] 🟠 Stripe API Key [HIGH]
  Location: payments/billing.py:119
  Context:
    stripe.api_key = "sk_l...eK1P"

⏱ Scan completed in 0.04s | 312 files scanned | 3 findings
```

<br />

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Detection coverage](#detection-coverage)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [CI/CD integration](#cicd-integration)
- [Output formats](#output-formats)
- [Contributing](#contributing)

<br />

## Install

```bash
cargo install leaktor
```

Pre-built binaries for Linux, macOS, and Windows on the [releases page](https://github.com/reschjonas/leaktor/releases).

<details>
<summary><b>Other methods</b></summary>
<br />

| Method | Command |
|--------|---------|
| Homebrew (macOS) | `brew tap reschjonas/tap && brew install leaktor` |
| Scoop (Windows) | `scoop bucket add leaktor https://github.com/reschjonas/scoop-leaktor && scoop install leaktor` |
| Pre-built (Linux x86_64) | `curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-amd64.tar.gz \| tar xz && sudo mv leaktor /usr/local/bin/` |
| Pre-built (Linux ARM64) | `curl -L https://github.com/reschjonas/leaktor/releases/latest/download/leaktor-linux-aarch64.tar.gz \| tar xz && sudo mv leaktor /usr/local/bin/` |
| From source | `git clone https://github.com/reschjonas/leaktor && cd leaktor && cargo build --release` |

Build from source requires: Rust toolchain, `pkg-config`, `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (Fedora/RHEL).

</details>

<br />

## Quick start

```bash
# Scan current directory (includes git history)
leaktor scan

# Scan a specific project
leaktor scan /path/to/project

# Validate found secrets against live APIs
leaktor scan --validate

# Generate reports
leaktor scan --format json -o results.json
leaktor scan --format sarif -o results.sarif
leaktor scan --format html -o report.html

# For CI pipelines -- exit 1 when secrets are found
leaktor scan --fail-on-found
```

All flags:

| Flag | Default | |
|------|---------|---|
| `--format <fmt>` | `console` | `console` `json` `sarif` `html` |
| `-o, --output <path>` | stdout | Write report to file |
| `--validate` | off | Check secrets against live APIs |
| `--git-history <bool>` | `true` | Scan git commit history |
| `--max-depth <n>` | all | Limit git commits scanned |
| `--entropy <f64>` | `3.5` | Shannon entropy threshold |
| `--min-confidence <f64>` | `0.6` | Confidence cutoff (0.0 -- 1.0) |
| `--exclude-tests` | off | Skip test files |
| `--fail-on-found` | off | Non-zero exit on findings |
| `-v, --verbose` | off | Confidence, entropy, commit metadata |

```bash
# Utility commands
leaktor list              # Print all 68 supported secret types
leaktor init              # Create .leaktorignore
leaktor config            # Generate .leaktor.toml
leaktor install-hook      # Git pre-commit hook (staged files only)
```

<br />

## Detection coverage

68 secret types. 72 regex patterns. Run `leaktor list` for the full list.

| Category | Secrets |
|:---------|:--------|
| **Cloud providers** | AWS access keys, secret keys, session tokens, MWS &middot; GCP API keys, service accounts &middot; Azure storage keys, connection strings &middot; DigitalOcean tokens, Spaces keys |
| **AI / ML** | OpenAI &middot; Anthropic &middot; HuggingFace &middot; Replicate &middot; Cohere |
| **Version control** | GitHub PATs, OAuth, fine-grained tokens &middot; GitLab PATs |
| **Payments** | Stripe API & restricted keys &middot; Shopify API & shared secrets &middot; Square access tokens |
| **Databases** | PostgreSQL &middot; MongoDB &middot; MySQL &middot; Redis connection strings &middot; PlanetScale tokens |
| **Private keys** | RSA &middot; SSH (OpenSSH) &middot; PGP &middot; EC (elliptic curve) |
| **Package registries** | NPM &middot; PyPI &middot; NuGet &middot; RubyGems &middot; Docker Hub |
| **Communication** | Slack tokens & webhooks &middot; Discord bots & webhooks &middot; Telegram bot tokens |
| **Infrastructure** | HashiCorp Vault &middot; Sentry DSNs &middot; Datadog &middot; New Relic &middot; Grafana &middot; Algolia &middot; Elastic |
| **CI/CD & hosting** | Vercel &middot; Netlify &middot; CircleCI &middot; Heroku |
| **Auth & identity** | Okta &middot; Auth0 &middot; Firebase &middot; Supabase &middot; JWT &middot; OAuth tokens |
| **Generic** | API key assignments &middot; password assignments &middot; bearer/access tokens &middot; passwords in URLs &middot; high-entropy strings |

<br />

## How it works

```
 Source files ─┐
               ├──▶ Pattern matching  (72 tuned regexes, multi-match per line)
 Git history ──┘         │
                         ▼
                  Entropy analysis  (Shannon entropy on matched values)
                         │
                         ▼
                  Context analysis  (test files, docs, comments, placeholders)
                         │
                         ▼
                  Confidence scoring  (0.0 – 1.0 per finding)
                         │
                         ▼
                  Validation  (opt-in: GitHub, Slack, Stripe, AWS — parallel)
                         │
                         ▼
                     Report  (console / json / sarif / html)
```

**Automatic filtering** -- the following are skipped without configuration: binary files (by extension + content sniffing for null bytes), lockfiles (`package-lock.json`, `Cargo.lock`, `yarn.lock`, ...), minified files, vendor/`node_modules` directories, `.gitignore`'d paths, and known placeholder values like `AKIAIOSFODNN7EXAMPLE`.

<br />

## Configuration

Leaktor reads `.leaktor.toml` or `.leaktor.yaml` from the project root. CLI flags take precedence.

```bash
leaktor config            # writes .leaktor.toml with defaults
```

```toml
entropy_threshold = 3.5
min_confidence = 0.6
enable_validation = false
scan_git_history = true
max_git_depth = 1000
respect_gitignore = true
max_file_size = 1048576       # bytes
exclude_tests = false
exclude_docs = false
report_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Add your own patterns
[[custom_patterns]]
name = "Internal API Key"
regex = "internal_api_[0-9a-f]{32}"
severity = "HIGH"
confidence = 0.85
```

### Ignoring findings

**By file pattern** -- create `.leaktorignore` (or run `leaktor init`):

```gitignore
*.test.js
*_test.go
tests/*
fixtures/*
node_modules/*
config/example.env
```

**Inline** -- append a comment to any line:

```python
API_KEY = "test_key_for_unit_tests"  # leaktor:ignore
```

Also supported: `leaktor-ignore` and `@leaktor-ignore`.

<br />

## CI/CD integration

### GitHub Actions

```yaml
name: Secrets scan
on: [push, pull_request]

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # full history

      - name: Install
        run: cargo install leaktor

      - name: Scan
        run: leaktor scan --format sarif -o results.sarif --fail-on-found

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
secrets-scan:
  image: rust:latest
  script:
    - cargo install leaktor
    - leaktor scan --format json -o results.json --fail-on-found
  artifacts:
    reports:
      sast: results.json
```

### Pre-commit hook

```bash
leaktor install-hook
```

Scans staged files only. Bypass: `git commit --no-verify`.

<br />

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| **Console** | `--format console` | Terminal review. Color-coded severity, code context, validation badges. |
| **JSON** | `--format json` | Programmatic processing. Full finding metadata and summary stats. |
| **SARIF** | `--format sarif` | CI/CD integration. GitHub Security tab, Azure DevOps, VS Code. |
| **HTML** | `--format html` | Sharing & review. Self-contained page with search, filters, code context. |

<br />

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo test              # 82 tests
cargo clippy            # 0 warnings
```

<br />

## Security

Built for legitimate use: your own repositories, authorized assessments, CI pipelines.
Vulnerability reports: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
