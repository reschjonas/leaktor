<p align="center">
  <h1 align="center">Leaktor</h1>
  <p align="center">
    Secrets scanner for codebases and git history.
    <br />
    Pattern matching &middot; Entropy analysis &middot; Live validation
    <br /><br />
    <a href="https://crates.io/crates/leaktor"><img src="https://img.shields.io/crates/v/leaktor.svg?style=flat-square" alt="Crates.io"></a>&nbsp;
    <a href="https://github.com/reschjonas/leaktor"><img src="https://img.shields.io/github/stars/reschjonas/leaktor?style=flat-square" alt="Stars"></a>&nbsp;
    <a href="https://github.com/reschjonas/leaktor/releases"><img src="https://img.shields.io/github/v/release/reschjonas/leaktor?style=flat-square" alt="Release"></a>&nbsp;
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  </p>
</p>

<br />

```
$ leaktor scan

╔═══════════════════════════════════════════════╗
║            LEAKTOR SECURITY SCAN              ║
╚═══════════════════════════════════════════════╝

Summary
Total Findings: 3
  Critical: 2    High: 1

[1] [CRITICAL] AWS Access Key [CRITICAL]
  Status: [OK] VALIDATED
  Location: src/config.rs:42
  Context:
    AWS_ACCESS_KEY_ID=AKIA...MPLE

[2] [CRITICAL] GitHub Personal Access Token [CRITICAL]
  Location: .env:7
  Context:
    GITHUB_TOKEN=ghp_...a8f2

[3] [HIGH] Stripe API Key [HIGH]
  Location: payments/billing.py:119
  Context:
    stripe.api_key = "sk_l...eK1P"

Scan completed in 0.04s | 312 files scanned | 3 findings
```

<br />

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Detection coverage](#detection-coverage)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Project setup (`leaktor init`)](#project-setup)
- [Blast radius analysis (`leaktor trace`)](#blast-radius-analysis)
- [Scan diffing (`leaktor diff`)](#scan-diffing)
- [Dependency scanning (`--include-deps`)](#dependency-scanning)
- [Multi-format scanning](#multi-format-scanning)
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

### Stdin scanning

Pipe content from any source directly into Leaktor:

```bash
# Scan a single file
cat .env | leaktor scan --stdin

# Scan a git diff
git diff HEAD~1 | leaktor scan --stdin

# Scan remote content
curl -s https://example.com/config | leaktor scan --stdin
```

### Incremental scanning

Only scan new commits -- ideal for CI pipelines on pull requests:

```bash
# Only scan commits after a specific hash
leaktor scan --since-commit abc1234

# Scan a specific commit range (from..to)
leaktor scan --commit-range abc1234..HEAD
leaktor scan --commit-range main..feature-branch
```

### Baseline support

Adopt Leaktor on existing projects without drowning in legacy findings. Create a baseline to record known findings, then only flag *new* secrets on subsequent scans:

```bash
# Create a baseline from the current state
leaktor scan --create-baseline baseline.json

# Scan and suppress known findings
leaktor scan --baseline baseline.json --fail-on-found

# Update the baseline with newly accepted findings
leaktor scan --update-baseline baseline.json
```

### All flags

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
| `--stdin` | off | Read from stdin instead of filesystem |
| `--since-commit <hash>` | -- | Only scan commits after this hash |
| `--commit-range <from..to>` | -- | Scan a specific commit range |
| `--baseline <path>` | -- | Suppress findings present in baseline |
| `--create-baseline <path>` | -- | Create a baseline file from results |
| `--update-baseline <path>` | -- | Merge new findings into a baseline |
| `--only-verified` | off | Only show secrets confirmed active (needs `--validate`) |
| `--include-deps` | off | Scan dependency dirs (node_modules, vendor, .venv) |

```bash
# Utility commands
leaktor list              # Print all 146 supported secret types
leaktor init              # Full project setup (config + hook + CI + baseline)
leaktor config            # Generate .leaktor.toml
leaktor install-hook      # Git pre-commit hook (staged files only)
leaktor trace AKIAZ5...   # Blast radius analysis
leaktor diff old.json new.json  # Compare scan results
```

<br />

## Detection coverage

146 secret types. 152 regex patterns. 10 live validators. Run `leaktor list` for the full list.

| Category | Secrets |
|:---------|:--------|
| **Cloud providers** | AWS access keys, secret keys, session tokens, MWS &middot; GCP API keys, service accounts &middot; Azure storage keys, connection strings, AD client secrets &middot; DigitalOcean tokens, Spaces keys &middot; Alibaba Cloud &middot; Tencent Cloud &middot; Yandex Cloud |
| **AI / ML** | OpenAI &middot; Anthropic &middot; HuggingFace &middot; Replicate &middot; Cohere |
| **Version control** | GitHub PATs, OAuth, fine-grained PATs, App tokens &middot; GitLab PATs &middot; Bitbucket app passwords &middot; Sourcegraph |
| **Payments & finance** | Stripe API & restricted keys &middot; Shopify API & shared secrets &middot; Square &middot; Braintree &middot; Plaid &middot; Coinbase &middot; Flutterwave |
| **Databases** | PostgreSQL &middot; MongoDB &middot; MySQL &middot; Redis &middot; PlanetScale tokens & passwords &middot; Snowflake &middot; Databricks |
| **Private keys** | RSA &middot; SSH (OpenSSH) &middot; PGP &middot; EC &middot; PKCS8 &middot; DSA |
| **Package registries** | NPM &middot; PyPI &middot; NuGet &middot; RubyGems &middot; Docker Hub &middot; Clojars |
| **Communication** | Slack tokens & webhooks &middot; Discord bots & webhooks &middot; Telegram &middot; Twitch &middot; Twitter &middot; Intercom &middot; Beamer |
| **Infrastructure** | HashiCorp Vault & batch tokens &middot; Sentry &middot; Datadog &middot; New Relic &middot; Grafana &middot; Algolia &middot; Elastic &middot; Terraform Cloud &middot; Pulumi &middot; Doppler &middot; Dynatrace &middot; Tailscale |
| **CI/CD & hosting** | Vercel &middot; Netlify &middot; CircleCI &middot; Heroku &middot; Fly.io &middot; Render &middot; Confluent &middot; Scalingo &middot; Railway &middot; Infracost &middot; Prefect |
| **Feature flags & analytics** | LaunchDarkly &middot; PostHog &middot; Amplitude &middot; Segment &middot; Mixpanel |
| **CDN & APIs** | Cloudflare &middot; Fastly &middot; Mapbox &middot; Contentful &middot; Postman &middot; RapidAPI &middot; ReadMe &middot; Typeform |
| **Password managers** | 1Password secret keys & service tokens &middot; Bitwarden |
| **Other SaaS** | PagerDuty &middot; Jira / Atlassian &middot; Asana &middot; Trello &middot; FreshBooks &middot; Codecov &middot; Frame.io &middot; Zendesk &middot; Sumo Logic &middot; Adobe &middot; Dropbox &middot; EasyPost &middot; Facebook &middot; Duffel &middot; Neon &middot; Turborepo |
| **Auth & identity** | Okta &middot; Auth0 &middot; Firebase &middot; Supabase &middot; JWT &middot; OAuth &middot; Google OAuth client secrets |
| **Encryption** | Age secret keys &middot; Artifactory API keys & reference tokens |
| **Generic** | API key assignments &middot; password assignments &middot; bearer/access tokens &middot; passwords in URLs &middot; high-entropy strings |

### Live validation (10 services)

When you pass `--validate`, Leaktor calls the provider's API to confirm whether a detected credential is actually active:

| Provider | Method |
|:---------|:-------|
| AWS | STS GetCallerIdentity (Signature V4) |
| GitHub | `/user` endpoint |
| GitLab | `/api/v4/user` endpoint |
| Slack | `auth.test` endpoint |
| Stripe | `/v1/charges` endpoint |
| OpenAI | `/v1/models` endpoint |
| Anthropic | `/v1/models` endpoint |
| SendGrid | `/v3/scopes` endpoint |
| Datadog | `/api/v1/validate` endpoint |
| HuggingFace | `whoami-v2` endpoint |

Combine with `--only-verified` to see **only** secrets confirmed active -- useful for cutting noise in large repos:

```bash
leaktor scan --validate --only-verified
```

<br />

## How it works

```
 Source files ---+
 Git history ---+
 Stdin (pipe) ---+
 Dependencies ---+  (opt-in: --include-deps)
        |
        v
 Multi-format decode  (K8s Secrets base64, Terraform state, Docker Compose, CloudFormation)
        |
        v
 Pattern matching  (152 built-in + custom regexes, multi-match per line)
        |
        v
 Entropy analysis  (Shannon entropy on matched values)
        |
        v
 Context analysis  (test files, docs, comments, placeholders)
        |
        v
 Confidence scoring  (0.0 - 1.0 per finding)
        |
        v
 Allowlist + Baseline  (type/path/value/severity rules, fingerprints, baseline)
        |
        v
 Validation  (opt-in: 10 providers, parallel, --only-verified)
        |
        v
 Report  (console / json / sarif / html)
        |
        v
 Trace / Diff  (blast radius analysis, scan comparison)
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
```

### Custom patterns

Define your own detection rules using Rust regex syntax. They run alongside the 152 built-in patterns:

```toml
[[custom_patterns]]
name = "Internal API Key"
regex = "internal_api_[0-9a-f]{32}"
severity = "HIGH"
confidence = 0.85
description = "Internal backend API key"

[[custom_patterns]]
name = "Company JWT"
regex = "eyJ[A-Za-z0-9_-]+\\.company\\.[A-Za-z0-9_-]+"
severity = "CRITICAL"
confidence = 0.90
```

Custom patterns appear in all output formats (console, JSON, SARIF, HTML) with their configured name and severity. Invalid regex is skipped with a warning.

### Allowlist rules

Suppress findings by secret type, file path, value regex, or severity. All specified fields must match (AND logic). Empty/absent fields match everything:

```toml
# Suppress all Sentry DSNs (public by design)
[[allowlist]]
description = "Sentry DSNs are not secrets"
secret_types = ["Sentry DSN"]

# Suppress everything in test fixtures
[[allowlist]]
description = "Test fixtures contain fake secrets"
paths = ["tests/fixtures/*", "*.test.*"]

# Suppress the AWS example key from documentation
[[allowlist]]
description = "AWS documentation example key"
value_regex = "AKIAIOSFODNN7EXAMPLE"

# Suppress low-severity findings in docs
[[allowlist]]
description = "Low-risk findings in documentation"
paths = ["docs/*", "*.md"]
severities = ["LOW", "MEDIUM"]
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

**By fingerprint** -- allowlist specific findings by their SHA-256 fingerprint (from baseline or `--format json`):

```gitignore
# .leaktorignore -- fingerprint allowlisting
*.test.js

# Allowlist a specific known finding by fingerprint
fingerprint:a1b2c3d4e5f6...full-64-char-hex-hash...

# Or just paste the bare 64-char hex hash
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
```

<br />

## Project setup

Set up Leaktor for a project with one command:

```bash
leaktor init
```

This creates:

| File | Purpose |
|:-----|:--------|
| `.leaktor.toml` | Configuration (patterns, thresholds, allowlists) |
| `.leaktorignore` | Ignore patterns (files, fingerprints) |
| `.git/hooks/pre-commit` | Pre-commit hook (auto-scan before commits) |
| `.github/workflows/leaktor.yml` | GitHub Actions CI workflow |

Options:

```bash
leaktor init --baseline          # Also create an initial baseline
leaktor init --no-hook           # Skip pre-commit hook
leaktor init --no-ci             # Skip GitHub Actions workflow
leaktor init /path/to/project    # Initialize a specific directory
```

<br />

## Blast radius analysis

When you find a secret, `leaktor trace` shows you everywhere it's used:

```bash
# Trace a specific value
leaktor trace AKIAZ52HGXYRN4WB

# Trace by secret type
leaktor trace --type "AWS Access Key"

# Trace all secrets found in a file
leaktor trace --file .env
```

Output shows all references with a blast radius summary:

```
Blast Radius Analysis

  [*] Tracing: AKIAZ52HGXYRN4WB (Query)

    [!] 4 reference(s) found:

    -> deploy/terraform.tfstate:11
      "id": "AKIAZ52HGXYRN4WB...",
    -> deploy/docker-compose.yml:6
      AWS_ACCESS_KEY_ID: AKIAZ52HGXYRN4WB...
    -> src/config.py:4
      AWS_ACCESS_KEY_ID = "AKIAZ52HGXYRN4WB..."
    -> k8s/secret.yaml:9
      aws_access_key: QUtJQ...  (base64)

  Blast Radius Summary
    [!] Infrastructure (2 files)
    [-] Config files (1 file)
```

<br />

## Scan diffing

Compare two scan results to track secret hygiene over time:

```bash
# Create scan snapshots
leaktor scan --format json -o scan-v1.json
# ... make changes ...
leaktor scan --format json -o scan-v2.json

# Compare
leaktor diff scan-v1.json scan-v2.json
```

Output:

```
Scan Diff Report

  + 1 new  - 2 fixed  = 19 unchanged  (-1 net)

  New findings:
    + [CRITICAL] OpenAI API Key at src/config.py:10

  Fixed findings:
    - Stripe API Key at .env:1
    - GitHub PAT at .env:2
```

Also supports JSON output for automation: `leaktor diff old.json new.json --format json`

<br />

## Dependency scanning

Scan secrets inside `node_modules/`, `vendor/`, `.venv/`, and other dependency directories that are normally skipped:

```bash
leaktor scan --include-deps
```

This catches supply-chain risks: secrets accidentally shipped inside third-party packages.

<br />

## Multi-format scanning

Leaktor automatically decodes and scans structured files:

| Format | What it does |
|:-------|:-------------|
| **Kubernetes Secrets** | Decodes base64 `.data` values and scans the plaintext |
| **Terraform state** (`.tfstate`) | Walks all JSON values recursively, decodes base64 blobs |
| **Docker Compose** | Scans `environment:` values in both mapping and list styles |
| **CloudFormation** | Scans `Parameters` defaults and `Resources` properties |

This happens automatically during `leaktor scan` -- no flags needed. Findings show the decoded context:

```
[1] [CRITICAL] AWS Access Key [CRITICAL]
  Location: k8s/secret.yaml:9
  Context:
    K8s Secret .data.aws_access_key [base64 decoded]
    AKIA...TEST
```

<br />

## CI/CD integration

### GitHub Actions (recommended)

Use the official action for the simplest setup. SARIF results are automatically uploaded to the GitHub Security tab.

```yaml
name: Secrets scan
on: [push, pull_request]

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: reschjonas/leaktor@v1
        with:
          scan-mode: full          # full | pr-diff | history
          fail-on-found: true
```

<details>
<summary><b>PR-diff scanning with baseline</b></summary>

Only flag new secrets introduced in a pull request, suppressing known findings via a committed baseline file:

```yaml
name: Secrets scan (PR)
on: pull_request

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: reschjonas/leaktor@v1
        with:
          scan-mode: pr-diff
          baseline: .leaktor-baseline.json
          fail-on-found: true
```
</details>

<details>
<summary><b>Manual setup (without the action)</b></summary>

```yaml
name: Secrets scan
on: [push, pull_request]

jobs:
  leaktor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

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
</details>

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

### Pre-commit framework

If you use the [pre-commit](https://pre-commit.com) framework, add Leaktor to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/reschjonas/leaktor
    rev: v0.3.0
    hooks:
      - id: leaktor
```

<br />

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| **Console** | `--format console` | Terminal review. Color-coded severity, code context, validation status. |
| **JSON** | `--format json` | Programmatic processing. Full finding metadata and summary stats. |
| **SARIF** | `--format sarif` | CI/CD integration. GitHub Security tab, Azure DevOps, VS Code. |
| **HTML** | `--format html` | Sharing & review. Self-contained page with search, filters, code context. |

<br />

## Performance

Multi-threaded scanning with rayon parallelism and compiled regexes.

| Benchmark (10 000 files, ~150 MB) | Leaktor | gitleaks | trufflehog |
|:----------------------------------|--------:|---------:|-----------:|
| Filesystem scan | **0.8s** | 3.2s | 12.4s |
| Git history (1000 commits) | **2.1s** | 8.7s | 24.1s |
| Memory usage (peak RSS) | **~45 MB** | ~120 MB | ~350 MB |

*Benchmarks run on an M2 MacBook Pro, 16 GB RAM. Results vary with hardware and repo size.*

<br />

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/reschjonas/leaktor
cd leaktor
cargo test
cargo clippy
```

<br />

## Security

Built for legitimate use: your own repositories, authorized assessments, CI pipelines.
Vulnerability reports: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
