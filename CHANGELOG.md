# Changelog

All notable changes to Leaktor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-02-08

### Fixed

- **Terraform state scanner misses context-dependent secrets** -- Secrets like AWS Secret Keys whose patterns require keyword context (e.g. `aws...secret=`) were missed when the JSON key was just `"secret"`. The scanner now uses the Terraform resource type (e.g. `aws_iam_access_key`) to enrich the key name, so `"secret": "wJalr..."` inside an `aws_iam_access_key` resource correctly matches the AWS Secret Key pattern.
- **JSON output files get rescanned** -- Running `leaktor scan --format json -o scan.json` and then scanning again would detect secrets inside the JSON report itself, inflating finding counts by ~63%. The scanner now detects leaktor JSON output files by their schema signature (`version` + `total_findings` + `findings` header) and skips them automatically, regardless of filename.
- **Datadog API key misidentified as Close CRM** -- Keys with the `ddapi_` prefix were matched by the overly broad Close CRM pattern (`api_[a-zA-Z0-9.]{30,}`). Added a dedicated `ddapi_` Datadog pattern with higher confidence, and tightened the Close CRM pattern to require a `close` context keyword.
- **Blast radius includes scan output files** -- `leaktor trace` searched JSON scan output files, inflating reference counts. Trace now applies the same leaktor-schema detection to skip output files.

### Improved

- **Docker Compose mixed format warning** -- Mixing list-style (`- KEY=val`) and mapping-style (`KEY: val`) in the same `environment:` block now produces a clear diagnostic tip explaining the issue, and falls back to line-based scanning instead of silently giving up.
- **Config TOML ordering trap** -- `leaktor config` now generates all scalar keys (like `report_severities`) before `[[custom_patterns]]` and `[[allowlist]]` table arrays, with a comment warning about TOML section ordering. Previously, keys placed after `[[sections]]` were silently absorbed into that section.
- **`-v` short flag disambiguation** -- `-v` now maps to `--verbose` (the conventional usage). `--validate` is now `-V` (uppercase). Previously both flags competed for `-v`, causing confusing behavior.
- **Docker image false positives** -- Certificate store files (`/etc/ssl/certs/ca-certificates.crt` and similar) are now skipped when scanning Docker images. Scanning `alpine:latest` previously produced 11 false positives; now produces 0.

[0.4.1]: https://github.com/reschjonas/leaktor/compare/v0.4.0...v0.4.1

## [0.4.0] - 2026-02-08

### Fixed

- **Allowlist misconfiguration guard** -- Allowlist rules with typos in field names (e.g. `secret_type` instead of `secret_types`) were silently ignored, causing the rule to have no criteria and act as a wildcard that suppresses all findings. Added `#[serde(deny_unknown_fields)]` to reject unknown fields with a clear error message, and a safety guard that prevents empty rules from matching any finding.
- **SIGPIPE handling** -- Piping output to commands that close early (e.g. `leaktor list | head`) caused a panic (exit code 101). Now terminates cleanly with signal 13 (exit code 141), matching standard Unix CLI behavior.

### Changed

- Updated documentation: fixed duplicated severity tags in terminal examples, corrected comparison data (Gitleaks ~220 rules, TruffleHog 900+ detectors), updated CI action versions, added missing v0.3.0 feature documentation.

[0.4.0]: https://github.com/reschjonas/leaktor/compare/v0.3.0...v0.4.0

## [0.3.0] - 2026-02-07

### Added

- **`leaktor scan-s3`** -- scan S3 bucket objects for secrets. Uses the standard AWS credential chain. Supports `--prefix` to scope to a key prefix, `--region` override, and all standard output/validation flags. Binary objects and files >5 MB are automatically skipped.
- **`leaktor scan-docker`** -- scan Docker image filesystems for secrets. Pulls the image (unless `--no-pull`), exports the container filesystem, and scans text files while skipping system directories. Requires a running Docker daemon.
- **Feature flags** -- S3 and Docker scanners are optional features (`s3`, `docker`), enabled by default. Install with `--no-default-features` for a smaller binary without cloud/container dependencies.
- **`leaktor init`** -- one-command project setup: creates config, ignore file, pre-commit hook, GitHub Actions workflow, and optional baseline. Supports `--no-hook`, `--no-ci`, `--baseline` flags. Idempotent (skips existing files on re-run).
- **`leaktor trace`** -- blast radius analysis: find everywhere a secret is referenced across the codebase. Supports tracing by value, by secret type (`--type`), or from a file (`--file`). Shows categorized blast radius summary.
- **`leaktor diff`** -- scan comparison: compare two JSON scan results to see added, removed, and unchanged findings. Supports console and JSON output formats.
- **`--include-deps`** flag on `leaktor scan` -- scans dependency directories (`node_modules/`, `vendor/`, `.venv/`, etc.) that are normally skipped. Uses `walkdir` directly to bypass gitignore filtering for maximum coverage.
- **Multi-format scanning** -- automatically decodes and scans structured files:
  - Kubernetes Secrets: base64 `.data` values decoded and scanned
  - Terraform state (`.tfstate`): JSON values recursively walked + base64 blobs decoded
  - Docker Compose: `environment:` values scanned (both mapping and list styles)
  - CloudFormation: `Parameters` defaults and `Resources` properties scanned
- Massive secret pattern expansion (888 types total, 894 regex patterns, ~80 services): 1Password, Age, Alibaba, Artifactory, Asana, Azure AD, Beamer, Bitwarden, Clojars, Codecov, Coinbase, Contentful, Dropbox, DSA, Duffel, Dynatrace, EasyPost, Facebook, Flutterwave, Frame.io, FreshBooks, GitHub App/Fine-grained PAT, Google OAuth, Infracost, Intercom, Kraken, Lob, MessageBird, Neon, New Relic Browser, NY Times, PKCS8, PlanetScale, Postman, Prefect, Railway, RapidAPI, ReadMe, Scalingo, Sourcegraph, Tailscale, Tencent, Trello, Turborepo, Twitch, Twitter, Typeform, Vault Batch, Yandex, Zendesk, and hundreds more services via comprehensive API key pattern coverage
- DSL pattern configuration via `.leaktor.toml` custom patterns (name, regex, severity, confidence, description)
- Rule-based allowlisting in `.leaktor.toml` (match by secret type, file path glob, value regex, severity)

### Fixed

- `.txt` files are no longer classified as documentation -- this was silently downgrading severity for all findings in `.txt` files (CRITICAL -> High, HIGH -> Medium, etc.), including custom patterns with explicit severity overrides.
- Terraform state scanner now combines JSON key names with values (e.g. `secret=wJalr...`) before scanning, matching context-dependent patterns that require keyword prefixes. Previously only self-identifying patterns (like `AKIA` prefix) were found.
- Auto-exclude scan output files (`*.sarif`, `leaktor-report.html`, common report filenames) from default filesystem scanning to prevent re-scanning previous results.
- AWS keypair validation now pairs access keys and secret keys found in the same file for STS `GetCallerIdentity` validation, instead of format-only checks.
- `has_repeated_pattern` in context analysis was too aggressive -- raised threshold from 5 to 8 consecutive chars, excluded structural characters (`-`, `=`, `.`, `_`), and required 60% coverage for repeated short patterns. Fixes false negatives on PEM headers and tokens with common repeated characters.
- GitScanner now propagates `include_deps` to its internal FilesystemScanner

[0.3.0]: https://github.com/reschjonas/leaktor/releases/tag/v0.3.0

## [0.2.0] - 2026-02-06

### Added

- 30+ new secret patterns: OpenAI, Anthropic, HuggingFace, Replicate, Cohere, NPM, PyPI, NuGet, RubyGems, Discord (bot + webhook), Telegram, Shopify, Square, Datadog, Cloudflare, DigitalOcean, Vercel, Linear, Notion, Airtable, PlanetScale, Docker Hub, HashiCorp Vault, New Relic, Sentry, Algolia, Grafana, CircleCI, Okta, Firebase -- 68 secret types total (72 regex patterns)
- Slack token and webhook validator
- Stripe API key validator
- Parallel secret validation using tokio task pool
- Lockfile detection and skipping (package-lock.json, Cargo.lock, yarn.lock, etc.)
- Minified file detection and skipping
- Binary content sniffing (null byte check in first 512 bytes)
- Long line skipping (>5000 chars) for generated/minified code
- Per-line multi-match: finds all secrets on a single line, not just the first
- Accurate column position tracking for each finding
- Finding deduplication (same file + line + value)
- Config file loading during scan (.leaktor.toml / .leaktor.yaml)
- Scan statistics in output (files scanned, timing)
- Generic password and token assignment detection patterns
- Expanded placeholder detection (AWS example keys, more dummy values)

### Fixed

- Entropy calculation used byte count instead of character count (wrong values for multi-byte UTF-8)
- Redaction panicked on strings with multi-byte UTF-8 characters
- Git scanner now scans both working directory and history (previously only scanned history OR directory, not both)
- Boolean CLI flags (--git-history, --context) now accept =true/=false syntax
- HTML output used .len() > 0 instead of .is_empty()
- Overly broad patterns (Cohere, Cloudflare, Okta) now require contextual keywords to avoid matching arbitrary alphanumeric strings

### Changed

- Pre-commit hook now scans only staged files (not entire repo)
- CLI flags take precedence over config file values
- `leaktor list` output reorganized into 16 categories with deduplication and pattern count
- README rewritten

[0.2.0]: https://github.com/reschjonas/leaktor/compare/v0.1.0...v0.2.0

## [0.1.0] - 2025-11-17

### Initial Release

First public release of Leaktor -- a secrets scanner with pattern matching, entropy analysis, and live validation.

### Features

- **40+ Secret Patterns** - AWS, GCP, Azure, GitHub, GitLab, Stripe, databases, private keys, and more
- **Git History Scanning** - Scan entire repository history for exposed secrets
- **Live Validation** - Verify if AWS keys and GitHub tokens are active
- **Multiple Output Formats** - Console, JSON, SARIF, HTML
- **Smart Detection** - Entropy analysis, context-aware filtering, confidence scoring
- **CI/CD Ready** - GitHub Actions workflows, SARIF output, fail-on-found option
- **Pre-commit Hooks** - Prevent secrets from being committed
- **Flexible Configuration** - YAML/TOML config, .leaktorignore, inline ignoring
- **Parallel Processing** - Fast multi-threaded scanning
- **Cross-platform** - Linux, macOS, Windows support

### Technical Details

- Built with Rust 2021 Edition
- Async validation with Tokio
- Pattern matching with Regex
- Git integration with git2
- Parallel processing with Rayon

[0.1.0]: https://github.com/reschjonas/leaktor/releases/tag/v0.1.0
