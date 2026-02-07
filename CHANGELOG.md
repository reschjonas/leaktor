# Changelog

All notable changes to Leaktor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-07

### Added

- **`leaktor init`** -- one-command project setup: creates config, ignore file, pre-commit hook, GitHub Actions workflow, and optional baseline. Supports `--no-hook`, `--no-ci`, `--baseline` flags. Idempotent (skips existing files on re-run).
- **`leaktor trace`** -- blast radius analysis: find everywhere a secret is referenced across the codebase. Supports tracing by value, by secret type (`--type`), or from a file (`--file`). Shows categorized blast radius summary.
- **`leaktor diff`** -- scan comparison: compare two JSON scan results to see added, removed, and unchanged findings. Supports console and JSON output formats.
- **`--include-deps`** flag on `leaktor scan` -- scans dependency directories (`node_modules/`, `vendor/`, `.venv/`, etc.) that are normally skipped. Uses `walkdir` directly to bypass gitignore filtering for maximum coverage.
- **Multi-format scanning** -- automatically decodes and scans structured files:
  - Kubernetes Secrets: base64 `.data` values decoded and scanned
  - Terraform state (`.tfstate`): JSON values recursively walked + base64 blobs decoded
  - Docker Compose: `environment:` values scanned (both mapping and list styles)
  - CloudFormation: `Parameters` defaults and `Resources` properties scanned
- 61 new secret patterns (146 types total, 152 regex patterns): 1Password, Age, Alibaba, Artifactory, Asana, Azure AD, Beamer, Bitwarden, Clojars, Codecov, Coinbase, Contentful, Dropbox, DSA, Duffel, Dynatrace, EasyPost, Facebook, Flutterwave, Frame.io, FreshBooks, GitHub App/Fine-grained PAT, Google OAuth, Infracost, Intercom, Kraken, Lob, MessageBird, Neon, New Relic Browser, NY Times, PKCS8, PlanetScale, Postman, Prefect, Railway, RapidAPI, ReadMe, Scalingo, Sourcegraph, Tailscale, Tencent, Trello, Turborepo, Twitch, Twitter, Typeform, Vault Batch, Yandex, Zendesk
- DSL pattern configuration via `.leaktor.toml` custom patterns (name, regex, severity, confidence, description)
- Rule-based allowlisting in `.leaktor.toml` (match by secret type, file path glob, value regex, severity)

### Fixed

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

[0.2.0]: https://github.com/reschjonas/leaktor/releases/tag/v0.2.0

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

- Built with Rust 2024 Edition
- Async validation with Tokio
- Pattern matching with Regex
- Git integration with git2
- Parallel processing with Rayon

[0.2.0]: https://github.com/reschjonas/leaktor/releases/tag/v0.2.0
[0.1.0]: https://github.com/reschjonas/leaktor/releases/tag/v0.1.0
