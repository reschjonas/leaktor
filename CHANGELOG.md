# Changelog

All notable changes to Leaktor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

First public release of Leaktor - a blazingly fast secrets scanner with validation capabilities!

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
