# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing:
- **Email:** Create a private security advisory at https://github.com/reschjonas/leaktor/security/advisories/new

### What to Include

Please include the following information:
- Type of vulnerability
- Full paths of affected source file(s)
- Location of the affected code (tag/branch/commit/direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity, typically 30-90 days
- **Credit:** You will be credited in the security advisory (if desired)

## Security Best Practices for Users

When using Leaktor:

1. **Validation Flag** - Only use `--validate` when authorized to test credentials
2. **Token Storage** - Store GitHub tokens securely, never commit them
3. **Output Files** - Be careful with JSON/SARIF outputs containing actual secrets
4. **False Positives** - Review findings before sharing reports
5. **CI/CD** - Use `--fail-on-found` in pipelines to prevent secret commits

## Known Security Considerations

### Validation Feature

The `--validate` flag makes API calls to check if secrets are active:
- AWS validation uses AWS STS GetCallerIdentity
- GitHub, GitLab, Stripe, Slack, and 15+ other services validated via their APIs
- Rate limiting protects against API hammering (configurable concurrency, delay, retries)
- **Use responsibly** and only with proper authorization

### Output Files

Output files (JSON, SARIF, HTML) may contain:
- Partial or full secret values
- File paths and line numbers
- Git commit information
- **Handle with care** and don't commit to repositories

## Security Features in Leaktor

- **No external telemetry** - All scanning happens locally
- **Opt-in validation** - Network calls only with explicit `--validate` flag
- **Rate-limited validation** - Configurable concurrency, delay, and retry limits
- **Secret redaction** - Secrets are partially redacted in console output
- **Entropy analysis** - Reduces false positives
- **Context awareness** - Understands test files and examples
- **Warning diagnostics** - Non-fatal errors surfaced via `scan_warn!` instead of silently ignored

## Vulnerability Disclosure Policy

We follow responsible disclosure practices:
- Security researchers have 90 days to report before public disclosure
- We aim to patch critical vulnerabilities within 30 days
- Coordinated disclosure with security researchers
- Public credit given to reporters (if desired)

## Security Acknowledgments

We thank the following researchers for responsibly disclosing vulnerabilities:
- (None yet - be the first!)

---

**Last Updated:** 2026-02-08
