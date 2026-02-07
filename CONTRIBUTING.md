# Contributing to Leaktor

Thank you for your interest in contributing to Leaktor! This document provides guidelines and information for contributors.

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:

1. **Clear title** - Summarize the issue
2. **Description** - Explain what happened vs. what you expected
3. **Steps to reproduce** - Detailed steps to trigger the bug
4. **Environment**:
   - OS (Linux, macOS, Windows)
   - Rust version (`rustc --version`)
   - Leaktor version
5. **Sample code/file** - If applicable (redact sensitive info!)
6. **Error messages** - Full error output

### Suggesting Features

Feature requests are welcome! Please include:

1. **Use case** - Why is this feature needed?
2. **Description** - What should it do?
3. **Examples** - How would it work?
4. **Alternatives** - What workarounds exist currently?

### Pull Requests

#### Before Starting

1. Check existing issues and PRs to avoid duplication
2. For major changes, open an issue first to discuss
3. Fork the repository and create a branch from `main`

#### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/leaktor
cd leaktor

# Build the project
cargo build

# Run tests
cargo test

# Run clippy for linting
cargo clippy

# Format code
cargo fmt
```

#### Making Changes

1. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow Rust conventions and idioms
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass

3. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

   Commit message format:
   - Use imperative mood ("Add feature" not "Added feature")
   - Keep first line under 50 characters
   - Add detailed description if needed

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request**:
   - Fill in the PR template
   - Link related issues
   - Describe your changes clearly
   - Add screenshots for UI changes

#### PR Guidelines

- **One feature per PR** - Keep changes focused
- **Tests required** - Add tests for new features/fixes
- **Documentation** - Update README and docs
- **Code quality** - Run `cargo clippy` and `cargo fmt`
- **No breaking changes** - Unless discussed first

## Development Guidelines

### Code Style

- Follow Rust's official style guide
- Run `cargo fmt` before committing
- Fix all `cargo clippy` warnings
- Use meaningful variable names
- Add comments for complex logic
- Keep functions small and focused

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture
```

Types of tests needed:
- **Unit tests** - Test individual functions
- **Integration tests** - Test complete workflows
- **Pattern tests** - Verify regex patterns work correctly

Example test:
```rust
#[test]
fn test_aws_key_detection() {
    let detector = PatternDetector::new();
    let line = "AWS_KEY=AKIAIOSFODNN7EXAMPLE";
    let secrets = detector.scan_line(line, 3.0);

    assert!(!secrets.is_empty());
    assert!(matches!(secrets[0].secret_type, SecretType::AwsAccessKey));
}
```

### Adding New Secret Patterns

To add a new secret type:

1. **Add to `SecretType` enum** in `src/models/secret.rs`:
   ```rust
   pub enum SecretType {
       // ... existing types
       NewServiceApiKey,
   }
   ```

2. **Add pattern** in `src/detectors/patterns.rs`:
   ```rust
   Pattern {
       name: SecretType::NewServiceApiKey,
       regex: Regex::new(r"newservice_[0-9a-f]{32}").unwrap(),
       severity: Severity::High,
       confidence_base: 0.90,
   },
   ```

3. **Add tests**:
   ```rust
   #[test]
   fn test_new_service_key() {
       let detector = PatternDetector::new();
       let secrets = detector.scan_line("KEY=newservice_abc123...", 3.0);
       assert!(!secrets.is_empty());
   }
   ```

4. **Update documentation** - Add to README's supported secrets list

### Project Structure

```
leaktor/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── config/              # Configuration management
│   │   ├── ignore.rs        # .leaktorignore handling
│   │   └── settings.rs      # Config file parsing
│   ├── detectors/           # Secret detection logic
│   │   ├── patterns.rs      # Regex patterns
│   │   ├── entropy.rs       # Entropy calculation
│   │   └── context.rs       # Context analysis
│   ├── models/              # Data structures
│   │   ├── finding.rs       # Finding representation
│   │   └── secret.rs        # Secret types
│   ├── output/              # Output formatters
│   │   ├── json.rs          # JSON output
│   │   ├── sarif.rs         # SARIF output
│   │   ├── html.rs          # HTML reports
│   │   └── console.rs       # Terminal output
│   ├── scanners/            # File/repo scanners
│   │   ├── git.rs           # Git history scanner
│   │   └── filesystem.rs    # Directory scanner
│   └── validators/          # Secret validators
│       ├── aws.rs           # AWS validation
│       ├── github.rs        # GitHub validation
│       └── http.rs          # Generic HTTP validation
├── tests/                   # Integration tests
├── Cargo.toml              # Dependencies
└── README.md               # Documentation
```

## Review Process

1. **Automated checks** - CI runs tests and linting
2. **Code review** - Maintainers review your code
3. **Feedback** - Address review comments
4. **Approval** - At least one maintainer approval needed
5. **Merge** - Maintainer will merge your PR

## Release Process

Maintainers handle releases:

1. Update version in `Cargo.toml`
2. Update CHANGELOG
3. Create git tag
4. Publish to crates.io
5. Create GitHub release

## Getting Help

- **Questions?** Open a discussion or issue
- **Stuck?** Comment on your PR for help
- **Security issue?** Email maintainer privately

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- README acknowledgments

## Areas for Contribution

Good first issues:
- Adding new secret patterns
- Improving documentation
- Writing tests
- Fixing bugs

Advanced contributions:
- Performance optimizations
- New output formats
- Additional validators
- Cloud provider support

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Thank You

Contributions help improve Leaktor for everyone. Your time and effort are appreciated.
