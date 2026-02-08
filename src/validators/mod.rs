pub mod anthropic;
pub mod aws;
pub mod datadog;
pub mod digitalocean;
pub mod discord;
pub mod format;
pub mod github;
pub mod gitlab;
pub mod http;
pub mod huggingface;
pub mod linear;
pub mod newrelic;
pub mod npm;
pub mod openai;
pub mod pypi;
pub mod sendgrid;
pub mod services;
pub mod shopify;
pub mod slack;
pub mod stripe;
pub mod telegram;
pub mod twilio;

pub use anthropic::AnthropicValidator;
pub use aws::AwsValidator;
pub use datadog::DatadogValidator;
pub use digitalocean::DigitalOceanValidator;
pub use discord::DiscordValidator;
pub use format::FormatValidator;
pub use github::GitHubValidator;
pub use gitlab::GitLabValidator;
pub use http::HttpValidator;
pub use huggingface::HuggingFaceValidator;
pub use linear::LinearValidator;
pub use newrelic::NewRelicValidator;
pub use npm::NpmValidator;
pub use openai::OpenAiValidator;
pub use pypi::PyPiValidator;
pub use sendgrid::SendGridValidator;
pub use services::ServiceValidator;
pub use shopify::ShopifyValidator;
pub use slack::SlackValidator;
pub use stripe::StripeValidator;
pub use telegram::TelegramValidator;
pub use twilio::TwilioValidator;

use crate::models::{Secret, SecretType};
use crate::scan_warn;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Trait for validating secrets
#[async_trait::async_trait]
pub trait Validator {
    async fn validate(&self, secret: &Secret) -> Result<bool>;
    fn supports(&self, secret_type: &SecretType) -> bool;
}

// ═══════════════════════════════════════════════════════════════════════════
// Rate limiting
// ═══════════════════════════════════════════════════════════════════════════

/// Rate limiter for API-based validation.
///
/// Prevents hammering external APIs when scanning large repos with many
/// findings. Uses a counting semaphore for global concurrency and a
/// configurable inter-request delay.
#[derive(Clone)]
pub struct ValidationRateLimiter {
    /// Global concurrency cap: at most N API calls in flight at once.
    semaphore: Arc<Semaphore>,

    /// Minimum delay (ms) injected between consecutive API calls.
    /// Spreads requests across time to avoid burst-triggering rate limits.
    delay_ms: u64,

    /// Max retries on 429 / transient errors.
    pub max_retries: u32,
}

impl ValidationRateLimiter {
    pub fn new(max_concurrent: usize, delay_ms: u64, max_retries: u32) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            delay_ms,
            max_retries,
        }
    }

    /// Create a rate limiter from config values.
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self::new(
            config.max_concurrent_validations,
            config.validation_delay_ms,
            config.validation_max_retries,
        )
    }

    /// Create a default rate limiter (10 concurrent, 100ms delay, 3 retries).
    pub fn default_limiter() -> Self {
        Self::new(10, 100, 3)
    }

    /// Acquire a permit before making an API call.
    /// This blocks (asynchronously) until a slot is available and then
    /// injects the configured inter-request delay.
    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed unexpectedly");

        // Inject inter-request delay to spread out calls
        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }

        permit
    }

    /// Compute the back-off duration for a retry attempt after a 429 or
    /// transient failure.  Uses exponential back-off with jitter:
    ///   base_delay * 2^attempt  +  random 0-500ms
    pub fn backoff_duration(&self, attempt: u32) -> std::time::Duration {
        let base_ms = 1000u64; // 1 second base
        let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(5));
        // Deterministic "jitter" based on attempt number (avoids rand dep)
        let jitter_ms = (attempt as u64 * 137) % 500;
        std::time::Duration::from_millis(exp_ms + jitter_ms)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Validator registry
// ═══════════════════════════════════════════════════════════════════════════

/// Create the full list of all available validators.
///
/// Registration order matters: the first validator that `supports()` a given
/// SecretType wins. Order is:
///   1. Dedicated API validators (GitHub, AWS, Stripe, etc.) — most accurate
///   2. ServiceValidator — config-driven API validation for ~100+ services
///   3. FormatValidator — universal format checks for ALL remaining types
fn all_validators() -> Vec<Box<dyn Validator + Send + Sync>> {
    vec![
        // ── Tier 1: Dedicated API validators ──────────────────────────
        Box::new(AwsValidator::new()),
        Box::new(GitHubValidator::new()),
        Box::new(GitLabValidator::new()),
        Box::new(SlackValidator::new()),
        Box::new(StripeValidator::new()),
        Box::new(OpenAiValidator::new()),
        Box::new(AnthropicValidator::new()),
        Box::new(SendGridValidator::new()),
        Box::new(DatadogValidator::new()),
        Box::new(HuggingFaceValidator::new()),
        Box::new(DigitalOceanValidator::new()),
        Box::new(TwilioValidator::new()),
        Box::new(NpmValidator::new()),
        Box::new(DiscordValidator::new()),
        Box::new(TelegramValidator::new()),
        Box::new(PyPiValidator::new()),
        Box::new(ShopifyValidator::new()),
        Box::new(LinearValidator::new()),
        Box::new(NewRelicValidator::new()),
        // ── Tier 2: Config-driven API validator (~100+ services) ──────
        Box::new(ServiceValidator::new()),
        // ── Tier 3: Universal format validator (ALL types) ────────────
        Box::new(FormatValidator::new()),
    ]
}

/// Check if a validator is format-only (doesn't make API calls).
/// FormatValidator is the only pure-format validator and is always last.
fn is_format_only_validator(
    validators: &[Box<dyn Validator + Send + Sync>],
    idx: usize,
) -> bool {
    // FormatValidator is always last in the list
    idx == validators.len() - 1
}

// ═══════════════════════════════════════════════════════════════════════════
// Public validation API
// ═══════════════════════════════════════════════════════════════════════════

/// Validate a single secret using the appropriate validator.
/// Uses the default rate limiter (for backward compatibility).
pub async fn validate_secret(secret: &mut Secret) -> Result<()> {
    let limiter = ValidationRateLimiter::default_limiter();
    validate_secret_with_limiter(secret, &limiter).await
}

/// Validate a single secret with an explicit rate limiter.
pub async fn validate_secret_with_limiter(
    secret: &mut Secret,
    limiter: &ValidationRateLimiter,
) -> Result<()> {
    let validators = all_validators();

    for (i, validator) in validators.iter().enumerate() {
        if validator.supports(&secret.secret_type) {
            // Format-only validators don't make API calls, no need to rate-limit
            if is_format_only_validator(&validators, i) {
                match validator.validate(secret).await {
                    Ok(is_valid) => {
                        secret.validated = Some(is_valid);
                        return Ok(());
                    }
                    Err(_) => {
                        secret.validated = None;
                    }
                }
            } else {
                // API-based validator: acquire rate-limit permit + retry on 429
                for attempt in 0..=limiter.max_retries {
                    let _permit = limiter.acquire().await;

                    match validator.validate(secret).await {
                        Ok(is_valid) => {
                            secret.validated = Some(is_valid);
                            return Ok(());
                        }
                        Err(e) => {
                            let is_rate_limited = e
                                .to_string()
                                .contains("429")
                                || e.to_string().to_lowercase().contains("too many requests");

                            if is_rate_limited && attempt < limiter.max_retries {
                                // Back off and retry
                                let backoff = limiter.backoff_duration(attempt);
                                tokio::time::sleep(backoff).await;
                                continue;
                            }

                            // Non-retriable error or retries exhausted
                            secret.validated = None;
                        }
                    }
                }
            }
            return Ok(());
        }
    }

    Ok(())
}

/// Validate multiple secrets in parallel with rate limiting.
/// Uses the default rate limiter.
pub async fn validate_secrets_parallel(secrets: &mut [Secret]) -> Result<()> {
    let limiter = ValidationRateLimiter::default_limiter();
    validate_secrets_parallel_with_limiter(secrets, &limiter).await
}

/// Validate multiple secrets in parallel with an explicit rate limiter.
///
/// The semaphore inside the limiter caps how many API calls run at once.
/// Format-only validation (no API call) runs without acquiring a permit,
/// so it never blocks.
pub async fn validate_secrets_parallel_with_limiter(
    secrets: &mut [Secret],
    limiter: &ValidationRateLimiter,
) -> Result<()> {
    use tokio::task::JoinSet;

    let validators = all_validators();
    let limiter = limiter.clone();

    let mut tasks: JoinSet<(usize, Option<bool>)> = JoinSet::new();

    for (idx, secret) in secrets.iter().enumerate() {
        // Determine which validator index supports this secret type
        let mut validator_idx: Option<usize> = None;
        for (i, v) in validators.iter().enumerate() {
            if v.supports(&secret.secret_type) {
                validator_idx = Some(i);
                break;
            }
        }

        let Some(v_idx) = validator_idx else {
            continue;
        };

        let secret_clone = secret.clone();
        let limiter = limiter.clone();
        let needs_api = !is_format_only_validator(&validators, v_idx);

        tasks.spawn(async move {
            let validators = all_validators();
            let validator = &validators[v_idx];

            if !needs_api {
                // Format-only: no rate limiting needed
                match validator.validate(&secret_clone).await {
                    Ok(is_valid) => return (idx, Some(is_valid)),
                    Err(_) => return (idx, None),
                }
            }

            // API-based: acquire permit + retry with backoff
            for attempt in 0..=limiter.max_retries {
                let _permit = limiter.acquire().await;

                match validator.validate(&secret_clone).await {
                    Ok(is_valid) => return (idx, Some(is_valid)),
                    Err(e) => {
                        let is_rate_limited = e
                            .to_string()
                            .contains("429")
                            || e.to_string().to_lowercase().contains("too many requests");

                        if is_rate_limited && attempt < limiter.max_retries {
                            let backoff = limiter.backoff_duration(attempt);
                            tokio::time::sleep(backoff).await;
                            continue;
                        }

                        return (idx, None);
                    }
                }
            }

            (idx, None)
        });
    }

    // Collect results
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((idx, validated)) => {
                secrets[idx].validated = validated;
            }
            Err(e) => {
                // JoinError means the task panicked or was cancelled.
                // Log it instead of silently dropping.
                scan_warn!(
                    "validate",
                    "validation task failed: {}",
                    e
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    fn make(st: SecretType, value: &str) -> Secret {
        Secret::new(st, value.to_string(), 4.0, Severity::High, 0.9)
    }

    /// Every SecretType must be supported by at least one validator.
    /// Since FormatValidator returns `true` for all types, this always passes.
    /// This test documents the architecture and catches if someone removes
    /// FormatValidator from the chain.
    #[test]
    fn test_all_types_have_a_validator() {
        let validators = all_validators();

        // Comprehensive list of representative SecretType variants
        let types: Vec<SecretType> = vec![
            // Cloud
            SecretType::AwsAccessKey,
            SecretType::AwsSecretKey,
            SecretType::AwsSessionToken,
            SecretType::AwsMwsKey,
            SecretType::GcpApiKey,
            SecretType::GcpServiceAccount,
            SecretType::AzureStorageKey,
            SecretType::AzureConnectionString,
            SecretType::AzureClientSecret,
            // VCS
            SecretType::GitHubToken,
            SecretType::GitHubPat,
            SecretType::GitHubOauth,
            SecretType::GitLabToken,
            SecretType::GitLabPat,
            SecretType::BitbucketToken,
            // Payment
            SecretType::StripeApiKey,
            SecretType::StripeRestrictedKey,
            SecretType::SendGridApiKey,
            SecretType::TwilioApiKey,
            SecretType::SlackToken,
            SecretType::SlackWebhook,
            SecretType::SquareAccessToken,
            SecretType::SquareOAuthToken,
            SecretType::ShopifyApiKey,
            SecretType::ShopifySharedSecret,
            SecretType::ShopifyAccessToken,
            SecretType::PaypalClientSecret,
            // Communication
            SecretType::DiscordBotToken,
            SecretType::DiscordWebhook,
            SecretType::TelegramBotToken,
            // Database
            SecretType::DatabaseUrl,
            SecretType::PostgresConnectionString,
            SecretType::MongoDbConnectionString,
            SecretType::MysqlConnectionString,
            SecretType::RedisConnectionString,
            // Keys
            SecretType::RsaPrivateKey,
            SecretType::SshPrivateKey,
            SecretType::PgpPrivateKey,
            SecretType::EcPrivateKey,
            SecretType::Pkcs8PrivateKey,
            SecretType::DsaPrivateKey,
            SecretType::OpensslPrivateKey,
            SecretType::EncryptedPrivateKey,
            SecretType::PuttyPrivateKey,
            // Tokens
            SecretType::JwtToken,
            SecretType::OAuthToken,
            SecretType::GenericApiKey,
            SecretType::GenericSecret,
            SecretType::GenericCredential,
            // AI/ML
            SecretType::OpenAiApiKey,
            SecretType::AnthropicApiKey,
            SecretType::CohereApiKey,
            SecretType::HuggingFaceToken,
            SecretType::ReplicateApiKey,
            SecretType::GroqApiKey,
            SecretType::DeepSeekApiKey,
            SecretType::MistralApiKey,
            // Cloud/SaaS
            SecretType::DatadogApiKey,
            SecretType::DatadogAppKey,
            SecretType::CloudflareApiKey,
            SecretType::CloudflareApiToken,
            SecretType::DigitalOceanToken,
            SecretType::VercelToken,
            SecretType::NetlifyToken,
            SecretType::LinearApiKey,
            SecretType::NotionApiKey,
            SecretType::AirtableApiKey,
            SecretType::PlanetScaleToken,
            // Package Registries
            SecretType::NpmToken,
            SecretType::PyPiApiToken,
            SecretType::NuGetApiKey,
            SecretType::RubyGemsApiKey,
            // Auth
            SecretType::OktaApiToken,
            SecretType::Auth0ManagementToken,
            SecretType::FirebaseApiKey,
            SecretType::SupabaseAnonKey,
            // Infra
            SecretType::DockerHubToken,
            SecretType::HashiCorpVaultToken,
            SecretType::NewRelicApiKey,
            SecretType::SentryDsn,
            SecretType::AlgoliaApiKey,
            SecretType::ElasticApiKey,
            SecretType::GrafanaApiKey,
            SecretType::CircleCiToken,
            // Misc
            SecretType::HerokuApiKey,
            SecretType::MapboxToken,
            SecretType::PasswordInUrl,
            SecretType::HighEntropyString,
            SecretType::Custom("test".to_string()),
            // Newer types - broad coverage
            SecretType::AgeSecretKey,
            SecretType::OnePasswordSecretKey,
            SecretType::ClerkApiKey,
            SecretType::FigmaPat,
            SecretType::DopplerToken,
            SecretType::TerraformCloudToken,
            SecretType::PulumiAccessToken,
            SecretType::SonarQubeToken,
            SecretType::DynatraceApiToken,
            SecretType::HetznerApiToken,
            SecretType::BinanceApiKey,
            SecretType::EtherscanApiKey,
        ];

        for st in &types {
            let supported = validators.iter().any(|v| v.supports(st));
            assert!(
                supported,
                "SecretType {:?} is NOT supported by any validator!",
                st
            );
        }
    }

    /// Verify the validator chain ordering: first matching validator wins.
    /// FormatValidator (last) should catch everything.
    #[test]
    fn test_validator_chain_ordering() {
        let validators = all_validators();

        // FormatValidator must be last (supports everything)
        let last = &validators[validators.len() - 1];
        assert!(
            last.supports(&SecretType::Custom("test".to_string())),
            "Last validator should support Custom types (FormatValidator)"
        );

        // All validators except the last should NOT support Custom types
        // (unless they're very permissive, which dedicated ones shouldn't be)
        let non_last = &validators[..validators.len() - 1];
        let custom_supporter = non_last
            .iter()
            .any(|v| v.supports(&SecretType::Custom("random_custom".to_string())));
        assert!(
            !custom_supporter,
            "Only FormatValidator should support Custom types"
        );
    }

    /// Test the full validate_secret pipeline: format validation for properly
    /// formatted values should set validated = Some(true)
    #[tokio::test]
    async fn test_format_validate_pipeline() {
        // Test a variety of types through the full validate_secret pipeline
        let test_cases = vec![
            make(SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"),
            make(SecretType::GitHubPat, "ghp_1234567890123456789012345678901234"),
            make(SecretType::StripeApiKey, "sk_live_1234567890abcdefghijklmnop"),
            make(SecretType::DatadogApiKey, "abcdef0123456789abcdef0123456789"),
            make(SecretType::RsaPrivateKey, "-----BEGIN RSA PRIVATE KEY-----"),
            make(SecretType::PostgresConnectionString, "postgresql://user:pass@host:5432/db"),
            make(SecretType::JwtToken, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"),
        ];

        for mut secret in test_cases {
            validate_secret(&mut secret).await.unwrap();
            assert!(
                secret.validated.is_some(),
                "validate_secret() returned None for {:?} - no validator handled it",
                secret.secret_type
            );
        }
    }

    /// Test validate_secrets_parallel works correctly
    #[tokio::test]
    async fn test_parallel_validation() {
        let mut secrets = vec![
            make(SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"),
            make(SecretType::GitHubPat, "ghp_1234567890123456789012345678901234"),
            make(SecretType::DatadogApiKey, "abcdef0123456789abcdef0123456789"),
            make(SecretType::RsaPrivateKey, "-----BEGIN RSA PRIVATE KEY-----"),
        ];

        validate_secrets_parallel(&mut secrets).await.unwrap();

        for secret in &secrets {
            assert!(
                secret.validated.is_some(),
                "Parallel validation returned None for {:?}",
                secret.secret_type
            );
        }
    }

    /// Ensure bad values are correctly rejected through the pipeline
    #[tokio::test]
    async fn test_format_rejects_bad_values() {
        let test_cases = vec![
            make(SecretType::AwsAccessKey, "XXXX_not_an_aws_key"),
            make(SecretType::GitHubPat, "not_a_github_pat"),
            make(SecretType::StripeApiKey, "pk_test_wrong_prefix"),
            make(SecretType::DatadogApiKey, "tooshort"),
        ];

        for mut secret in test_cases {
            validate_secret(&mut secret).await.unwrap();
            assert_eq!(
                secret.validated,
                Some(false),
                "Expected validated=Some(false) for invalid {:?} value '{}'",
                secret.secret_type,
                &secret.value[..secret.value.len().min(30)]
            );
        }
    }

    /// ServiceValidator should support specific types
    #[test]
    fn test_service_validator_supports_specific_types() {
        let sv = ServiceValidator::new();
        // Services with known API endpoints
        assert!(sv.supports(&SecretType::CloudflareApiToken));
        assert!(sv.supports(&SecretType::VercelToken));
        assert!(sv.supports(&SecretType::NotionApiKey));
        assert!(sv.supports(&SecretType::CohereApiKey));
        assert!(sv.supports(&SecretType::PosthogApiKey));
        assert!(sv.supports(&SecretType::FaunaDbApiKey));

        // Should NOT support generic types
        assert!(!sv.supports(&SecretType::GenericApiKey));
        assert!(!sv.supports(&SecretType::HighEntropyString));
        assert!(!sv.supports(&SecretType::PasswordInUrl));
    }

    /// FormatValidator should support ALL types
    #[test]
    fn test_format_validator_supports_everything() {
        let fv = FormatValidator::new();
        let all_types = vec![
            SecretType::AwsAccessKey,
            SecretType::GitHubPat,
            SecretType::GenericApiKey,
            SecretType::HighEntropyString,
            SecretType::PasswordInUrl,
            SecretType::Custom("anything".to_string()),
            SecretType::RsaPrivateKey,
            SecretType::JwtToken,
            SecretType::PostgresConnectionString,
        ];

        for st in all_types {
            assert!(
                fv.supports(&st),
                "FormatValidator should support {:?}",
                st
            );
        }
    }

    // ── Rate Limiter Tests ────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_default_construction() {
        let rl = ValidationRateLimiter::default_limiter();
        assert_eq!(rl.max_retries, 3);
        assert_eq!(rl.delay_ms, 100);
    }

    #[test]
    fn test_rate_limiter_from_config() {
        let mut config = crate::config::Config::default();
        config.max_concurrent_validations = 5;
        config.validation_delay_ms = 200;
        config.validation_max_retries = 2;

        let rl = ValidationRateLimiter::from_config(&config);
        assert_eq!(rl.max_retries, 2);
        assert_eq!(rl.delay_ms, 200);
    }

    #[test]
    fn test_backoff_duration_exponential() {
        let rl = ValidationRateLimiter::new(10, 0, 5);

        let d0 = rl.backoff_duration(0);
        let d1 = rl.backoff_duration(1);
        let d2 = rl.backoff_duration(2);
        let d3 = rl.backoff_duration(3);

        // Each attempt should roughly double the base duration
        assert!(d1 > d0, "attempt 1 should be longer than attempt 0");
        assert!(d2 > d1, "attempt 2 should be longer than attempt 1");
        assert!(d3 > d2, "attempt 3 should be longer than attempt 2");

        // Base is 1000ms, so attempt 0 should be ~1000-1500ms
        assert!(
            d0.as_millis() >= 1000 && d0.as_millis() < 2000,
            "attempt 0 backoff should be ~1-2s, got {}ms",
            d0.as_millis()
        );

        // Attempt 2 should be ~4000-5000ms
        assert!(
            d2.as_millis() >= 4000 && d2.as_millis() < 6000,
            "attempt 2 backoff should be ~4-6s, got {}ms",
            d2.as_millis()
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_concurrency_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let rl = ValidationRateLimiter::new(3, 0, 0); // 3 concurrent, no delay
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let rl = rl.clone();
            let active = active.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _permit = rl.acquire().await;
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                // Record the peak
                peak.fetch_max(current, Ordering::SeqCst);
                // Simulate some work
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= 3,
            "Peak concurrency should be <= 3, but was {}",
            observed_peak
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_delay_enforced() {
        let rl = ValidationRateLimiter::new(1, 100, 0); // 1 concurrent, 100ms delay

        let start = std::time::Instant::now();

        // Acquire 3 permits sequentially
        for _ in 0..3 {
            let _permit = rl.acquire().await;
            // Release immediately by dropping permit
        }

        let elapsed = start.elapsed();
        // 3 acquires * 100ms delay = at least 300ms
        assert!(
            elapsed.as_millis() >= 250,
            "Expected >= 250ms for 3 acquires with 100ms delay, got {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    async fn test_format_only_skips_rate_limit() {
        // FormatValidator (last) should NOT be rate limited
        let validators = all_validators();
        assert!(
            is_format_only_validator(&validators, validators.len() - 1),
            "Last validator should be format-only"
        );
        // Dedicated validators should NOT be format-only
        assert!(
            !is_format_only_validator(&validators, 0),
            "First validator should NOT be format-only"
        );
    }

    #[tokio::test]
    async fn test_validate_with_custom_limiter() {
        let limiter = ValidationRateLimiter::new(2, 0, 1);

        let mut secrets = vec![
            make(SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE"),
            make(SecretType::GitHubPat, "ghp_1234567890123456789012345678901234"),
            make(SecretType::DatadogApiKey, "abcdef0123456789abcdef0123456789"),
            make(SecretType::RsaPrivateKey, "-----BEGIN RSA PRIVATE KEY-----"),
        ];

        validate_secrets_parallel_with_limiter(&mut secrets, &limiter)
            .await
            .unwrap();

        for secret in &secrets {
            assert!(
                secret.validated.is_some(),
                "Validation with custom limiter returned None for {:?}",
                secret.secret_type
            );
        }
    }
}
