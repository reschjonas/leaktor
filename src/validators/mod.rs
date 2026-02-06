pub mod aws;
pub mod github;
pub mod http;
pub mod slack;
pub mod stripe;

pub use aws::AwsValidator;
pub use github::GitHubValidator;
pub use http::HttpValidator;
pub use slack::SlackValidator;
pub use stripe::StripeValidator;

use crate::models::{Secret, SecretType};
use anyhow::Result;

/// Trait for validating secrets
#[async_trait::async_trait]
pub trait Validator {
    async fn validate(&self, secret: &Secret) -> Result<bool>;
    fn supports(&self, secret_type: &SecretType) -> bool;
}

/// Validate a secret using the appropriate validator
pub async fn validate_secret(secret: &mut Secret) -> Result<()> {
    let validators: Vec<Box<dyn Validator + Send + Sync>> = vec![
        Box::new(AwsValidator::new()),
        Box::new(GitHubValidator::new()),
        Box::new(SlackValidator::new()),
        Box::new(StripeValidator::new()),
    ];

    for validator in validators {
        if validator.supports(&secret.secret_type) {
            match validator.validate(secret).await {
                Ok(is_valid) => {
                    secret.validated = Some(is_valid);
                    return Ok(());
                }
                Err(_) => {
                    // Validation failed (network error, etc.), mark as unknown
                    secret.validated = None;
                }
            }
        }
    }

    Ok(())
}

/// Validate multiple secrets in parallel using tokio tasks
pub async fn validate_secrets_parallel(secrets: &mut [Secret]) -> Result<()> {
    use tokio::task::JoinSet;

    let validators: Vec<Box<dyn Validator + Send + Sync>> = vec![
        Box::new(AwsValidator::new()),
        Box::new(GitHubValidator::new()),
        Box::new(SlackValidator::new()),
        Box::new(StripeValidator::new()),
    ];

    // Build a list of (index, secret_clone) pairs that have a matching validator
    let mut tasks: JoinSet<(usize, Option<bool>)> = JoinSet::new();

    for (idx, secret) in secrets.iter().enumerate() {
        // Find which validator supports this secret type
        let mut found_validator = false;
        for v in &validators {
            if v.supports(&secret.secret_type) {
                found_validator = true;
                break;
            }
        }

        if !found_validator {
            continue;
        }

        let secret_clone = secret.clone();
        tasks.spawn(async move {
            // Re-create validators inside the task (they're cheap)
            let validators: Vec<Box<dyn Validator + Send + Sync>> = vec![
                Box::new(AwsValidator::new()),
                Box::new(GitHubValidator::new()),
                Box::new(SlackValidator::new()),
                Box::new(StripeValidator::new()),
            ];

            for validator in &validators {
                if validator.supports(&secret_clone.secret_type) {
                    match validator.validate(&secret_clone).await {
                        Ok(is_valid) => return (idx, Some(is_valid)),
                        Err(_) => return (idx, None),
                    }
                }
            }

            (idx, None)
        });
    }

    // Collect results
    while let Some(result) = tasks.join_next().await {
        if let Ok((idx, validated)) = result {
            secrets[idx].validated = validated;
        }
    }

    Ok(())
}
