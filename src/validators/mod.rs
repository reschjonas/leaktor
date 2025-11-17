pub mod aws;
pub mod github;
pub mod http;

pub use aws::AwsValidator;
pub use github::GitHubValidator;
pub use http::HttpValidator;

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
    ];

    for validator in validators {
        if validator.supports(&secret.secret_type) {
            match validator.validate(secret).await {
                Ok(is_valid) => {
                    secret.validated = Some(is_valid);
                    return Ok(());
                }
                Err(_) => {
                    // Validation failed, continue to next validator or mark as unknown
                    secret.validated = None;
                }
            }
        }
    }

    Ok(())
}
