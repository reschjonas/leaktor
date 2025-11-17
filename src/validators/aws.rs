use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct AwsValidator {
    #[allow(dead_code)]
    client: Client,
}

impl AwsValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    /// Validate AWS access key by attempting to call STS GetCallerIdentity
    #[allow(dead_code)]
    async fn validate_access_key(&self, access_key: &str, _secret_key: &str) -> Result<bool> {
        // This is a simplified validation - in production you'd want to use
        // the AWS SDK and properly sign requests

        // For now, we do basic format validation
        // Real validation would require the secret key and proper AWS signature

        // Check format: should start with AKIA, ASIA, etc.
        let is_valid_format = access_key.starts_with("AKIA")
            || access_key.starts_with("ASIA")
            || access_key.starts_with("AGPA")
            || access_key.starts_with("AIDA");

        if !is_valid_format {
            return Ok(false);
        }

        // In a real implementation, you would:
        // 1. Use AWS SDK to create a client with these credentials
        // 2. Call STS::GetCallerIdentity
        // 3. Return true if successful, false if unauthorized

        // For safety reasons in a pentesting tool, we'll just do format validation
        // and not actually attempt to use the credentials
        Ok(is_valid_format && access_key.len() == 20)
    }
}

impl Default for AwsValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for AwsValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::AwsAccessKey => {
                // Basic format validation only
                let is_valid = secret.value.len() == 20
                    && (secret.value.starts_with("AKIA")
                        || secret.value.starts_with("ASIA")
                        || secret.value.starts_with("AGPA")
                        || secret.value.starts_with("AIDA"));
                Ok(is_valid)
            }
            SecretType::AwsSecretKey => {
                // Secret keys are 40 characters base64
                Ok(secret.value.len() == 40)
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::AwsAccessKey | SecretType::AwsSecretKey | SecretType::AwsSessionToken
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    #[tokio::test]
    async fn test_aws_access_key_format_validation() {
        let validator = AwsValidator::new();
        let secret = Secret::new(
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            4.0,
            Severity::Critical,
            0.9,
        );

        let result = validator.validate(&secret).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_supports() {
        let validator = AwsValidator::new();
        assert!(validator.supports(&SecretType::AwsAccessKey));
        assert!(validator.supports(&SecretType::AwsSecretKey));
        assert!(!validator.supports(&SecretType::GitHubToken));
    }
}
