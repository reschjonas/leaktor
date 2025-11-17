use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct GitHubValidator {
    client: Client,
}

impl GitHubValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    /// Validate GitHub token by calling the GitHub API
    async fn validate_token(&self, token: &str) -> Result<bool> {
        // Call GitHub API to validate the token
        let response = self
            .client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {}", token))
            .send()
            .await?;

        // If we get 200, token is valid
        // If we get 401, token is invalid
        // Other errors might be rate limiting, network issues, etc.
        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED => Ok(false),
            _ => {
                // For other status codes, we can't definitively say
                // Return false to be safe
                Ok(false)
            }
        }
    }
}

impl Default for GitHubValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for GitHubValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::GitHubPat | SecretType::GitHubOauth | SecretType::GitHubToken => {
                // Attempt to validate the token
                self.validate_token(&secret.value).await
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::GitHubPat | SecretType::GitHubOauth | SecretType::GitHubToken
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    #[test]
    fn test_supports() {
        let validator = GitHubValidator::new();
        assert!(validator.supports(&SecretType::GitHubPat));
        assert!(validator.supports(&SecretType::GitHubToken));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let validator = GitHubValidator::new();
        let secret = Secret::new(
            SecretType::GitHubPat,
            "ghp_invalidtokeninvalidtokeninvalidto".to_string(),
            4.0,
            Severity::Critical,
            0.9,
        );

        let result = validator.validate(&secret).await;
        // Should return Ok(false) for invalid token
        assert!(result.is_ok());
        if let Ok(is_valid) = result {
            assert!(!is_valid);
        }
    }
}
