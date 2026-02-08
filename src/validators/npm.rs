use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct NpmValidator {
    client: Client,
}

impl NpmValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_token(&self, token: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://registry.npmjs.org/-/whoami")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from registry.npmjs.org")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from registry.npmjs.org", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for NpmValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for NpmValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::NpmToken => self.validate_token(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::NpmToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = NpmValidator::new();
        assert!(validator.supports(&SecretType::NpmToken));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
