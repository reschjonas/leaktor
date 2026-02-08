use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct DigitalOceanValidator {
    client: Client,
}

impl DigitalOceanValidator {
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
            .get("https://api.digitalocean.com/v2/account")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from api.digitalocean.com")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from api.digitalocean.com", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for DigitalOceanValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for DigitalOceanValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::DigitalOceanToken => self.validate_token(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::DigitalOceanToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = DigitalOceanValidator::new();
        assert!(validator.supports(&SecretType::DigitalOceanToken));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
