use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct NewRelicValidator {
    client: Client,
}

impl NewRelicValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_key(&self, key: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://api.newrelic.com/v2/applications.json")
            .header("Api-Key", key)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from api.newrelic.com")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from api.newrelic.com", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for NewRelicValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for NewRelicValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::NewRelicApiKey | SecretType::NewRelicBrowserApiKey => {
                self.validate_key(&secret.value).await
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::NewRelicApiKey | SecretType::NewRelicBrowserApiKey
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = NewRelicValidator::new();
        assert!(validator.supports(&SecretType::NewRelicApiKey));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
