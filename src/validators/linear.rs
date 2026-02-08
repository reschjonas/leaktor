use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct LinearValidator {
    client: Client,
}

impl LinearValidator {
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
            .post("https://api.linear.app/graphql")
            .header("Authorization", key)
            .json(&serde_json::json!({
                "query": "{ viewer { id } }"
            }))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => {
                let body: serde_json::Value = response.json().await?;
                // If we get data.viewer, the key is valid
                Ok(body.get("data").and_then(|d| d.get("viewer")).is_some())
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from api.linear.app")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from api.linear.app", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for LinearValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for LinearValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::LinearApiKey => self.validate_key(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::LinearApiKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = LinearValidator::new();
        assert!(validator.supports(&SecretType::LinearApiKey));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
