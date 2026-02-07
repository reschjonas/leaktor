use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct DatadogValidator {
    client: Client,
}

impl DatadogValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_api_key(&self, key: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://api.datadoghq.com/api/v1/validate")
            .header("DD-API-KEY", key)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let body: serde_json::Value = response.json().await?;
                Ok(body.get("valid").and_then(|v| v.as_bool()).unwrap_or(false))
            }
            403 => Ok(false),
            _ => Ok(false),
        }
    }
}

impl Default for DatadogValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for DatadogValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::DatadogApiKey => self.validate_api_key(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::DatadogApiKey | SecretType::DatadogAppKey
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let v = DatadogValidator::new();
        assert!(v.supports(&SecretType::DatadogApiKey));
        assert!(v.supports(&SecretType::DatadogAppKey));
        assert!(!v.supports(&SecretType::StripeApiKey));
    }
}
