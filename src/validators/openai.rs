use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct OpenAiValidator {
    client: Client,
}

impl OpenAiValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_key(&self, key: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            429 => Ok(true), // Rate limited = key is valid
            _ => Ok(false),
        }
    }
}

impl Default for OpenAiValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for OpenAiValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::OpenAiApiKey => self.validate_key(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::OpenAiApiKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let v = OpenAiValidator::new();
        assert!(v.supports(&SecretType::OpenAiApiKey));
        assert!(!v.supports(&SecretType::AwsAccessKey));
    }
}
