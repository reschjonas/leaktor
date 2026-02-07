use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct SendGridValidator {
    client: Client,
}

impl SendGridValidator {
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
            .get("https://api.sendgrid.com/v3/scopes")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            401 | 403 => Ok(false),
            429 => Ok(true), // Rate limited = key is valid
            _ => Ok(false),
        }
    }
}

impl Default for SendGridValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for SendGridValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::SendGridApiKey => self.validate_key(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::SendGridApiKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let v = SendGridValidator::new();
        assert!(v.supports(&SecretType::SendGridApiKey));
        assert!(!v.supports(&SecretType::SlackToken));
    }
}
