use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct HuggingFaceValidator {
    client: Client,
}

impl HuggingFaceValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_token(&self, token: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://huggingface.co/api/whoami-v2")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            _ => Ok(false),
        }
    }
}

impl Default for HuggingFaceValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for HuggingFaceValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::HuggingFaceToken => self.validate_token(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::HuggingFaceToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let v = HuggingFaceValidator::new();
        assert!(v.supports(&SecretType::HuggingFaceToken));
        assert!(!v.supports(&SecretType::GitHubPat));
    }
}
