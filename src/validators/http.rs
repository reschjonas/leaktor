use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct HttpValidator {
    #[allow(dead_code)]
    client: Client,
}

impl HttpValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    /// Generic HTTP-based validation
    /// This can be extended for various API keys that can be validated via HTTP
    #[allow(dead_code)]
    async fn validate_http_endpoint(&self, url: &str, token: &str) -> Result<bool> {
        let response = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

impl Default for HttpValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for HttpValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        // Generic HTTP validator - can be extended for specific API keys
        match secret.secret_type {
            SecretType::GenericApiKey | SecretType::OAuthToken => {
                // For generic API keys, we can't validate without knowing the endpoint
                // Return false to indicate unknown
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::GenericApiKey | SecretType::OAuthToken
        )
    }
}
