use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct StripeValidator {
    client: Client,
}

impl StripeValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    /// Validate a Stripe key by calling the /v1/charges endpoint
    async fn validate_key(&self, key: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://api.stripe.com/v1/charges?limit=1")
            .basic_auth(key, None::<&str>)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            // 403 means the key is valid but doesn't have permission for this endpoint
            403 => Ok(true),
            429 => anyhow::bail!("429 Too Many Requests from api.stripe.com"),
            s if s >= 500 => anyhow::bail!("Server error {} from api.stripe.com", s),
            _ => Ok(false),
        }
    }
}

impl Default for StripeValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for StripeValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::StripeApiKey | SecretType::StripeRestrictedKey => {
                self.validate_key(&secret.value).await
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::StripeApiKey | SecretType::StripeRestrictedKey
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = StripeValidator::new();
        assert!(validator.supports(&SecretType::StripeApiKey));
        assert!(validator.supports(&SecretType::StripeRestrictedKey));
        assert!(!validator.supports(&SecretType::GitHubPat));
    }
}
