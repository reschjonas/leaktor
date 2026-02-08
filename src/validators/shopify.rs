use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct ShopifyValidator {
    client: Client,
}

impl ShopifyValidator {
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
        // Shopify admin API tokens (shpat_) can be validated by calling the shop API
        // We use a non-existent shop to check if the token format is valid
        // A real validation would need the shop domain
        let response = self
            .client
            .get("https://leaktor-probe.myshopify.com/admin/api/2024-01/shop.json")
            .header("X-Shopify-Access-Token", token)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            // 404 means shop doesn't exist but token format could be valid
            StatusCode::NOT_FOUND => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from myshopify.com")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from myshopify.com", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for ShopifyValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for ShopifyValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::ShopifyApiKey | SecretType::ShopifySharedSecret => {
                self.validate_token(&secret.value).await
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::ShopifyApiKey | SecretType::ShopifySharedSecret
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = ShopifyValidator::new();
        assert!(validator.supports(&SecretType::ShopifyApiKey));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
