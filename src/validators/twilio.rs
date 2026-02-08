use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct TwilioValidator {
    client: Client,
}

impl TwilioValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_key(&self, api_key: &str) -> Result<bool> {
        // Twilio API keys (SKxxxx) can be validated by calling the Twilio API
        // with the key as the username and empty password
        let response = self
            .client
            .get("https://api.twilio.com/2010-04-01/Accounts.json")
            .basic_auth(api_key, Some(""))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from api.twilio.com")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from api.twilio.com", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for TwilioValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for TwilioValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::TwilioApiKey => self.validate_key(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::TwilioApiKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = TwilioValidator::new();
        assert!(validator.supports(&SecretType::TwilioApiKey));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
