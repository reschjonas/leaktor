use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct DiscordValidator {
    client: Client,
}

impl DiscordValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }

    async fn validate_bot_token(&self, token: &str) -> Result<bool> {
        let response = self
            .client
            .get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bot {}", token))
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from discord.com")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from discord.com", status.as_u16())
            }
            _ => Ok(false),
        }
    }

    async fn validate_webhook(&self, url: &str) -> Result<bool> {
        let response = self.client.get(url).send().await?;

        match response.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from discord.com webhook")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from discord.com webhook", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for DiscordValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for DiscordValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::DiscordBotToken => self.validate_bot_token(&secret.value).await,
            SecretType::DiscordWebhook => self.validate_webhook(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::DiscordBotToken | SecretType::DiscordWebhook
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = DiscordValidator::new();
        assert!(validator.supports(&SecretType::DiscordBotToken));
        assert!(validator.supports(&SecretType::DiscordWebhook));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
