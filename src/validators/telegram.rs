use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct TelegramValidator {
    client: Client,
}

impl TelegramValidator {
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
        let url = format!("https://api.telegram.org/bot{}/getMe", token);
        let response = self.client.get(&url).send().await?;

        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("429 Too Many Requests from api.telegram.org");
        }
        if status.is_server_error() {
            anyhow::bail!("Server error {} from api.telegram.org", status.as_u16());
        }

        if status.is_success() {
            let body: serde_json::Value = response.json().await?;
            Ok(body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false))
        } else {
            Ok(false)
        }
    }
}

impl Default for TelegramValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for TelegramValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::TelegramBotToken => self.validate_bot_token(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::TelegramBotToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = TelegramValidator::new();
        assert!(validator.supports(&SecretType::TelegramBotToken));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
