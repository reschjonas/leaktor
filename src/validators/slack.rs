use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct SlackValidator {
    client: Client,
}

impl SlackValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap(),
        }
    }

    /// Validate Slack token by calling auth.test
    async fn validate_token(&self, token: &str) -> Result<bool> {
        let response = self
            .client
            .post("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;

        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("429 Too Many Requests from slack.com");
        }
        if status.is_server_error() {
            anyhow::bail!("Server error {} from slack.com", status.as_u16());
        }

        if status.is_success() {
            let body: serde_json::Value = response.json().await?;
            Ok(body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false))
        } else {
            Ok(false)
        }
    }

    /// Validate Slack webhook by sending a dry-run style check
    async fn validate_webhook(&self, url: &str) -> Result<bool> {
        // We just check if the URL responds - we don't actually post a message
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({}))
            .send()
            .await?;

        // Slack webhooks return 400 for empty payloads but 404/410 for invalid URLs
        // A 400 means the webhook exists but payload was bad = valid webhook
        let status = response.status().as_u16();
        if status == 429 {
            anyhow::bail!("429 Too Many Requests from slack.com webhook");
        }
        if status >= 500 {
            anyhow::bail!("Server error {} from slack.com webhook", status);
        }
        Ok(status == 400 || status == 200)
    }
}

impl Default for SlackValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for SlackValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::SlackToken => self.validate_token(&secret.value).await,
            SecretType::SlackWebhook => self.validate_webhook(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::SlackToken | SecretType::SlackWebhook
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = SlackValidator::new();
        assert!(validator.supports(&SecretType::SlackToken));
        assert!(validator.supports(&SecretType::SlackWebhook));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
