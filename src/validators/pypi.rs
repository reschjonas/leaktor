use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct PyPiValidator {
    client: Client,
}

impl PyPiValidator {
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
        // PyPI tokens can be validated by checking the upload endpoint
        let response = self
            .client
            .get("https://upload.pypi.org/legacy/")
            .basic_auth("__token__", Some(token))
            .send()
            .await?;

        // A valid token will get a different response than an invalid one
        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            // PyPI returns 405 Method Not Allowed for GET with valid auth
            StatusCode::METHOD_NOT_ALLOWED => Ok(true),
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::bail!("429 Too Many Requests from upload.pypi.org")
            }
            status if status.is_server_error() => {
                anyhow::bail!("Server error {} from upload.pypi.org", status.as_u16())
            }
            _ => Ok(false),
        }
    }
}

impl Default for PyPiValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for PyPiValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::PyPiApiToken => self.validate_token(&secret.value).await,
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::PyPiApiToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let validator = PyPiValidator::new();
        assert!(validator.supports(&SecretType::PyPiApiToken));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
    }
}
