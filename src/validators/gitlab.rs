use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::Client;

pub struct GitLabValidator {
    client: Client,
}

impl GitLabValidator {
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
            .get("https://gitlab.com/api/v4/user")
            .header("PRIVATE-TOKEN", token)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            429 => anyhow::bail!("429 Too Many Requests from gitlab.com"),
            s if s >= 500 => anyhow::bail!("Server error {} from gitlab.com", s),
            _ => Ok(false),
        }
    }
}

impl Default for GitLabValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for GitLabValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::GitLabPat | SecretType::GitLabToken => {
                self.validate_token(&secret.value).await
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(secret_type, SecretType::GitLabPat | SecretType::GitLabToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let v = GitLabValidator::new();
        assert!(v.supports(&SecretType::GitLabPat));
        assert!(v.supports(&SecretType::GitLabToken));
        assert!(!v.supports(&SecretType::GitHubPat));
    }
}
