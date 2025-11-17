use serde::{Deserialize, Serialize};

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretType {
    // Cloud Provider Credentials
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    AwsMwsKey,
    GcpApiKey,
    GcpServiceAccount,
    AzureStorageKey,
    AzureConnectionString,
    AzureClientSecret,

    // Version Control
    GitHubToken,
    GitHubPat,
    GitHubOauth,
    GitLabToken,
    GitLabPat,
    BitbucketToken,

    // API Keys
    StripeApiKey,
    StripeRestrictedKey,
    SendGridApiKey,
    TwilioApiKey,
    SlackToken,
    SlackWebhook,
    MailgunApiKey,
    MailchimpApiKey,
    HerokuApiKey,

    // Database
    DatabaseUrl,
    MongoDbConnectionString,
    PostgresConnectionString,
    MysqlConnectionString,
    RedisConnectionString,

    // Private Keys
    RsaPrivateKey,
    SshPrivateKey,
    PgpPrivateKey,
    EcPrivateKey,
    OpensslPrivateKey,

    // Tokens
    JwtToken,
    OAuthToken,
    GenericApiKey,
    GenericSecret,

    // Other
    PasswordInUrl,
    GenericCredential,
    HighEntropyString,

    // Custom
    Custom(String),
}

impl SecretType {
    pub fn as_str(&self) -> &str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::AwsSessionToken => "AWS Session Token",
            SecretType::AwsMwsKey => "AWS MWS Key",
            SecretType::GcpApiKey => "GCP API Key",
            SecretType::GcpServiceAccount => "GCP Service Account",
            SecretType::AzureStorageKey => "Azure Storage Key",
            SecretType::AzureConnectionString => "Azure Connection String",
            SecretType::AzureClientSecret => "Azure Client Secret",
            SecretType::GitHubToken => "GitHub Token",
            SecretType::GitHubPat => "GitHub Personal Access Token",
            SecretType::GitHubOauth => "GitHub OAuth Token",
            SecretType::GitLabToken => "GitLab Token",
            SecretType::GitLabPat => "GitLab Personal Access Token",
            SecretType::BitbucketToken => "Bitbucket Token",
            SecretType::StripeApiKey => "Stripe API Key",
            SecretType::StripeRestrictedKey => "Stripe Restricted Key",
            SecretType::SendGridApiKey => "SendGrid API Key",
            SecretType::TwilioApiKey => "Twilio API Key",
            SecretType::SlackToken => "Slack Token",
            SecretType::SlackWebhook => "Slack Webhook",
            SecretType::MailgunApiKey => "Mailgun API Key",
            SecretType::MailchimpApiKey => "Mailchimp API Key",
            SecretType::HerokuApiKey => "Heroku API Key",
            SecretType::DatabaseUrl => "Database URL",
            SecretType::MongoDbConnectionString => "MongoDB Connection String",
            SecretType::PostgresConnectionString => "PostgreSQL Connection String",
            SecretType::MysqlConnectionString => "MySQL Connection String",
            SecretType::RedisConnectionString => "Redis Connection String",
            SecretType::RsaPrivateKey => "RSA Private Key",
            SecretType::SshPrivateKey => "SSH Private Key",
            SecretType::PgpPrivateKey => "PGP Private Key",
            SecretType::EcPrivateKey => "EC Private Key",
            SecretType::OpensslPrivateKey => "OpenSSL Private Key",
            SecretType::JwtToken => "JWT Token",
            SecretType::OAuthToken => "OAuth Token",
            SecretType::GenericApiKey => "Generic API Key",
            SecretType::GenericSecret => "Generic Secret",
            SecretType::PasswordInUrl => "Password in URL",
            SecretType::GenericCredential => "Generic Credential",
            SecretType::HighEntropyString => "High Entropy String",
            SecretType::Custom(name) => name,
        }
    }
}

/// Severity level of a detected secret
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// Represents a detected secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub secret_type: SecretType,
    pub value: String,
    pub redacted_value: String,
    pub entropy: f64,
    pub severity: Severity,
    pub confidence: f64,
    pub validated: Option<bool>,
}

impl Secret {
    pub fn new(
        secret_type: SecretType,
        value: String,
        entropy: f64,
        severity: Severity,
        confidence: f64,
    ) -> Self {
        let redacted_value = Self::redact(&value);
        Self {
            secret_type,
            value,
            redacted_value,
            entropy,
            severity,
            confidence,
            validated: None,
        }
    }

    fn redact(value: &str) -> String {
        if value.len() <= 8 {
            return "*".repeat(value.len());
        }
        let prefix_len = 4.min(value.len() / 4);
        let suffix_len = 4.min(value.len() / 4);
        let prefix = &value[..prefix_len];
        let suffix = &value[value.len() - suffix_len..];
        format!("{}...{}", prefix, suffix)
    }
}
