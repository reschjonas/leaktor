use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Serialize for SecretType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "AWS Access Key" => Ok(SecretType::AwsAccessKey),
            "AWS Secret Key" => Ok(SecretType::AwsSecretKey),
            "AWS Session Token" => Ok(SecretType::AwsSessionToken),
            "AWS MWS Key" => Ok(SecretType::AwsMwsKey),
            "GCP API Key" => Ok(SecretType::GcpApiKey),
            "GCP Service Account" => Ok(SecretType::GcpServiceAccount),
            "Azure Storage Key" => Ok(SecretType::AzureStorageKey),
            "Azure Connection String" => Ok(SecretType::AzureConnectionString),
            "Azure Client Secret" => Ok(SecretType::AzureClientSecret),
            "GitHub Token" => Ok(SecretType::GitHubToken),
            "GitHub Personal Access Token" => Ok(SecretType::GitHubPat),
            "GitHub OAuth Token" => Ok(SecretType::GitHubOauth),
            "GitLab Token" => Ok(SecretType::GitLabToken),
            "GitLab Personal Access Token" => Ok(SecretType::GitLabPat),
            "Bitbucket Token" => Ok(SecretType::BitbucketToken),
            "Stripe API Key" => Ok(SecretType::StripeApiKey),
            "Stripe Restricted Key" => Ok(SecretType::StripeRestrictedKey),
            "SendGrid API Key" => Ok(SecretType::SendGridApiKey),
            "Twilio API Key" => Ok(SecretType::TwilioApiKey),
            "Slack Token" => Ok(SecretType::SlackToken),
            "Slack Webhook" => Ok(SecretType::SlackWebhook),
            "Mailgun API Key" => Ok(SecretType::MailgunApiKey),
            "Mailchimp API Key" => Ok(SecretType::MailchimpApiKey),
            "Heroku API Key" => Ok(SecretType::HerokuApiKey),
            "Database URL" => Ok(SecretType::DatabaseUrl),
            "MongoDB Connection String" => Ok(SecretType::MongoDbConnectionString),
            "PostgreSQL Connection String" => Ok(SecretType::PostgresConnectionString),
            "MySQL Connection String" => Ok(SecretType::MysqlConnectionString),
            "Redis Connection String" => Ok(SecretType::RedisConnectionString),
            "RSA Private Key" => Ok(SecretType::RsaPrivateKey),
            "SSH Private Key" => Ok(SecretType::SshPrivateKey),
            "PGP Private Key" => Ok(SecretType::PgpPrivateKey),
            "EC Private Key" => Ok(SecretType::EcPrivateKey),
            "OpenSSL Private Key" => Ok(SecretType::OpensslPrivateKey),
            "JWT Token" => Ok(SecretType::JwtToken),
            "OAuth Token" => Ok(SecretType::OAuthToken),
            "Generic API Key" => Ok(SecretType::GenericApiKey),
            "Generic Secret" => Ok(SecretType::GenericSecret),
            "Password in URL" => Ok(SecretType::PasswordInUrl),
            "Generic Credential" => Ok(SecretType::GenericCredential),
            "High Entropy String" => Ok(SecretType::HighEntropyString),
            custom => Ok(SecretType::Custom(custom.to_string())),
        }
    }
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
