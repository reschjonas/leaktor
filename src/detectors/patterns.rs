use crate::models::{Secret, SecretType, Severity};
use lazy_static::lazy_static;
use regex::Regex;

/// Pattern definition for detecting secrets
#[derive(Debug, Clone)]
pub struct Pattern {
    pub name: SecretType,
    pub regex: Regex,
    pub severity: Severity,
    pub confidence_base: f64,
}

lazy_static! {
    /// Compiled regex patterns for secret detection
    pub static ref PATTERNS: Vec<Pattern> = vec![
        // AWS Credentials
        Pattern {
            name: SecretType::AwsAccessKey,
            regex: Regex::new(r"(?i)(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AwsSecretKey,
            regex: Regex::new(r#"(?i)(?:aws.{0,20}(?:secret|access.?key)|aws_secret_access_key)\s*[=:]\s*['"]?([0-9a-zA-Z/+]{40})['"]?"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::AwsSessionToken,
            regex: Regex::new(r#"(?i)aws.?session.?token.{0,20}['"][A-Za-z0-9/+=]{100,}['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AwsMwsKey,
            regex: Regex::new(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },

        // GCP Credentials
        Pattern {
            name: SecretType::GcpApiKey,
            regex: Regex::new(r"AIza[0-9A-Za-z\\-_]{35}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::GcpServiceAccount,
            regex: Regex::new(r#""type":\s*"service_account""#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },

        // Azure Credentials
        Pattern {
            name: SecretType::AzureStorageKey,
            regex: Regex::new(r"(?i)DefaultEndpointsProtocol=https;AccountName=.+?;AccountKey=[A-Za-z0-9+/=]{88};").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AzureConnectionString,
            regex: Regex::new(r"(?i)(?:Server|Data Source)=.+?;(?:User ID|UID)=.+?;(?:Password|PWD)=.+?;").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // GitHub Tokens
        Pattern {
            name: SecretType::GitHubPat,
            regex: Regex::new(r"ghp_[0-9a-zA-Z]{30,40}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::GitHubOauth,
            regex: Regex::new(r"gho_[0-9a-zA-Z]{30,40}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::GitHubToken,
            regex: Regex::new(r#"(?i)github.{0,20}['"][0-9a-zA-Z]{30,45}['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.80,
        },

        // GitLab Tokens
        Pattern {
            name: SecretType::GitLabPat,
            regex: Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },

        // Stripe Keys
        Pattern {
            name: SecretType::StripeApiKey,
            regex: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::StripeRestrictedKey,
            regex: Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },

        // SendGrid
        Pattern {
            name: SecretType::SendGridApiKey,
            regex: Regex::new(r"SG\.[0-9A-Za-z\-_]{20,}\.[0-9A-Za-z\-_]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },

        // Twilio
        Pattern {
            name: SecretType::TwilioApiKey,
            regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // Slack
        Pattern {
            name: SecretType::SlackToken,
            regex: Regex::new(r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{20,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::SlackWebhook,
            regex: Regex::new(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]{24}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },

        // Heroku
        Pattern {
            name: SecretType::HerokuApiKey,
            regex: Regex::new(r"(?i)heroku.{0,20}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },

        // Mailgun
        Pattern {
            name: SecretType::MailgunApiKey,
            regex: Regex::new(r#"(?i)mailgun.{0,20}['"]([0-9a-f]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // Mailchimp
        Pattern {
            name: SecretType::MailchimpApiKey,
            regex: Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // Private Keys
        Pattern {
            name: SecretType::RsaPrivateKey,
            regex: Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::SshPrivateKey,
            regex: Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::PgpPrivateKey,
            regex: Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::EcPrivateKey,
            regex: Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },

        // Database Connection Strings
        Pattern {
            name: SecretType::MongoDbConnectionString,
            regex: Regex::new(r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::PostgresConnectionString,
            regex: Regex::new(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::MysqlConnectionString,
            regex: Regex::new(r"mysql://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::RedisConnectionString,
            regex: Regex::new(r"redis(?:s)?://.*@.+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // Password in URL
        Pattern {
            name: SecretType::PasswordInUrl,
            regex: Regex::new(r"[a-zA-Z]{3,10}://[^:]+:[^@]{8,}@[^/]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },

        // JWT Tokens
        Pattern {
            name: SecretType::JwtToken,
            regex: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.75,
        },

        // ══════════════════════════════════════════════
        // AI/ML Platform Keys
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::OpenAiApiKey,
            regex: Regex::new(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // OpenAI project keys (newer format)
        Pattern {
            name: SecretType::OpenAiApiKey,
            regex: Regex::new(r"sk-proj-[A-Za-z0-9\-_]{40,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.97,
        },
        // OpenAI service keys
        Pattern {
            name: SecretType::OpenAiApiKey,
            regex: Regex::new(r"sk-svcacct-[A-Za-z0-9\-_]{40,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::AnthropicApiKey,
            regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9\-_]{90,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::CohereApiKey,
            regex: Regex::new(r#"(?i)cohere.{0,20}['"]([a-zA-Z0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::HuggingFaceToken,
            regex: Regex::new(r"hf_[A-Za-z0-9]{34,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::ReplicateApiKey,
            regex: Regex::new(r"r8_[A-Za-z0-9]{36,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },

        // ══════════════════════════════════════════════
        // Additional Cloud/SaaS
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::DatadogApiKey,
            regex: Regex::new(r#"(?i)datadog.{0,20}['"]([0-9a-f]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::DatadogAppKey,
            regex: Regex::new(r#"(?i)dd.?app.?key.{0,20}['"]([0-9a-f]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CloudflareApiToken,
            regex: Regex::new(r#"(?i)cloudflare.{0,20}['"]([A-Za-z0-9_-]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::DigitalOceanToken,
            regex: Regex::new(r"dop_v1_[a-f0-9]{64}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::DigitalOceanSpacesKey,
            regex: Regex::new(r"DO[0-9A-Z]{18}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::VercelToken,
            regex: Regex::new(r#"(?i)vercel.{0,20}['"]([A-Za-z0-9]{24})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::LinearApiKey,
            regex: Regex::new(r"lin_api_[A-Za-z0-9]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::NotionApiKey,
            regex: Regex::new(r"(?:ntn_|secret_)[A-Za-z0-9]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::AirtableApiKey,
            regex: Regex::new(r"pat[A-Za-z0-9]{14}\.[a-f0-9]{64}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::PlanetScaleToken,
            regex: Regex::new(r"pscale_tkn_[A-Za-z0-9_]{30,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },

        // ══════════════════════════════════════════════
        // Package Registry Tokens
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::NpmToken,
            regex: Regex::new(r"npm_[A-Za-z0-9]{36,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::PyPiApiToken,
            regex: Regex::new(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::NuGetApiKey,
            regex: Regex::new(r"oy2[A-Za-z0-9]{43}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::RubyGemsApiKey,
            regex: Regex::new(r"rubygems_[a-f0-9]{48}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },

        // ══════════════════════════════════════════════
        // Communication Platforms
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::DiscordBotToken,
            regex: Regex::new(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::DiscordWebhook,
            regex: Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::TelegramBotToken,
            regex: Regex::new(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // ══════════════════════════════════════════════
        // E-Commerce / Payment
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::ShopifyApiKey,
            regex: Regex::new(r"shpat_[a-fA-F0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::ShopifySharedSecret,
            regex: Regex::new(r"shpss_[a-fA-F0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::SquareAccessToken,
            regex: Regex::new(r"sq0atp-[0-9A-Za-z\-_]{22}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },

        // ══════════════════════════════════════════════
        // Authentication / Identity
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::OktaApiToken,
            regex: Regex::new(r#"(?i)okta.{0,20}['"]00[A-Za-z0-9_-]{40}['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        // Firebase API Key intentionally omitted - same regex as GCP API Key (AIza...).
        // GCP API Key pattern above already detects Firebase keys.
        // To avoid double-counting, Firebase is handled as an alias.

        // ══════════════════════════════════════════════
        // Infrastructure / DevOps
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::DockerHubToken,
            regex: Regex::new(r"dckr_pat_[A-Za-z0-9_-]{27,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::HashiCorpVaultToken,
            regex: Regex::new(r"hvs\.[A-Za-z0-9_-]{24,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::NewRelicApiKey,
            regex: Regex::new(r"NRAK-[A-Z0-9]{27}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::SentryDsn,
            regex: Regex::new(r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AlgoliaApiKey,
            regex: Regex::new(r#"(?i)algolia.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::GrafanaApiKey,
            regex: Regex::new(r"glc_[A-Za-z0-9+/]{32,}={0,2}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::GrafanaApiKey,
            regex: Regex::new(r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },

        // ══════════════════════════════════════════════
        // CI/CD Platforms
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::CircleCiToken,
            regex: Regex::new(r#"(?i)circle.?ci.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // ══════════════════════════════════════════════
        // Additional Services (new)
        // ══════════════════════════════════════════════

        // PagerDuty
        Pattern {
            name: SecretType::PagerDutyApiKey,
            regex: Regex::new(r#"(?i)pagerduty.{0,20}['"]([A-Za-z0-9+/=]{20})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // Jira / Atlassian API token
        Pattern {
            name: SecretType::JiraApiToken,
            regex: Regex::new(r#"(?i)(?:jira|atlassian|confluence).{0,20}['"]([A-Za-z0-9]{24,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Bitbucket App Password (base64-like 18+ chars with context)
        Pattern {
            name: SecretType::BitbucketAppPassword,
            regex: Regex::new(r#"(?i)bitbucket.{0,20}['"]([A-Za-z0-9]{18,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Terraform Cloud
        Pattern {
            name: SecretType::TerraformCloudToken,
            regex: Regex::new(r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Pulumi
        Pattern {
            name: SecretType::PulumiAccessToken,
            regex: Regex::new(r"pul-[a-f0-9]{40}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Fastly
        Pattern {
            name: SecretType::FastlyApiToken,
            regex: Regex::new(r#"(?i)fastly.{0,20}['"]([A-Za-z0-9_-]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // LaunchDarkly
        Pattern {
            name: SecretType::LaunchDarklyKey,
            regex: Regex::new(r"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Mapbox
        Pattern {
            name: SecretType::MapboxToken,
            regex: Regex::new(r"sk\.eyJ1[A-Za-z0-9_-]{50,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::MapboxToken,
            regex: Regex::new(r"pk\.eyJ1[A-Za-z0-9_-]{50,}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.90,
        },
        // Doppler
        Pattern {
            name: SecretType::DopplerToken,
            regex: Regex::new(r"dp\.(?:ct|st|sa|scim)\.[a-zA-Z0-9]{40,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Netlify PAT
        Pattern {
            name: SecretType::NetlifyPat,
            regex: Regex::new(r"nfp_[A-Za-z0-9]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Fly.io
        Pattern {
            name: SecretType::FlyAccessToken,
            regex: Regex::new(r"FlyV1\s+fm2_[A-Za-z0-9_-]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Confluent Cloud
        Pattern {
            name: SecretType::ConfluentApiKey,
            regex: Regex::new(r#"(?i)confluent.{0,20}['"]([A-Za-z0-9]{16})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Databricks
        Pattern {
            name: SecretType::DatabricksToken,
            regex: Regex::new(r"dapi[a-f0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        // Sumo Logic
        Pattern {
            name: SecretType::SumoLogicKey,
            regex: Regex::new(r#"(?i)sumologic.{0,20}['"]([A-Za-z0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // PostHog
        Pattern {
            name: SecretType::PosthogApiKey,
            regex: Regex::new(r"phx_[A-Za-z0-9]{40,}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::PosthogApiKey,
            regex: Regex::new(r"phc_[A-Za-z0-9]{40,}").unwrap(),
            severity: Severity::Low,
            confidence_base: 0.85,
        },
        // Segment
        Pattern {
            name: SecretType::SegmentWriteKey,
            regex: Regex::new(r#"(?i)segment.{0,20}['"]([A-Za-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        // Plaid
        Pattern {
            name: SecretType::PlaidClientSecret,
            regex: Regex::new(r#"(?i)plaid.{0,20}['"]([a-f0-9]{30})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },

        // ══════════════════════════════════════════════
        // Tier 3 Expansion - Additional Services
        // ══════════════════════════════════════════════

        // 1Password
        Pattern {
            name: SecretType::OnePasswordSecretKey,
            regex: Regex::new(r"A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::OnePasswordServiceToken,
            regex: Regex::new(r"ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Adobe
        Pattern {
            name: SecretType::AdobeClientSecret,
            regex: Regex::new(r"(?i)p8e-[a-z0-9]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Age
        Pattern {
            name: SecretType::AgeSecretKey,
            regex: Regex::new(r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        // Alibaba
        Pattern {
            name: SecretType::AlibabaAccessKey,
            regex: Regex::new(r"LTAI[a-zA-Z0-9]{20}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AlibabaSecretKey,
            regex: Regex::new(r#"(?i)alibaba.{0,20}['"]([a-z0-9]{30})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        // Artifactory
        Pattern {
            name: SecretType::ArtifactoryApiKey,
            regex: Regex::new(r"AKCp[A-Za-z0-9]{69}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::ArtifactoryReferenceToken,
            regex: Regex::new(r"cmVmd[A-Za-z0-9]{59}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        // Asana
        Pattern {
            name: SecretType::AsanaSecret,
            regex: Regex::new(r#"(?i)asana.{0,20}['"]([a-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Azure AD Client Secret
        Pattern {
            name: SecretType::AzureAdClientSecret,
            regex: Regex::new(r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        // Clojars
        Pattern {
            name: SecretType::ClojarsApiToken,
            regex: Regex::new(r"(?i)CLOJARS_[a-z0-9]{60}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        // Codecov
        Pattern {
            name: SecretType::CodecovAccessToken,
            regex: Regex::new(r#"(?i)codecov.{0,20}['"]([a-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Coinbase
        Pattern {
            name: SecretType::CoinbaseAccessToken,
            regex: Regex::new(r#"(?i)coinbase.{0,20}['"]([a-z0-9_\-]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Contentful
        Pattern {
            name: SecretType::ContentfulApiToken,
            regex: Regex::new(r#"(?i)contentful.{0,20}['"]([a-z0-9=_\-]{43})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // Dropbox
        Pattern {
            name: SecretType::DropboxApiToken,
            regex: Regex::new(r#"(?i)dropbox.{0,20}['"]([a-z0-9]{15})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DropboxLongLivedToken,
            regex: Regex::new(r#"(?i)dropbox.{0,20}['"]([a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::DropboxShortLivedToken,
            regex: Regex::new(r"sl\.[a-zA-Z0-9\-=_]{135,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Duffel
        Pattern {
            name: SecretType::DuffelApiToken,
            regex: Regex::new(r"duffel_(?:test|live)_[a-zA-Z0-9_\-=]{43}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        // Dynatrace
        Pattern {
            name: SecretType::DynatraceApiToken,
            regex: Regex::new(r"dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // EasyPost
        Pattern {
            name: SecretType::EasyPostApiToken,
            regex: Regex::new(r"EZAK[a-zA-Z0-9]{54}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::EasyPostTestApiToken,
            regex: Regex::new(r"EZTK[a-zA-Z0-9]{54}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.90,
        },
        // Facebook
        Pattern {
            name: SecretType::FacebookAccessToken,
            regex: Regex::new(r"EAA[MC][a-zA-Z0-9]{100,}").unwrap(),  // no capture group - full match is the token
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::FacebookPageAccessToken,
            regex: Regex::new(r#"(?i)facebook.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Flutterwave
        Pattern {
            name: SecretType::FlutterwaveSecretKey,
            regex: Regex::new(r"FLWSECK_TEST-[a-hA-H0-9]{12}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Frame.io
        Pattern {
            name: SecretType::FrameIoApiToken,
            regex: Regex::new(r"fio-u-[a-zA-Z0-9\-_=]{64}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // FreshBooks
        Pattern {
            name: SecretType::FreshbooksAccessToken,
            regex: Regex::new(r#"(?i)freshbooks.{0,20}['"]([a-z0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // GitHub App Token & Fine-Grained PAT
        Pattern {
            name: SecretType::GitHubAppToken,
            regex: Regex::new(r"ghs_[0-9a-zA-Z]{30,40}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::GitHubFineGrainedPat,
            regex: Regex::new(r"github_pat_[0-9a-zA-Z_]{82}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        // Google OAuth
        Pattern {
            name: SecretType::GoogleOAuthClientSecret,
            regex: Regex::new(r"GOCSPX-[a-zA-Z0-9_\-]{28}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Intercom
        Pattern {
            name: SecretType::IntercomAccessToken,
            regex: Regex::new(r#"(?i)intercom.{0,20}['"]([a-z0-9=_\-]{60})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Kraken
        Pattern {
            name: SecretType::KrakenAccessToken,
            regex: Regex::new(r#"(?i)kraken.{0,20}['"]([a-z0-9/+=]{80,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Lob
        Pattern {
            name: SecretType::LobApiKey,
            regex: Regex::new(r#"(?i)lob.{0,20}['"]((live|test)_[a-f0-9]{35})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // MessageBird
        Pattern {
            name: SecretType::MessageBirdApiKey,
            regex: Regex::new(r#"(?i)messagebird.{0,20}['"]([a-z0-9]{25})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // New Relic Browser
        Pattern {
            name: SecretType::NewRelicBrowserApiKey,
            regex: Regex::new(r"NRJS-[a-f0-9]{19}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        // NY Times
        Pattern {
            name: SecretType::NytimesAccessToken,
            regex: Regex::new(r#"(?i)nytimes.{0,20}['"]([a-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Postman
        Pattern {
            name: SecretType::PostmanApiToken,
            regex: Regex::new(r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        // Private Keys (PKCS8, DSA)
        Pattern {
            name: SecretType::Pkcs8PrivateKey,
            regex: Regex::new(r"-----BEGIN PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::DsaPrivateKey,
            regex: Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        // RapidAPI
        Pattern {
            name: SecretType::RapidApiKey,
            regex: Regex::new(r#"(?i)rapid.{0,20}['"]([a-z0-9]{50})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // ReadMe
        Pattern {
            name: SecretType::ReadmeApiKey,
            regex: Regex::new(r"rdme_[a-z0-9]{70}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Scalingo
        Pattern {
            name: SecretType::ScalingoApiToken,
            regex: Regex::new(r"tk-us-[a-zA-Z0-9\-_]{48}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Sourcegraph
        Pattern {
            name: SecretType::SourcegraphAccessToken,
            regex: Regex::new(r"sgp_[a-fA-F0-9]{40,64}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Tailscale
        Pattern {
            name: SecretType::TailscaleApiKey,
            regex: Regex::new(r"tskey-[a-zA-Z0-9\-]{20,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Tencent
        Pattern {
            name: SecretType::TencentSecretId,
            regex: Regex::new(r"AKID[a-zA-Z0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        // Trello
        Pattern {
            name: SecretType::TrelloAccessToken,
            regex: Regex::new(r#"(?i)trello.{0,20}['"]([a-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Twitch
        Pattern {
            name: SecretType::TwitchApiToken,
            regex: Regex::new(r#"(?i)twitch.{0,20}['"]([a-z0-9]{30})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Twitter
        Pattern {
            name: SecretType::TwitterApiKey,
            regex: Regex::new(r#"(?i)twitter.{0,20}['"]([a-zA-Z0-9]{25})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::TwitterAccessToken,
            regex: Regex::new(r#"(?i)twitter.{0,20}['"]([0-9]+-[a-zA-Z0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // Typeform
        Pattern {
            name: SecretType::TypeformApiToken,
            regex: Regex::new(r"tfp_[a-z0-9_\-]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Vault Batch Token
        Pattern {
            name: SecretType::VaultBatchToken,
            regex: Regex::new(r"hvb\.[A-Za-z0-9_\-]{130,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Yandex
        Pattern {
            name: SecretType::YandexApiKey,
            regex: Regex::new(r"AQVN[a-zA-Z0-9_\-]{35,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::YandexAwsAccessToken,
            regex: Regex::new(r"YC[a-zA-Z0-9_\-]{38}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        // Zendesk
        Pattern {
            name: SecretType::ZendeskSecretKey,
            regex: Regex::new(r#"(?i)zendesk.{0,20}['"]([a-z0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Beamer
        Pattern {
            name: SecretType::BeamerApiToken,
            regex: Regex::new(r#"(?i)beamer.{0,20}['"]b_[a-z0-9=_\-]{44}['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        // Bitwarden
        Pattern {
            name: SecretType::BitwardenApiKey,
            regex: Regex::new(r#"(?i)bitwarden.{0,20}['"]([a-z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // PlanetScale Password
        Pattern {
            name: SecretType::PlanetScalePassword,
            regex: Regex::new(r"pscale_pw_[A-Za-z0-9_]{30,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        // Infracost
        Pattern {
            name: SecretType::InfracostApiKey,
            regex: Regex::new(r"ico-[a-zA-Z0-9]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Prefect
        Pattern {
            name: SecretType::PrefectApiToken,
            regex: Regex::new(r"pnu_[a-z0-9]{36}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        // Railway
        Pattern {
            name: SecretType::RailwayApiToken,
            regex: Regex::new(r#"(?i)railway.{0,20}['"]([a-f0-9]{36})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Neon
        Pattern {
            name: SecretType::NeonApiKey,
            regex: Regex::new(r#"(?i)neon.{0,20}['"]([a-z0-9]{60,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        // Turborepo
        Pattern {
            name: SecretType::TurborepoAccessToken,
            regex: Regex::new(r#"(?i)turbo.{0,20}['"]([a-zA-Z0-9]{36})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },

        // ══════════════════════════════════════════════
        // Prefix-based patterns (distinctive key formats)
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::AdafruitIoApiKey,
            regex: Regex::new(r"aio_[a-zA-Z0-9]{28}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AdyenApiKey,
            regex: Regex::new(r"AQE[a-z0-9]{5}\.[A-Za-z0-9_\-]{80,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AnthropicAdminApiKey,
            regex: Regex::new(r"sk-ant-admin[a-zA-Z0-9\-_]{20,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::AwsBedrockApiKey,
            regex: Regex::new(r#"(?i)bedrock.{0,20}(?:AKIA|ASIA)[A-Z0-9]{16}"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::AzureSasToken,
            regex: Regex::new(r"(?i)sig=[a-zA-Z0-9%/+=]{30,}&s[evptr]=[^&]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureDevOpsPat,
            regex: Regex::new(r#"(?i)(?:azure.?devops|ado|vsts).{0,20}['"]([a-z0-9]{52})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureContainerRegistryKey,
            regex: Regex::new(r#"(?i)(?:azurecr|\.azurecr\.io).{0,30}['"]([a-zA-Z0-9+/=]{52})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureCosmosDbKey,
            regex: Regex::new(r"AccountKey=[a-zA-Z0-9+/=]{86}==").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AzureFunctionKey,
            regex: Regex::new(r#"(?i)(?:function.?key|x-functions-key).{0,20}['"]([a-zA-Z0-9_\-/+=]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureSearchAdminKey,
            regex: Regex::new(r#"(?i)(?:search.?admin|cognitive.?search).{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureAppConfigKey,
            regex: Regex::new(r"Endpoint=https://[a-z0-9-]+\.azconfig\.io;Id=[^;]+;Secret=[a-zA-Z0-9+/=]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AzureBatchKey,
            regex: Regex::new(r#"(?i)(?:batch.?account).{0,20}['"]([a-zA-Z0-9+/=]{86}==)['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureOpenAiApiKey,
            regex: Regex::new(r#"(?i)(?:azure.?openai|aoai).{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureSearchQueryKey,
            regex: Regex::new(r#"(?i)(?:search.?query.?key).{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AzureApiManagementKey,
            regex: Regex::new(r#"(?i)(?:apim|api.?management).{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BigCommerceApiToken,
            regex: Regex::new(r#"(?i)bigcommerce.{0,20}['"]([a-z0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::BraintreeAccessToken,
            regex: Regex::new(r"access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::BuildKiteApiToken,
            regex: Regex::new(r"bkua_[a-f0-9]{40}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::CockroachDbConnectionString,
            regex: Regex::new(r"cockroachdb://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::DenoDeployToken,
            regex: Regex::new(r"ddp_[a-zA-Z0-9]{40}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::DigitalOceanOAuthToken,
            regex: Regex::new(r"doo_v1_[a-f0-9]{64}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::DigitalOceanRefreshToken,
            regex: Regex::new(r"dor_v1_[a-f0-9]{64}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::ElasticsearchConnectionString,
            regex: Regex::new(r"https?://[^:]+:[^@]+@[^/]*elastic[^/]*").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::EncryptedPrivateKey,
            regex: Regex::new(r"-----BEGIN ENCRYPTED PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::FaunaDbApiKey,
            regex: Regex::new(r"fnA[a-zA-Z0-9_\-]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::FigmaPat,
            regex: Regex::new(r"figd_[a-zA-Z0-9_\-]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::FirebaseApiKey,
            regex: Regex::new(r#"(?i)firebase.{0,20}AIza[0-9A-Za-z_\-]{35}"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::FlutterwavePublicKey,
            regex: Regex::new(r"FLWPUBK(?:_TEST)?-[a-zA-Z0-9]{32,}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::FlutterwaveEncryptionKey,
            regex: Regex::new(r"FLWSECK(?:_TEST)?-[a-zA-Z0-9]{32,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::FlyIoPersonalToken,
            regex: Regex::new(r"fo1_[a-zA-Z0-9_]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::FtpCredential,
            regex: Regex::new(r"ftp://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::GcpApplicationDefaultCredentials,
            regex: Regex::new(r#""client_email":\s*"[^"]+@[^"]*\.iam\.gserviceaccount\.com""#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::GitLabRunnerToken,
            regex: Regex::new(r"glrt-[A-Za-z0-9\-_]{20,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::GitLabProjectToken,
            regex: Regex::new(r#"(?i)(?:project|group).?token.{0,20}glpat-[A-Za-z0-9\-_]{20}"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::GoogleAiStudioKey,
            regex: Regex::new(r#"(?i)(?:gemini|google.?ai|ai.?studio).{0,20}AIza[0-9A-Za-z_\-]{35}"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::GoogleMapsApiKey,
            regex: Regex::new(r#"(?i)(?:maps|places|geocod).{0,20}AIza[0-9A-Za-z_\-]{35}"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::GroqApiKey,
            regex: Regex::new(r"gsk_[a-zA-Z0-9]{52,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::HarnessPat,
            regex: Regex::new(r"pat\.[a-zA-Z0-9_]{22}\.[a-f0-9]{24}\.[a-zA-Z0-9_]{20,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::MicrosoftTeamsWebhook,
            regex: Regex::new(r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9\-]+@[a-z0-9\-]+/IncomingWebhook/[a-z0-9]+/[a-z0-9\-]+").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::NewRelicInsightsQueryKey,
            regex: Regex::new(r"NRIQ-[A-Za-z0-9]{32}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::NewRelicLicenseKey,
            regex: Regex::new(r"[a-f0-9]{40}NRAL").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::NightfallApiKey,
            regex: Regex::new(r"NF-[a-zA-Z0-9]{32,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::OpensslPrivateKey,
            regex: Regex::new(r"-----BEGIN (?:ANY )?PRIVATE KEY-----").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::PaystackSecretKey,
            regex: Regex::new(r"sk_(?:live|test)_[a-zA-Z0-9]{40,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::PerplexityApiKey,
            regex: Regex::new(r"pplx-[a-f0-9]{48}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::PuttyPrivateKey,
            regex: Regex::new(r"PuTTY-User-Key-File-[0-9]+:").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.99,
        },
        Pattern {
            name: SecretType::RazorpayKeyId,
            regex: Regex::new(r"rzp_(?:live|test)_[a-zA-Z0-9]{14}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::RenderApiKey,
            regex: Regex::new(r"rnd_[a-zA-Z0-9]{32,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::ResendApiKey,
            regex: Regex::new(r"re_[a-zA-Z0-9_]{30,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::ShopifyAccessToken,
            regex: Regex::new(r"shpca_[a-fA-F0-9]{32}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::SlackAppToken,
            regex: Regex::new(r"xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::SlackConfigToken,
            regex: Regex::new(r"xoxe\.xox[bp]-1-[a-zA-Z0-9]+-[0-9]+-[a-zA-Z0-9]+").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::SonarQubeToken,
            regex: Regex::new(r"squ_[a-zA-Z0-9]{40}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::TelnyxApiKey,
            regex: Regex::new(r"KEY[a-zA-Z0-9_\-]{50,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::UpstashRedisToken,
            regex: Regex::new(r"AX[a-zA-Z0-9_\-]{60,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::DatabaseUrl,
            regex: Regex::new(r#"(?i)DATABASE_URL\s*=\s*['"]?(?:postgres|mysql|mongodb|cockroachdb)(?:ql)?://[^'"\s]+"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::FireworksAiApiKey,
            regex: Regex::new(r#"(?i)fireworks.{0,20}['"]fw_[a-zA-Z0-9]{40,}['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::DeepSeekApiKey,
            regex: Regex::new(r"sk-[a-f0-9]{48}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::MistralApiKey,
            regex: Regex::new(r#"(?i)mistral.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::StabilityAiApiKey,
            regex: Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.75,
        },
        Pattern {
            name: SecretType::TogetherAiApiKey,
            regex: Regex::new(r#"(?i)together.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::MailerSendApiKey,
            regex: Regex::new(r"mlsn\.[a-f0-9]{64}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::MandrillApiKey,
            regex: Regex::new(r#"(?i)mandrill.{0,20}['"]([a-zA-Z0-9_\-]{22})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::SnykApiToken,
            regex: Regex::new(r#"(?i)snyk.{0,20}['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::SplunkHecToken,
            regex: Regex::new(r#"(?i)splunk.{0,20}['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CocoaPodsToken,
            regex: Regex::new(r#"(?i)cocoapods.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ComposerApiToken,
            regex: Regex::new(r#"(?i)composer.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CratesIoApiToken,
            regex: Regex::new(r"cio[a-zA-Z0-9]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::HexPmApiKey,
            regex: Regex::new(r#"(?i)hex.{0,20}['"]([a-zA-Z0-9]{64,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CargoRegistryToken,
            regex: Regex::new(r#"(?i)cargo.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },

        // ══════════════════════════════════════════════
        // Context-based patterns (A)
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::AbstractApiKey,
            regex: Regex::new(r#"(?i)abstract.{0,20}api.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AbuseIpDbApiKey,
            regex: Regex::new(r#"(?i)abuseipdb.{0,20}['"]([a-f0-9]{80})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AbyssaleApiKey,
            regex: Regex::new(r#"(?i)abyssale.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AccuWeatherApiKey,
            regex: Regex::new(r#"(?i)accuweather.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::ActiveCampaignApiKey,
            regex: Regex::new(r#"(?i)activecampaign.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AdafruitApiKey,
            regex: Regex::new(r#"(?i)adafruit.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AdobeClientId,
            regex: Regex::new(r#"(?i)adobe.{0,20}client.?id.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AdyenClientKey,
            regex: Regex::new(r"(?:test|live)_[a-zA-Z0-9]{24,32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.70,
        },
        Pattern {
            name: SecretType::AdzunaApiKey,
            regex: Regex::new(r#"(?i)adzuna.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AeroWorkflowApiKey,
            regex: Regex::new(r#"(?i)aeroworkflow.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AgoraApiKey,
            regex: Regex::new(r#"(?i)agora.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AhaApiKey,
            regex: Regex::new(r#"(?i)aha.{0,20}api.{0,10}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::Ai21LabsApiKey,
            regex: Regex::new(r#"(?i)ai21.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AirVisualApiKey,
            regex: Regex::new(r#"(?i)(?:airvisual|iqair).{0,20}['"]([a-f0-9\-]{36,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AirbrakeProjectKey,
            regex: Regex::new(r#"(?i)airbrake.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AirbrakeUserKey,
            regex: Regex::new(r#"(?i)airbrake.{0,20}user.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AirshipApiKey,
            regex: Regex::new(r#"(?i)airship.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AirtableOAuthToken,
            regex: Regex::new(r#"(?i)airtable.{0,20}oauth.{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AivenApiToken,
            regex: Regex::new(r#"(?i)aiven.{0,20}['"]([a-zA-Z0-9+/]{200,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AkamaiApiKey,
            regex: Regex::new(r#"(?i)akamai.{0,20}['"]([a-zA-Z0-9_\-/=]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AlchemyApiKey,
            regex: Regex::new(r#"(?i)alchemy.{0,20}['"]([a-zA-Z0-9_\-]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AlconostApiKey,
            regex: Regex::new(r#"(?i)alconost.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AlegraApiKey,
            regex: Regex::new(r#"(?i)alegra.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AlethiaApiKey,
            regex: Regex::new(r#"(?i)alethia.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AlienVaultApiKey,
            regex: Regex::new(r#"(?i)(?:alienvault|otx).{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AllSportsApiKey,
            regex: Regex::new(r#"(?i)allsports.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AmadeusApiKey,
            regex: Regex::new(r#"(?i)amadeus.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AmbeeApiKey,
            regex: Regex::new(r#"(?i)ambee.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AmplitudeApiKey,
            regex: Regex::new(r#"(?i)amplitude.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AnkrApiKey,
            regex: Regex::new(r#"(?i)ankr.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AnypointApiKey,
            regex: Regex::new(r#"(?i)anypoint.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApactaApiKey,
            regex: Regex::new(r#"(?i)apacta.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::Api2CartApiKey,
            regex: Regex::new(r#"(?i)api2cart.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApiDeckApiKey,
            regex: Regex::new(r#"(?i)apideck.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApiFlashApiKey,
            regex: Regex::new(r#"(?i)apiflash.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApiLayerApiKey,
            regex: Regex::new(r#"(?i)apilayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApifonicaApiKey,
            regex: Regex::new(r#"(?i)apifonica.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApimaticApiKey,
            regex: Regex::new(r#"(?i)apimatic.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApimetricsApiKey,
            regex: Regex::new(r#"(?i)apimetrics.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApiTemplateApiKey,
            regex: Regex::new(r#"(?i)apitemplate.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApifyApiKey,
            regex: Regex::new(r"apify_api_[a-zA-Z0-9]{32,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::ApolloApiKey,
            regex: Regex::new(r#"(?i)apollo.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppDynamicsApiKey,
            regex: Regex::new(r#"(?i)appdynamics.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppFollowApiKey,
            regex: Regex::new(r#"(?i)appfollow.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppOpticsApiKey,
            regex: Regex::new(r#"(?i)appoptics.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppSynergyApiKey,
            regex: Regex::new(r#"(?i)appsynergy.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppVeyorApiToken,
            regex: Regex::new(r"v2\.[a-zA-Z0-9]{20,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppcuesApiKey,
            regex: Regex::new(r#"(?i)appcues.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AppointeddApiKey,
            regex: Regex::new(r#"(?i)appointedd.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ApptivoApiKey,
            regex: Regex::new(r#"(?i)apptivo.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ArtsyApiKey,
            regex: Regex::new(r#"(?i)artsy.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AsanaClientId,
            regex: Regex::new(r#"(?i)asana.{0,20}client.?id.{0,10}['"]([0-9]{16,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AssemblyAiApiKey,
            regex: Regex::new(r#"(?i)assemblyai.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AteraApiKey,
            regex: Regex::new(r#"(?i)atera.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AtlassianApiToken,
            regex: Regex::new(r#"(?i)(?:atlassian|confluence|jira).{0,20}token.{0,10}['"]([a-zA-Z0-9]{24,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AuddApiKey,
            regex: Regex::new(r#"(?i)audd.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::Auth0ClientSecret,
            regex: Regex::new(r#"(?i)auth0.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::Auth0ManagementToken,
            regex: Regex::new(r#"(?i)auth0.{0,20}management.{0,10}['"]([a-zA-Z0-9_\-\.]{40,})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::AuthressServiceKey,
            regex: Regex::new(r#"(?i)authress.{0,20}['"]([a-zA-Z0-9_\-\.]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AutodeskApiKey,
            regex: Regex::new(r#"(?i)autodesk.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AutokloseApiKey,
            regex: Regex::new(r#"(?i)autoklose.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AutopilotApiKey,
            regex: Regex::new(r#"(?i)autopilot.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AvazaApiKey,
            regex: Regex::new(r#"(?i)avaza.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AviationStackApiKey,
            regex: Regex::new(r#"(?i)aviationstack.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AweberApiKey,
            regex: Regex::new(r#"(?i)aweber.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AxonautApiKey,
            regex: Regex::new(r#"(?i)axonaut.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AylienApiKey,
            regex: Regex::new(r#"(?i)aylien.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::AyrshareApiKey,
            regex: Regex::new(r#"(?i)ayrshare.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },

        // Context-based patterns (B)
        Pattern {
            name: SecretType::BannerbearApiKey,
            regex: Regex::new(r#"(?i)bannerbear.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BaremetricsApiKey,
            regex: Regex::new(r#"(?i)baremetrics.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BasecampApiKey,
            regex: Regex::new(r#"(?i)basecamp.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BeeboleApiKey,
            regex: Regex::new(r#"(?i)beebole.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BesnappyApiKey,
            regex: Regex::new(r#"(?i)besnappy.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BestTimeApiKey,
            regex: Regex::new(r#"(?i)besttime.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BetterStackApiToken,
            regex: Regex::new(r#"(?i)betterstack.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BillomatApiKey,
            regex: Regex::new(r#"(?i)billomat.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BinanceApiKey,
            regex: Regex::new(r#"(?i)binance.{0,20}['"]([a-zA-Z0-9]{64})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::BinaryEdgeApiKey,
            regex: Regex::new(r#"(?i)binaryedge.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BingSubscriptionKey,
            regex: Regex::new(r#"(?i)(?:bing|ocp-apim).{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitBarApiKey,
            regex: Regex::new(r#"(?i)bitbar.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitMexApiKey,
            regex: Regex::new(r#"(?i)bitmex.{0,20}['"]([a-zA-Z0-9_\-]{24})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitbucketToken,
            regex: Regex::new(r#"(?i)bitbucket.{0,20}token.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitbucketServerToken,
            regex: Regex::new(r#"(?i)bitbucket.{0,20}server.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitcoinAverageApiKey,
            regex: Regex::new(r#"(?i)bitcoinaverage.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitfinexApiKey,
            regex: Regex::new(r#"(?i)bitfinex.{0,20}['"]([a-zA-Z0-9_\-]{43})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BitlyAccessToken,
            regex: Regex::new(r#"(?i)bit\.?ly.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BittrexAccessKey,
            regex: Regex::new(r#"(?i)bittrex.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BittrexSecretKey,
            regex: Regex::new(r#"(?i)bittrex.{0,20}secret.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BlazeMeterApiKey,
            regex: Regex::new(r#"(?i)blazemeter.{0,20}['"]([a-f0-9]{50,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BlitAppApiKey,
            regex: Regex::new(r#"(?i)blitapp.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BlockNativeApiKey,
            regex: Regex::new(r#"(?i)blocknative.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BloggerApiKey,
            regex: Regex::new(r#"(?i)blogger.{0,20}['"]AIza[0-9A-Za-z_\-]{35}['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BombBombApiKey,
            regex: Regex::new(r#"(?i)bombbomb.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BoostNoteApiKey,
            regex: Regex::new(r#"(?i)boostnote.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BorgBaseApiKey,
            regex: Regex::new(r#"(?i)borgbase.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BoxApiKey,
            regex: Regex::new(r#"(?i)box.{0,10}(?:api|client).{0,10}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BoxOAuthToken,
            regex: Regex::new(r#"(?i)box.{0,10}oauth.{0,10}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BrandfetchApiKey,
            regex: Regex::new(r#"(?i)brandfetch.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BrevoApiKey,
            regex: Regex::new(r"xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.98,
        },
        Pattern {
            name: SecretType::BrowserStackAccessKey,
            regex: Regex::new(r#"(?i)browserstack.{0,20}['"]([a-zA-Z0-9]{20})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BrowshotApiKey,
            regex: Regex::new(r#"(?i)browshot.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BscScanApiKey,
            regex: Regex::new(r#"(?i)bscscan.{0,20}['"]([A-Z0-9]{34})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BuddyNsApiKey,
            regex: Regex::new(r#"(?i)buddyns.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BudibaseApiKey,
            regex: Regex::new(r#"(?i)budibase.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BugHerdApiKey,
            regex: Regex::new(r#"(?i)bugherd.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BugSnagApiKey,
            regex: Regex::new(r#"(?i)bugsnag.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BuilderIoApiKey,
            regex: Regex::new(r#"(?i)builder\.?io.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BulbulApiKey,
            regex: Regex::new(r#"(?i)bulbul.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BulkSmsApiKey,
            regex: Regex::new(r#"(?i)bulksms.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::BunnyCdnApiKey,
            regex: Regex::new(r#"(?i)bunny.?cdn.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ButterCmsApiKey,
            regex: Regex::new(r#"(?i)buttercms.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },

        // Context-based patterns (C)
        Pattern {
            name: SecretType::CaflouApiKey,
            regex: Regex::new(r#"(?i)caflou.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CalendarificApiKey,
            regex: Regex::new(r#"(?i)calendarific.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CalendlyApiKey,
            regex: Regex::new(r#"(?i)calendly.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CalorieNinjaApiKey,
            regex: Regex::new(r#"(?i)calorieninja.{0,20}['"]([a-zA-Z0-9_\-/+=]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CampaignMonitorApiKey,
            regex: Regex::new(r#"(?i)campaignmonitor.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CampaynApiKey,
            regex: Regex::new(r#"(?i)campayn.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CannyIoApiKey,
            regex: Regex::new(r#"(?i)canny.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CanvaApiToken,
            regex: Regex::new(r#"(?i)canva.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CapsuleCrmApiKey,
            regex: Regex::new(r#"(?i)capsule.?crm.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CaptainDataApiKey,
            regex: Regex::new(r#"(?i)captaindata.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CarbonInterfaceApiKey,
            regex: Regex::new(r#"(?i)carboninterface.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CashboardApiKey,
            regex: Regex::new(r#"(?i)cashboard.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CaspioApiKey,
            regex: Regex::new(r#"(?i)caspio.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CensysApiKey,
            regex: Regex::new(r#"(?i)censys.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CentralStationCrmApiKey,
            regex: Regex::new(r#"(?i)centralstation.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CexIoApiKey,
            regex: Regex::new(r#"(?i)cex\.?io.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChargeBeeApiKey,
            regex: Regex::new(r#"(?i)chargebee.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChartMogulApiKey,
            regex: Regex::new(r#"(?i)chartmogul.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChatbotApiKey,
            regex: Regex::new(r#"(?i)chatbot.{0,10}(?:api|key).{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChatfuelApiKey,
            regex: Regex::new(r#"(?i)chatfuel.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChecIoApiKey,
            regex: Regex::new(r#"(?i)chec\.?io.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ChecklyApiKey,
            regex: Regex::new(r"cu_[a-zA-Z0-9]{20,}").unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::CheckoutComApiKey,
            regex: Regex::new(r"sk_(?:sbox_|live_)[a-zA-Z0-9\-]{20,}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::CheckvistApiKey,
            regex: Regex::new(r#"(?i)checkvist.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CiceroApiKey,
            regex: Regex::new(r#"(?i)cicero.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CircleCiPersonalToken,
            regex: Regex::new(r#"(?i)circle.?ci.{0,20}personal.{0,10}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CiscoMerakiApiKey,
            regex: Regex::new(r#"(?i)meraki.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::ClarifaiApiKey,
            regex: Regex::new(r#"(?i)clarifai.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::ClearbitApiKey,
            regex: Regex::new(r"sk_[a-f0-9]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.75,
        },
        Pattern {
            name: SecretType::ClerkApiKey,
            regex: Regex::new(r#"(?i)clerk.{0,20}['"]sk_(?:live|test)_[a-zA-Z0-9]{20,}['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::ClickHelpApiKey,
            regex: Regex::new(r#"(?i)clickhelp.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClickHouseApiSecret,
            regex: Regex::new(r#"(?i)clickhouse.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClickSendApiKey,
            regex: Regex::new(r#"(?i)clicksend.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClickUpPersonalToken,
            regex: Regex::new(r"pk_[0-9]+_[A-Z0-9]{32}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::CliengoApiKey,
            regex: Regex::new(r#"(?i)cliengo.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClientaryApiKey,
            regex: Regex::new(r#"(?i)clientary.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClinchPadApiKey,
            regex: Regex::new(r#"(?i)clinchpad.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClockifyApiKey,
            regex: Regex::new(r#"(?i)clockify.{0,20}['"]([a-zA-Z0-9]{48})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClockworkSmsApiKey,
            regex: Regex::new(r#"(?i)clockwork.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloseCrmApiKey,
            regex: Regex::new(r"api_[a-zA-Z0-9\.]{30,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudConvertApiKey,
            regex: Regex::new(r#"(?i)cloudconvert.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudElementsApiKey,
            regex: Regex::new(r#"(?i)cloudelements.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudFrontKey,
            regex: Regex::new(r#"(?i)cloudfront.{0,20}['"]([A-Z0-9]{14})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudflareApiKey,
            regex: Regex::new(r#"(?i)cloudflare.{0,20}api.?key.{0,10}['"]([a-f0-9]{37})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CloudflareGlobalApiKey,
            regex: Regex::new(r#"(?i)cloudflare.{0,20}global.{0,10}['"]([a-f0-9]{37})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CloudflareOriginCaKey,
            regex: Regex::new(r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::CloudImageApiKey,
            regex: Regex::new(r#"(?i)cloudimage.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudMersiveApiKey,
            regex: Regex::new(r#"(?i)cloudmersive.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudPlanApiKey,
            regex: Regex::new(r#"(?i)cloudplan.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloudinaryApiSecret,
            regex: Regex::new(r#"(?i)cloudinary.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CloudsmithApiKey,
            regex: Regex::new(r#"(?i)cloudsmith.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CloverlyApiKey,
            regex: Regex::new(r#"(?i)cloverly.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClozeApiKey,
            regex: Regex::new(r#"(?i)cloze.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ClustDocApiKey,
            regex: Regex::new(r#"(?i)clustdoc.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CodaApiKey,
            regex: Regex::new(r#"(?i)coda.{0,10}(?:api|key|token).{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CodacyApiToken,
            regex: Regex::new(r#"(?i)codacy.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CodeClimateApiToken,
            regex: Regex::new(r#"(?i)codeclimate.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CodeMagicApiToken,
            regex: Regex::new(r#"(?i)codemagic.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CodeQuiryApiKey,
            regex: Regex::new(r#"(?i)codequiry.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CognitoClientSecret,
            regex: Regex::new(r#"(?i)cognito.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CoinApiKey,
            regex: Regex::new(r#"(?i)coinapi.{0,20}['"]([A-Z0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CoinLayerApiKey,
            regex: Regex::new(r#"(?i)coinlayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CoinLibApiKey,
            regex: Regex::new(r#"(?i)coinlib.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CoinMarketCapApiKey,
            regex: Regex::new(r#"(?i)coinmarketcap.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::Collect2ApiKey,
            regex: Regex::new(r#"(?i)collect2.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ColumnApiKey,
            regex: Regex::new(r#"(?i)column.{0,10}(?:api|key).{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CommerceJsApiKey,
            regex: Regex::new(r#"(?i)commerce\.?js.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CommercetoolsApiKey,
            regex: Regex::new(r#"(?i)commercetools.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CommoditiesApiKey,
            regex: Regex::new(r#"(?i)commodities.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CompanyHubApiKey,
            regex: Regex::new(r#"(?i)companyhub.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConfluentSecretKey,
            regex: Regex::new(r#"(?i)confluent.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-/+=]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::ConstantContactApiKey,
            regex: Regex::new(r#"(?i)constantcontact.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ContentstackToken,
            regex: Regex::new(r"cs[a-f0-9]{30,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConversionToolsApiKey,
            regex: Regex::new(r#"(?i)conversiontools.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConvertApiKey,
            regex: Regex::new(r#"(?i)convertapi.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConvertKitApiKey,
            regex: Regex::new(r#"(?i)convertkit.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConvertKitApiSecret,
            regex: Regex::new(r#"(?i)convertkit.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::ConvierApiKey,
            regex: Regex::new(r#"(?i)convier.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CopperApiKey,
            regex: Regex::new(r#"(?i)copper.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CouchbaseConnectionString,
            regex: Regex::new(r"couchbases?://[^:]+:[^@]+@[^/]+").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::CountryLayerApiKey,
            regex: Regex::new(r#"(?i)countrylayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CourierApiKey,
            regex: Regex::new(r#"(?i)courier.{0,10}(?:api|auth).{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CoverallsApiToken,
            regex: Regex::new(r#"(?i)coveralls.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CraftMyPdfApiKey,
            regex: Regex::new(r#"(?i)craftmypdf.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CrowdStrikeApiKey,
            regex: Regex::new(r#"(?i)crowdstrike.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::CrowdinApiToken,
            regex: Regex::new(r#"(?i)crowdin.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CryptoCompareApiKey,
            regex: Regex::new(r#"(?i)cryptocompare.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CurrencyCloudApiKey,
            regex: Regex::new(r#"(?i)currencycloud.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CurrencyFreaksApiKey,
            regex: Regex::new(r#"(?i)currencyfreaks.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CurrencyLayerApiKey,
            regex: Regex::new(r#"(?i)currencylayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CurrencyScoopApiKey,
            regex: Regex::new(r#"(?i)currencyscoop.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CurrentsApiKey,
            regex: Regex::new(r#"(?i)currentsapi.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CustomerGuruApiKey,
            regex: Regex::new(r#"(?i)customerguru.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::CustomerIoApiKey,
            regex: Regex::new(r#"(?i)customer\.?io.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },

        // Context-based patterns (D)
        Pattern {
            name: SecretType::D7NetworkApiKey,
            regex: Regex::new(r#"(?i)d7.?network.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DailyCoApiKey,
            regex: Regex::new(r#"(?i)daily\.?co.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DandelionApiKey,
            regex: Regex::new(r#"(?i)dandelion.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DareBoostApiKey,
            regex: Regex::new(r#"(?i)dareboost.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DataGovApiKey,
            regex: Regex::new(r#"(?i)data\.?gov.{0,20}['"]([a-zA-Z0-9]{40})['"]"#).unwrap(),
            severity: Severity::Low,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DataboxApiKey,
            regex: Regex::new(r#"(?i)databox.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DatoCmsApiToken,
            regex: Regex::new(r#"(?i)datocms.{0,20}['"]([a-f0-9]{30,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DebounceApiKey,
            regex: Regex::new(r#"(?i)debounce.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DeepAiApiKey,
            regex: Regex::new(r#"(?i)deepai.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DeepLApiKey,
            regex: Regex::new(r#"(?i)deepl.{0,20}['"]([a-f0-9\-]{36}:fx)['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.90,
        },
        Pattern {
            name: SecretType::DeepgramApiKey,
            regex: Regex::new(r#"(?i)deepgram.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::DefinedNetworkingApiToken,
            regex: Regex::new(r"dnkey-[a-zA-Z0-9\-_]{40,}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::DelightedApiKey,
            regex: Regex::new(r#"(?i)delighted.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DemioApiKey,
            regex: Regex::new(r#"(?i)demio.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DeployHqApiKey,
            regex: Regex::new(r#"(?i)deployhq.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DeputyApiKey,
            regex: Regex::new(r#"(?i)deputy.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DetectLanguageApiKey,
            regex: Regex::new(r#"(?i)detectlanguage.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DetectifyApiKey,
            regex: Regex::new(r#"(?i)detectify.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DfuseApiKey,
            regex: Regex::new(r#"(?i)dfuse.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DiffBotApiKey,
            regex: Regex::new(r#"(?i)diffbot.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DiggernautApiKey,
            regex: Regex::new(r#"(?i)diggernaut.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DisqusApiKey,
            regex: Regex::new(r#"(?i)disqus.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DittoApiKey,
            regex: Regex::new(r#"(?i)ditto.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DnSimpleApiToken,
            regex: Regex::new(r#"(?i)dnsimple.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DnsCheckApiKey,
            regex: Regex::new(r#"(?i)dnscheck.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DocparserApiKey,
            regex: Regex::new(r#"(?i)docparser.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DocuSignApiKey,
            regex: Regex::new(r#"(?i)docusign.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DocumoApiKey,
            regex: Regex::new(r#"(?i)documo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DotDigitalApiKey,
            regex: Regex::new(r#"(?i)dotdigital.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DovicoApiKey,
            regex: Regex::new(r#"(?i)dovico.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DripApiKey,
            regex: Regex::new(r#"(?i)drip.{0,10}(?:api|token).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DronaHqApiKey,
            regex: Regex::new(r#"(?i)dronahq.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DroneCiAccessToken,
            regex: Regex::new(r#"(?i)drone.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DuoApiKey,
            regex: Regex::new(r"DI[A-Z0-9]{18}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85,
        },
        Pattern {
            name: SecretType::DuplyApiKey,
            regex: Regex::new(r#"(?i)duply.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DwollaApiKey,
            regex: Regex::new(r#"(?i)dwolla.{0,20}['"]([a-zA-Z0-9]{40,})['"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DynalistApiKey,
            regex: Regex::new(r#"(?i)dynalist.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },
        Pattern {
            name: SecretType::DyspatchApiKey,
            regex: Regex::new(r#"(?i)dyspatch.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.80,
        },

        // Context-based patterns (E)
        Pattern { name: SecretType::EagleEyeNetworksApiKey, regex: Regex::new(r#"(?i)eagleeye.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EasyInsightApiKey, regex: Regex::new(r#"(?i)easyinsight.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EcoStruxureApiKey, regex: Regex::new(r#"(?i)ecostruxure.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EdamamApiKey, regex: Regex::new(r#"(?i)edamam.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EdenAiApiKey, regex: Regex::new(r#"(?i)edenai.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EightByEightApiKey, regex: Regex::new(r#"(?i)8x8.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ElasticApiKey, regex: Regex::new(r#"(?i)elastic.{0,10}(?:api|key|cloud).{0,10}['"]([a-zA-Z0-9_\-=]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ElasticCloudApiKey, regex: Regex::new(r#"(?i)elastic.{0,10}cloud.{0,10}['"]([a-zA-Z0-9_\-=]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ElasticEmailApiKey, regex: Regex::new(r#"(?i)elasticemail.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ElevenLabsApiKey, regex: Regex::new(r#"(?i)elevenlabs.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::EmailOctopusApiKey, regex: Regex::new(r#"(?i)emailoctopus.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EnableXApiKey, regex: Regex::new(r#"(?i)enablex.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EndorLabsApiKey, regex: Regex::new(r#"(?i)endorlabs.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::EnigmaApiKey, regex: Regex::new(r#"(?i)enigma.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EnvoyApiKey, regex: Regex::new(r#"(?i)envoy.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EraserApiKey, regex: Regex::new(r#"(?i)eraser.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EtherscanApiKey, regex: Regex::new(r#"(?i)etherscan.{0,20}['"]([A-Z0-9]{34})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.85 },
        Pattern { name: SecretType::EthplorerApiKey, regex: Regex::new(r#"(?i)ethplorer.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EtsyAccessToken, regex: Regex::new(r#"(?i)etsy.{0,20}['"]([a-zA-Z0-9_\-]{24,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::EventbriteApiKey, regex: Regex::new(r#"(?i)eventbrite.{0,20}['"]([a-zA-Z0-9]{50,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::EverhourApiKey, regex: Regex::new(r#"(?i)everhour.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ExchangeRateApiKey, regex: Regex::new(r#"(?i)exchangerate.{0,20}['"]([a-f0-9]{24,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ExchangeRatesApiKey, regex: Regex::new(r#"(?i)exchangeratesapi.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ExportSdkApiKey, regex: Regex::new(r#"(?i)exportsdk.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ExtractorApiKey, regex: Regex::new(r#"(?i)extractorapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (F)
        Pattern { name: SecretType::FacebookOAuthToken, regex: Regex::new(r#"(?i)facebook.{0,20}oauth.{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::FacePlusPlusApiKey, regex: Regex::new(r#"(?i)faceplusplus.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FastForexApiKey, regex: Regex::new(r#"(?i)fastforex.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FastlyPersonalToken, regex: Regex::new(r#"(?i)fastly.{0,20}personal.{0,10}['"]([a-zA-Z0-9_\-]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::FeedierApiKey, regex: Regex::new(r#"(?i)feedier.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FetchRssApiKey, regex: Regex::new(r#"(?i)fetchrss.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FiberyApiKey, regex: Regex::new(r#"(?i)fibery.{0,20}['"]([a-f0-9\.\-]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FileIoApiKey, regex: Regex::new(r#"(?i)file\.?io.{0,20}['"]([a-f0-9\.\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FinageApiKey, regex: Regex::new(r#"(?i)finage.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FinancialModelingPrepApiKey, regex: Regex::new(r#"(?i)financialmodelingprep.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FindlApiKey, regex: Regex::new(r#"(?i)findl.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FinicityApiToken, regex: Regex::new(r#"(?i)finicity.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::FinicityClientSecret, regex: Regex::new(r#"(?i)finicity.{0,20}secret.{0,10}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::FinnhubAccessToken, regex: Regex::new(r#"(?i)finnhub.{0,20}['"]([a-z0-9]{20})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FixerIoApiKey, regex: Regex::new(r#"(?i)fixer\.?io.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FlatIoApiKey, regex: Regex::new(r#"(?i)flat\.?io.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FleetbaseApiKey, regex: Regex::new(r#"(?i)fleetbase.{0,20}['"]flb_[a-z0-9]{30,}['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.90 },
        Pattern { name: SecretType::FlexportApiKey, regex: Regex::new(r#"(?i)flexport.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::FlickrApiKey, regex: Regex::new(r#"(?i)flickr.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FlightApiKey, regex: Regex::new(r#"(?i)flightapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FlightLabsApiKey, regex: Regex::new(r#"(?i)flightlabs.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FlightStatsApiKey, regex: Regex::new(r#"(?i)flightstats.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FloatApiKey, regex: Regex::new(r#"(?i)float.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FlowFluApiKey, regex: Regex::new(r#"(?i)flowflu.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FmfwApiKey, regex: Regex::new(r#"(?i)fmfw.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FormBucketApiKey, regex: Regex::new(r#"(?i)formbucket.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FormCraftApiKey, regex: Regex::new(r#"(?i)formcraft.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FormIoApiKey, regex: Regex::new(r#"(?i)form\.?io.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FormSiteApiKey, regex: Regex::new(r#"(?i)formsite.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FoursquareApiKey, regex: Regex::new(r#"(?i)foursquare.{0,20}['"]([A-Z0-9]{48})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FreshdeskApiKey, regex: Regex::new(r#"(?i)freshdesk.{0,20}['"]([a-zA-Z0-9]{20})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FrontApiToken, regex: Regex::new(r#"(?i)front.{0,10}(?:api|token).{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FulcrumApiKey, regex: Regex::new(r#"(?i)fulcrum.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FullStoryApiKey, regex: Regex::new(r#"(?i)fullstory.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::FusionAuthApiKey, regex: Regex::new(r#"(?i)fusionauth.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::FxMarketApiKey, regex: Regex::new(r#"(?i)fxmarket.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (G)
        Pattern { name: SecretType::GeocodioApiKey, regex: Regex::new(r#"(?i)geocodio.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GetGistApiKey, regex: Regex::new(r#"(?i)getgist.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GetResponseApiKey, regex: Regex::new(r#"(?i)getresponse.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GhostAdminApiKey, regex: Regex::new(r"[a-f0-9]{24}:[a-f0-9]{64}").unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::GitGuardianApiToken, regex: Regex::new(r#"(?i)gitguardian.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::GitLabToken, regex: Regex::new(r#"(?i)gitlab.{0,20}token.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::GiteaAccessToken, regex: Regex::new(r#"(?i)gitea.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::GiteePat, regex: Regex::new(r#"(?i)gitee.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::GitterAccessToken, regex: Regex::new(r#"(?i)gitter.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GlassfrogApiKey, regex: Regex::new(r#"(?i)glassfrog.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GoCanvasApiKey, regex: Regex::new(r#"(?i)gocanvas.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GoCardlessApiToken, regex: Regex::new(r#"(?i)gocardless.{0,20}['"]live_[a-zA-Z0-9_\-]{40,}['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.90 },
        Pattern { name: SecretType::GraphCmsApiKey, regex: Regex::new(r#"(?i)(?:graphcms|hygraph).{0,20}['"]([a-zA-Z0-9_\-]{100,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GraphhopperApiKey, regex: Regex::new(r#"(?i)graphhopper.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GreyNoiseApiKey, regex: Regex::new(r#"(?i)greynoise.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GumroadApiKey, regex: Regex::new(r#"(?i)gumroad.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::GuruApiKey, regex: Regex::new(r#"(?i)guru.{0,10}(?:api|key|token).{0,10}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::GyazoApiKey, regex: Regex::new(r#"(?i)gyazo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (H)
        Pattern { name: SecretType::HarnessApiKey, regex: Regex::new(r#"(?i)harness.{0,20}['"]([a-zA-Z0-9_\.\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::HarvestApiToken, regex: Regex::new(r#"(?i)harvest.{0,20}['"]([a-zA-Z0-9_\-]{30,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HaveIBeenPwnedApiKey, regex: Regex::new(r#"(?i)haveibeenpwned.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HealthchecksIoApiKey, regex: Regex::new(r#"(?i)healthchecks.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HeapApiKey, regex: Regex::new(r#"(?i)heap.{0,10}(?:api|app).{0,10}['"]([0-9]{10,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HelpCrunchApiKey, regex: Regex::new(r#"(?i)helpcrunch.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HelpScoutApiKey, regex: Regex::new(r#"(?i)helpscout.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HereMapsApiKey, regex: Regex::new(r#"(?i)here.{0,10}(?:map|api).{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HetznerApiToken, regex: Regex::new(r#"(?i)hetzner.{0,20}['"]([a-zA-Z0-9]{64})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::HiveApiKey, regex: Regex::new(r#"(?i)hive.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HoneyBadgerApiKey, regex: Regex::new(r#"(?i)honeybadger.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HoneycombApiKey, regex: Regex::new(r#"(?i)honeycomb.{0,20}['"]([a-zA-Z0-9]{22,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::HotjarApiKey, regex: Regex::new(r#"(?i)hotjar.{0,20}['"]([0-9]{7,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.75 },
        Pattern { name: SecretType::HubSpotApiKey, regex: Regex::new(r#"(?i)hubspot.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::HubSpotPrivateAppToken, regex: Regex::new(r"pat-na1-[a-f0-9\-]{36}").unwrap(), severity: Severity::High, confidence_base: 0.95 },
        Pattern { name: SecretType::HumioApiKey, regex: Regex::new(r#"(?i)humio.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::HunterApiKey, regex: Regex::new(r#"(?i)hunter.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::HyperTrackApiKey, regex: Regex::new(r#"(?i)hypertrack.{0,20}['"]([a-f0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (I)
        Pattern { name: SecretType::IbmCloudApiKey, regex: Regex::new(r#"(?i)ibm.{0,10}cloud.{0,10}['"]([a-zA-Z0-9_\-]{44})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::IexCloudApiKey, regex: Regex::new(r#"(?i)iexcloud.{0,20}['"]([a-zA-Z0-9_]{30,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ImageKitApiKey, regex: Regex::new(r#"(?i)imagekit.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ImgBbApiKey, regex: Regex::new(r#"(?i)imgbb.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::InVisionApiKey, regex: Regex::new(r#"(?i)invision.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::InfluxDbToken, regex: Regex::new(r#"(?i)influx.{0,20}['"]([a-zA-Z0-9_\-=]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::InfobipApiKey, regex: Regex::new(r#"(?i)infobip.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::InfuraApiKey, regex: Regex::new(r#"(?i)infura.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::InstamojoApiKey, regex: Regex::new(r#"(?i)instamojo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::InstanaApiToken, regex: Regex::new(r#"(?i)instana.{0,20}['"]([a-zA-Z0-9_\-]{22,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::InterzoidApiKey, regex: Regex::new(r#"(?i)interzoid.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::InvoiceOceanApiKey, regex: Regex::new(r#"(?i)invoiceocean.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::Ip2LocationApiKey, regex: Regex::new(r#"(?i)ip2location.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpApiKey, regex: Regex::new(r#"(?i)ipapi.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpDataApiKey, regex: Regex::new(r#"(?i)ipdata.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpFindApiKey, regex: Regex::new(r#"(?i)ipfind.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpGeolocationApiKey, regex: Regex::new(r#"(?i)ipgeolocation.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpInfoApiKey, regex: Regex::new(r#"(?i)ipinfo.{0,20}['"]([a-f0-9]{14})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpQualityScoreApiKey, regex: Regex::new(r#"(?i)ipqualityscore.{0,20}['"]([a-zA-Z0-9]{25,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpStackApiKey, regex: Regex::new(r#"(?i)ipstack.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::IpifyApiKey, regex: Regex::new(r#"(?i)ipify.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.75 },
        Pattern { name: SecretType::IterableApiKey, regex: Regex::new(r#"(?i)iterable.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },

        // Context-based patterns (J-K)
        Pattern { name: SecretType::JFrogIdentityToken, regex: Regex::new(r#"(?i)jfrog.{0,20}['"]([a-zA-Z0-9_\-]{60,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::JambonesApiKey, regex: Regex::new(r#"(?i)jambones.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::JanioApiKey, regex: Regex::new(r#"(?i)janio.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::JenkinsApiToken, regex: Regex::new(r#"(?i)jenkins.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::JotFormApiKey, regex: Regex::new(r#"(?i)jotform.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::JumpCloudApiKey, regex: Regex::new(r#"(?i)jumpcloud.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::KanbanToolApiKey, regex: Regex::new(r#"(?i)kanbantool.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KarbonApiKey, regex: Regex::new(r#"(?i)karbon.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KeenApiKey, regex: Regex::new(r#"(?i)keen.{0,10}(?:api|key|write|read).{0,10}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KeyCdnApiKey, regex: Regex::new(r#"(?i)keycdn.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KeycloakClientSecret, regex: Regex::new(r#"(?i)keycloak.{0,20}secret.{0,10}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::KickboxApiKey, regex: Regex::new(r#"(?i)kickbox.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KintoneApiKey, regex: Regex::new(r#"(?i)kintone.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KlaviyoApiKey, regex: Regex::new(r"pk_[a-f0-9]{34}").unwrap(), severity: Severity::High, confidence_base: 0.90 },
        Pattern { name: SecretType::KlipfolioApiKey, regex: Regex::new(r#"(?i)klipfolio.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KnockApiKey, regex: Regex::new(r#"(?i)knock.{0,10}(?:api|key).{0,10}['"]([a-f0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KonakartApiKey, regex: Regex::new(r#"(?i)konakart.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::KucoinAccessToken, regex: Regex::new(r#"(?i)kucoin.{0,20}['"]([a-f0-9]{24,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::KylasApiKey, regex: Regex::new(r#"(?i)kylas.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (L)
        Pattern { name: SecretType::LarkSuitApiKey, regex: Regex::new(r#"(?i)lark.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LaunchableApiKey, regex: Regex::new(r#"(?i)launchable.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LeadfeederApiKey, regex: Regex::new(r#"(?i)leadfeeder.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LemlistApiKey, regex: Regex::new(r#"(?i)lemlist.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LemonSqueezyApiKey, regex: Regex::new(r#"(?i)lemonsqueezy.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::LendflowApiKey, regex: Regex::new(r#"(?i)lendflow.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LessAnnoyingCrmApiKey, regex: Regex::new(r#"(?i)lessannoying.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LeverApiKey, regex: Regex::new(r#"(?i)lever.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LexigramApiKey, regex: Regex::new(r#"(?i)lexigram.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LinearClientSecret, regex: Regex::new(r#"(?i)linear.{0,20}secret.{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::LinkPreviewApiKey, regex: Regex::new(r#"(?i)linkpreview.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LinodeApiToken, regex: Regex::new(r#"(?i)linode.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::LiveAgentApiKey, regex: Regex::new(r#"(?i)liveagent.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LiveChatApiKey, regex: Regex::new(r#"(?i)livechat.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LivestormApiKey, regex: Regex::new(r#"(?i)livestorm.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LocationIqApiKey, regex: Regex::new(r#"(?i)locationiq.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LogRocketApiKey, regex: Regex::new(r#"(?i)logrocket.{0,20}['"]([a-zA-Z0-9_/]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LogglyApiToken, regex: Regex::new(r#"(?i)loggly.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LoginRadiusApiKey, regex: Regex::new(r#"(?i)loginradius.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::LogzIoApiKey, regex: Regex::new(r#"(?i)logz\.?io.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::LokaliseApiToken, regex: Regex::new(r#"(?i)lokalise.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LoomApiKey, regex: Regex::new(r#"(?i)loom.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LoopsApiKey, regex: Regex::new(r#"(?i)loops.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LovenseApiKey, regex: Regex::new(r#"(?i)lovense.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LoyverseApiKey, regex: Regex::new(r#"(?i)loyverse.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LunacrushApiKey, regex: Regex::new(r#"(?i)lunacrush.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::LunoApiKey, regex: Regex::new(r#"(?i)luno.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },

        // Context-based patterns (M)
        Pattern { name: SecretType::MagicApiKey, regex: Regex::new(r#"(?i)magic.{0,10}(?:api|key|secret).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailCheckApiKey, regex: Regex::new(r#"(?i)mailcheck.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailboxLayerApiKey, regex: Regex::new(r#"(?i)mailboxlayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailerLiteApiKey, regex: Regex::new(r#"(?i)mailerlite.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailjetApiKey, regex: Regex::new(r#"(?i)mailjet.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailjetSecretKey, regex: Regex::new(r#"(?i)mailjet.{0,20}secret.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::MailmodoApiKey, regex: Regex::new(r#"(?i)mailmodo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MailsacApiKey, regex: Regex::new(r#"(?i)mailsac.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MapQuestApiKey, regex: Regex::new(r#"(?i)mapquest.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MaxMindLicenseKey, regex: Regex::new(r#"(?i)maxmind.{0,20}['"]([a-zA-Z0-9]{16})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MeadowApiKey, regex: Regex::new(r#"(?i)meadow.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MeaningCloudApiKey, regex: Regex::new(r#"(?i)meaningcloud.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MediaStackApiKey, regex: Regex::new(r#"(?i)mediastack.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MedusaApiKey, regex: Regex::new(r#"(?i)medusa.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MercuryApiKey, regex: Regex::new(r#"(?i)mercury.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::MetaApiKey, regex: Regex::new(r#"(?i)metaapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MindMeisterApiKey, regex: Regex::new(r#"(?i)mindmeister.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MiroApiToken, regex: Regex::new(r#"(?i)miro.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MixMaxApiKey, regex: Regex::new(r#"(?i)mixmax.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MixpanelToken, regex: Regex::new(r#"(?i)mixpanel.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MockoonApiKey, regex: Regex::new(r#"(?i)mockoon.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.80 },
        Pattern { name: SecretType::ModerationApiKey, regex: Regex::new(r#"(?i)moderation.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MollieApiKey, regex: Regex::new(r"(?:live|test)_[a-zA-Z0-9]{30,}").unwrap(), severity: Severity::High, confidence_base: 0.75 },
        Pattern { name: SecretType::MondayApiKey, regex: Regex::new(r#"(?i)monday.{0,20}['"]([a-zA-Z0-9]{300,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MonFloApiKey, regex: Regex::new(r#"(?i)monflo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MoosendApiKey, regex: Regex::new(r#"(?i)moosend.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::MoralisApiKey, regex: Regex::new(r#"(?i)moralis.{0,20}['"]([a-zA-Z0-9]{50,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::MuxApiKey, regex: Regex::new(r#"(?i)mux.{0,10}(?:api|token|key).{0,10}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (N)
        Pattern { name: SecretType::NasdaqDataLinkApiKey, regex: Regex::new(r#"(?i)(?:nasdaq|quandl).{0,20}['"]([a-zA-Z0-9_\-]{20})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::Neo4jCredential, regex: Regex::new(r"neo4j(?:\+s)?://[^:]+:[^@]+@[^/]+").unwrap(), severity: Severity::Critical, confidence_base: 0.90 },
        Pattern { name: SecretType::NetlifyToken, regex: Regex::new(r#"(?i)netlify.{0,20}token.{0,10}['"]([a-f0-9\-]{36,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::NewsApiKey, regex: Regex::new(r#"(?i)newsapi.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::NhostApiKey, regex: Regex::new(r#"(?i)nhost.{0,20}['"]([a-f0-9\-]{36,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::NoticeableApiKey, regex: Regex::new(r#"(?i)noticeable.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::NotionOAuthToken, regex: Regex::new(r#"(?i)notion.{0,20}oauth.{0,10}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::NovuApiKey, regex: Regex::new(r#"(?i)novu.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::Ns1ApiKey, regex: Regex::new(r#"(?i)ns1.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::NumbersApiKey, regex: Regex::new(r#"(?i)numbersapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.75 },
        Pattern { name: SecretType::NutshellApiKey, regex: Regex::new(r#"(?i)nutshell.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (O)
        Pattern { name: SecretType::OAuthToken, regex: Regex::new(r#"(?i)oauth.?token\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.75 },
        Pattern { name: SecretType::OandaApiKey, regex: Regex::new(r#"(?i)oanda.{0,20}['"]([a-f0-9\-]{65})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::OmnisendApiKey, regex: Regex::new(r#"(?i)omnisend.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OneLoginApiKey, regex: Regex::new(r#"(?i)onelogin.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::OneSignalApiKey, regex: Regex::new(r#"(?i)onesignal.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OnfleetApiKey, regex: Regex::new(r#"(?i)onfleet.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OpenCageApiKey, regex: Regex::new(r#"(?i)opencage.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OpenExchangeRatesApiKey, regex: Regex::new(r#"(?i)openexchangerates.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OpenWeatherMapApiKey, regex: Regex::new(r#"(?i)openweather.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OpsGenieApiKey, regex: Regex::new(r#"(?i)opsgenie.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::OracleCloudApiKey, regex: Regex::new(r#"(?i)oracle.{0,10}cloud.{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.80 },
        Pattern { name: SecretType::OrbitApiKey, regex: Regex::new(r#"(?i)orbit.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::OryApiKey, regex: Regex::new(r#"(?i)ory.{0,10}(?:api|key|token).{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },

        // Context-based patterns (P)
        Pattern { name: SecretType::PaddleApiKey, regex: Regex::new(r#"(?i)paddle.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::PandaDocApiKey, regex: Regex::new(r#"(?i)pandadoc.{0,20}['"]([a-f0-9]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PaperformApiKey, regex: Regex::new(r#"(?i)paperform.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ParseHubApiKey, regex: Regex::new(r#"(?i)parsehub.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PaypalClientSecret, regex: Regex::new(r#"(?i)paypal.{0,20}secret.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::PdfCoApiKey, regex: Regex::new(r#"(?i)pdf\.?co.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PdfLayerApiKey, regex: Regex::new(r#"(?i)pdflayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PendoApiKey, regex: Regex::new(r#"(?i)pendo.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PercyApiKey, regex: Regex::new(r#"(?i)percy.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PersonApiKey, regex: Regex::new(r#"(?i)personapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PexelsApiKey, regex: Regex::new(r#"(?i)pexels.{0,20}['"]([a-zA-Z0-9]{56})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PinataApiKey, regex: Regex::new(r#"(?i)pinata.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PipedreamApiKey, regex: Regex::new(r#"(?i)pipedream.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PipedriveApiToken, regex: Regex::new(r#"(?i)pipedrive.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PivotalTrackerApiToken, regex: Regex::new(r#"(?i)pivotal.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PlanhatApiKey, regex: Regex::new(r#"(?i)planhat.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PlanyoApiKey, regex: Regex::new(r#"(?i)planyo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PleskApiKey, regex: Regex::new(r#"(?i)plesk.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::PlivoApiKey, regex: Regex::new(r#"(?i)plivo.{0,20}['"]([A-Za-z0-9]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::PodioApiKey, regex: Regex::new(r#"(?i)podio.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PollsApiKey, regex: Regex::new(r#"(?i)pollsapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.80 },
        Pattern { name: SecretType::PositionStackApiKey, regex: Regex::new(r#"(?i)positionstack.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PostageAppApiKey, regex: Regex::new(r#"(?i)postageapp.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PostmarkApiToken, regex: Regex::new(r#"(?i)postmark.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::PowerBiApiKey, regex: Regex::new(r#"(?i)powerbi.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::PrerenderApiKey, regex: Regex::new(r#"(?i)prerender.{0,20}['"]([a-f0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PrismicApiToken, regex: Regex::new(r#"(?i)prismic.{0,20}['"]([a-zA-Z0-9_\-\.]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PrivacyCloudApiKey, regex: Regex::new(r#"(?i)privacycloud.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ProfitwellApiKey, regex: Regex::new(r#"(?i)profitwell.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ProspectIoApiKey, regex: Regex::new(r#"(?i)prospect\.?io.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ProxyCrawlApiKey, regex: Regex::new(r#"(?i)proxycrawl.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ProxyScrapeApiKey, regex: Regex::new(r#"(?i)proxyscrape.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PushBulletApiKey, regex: Regex::new(r#"(?i)pushbullet.{0,20}['"]([a-zA-Z0-9\.]{34})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::PushoverApiKey, regex: Regex::new(r#"(?i)pushover.{0,20}['"]([a-z0-9]{30})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (Q-R)
        Pattern { name: SecretType::QaseApiKey, regex: Regex::new(r#"(?i)qase.{0,20}['"]([a-f0-9]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::QuboleApiKey, regex: Regex::new(r#"(?i)qubole.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::QuickBaseApiKey, regex: Regex::new(r#"(?i)quickbase.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::QuickNodeApiKey, regex: Regex::new(r#"(?i)quicknode.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RampApiKey, regex: Regex::new(r#"(?i)ramp.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RavenToolsApiKey, regex: Regex::new(r#"(?i)raventools.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RawgApiKey, regex: Regex::new(r#"(?i)rawg.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RazorpayKeySecret, regex: Regex::new(r#"(?i)razorpay.{0,20}secret.{0,10}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::ReallySimpleSystemsApiKey, regex: Regex::new(r#"(?i)reallysimplesystems.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RebrandlyApiKey, regex: Regex::new(r#"(?i)rebrandly.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RechargePaymentsApiKey, regex: Regex::new(r#"(?i)recharge.{0,20}['"]([a-f0-9]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RecruiteeApiKey, regex: Regex::new(r#"(?i)recruitee.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RecurlyApiKey, regex: Regex::new(r#"(?i)recurly.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RedisLabsApiKey, regex: Regex::new(r#"(?i)redislabs.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RefinerApiKey, regex: Regex::new(r#"(?i)refiner.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ResmushApiKey, regex: Regex::new(r#"(?i)resmush.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.80 },
        Pattern { name: SecretType::RestPackApiKey, regex: Regex::new(r#"(?i)restpack.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RevApiKey, regex: Regex::new(r#"(?i)rev.{0,10}(?:api|key|token).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RevampCrmApiKey, regex: Regex::new(r#"(?i)revampcrm.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RiteKitApiKey, regex: Regex::new(r#"(?i)ritekit.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RiveApiKey, regex: Regex::new(r#"(?i)rive.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RobinApiKey, regex: Regex::new(r#"(?i)robin.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RocketReachApiKey, regex: Regex::new(r#"(?i)rocketreach.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RollbarApiKey, regex: Regex::new(r#"(?i)rollbar.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RoninAppApiKey, regex: Regex::new(r#"(?i)roninapp.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::Route4MeApiKey, regex: Regex::new(r#"(?i)route4me.{0,20}['"]([A-F0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::Route53Key, regex: Regex::new(r#"(?i)route53.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RowndApiKey, regex: Regex::new(r#"(?i)rownd.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::RunPodApiKey, regex: Regex::new(r#"(?i)runpod.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::RunscopeApiKey, regex: Regex::new(r#"(?i)runscope.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (S)
        Pattern { name: SecretType::SaladCloudApiKey, regex: Regex::new(r#"(?i)saladcloud.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SalesforceApiToken, regex: Regex::new(r#"(?i)salesforce.{0,20}['"]([a-zA-Z0-9!]{20,})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.80 },
        Pattern { name: SecretType::SalesMateApiKey, regex: Regex::new(r#"(?i)salesmate.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SanityApiToken, regex: Regex::new(r"sk[a-zA-Z0-9]{60,}").unwrap(), severity: Severity::High, confidence_base: 0.75 },
        Pattern { name: SecretType::SatisMeterApiKey, regex: Regex::new(r#"(?i)satismeter.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SauceLabsApiKey, regex: Regex::new(r#"(?i)saucelabs.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SauceNaoApiKey, regex: Regex::new(r#"(?i)saucenao.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScaleSerpApiKey, regex: Regex::new(r#"(?i)scaleserp.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScalewayApiKey, regex: Regex::new(r#"(?i)scaleway.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ScraperApiKey, regex: Regex::new(r#"(?i)scraperapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScraperBoxApiKey, regex: Regex::new(r#"(?i)scraperbox.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScrapFlyApiKey, regex: Regex::new(r#"(?i)scrapfly.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScrapinApiKey, regex: Regex::new(r#"(?i)scrapin.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScreenshotApiKey, regex: Regex::new(r#"(?i)screenshotapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ScriptrApiKey, regex: Regex::new(r#"(?i)scriptr.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SecurityTrailsApiKey, regex: Regex::new(r#"(?i)securitytrails.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::SemantriaApiKey, regex: Regex::new(r#"(?i)semantria.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SemaphoreCiToken, regex: Regex::new(r#"(?i)semaphore.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::SendBirdApiKey, regex: Regex::new(r#"(?i)sendbird.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SendPulseApiKey, regex: Regex::new(r#"(?i)sendpulse.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SerpApiKey, regex: Regex::new(r#"(?i)serpapi.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ServiceBellApiKey, regex: Regex::new(r#"(?i)servicebell.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ServiceNowApiKey, regex: Regex::new(r#"(?i)servicenow.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ShipDayApiKey, regex: Regex::new(r#"(?i)shipday.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ShipEngineApiKey, regex: Regex::new(r"TEST_[a-zA-Z0-9+/]{50,}").unwrap(), severity: Severity::Medium, confidence_base: 0.75 },
        Pattern { name: SecretType::ShippingCloudApiKey, regex: Regex::new(r#"(?i)shippingcloud.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ShippoApiKey, regex: Regex::new(r"shippo_(?:live|test)_[a-f0-9]{40}").unwrap(), severity: Severity::High, confidence_base: 0.95 },
        Pattern { name: SecretType::ShodanApiKey, regex: Regex::new(r#"(?i)shodan.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::ShopwareApiKey, regex: Regex::new(r#"(?i)shopware.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ShortcutApiToken, regex: Regex::new(r#"(?i)shortcut.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ShotStackApiKey, regex: Regex::new(r#"(?i)shotstack.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ShutterStockApiKey, regex: Regex::new(r#"(?i)shutterstock.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SignableApiKey, regex: Regex::new(r#"(?i)signable.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SignaturitApiKey, regex: Regex::new(r#"(?i)signaturit.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SimFinApiKey, regex: Regex::new(r#"(?i)simfin.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SimpleSatApiKey, regex: Regex::new(r#"(?i)simplesat.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SimplyNotedApiKey, regex: Regex::new(r#"(?i)simplynoted.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SimvolyApiKey, regex: Regex::new(r#"(?i)simvoly.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SirvApiKey, regex: Regex::new(r#"(?i)sirv.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SiteLeafApiKey, regex: Regex::new(r#"(?i)siteleaf.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SkylightApiKey, regex: Regex::new(r#"(?i)skylight.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SmartSheetsApiKey, regex: Regex::new(r#"(?i)smartsheet.{0,20}['"]([a-zA-Z0-9]{26,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SmartlingApiKey, regex: Regex::new(r#"(?i)smartling.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SmartyApiKey, regex: Regex::new(r#"(?i)smarty.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SmsApiKey, regex: Regex::new(r#"(?i)smsapi.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SnovApiKey, regex: Regex::new(r#"(?i)snov.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SnowflakeCredential, regex: Regex::new(r#"(?i)snowflake.{0,20}(?:password|pwd).{0,10}['"]([a-zA-Z0-9!@#$%^&*]{8,})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.80 },
        Pattern { name: SecretType::SonarCloudApiKey, regex: Regex::new(r#"(?i)sonarcloud.{0,20}['"]([a-f0-9]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::SparkPostApiKey, regex: Regex::new(r#"(?i)sparkpost.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::SpoonacularApiKey, regex: Regex::new(r#"(?i)spoonacular.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SpotifyApiKey, regex: Regex::new(r#"(?i)spotify.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SquareOAuthToken, regex: Regex::new(r"sq0csp-[0-9A-Za-z\-_]{43}").unwrap(), severity: Severity::Critical, confidence_base: 0.98 },
        Pattern { name: SecretType::SslMateApiKey, regex: Regex::new(r#"(?i)sslmate.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StackHawkApiKey, regex: Regex::new(r"hawk\.[a-zA-Z0-9_\-]{20,}").unwrap(), severity: Severity::High, confidence_base: 0.90 },
        Pattern { name: SecretType::StackPathApiKey, regex: Regex::new(r#"(?i)stackpath.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StatusCakeApiKey, regex: Regex::new(r#"(?i)statuscake.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StatusPageApiKey, regex: Regex::new(r#"(?i)statuspage.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StatusPalApiKey, regex: Regex::new(r#"(?i)statuspal.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StitchDataApiKey, regex: Regex::new(r#"(?i)stitchdata.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StormBoardApiKey, regex: Regex::new(r#"(?i)stormboard.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StormGlassApiKey, regex: Regex::new(r#"(?i)stormglass.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StoryblokApiToken, regex: Regex::new(r#"(?i)storyblok.{0,20}['"]([a-zA-Z0-9]{22,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StoryChiefApiKey, regex: Regex::new(r#"(?i)storychief.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StrapiApiToken, regex: Regex::new(r#"(?i)strapi.{0,20}['"]([a-f0-9]{64,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::StripoApiKey, regex: Regex::new(r#"(?i)stripo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::StytchApiKey, regex: Regex::new(r#"(?i)stytch.{0,20}['"]([a-zA-Z0-9_\-]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::SupabaseAnonKey, regex: Regex::new(r#"(?i)supabase.{0,20}anon.{0,10}['"]eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+['"]"#).unwrap(), severity: Severity::Low, confidence_base: 0.85 },
        Pattern { name: SecretType::SupabaseServiceKey, regex: Regex::new(r#"(?i)supabase.{0,20}service.{0,10}['"]eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::SurveyAnyplaceApiKey, regex: Regex::new(r#"(?i)surveyanyplace.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SurveySparrowApiKey, regex: Regex::new(r#"(?i)surveysparrow.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SurvicateApiKey, regex: Regex::new(r#"(?i)survicate.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SvixApiKey, regex: Regex::new(r#"(?i)svix.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SwellApiKey, regex: Regex::new(r#"(?i)swell.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::SwiftypeApiKey, regex: Regex::new(r#"(?i)swiftype.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (T)
        Pattern { name: SecretType::TallyFyApiKey, regex: Regex::new(r#"(?i)tallyfy.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TatumIoApiKey, regex: Regex::new(r#"(?i)tatum.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TaxJarApiToken, regex: Regex::new(r#"(?i)taxjar.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TeamCityApiToken, regex: Regex::new(r#"(?i)teamcity.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TeamGateApiKey, regex: Regex::new(r#"(?i)teamgate.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TeamworkApiKey, regex: Regex::new(r#"(?i)teamwork.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TeleSignApiKey, regex: Regex::new(r#"(?i)telesign.{0,20}['"]([a-zA-Z0-9+/=]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TextMagicApiKey, regex: Regex::new(r#"(?i)textmagic.{0,20}['"]([a-zA-Z0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ThinkificApiKey, regex: Regex::new(r#"(?i)thinkific.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TicketTailorApiKey, regex: Regex::new(r#"(?i)tickettailor.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TikTokApiKey, regex: Regex::new(r#"(?i)tiktok.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TimeCampApiKey, regex: Regex::new(r#"(?i)timecamp.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TimekitApiKey, regex: Regex::new(r#"(?i)timekit.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TimescaleDbToken, regex: Regex::new(r#"(?i)timescale.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TinesWebhookApiKey, regex: Regex::new(r#"(?i)tines.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TodoistApiKey, regex: Regex::new(r#"(?i)todoist.{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TogglApiKey, regex: Regex::new(r#"(?i)toggl.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TomTomApiKey, regex: Regex::new(r#"(?i)tomtom.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TomorrowIoApiKey, regex: Regex::new(r#"(?i)tomorrow\.?io.{0,20}['"]([a-zA-Z0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TradierApiKey, regex: Regex::new(r#"(?i)tradier.{0,20}['"]([a-zA-Z0-9]{20,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TransifexApiToken, regex: Regex::new(r#"(?i)transifex.{0,20}['"]([a-f0-9/]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TravisCiApiToken, regex: Regex::new(r#"(?i)travis.{0,20}['"]([a-zA-Z0-9_\-]{22,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TravisCiToken, regex: Regex::new(r#"(?i)travis.{0,20}token.{0,10}['"]([a-zA-Z0-9_\-]{22,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TursoApiToken, regex: Regex::new(r#"(?i)turso.{0,20}['"]([a-zA-Z0-9_\-\.]{40,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::TwilioAuthToken, regex: Regex::new(r#"(?i)twilio.{0,20}auth.{0,10}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Critical, confidence_base: 0.85 },
        Pattern { name: SecretType::TypesenseApiKey, regex: Regex::new(r#"(?i)typesense.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::TypetalkApiKey, regex: Regex::new(r#"(?i)typetalk.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // Context-based patterns (U-Z)
        Pattern { name: SecretType::UbidotsApiKey, regex: Regex::new(r#"(?i)ubidots.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UnityApiKey, regex: Regex::new(r#"(?i)unity.{0,10}(?:api|key).{0,10}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UploadIoApiKey, regex: Regex::new(r#"(?i)upload\.?io.{0,20}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UploadcareApiKey, regex: Regex::new(r#"(?i)uploadcare.{0,20}['"]([a-f0-9]{20})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UptimeRobotApiKey, regex: Regex::new(r"[um][0-9]+-[a-f0-9]{48,}").unwrap(), severity: Severity::Medium, confidence_base: 0.85 },
        Pattern { name: SecretType::UrlScanApiKey, regex: Regex::new(r#"(?i)urlscan.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UserStackApiKey, regex: Regex::new(r#"(?i)userstack.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::UserflowApiKey, regex: Regex::new(r#"(?i)userflow.{0,20}['"]ct_[a-z0-9]{32,}['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.90 },
        Pattern { name: SecretType::VatLayerApiKey, regex: Regex::new(r#"(?i)vatlayer.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::VeracodeApiKey, regex: Regex::new(r#"(?i)veracode.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::VeriphoneApiKey, regex: Regex::new(r#"(?i)veriphone.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::VirustotalApiKey, regex: Regex::new(r#"(?i)virustotal.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::VoiceflowApiKey, regex: Regex::new(r"VF\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9_\-]{16,}").unwrap(), severity: Severity::Medium, confidence_base: 0.95 },
        Pattern { name: SecretType::VonageApiKey, regex: Regex::new(r#"(?i)(?:vonage|nexmo).{0,20}['"]([a-f0-9]{8})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.75 },
        Pattern { name: SecretType::VoucheryApiKey, regex: Regex::new(r#"(?i)vouchery.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::VultrApiKey, regex: Regex::new(r#"(?i)vultr.{0,20}['"]([A-Z0-9]{36})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.85 },
        Pattern { name: SecretType::WakaTimeApiKey, regex: Regex::new(r#"(?i)wakatime.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WandBApiKey, regex: Regex::new(r#"(?i)(?:wandb|weights.{0,3}biases).{0,20}['"]([a-f0-9]{40})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::WebScraperApiKey, regex: Regex::new(r#"(?i)webscraper.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WebScrapingApiKey, regex: Regex::new(r#"(?i)webscraping.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WebexApiKey, regex: Regex::new(r#"(?i)webex.{0,20}['"]([a-zA-Z0-9_\-]{64,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::WebflowApiToken, regex: Regex::new(r#"(?i)webflow.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WebhookRelayApiKey, regex: Regex::new(r#"(?i)webhookrelay.{0,20}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WeekdoneApiKey, regex: Regex::new(r#"(?i)weekdone.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WhatCmsApiKey, regex: Regex::new(r#"(?i)whatcms.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WhoxyApiKey, regex: Regex::new(r#"(?i)whoxy.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WistiaApiKey, regex: Regex::new(r#"(?i)wistia.{0,20}['"]([a-f0-9]{40,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WitApiKey, regex: Regex::new(r#"(?i)wit\.?ai.{0,20}['"]([A-Z0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WixApiKey, regex: Regex::new(r#"(?i)wix.{0,10}(?:api|key|secret).{0,10}['"]([a-f0-9\-]{36})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::WooCommerceApiKey, regex: Regex::new(r"ck_[a-f0-9]{40}").unwrap(), severity: Severity::High, confidence_base: 0.90 },
        Pattern { name: SecretType::WorkOsApiKey, regex: Regex::new(r#"(?i)workos.{0,20}['"]sk_[a-zA-Z0-9_\-]{40,}['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.90 },
        Pattern { name: SecretType::WrikeApiToken, regex: Regex::new(r#"(?i)wrike.{0,20}['"]([a-zA-Z0-9]{24,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::XeroApiKey, regex: Regex::new(r#"(?i)xero.{0,20}['"]([A-Z0-9]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::YelpApiKey, regex: Regex::new(r#"(?i)yelp.{0,20}['"]([a-zA-Z0-9_\-]{128})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::YextApiKey, regex: Regex::new(r#"(?i)yext.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::YouNeedABudgetApiKey, regex: Regex::new(r#"(?i)(?:ynab|youneedabudget).{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::YouTubeApiKey, regex: Regex::new(r#"(?i)youtube.{0,20}AIza[0-9A-Za-z_\-]{35}"#).unwrap(), severity: Severity::Medium, confidence_base: 0.85 },
        Pattern { name: SecretType::ZapierApiKey, regex: Regex::new(r#"(?i)zapier.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZendeskChatApiKey, regex: Regex::new(r#"(?i)zendesk.{0,10}chat.{0,10}['"]([a-zA-Z0-9_\-]{20,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZenRowsApiKey, regex: Regex::new(r#"(?i)zenrows.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZenScrapeApiKey, regex: Regex::new(r#"(?i)zenscrape.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZeplinApiKey, regex: Regex::new(r#"(?i)zeplin.{0,20}['"]([a-f0-9]{64})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZeroBounceApiKey, regex: Regex::new(r#"(?i)zerobounce.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZeroSslApiKey, regex: Regex::new(r#"(?i)zerossl.{0,20}['"]([a-f0-9]{32})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZipBooksApiKey, regex: Regex::new(r#"(?i)zipbooks.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },
        Pattern { name: SecretType::ZohoApiKey, regex: Regex::new(r"Zoho-oauthtoken [a-zA-Z0-9\.]{30,}").unwrap(), severity: Severity::High, confidence_base: 0.95 },
        Pattern { name: SecretType::ZoomApiKey, regex: Regex::new(r#"(?i)zoom.{0,20}['"]([a-zA-Z0-9_\-]{32,})['"]"#).unwrap(), severity: Severity::High, confidence_base: 0.80 },
        Pattern { name: SecretType::ZoomInfoApiKey, regex: Regex::new(r#"(?i)zoominfo.{0,20}['"]([a-f0-9]{32,})['"]"#).unwrap(), severity: Severity::Medium, confidence_base: 0.80 },

        // ══════════════════════════════════════════════
        // Generic API Key patterns (keep last as fallback)
        // ══════════════════════════════════════════════
        Pattern {
            name: SecretType::GenericApiKey,
            regex: Regex::new(r#"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{32,})['\"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.70,
        },
        Pattern {
            name: SecretType::GenericSecret,
            regex: Regex::new(r#"(?i)secret['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{32,})['\"]"#).unwrap(),
            severity: Severity::Medium,
            confidence_base: 0.65,
        },
        // Generic password assignment patterns
        Pattern {
            name: SecretType::GenericCredential,
            regex: Regex::new(r#"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.70,
        },
        // Generic token assignment patterns
        Pattern {
            name: SecretType::GenericCredential,
            regex: Regex::new(r#"(?i)(?:access_token|auth_token|bearer_token)\s*[:=]\s*['\"]([A-Za-z0-9\-_\.]{20,})['\"]"#).unwrap(),
            severity: Severity::High,
            confidence_base: 0.70,
        },
    ];
}

/// Represents a detected match with its position in the line
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub secret: Secret,
    pub column_start: usize,
    pub column_end: usize,
}

pub struct PatternDetector {
    /// Extra patterns loaded from `.leaktor.toml` [[custom_patterns]].
    custom_patterns: Vec<Pattern>,
}

/// Extract the credential portion from a connection string for entropy analysis.
///
/// Given `mongodb+srv://user:p4$$w0rd@cluster.example.com`, returns `user:p4$$w0rd`.
/// If no `://` scheme is found, returns the whole value unchanged.
fn extract_connection_string_credential(value: &str) -> String {
    // Strip the protocol scheme (everything up to and including `://`)
    let after_scheme = match value.find("://") {
        Some(idx) => &value[idx + 3..],
        None => return value.to_string(),
    };
    // The credential portion is `user:pass` before the `@` host separator
    match after_scheme.find('@') {
        Some(idx) => after_scheme[..idx].to_string(),
        None => after_scheme.to_string(),
    }
}

impl PatternDetector {
    pub fn new() -> Self {
        Self {
            custom_patterns: Vec::new(),
        }
    }

    /// Create a detector with additional user-defined patterns from config.
    pub fn with_custom_patterns(custom: &[crate::config::settings::CustomPattern]) -> Self {
        let mut custom_patterns = Vec::new();

        for cp in custom {
            let severity = match cp.severity.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                _ => Severity::Low,
            };

            match Regex::new(&cp.regex) {
                Ok(re) => {
                    custom_patterns.push(Pattern {
                        name: SecretType::Custom(cp.name.clone()),
                        regex: re,
                        severity,
                        confidence_base: cp.confidence.clamp(0.0, 1.0),
                    });
                }
                Err(e) => {
                    eprintln!("[!] Skipping invalid custom pattern \"{}\": {}", cp.name, e);
                }
            }
        }

        Self { custom_patterns }
    }

    /// Scan a line of text for secrets, returning all matches with positions
    pub fn scan_line(&self, line: &str, entropy_threshold: f64) -> Vec<Secret> {
        self.scan_line_with_positions(line, entropy_threshold)
            .into_iter()
            .map(|m| m.secret)
            .collect()
    }

    /// Scan a line and return matches with their column positions
    pub fn scan_line_with_positions(
        &self,
        line: &str,
        entropy_threshold: f64,
    ) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let mut seen_ranges: Vec<(usize, usize)> = Vec::new();

        // Chain built-in patterns with custom patterns
        let all_patterns = PATTERNS.iter().chain(self.custom_patterns.iter());

        for pattern in all_patterns {
            // Use captures_iter to extract capture groups when available
            for caps in pattern.regex.captures_iter(line) {
                // If the pattern has a capture group, use group 1 as the value;
                // otherwise use the full match (group 0).
                let (value, col_start, col_end) = if let Some(group1) = caps.get(1) {
                    (
                        group1.as_str().to_string(),
                        group1.start(),
                        group1.end(),
                    )
                } else {
                    let full = caps.get(0).unwrap();
                    (
                        full.as_str().to_string(),
                        full.start(),
                        full.end(),
                    )
                };

                // Deduplicate: skip if this range overlaps with an already-found match
                let dominated = seen_ranges
                    .iter()
                    .any(|&(s, e)| s <= col_start && col_end <= e);
                if dominated {
                    continue;
                }

                // Remove any existing ranges that this new one fully covers
                seen_ranges.retain(|&(s, e)| !(col_start <= s && e <= col_end));
                seen_ranges.push((col_start, col_end));

                // Calculate entropy.
                // For connection strings, extract the credential portion
                // (user:pass) instead of measuring the low-entropy protocol
                // prefix (e.g. "mongodb+srv://"), which would unfairly drop
                // the confidence score.
                let entropy_text = if pattern.name.is_connection_string() {
                    extract_connection_string_credential(&value)
                } else {
                    value.clone()
                };
                let entropy =
                    crate::detectors::entropy::EntropyAnalyzer::calculate(&entropy_text);

                // Adjust confidence based on entropy
                // Skip entropy penalty for private key patterns (PEM headers are fixed strings)
                let mut confidence = pattern.confidence_base;
                if entropy < entropy_threshold && !pattern.name.is_private_key() {
                    confidence *= 0.7;
                }

                let secret = Secret::new(
                    pattern.name.clone(),
                    value,
                    entropy,
                    pattern.severity,
                    confidence,
                );

                matches.push(PatternMatch {
                    secret,
                    column_start: col_start,
                    column_end: col_end,
                });
            }
        }

        // Post-process: remove generic matches when a specific match covers the same value.
        // Generic types like GenericApiKey, GenericSecret, GenericCredential should yield
        // to more specific detections (e.g., Stripe API Key).
        let generic_types = [SecretType::GenericApiKey, SecretType::GenericSecret, SecretType::GenericCredential];
        let specific_values: Vec<String> = matches
            .iter()
            .filter(|m| !generic_types.contains(&m.secret.secret_type))
            .map(|m| m.secret.value.clone())
            .collect();

        if !specific_values.is_empty() {
            matches.retain(|m| {
                if generic_types.contains(&m.secret.secret_type) {
                    // Remove this generic match if any specific match's value overlaps
                    !specific_values.iter().any(|sv| {
                        sv.contains(&m.secret.value) || m.secret.value.contains(sv.as_str())
                    })
                } else {
                    true
                }
            });
        }

        matches
    }

    /// Get all pattern names for documentation
    pub fn get_pattern_types() -> Vec<String> {
        PATTERNS
            .iter()
            .map(|p| p.name.as_str().to_string())
            .collect()
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_type(secrets: &[Secret], secret_type: SecretType) -> bool {
        secrets.iter().any(|s| s.secret_type == secret_type)
    }

    // ═══════════════════════════════════════
    // Cloud Provider Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_aws_access_key_detection() {
        let detector = PatternDetector::new();
        let line = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::AwsAccessKey));
    }

    #[test]
    fn test_aws_secret_key_detection() {
        let detector = PatternDetector::new();
        // Value must be exactly 40 chars of [0-9a-zA-Z/+]
        let line = r#"aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY0123456789""#;
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "AWS Secret Key should be detected");
        assert!(has_type(&secrets, SecretType::AwsSecretKey));
        // The captured value should be just the 40-char key, not the whole line
        let aws_secret = secrets.iter().find(|s| s.secret_type == SecretType::AwsSecretKey).unwrap();
        assert_eq!(aws_secret.value, "wJalrXUtnFEMI/K7MDENG/bPxRfiCY0123456789");
    }

    #[test]
    fn test_gcp_api_key_detection() {
        let detector = PatternDetector::new();
        let line = "GCP_KEY=AIzaSyA1234567890abcdefghijklmnopqrstuv";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "GCP API Key should be detected");
    }

    #[test]
    fn test_azure_storage_key_detection() {
        let detector = PatternDetector::new();
        let line = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn==;";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Azure Storage Key should be detected");
        assert!(has_type(&secrets, SecretType::AzureStorageKey));
    }

    // ═══════════════════════════════════════
    // Version Control Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_github_pat_detection() {
        let detector = PatternDetector::new();
        let line = "GITHUB_TOKEN=ghp_1234567890123456789012345678901234";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::GitHubPat));
    }

    #[test]
    fn test_github_oauth_detection() {
        let detector = PatternDetector::new();
        let line = "TOKEN=gho_1234567890123456789012345678901234";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::GitHubOauth));
    }

    #[test]
    fn test_gitlab_pat_detection() {
        let detector = PatternDetector::new();
        let line = "GITLAB_TOKEN=glpat-12345678901234567890";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::GitLabPat));
    }

    // ═══════════════════════════════════════
    // Private Key Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_rsa_private_key_detection() {
        let detector = PatternDetector::new();
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::RsaPrivateKey));
    }

    #[test]
    fn test_ssh_private_key_detection() {
        let detector = PatternDetector::new();
        let line = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::SshPrivateKey));
    }

    #[test]
    fn test_ec_private_key_detection() {
        let detector = PatternDetector::new();
        let line = "-----BEGIN EC PRIVATE KEY-----";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::EcPrivateKey));
    }

    #[test]
    fn test_pgp_private_key_detection() {
        let detector = PatternDetector::new();
        let line = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::PgpPrivateKey));
    }

    // ═══════════════════════════════════════
    // Database Connection String Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_redis_detection() {
        let detector = PatternDetector::new();
        let line = "REDIS_URL=redis://:super_secret_redis_pass@redis-cluster.internal:6379";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Redis pattern should match");
        assert!(has_type(&secrets, SecretType::RedisConnectionString));
    }

    #[test]
    fn test_mongodb_detection() {
        let detector = PatternDetector::new();
        let line = "MONGO_URL=mongodb+srv://user:s3cretP4ss@cluster0.abc123.mongodb.net/mydb";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "MongoDB pattern should match");
        assert!(has_type(&secrets, SecretType::MongoDbConnectionString));
    }

    #[test]
    fn test_postgres_detection() {
        let detector = PatternDetector::new();
        let line = "DATABASE_URL=postgresql://admin:supersecret@db.internal:5432/production";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Postgres pattern should match");
        assert!(has_type(&secrets, SecretType::PostgresConnectionString));
    }

    #[test]
    fn test_mysql_detection() {
        let detector = PatternDetector::new();
        let line = "DB_URL=mysql://root:mypassword@localhost:3306/mydb";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "MySQL pattern should match");
        assert!(has_type(&secrets, SecretType::MysqlConnectionString));
    }

    // ═══════════════════════════════════════
    // API Key Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_stripe_api_key_detection() {
        let detector = PatternDetector::new();
        let line = "STRIPE_KEY=sk_live_1234567890abcdefghijklmnop";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::StripeApiKey));
    }

    #[test]
    fn test_sendgrid_api_key_detection() {
        let detector = PatternDetector::new();
        let line =
            "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDE";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::SendGridApiKey));
    }

    #[test]
    fn test_slack_token_detection() {
        let detector = PatternDetector::new();
        let line = "SLACK_TOKEN=xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::SlackToken));
    }

    #[test]
    fn test_slack_webhook_detection() {
        let detector = PatternDetector::new();
        let line =
            "WEBHOOK=https://hooks.slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(has_type(&secrets, SecretType::SlackWebhook));
    }

    // ═══════════════════════════════════════
    // NEW: AI/ML Platform Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_huggingface_token_detection() {
        let detector = PatternDetector::new();
        let line = "HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz1234567890";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "HuggingFace token should be detected");
        assert!(has_type(&secrets, SecretType::HuggingFaceToken));
    }

    // ═══════════════════════════════════════
    // NEW: Package Registry Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_npm_token_detection() {
        let detector = PatternDetector::new();
        let line = "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "NPM token should be detected");
        assert!(has_type(&secrets, SecretType::NpmToken));
    }

    #[test]
    fn test_pypi_token_detection() {
        let detector = PatternDetector::new();
        // After the prefix `pypi-AgEIcHlwaS5vcmc`, need 50+ alphanumeric chars
        let line =
            "PYPI_TOKEN=pypi-AgEIcHlwaS5vcmcabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "PyPI token should be detected");
        assert!(has_type(&secrets, SecretType::PyPiApiToken));
    }

    // ═══════════════════════════════════════
    // NEW: Communication Platform Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_discord_webhook_detection() {
        let detector = PatternDetector::new();
        let line = "DISCORD_WEBHOOK=https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz0123456789_ABCDE-FGHIJ";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Discord webhook should be detected");
        assert!(has_type(&secrets, SecretType::DiscordWebhook));
    }

    // ═══════════════════════════════════════
    // NEW: Infrastructure Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_digitalocean_token_detection() {
        let detector = PatternDetector::new();
        let line =
            "DO_TOKEN=dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "DigitalOcean token should be detected");
        assert!(has_type(&secrets, SecretType::DigitalOceanToken));
    }

    #[test]
    fn test_hashicorp_vault_token_detection() {
        let detector = PatternDetector::new();
        let line = "VAULT_TOKEN=hvs.CAESIDR0YWxzby1uby1tb3JlLXRva2VuLTEyMzQ1Njc4OTBhYmNkZWY";
        let secrets = detector.scan_line(line, 3.0);
        assert!(
            !secrets.is_empty(),
            "HashiCorp Vault token should be detected"
        );
        assert!(has_type(&secrets, SecretType::HashiCorpVaultToken));
    }

    #[test]
    fn test_docker_hub_token_detection() {
        let detector = PatternDetector::new();
        let line = "DOCKER_TOKEN=dckr_pat_abcdefghijklmnopqrstuvwxyz01";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Docker Hub token should be detected");
        assert!(has_type(&secrets, SecretType::DockerHubToken));
    }

    #[test]
    fn test_shopify_token_detection() {
        let detector = PatternDetector::new();
        let line = "SHOPIFY_TOKEN=shpat_abcdef0123456789abcdef0123456789";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Shopify token should be detected");
        assert!(has_type(&secrets, SecretType::ShopifyApiKey));
    }

    #[test]
    fn test_planetscale_token_detection() {
        let detector = PatternDetector::new();
        let line = "PS_TOKEN=pscale_tkn_abcdefghijklmnopqrstuvwxyz012345";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "PlanetScale token should be detected");
        assert!(has_type(&secrets, SecretType::PlanetScaleToken));
    }

    #[test]
    fn test_new_relic_key_detection() {
        let detector = PatternDetector::new();
        let line = "NEW_RELIC_KEY=NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "New Relic API key should be detected");
        assert!(has_type(&secrets, SecretType::NewRelicApiKey));
    }

    #[test]
    fn test_sentry_dsn_detection() {
        let detector = PatternDetector::new();
        let line =
            "SENTRY_DSN=https://abcdef0123456789abcdef0123456789@o123456.ingest.sentry.io/1234567";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Sentry DSN should be detected");
        assert!(has_type(&secrets, SecretType::SentryDsn));
    }

    #[test]
    fn test_linear_api_key_detection() {
        let detector = PatternDetector::new();
        let line = "LINEAR_KEY=lin_api_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Linear API key should be detected");
        assert!(has_type(&secrets, SecretType::LinearApiKey));
    }

    // ═══════════════════════════════════════
    // Multi-match Tests (bug fix verification)
    // ═══════════════════════════════════════
    #[test]
    fn test_multiple_secrets_on_one_line() {
        let detector = PatternDetector::new();
        let line = "AWS_KEY=AKIAZ52HGXYRN4WBTEST GITHUB=ghp_1234567890123456789012345678901234";
        let secrets = detector.scan_line(line, 3.0);
        assert!(
            secrets.len() >= 2,
            "Should find multiple secrets on one line, found: {}",
            secrets.len()
        );
        assert!(has_type(&secrets, SecretType::AwsAccessKey));
        assert!(has_type(&secrets, SecretType::GitHubPat));
    }

    #[test]
    fn test_column_positions_tracked() {
        let detector = PatternDetector::new();
        let line = "GITHUB_TOKEN=ghp_1234567890123456789012345678901234";
        let matches = detector.scan_line_with_positions(line, 3.0);
        assert!(!matches.is_empty());
        // The ghp_ token should start after the =
        let ghp_match = matches
            .iter()
            .find(|m| matches!(m.secret.secret_type, SecretType::GitHubPat))
            .unwrap();
        assert!(ghp_match.column_start > 0, "Column start should be > 0");
        assert!(
            ghp_match.column_end > ghp_match.column_start,
            "Column end should be > start"
        );
    }

    // ═══════════════════════════════════════
    // JWT Test
    // ═══════════════════════════════════════
    #[test]
    fn test_jwt_token_detection() {
        let detector = PatternDetector::new();
        let line = "TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "JWT should be detected");
        assert!(has_type(&secrets, SecretType::JwtToken));
    }

    // ═══════════════════════════════════════
    // Generic Credential Tests
    // ═══════════════════════════════════════
    #[test]
    fn test_generic_password_detection() {
        let detector = PatternDetector::new();
        let line = r#"password = "mySuperSecretP@ssw0rd!123""#;
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Generic password should be detected");
        assert!(has_type(&secrets, SecretType::GenericCredential));
    }
}
