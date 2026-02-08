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
            regex: Regex::new(r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap(),
            severity: Severity::Critical,
            confidence_base: 0.95,
        },
        Pattern {
            name: SecretType::AwsSecretKey,
            regex: Regex::new(r#"(?i)aws(.{0,20})?(?:secret|access.?key)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"#).unwrap(),
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
            regex: Regex::new(r"(ntn_|secret_)[A-Za-z0-9]{40,}").unwrap(),
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
            regex: Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}").unwrap(),
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
        Pattern {
            name: SecretType::FirebaseApiKey,
            regex: Regex::new(r"AIza[0-9A-Za-z\\-_]{35}").unwrap(),
            severity: Severity::High,
            confidence_base: 0.85, // Same format as GCP, slightly lower
        },

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
            regex: Regex::new(r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}").unwrap(),
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
            regex: Regex::new(r"EAA[MC][a-zA-Z0-9]{100,}").unwrap(),
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
            // Use find_iter to find ALL matches, not just the first
            for mat in pattern.regex.find_iter(line) {
                let value = mat.as_str().to_string();
                let col_start = mat.start();
                let col_end = mat.end();

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

                // Calculate entropy
                let entropy = crate::detectors::entropy::EntropyAnalyzer::calculate(&value);

                // Adjust confidence based on entropy
                let mut confidence = pattern.confidence_base;
                if entropy < entropy_threshold {
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
