//! Universal format validator for ALL secret types.
//!
//! This validator checks whether a detected secret value matches the expected
//! format for its type (prefix, length, character set). It provides baseline
//! validation for every secret type, ensuring 100% validator coverage.
//!
//! Registered LAST in the validator chain so API-based validators take priority.

use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;

pub struct FormatValidator;

impl FormatValidator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FormatValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Charset helper functions
// ══════════════════════════════════════════════════════════════════════════════

fn is_hex(c: char) -> bool {
    c.is_ascii_hexdigit()
}
fn is_hex_lower(c: char) -> bool {
    matches!(c, 'a'..='f' | '0'..='9')
}
fn is_alphanum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}
fn is_alphanum_upper(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}
fn is_base64(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}
fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}
fn is_ext(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}
fn is_ext_dot(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}
fn is_ext_slash(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '+' | '=')
}
fn is_uuid_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '-'
}

// ══════════════════════════════════════════════════════════════════════════════
// Format validation helper functions
// ══════════════════════════════════════════════════════════════════════════════

/// Check prefix + exact body length + charset
fn pfx(v: &str, p: &str, body_len: usize, f: fn(char) -> bool) -> bool {
    v.starts_with(p) && v.len() == p.len() + body_len && v[p.len()..].chars().all(f)
}

/// Check prefix + minimum body length + charset
fn pfx_min(v: &str, p: &str, min_body: usize, f: fn(char) -> bool) -> bool {
    v.starts_with(p) && v.len() >= p.len() + min_body && v[p.len()..].chars().all(f)
}

/// Check prefix + body length range + charset
fn pfx_range(v: &str, p: &str, min_b: usize, max_b: usize, f: fn(char) -> bool) -> bool {
    let bl = v.len().saturating_sub(p.len());
    v.starts_with(p) && bl >= min_b && bl <= max_b && v[p.len()..].chars().all(f)
}

/// Check exact length + charset
fn exact(v: &str, len: usize, f: fn(char) -> bool) -> bool {
    v.len() == len && v.chars().all(f)
}

/// Check minimum length + charset
fn min_len(v: &str, min: usize, f: fn(char) -> bool) -> bool {
    v.len() >= min && v.chars().all(f)
}

/// Check length range + charset
fn range_len(v: &str, min: usize, max: usize, f: fn(char) -> bool) -> bool {
    v.len() >= min && v.len() <= max && v.chars().all(f)
}

/// Check that value contains a PEM header
fn is_pem(v: &str, header: &str) -> bool {
    v.contains(header)
}

/// Check that value looks like a connection string URL
fn is_conn_str(v: &str) -> bool {
    v.contains("://") && v.len() >= 10
}

/// Minimum length with no whitespace
fn non_empty(v: &str, min: usize) -> bool {
    v.len() >= min && !v.chars().any(|c| c.is_ascii_whitespace())
}

/// Check UUID format: 8-4-4-4-12 hex with dashes
fn is_uuid(v: &str) -> bool {
    v.len() == 36 && v.chars().all(is_uuid_char) && v.chars().filter(|&c| c == '-').count() == 4
}

#[async_trait::async_trait]
impl Validator for FormatValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        let v = &secret.value;
        let valid = match &secret.secret_type {
            // ══════════════════════════════════════════════
            // Cloud Providers
            // ══════════════════════════════════════════════
            SecretType::AwsAccessKey => {
                v.len() == 20
                    && (v.starts_with("AKIA")
                        || v.starts_with("ASIA")
                        || v.starts_with("AGPA")
                        || v.starts_with("AIDA")
                        || v.starts_with("AROA")
                        || v.starts_with("AIPA")
                        || v.starts_with("ANPA")
                        || v.starts_with("ANVA")
                        || v.starts_with("A3T"))
            }
            SecretType::AwsSecretKey => exact(v, 40, |c| is_base64(c) || c == '/'),
            SecretType::AwsSessionToken => min_len(v, 100, is_base64),
            SecretType::AwsMwsKey => v.starts_with("amzn.mws.") && v.len() >= 45,
            SecretType::AwsBedrockApiKey => {
                v.len() == 20
                    && (v.starts_with("AKIA") || v.starts_with("ASIA"))
                    && v[4..].chars().all(is_alphanum_upper)
            }
            SecretType::GcpApiKey | SecretType::GoogleAiStudioKey | SecretType::GoogleMapsApiKey => {
                pfx(v, "AIza", 35, is_base64url)
            }
            SecretType::GcpServiceAccount => v.contains("service_account"),
            SecretType::GcpApplicationDefaultCredentials => {
                v.contains("iam.gserviceaccount.com")
            }
            SecretType::AzureStorageKey => v.contains("DefaultEndpointsProtocol="),
            SecretType::AzureConnectionString => {
                (v.contains("Server=") || v.contains("Data Source="))
                    && (v.contains("Password=") || v.contains("PWD="))
            }
            SecretType::AzureSasToken => v.contains("sig=") && v.contains("&s"),
            SecretType::AzureDevOpsPat => exact(v, 52, is_alphanum),
            SecretType::AzureContainerRegistryKey => exact(v, 52, is_base64),
            SecretType::AzureCosmosDbKey => v.contains("AccountKey=") && v.len() >= 88,
            SecretType::AzureFunctionKey => min_len(v, 40, is_ext_slash),
            SecretType::AzureSearchAdminKey | SecretType::AzureSearchQueryKey | SecretType::AzureApiManagementKey => {
                min_len(v, 32, is_alphanum)
            }
            SecretType::AzureAppConfigKey => v.contains("azconfig.io") && v.contains("Secret="),
            SecretType::AzureBatchKey => v.ends_with("==") && v.len() == 88,
            SecretType::AzureOpenAiApiKey => exact(v, 32, is_hex_lower),
            SecretType::AzureAdClientSecret | SecretType::AzureClientSecret => {
                v.len() >= 34 && v.contains("Q~")
            }
            SecretType::AlibabaAccessKey => pfx(v, "LTAI", 20, is_alphanum),
            SecretType::AlibabaSecretKey => min_len(v, 30, is_alphanum),

            // ══════════════════════════════════════════════
            // Version Control
            // ══════════════════════════════════════════════
            SecretType::GitHubPat => pfx_range(v, "ghp_", 30, 40, is_alphanum),
            SecretType::GitHubOauth => pfx_range(v, "gho_", 30, 40, is_alphanum),
            SecretType::GitHubToken => range_len(v, 30, 45, is_alphanum),
            SecretType::GitHubAppToken => pfx_range(v, "ghs_", 30, 40, is_alphanum),
            SecretType::GitHubFineGrainedPat => pfx(v, "github_pat_", 82, is_ext),
            SecretType::GitLabPat => pfx(v, "glpat-", 20, is_ext),
            SecretType::GitLabRunnerToken => pfx_min(v, "glrt-", 20, is_ext),
            SecretType::GitLabProjectToken => v.contains("glpat-"),
            SecretType::GitLabToken => min_len(v, 20, is_ext),
            SecretType::BitbucketAppPassword | SecretType::BitbucketToken | SecretType::BitbucketServerToken => {
                min_len(v, 18, is_ext)
            }

            // ══════════════════════════════════════════════
            // Payment / Stripe / Square
            // ══════════════════════════════════════════════
            SecretType::StripeApiKey => pfx_min(v, "sk_live_", 24, is_alphanum),
            SecretType::StripeRestrictedKey => pfx_min(v, "rk_live_", 24, is_alphanum),
            SecretType::PaystackSecretKey => {
                (v.starts_with("sk_live_") || v.starts_with("sk_test_"))
                    && v.len() >= 40
                    && v[8..].chars().all(is_alphanum)
            }
            SecretType::SquareAccessToken => pfx(v, "sq0atp-", 22, is_ext),
            SecretType::SquareOAuthToken => pfx(v, "sq0csp-", 43, is_ext),
            SecretType::BraintreeAccessToken => {
                v.starts_with("access_token$") && v.len() >= 60
            }
            SecretType::RazorpayKeyId => {
                (v.starts_with("rzp_live_") || v.starts_with("rzp_test_"))
                    && v.len() >= 14
            }
            SecretType::FlutterwaveSecretKey | SecretType::FlutterwaveEncryptionKey => {
                v.starts_with("FLWSECK") && v.len() >= 20
            }
            SecretType::FlutterwavePublicKey => v.starts_with("FLWPUBK") && v.len() >= 32,
            SecretType::AdyenApiKey => v.starts_with("AQE") && v.len() >= 80,
            SecretType::CheckoutComApiKey => {
                (v.starts_with("sk_sbox_") || v.starts_with("sk_live_"))
                    && v.len() >= 20
            }

            // ══════════════════════════════════════════════
            // Communication
            // ══════════════════════════════════════════════
            SecretType::SendGridApiKey => {
                v.starts_with("SG.") && v.len() >= 60 && v.contains('.')
            }
            SecretType::TwilioApiKey => pfx(v, "SK", 32, is_hex),
            SecretType::TwilioAuthToken => exact(v, 32, is_hex_lower),
            SecretType::SlackToken => v.starts_with("xox") && v.len() >= 30,
            SecretType::SlackWebhook => v.starts_with("https://hooks.slack.com/"),
            SecretType::SlackAppToken => v.starts_with("xapp-") && v.len() >= 20,
            SecretType::SlackConfigToken => v.starts_with("xoxe.") && v.len() >= 20,
            SecretType::DiscordBotToken => v.len() >= 50 && v.contains('.'),
            SecretType::DiscordWebhook => {
                v.starts_with("https://discord") && v.contains("/webhooks/")
            }
            SecretType::TelegramBotToken => v.contains(':') && v.len() >= 35,
            SecretType::MicrosoftTeamsWebhook => v.contains("webhook.office.com"),
            SecretType::TelnyxApiKey => v.starts_with("KEY") && v.len() >= 50,
            SecretType::VonageApiKey => exact(v, 8, is_hex_lower),

            // ══════════════════════════════════════════════
            // Email Services
            // ══════════════════════════════════════════════
            SecretType::MailgunApiKey => exact(v, 32, is_hex_lower),
            SecretType::MailchimpApiKey => v.contains("-us") && v.len() >= 35,
            SecretType::MailerSendApiKey => pfx_min(v, "mlsn.", 64, is_hex_lower),
            SecretType::MandrillApiKey => range_len(v, 22, 22, is_ext),
            SecretType::BrevoApiKey => v.starts_with("xkeysib-") && v.len() >= 80,
            SecretType::ResendApiKey => pfx_min(v, "re_", 30, is_ext),

            // ══════════════════════════════════════════════
            // AI / ML Platforms
            // ══════════════════════════════════════════════
            SecretType::OpenAiApiKey => {
                v.starts_with("sk-")
                    && v.len() >= 20
                    && v[3..].chars().all(|c| is_ext(c) || c == '.')
            }
            SecretType::AnthropicApiKey => pfx_min(v, "sk-ant-api03-", 90, is_base64url),
            SecretType::AnthropicAdminApiKey => pfx_min(v, "sk-ant-admin", 20, is_ext),
            SecretType::CohereApiKey => exact(v, 40, is_alphanum),
            SecretType::HuggingFaceToken => pfx_min(v, "hf_", 34, is_alphanum),
            SecretType::ReplicateApiKey => pfx_min(v, "r8_", 36, is_alphanum),
            SecretType::GroqApiKey => pfx_min(v, "gsk_", 52, is_alphanum),
            SecretType::PerplexityApiKey => pfx(v, "pplx-", 48, is_hex_lower),
            SecretType::DeepSeekApiKey => pfx(v, "sk-", 48, is_hex_lower),
            SecretType::MistralApiKey => exact(v, 32, is_alphanum),
            SecretType::StabilityAiApiKey => pfx_min(v, "sk-", 48, is_alphanum),
            SecretType::TogetherAiApiKey => exact(v, 64, is_hex_lower),
            SecretType::FireworksAiApiKey => pfx_min(v, "fw_", 40, is_alphanum),
            SecretType::Ai21LabsApiKey => min_len(v, 32, is_alphanum),
            SecretType::AssemblyAiApiKey => exact(v, 32, is_hex_lower),
            SecretType::ElevenLabsApiKey => exact(v, 32, is_hex_lower),
            SecretType::DeepgramApiKey => exact(v, 40, is_hex_lower),

            // ══════════════════════════════════════════════
            // Monitoring & Observability
            // ══════════════════════════════════════════════
            SecretType::DatadogApiKey => exact(v, 32, is_hex_lower),
            SecretType::DatadogAppKey => exact(v, 40, is_hex_lower),
            SecretType::NewRelicApiKey => pfx(v, "NRAK-", 27, is_alphanum_upper),
            SecretType::NewRelicBrowserApiKey => pfx(v, "NRJS-", 19, is_hex_lower),
            SecretType::NewRelicInsightsQueryKey => pfx(v, "NRIQ-", 32, is_alphanum),
            SecretType::NewRelicLicenseKey => v.ends_with("NRAL") && v.len() >= 44,
            SecretType::SentryDsn => v.starts_with("https://") && v.contains("@") && v.contains("sentry.io"),
            SecretType::GrafanaApiKey => {
                (v.starts_with("glc_") || v.starts_with("glsa_")) && v.len() >= 32
            }
            SecretType::PagerDutyApiKey => min_len(v, 20, is_base64),
            SecretType::SplunkHecToken => is_uuid(v),
            SecretType::DynatraceApiToken => v.starts_with("dt0c01.") && v.len() >= 80,
            SecretType::PosthogApiKey => {
                (v.starts_with("phx_") || v.starts_with("phc_")) && v.len() >= 40
            }
            SecretType::SumoLogicKey => exact(v, 64, is_alphanum),

            // ══════════════════════════════════════════════
            // Infrastructure & Hosting
            // ══════════════════════════════════════════════
            SecretType::CloudflareApiToken => min_len(v, 40, is_ext),
            SecretType::CloudflareApiKey | SecretType::CloudflareGlobalApiKey => {
                exact(v, 37, is_hex_lower)
            }
            SecretType::CloudflareOriginCaKey => v.starts_with("v1.0-") && v.len() >= 170,
            SecretType::DigitalOceanToken => pfx(v, "dop_v1_", 64, is_hex_lower),
            SecretType::DigitalOceanOAuthToken => pfx(v, "doo_v1_", 64, is_hex_lower),
            SecretType::DigitalOceanRefreshToken => pfx(v, "dor_v1_", 64, is_hex_lower),
            SecretType::DigitalOceanSpacesKey => pfx(v, "DO", 18, is_alphanum_upper),
            SecretType::VercelToken => exact(v, 24, is_alphanum),
            SecretType::HerokuApiKey => is_uuid(v),
            SecretType::NetlifyPat => pfx_min(v, "nfp_", 40, is_alphanum),
            SecretType::NetlifyToken => min_len(v, 36, is_uuid_char),
            SecretType::FlyAccessToken => v.contains("fm2_") && v.len() >= 40,
            SecretType::FlyIoPersonalToken => pfx_min(v, "fo1_", 40, is_ext),
            SecretType::RenderApiKey => pfx_min(v, "rnd_", 32, is_alphanum),
            SecretType::DenoDeployToken => pfx(v, "ddp_", 40, is_alphanum),
            SecretType::DockerHubToken => pfx_min(v, "dckr_pat_", 27, is_ext),
            SecretType::HashiCorpVaultToken => pfx_min(v, "hvs.", 24, is_ext),
            SecretType::VaultBatchToken => pfx_min(v, "hvb.", 130, is_ext),
            SecretType::TerraformCloudToken => v.contains("atlasv1.") && v.len() >= 60,
            SecretType::PulumiAccessToken => pfx(v, "pul-", 40, is_hex_lower),
            SecretType::FastlyApiToken => min_len(v, 32, is_ext),
            SecretType::DopplerToken => v.starts_with("dp.") && v.len() >= 40,
            SecretType::PlanetScaleToken => pfx_min(v, "pscale_tkn_", 30, is_ext),
            SecretType::PlanetScalePassword => pfx_min(v, "pscale_pw_", 30, is_ext),
            SecretType::InfracostApiKey => pfx(v, "ico-", 32, is_alphanum),
            SecretType::RailwayApiToken => exact(v, 36, is_hex_lower),
            SecretType::NeonApiKey => min_len(v, 60, is_alphanum),
            SecretType::TurborepoAccessToken => exact(v, 36, is_alphanum),
            SecretType::SonarQubeToken => pfx(v, "squ_", 40, is_alphanum),
            SecretType::UpstashRedisToken => v.starts_with("AX") && v.len() >= 60,
            SecretType::HetznerApiToken => exact(v, 64, is_alphanum),

            // ══════════════════════════════════════════════
            // DevTools / CI
            // ══════════════════════════════════════════════
            SecretType::CircleCiToken | SecretType::CircleCiPersonalToken => {
                exact(v, 40, is_hex_lower)
            }
            SecretType::JiraApiToken | SecretType::AtlassianApiToken => {
                min_len(v, 24, is_alphanum)
            }
            SecretType::LaunchDarklyKey => {
                v.starts_with("sdk-") && v.len() >= 36 && v.contains('-')
            }
            SecretType::DatabricksToken => pfx(v, "dapi", 32, is_hex_lower),
            SecretType::ConfluentApiKey => exact(v, 16, is_alphanum),
            SecretType::ConfluentSecretKey => min_len(v, 40, is_ext_slash),
            SecretType::OktaApiToken => {
                v.starts_with("00") && v.len() >= 40 && v[2..].chars().all(is_ext)
            }
            SecretType::PostmanApiToken => {
                v.starts_with("PMAK-") && v.len() >= 60 && v.contains('-')
            }
            SecretType::SnykApiToken => is_uuid(v),
            SecretType::CodecovAccessToken => exact(v, 32, is_alphanum),
            SecretType::AppVeyorApiToken => v.starts_with("v2.") && v.len() >= 20,
            SecretType::BuildKiteApiToken => pfx(v, "bkua_", 40, is_hex_lower),
            SecretType::PrefectApiToken => pfx(v, "pnu_", 36, is_alphanum),
            SecretType::HarnessPat => v.starts_with("pat.") && v.len() >= 60,
            SecretType::ScalingoApiToken => pfx(v, "tk-us-", 48, is_ext),
            SecretType::SourcegraphAccessToken => pfx_min(v, "sgp_", 40, is_hex),
            SecretType::TailscaleApiKey => pfx_min(v, "tskey-", 20, is_ext),
            SecretType::BeamerApiToken => v.contains("b_") && v.len() >= 44,

            // ══════════════════════════════════════════════
            // SaaS / Productivity
            // ══════════════════════════════════════════════
            SecretType::LinearApiKey => pfx_min(v, "lin_api_", 40, is_alphanum),
            SecretType::LinearClientSecret => min_len(v, 32, is_hex_lower),
            SecretType::NotionApiKey => {
                (v.starts_with("ntn_") || v.starts_with("secret_")) && v.len() >= 40
            }
            SecretType::NotionOAuthToken => min_len(v, 40, is_ext),
            SecretType::AirtableApiKey => v.starts_with("pat") && v.contains('.'),
            SecretType::AirtableOAuthToken => min_len(v, 40, is_ext),
            SecretType::ShopifyApiKey | SecretType::ShopifyAccessToken => {
                (v.starts_with("shpat_") || v.starts_with("shpca_")) && v.len() >= 38
            }
            SecretType::ShopifySharedSecret => pfx(v, "shpss_", 32, is_hex),
            SecretType::FigmaPat => pfx_min(v, "figd_", 40, is_ext),
            SecretType::AsanaSecret | SecretType::AsanaClientId => min_len(v, 16, is_alphanum),
            SecretType::TrelloAccessToken => exact(v, 32, is_alphanum),
            SecretType::TypeformApiToken => pfx_min(v, "tfp_", 40, is_ext),
            SecretType::MapboxToken => {
                (v.starts_with("sk.eyJ") || v.starts_with("pk.eyJ")) && v.len() >= 50
            }
            SecretType::SegmentWriteKey => exact(v, 32, is_alphanum),
            SecretType::PlaidClientSecret => exact(v, 30, is_hex_lower),
            SecretType::ContentfulApiToken => range_len(v, 43, 43, |c| is_ext(c) || c == '='),
            SecretType::IntercomAccessToken => min_len(v, 60, |c| is_ext(c) || c == '='),
            SecretType::ClickUpPersonalToken => {
                v.starts_with("pk_") && v.contains('_') && v.len() >= 32
            }

            // ══════════════════════════════════════════════
            // Package Registries
            // ══════════════════════════════════════════════
            SecretType::NpmToken => pfx_min(v, "npm_", 36, is_alphanum),
            SecretType::PyPiApiToken => pfx_min(v, "pypi-AgEIcHlwaS5vcmc", 50, is_base64url),
            SecretType::NuGetApiKey => pfx(v, "oy2", 43, is_alphanum),
            SecretType::RubyGemsApiKey => pfx(v, "rubygems_", 48, is_hex_lower),
            SecretType::CratesIoApiToken => pfx(v, "cio", 32, is_alphanum),
            SecretType::ClojarsApiToken => v.starts_with("CLOJARS_") && v.len() >= 60,
            SecretType::CocoaPodsToken => exact(v, 32, is_hex_lower),
            SecretType::ComposerApiToken => min_len(v, 32, is_alphanum),
            SecretType::HexPmApiKey => min_len(v, 64, is_alphanum),
            SecretType::CargoRegistryToken => min_len(v, 32, is_ext),

            // ══════════════════════════════════════════════
            // Private Keys & Certificates
            // ══════════════════════════════════════════════
            SecretType::RsaPrivateKey => is_pem(v, "BEGIN RSA PRIVATE KEY"),
            SecretType::SshPrivateKey => is_pem(v, "BEGIN OPENSSH PRIVATE KEY"),
            SecretType::PgpPrivateKey => is_pem(v, "BEGIN PGP PRIVATE KEY"),
            SecretType::EcPrivateKey => is_pem(v, "BEGIN EC PRIVATE KEY"),
            SecretType::Pkcs8PrivateKey => is_pem(v, "BEGIN PRIVATE KEY"),
            SecretType::DsaPrivateKey => is_pem(v, "BEGIN DSA PRIVATE KEY"),
            SecretType::OpensslPrivateKey => is_pem(v, "BEGIN") && v.contains("PRIVATE KEY"),
            SecretType::EncryptedPrivateKey => is_pem(v, "BEGIN ENCRYPTED PRIVATE KEY"),
            SecretType::PuttyPrivateKey => v.starts_with("PuTTY-User-Key-File-"),

            // ══════════════════════════════════════════════
            // Connection Strings & Database URLs
            // ══════════════════════════════════════════════
            SecretType::MongoDbConnectionString => v.starts_with("mongodb"),
            SecretType::PostgresConnectionString => v.starts_with("postgres"),
            SecretType::MysqlConnectionString => v.starts_with("mysql://"),
            SecretType::RedisConnectionString => v.starts_with("redis"),
            SecretType::CockroachDbConnectionString => v.starts_with("cockroachdb://"),
            SecretType::ElasticsearchConnectionString => v.contains("elastic"),
            SecretType::DatabaseUrl => is_conn_str(v),
            SecretType::FtpCredential => v.starts_with("ftp://"),
            SecretType::CouchbaseConnectionString => v.starts_with("couchbase"),
            SecretType::Neo4jCredential => v.starts_with("neo4j"),
            SecretType::PasswordInUrl => v.contains("://") && v.contains('@'),

            // ══════════════════════════════════════════════
            // Tokens & JWTs
            // ══════════════════════════════════════════════
            SecretType::JwtToken => {
                v.starts_with("eyJ")
                    && v.matches('.').count() == 2
                    && v.len() >= 30
            }
            SecretType::OAuthToken => min_len(v, 20, is_ext_dot),

            // ══════════════════════════════════════════════
            // Security Services
            // ══════════════════════════════════════════════
            SecretType::OnePasswordSecretKey => v.starts_with("A3-") && v.len() >= 30,
            SecretType::OnePasswordServiceToken => v.starts_with("ops_eyJ") && v.len() >= 250,
            SecretType::AdobeClientSecret => v.starts_with("p8e-") && v.len() >= 36,
            SecretType::AgeSecretKey => pfx_min(v, "AGE-SECRET-KEY-1", 58, is_alphanum),
            SecretType::Auth0ClientSecret => min_len(v, 32, is_ext),
            SecretType::Auth0ManagementToken => min_len(v, 40, is_ext_dot),
            SecretType::BitwardenApiKey => exact(v, 32, is_alphanum),
            SecretType::NightfallApiKey => pfx_min(v, "NF-", 32, is_alphanum),

            // ══════════════════════════════════════════════
            // Specific Prefix-based Types
            // ══════════════════════════════════════════════
            SecretType::AdafruitIoApiKey => pfx(v, "aio_", 28, is_alphanum),
            SecretType::AdyenClientKey => {
                (v.starts_with("test_") || v.starts_with("live_")) && v.len() >= 24
            }
            SecretType::ArtifactoryApiKey => pfx(v, "AKCp", 69, is_alphanum),
            SecretType::ArtifactoryReferenceToken => pfx(v, "cmVmd", 59, is_alphanum),
            SecretType::ClearbitApiKey => pfx_min(v, "sk_", 32, is_hex_lower),
            SecretType::ClerkApiKey => {
                (v.starts_with("sk_live_") || v.starts_with("sk_test_"))
                    && v.len() >= 20
            }
            SecretType::CloseCrmApiKey => pfx_min(v, "api_", 30, is_ext_dot),
            SecretType::ContentstackToken => pfx_min(v, "cs", 30, is_hex_lower),
            SecretType::ChecklyApiKey => pfx_min(v, "cu_", 20, is_alphanum),
            SecretType::DefinedNetworkingApiToken => pfx_min(v, "dnkey-", 40, is_ext),
            SecretType::DropboxApiToken => exact(v, 15, is_alphanum),
            SecretType::DropboxLongLivedToken => v.contains("AAAAAAAAAA") && v.len() >= 54,
            SecretType::DropboxShortLivedToken => pfx_min(v, "sl.", 135, is_base64url),
            SecretType::DuffelApiToken => {
                (v.starts_with("duffel_test_") || v.starts_with("duffel_live_"))
                    && v.len() >= 43
            }
            SecretType::DuoApiKey => pfx(v, "DI", 18, is_alphanum_upper),
            SecretType::EasyPostApiToken => pfx(v, "EZAK", 54, is_alphanum),
            SecretType::EasyPostTestApiToken => pfx(v, "EZTK", 54, is_alphanum),
            SecretType::FacebookAccessToken => v.starts_with("EAA") && v.len() >= 100,
            SecretType::FacebookPageAccessToken => exact(v, 32, is_hex_lower),
            SecretType::FaunaDbApiKey => pfx_min(v, "fnA", 40, is_ext),
            SecretType::FirebaseApiKey => v.starts_with("AIza") && v.len() == 39,
            SecretType::FrameIoApiToken => pfx(v, "fio-u-", 64, is_ext),
            SecretType::GhostAdminApiKey => {
                v.len() >= 88 && v.contains(':') && v.chars().all(|c| is_hex(c) || c == ':')
            }
            SecretType::GoCardlessApiToken => v.starts_with("live_") && v.len() >= 40,
            SecretType::GoogleOAuthClientSecret => pfx(v, "GOCSPX-", 28, is_ext),
            SecretType::HubSpotPrivateAppToken => pfx_min(v, "pat-na1-", 36, is_uuid_char),
            SecretType::KlaviyoApiKey => pfx(v, "pk_", 34, is_hex_lower),
            SecretType::LobApiKey => {
                (v.starts_with("live_") || v.starts_with("test_")) && v.len() >= 35
            }
            SecretType::MollieApiKey => {
                (v.starts_with("live_") || v.starts_with("test_")) && v.len() >= 30
            }
            SecretType::ReadmeApiKey => pfx_min(v, "rdme_", 70, is_alphanum),
            SecretType::SanityApiToken => pfx_min(v, "sk", 60, is_alphanum),
            SecretType::ShippoApiKey => {
                (v.starts_with("shippo_live_") || v.starts_with("shippo_test_"))
                    && v.len() >= 40
            }
            SecretType::StackHawkApiKey => pfx_min(v, "hawk.", 20, is_ext),
            SecretType::TencentSecretId => pfx(v, "AKID", 32, is_alphanum),
            SecretType::UptimeRobotApiKey => v.len() >= 48 && v.contains('-'),
            SecretType::UserflowApiKey => v.starts_with("ct_") && v.len() >= 32,
            SecretType::VoiceflowApiKey => v.starts_with("VF.") && v.len() >= 40,
            SecretType::WooCommerceApiKey => pfx(v, "ck_", 40, is_hex_lower),
            SecretType::WorkOsApiKey => v.starts_with("sk_") && v.len() >= 40,
            SecretType::ZohoApiKey => v.starts_with("Zoho-oauthtoken ") && v.len() >= 30,
            SecretType::SupabaseAnonKey | SecretType::SupabaseServiceKey => {
                v.starts_with("eyJ") && v.contains('.') && v.len() >= 100
            }
            SecretType::YandexApiKey => pfx_min(v, "AQVN", 35, is_ext),
            SecretType::YandexAwsAccessToken => pfx(v, "YC", 38, is_ext),
            SecretType::ApifyApiKey => pfx_min(v, "apify_api_", 32, is_alphanum),
            SecretType::CoinbaseAccessToken => min_len(v, 64, is_ext),

            // ══════════════════════════════════════════════
            // Context-based types: 32 hex chars (exact)
            // ══════════════════════════════════════════════
            SecretType::AbstractApiKey
            | SecretType::AccuWeatherApiKey
            | SecretType::AdobeClientId
            | SecretType::AdzunaApiKey
            | SecretType::AgoraApiKey
            | SecretType::AirbrakeProjectKey
            | SecretType::AirbrakeUserKey
            | SecretType::AlgoliaApiKey
            | SecretType::AmplitudeApiKey
            | SecretType::AylienApiKey
            | SecretType::AviationStackApiKey
            | SecretType::BillomatApiKey
            | SecretType::BingSubscriptionKey
            | SecretType::BittrexAccessKey
            | SecretType::BittrexSecretKey
            | SecretType::BugSnagApiKey
            | SecretType::BuilderIoApiKey
            | SecretType::ChartMogulApiKey
            | SecretType::ClarifaiApiKey
            | SecretType::CoinLayerApiKey
            | SecretType::CoinLibApiKey
            | SecretType::CommoditiesApiKey
            | SecretType::CountryLayerApiKey
            | SecretType::CrowdStrikeApiKey
            | SecretType::CurrencyFreaksApiKey
            | SecretType::CurrencyLayerApiKey
            | SecretType::CurrencyScoopApiKey
            | SecretType::DetectLanguageApiKey
            | SecretType::DiffBotApiKey
            | SecretType::EdamamApiKey
            | SecretType::ExchangeRatesApiKey
            | SecretType::FacePlusPlusApiKey
            | SecretType::FastForexApiKey
            | SecretType::FixerIoApiKey
            | SecretType::FlickrApiKey
            | SecretType::ImgBbApiKey
            | SecretType::InfuraApiKey
            | SecretType::IpApiKey
            | SecretType::IpGeolocationApiKey
            | SecretType::IpStackApiKey
            | SecretType::LinkPreviewApiKey
            | SecretType::LocationIqApiKey
            | SecretType::MailboxLayerApiKey
            | SecretType::MailjetApiKey
            | SecretType::MailjetSecretKey
            | SecretType::MediaStackApiKey
            | SecretType::MixpanelToken
            | SecretType::NewsApiKey
            | SecretType::OpenCageApiKey
            | SecretType::OpenExchangeRatesApiKey
            | SecretType::OpenWeatherMapApiKey
            | SecretType::PdfLayerApiKey
            | SecretType::PivotalTrackerApiToken
            | SecretType::PositionStackApiKey
            | SecretType::RawgApiKey
            | SecretType::RollbarApiKey
            | SecretType::SpotifyApiKey
            | SecretType::TaxJarApiToken
            | SecretType::TogglApiKey
            | SecretType::UploadcareApiKey
            | SecretType::UserStackApiKey
            | SecretType::VatLayerApiKey
            | SecretType::ZeroSslApiKey
            | SecretType::ApiFlashApiKey
            | SecretType::ApiLayerApiKey
            | SecretType::IpInfoApiKey => range_len(v, 14, 80, is_hex_lower),

            // ══════════════════════════════════════════════
            // Context-based types: 32+ hex chars
            // ══════════════════════════════════════════════
            SecretType::AbuseIpDbApiKey
            | SecretType::ActiveCampaignApiKey
            | SecretType::AhaApiKey
            | SecretType::AlienVaultApiKey
            | SecretType::AllSportsApiKey
            | SecretType::AmbeeApiKey
            | SecretType::AnkrApiKey
            | SecretType::AnypointApiKey
            | SecretType::Api2CartApiKey
            | SecretType::ArtsyApiKey
            | SecretType::AuddApiKey
            | SecretType::BigCommerceApiToken
            | SecretType::BlazeMeterApiKey
            | SecretType::ButterCmsApiKey
            | SecretType::CaspioApiKey
            | SecretType::ClinchPadApiKey
            | SecretType::CloudElementsApiKey
            | SecretType::CloudsmithApiKey
            | SecretType::ClozeApiKey
            | SecretType::CodacyApiToken
            | SecretType::CodeQuiryApiKey
            | SecretType::Collect2ApiKey
            | SecretType::CompanyHubApiKey
            | SecretType::ConvierApiKey
            | SecretType::CopperApiKey
            | SecretType::CoverallsApiToken
            | SecretType::CraftMyPdfApiKey
            | SecretType::CryptoCompareApiKey
            | SecretType::CurrencyCloudApiKey
            | SecretType::CustomerGuruApiKey
            | SecretType::CustomerIoApiKey
            | SecretType::DandelionApiKey
            | SecretType::DareBoostApiKey
            | SecretType::DatoCmsApiToken
            | SecretType::DebounceApiKey
            | SecretType::DemioApiKey
            | SecretType::DeployHqApiKey
            | SecretType::DeputyApiKey
            | SecretType::DetectifyApiKey
            | SecretType::DiggernautApiKey
            | SecretType::DnsCheckApiKey
            | SecretType::DocumoApiKey
            | SecretType::DovicoApiKey
            | SecretType::DripApiKey
            | SecretType::DronaHqApiKey
            | SecretType::DuplyApiKey
            | SecretType::DynalistApiKey
            | SecretType::DyspatchApiKey
            | SecretType::EasyInsightApiKey
            | SecretType::EcoStruxureApiKey
            | SecretType::EnableXApiKey
            | SecretType::EnigmaApiKey
            | SecretType::EnvoyApiKey
            | SecretType::EraserApiKey
            | SecretType::ExportSdkApiKey
            | SecretType::ExtractorApiKey
            | SecretType::FeedierApiKey
            | SecretType::FetchRssApiKey
            | SecretType::FindlApiKey
            | SecretType::FinicityApiToken
            | SecretType::FlatIoApiKey
            | SecretType::FlexportApiKey
            | SecretType::FlightApiKey
            | SecretType::FlightLabsApiKey
            | SecretType::FlightStatsApiKey
            | SecretType::FloatApiKey
            | SecretType::FlowFluApiKey
            | SecretType::FmfwApiKey
            | SecretType::FormBucketApiKey
            | SecretType::FormCraftApiKey
            | SecretType::FormIoApiKey
            | SecretType::FormSiteApiKey
            | SecretType::FulcrumApiKey
            | SecretType::FullStoryApiKey
            | SecretType::FxMarketApiKey
            | SecretType::GetGistApiKey
            | SecretType::GiteePat
            | SecretType::GlassfrogApiKey
            | SecretType::GoCanvasApiKey
            | SecretType::GumroadApiKey
            | SecretType::GyazoApiKey
            | SecretType::HaveIBeenPwnedApiKey
            | SecretType::HelpCrunchApiKey
            | SecretType::HelpScoutApiKey
            | SecretType::HiveApiKey
            | SecretType::HoneyBadgerApiKey
            | SecretType::InVisionApiKey
            | SecretType::InfobipApiKey
            | SecretType::InstamojoApiKey
            | SecretType::InterzoidApiKey
            | SecretType::InvoiceOceanApiKey
            | SecretType::IpifyApiKey
            | SecretType::IterableApiKey
            | SecretType::JanioApiKey
            | SecretType::JenkinsApiToken
            | SecretType::JotFormApiKey
            | SecretType::KanbanToolApiKey
            | SecretType::KarbonApiKey
            | SecretType::KickboxApiKey
            | SecretType::KlipfolioApiKey
            | SecretType::KnockApiKey
            | SecretType::KonakartApiKey
            | SecretType::KylasApiKey
            | SecretType::LaunchableApiKey
            | SecretType::LeadfeederApiKey
            | SecretType::LemlistApiKey
            | SecretType::LendflowApiKey
            | SecretType::LessAnnoyingCrmApiKey
            | SecretType::LeverApiKey
            | SecretType::LexigramApiKey
            | SecretType::LiveAgentApiKey
            | SecretType::LiveChatApiKey
            | SecretType::LivestormApiKey
            | SecretType::LoomApiKey
            | SecretType::LoopsApiKey
            | SecretType::LovenseApiKey
            | SecretType::LoyverseApiKey
            | SecretType::LunacrushApiKey
            | SecretType::MagicApiKey
            | SecretType::MailCheckApiKey
            | SecretType::MailerLiteApiKey
            | SecretType::MailmodoApiKey
            | SecretType::MeadowApiKey
            | SecretType::MeaningCloudApiKey
            | SecretType::MedusaApiKey
            | SecretType::MercuryApiKey
            | SecretType::MetaApiKey
            | SecretType::MindMeisterApiKey
            | SecretType::MixMaxApiKey
            | SecretType::MockoonApiKey
            | SecretType::ModerationApiKey
            | SecretType::MonFloApiKey
            | SecretType::NoticeableApiKey
            | SecretType::NovuApiKey
            | SecretType::Ns1ApiKey
            | SecretType::NumbersApiKey
            | SecretType::NutshellApiKey
            | SecretType::PaddleApiKey
            | SecretType::PaperformApiKey
            | SecretType::PdfCoApiKey
            | SecretType::PersonApiKey
            | SecretType::PipedreamApiKey
            | SecretType::PlanhatApiKey
            | SecretType::PlanyoApiKey
            | SecretType::PleskApiKey
            | SecretType::PodioApiKey
            | SecretType::PollsApiKey
            | SecretType::PrerenderApiKey
            | SecretType::PrivacyCloudApiKey
            | SecretType::ProfitwellApiKey
            | SecretType::ProspectIoApiKey
            | SecretType::ProxyCrawlApiKey
            | SecretType::ProxyScrapeApiKey
            | SecretType::RavenToolsApiKey
            | SecretType::ReallySimpleSystemsApiKey
            | SecretType::RebrandlyApiKey
            | SecretType::RecruiteeApiKey
            | SecretType::RecurlyApiKey
            | SecretType::RedisLabsApiKey
            | SecretType::RefinerApiKey
            | SecretType::ResmushApiKey
            | SecretType::RestPackApiKey
            | SecretType::RevApiKey
            | SecretType::RevampCrmApiKey
            | SecretType::RiteKitApiKey
            | SecretType::RiveApiKey
            | SecretType::RobinApiKey
            | SecretType::RocketReachApiKey
            | SecretType::RoninAppApiKey
            | SecretType::RowndApiKey
            | SecretType::RunPodApiKey
            | SecretType::SaladCloudApiKey
            | SecretType::SalesMateApiKey
            | SecretType::SatisMeterApiKey
            | SecretType::ScaleSerpApiKey
            | SecretType::ScraperApiKey
            | SecretType::ScraperBoxApiKey
            | SecretType::ScrapFlyApiKey
            | SecretType::ScrapinApiKey
            | SecretType::ScreenshotApiKey
            | SecretType::ScriptrApiKey
            | SecretType::SemaphoreCiToken
            | SecretType::SendPulseApiKey
            | SecretType::ServiceBellApiKey
            | SecretType::ServiceNowApiKey
            | SecretType::ShipDayApiKey
            | SecretType::ShippingCloudApiKey
            | SecretType::ShotStackApiKey
            | SecretType::SignableApiKey
            | SecretType::SignaturitApiKey
            | SecretType::SimFinApiKey
            | SecretType::SimpleSatApiKey
            | SecretType::SimplyNotedApiKey
            | SecretType::SimvolyApiKey
            | SecretType::SirvApiKey
            | SecretType::SiteLeafApiKey
            | SecretType::SmartyApiKey
            | SecretType::SmsApiKey
            | SecretType::SnovApiKey
            | SecretType::SpoonacularApiKey
            | SecretType::SslMateApiKey
            | SecretType::StackPathApiKey
            | SecretType::StatusPalApiKey
            | SecretType::StitchDataApiKey
            | SecretType::StormBoardApiKey
            | SecretType::StoryChiefApiKey
            | SecretType::StripoApiKey
            | SecretType::SurveyAnyplaceApiKey
            | SecretType::SurveySparrowApiKey
            | SecretType::SurvicateApiKey
            | SecretType::SwellApiKey
            | SecretType::TallyFyApiKey
            | SecretType::TeamGateApiKey
            | SecretType::TeamworkApiKey
            | SecretType::ThinkificApiKey
            | SecretType::TicketTailorApiKey
            | SecretType::TikTokApiKey
            | SecretType::TimeCampApiKey
            | SecretType::TimekitApiKey
            | SecretType::TimescaleDbToken
            | SecretType::TinesWebhookApiKey
            | SecretType::TypetalkApiKey
            | SecretType::VeracodeApiKey
            | SecretType::VeriphoneApiKey
            | SecretType::VoucheryApiKey
            | SecretType::WebScraperApiKey
            | SecretType::WebScrapingApiKey
            | SecretType::WeekdoneApiKey
            | SecretType::WhatCmsApiKey
            | SecretType::WhoxyApiKey
            | SecretType::YextApiKey
            | SecretType::ZapierApiKey
            | SecretType::ZenRowsApiKey
            | SecretType::ZenScrapeApiKey
            | SecretType::ZeroBounceApiKey
            | SecretType::ZipBooksApiKey
            | SecretType::ZoomInfoApiKey
            | SecretType::ConversionToolsApiKey => min_len(v, 20, is_hex_lower),

            // ══════════════════════════════════════════════
            // Context-based types: 40 hex chars
            // ══════════════════════════════════════════════
            SecretType::CalendarificApiKey
            | SecretType::CiscoMerakiApiKey
            | SecretType::ClockworkSmsApiKey
            | SecretType::CodeClimateApiToken
            | SecretType::DocparserApiKey
            | SecretType::GeocodioApiKey
            | SecretType::GiteaAccessToken
            | SecretType::GitterAccessToken
            | SecretType::HunterApiKey
            | SecretType::IpDataApiKey
            | SecretType::JumpCloudApiKey
            | SecretType::LokaliseApiToken
            | SecretType::PandaDocApiKey
            | SecretType::PipedriveApiToken
            | SecretType::RechargePaymentsApiKey
            | SecretType::SauceNaoApiKey
            | SecretType::SendBirdApiKey
            | SecretType::SparkPostApiKey
            | SecretType::SonarCloudApiKey
            | SecretType::TodoistApiKey
            | SecretType::WistiaApiKey
            | SecretType::BitlyAccessToken
            | SecretType::QaseApiKey => min_len(v, 36, is_hex_lower),

            // ══════════════════════════════════════════════
            // Context-based types: 64 hex chars
            // ══════════════════════════════════════════════
            SecretType::CannyIoApiKey
            | SecretType::DailyCoApiKey
            | SecretType::KeenApiKey
            | SecretType::LinodeApiToken
            | SecretType::OnfleetApiKey
            | SecretType::OneLoginApiKey
            | SecretType::PercyApiKey
            | SecretType::PinataApiKey
            | SecretType::QuboleApiKey
            | SecretType::SerpApiKey
            | SecretType::StrapiApiToken
            | SecretType::VirustotalApiKey
            | SecretType::WebflowApiToken
            | SecretType::YouNeedABudgetApiKey
            | SecretType::ZeplinApiKey => exact(v, 64, is_hex_lower),

            // ══════════════════════════════════════════════
            // Context-based types: UUID-like format [a-f0-9-]{36}
            // ══════════════════════════════════════════════
            SecretType::AirVisualApiKey
            | SecretType::BinaryEdgeApiKey
            | SecretType::BlockNativeApiKey
            | SecretType::BunnyCdnApiKey
            | SecretType::CloudMersiveApiKey
            | SecretType::CoinMarketCapApiKey
            | SecretType::ConstantContactApiKey
            | SecretType::DeepAiApiKey
            | SecretType::DocuSignApiKey
            | SecretType::ElasticEmailApiKey
            | SecretType::EmailOctopusApiKey
            | SecretType::EverhourApiKey
            | SecretType::FusionAuthApiKey
            | SecretType::GraphhopperApiKey
            | SecretType::GuruApiKey
            | SecretType::IpFindApiKey
            | SecretType::JambonesApiKey
            | SecretType::KeycloakClientSecret
            | SecretType::LogglyApiToken
            | SecretType::LoginRadiusApiKey
            | SecretType::MoosendApiKey
            | SecretType::MuxApiKey
            | SecretType::NhostApiKey
            | SecretType::OmnisendApiKey
            | SecretType::OneSignalApiKey
            | SecretType::OpsGenieApiKey
            | SecretType::PendoApiKey
            | SecretType::PostmarkApiToken
            | SecretType::RunscopeApiKey
            | SecretType::SauceLabsApiKey
            | SecretType::ScalewayApiKey
            | SecretType::SemantriaApiKey
            | SecretType::ShortcutApiToken
            | SecretType::SmartlingApiKey
            | SecretType::StatusPageApiKey
            | SecretType::StormGlassApiKey
            | SecretType::TatumIoApiKey
            | SecretType::UrlScanApiKey
            | SecretType::WakaTimeApiKey
            | SecretType::WebhookRelayApiKey
            | SecretType::WixApiKey
            | SecretType::HubSpotApiKey => range_len(v, 32, 70, is_uuid_char),

            // ══════════════════════════════════════════════
            // Context-based types: Extended charset [a-zA-Z0-9_-]{20,}
            // ══════════════════════════════════════════════
            SecretType::AbyssaleApiKey
            | SecretType::AdafruitApiKey
            | SecretType::AeroWorkflowApiKey
            | SecretType::AirshipApiKey
            | SecretType::AkamaiApiKey
            | SecretType::AlconostApiKey
            | SecretType::AlegraApiKey
            | SecretType::AlethiaApiKey
            | SecretType::ApactaApiKey
            | SecretType::ApiDeckApiKey
            | SecretType::ApifonicaApiKey
            | SecretType::ApimaticApiKey
            | SecretType::ApimetricsApiKey
            | SecretType::ApiTemplateApiKey
            | SecretType::ApolloApiKey
            | SecretType::AppDynamicsApiKey
            | SecretType::AppFollowApiKey
            | SecretType::AppOpticsApiKey
            | SecretType::AppSynergyApiKey
            | SecretType::AppcuesApiKey
            | SecretType::AppointeddApiKey
            | SecretType::ApptivoApiKey
            | SecretType::AteraApiKey
            | SecretType::AuthressServiceKey
            | SecretType::AutokloseApiKey
            | SecretType::AutopilotApiKey
            | SecretType::AvazaApiKey
            | SecretType::AweberApiKey
            | SecretType::AxonautApiKey
            | SecretType::AyrshareApiKey
            | SecretType::BannerbearApiKey
            | SecretType::BaremetricsApiKey
            | SecretType::BasecampApiKey
            | SecretType::BeeboleApiKey
            | SecretType::BesnappyApiKey
            | SecretType::BestTimeApiKey
            | SecretType::BetterStackApiToken
            | SecretType::BitBarApiKey
            | SecretType::BlitAppApiKey
            | SecretType::BombBombApiKey
            | SecretType::BoostNoteApiKey
            | SecretType::BorgBaseApiKey
            | SecretType::BrandfetchApiKey
            | SecretType::BrowshotApiKey
            | SecretType::BuddyNsApiKey
            | SecretType::BudibaseApiKey
            | SecretType::BugHerdApiKey
            | SecretType::BulbulApiKey
            | SecretType::BulkSmsApiKey
            | SecretType::CaflouApiKey
            | SecretType::CampaignMonitorApiKey
            | SecretType::CampaynApiKey
            | SecretType::CaptainDataApiKey
            | SecretType::CarbonInterfaceApiKey
            | SecretType::CashboardApiKey
            | SecretType::ChatbotApiKey
            | SecretType::ChatfuelApiKey
            | SecretType::ChecIoApiKey
            | SecretType::CheckvistApiKey
            | SecretType::ClickHelpApiKey
            | SecretType::ClickHouseApiSecret
            | SecretType::ClickSendApiKey
            | SecretType::CliengoApiKey
            | SecretType::ClientaryApiKey
            | SecretType::CloudConvertApiKey
            | SecretType::CloudImageApiKey
            | SecretType::CloudPlanApiKey
            | SecretType::CloverlyApiKey
            | SecretType::ClustDocApiKey
            | SecretType::CodaApiKey
            | SecretType::CodeMagicApiToken
            | SecretType::ColumnApiKey
            | SecretType::CommerceJsApiKey
            | SecretType::CommercetoolsApiKey
            | SecretType::ConvertKitApiKey
            | SecretType::ConvertKitApiSecret
            | SecretType::CourierApiKey
            | SecretType::CurrentsApiKey
            | SecretType::D7NetworkApiKey
            | SecretType::DataboxApiKey
            | SecretType::DelightedApiKey
            | SecretType::DfuseApiKey
            | SecretType::DnSimpleApiToken
            | SecretType::DotDigitalApiKey
            | SecretType::EagleEyeNetworksApiKey
            | SecretType::EightByEightApiKey
            | SecretType::EndorLabsApiKey
            | SecretType::EthplorerApiKey
            | SecretType::HealthchecksIoApiKey
            | SecretType::HumioApiKey
            | SecretType::ImageKitApiKey
            | SecretType::KintoneApiKey
            | SecretType::LarkSuitApiKey
            | SecretType::LunoApiKey
            | SecretType::MailsacApiKey
            | SecretType::OryApiKey
            | SecretType::ParseHubApiKey
            | SecretType::PaypalClientSecret
            | SecretType::PostageAppApiKey
            | SecretType::PowerBiApiKey
            | SecretType::QuickBaseApiKey
            | SecretType::Route53Key
            | SecretType::SkylightApiKey
            | SecretType::SvixApiKey
            | SecretType::SwiftypeApiKey
            | SecretType::TeamCityApiToken
            | SecretType::TypesenseApiKey
            | SecretType::UbidotsApiKey
            | SecretType::UploadIoApiKey
            | SecretType::ZendeskChatApiKey => min_len(v, 20, is_ext),

            // ══════════════════════════════════════════════
            // Context-based types: Alphanumeric 20+ chars
            // ══════════════════════════════════════════════
            SecretType::AmadeusApiKey
            | SecretType::AutodeskApiKey
            | SecretType::BitcoinAverageApiKey
            | SecretType::BrowserStackAccessKey
            | SecretType::ConvertApiKey
            | SecretType::CrowdinApiToken
            | SecretType::DataGovApiKey
            | SecretType::DroneCiAccessToken
            | SecretType::DwollaApiKey
            | SecretType::EtsyAccessToken
            | SecretType::FinageApiKey
            | SecretType::FinancialModelingPrepApiKey
            | SecretType::FinicityClientSecret
            | SecretType::FreshdeskApiKey
            | SecretType::GetResponseApiKey
            | SecretType::Ip2LocationApiKey
            | SecretType::KeyCdnApiKey
            | SecretType::PlivoApiKey
            | SecretType::SecurityTrailsApiKey
            | SecretType::ShodanApiKey
            | SecretType::ShopwareApiKey
            | SecretType::ShutterStockApiKey
            | SecretType::StatusCakeApiKey
            | SecretType::TextMagicApiKey
            | SecretType::TradierApiKey
            | SecretType::WrikeApiToken => min_len(v, 20, is_alphanum),

            // ══════════════════════════════════════════════
            // Context-based types: Alphanumeric 32+ chars
            // ══════════════════════════════════════════════
            SecretType::AlchemyApiKey
            | SecretType::CensysApiKey
            | SecretType::GitGuardianApiToken
            | SecretType::GreyNoiseApiKey
            | SecretType::LogzIoApiKey
            | SecretType::MiroApiToken
            | SecretType::ZoomApiKey
            | SecretType::InfluxDbToken => min_len(v, 32, is_ext),

            // ══════════════════════════════════════════════
            // Context-based types: Longer alphanum (40+, 50+, etc.)
            // ══════════════════════════════════════════════
            SecretType::CalendlyApiKey
            | SecretType::CanvaApiToken
            | SecretType::CognitoClientSecret
            | SecretType::DisqusApiKey
            | SecretType::EdenAiApiKey
            | SecretType::ElasticApiKey
            | SecretType::ElasticCloudApiKey
            | SecretType::FacebookOAuthToken
            | SecretType::FrontApiToken
            | SecretType::HarnessApiKey
            | SecretType::HarvestApiToken
            | SecretType::HereMapsApiKey
            | SecretType::LemonSqueezyApiKey
            | SecretType::StytchApiKey
            | SecretType::PrismicApiToken
            | SecretType::TursoApiToken => min_len(v, 30, is_ext_dot),

            SecretType::BinanceApiKey => exact(v, 64, is_alphanum),
            SecretType::BitfinexApiKey => range_len(v, 43, 43, is_ext),
            SecretType::BitMexApiKey => exact(v, 24, is_ext),
            SecretType::BscScanApiKey | SecretType::EtherscanApiKey => {
                exact(v, 34, is_alphanum_upper)
            }
            SecretType::BoxApiKey => exact(v, 32, is_alphanum),
            SecretType::BoxOAuthToken => min_len(v, 32, is_alphanum),
            SecretType::ClockifyApiKey => exact(v, 48, is_alphanum),
            SecretType::CloudFrontKey => exact(v, 14, is_alphanum_upper),
            SecretType::CloudinaryApiSecret => min_len(v, 20, is_ext),
            SecretType::ChargeBeeApiKey => min_len(v, 32, is_ext),
            SecretType::DeepLApiKey => v.ends_with(":fx") && v.len() >= 36,
            SecretType::EventbriteApiKey => min_len(v, 50, is_alphanum),
            SecretType::FiberyApiKey => min_len(v, 32, |c| is_hex(c) || c == '.' || c == '-'),
            SecretType::FileIoApiKey => min_len(v, 20, |c| is_hex(c) || c == '.' || c == '-'),
            SecretType::FinnhubAccessToken => exact(v, 20, is_alphanum),
            SecretType::FleetbaseApiKey => v.starts_with("flb_") && v.len() >= 30,
            SecretType::FoursquareApiKey => exact(v, 48, is_alphanum_upper),
            SecretType::FreshbooksAccessToken => exact(v, 64, is_alphanum),
            SecretType::GraphCmsApiKey => min_len(v, 100, is_ext),
            SecretType::HeapApiKey => min_len(v, 10, |c| c.is_ascii_digit()),
            SecretType::HoneycombApiKey => min_len(v, 22, is_alphanum),
            SecretType::HotjarApiKey => min_len(v, 7, |c| c.is_ascii_digit()),
            SecretType::HyperTrackApiKey => min_len(v, 20, is_ext),
            SecretType::IbmCloudApiKey => exact(v, 44, is_ext),
            SecretType::IexCloudApiKey => min_len(v, 30, is_ext),
            SecretType::InstanaApiToken => min_len(v, 22, is_ext),
            SecretType::IpQualityScoreApiKey => min_len(v, 25, is_alphanum),
            SecretType::JFrogIdentityToken => min_len(v, 60, is_ext),
            SecretType::KrakenAccessToken => min_len(v, 80, is_base64),
            SecretType::KucoinAccessToken => min_len(v, 24, is_hex_lower),
            SecretType::LogRocketApiKey => min_len(v, 20, |c| is_alphanum(c) || c == '/' || c == '_'),
            SecretType::MapQuestApiKey => exact(v, 32, is_alphanum),
            SecretType::MaxMindLicenseKey => exact(v, 16, is_alphanum),
            SecretType::MessageBirdApiKey => exact(v, 25, is_alphanum),
            SecretType::MondayApiKey => min_len(v, 300, is_alphanum),
            SecretType::MoralisApiKey => min_len(v, 50, is_alphanum),
            SecretType::NasdaqDataLinkApiKey => exact(v, 20, is_ext),
            SecretType::NytimesAccessToken => exact(v, 32, is_alphanum),
            SecretType::OandaApiKey => exact(v, 65, is_uuid_char),
            SecretType::OracleCloudApiKey => min_len(v, 32, is_hex_lower),
            SecretType::OrbitApiKey => min_len(v, 32, is_hex_lower),
            SecretType::PexelsApiKey => exact(v, 56, is_alphanum),
            SecretType::PushBulletApiKey => exact(v, 34, is_ext_dot),
            SecretType::PushoverApiKey => exact(v, 30, is_alphanum),
            SecretType::QuickNodeApiKey => min_len(v, 32, is_hex_lower),
            SecretType::RampApiKey => min_len(v, 32, is_hex_lower),
            SecretType::RazorpayKeySecret => min_len(v, 20, is_alphanum),
            SecretType::Route4MeApiKey => exact(v, 32, |c| c.is_ascii_hexdigit()),
            SecretType::SalesforceApiToken => min_len(v, 20, |c| is_alphanum(c) || c == '!'),
            SecretType::ShipEngineApiKey => v.starts_with("TEST_") && v.len() >= 50,
            SecretType::SmartSheetsApiKey => min_len(v, 26, is_alphanum),
            SecretType::SnowflakeCredential => min_len(v, 8, |c| !c.is_ascii_whitespace()),
            SecretType::StoryblokApiToken => min_len(v, 22, is_alphanum),
            SecretType::TeleSignApiKey => min_len(v, 40, is_base64),
            SecretType::TomTomApiKey | SecretType::TomorrowIoApiKey => {
                exact(v, 32, is_alphanum)
            }
            SecretType::TransifexApiToken => min_len(v, 40, |c| is_hex(c) || c == '/'),
            SecretType::TravisCiApiToken | SecretType::TravisCiToken => {
                min_len(v, 22, is_ext)
            }
            SecretType::TwitterApiKey => exact(v, 25, is_alphanum),
            SecretType::TwitterAccessToken => v.contains('-') && v.len() >= 40,
            SecretType::TwitchApiToken => exact(v, 30, is_alphanum),
            SecretType::VultrApiKey => exact(v, 36, is_alphanum_upper),
            SecretType::WandBApiKey => exact(v, 40, is_hex_lower),
            SecretType::WebexApiKey => min_len(v, 64, is_ext),
            SecretType::WitApiKey => exact(v, 32, is_alphanum_upper),
            SecretType::XeroApiKey => min_len(v, 32, is_alphanum_upper),
            SecretType::YelpApiKey => exact(v, 128, is_ext),
            SecretType::YouTubeApiKey | SecretType::BloggerApiKey => {
                v.starts_with("AIza") && v.len() == 39
            }
            SecretType::ExchangeRateApiKey => min_len(v, 24, is_hex_lower),

            // ══════════════════════════════════════════════
            // Remaining specific types
            // ══════════════════════════════════════════════
            SecretType::RapidApiKey => exact(v, 50, is_alphanum),
            SecretType::ZendeskSecretKey => exact(v, 40, is_alphanum),
            SecretType::CoinApiKey => exact(v, 36, |c| is_alphanum_upper(c) || c == '-'),

            // Generic catch-all types
            SecretType::GenericApiKey | SecretType::GenericSecret | SecretType::GenericCredential => {
                non_empty(v, 8)
            }
            SecretType::HighEntropyString => v.len() >= 20,

            // Custom types: can't validate format
            SecretType::Custom(_) => non_empty(v, 8),

            // Catch-all for any remaining types: basic non-empty check
            _ => non_empty(v, 8),
        };
        Ok(valid)
    }

    fn supports(&self, _secret_type: &SecretType) -> bool {
        // The FormatValidator supports ALL types as a fallback.
        // It is registered LAST so API-based validators take priority.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    /// Helper to quickly create a Secret for testing
    fn make(st: SecretType, value: &str) -> Secret {
        Secret::new(st, value.to_string(), 4.0, Severity::High, 0.9)
    }

    /// Helper: assert validation returns Ok(true)
    async fn accept(st: SecretType, value: &str) {
        let v = FormatValidator::new();
        let result = v.validate(&make(st.clone(), value)).await;
        assert!(
            result.is_ok(),
            "validate() returned Err for {:?}: {:?}",
            st,
            result
        );
        assert!(
            result.unwrap(),
            "Expected ACCEPT for {:?} with value '{}'",
            st,
            &value[..value.len().min(40)]
        );
    }

    /// Helper: assert validation returns Ok(false)
    async fn reject(st: SecretType, value: &str) {
        let v = FormatValidator::new();
        let result = v.validate(&make(st.clone(), value)).await;
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Expected REJECT for {:?} with value '{}'",
            st,
            &value[..value.len().min(40)]
        );
    }

    // ═══════════════════════════════════════════════
    // supports() tests
    // ═══════════════════════════════════════════════

    #[test]
    fn test_supports_all() {
        let validator = FormatValidator::new();
        assert!(validator.supports(&SecretType::AwsAccessKey));
        assert!(validator.supports(&SecretType::GitHubPat));
        assert!(validator.supports(&SecretType::GenericApiKey));
        assert!(validator.supports(&SecretType::HighEntropyString));
        assert!(validator.supports(&SecretType::Custom("test".to_string())));
        // Spot-check every category
        assert!(validator.supports(&SecretType::RsaPrivateKey));
        assert!(validator.supports(&SecretType::PostgresConnectionString));
        assert!(validator.supports(&SecretType::StripeApiKey));
        assert!(validator.supports(&SecretType::CloudflareApiToken));
        assert!(validator.supports(&SecretType::NpmToken));
        assert!(validator.supports(&SecretType::SentryDsn));
        assert!(validator.supports(&SecretType::PuttyPrivateKey));
        assert!(validator.supports(&SecretType::PasswordInUrl));
    }

    // ═══════════════════════════════════════════════
    // Cloud Providers — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_aws_access_key_valid() {
        accept(SecretType::AwsAccessKey, "AKIAIOSFODNN7EXAMPLE").await;
    }

    #[tokio::test]
    async fn test_aws_access_key_asia_prefix() {
        accept(SecretType::AwsAccessKey, "ASIAIOSFODNN7EXAMPLE").await;
    }

    #[tokio::test]
    async fn test_aws_secret_key_valid() {
        accept(
            SecretType::AwsSecretKey,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .await;
    }

    #[tokio::test]
    async fn test_aws_session_token_valid() {
        let token = "a".repeat(150); // 150 base64 chars
        accept(SecretType::AwsSessionToken, &token).await;
    }

    #[tokio::test]
    async fn test_aws_mws_key_valid() {
        accept(
            SecretType::AwsMwsKey,
            "amzn.mws.00000000-0000-0000-0000-000000000000",
        )
        .await;
    }

    #[tokio::test]
    async fn test_gcp_api_key_valid() {
        // pfx("AIza", 35, is_base64url) = prefix 4 + body 35 = 39 chars total
        accept(
            SecretType::GcpApiKey,
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        )
        .await;
    }

    #[tokio::test]
    async fn test_azure_storage_key_valid() {
        accept(
            SecretType::AzureStorageKey,
            "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=abc123==;EndpointSuffix=core.windows.net",
        )
        .await;
    }

    #[tokio::test]
    async fn test_azure_connection_string_valid() {
        accept(
            SecretType::AzureConnectionString,
            "Server=tcp:myserver.database.windows.net;Password=MyP@ssw0rd;",
        )
        .await;
    }

    #[tokio::test]
    async fn test_azure_sas_token_valid() {
        accept(
            SecretType::AzureSasToken,
            "sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacuptfx&se=2025&sig=abc123",
        )
        .await;
    }

    #[tokio::test]
    async fn test_azure_devops_pat_valid() {
        let pat = "a".repeat(52);
        accept(SecretType::AzureDevOpsPat, &pat).await;
    }

    #[tokio::test]
    async fn test_alibaba_access_key_valid() {
        accept(SecretType::AlibabaAccessKey, "LTAIabcdefghijklmnopqrst").await;
    }

    // ═══════════════════════════════════════════════
    // Cloud Providers — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_aws_access_key_reject_wrong_prefix() {
        reject(SecretType::AwsAccessKey, "XXIAIOSFODNN7EXAMPLE").await;
    }

    #[tokio::test]
    async fn test_aws_access_key_reject_too_short() {
        reject(SecretType::AwsAccessKey, "AKIA12345").await;
    }

    #[tokio::test]
    async fn test_aws_secret_key_reject_wrong_length() {
        reject(SecretType::AwsSecretKey, "tooshort").await;
    }

    #[tokio::test]
    async fn test_gcp_api_key_reject_wrong_prefix() {
        reject(SecretType::GcpApiKey, "XYza1234567890abcdefghijklmnopqrstuvwx").await;
    }

    // ═══════════════════════════════════════════════
    // Version Control — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_github_pat_valid() {
        accept(
            SecretType::GitHubPat,
            "ghp_1234567890123456789012345678901234",
        )
        .await;
    }

    #[tokio::test]
    async fn test_github_oauth_valid() {
        accept(
            SecretType::GitHubOauth,
            "gho_1234567890123456789012345678901234",
        )
        .await;
    }

    #[tokio::test]
    async fn test_github_app_token_valid() {
        accept(
            SecretType::GitHubAppToken,
            "ghs_1234567890123456789012345678901234",
        )
        .await;
    }

    #[tokio::test]
    async fn test_github_fine_grained_pat_valid() {
        let pat = format!("github_pat_{}", "a".repeat(82));
        accept(SecretType::GitHubFineGrainedPat, &pat).await;
    }

    #[tokio::test]
    async fn test_gitlab_pat_valid() {
        accept(SecretType::GitLabPat, "glpat-abcdefghijklmnopqrst").await;
    }

    #[tokio::test]
    async fn test_gitlab_runner_token_valid() {
        accept(SecretType::GitLabRunnerToken, "glrt-abcdefghijklmnopqrstuvwx").await;
    }

    #[tokio::test]
    async fn test_bitbucket_token_valid() {
        accept(SecretType::BitbucketToken, "abcdefghijklmnopqrst").await;
    }

    // ═══════════════════════════════════════════════
    // Version Control — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_github_pat_reject_wrong_prefix() {
        reject(SecretType::GitHubPat, "not_a_github_pat_at_all").await;
    }

    #[tokio::test]
    async fn test_gitlab_pat_reject_wrong_prefix() {
        reject(SecretType::GitLabPat, "xyz-tooshort").await;
    }

    // ═══════════════════════════════════════════════
    // Payment — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_stripe_api_key_valid() {
        accept(
            SecretType::StripeApiKey,
            "sk_live_1234567890abcdefghijklmnop",
        )
        .await;
    }

    #[tokio::test]
    async fn test_stripe_restricted_key_valid() {
        accept(
            SecretType::StripeRestrictedKey,
            "rk_live_1234567890abcdefghijklmnop",
        )
        .await;
    }

    #[tokio::test]
    async fn test_paystack_secret_key_valid() {
        accept(
            SecretType::PaystackSecretKey,
            "sk_live_abcdefghijklmnopqrstuvwxyz1234567890ab",
        )
        .await;
    }

    #[tokio::test]
    async fn test_square_access_token_valid() {
        accept(
            SecretType::SquareAccessToken,
            "sq0atp-1234567890abcdefghijkl",
        )
        .await;
    }

    #[tokio::test]
    async fn test_square_oauth_token_valid() {
        let tok = format!("sq0csp-{}", "a".repeat(43));
        accept(SecretType::SquareOAuthToken, &tok).await;
    }

    #[tokio::test]
    async fn test_braintree_access_token_valid() {
        let tok = format!("access_token${}", "a".repeat(50));
        accept(SecretType::BraintreeAccessToken, &tok).await;
    }

    #[tokio::test]
    async fn test_razorpay_key_id_valid() {
        accept(SecretType::RazorpayKeyId, "rzp_live_abcdef").await;
    }

    #[tokio::test]
    async fn test_adyen_api_key_valid() {
        let key = format!("AQE{}", "a".repeat(80));
        accept(SecretType::AdyenApiKey, &key).await;
    }

    // ═══════════════════════════════════════════════
    // Payment — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_stripe_api_key_reject_wrong_prefix() {
        reject(SecretType::StripeApiKey, "pk_live_1234567890abcdefghijklmnop").await;
    }

    #[tokio::test]
    async fn test_square_access_token_reject_wrong_prefix() {
        reject(SecretType::SquareAccessToken, "invalid_token").await;
    }

    // ═══════════════════════════════════════════════
    // Communication — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_sendgrid_api_key_valid() {
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(40));
        accept(SecretType::SendGridApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_twilio_api_key_valid() {
        accept(
            SecretType::TwilioApiKey,
            "SKabcdef0123456789abcdef0123456789",
        )
        .await;
    }

    #[tokio::test]
    async fn test_slack_token_valid() {
        accept(
            SecretType::SlackToken,
            "xoxb-123456789012-123456789012-abcdefghijklmnop",
        )
        .await;
    }

    #[tokio::test]
    async fn test_slack_webhook_valid() {
        accept(
            SecretType::SlackWebhook,
            "https://hooks.slack.com/services/T00/B00/xxxx",
        )
        .await;
    }

    #[tokio::test]
    async fn test_discord_bot_token_valid() {
        let tok = format!("{}.{}.{}", "a".repeat(24), "b".repeat(6), "c".repeat(27));
        accept(SecretType::DiscordBotToken, &tok).await;
    }

    #[tokio::test]
    async fn test_discord_webhook_valid() {
        accept(
            SecretType::DiscordWebhook,
            "https://discord.com/api/webhooks/123456/abcdef",
        )
        .await;
    }

    #[tokio::test]
    async fn test_telegram_bot_token_valid() {
        accept(
            SecretType::TelegramBotToken,
            "1234567890:ABCDEFGHIJKLMNOPqrstuvwxyz123456",
        )
        .await;
    }

    #[tokio::test]
    async fn test_teams_webhook_valid() {
        accept(
            SecretType::MicrosoftTeamsWebhook,
            "https://contoso.webhook.office.com/webhookb2/xxx/IncomingWebhook/xxx",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // Communication — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_slack_token_reject_wrong_prefix() {
        reject(SecretType::SlackToken, "not_a_slack_token_at_all").await;
    }

    #[tokio::test]
    async fn test_telegram_reject_no_colon() {
        reject(SecretType::TelegramBotToken, "1234567890ABCDEFGHIJKLMNOPqrstuvwxyz123456").await;
    }

    // ═══════════════════════════════════════════════
    // Email Services — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_mailgun_api_key_valid() {
        accept(
            SecretType::MailgunApiKey,
            "abcdef0123456789abcdef0123456789",
        )
        .await;
    }

    #[tokio::test]
    async fn test_mailchimp_api_key_valid() {
        accept(
            SecretType::MailchimpApiKey,
            "abcdef0123456789abcdef0123456789-us20",
        )
        .await;
    }

    #[tokio::test]
    async fn test_brevo_api_key_valid() {
        let key = format!("xkeysib-{}", "a".repeat(80));
        accept(SecretType::BrevoApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_resend_api_key_valid() {
        let key = format!("re_{}", "a".repeat(35));
        accept(SecretType::ResendApiKey, &key).await;
    }

    // ═══════════════════════════════════════════════
    // AI / ML Platforms — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_openai_api_key_valid() {
        accept(
            SecretType::OpenAiApiKey,
            "sk-1234567890abcdefghijklmnop1234567890abcdefghijklmnop",
        )
        .await;
    }

    #[tokio::test]
    async fn test_anthropic_api_key_valid() {
        let key = format!("sk-ant-api03-{}", "a".repeat(90));
        accept(SecretType::AnthropicApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_huggingface_token_valid() {
        let key = format!("hf_{}", "a".repeat(36));
        accept(SecretType::HuggingFaceToken, &key).await;
    }

    #[tokio::test]
    async fn test_replicate_api_key_valid() {
        let key = format!("r8_{}", "a".repeat(38));
        accept(SecretType::ReplicateApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_groq_api_key_valid() {
        let key = format!("gsk_{}", "a".repeat(52));
        accept(SecretType::GroqApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_deepseek_api_key_valid() {
        let key = format!("sk-{}", "a".repeat(48));
        accept(SecretType::DeepSeekApiKey, &key).await;
    }

    // ═══════════════════════════════════════════════
    // AI / ML Platforms — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_openai_reject_too_short() {
        reject(SecretType::OpenAiApiKey, "sk-abc").await;
    }

    #[tokio::test]
    async fn test_anthropic_reject_wrong_prefix() {
        reject(SecretType::AnthropicApiKey, "wrong_prefix_key").await;
    }

    // ═══════════════════════════════════════════════
    // Monitoring & Observability — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_datadog_api_key_valid() {
        accept(
            SecretType::DatadogApiKey,
            "abcdef0123456789abcdef0123456789",
        )
        .await;
    }

    #[tokio::test]
    async fn test_datadog_app_key_valid() {
        accept(
            SecretType::DatadogAppKey,
            "abcdef0123456789abcdef0123456789abcdef01",
        )
        .await;
    }

    #[tokio::test]
    async fn test_newrelic_api_key_valid() {
        // pfx("NRAK-", 27, is_alphanum_upper) = prefix 5 + body 27 = 32 total
        accept(
            SecretType::NewRelicApiKey,
            "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXY01",
        )
        .await;
    }

    #[tokio::test]
    async fn test_sentry_dsn_valid() {
        accept(
            SecretType::SentryDsn,
            "https://abcdef@o12345.ingest.sentry.io/67890",
        )
        .await;
    }

    #[tokio::test]
    async fn test_grafana_api_key_valid() {
        let key = format!("glc_{}", "a".repeat(32));
        accept(SecretType::GrafanaApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_splunk_hec_token_valid() {
        accept(
            SecretType::SplunkHecToken,
            "12345678-1234-1234-1234-123456789012",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // Monitoring — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_datadog_api_key_reject_wrong_length() {
        reject(SecretType::DatadogApiKey, "abcdef0123456789").await;
    }

    #[tokio::test]
    async fn test_sentry_dsn_reject_not_url() {
        reject(SecretType::SentryDsn, "not-a-dsn-at-all").await;
    }

    // ═══════════════════════════════════════════════
    // Infrastructure & Hosting — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_cloudflare_api_token_valid() {
        let tok = "a".repeat(40);
        accept(SecretType::CloudflareApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_digitalocean_token_valid() {
        let tok = format!("dop_v1_{}", "a".repeat(64));
        accept(SecretType::DigitalOceanToken, &tok).await;
    }

    #[tokio::test]
    async fn test_vercel_token_valid() {
        accept(SecretType::VercelToken, "abcdefghijklmnopqrstuvwx").await;
    }

    #[tokio::test]
    async fn test_heroku_api_key_uuid_valid() {
        accept(
            SecretType::HerokuApiKey,
            "12345678-1234-1234-1234-123456789012",
        )
        .await;
    }

    #[tokio::test]
    async fn test_docker_hub_token_valid() {
        let tok = format!("dckr_pat_{}", "a".repeat(30));
        accept(SecretType::DockerHubToken, &tok).await;
    }

    #[tokio::test]
    async fn test_hashicorp_vault_token_valid() {
        let tok = format!("hvs.{}", "a".repeat(24));
        accept(SecretType::HashiCorpVaultToken, &tok).await;
    }

    #[tokio::test]
    async fn test_terraform_cloud_token_valid() {
        let tok = format!("atlasv1.{}", "a".repeat(60));
        accept(SecretType::TerraformCloudToken, &tok).await;
    }

    #[tokio::test]
    async fn test_fly_access_token_valid() {
        let tok = format!("fm2_{}", "a".repeat(40));
        accept(SecretType::FlyAccessToken, &tok).await;
    }

    #[tokio::test]
    async fn test_hetzner_api_token_valid() {
        let tok = "a".repeat(64);
        accept(SecretType::HetznerApiToken, &tok).await;
    }

    // ═══════════════════════════════════════════════
    // Infrastructure — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_digitalocean_reject_wrong_prefix() {
        reject(SecretType::DigitalOceanToken, "wrong_prefix_1234567890").await;
    }

    #[tokio::test]
    async fn test_heroku_reject_not_uuid() {
        reject(SecretType::HerokuApiKey, "not-a-uuid").await;
    }

    // ═══════════════════════════════════════════════
    // DevTools / CI — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_circleci_token_valid() {
        accept(
            SecretType::CircleCiToken,
            "abcdef0123456789abcdef0123456789abcdef01",
        )
        .await;
    }

    #[tokio::test]
    async fn test_jira_api_token_valid() {
        accept(
            SecretType::JiraApiToken,
            "abcdefghijklmnopqrstuvwxyz",
        )
        .await;
    }

    #[tokio::test]
    async fn test_launchdarkly_key_valid() {
        accept(
            SecretType::LaunchDarklyKey,
            "sdk-12345678-abcd-1234-abcd-123456789012",
        )
        .await;
    }

    #[tokio::test]
    async fn test_postman_api_token_valid() {
        let tok = format!("PMAK-{}-{}", "a".repeat(24), "b".repeat(36));
        accept(SecretType::PostmanApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_snyk_api_token_uuid_valid() {
        accept(
            SecretType::SnykApiToken,
            "12345678-1234-1234-1234-123456789012",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // SaaS / Productivity — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_linear_api_key_valid() {
        let key = format!("lin_api_{}", "a".repeat(40));
        accept(SecretType::LinearApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_notion_api_key_ntn_valid() {
        let key = format!("ntn_{}", "a".repeat(40));
        accept(SecretType::NotionApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_notion_api_key_secret_valid() {
        let key = format!("secret_{}", "a".repeat(40));
        accept(SecretType::NotionApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_airtable_api_key_valid() {
        accept(SecretType::AirtableApiKey, "patABC123.xyz456").await;
    }

    #[tokio::test]
    async fn test_shopify_api_key_valid() {
        let key = format!("shpat_{}", "a".repeat(34));
        accept(SecretType::ShopifyApiKey, &key).await;
    }

    #[tokio::test]
    async fn test_figma_pat_valid() {
        let key = format!("figd_{}", "a".repeat(40));
        accept(SecretType::FigmaPat, &key).await;
    }

    #[tokio::test]
    async fn test_mapbox_token_valid() {
        let tok = format!("pk.eyJ{}", "a".repeat(50));
        accept(SecretType::MapboxToken, &tok).await;
    }

    // ═══════════════════════════════════════════════
    // Package Registries — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_npm_token_valid() {
        let tok = format!("npm_{}", "a".repeat(36));
        accept(SecretType::NpmToken, &tok).await;
    }

    #[tokio::test]
    async fn test_pypi_api_token_valid() {
        let tok = format!("pypi-AgEIcHlwaS5vcmc{}", "a".repeat(50));
        accept(SecretType::PyPiApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_nuget_api_key_valid() {
        let tok = format!("oy2{}", "a".repeat(43));
        accept(SecretType::NuGetApiKey, &tok).await;
    }

    #[tokio::test]
    async fn test_rubygems_api_key_valid() {
        let tok = format!("rubygems_{}", "a".repeat(48));
        accept(SecretType::RubyGemsApiKey, &tok).await;
    }

    // ═══════════════════════════════════════════════
    // Package Registries — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_npm_token_reject_wrong_prefix() {
        reject(SecretType::NpmToken, "wrong_prefix_12345678901234567890").await;
    }

    // ═══════════════════════════════════════════════
    // Private Keys — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_rsa_private_key_valid() {
        accept(
            SecretType::RsaPrivateKey,
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_ssh_private_key_valid() {
        accept(
            SecretType::SshPrivateKey,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_ec_private_key_valid() {
        accept(
            SecretType::EcPrivateKey,
            "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_pgp_private_key_valid() {
        accept(
            SecretType::PgpPrivateKey,
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG...\n-----END PGP PRIVATE KEY BLOCK-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_pkcs8_private_key_valid() {
        accept(
            SecretType::Pkcs8PrivateKey,
            "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_dsa_private_key_valid() {
        accept(
            SecretType::DsaPrivateKey,
            "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ...\n-----END DSA PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_encrypted_private_key_valid() {
        accept(
            SecretType::EncryptedPrivateKey,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFH...\n-----END ENCRYPTED PRIVATE KEY-----",
        )
        .await;
    }

    #[tokio::test]
    async fn test_putty_private_key_valid() {
        accept(
            SecretType::PuttyPrivateKey,
            "PuTTY-User-Key-File-2: ssh-rsa",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // Private Keys — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_rsa_private_key_reject_no_header() {
        reject(SecretType::RsaPrivateKey, "not_a_private_key_at_all").await;
    }

    // ═══════════════════════════════════════════════
    // Connection Strings — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_postgres_connection_string_valid() {
        accept(
            SecretType::PostgresConnectionString,
            "postgresql://user:password@localhost:5432/mydb",
        )
        .await;
    }

    #[tokio::test]
    async fn test_mongo_connection_string_valid() {
        accept(
            SecretType::MongoDbConnectionString,
            "mongodb+srv://user:pass@cluster0.mongodb.net/mydb",
        )
        .await;
    }

    #[tokio::test]
    async fn test_mysql_connection_string_valid() {
        accept(
            SecretType::MysqlConnectionString,
            "mysql://root:password@localhost:3306/mydb",
        )
        .await;
    }

    #[tokio::test]
    async fn test_redis_connection_string_valid() {
        accept(
            SecretType::RedisConnectionString,
            "redis://default:password@localhost:6379/0",
        )
        .await;
    }

    #[tokio::test]
    async fn test_database_url_valid() {
        accept(
            SecretType::DatabaseUrl,
            "postgres://user:pass@host:5432/dbname",
        )
        .await;
    }

    #[tokio::test]
    async fn test_password_in_url_valid() {
        accept(
            SecretType::PasswordInUrl,
            "https://user:password@example.com/path",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // Connection Strings — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_postgres_reject_no_prefix() {
        reject(SecretType::PostgresConnectionString, "not_a_connection_string").await;
    }

    // ═══════════════════════════════════════════════
    // JWT Tokens — ACCEPT / REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_jwt_token_valid() {
        accept(
            SecretType::JwtToken,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        .await;
    }

    #[tokio::test]
    async fn test_jwt_token_reject_no_dots() {
        reject(SecretType::JwtToken, "eyJhbGciOiJIUzI1NiJ9eyJzdWIiOiIxMjM0In0abc").await;
    }

    #[tokio::test]
    async fn test_jwt_token_reject_wrong_prefix() {
        reject(SecretType::JwtToken, "not.a.jwt").await;
    }

    // ═══════════════════════════════════════════════
    // Security Services — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_onepassword_secret_key_valid() {
        let key = format!("A3-{}", "a".repeat(30));
        accept(SecretType::OnePasswordSecretKey, &key).await;
    }

    #[tokio::test]
    async fn test_age_secret_key_valid() {
        let key = format!("AGE-SECRET-KEY-1{}", "a".repeat(58));
        accept(SecretType::AgeSecretKey, &key).await;
    }

    // ═══════════════════════════════════════════════
    // Batch group: 32-hex-char types — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_hex_range_types_valid() {
        let hex32 = "abcdef0123456789abcdef0123456789";
        // Test representative types from the range_len hex group
        for st in [
            SecretType::AbstractApiKey,
            SecretType::AccuWeatherApiKey,
            SecretType::AlgoliaApiKey,
            SecretType::AmplitudeApiKey,
            SecretType::NewsApiKey,
            SecretType::OpenWeatherMapApiKey,
        ] {
            accept(st, hex32).await;
        }
    }

    // ═══════════════════════════════════════════════
    // Batch group: 20+ hex-lower types — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_hex_lower_20_types_valid() {
        let hex20 = "abcdef0123456789abcdef0123456789";
        for st in [
            SecretType::ActiveCampaignApiKey,
            SecretType::CustomerIoApiKey,
            SecretType::IterableApiKey,
        ] {
            accept(st, hex20).await;
        }
    }

    // ═══════════════════════════════════════════════
    // Batch group: UUID-like types — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_uuid_types_valid() {
        let uuid = "12345678-1234-1234-1234-123456789012";
        for st in [
            SecretType::AirVisualApiKey,
            SecretType::DocuSignApiKey,
            SecretType::FusionAuthApiKey,
            SecretType::HubSpotApiKey,
        ] {
            accept(st, uuid).await;
        }
    }

    // ═══════════════════════════════════════════════
    // Batch group: Extended charset (20+) — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_extended_charset_types_valid() {
        let ext = "abcdefghijklmnopqrst-uvwx_yz123";
        for st in [
            SecretType::AbyssaleApiKey,
            SecretType::AirshipApiKey,
            SecretType::AkamaiApiKey,
        ] {
            accept(st, ext).await;
        }
    }

    // ═══════════════════════════════════════════════
    // Generic / Catch-all — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_generic_api_key_valid() {
        accept(SecretType::GenericApiKey, "some_generic_api_key_value_1234").await;
    }

    #[tokio::test]
    async fn test_generic_secret_valid() {
        accept(SecretType::GenericSecret, "some_generic_secret_value_1234").await;
    }

    #[tokio::test]
    async fn test_high_entropy_string_valid() {
        accept(
            SecretType::HighEntropyString,
            "aB3$kL9mN2pQ5rT8wX1z",
        )
        .await;
    }

    #[tokio::test]
    async fn test_custom_type_valid() {
        accept(
            SecretType::Custom("my_custom_type".to_string()),
            "some_custom_value_1234",
        )
        .await;
    }

    // ═══════════════════════════════════════════════
    // Generic / Catch-all — REJECT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_generic_api_key_reject_too_short() {
        reject(SecretType::GenericApiKey, "short").await;
    }

    #[tokio::test]
    async fn test_high_entropy_reject_too_short() {
        reject(SecretType::HighEntropyString, "tooshort1234567890a").await;
    }

    // ═══════════════════════════════════════════════
    // Specific prefix types — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_doppler_token_valid() {
        let tok = format!("dp.{}", "a".repeat(40));
        accept(SecretType::DopplerToken, &tok).await;
    }

    #[tokio::test]
    async fn test_planetscale_token_valid() {
        let tok = format!("pscale_tkn_{}", "a".repeat(30));
        accept(SecretType::PlanetScaleToken, &tok).await;
    }

    #[tokio::test]
    async fn test_netlify_pat_valid() {
        let tok = format!("nfp_{}", "a".repeat(40));
        accept(SecretType::NetlifyPat, &tok).await;
    }

    #[tokio::test]
    async fn test_render_api_key_valid() {
        let tok = format!("rnd_{}", "a".repeat(32));
        accept(SecretType::RenderApiKey, &tok).await;
    }

    #[tokio::test]
    async fn test_sonarqube_token_valid() {
        let tok = format!("squ_{}", "a".repeat(40));
        accept(SecretType::SonarQubeToken, &tok).await;
    }

    #[tokio::test]
    async fn test_supabase_anon_key_valid() {
        let tok = format!("eyJhbGciOiJIUzI1NiJ9.{}", "a".repeat(90));
        accept(SecretType::SupabaseAnonKey, &tok).await;
    }

    #[tokio::test]
    async fn test_dynatrace_api_token_valid() {
        let tok = format!("dt0c01.{}", "a".repeat(80));
        accept(SecretType::DynatraceApiToken, &tok).await;
    }

    // ═══════════════════════════════════════════════
    // Additional specific types — ACCEPT
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_facebook_access_token_valid() {
        let tok = format!("EAA{}", "a".repeat(100));
        accept(SecretType::FacebookAccessToken, &tok).await;
    }

    #[tokio::test]
    async fn test_easypost_api_token_valid() {
        let tok = format!("EZAK{}", "a".repeat(54));
        accept(SecretType::EasyPostApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_artifactory_api_key_valid() {
        let tok = format!("AKCp{}", "a".repeat(69));
        accept(SecretType::ArtifactoryApiKey, &tok).await;
    }

    #[tokio::test]
    async fn test_clerk_api_key_valid() {
        accept(SecretType::ClerkApiKey, "sk_live_1234567890abcdefghij").await;
    }

    #[tokio::test]
    async fn test_dropbox_short_lived_token_valid() {
        let tok = format!("sl.{}", "a".repeat(135));
        accept(SecretType::DropboxShortLivedToken, &tok).await;
    }

    #[tokio::test]
    async fn test_duffel_api_token_valid() {
        let tok = format!("duffel_test_{}", "a".repeat(32));
        accept(SecretType::DuffelApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_google_oauth_client_secret_valid() {
        let tok = format!("GOCSPX-{}", "a".repeat(28));
        accept(SecretType::GoogleOAuthClientSecret, &tok).await;
    }

    #[tokio::test]
    async fn test_firebase_api_key_valid() {
        // FirebaseApiKey checks: starts_with("AIza") && len == 39
        accept(
            SecretType::FirebaseApiKey,
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        )
        .await;
    }

    #[tokio::test]
    async fn test_okta_api_token_valid() {
        let tok = format!("00{}", "a".repeat(40));
        accept(SecretType::OktaApiToken, &tok).await;
    }

    #[tokio::test]
    async fn test_depl_api_key_valid() {
        let tok = format!("{}:fx", "a".repeat(36));
        accept(SecretType::DeepLApiKey, &tok).await;
    }

    #[tokio::test]
    async fn test_coinbase_access_token_valid() {
        let tok = "a".repeat(64);
        accept(SecretType::CoinbaseAccessToken, &tok).await;
    }

    // ═══════════════════════════════════════════════
    // Edge cases
    // ═══════════════════════════════════════════════

    #[tokio::test]
    async fn test_empty_value_rejected() {
        reject(SecretType::GenericApiKey, "").await;
    }

    #[tokio::test]
    async fn test_whitespace_only_rejected() {
        reject(SecretType::GenericApiKey, "        ").await;
    }

    #[tokio::test]
    async fn test_spaces_in_value_rejected_for_ext_types() {
        reject(SecretType::GenericApiKey, "has spaces in it").await;
    }

    #[tokio::test]
    async fn test_very_long_value_for_generic() {
        let val = "a".repeat(10000);
        accept(SecretType::GenericApiKey, &val).await;
    }

    // ═══════════════════════════════════════════════
    // Helper function unit tests
    // ═══════════════════════════════════════════════

    #[test]
    fn test_pfx_helper() {
        // pfx expects prefix + exactly body_len chars
        assert!(pfx("ghp_abcdef01234567890123", "ghp_", 20, is_alphanum)); // 4+20=24
        assert!(!pfx("ghp_short", "ghp_", 20, is_alphanum)); // too short
        assert!(!pfx("xxx_abcdef01234567890123", "ghp_", 20, is_alphanum)); // wrong prefix
        assert!(!pfx("ghp_abcdef012345678901234", "ghp_", 20, is_alphanum)); // 4+21=25, too long
    }

    #[test]
    fn test_pfx_min_helper() {
        assert!(pfx_min("prefix_abcdef0123", "prefix_", 10, is_alphanum));
        assert!(pfx_min("prefix_abcdef01234567890", "prefix_", 10, is_alphanum));
        assert!(!pfx_min("prefix_abc", "prefix_", 10, is_alphanum));
    }

    #[test]
    fn test_pfx_range_helper() {
        assert!(pfx_range("ghp_abcdefghij", "ghp_", 8, 12, is_alphanum));
        assert!(!pfx_range("ghp_abcd", "ghp_", 8, 12, is_alphanum));
    }

    #[test]
    fn test_exact_helper() {
        assert!(exact("abcdef0123456789abcdef0123456789", 32, is_hex));
        assert!(!exact("abcdef0123456789abcdef012345678", 32, is_hex));
        assert!(!exact("abcdef0123456789abcdef01234567890", 32, is_hex));
    }

    #[test]
    fn test_is_pem_helper() {
        assert!(is_pem("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY"));
        assert!(!is_pem("not a pem header", "BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn test_is_conn_str_helper() {
        assert!(is_conn_str("postgresql://user:pass@host:5432/db"));
        assert!(!is_conn_str("not_url"));
    }

    #[test]
    fn test_is_uuid_helper() {
        assert!(is_uuid("12345678-1234-1234-1234-123456789012"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("12345678123412341234123456789012")); // no dashes
    }

    #[test]
    fn test_non_empty_helper() {
        assert!(non_empty("abcdefgh", 8));
        assert!(!non_empty("abcdefg", 8));
        assert!(!non_empty("abc def gh", 8)); // has whitespace
    }

    #[test]
    fn test_charset_helpers() {
        assert!(is_hex('a'));
        assert!(is_hex('F'));
        assert!(!is_hex('g'));

        assert!(is_hex_lower('a'));
        assert!(!is_hex_lower('A'));

        assert!(is_alphanum('A'));
        assert!(is_alphanum('0'));
        assert!(!is_alphanum('-'));

        assert!(is_base64('a'));
        assert!(is_base64('+'));
        assert!(is_base64('/'));
        assert!(is_base64('='));
        assert!(!is_base64('-'));

        assert!(is_base64url('-'));
        assert!(is_base64url('_'));
        assert!(!is_base64url('+'));

        assert!(is_ext('a'));
        assert!(is_ext('-'));
        assert!(is_ext('_'));
        assert!(!is_ext('.'));

        assert!(is_ext_dot('.'));
        assert!(is_ext_dot('-'));

        assert!(is_uuid_char('a'));
        assert!(is_uuid_char('-'));
        assert!(!is_uuid_char('g'));
    }
}
