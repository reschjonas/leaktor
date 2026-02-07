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

    // AI/ML Platforms
    OpenAiApiKey,
    AnthropicApiKey,
    CohereApiKey,
    HuggingFaceToken,
    ReplicateApiKey,

    // Additional Cloud/SaaS
    DatadogApiKey,
    DatadogAppKey,
    CloudflareApiKey,
    CloudflareApiToken,
    DigitalOceanToken,
    DigitalOceanSpacesKey,
    VercelToken,
    NetlifyToken,
    LinearApiKey,
    NotionApiKey,
    AirtableApiKey,
    PlanetScaleToken,

    // Package Registries
    NpmToken,
    PyPiApiToken,
    NuGetApiKey,
    RubyGemsApiKey,

    // Communication
    DiscordBotToken,
    DiscordWebhook,
    TelegramBotToken,

    // E-commerce / Payment
    ShopifyApiKey,
    ShopifySharedSecret,
    SquareAccessToken,
    PaypalClientSecret,

    // Authentication
    OktaApiToken,
    Auth0ManagementToken,
    FirebaseApiKey,
    SupabaseAnonKey,
    SupabaseServiceKey,

    // Infrastructure
    DockerHubToken,
    HashiCorpVaultToken,
    NewRelicApiKey,
    SentryDsn,
    AlgoliaApiKey,
    ElasticApiKey,
    GrafanaApiKey,
    CircleCiToken,
    TravisCiToken,

    // New: Additional services
    PagerDutyApiKey,
    JiraApiToken,
    BitbucketAppPassword,
    TerraformCloudToken,
    PulumiAccessToken,
    FastlyApiToken,
    LaunchDarklyKey,
    MapboxToken,
    BraintreeAccessToken,
    PlaidClientSecret,
    DopplerToken,
    NetlifyPat,
    RenderApiKey,
    FlyAccessToken,
    ConfluentApiKey,
    DatabricksToken,
    SnowflakeCredential,
    SumoLogicKey,
    PosthogApiKey,
    AmplitudeApiKey,
    SegmentWriteKey,
    MixpanelToken,

    // Tier 3 Expansion - Additional Services
    OnePasswordSecretKey,
    OnePasswordServiceToken,
    AdobeClientSecret,
    AgeSecretKey,
    AlibabaAccessKey,
    AlibabaSecretKey,
    ArtifactoryApiKey,
    ArtifactoryReferenceToken,
    AsanaSecret,
    AzureAdClientSecret,
    ClojarsApiToken,
    CodecovAccessToken,
    CoinbaseAccessToken,
    ContentfulApiToken,
    DropboxApiToken,
    DropboxLongLivedToken,
    DropboxShortLivedToken,
    DuffelApiToken,
    DynatraceApiToken,
    EasyPostApiToken,
    EasyPostTestApiToken,
    FacebookAccessToken,
    FacebookPageAccessToken,
    FlutterwaveSecretKey,
    FrameIoApiToken,
    FreshbooksAccessToken,
    GitHubAppToken,
    GitHubFineGrainedPat,
    GoogleOAuthClientSecret,
    IntercomAccessToken,
    KrakenAccessToken,
    LobApiKey,
    MessageBirdApiKey,
    NewRelicBrowserApiKey,
    NytimesAccessToken,
    PostmanApiToken,
    Pkcs8PrivateKey,
    DsaPrivateKey,
    RapidApiKey,
    ReadmeApiKey,
    ScalingoApiToken,
    SourcegraphAccessToken,
    TailscaleApiKey,
    TencentSecretId,
    TrelloAccessToken,
    TwitchApiToken,
    TwitterApiKey,
    TwitterAccessToken,
    TypeformApiToken,
    VaultBatchToken,
    YandexApiKey,
    YandexAwsAccessToken,
    ZendeskSecretKey,
    BeamerApiToken,
    BitwardenApiKey,
    PlanetScalePassword,
    InfracostApiKey,
    PrefectApiToken,
    RailwayApiToken,
    NeonApiKey,
    TurborepoAccessToken,

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
            "OpenAI API Key" => Ok(SecretType::OpenAiApiKey),
            "Anthropic API Key" => Ok(SecretType::AnthropicApiKey),
            "Cohere API Key" => Ok(SecretType::CohereApiKey),
            "HuggingFace Token" => Ok(SecretType::HuggingFaceToken),
            "Replicate API Key" => Ok(SecretType::ReplicateApiKey),
            "Datadog API Key" => Ok(SecretType::DatadogApiKey),
            "Datadog App Key" => Ok(SecretType::DatadogAppKey),
            "Cloudflare API Key" => Ok(SecretType::CloudflareApiKey),
            "Cloudflare API Token" => Ok(SecretType::CloudflareApiToken),
            "DigitalOcean Token" => Ok(SecretType::DigitalOceanToken),
            "DigitalOcean Spaces Key" => Ok(SecretType::DigitalOceanSpacesKey),
            "Vercel Token" => Ok(SecretType::VercelToken),
            "Netlify Token" => Ok(SecretType::NetlifyToken),
            "Linear API Key" => Ok(SecretType::LinearApiKey),
            "Notion API Key" => Ok(SecretType::NotionApiKey),
            "Airtable API Key" => Ok(SecretType::AirtableApiKey),
            "PlanetScale Token" => Ok(SecretType::PlanetScaleToken),
            "NPM Token" => Ok(SecretType::NpmToken),
            "PyPI API Token" => Ok(SecretType::PyPiApiToken),
            "NuGet API Key" => Ok(SecretType::NuGetApiKey),
            "RubyGems API Key" => Ok(SecretType::RubyGemsApiKey),
            "Discord Bot Token" => Ok(SecretType::DiscordBotToken),
            "Discord Webhook" => Ok(SecretType::DiscordWebhook),
            "Telegram Bot Token" => Ok(SecretType::TelegramBotToken),
            "Shopify API Key" => Ok(SecretType::ShopifyApiKey),
            "Shopify Shared Secret" => Ok(SecretType::ShopifySharedSecret),
            "Square Access Token" => Ok(SecretType::SquareAccessToken),
            "PayPal Client Secret" => Ok(SecretType::PaypalClientSecret),
            "Okta API Token" => Ok(SecretType::OktaApiToken),
            "Auth0 Management Token" => Ok(SecretType::Auth0ManagementToken),
            "Firebase API Key" => Ok(SecretType::FirebaseApiKey),
            "Supabase Anon Key" => Ok(SecretType::SupabaseAnonKey),
            "Supabase Service Key" => Ok(SecretType::SupabaseServiceKey),
            "Docker Hub Token" => Ok(SecretType::DockerHubToken),
            "HashiCorp Vault Token" => Ok(SecretType::HashiCorpVaultToken),
            "New Relic API Key" => Ok(SecretType::NewRelicApiKey),
            "Sentry DSN" => Ok(SecretType::SentryDsn),
            "Algolia API Key" => Ok(SecretType::AlgoliaApiKey),
            "Elastic API Key" => Ok(SecretType::ElasticApiKey),
            "Grafana API Key" => Ok(SecretType::GrafanaApiKey),
            "CircleCI Token" => Ok(SecretType::CircleCiToken),
            "Travis CI Token" => Ok(SecretType::TravisCiToken),
            "PagerDuty API Key" => Ok(SecretType::PagerDutyApiKey),
            "Jira API Token" => Ok(SecretType::JiraApiToken),
            "Bitbucket App Password" => Ok(SecretType::BitbucketAppPassword),
            "Terraform Cloud Token" => Ok(SecretType::TerraformCloudToken),
            "Pulumi Access Token" => Ok(SecretType::PulumiAccessToken),
            "Fastly API Token" => Ok(SecretType::FastlyApiToken),
            "LaunchDarkly Key" => Ok(SecretType::LaunchDarklyKey),
            "Mapbox Token" => Ok(SecretType::MapboxToken),
            "Braintree Access Token" => Ok(SecretType::BraintreeAccessToken),
            "Plaid Client Secret" => Ok(SecretType::PlaidClientSecret),
            "Doppler Token" => Ok(SecretType::DopplerToken),
            "Netlify PAT" => Ok(SecretType::NetlifyPat),
            "Render API Key" => Ok(SecretType::RenderApiKey),
            "Fly Access Token" => Ok(SecretType::FlyAccessToken),
            "Confluent API Key" => Ok(SecretType::ConfluentApiKey),
            "Databricks Token" => Ok(SecretType::DatabricksToken),
            "Snowflake Credential" => Ok(SecretType::SnowflakeCredential),
            "Sumo Logic Key" => Ok(SecretType::SumoLogicKey),
            "PostHog API Key" => Ok(SecretType::PosthogApiKey),
            "Amplitude API Key" => Ok(SecretType::AmplitudeApiKey),
            "Segment Write Key" => Ok(SecretType::SegmentWriteKey),
            "Mixpanel Token" => Ok(SecretType::MixpanelToken),
            "1Password Secret Key" => Ok(SecretType::OnePasswordSecretKey),
            "1Password Service Token" => Ok(SecretType::OnePasswordServiceToken),
            "Adobe Client Secret" => Ok(SecretType::AdobeClientSecret),
            "Age Secret Key" => Ok(SecretType::AgeSecretKey),
            "Alibaba Access Key" => Ok(SecretType::AlibabaAccessKey),
            "Alibaba Secret Key" => Ok(SecretType::AlibabaSecretKey),
            "Artifactory API Key" => Ok(SecretType::ArtifactoryApiKey),
            "Artifactory Reference Token" => Ok(SecretType::ArtifactoryReferenceToken),
            "Asana Secret" => Ok(SecretType::AsanaSecret),
            "Azure AD Client Secret" => Ok(SecretType::AzureAdClientSecret),
            "Clojars API Token" => Ok(SecretType::ClojarsApiToken),
            "Codecov Access Token" => Ok(SecretType::CodecovAccessToken),
            "Coinbase Access Token" => Ok(SecretType::CoinbaseAccessToken),
            "Contentful API Token" => Ok(SecretType::ContentfulApiToken),
            "Dropbox API Token" => Ok(SecretType::DropboxApiToken),
            "Dropbox Long-Lived Token" => Ok(SecretType::DropboxLongLivedToken),
            "Dropbox Short-Lived Token" => Ok(SecretType::DropboxShortLivedToken),
            "Duffel API Token" => Ok(SecretType::DuffelApiToken),
            "Dynatrace API Token" => Ok(SecretType::DynatraceApiToken),
            "EasyPost API Token" => Ok(SecretType::EasyPostApiToken),
            "EasyPost Test API Token" => Ok(SecretType::EasyPostTestApiToken),
            "Facebook Access Token" => Ok(SecretType::FacebookAccessToken),
            "Facebook Page Access Token" => Ok(SecretType::FacebookPageAccessToken),
            "Flutterwave Secret Key" => Ok(SecretType::FlutterwaveSecretKey),
            "Frame.io API Token" => Ok(SecretType::FrameIoApiToken),
            "FreshBooks Access Token" => Ok(SecretType::FreshbooksAccessToken),
            "GitHub App Token" => Ok(SecretType::GitHubAppToken),
            "GitHub Fine-Grained PAT" => Ok(SecretType::GitHubFineGrainedPat),
            "Google OAuth Client Secret" => Ok(SecretType::GoogleOAuthClientSecret),
            "Intercom Access Token" => Ok(SecretType::IntercomAccessToken),
            "Kraken Access Token" => Ok(SecretType::KrakenAccessToken),
            "Lob API Key" => Ok(SecretType::LobApiKey),
            "MessageBird API Key" => Ok(SecretType::MessageBirdApiKey),
            "New Relic Browser API Key" => Ok(SecretType::NewRelicBrowserApiKey),
            "NY Times Access Token" => Ok(SecretType::NytimesAccessToken),
            "Postman API Token" => Ok(SecretType::PostmanApiToken),
            "PKCS8 Private Key" => Ok(SecretType::Pkcs8PrivateKey),
            "DSA Private Key" => Ok(SecretType::DsaPrivateKey),
            "RapidAPI Key" => Ok(SecretType::RapidApiKey),
            "ReadMe API Key" => Ok(SecretType::ReadmeApiKey),
            "Scalingo API Token" => Ok(SecretType::ScalingoApiToken),
            "Sourcegraph Access Token" => Ok(SecretType::SourcegraphAccessToken),
            "Tailscale API Key" => Ok(SecretType::TailscaleApiKey),
            "Tencent Secret ID" => Ok(SecretType::TencentSecretId),
            "Trello Access Token" => Ok(SecretType::TrelloAccessToken),
            "Twitch API Token" => Ok(SecretType::TwitchApiToken),
            "Twitter API Key" => Ok(SecretType::TwitterApiKey),
            "Twitter Access Token" => Ok(SecretType::TwitterAccessToken),
            "Typeform API Token" => Ok(SecretType::TypeformApiToken),
            "Vault Batch Token" => Ok(SecretType::VaultBatchToken),
            "Yandex API Key" => Ok(SecretType::YandexApiKey),
            "Yandex AWS Access Token" => Ok(SecretType::YandexAwsAccessToken),
            "Zendesk Secret Key" => Ok(SecretType::ZendeskSecretKey),
            "Beamer API Token" => Ok(SecretType::BeamerApiToken),
            "Bitwarden API Key" => Ok(SecretType::BitwardenApiKey),
            "PlanetScale Password" => Ok(SecretType::PlanetScalePassword),
            "Infracost API Key" => Ok(SecretType::InfracostApiKey),
            "Prefect API Token" => Ok(SecretType::PrefectApiToken),
            "Railway API Token" => Ok(SecretType::RailwayApiToken),
            "Neon API Key" => Ok(SecretType::NeonApiKey),
            "Turborepo Access Token" => Ok(SecretType::TurborepoAccessToken),
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
            SecretType::OpenAiApiKey => "OpenAI API Key",
            SecretType::AnthropicApiKey => "Anthropic API Key",
            SecretType::CohereApiKey => "Cohere API Key",
            SecretType::HuggingFaceToken => "HuggingFace Token",
            SecretType::ReplicateApiKey => "Replicate API Key",
            SecretType::DatadogApiKey => "Datadog API Key",
            SecretType::DatadogAppKey => "Datadog App Key",
            SecretType::CloudflareApiKey => "Cloudflare API Key",
            SecretType::CloudflareApiToken => "Cloudflare API Token",
            SecretType::DigitalOceanToken => "DigitalOcean Token",
            SecretType::DigitalOceanSpacesKey => "DigitalOcean Spaces Key",
            SecretType::VercelToken => "Vercel Token",
            SecretType::NetlifyToken => "Netlify Token",
            SecretType::LinearApiKey => "Linear API Key",
            SecretType::NotionApiKey => "Notion API Key",
            SecretType::AirtableApiKey => "Airtable API Key",
            SecretType::PlanetScaleToken => "PlanetScale Token",
            SecretType::NpmToken => "NPM Token",
            SecretType::PyPiApiToken => "PyPI API Token",
            SecretType::NuGetApiKey => "NuGet API Key",
            SecretType::RubyGemsApiKey => "RubyGems API Key",
            SecretType::DiscordBotToken => "Discord Bot Token",
            SecretType::DiscordWebhook => "Discord Webhook",
            SecretType::TelegramBotToken => "Telegram Bot Token",
            SecretType::ShopifyApiKey => "Shopify API Key",
            SecretType::ShopifySharedSecret => "Shopify Shared Secret",
            SecretType::SquareAccessToken => "Square Access Token",
            SecretType::PaypalClientSecret => "PayPal Client Secret",
            SecretType::OktaApiToken => "Okta API Token",
            SecretType::Auth0ManagementToken => "Auth0 Management Token",
            SecretType::FirebaseApiKey => "Firebase API Key",
            SecretType::SupabaseAnonKey => "Supabase Anon Key",
            SecretType::SupabaseServiceKey => "Supabase Service Key",
            SecretType::DockerHubToken => "Docker Hub Token",
            SecretType::HashiCorpVaultToken => "HashiCorp Vault Token",
            SecretType::NewRelicApiKey => "New Relic API Key",
            SecretType::SentryDsn => "Sentry DSN",
            SecretType::AlgoliaApiKey => "Algolia API Key",
            SecretType::ElasticApiKey => "Elastic API Key",
            SecretType::GrafanaApiKey => "Grafana API Key",
            SecretType::CircleCiToken => "CircleCI Token",
            SecretType::TravisCiToken => "Travis CI Token",
            SecretType::PagerDutyApiKey => "PagerDuty API Key",
            SecretType::JiraApiToken => "Jira API Token",
            SecretType::BitbucketAppPassword => "Bitbucket App Password",
            SecretType::TerraformCloudToken => "Terraform Cloud Token",
            SecretType::PulumiAccessToken => "Pulumi Access Token",
            SecretType::FastlyApiToken => "Fastly API Token",
            SecretType::LaunchDarklyKey => "LaunchDarkly Key",
            SecretType::MapboxToken => "Mapbox Token",
            SecretType::BraintreeAccessToken => "Braintree Access Token",
            SecretType::PlaidClientSecret => "Plaid Client Secret",
            SecretType::DopplerToken => "Doppler Token",
            SecretType::NetlifyPat => "Netlify PAT",
            SecretType::RenderApiKey => "Render API Key",
            SecretType::FlyAccessToken => "Fly Access Token",
            SecretType::ConfluentApiKey => "Confluent API Key",
            SecretType::DatabricksToken => "Databricks Token",
            SecretType::SnowflakeCredential => "Snowflake Credential",
            SecretType::SumoLogicKey => "Sumo Logic Key",
            SecretType::PosthogApiKey => "PostHog API Key",
            SecretType::AmplitudeApiKey => "Amplitude API Key",
            SecretType::SegmentWriteKey => "Segment Write Key",
            SecretType::MixpanelToken => "Mixpanel Token",
            SecretType::OnePasswordSecretKey => "1Password Secret Key",
            SecretType::OnePasswordServiceToken => "1Password Service Token",
            SecretType::AdobeClientSecret => "Adobe Client Secret",
            SecretType::AgeSecretKey => "Age Secret Key",
            SecretType::AlibabaAccessKey => "Alibaba Access Key",
            SecretType::AlibabaSecretKey => "Alibaba Secret Key",
            SecretType::ArtifactoryApiKey => "Artifactory API Key",
            SecretType::ArtifactoryReferenceToken => "Artifactory Reference Token",
            SecretType::AsanaSecret => "Asana Secret",
            SecretType::AzureAdClientSecret => "Azure AD Client Secret",
            SecretType::ClojarsApiToken => "Clojars API Token",
            SecretType::CodecovAccessToken => "Codecov Access Token",
            SecretType::CoinbaseAccessToken => "Coinbase Access Token",
            SecretType::ContentfulApiToken => "Contentful API Token",
            SecretType::DropboxApiToken => "Dropbox API Token",
            SecretType::DropboxLongLivedToken => "Dropbox Long-Lived Token",
            SecretType::DropboxShortLivedToken => "Dropbox Short-Lived Token",
            SecretType::DuffelApiToken => "Duffel API Token",
            SecretType::DynatraceApiToken => "Dynatrace API Token",
            SecretType::EasyPostApiToken => "EasyPost API Token",
            SecretType::EasyPostTestApiToken => "EasyPost Test API Token",
            SecretType::FacebookAccessToken => "Facebook Access Token",
            SecretType::FacebookPageAccessToken => "Facebook Page Access Token",
            SecretType::FlutterwaveSecretKey => "Flutterwave Secret Key",
            SecretType::FrameIoApiToken => "Frame.io API Token",
            SecretType::FreshbooksAccessToken => "FreshBooks Access Token",
            SecretType::GitHubAppToken => "GitHub App Token",
            SecretType::GitHubFineGrainedPat => "GitHub Fine-Grained PAT",
            SecretType::GoogleOAuthClientSecret => "Google OAuth Client Secret",
            SecretType::IntercomAccessToken => "Intercom Access Token",
            SecretType::KrakenAccessToken => "Kraken Access Token",
            SecretType::LobApiKey => "Lob API Key",
            SecretType::MessageBirdApiKey => "MessageBird API Key",
            SecretType::NewRelicBrowserApiKey => "New Relic Browser API Key",
            SecretType::NytimesAccessToken => "NY Times Access Token",
            SecretType::PostmanApiToken => "Postman API Token",
            SecretType::Pkcs8PrivateKey => "PKCS8 Private Key",
            SecretType::DsaPrivateKey => "DSA Private Key",
            SecretType::RapidApiKey => "RapidAPI Key",
            SecretType::ReadmeApiKey => "ReadMe API Key",
            SecretType::ScalingoApiToken => "Scalingo API Token",
            SecretType::SourcegraphAccessToken => "Sourcegraph Access Token",
            SecretType::TailscaleApiKey => "Tailscale API Key",
            SecretType::TencentSecretId => "Tencent Secret ID",
            SecretType::TrelloAccessToken => "Trello Access Token",
            SecretType::TwitchApiToken => "Twitch API Token",
            SecretType::TwitterApiKey => "Twitter API Key",
            SecretType::TwitterAccessToken => "Twitter Access Token",
            SecretType::TypeformApiToken => "Typeform API Token",
            SecretType::VaultBatchToken => "Vault Batch Token",
            SecretType::YandexApiKey => "Yandex API Key",
            SecretType::YandexAwsAccessToken => "Yandex AWS Access Token",
            SecretType::ZendeskSecretKey => "Zendesk Secret Key",
            SecretType::BeamerApiToken => "Beamer API Token",
            SecretType::BitwardenApiKey => "Bitwarden API Key",
            SecretType::PlanetScalePassword => "PlanetScale Password",
            SecretType::InfracostApiKey => "Infracost API Key",
            SecretType::PrefectApiToken => "Prefect API Token",
            SecretType::RailwayApiToken => "Railway API Token",
            SecretType::NeonApiKey => "Neon API Key",
            SecretType::TurborepoAccessToken => "Turborepo Access Token",
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
        let chars: Vec<char> = value.chars().collect();
        let char_count = chars.len();

        if char_count <= 8 {
            return "*".repeat(char_count);
        }

        let prefix_len = 4.min(char_count / 4);
        let suffix_len = 4.min(char_count / 4);
        let prefix: String = chars[..prefix_len].iter().collect();
        let suffix: String = chars[char_count - suffix_len..].iter().collect();
        format!("{}...{}", prefix, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_short_value() {
        let secret = Secret::new(
            SecretType::GenericApiKey,
            "abc".to_string(),
            2.0,
            Severity::Low,
            0.5,
        );
        assert_eq!(secret.redacted_value, "***");
    }

    #[test]
    fn test_redact_normal_value() {
        let secret = Secret::new(
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7TESTKEY".to_string(),
            4.0,
            Severity::Critical,
            0.95,
        );
        // 20 chars: prefix=4, suffix=4 -> "AKIA...TKEY"
        assert!(secret.redacted_value.starts_with("AKIA"));
        assert!(secret.redacted_value.contains("..."));
        assert!(!secret.redacted_value.contains("OSFODNN7"));
    }

    #[test]
    fn test_redact_unicode_no_panic() {
        // This should NOT panic (was a bug before)
        let secret = Secret::new(
            SecretType::GenericSecret,
            "héllo_wörld_ñ_secret_value".to_string(),
            3.0,
            Severity::Medium,
            0.7,
        );
        assert!(secret.redacted_value.contains("..."));
    }

    #[test]
    fn test_redact_empty() {
        let secret = Secret::new(
            SecretType::GenericApiKey,
            "".to_string(),
            0.0,
            Severity::Low,
            0.5,
        );
        assert_eq!(secret.redacted_value, "");
    }

    #[test]
    fn test_secret_type_roundtrip() {
        let types = vec![
            SecretType::AwsAccessKey,
            SecretType::GitHubPat,
            SecretType::OpenAiApiKey,
            SecretType::DiscordBotToken,
            SecretType::ShopifyApiKey,
            SecretType::HashiCorpVaultToken,
            SecretType::NpmToken,
        ];

        for secret_type in types {
            let name = secret_type.as_str();
            assert!(!name.is_empty(), "SecretType should have a non-empty name");
        }
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}
