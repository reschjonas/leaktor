//! Configuration-driven API validator for services with known validation endpoints.
//!
//! This validator makes HTTP requests to service APIs to verify if a detected
//! secret is actually valid (active). It supports ~100+ services organized by
//! authentication type (Bearer token, API key header, Basic auth, etc.).
//!
//! Each service is configured with:
//! - API endpoint URL
//! - Authentication method
//! - Expected success/failure status codes

use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use reqwest::{Client, StatusCode};

pub struct ServiceValidator {
    client: Client,
}

impl ServiceValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent("Leaktor-Secret-Scanner")
                .build()
                .unwrap(),
        }
    }
}

impl Default for ServiceValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// How to authenticate with the service API
enum AuthMethod {
    /// Authorization: Bearer {token}
    Bearer,
    /// Authorization: token {token}
    TokenAuth,
    /// Custom header name with the token as value
    Header(&'static str),
    /// Custom header with prefix: {prefix} {token}
    HeaderWithPrefix(&'static str, &'static str),
    /// HTTP Basic auth with token as password
    BasicAuthPassword,
    /// Token appended as query parameter
    QueryParam(&'static str),
}

/// Configuration for validating a service via API
struct ServiceConfig {
    url: &'static str,
    auth: AuthMethod,
    /// Additional headers to include
    extra_headers: &'static [(&'static str, &'static str)],
}

/// Get the API validation config for a secret type, if available
fn get_config(secret_type: &SecretType) -> Option<ServiceConfig> {
    match secret_type {
        // ══════════════════════════════════════════════
        // Cloud & Infrastructure
        // ══════════════════════════════════════════════
        SecretType::CloudflareApiToken => Some(ServiceConfig {
            url: "https://api.cloudflare.com/client/v4/user/tokens/verify",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::VercelToken => Some(ServiceConfig {
            url: "https://api.vercel.com/v2/user",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::NetlifyPat | SecretType::NetlifyToken => Some(ServiceConfig {
            url: "https://api.netlify.com/api/v1/user",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::HerokuApiKey => Some(ServiceConfig {
            url: "https://api.heroku.com/account",
            auth: AuthMethod::Bearer,
            extra_headers: &[("Accept", "application/vnd.heroku+json; version=3")],
        }),
        SecretType::RenderApiKey => Some(ServiceConfig {
            url: "https://api.render.com/v1/owners",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::HetznerApiToken => Some(ServiceConfig {
            url: "https://api.hetzner.cloud/v1/servers",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::VultrApiKey => Some(ServiceConfig {
            url: "https://api.vultr.com/v2/account",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::LinodeApiToken => Some(ServiceConfig {
            url: "https://api.linode.com/v4/profile",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::ScalewayApiKey => Some(ServiceConfig {
            url: "https://api.scaleway.com/account/v3/projects",
            auth: AuthMethod::Header("X-Auth-Token"),
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // AI / ML Platforms
        // ══════════════════════════════════════════════
        SecretType::CohereApiKey => Some(ServiceConfig {
            url: "https://api.cohere.ai/v1/models",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::ReplicateApiKey => Some(ServiceConfig {
            url: "https://api.replicate.com/v1/account",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[],
        }),
        SecretType::GroqApiKey => Some(ServiceConfig {
            url: "https://api.groq.com/openai/v1/models",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::MistralApiKey => Some(ServiceConfig {
            url: "https://api.mistral.ai/v1/models",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::PerplexityApiKey => Some(ServiceConfig {
            url: "https://api.perplexity.ai/chat/completions",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::DeepgramApiKey => Some(ServiceConfig {
            url: "https://api.deepgram.com/v1/projects",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[],
        }),
        SecretType::AssemblyAiApiKey => Some(ServiceConfig {
            url: "https://api.assemblyai.com/v2/transcript",
            auth: AuthMethod::Header("authorization"),
            extra_headers: &[],
        }),
        SecretType::ElevenLabsApiKey => Some(ServiceConfig {
            url: "https://api.elevenlabs.io/v1/user",
            auth: AuthMethod::Header("xi-api-key"),
            extra_headers: &[],
        }),
        SecretType::WandBApiKey => Some(ServiceConfig {
            url: "https://api.wandb.ai/graphql",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Communication & Email
        // ══════════════════════════════════════════════
        SecretType::MailgunApiKey => Some(ServiceConfig {
            url: "https://api.mailgun.net/v3/domains",
            auth: AuthMethod::BasicAuthPassword,
            extra_headers: &[],
        }),
        SecretType::PostmarkApiToken => Some(ServiceConfig {
            url: "https://api.postmarkapp.com/server",
            auth: AuthMethod::Header("X-Postmark-Server-Token"),
            extra_headers: &[("Accept", "application/json")],
        }),
        SecretType::BrevoApiKey => Some(ServiceConfig {
            url: "https://api.brevo.com/v3/account",
            auth: AuthMethod::Header("api-key"),
            extra_headers: &[],
        }),
        SecretType::ResendApiKey => Some(ServiceConfig {
            url: "https://api.resend.com/domains",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::MailerSendApiKey => Some(ServiceConfig {
            url: "https://api.mailersend.com/v1/api-quota",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::MandrillApiKey => Some(ServiceConfig {
            url: "https://mandrillapp.com/api/1.0/users/info.json",
            auth: AuthMethod::Bearer, // Actually uses POST with key in body, but Bearer works for validation
            extra_headers: &[],
        }),
        SecretType::SparkPostApiKey => Some(ServiceConfig {
            url: "https://api.sparkpost.com/api/v1/account",
            auth: AuthMethod::Header("Authorization"),
            extra_headers: &[],
        }),
        SecretType::VonageApiKey => Some(ServiceConfig {
            url: "https://rest.nexmo.com/account/get-balance",
            auth: AuthMethod::QueryParam("api_key"),
            extra_headers: &[],
        }),
        SecretType::MessageBirdApiKey => Some(ServiceConfig {
            url: "https://rest.messagebird.com/balance",
            auth: AuthMethod::HeaderWithPrefix("AccessKey", ""),
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // SaaS & Productivity
        // ══════════════════════════════════════════════
        SecretType::NotionApiKey => Some(ServiceConfig {
            url: "https://api.notion.com/v1/users/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[("Notion-Version", "2022-06-28")],
        }),
        SecretType::AirtableApiKey | SecretType::AirtableOAuthToken => Some(ServiceConfig {
            url: "https://api.airtable.com/v0/meta/whoami",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::AsanaSecret | SecretType::AsanaClientId => Some(ServiceConfig {
            url: "https://app.asana.com/api/1.0/users/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::ClickUpPersonalToken => Some(ServiceConfig {
            url: "https://api.clickup.com/api/v2/user",
            auth: AuthMethod::Header("Authorization"),
            extra_headers: &[],
        }),
        SecretType::FigmaPat => Some(ServiceConfig {
            url: "https://api.figma.com/v1/me",
            auth: AuthMethod::Header("X-FIGMA-TOKEN"),
            extra_headers: &[],
        }),
        SecretType::TodoistApiKey => Some(ServiceConfig {
            url: "https://api.todoist.com/rest/v2/projects",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::TypeformApiToken => Some(ServiceConfig {
            url: "https://api.typeform.com/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::IntercomAccessToken => Some(ServiceConfig {
            url: "https://api.intercom.io/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[("Accept", "application/json")],
        }),
        SecretType::FreshdeskApiKey => Some(ServiceConfig {
            url: "https://support.freshdesk.com/api/v2/agents/me",
            auth: AuthMethod::BasicAuthPassword,
            extra_headers: &[],
        }),
        SecretType::WrikeApiToken => Some(ServiceConfig {
            url: "https://www.wrike.com/api/v4/contacts?me=true",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // DevTools & CI/CD
        // ══════════════════════════════════════════════
        SecretType::BitbucketAppPassword | SecretType::BitbucketToken => Some(ServiceConfig {
            url: "https://api.bitbucket.org/2.0/user",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::CircleCiToken | SecretType::CircleCiPersonalToken => Some(ServiceConfig {
            url: "https://circleci.com/api/v2/me",
            auth: AuthMethod::Header("Circle-Token"),
            extra_headers: &[],
        }),
        SecretType::TravisCiApiToken | SecretType::TravisCiToken => Some(ServiceConfig {
            url: "https://api.travis-ci.com/user",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[("Travis-API-Version", "3")],
        }),
        SecretType::BuildKiteApiToken => Some(ServiceConfig {
            url: "https://api.buildkite.com/v2/organizations",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::PostmanApiToken => Some(ServiceConfig {
            url: "https://api.getpostman.com/me",
            auth: AuthMethod::Header("X-Api-Key"),
            extra_headers: &[],
        }),
        SecretType::CodecovAccessToken => Some(ServiceConfig {
            url: "https://codecov.io/api/v2/",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::SnykApiToken => Some(ServiceConfig {
            url: "https://api.snyk.io/rest/self",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[("Content-Type", "application/vnd.api+json")],
        }),
        SecretType::SonarQubeToken => Some(ServiceConfig {
            url: "https://sonarcloud.io/api/authentication/validate",
            auth: AuthMethod::BasicAuthPassword,
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Monitoring & Observability
        // ══════════════════════════════════════════════
        SecretType::PagerDutyApiKey => Some(ServiceConfig {
            url: "https://api.pagerduty.com/users?limit=1",
            auth: AuthMethod::HeaderWithPrefix("Authorization", "Token token="),
            extra_headers: &[("Content-Type", "application/json")],
        }),
        // SentryDsn is a URL, not an API token — no API validation possible
        SecretType::PosthogApiKey => Some(ServiceConfig {
            url: "https://app.posthog.com/api/projects/",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::BugSnagApiKey => Some(ServiceConfig {
            url: "https://api.bugsnag.com/user",
            auth: AuthMethod::Header("Authorization"),
            extra_headers: &[],
        }),
        SecretType::RollbarApiKey => Some(ServiceConfig {
            url: "https://api.rollbar.com/api/1/status/ping",
            auth: AuthMethod::Header("X-Rollbar-Access-Token"),
            extra_headers: &[],
        }),
        SecretType::HoneycombApiKey => Some(ServiceConfig {
            url: "https://api.honeycomb.io/1/auth",
            auth: AuthMethod::Header("X-Honeycomb-Team"),
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Marketing & CRM
        // ══════════════════════════════════════════════
        SecretType::HubSpotApiKey | SecretType::HubSpotPrivateAppToken => Some(ServiceConfig {
            url: "https://api.hubapi.com/account-info/v3/api-usage/daily/private",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::ConvertKitApiKey => Some(ServiceConfig {
            url: "https://api.convertkit.com/v3/account",
            auth: AuthMethod::QueryParam("api_key"),
            extra_headers: &[],
        }),
        SecretType::KlaviyoApiKey => Some(ServiceConfig {
            url: "https://a.klaviyo.com/api/accounts/",
            auth: AuthMethod::HeaderWithPrefix("Authorization", "Klaviyo-API-Key "),
            extra_headers: &[("revision", "2023-12-15")],
        }),

        // ══════════════════════════════════════════════
        // Maps & Location
        // ══════════════════════════════════════════════
        SecretType::MapboxToken => Some(ServiceConfig {
            url: "https://api.mapbox.com/tokens/v2",
            auth: AuthMethod::QueryParam("access_token"),
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Database & Data
        // ══════════════════════════════════════════════
        SecretType::FaunaDbApiKey => Some(ServiceConfig {
            url: "https://graphql.fauna.com/graphql",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::PlanetScaleToken | SecretType::PlanetScalePassword => Some(ServiceConfig {
            url: "https://api.planetscale.com/v1/organizations",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::NeonApiKey => Some(ServiceConfig {
            url: "https://console.neon.tech/api/v2/projects",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::AivenApiToken => Some(ServiceConfig {
            url: "https://api.aiven.io/v1/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::InfluxDbToken => Some(ServiceConfig {
            url: "https://cloud2.influxdata.com/api/v2/me",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Payment
        // ══════════════════════════════════════════════
        SecretType::SquareAccessToken | SecretType::SquareOAuthToken => Some(ServiceConfig {
            url: "https://connect.squareup.com/v2/locations",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::CoinbaseAccessToken => Some(ServiceConfig {
            url: "https://api.coinbase.com/v2/user",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::GoCardlessApiToken => Some(ServiceConfig {
            url: "https://api.gocardless.com/creditors",
            auth: AuthMethod::Bearer,
            extra_headers: &[("GoCardless-Version", "2019-11-07")],
        }),
        SecretType::PaddleApiKey => Some(ServiceConfig {
            url: "https://vendors.paddle.com/api/2.0/subscription/users",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::LemonSqueezyApiKey => Some(ServiceConfig {
            url: "https://api.lemonsqueezy.com/v1/users/me",
            auth: AuthMethod::Bearer,
            extra_headers: &[("Accept", "application/vnd.api+json")],
        }),
        SecretType::RecurlyApiKey => Some(ServiceConfig {
            url: "https://v3.recurly.com/sites",
            auth: AuthMethod::Bearer,
            extra_headers: &[("Accept", "application/vnd.recurly.v2021-02-25+json")],
        }),

        // ══════════════════════════════════════════════
        // Content & CMS
        // ══════════════════════════════════════════════
        SecretType::ContentfulApiToken => Some(ServiceConfig {
            url: "https://cdn.contentful.com/spaces",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::StoryblokApiToken => Some(ServiceConfig {
            url: "https://api.storyblok.com/v2/cdn/spaces/me",
            auth: AuthMethod::QueryParam("token"),
            extra_headers: &[],
        }),
        SecretType::WebflowApiToken => Some(ServiceConfig {
            url: "https://api.webflow.com/v2/token/introspect",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Security & Identity
        // ══════════════════════════════════════════════
        SecretType::LaunchDarklyKey => Some(ServiceConfig {
            url: "https://app.launchdarkly.com/api/v2/caller-identity",
            auth: AuthMethod::Header("Authorization"),
            extra_headers: &[],
        }),
        SecretType::FastlyApiToken => Some(ServiceConfig {
            url: "https://api.fastly.com/current_user",
            auth: AuthMethod::Header("Fastly-Key"),
            extra_headers: &[],
        }),

        // ══════════════════════════════════════════════
        // Miscellaneous Services
        // ══════════════════════════════════════════════
        SecretType::AlgoliaApiKey => Some(ServiceConfig {
            url: "https://analytics.algolia.com/2/searches",
            auth: AuthMethod::Header("X-Algolia-API-Key"),
            extra_headers: &[],
        }),
        SecretType::TwilioAuthToken => Some(ServiceConfig {
            url: "https://api.twilio.com/2010-04-01/Accounts.json",
            auth: AuthMethod::BasicAuthPassword,
            extra_headers: &[],
        }),
        SecretType::BrowserStackAccessKey => Some(ServiceConfig {
            url: "https://api.browserstack.com/automate/plan.json",
            auth: AuthMethod::BasicAuthPassword,
            extra_headers: &[],
        }),
        SecretType::ShodanApiKey => Some(ServiceConfig {
            url: "https://api.shodan.io/api-info",
            auth: AuthMethod::QueryParam("key"),
            extra_headers: &[],
        }),
        SecretType::FullStoryApiKey => Some(ServiceConfig {
            url: "https://api.fullstory.com/operations/v1",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::SalesforceApiToken => Some(ServiceConfig {
            url: "https://login.salesforce.com/services/oauth2/userinfo",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::JFrogIdentityToken => Some(ServiceConfig {
            url: "https://jfrog.com/api/system/ping",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::DatabricksToken => Some(ServiceConfig {
            url: "https://accounts.cloud.databricks.com/api/2.0/preview/scim/v2/Me",
            auth: AuthMethod::Bearer,
            extra_headers: &[],
        }),
        SecretType::SourcegraphAccessToken => Some(ServiceConfig {
            url: "https://sourcegraph.com/.api/graphql",
            auth: AuthMethod::TokenAuth,
            extra_headers: &[],
        }),

        _ => None,
    }
}

#[async_trait::async_trait]
impl Validator for ServiceValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        let config = match get_config(&secret.secret_type) {
            Some(c) => c,
            None => return Ok(false),
        };

        let mut request = self.client.get(config.url);

        // Apply authentication
        match config.auth {
            AuthMethod::Bearer => {
                request = request.header("Authorization", format!("Bearer {}", secret.value));
            }
            AuthMethod::TokenAuth => {
                request = request.header("Authorization", format!("token {}", secret.value));
            }
            AuthMethod::Header(name) => {
                request = request.header(name, &secret.value);
            }
            AuthMethod::HeaderWithPrefix(header, prefix) => {
                request =
                    request.header(header, format!("{}{}", prefix, secret.value));
            }
            AuthMethod::BasicAuthPassword => {
                request = request.basic_auth("api", Some(&secret.value));
            }
            AuthMethod::QueryParam(param) => {
                request = request.query(&[(param, &secret.value)]);
            }
        }

        // Apply extra headers
        for (name, value) in config.extra_headers {
            request = request.header(*name, *value);
        }

        // Send request and check response
        let response = request.send().await?;
        match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(true),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Ok(false),
            StatusCode::TOO_MANY_REQUESTS => {
                // Propagate 429 as an error so the rate-limiter retry logic kicks in
                anyhow::bail!("429 Too Many Requests from {}", config.url)
            }
            status if status.is_server_error() => {
                // 5xx errors are transient — propagate so retry logic can handle them
                anyhow::bail!("Server error {} from {}", status.as_u16(), config.url)
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        get_config(secret_type).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    #[test]
    fn test_supports_known_services() {
        let validator = ServiceValidator::new();
        assert!(validator.supports(&SecretType::CloudflareApiToken));
        assert!(validator.supports(&SecretType::NotionApiKey));
        assert!(validator.supports(&SecretType::CohereApiKey));
        assert!(validator.supports(&SecretType::SquareAccessToken));
        assert!(validator.supports(&SecretType::CircleCiToken));
    }

    #[test]
    fn test_does_not_support_unknown() {
        let validator = ServiceValidator::new();
        // Types already handled by existing dedicated validators
        assert!(!validator.supports(&SecretType::GitHubPat));
        assert!(!validator.supports(&SecretType::AwsAccessKey));
        assert!(!validator.supports(&SecretType::SlackToken));
        // Generic types
        assert!(!validator.supports(&SecretType::GenericApiKey));
        assert!(!validator.supports(&SecretType::HighEntropyString));
    }

    #[tokio::test]
    async fn test_invalid_cloudflare_token() {
        let validator = ServiceValidator::new();
        let secret = Secret::new(
            SecretType::CloudflareApiToken,
            "invalid_token_12345678901234567890123".to_string(),
            4.0,
            Severity::High,
            0.9,
        );
        let result = validator.validate(&secret).await;
        assert!(result.is_ok());
        // Should return false for invalid token
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_invalid_notion_token() {
        let validator = ServiceValidator::new();
        let secret = Secret::new(
            SecretType::NotionApiKey,
            "ntn_invalidtokeninvalidtokeninvalidtokeninva".to_string(),
            4.0,
            Severity::High,
            0.9,
        );
        let result = validator.validate(&secret).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
