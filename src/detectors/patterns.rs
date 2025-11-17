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

        // Generic API Key patterns
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
    ];
}

pub struct PatternDetector;

impl PatternDetector {
    pub fn new() -> Self {
        Self
    }

    /// Scan a line of text for secrets
    pub fn scan_line(&self, line: &str, entropy_threshold: f64) -> Vec<Secret> {
        let mut secrets = Vec::new();

        for pattern in PATTERNS.iter() {
            if let Some(captures) = pattern.regex.captures(line) {
                if let Some(matched) = captures.get(0) {
                    let value = matched.as_str().to_string();

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

                    secrets.push(secret);
                }
            }
        }

        secrets
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

    #[test]
    fn test_aws_access_key_detection() {
        let detector = PatternDetector::new();
        let line = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(matches!(secrets[0].secret_type, SecretType::AwsAccessKey));
    }

    #[test]
    fn test_github_pat_detection() {
        let detector = PatternDetector::new();
        let line = "GITHUB_TOKEN=ghp_1234567890123456789012345678901234";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(matches!(secrets[0].secret_type, SecretType::GitHubPat));
    }

    #[test]
    fn test_private_key_detection() {
        let detector = PatternDetector::new();
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty());
        assert!(matches!(secrets[0].secret_type, SecretType::RsaPrivateKey));
    }

    #[test]
    fn test_redis_detection() {
        let detector = PatternDetector::new();
        let line = "REDIS_URL=redis://:super_secret_redis_pass@redis-cluster.internal:6379";
        let secrets = detector.scan_line(line, 3.0);
        assert!(!secrets.is_empty(), "Redis pattern should match");
        let has_redis = secrets
            .iter()
            .any(|s| matches!(s.secret_type, SecretType::RedisConnectionString));
        assert!(has_redis, "Should detect Redis connection string");
    }
}
