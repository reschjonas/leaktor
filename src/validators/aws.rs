use crate::models::{Secret, SecretType};
use crate::validators::Validator;
use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use sha2::{Digest, Sha256};

pub struct AwsValidator {
    client: Client,
}

impl AwsValidator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    /// Validate an AWS access key by calling STS GetCallerIdentity.
    ///
    /// This is a read-only, side-effect-free API call. It does not modify any
    /// resources and is the standard way to check if AWS credentials are active.
    /// It requires both an access key and a secret key to sign the request.
    ///
    /// If only an access key is found (no paired secret key), we fall back to
    /// format validation only.
    async fn validate_with_sts(&self, access_key: &str, secret_key: &str) -> Result<bool> {
        let region = "us-east-1";
        let service = "sts";
        let host = "sts.amazonaws.com";
        let endpoint = "https://sts.amazonaws.com/";
        let body = "Action=GetCallerIdentity&Version=2011-06-15";

        let now = Utc::now();
        let datestamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Step 1: Create canonical request
        let content_hash = hex_sha256(body.as_bytes());
        let canonical_headers = format!(
            "content-type:application/x-www-form-urlencoded\nhost:{}\nx-amz-date:{}\n",
            host, amz_date
        );
        let signed_headers = "content-type;host;x-amz-date";
        let canonical_request = format!(
            "POST\n/\n\n{}{}\n{}",
            canonical_headers, signed_headers, content_hash
        );

        // Step 2: Create string to sign
        let credential_scope = format!("{}/{}/{}/aws4_request", datestamp, region, service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex_sha256(canonical_request.as_bytes())
        );

        // Step 3: Calculate signature
        let signing_key = get_signature_key(secret_key, &datestamp, region, service);
        let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

        // Step 4: Build authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            access_key, credential_scope, signed_headers, signature
        );

        let response = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Host", host)
            .header("X-Amz-Date", &amz_date)
            .header("Authorization", &authorization)
            .body(body)
            .send()
            .await?;

        // 200 = valid credentials
        // 403 = invalid/expired credentials
        Ok(response.status().as_u16() == 200)
    }

    /// Basic format validation when we only have an access key (no secret key).
    fn validate_format_only(access_key: &str) -> bool {
        let valid_prefix = access_key.starts_with("AKIA")
            || access_key.starts_with("ASIA")
            || access_key.starts_with("AGPA")
            || access_key.starts_with("AIDA")
            || access_key.starts_with("AROA")
            || access_key.starts_with("AIPA")
            || access_key.starts_with("ANPA")
            || access_key.starts_with("ANVA");
        valid_prefix && access_key.len() == 20
    }
}

impl Default for AwsValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Validator for AwsValidator {
    async fn validate(&self, secret: &Secret) -> Result<bool> {
        match secret.secret_type {
            SecretType::AwsAccessKey => {
                // We only have the access key; we can't call STS without the secret key.
                // Return format validation. The caller can pair it with a secret key
                // if both are found in the same context.
                Ok(Self::validate_format_only(&secret.value))
            }
            SecretType::AwsSecretKey => {
                // Secret keys are 40 characters, base64-ish alphabet
                let looks_valid = secret.value.len() == 40
                    && secret
                        .value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
                Ok(looks_valid)
            }
            _ => Ok(false),
        }
    }

    fn supports(&self, secret_type: &SecretType) -> bool {
        matches!(
            secret_type,
            SecretType::AwsAccessKey | SecretType::AwsSecretKey | SecretType::AwsSessionToken
        )
    }
}

/// Validate an AWS access key + secret key pair via real STS call.
/// This is exposed as a standalone function so callers can pair keys found
/// in the same file/context and validate them together.
pub async fn validate_aws_keypair(access_key: &str, secret_key: &str) -> Result<bool> {
    let validator = AwsValidator::new();
    validator.validate_with_sts(access_key, secret_key).await
}

// ─── AWS Signature V4 helpers ────────────────────────────────────────────────

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use sha2::Sha256;
    // HMAC-SHA256 implemented manually (no extra crate needed)
    let block_size = 64;

    let key = if key.len() > block_size {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    let mut padded_key = vec![0u8; block_size];
    padded_key[..key.len()].copy_from_slice(&key);

    let mut ipad = vec![0x36u8; block_size];
    let mut opad = vec![0x5cu8; block_size];
    for i in 0..block_size {
        ipad[i] ^= padded_key[i];
        opad[i] ^= padded_key[i];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(inner_hash);
    outer_hasher.finalize().to_vec()
}

fn hex_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let result = hmac_sha256(key, data);
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

fn get_signature_key(key: &str, datestamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", key).as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    #[tokio::test]
    async fn test_aws_access_key_format_validation() {
        let validator = AwsValidator::new();
        let secret = Secret::new(
            SecretType::AwsAccessKey,
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            4.0,
            Severity::Critical,
            0.9,
        );

        let result = validator.validate(&secret).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Valid AKIA prefix + 20 chars should pass format check"
        );
    }

    #[tokio::test]
    async fn test_aws_access_key_invalid_prefix() {
        let validator = AwsValidator::new();
        let secret = Secret::new(
            SecretType::AwsAccessKey,
            "XYZAIOSFODNN7EXAMPL".to_string(),
            4.0,
            Severity::Critical,
            0.9,
        );

        let result = validator.validate(&secret).await.unwrap();
        assert!(!result, "Invalid prefix should fail format check");
    }

    #[tokio::test]
    async fn test_aws_secret_key_validation() {
        let validator = AwsValidator::new();
        let secret = Secret::new(
            SecretType::AwsSecretKey,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            4.5,
            Severity::Critical,
            0.9,
        );

        let result = validator.validate(&secret).await.unwrap();
        assert!(result, "40-char base64 string should pass");
    }

    #[test]
    fn test_supports() {
        let validator = AwsValidator::new();
        assert!(validator.supports(&SecretType::AwsAccessKey));
        assert!(validator.supports(&SecretType::AwsSecretKey));
        assert!(validator.supports(&SecretType::AwsSessionToken));
        assert!(!validator.supports(&SecretType::GitHubToken));
    }

    #[test]
    fn test_hmac_sha256_basic() {
        // Smoke test: HMAC should produce 32 bytes
        let result = hmac_sha256(b"key", b"data");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hex_sha256() {
        let hash = hex_sha256(b"");
        // SHA256 of empty string is well-known
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
