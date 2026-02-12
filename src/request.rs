//! Request building and signing logic for Alibaba Cloud STS API.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::config::ClientConfig;
use crate::credential::Credential;
use crate::error::{Result, StsError};
use crate::sign::{percent_encode, sign_request};

/// Cached regex for Role ARN validation.
///
/// ARN format: `acs:ram::{account-id}:role/{role-name}`
/// where account-id is 12-16 digits and role-name is 1-64 chars.
static ROLE_ARN_REGEX: OnceLock<Regex> = OnceLock::new();

/// Returns the cached Role ARN regex pattern.
fn role_arn_regex() -> &'static Regex {
    ROLE_ARN_REGEX.get_or_init(|| {
        Regex::new(r"^acs:ram::\d{12,16}:role/[a-zA-Z0-9\-_./]{1,64}$")
            .expect("Invalid ROLE_ARN_REGEX pattern")
    })
}

/// Validates a Role ARN format.
fn validate_role_arn(arn: &str) -> Result<()> {
    if !role_arn_regex().is_match(arn) {
        return Err(StsError::Validation(format!(
            "Invalid RoleArn format '{}'. Expected: acs:ram::{{12-16 digit account id}}:role/{{1-64 char role name}}",
            arn
        )));
    }
    Ok(())
}

/// Generates a random nonce for signature requests.
fn generate_nonce() -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is before Unix epoch")
        .as_nanos();
    format!("{}-{}", nonce, uuid::Uuid::new_v4())
}

/// Gets current timestamp in ISO 8601 format.
fn get_timestamp(time_offset_secs: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is before Unix epoch")
        .as_secs() as i64
        + time_offset_secs;
    let datetime =
        chrono::DateTime::from_timestamp(now, 0).expect("timestamp value is out of valid range");
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Builds a signed request body for Alibaba Cloud STS API.
///
/// This function:
/// 1. Adds common parameters (Action, Version, Format, etc.)
/// 2. Adds request-specific parameters
/// 3. Computes signature using HMAC-SHA256
/// 4. Returns the percent-encoded request body
///
/// # Arguments
///
/// * `action` - The STS API operation name (e.g., "AssumeRole")
/// * `params` - Key-value pairs of request parameters
/// * `credential` - Alibaba Cloud access key credential
/// * `config` - Client configuration
/// * `time_offset` - Time offset in seconds for clock skew correction
///
/// # Returns
///
/// Returns the percent-encoded request body on success.
///
/// # Errors
///
/// Returns [`StsError`] if:
///   - Credential cannot be resolved
///   - Signature computation fails
pub(crate) fn build_signed_request(
    action: &str,
    params: &[(&str, &str)],
    credential: &Credential,
    config: &ClientConfig,
    time_offset: i64,
) -> Result<String> {
    // Get credential fields directly
    let access_key_id = &credential.access_key_id;
    let access_key_secret = &credential.access_key_secret;

    // Validate RoleArn if present
    for (key, value) in params {
        if *key == "RoleArn" {
            validate_role_arn(value)?;
        }
    }

    // Build common parameters
    let timestamp = get_timestamp(time_offset);

    let mut all_params = BTreeMap::new();

    // Add common parameters
    all_params.insert("Action".to_string(), action.to_string());
    all_params.insert("Version".to_string(), config.api_version.to_string());
    all_params.insert("Format".to_string(), config.format.to_string());
    all_params.insert("AccessKeyId".to_string(), access_key_id.to_string());
    all_params.insert(
        "SignatureMethod".to_string(),
        config.signature_version.as_method_str().to_string(),
    );
    all_params.insert(
        "SignatureVersion".to_string(),
        config.signature_version.as_version_str().to_string(),
    );
    all_params.insert("SignatureNonce".to_string(), generate_nonce());
    all_params.insert("Timestamp".to_string(), timestamp);

    // Add request-specific parameters
    for (key, value) in params {
        all_params.insert(key.to_string(), value.to_string());
    }

    // Compute signature
    let signature = sign_request(
        &all_params,
        access_key_secret,
        "POST",
        config.signature_version,
    )?;

    // Build final request body
    all_params.insert("Signature".to_string(), signature);

    let body = all_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_signed_request_basic() {
        let credential = Credential {
            access_key_id: "test_key_id".to_string(),
            access_key_secret: "test_secret".to_string(),
        };
        let config = ClientConfig::default();

        let result = build_signed_request(
            "AssumeRole",
            &[("RoleArn", "acs:ram::1234567890123456:role/test")],
            &credential,
            &config,
            0,
        );

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("RoleArn=acs%3Aram%3A%3A1234567890123456%3Arole%2Ftest"));
        assert!(body.contains("Signature="));
    }

    #[test]
    fn build_signed_request_multiple_params() {
        let credential = Credential {
            access_key_id: "test_key_id".to_string(),
            access_key_secret: "test_secret".to_string(),
        };
        let config = ClientConfig::default();

        let result = build_signed_request(
            "AssumeRole",
            &[
                ("RoleArn", "acs:ram::1234567890123456:role/test"),
                ("RoleSessionName", "test-session"),
                ("DurationSeconds", "3600"),
            ],
            &credential,
            &config,
            0,
        );

        assert!(result.is_ok());
        let body = result.unwrap();
        assert!(body.contains("RoleSessionName=test-session"));
        assert!(body.contains("DurationSeconds=3600"));
    }
}
