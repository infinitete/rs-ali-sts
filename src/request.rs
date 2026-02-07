use std::collections::BTreeMap;

use chrono::Utc;
use uuid::Uuid;

use crate::config::ClientConfig;
use crate::credential::Credential;
use crate::error::Result;
use crate::sign::{percent_encode, sign_request};

/// Builds a fully signed request body (URL-encoded form data) for an STS API call.
pub(crate) fn build_signed_request(
    action: &str,
    action_params: &[(&str, &str)],
    credential: &Credential,
    config: &ClientConfig,
) -> Result<String> {
    let mut params = BTreeMap::new();

    // Common parameters
    params.insert("Action".to_string(), action.to_string());
    params.insert("Format".to_string(), config.format.to_string());
    params.insert("Version".to_string(), config.api_version.to_string());
    params.insert("AccessKeyId".to_string(), credential.access_key_id.clone());
    params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
    params.insert("SignatureVersion".to_string(), "1.0".to_string());
    params.insert("SignatureNonce".to_string(), Uuid::new_v4().to_string());
    params.insert(
        "Timestamp".to_string(),
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    );

    // Action-specific parameters
    for (key, value) in action_params {
        params.insert(key.to_string(), value.to_string());
    }

    // Compute signature
    let signature = sign_request(&params, &credential.access_key_secret, "POST")?;
    params.insert("Signature".to_string(), signature);

    // Build URL-encoded form body
    let body: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    Ok(body)
}

/// Builds a signed request body with a fixed nonce and timestamp (for testing).
#[cfg(test)]
pub(crate) fn build_signed_request_with_fixed(
    action: &str,
    action_params: &[(&str, &str)],
    credential: &Credential,
    config: &ClientConfig,
    nonce: &str,
    timestamp: &str,
) -> Result<String> {
    let mut params = BTreeMap::new();

    params.insert("Action".to_string(), action.to_string());
    params.insert("Format".to_string(), config.format.to_string());
    params.insert("Version".to_string(), config.api_version.to_string());
    params.insert("AccessKeyId".to_string(), credential.access_key_id.clone());
    params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
    params.insert("SignatureVersion".to_string(), "1.0".to_string());
    params.insert("SignatureNonce".to_string(), nonce.to_string());
    params.insert("Timestamp".to_string(), timestamp.to_string());

    for (key, value) in action_params {
        params.insert(key.to_string(), value.to_string());
    }

    let signature = sign_request(&params, &credential.access_key_secret, "POST")?;
    params.insert("Signature".to_string(), signature);

    let body: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credential() -> Credential {
        Credential {
            access_key_id: "test-ak-id".to_string(),
            access_key_secret: "test-ak-secret".to_string(),
        }
    }

    #[test]
    fn build_request_contains_common_params() {
        let body = build_signed_request(
            "AssumeRole",
            &[
                ("RoleArn", "acs:ram::123:role/test"),
                ("RoleSessionName", "sess"),
            ],
            &test_credential(),
            &ClientConfig::default(),
        )
        .unwrap();

        assert!(body.contains("Action=AssumeRole"));
        assert!(body.contains("Format=JSON"));
        assert!(body.contains("Version=2015-04-01"));
        assert!(body.contains("AccessKeyId=test-ak-id"));
        assert!(body.contains("SignatureMethod=HMAC-SHA1"));
        assert!(body.contains("SignatureVersion=1.0"));
        assert!(body.contains("SignatureNonce="));
        assert!(body.contains("Timestamp="));
        assert!(body.contains("Signature="));
    }

    #[test]
    fn build_request_contains_action_params() {
        let body = build_signed_request(
            "AssumeRole",
            &[
                ("RoleArn", "acs:ram::123:role/myrole"),
                ("RoleSessionName", "test-session"),
            ],
            &test_credential(),
            &ClientConfig::default(),
        )
        .unwrap();

        assert!(body.contains("RoleSessionName=test-session"));
        assert!(body.contains("RoleArn="));
    }

    #[test]
    fn build_request_unique_nonce() {
        let cred = test_credential();
        let config = ClientConfig::default();

        let body1 = build_signed_request("GetCallerIdentity", &[], &cred, &config).unwrap();
        let body2 = build_signed_request("GetCallerIdentity", &[], &cred, &config).unwrap();

        assert_ne!(body1, body2);
    }

    #[test]
    fn build_request_fixed_is_deterministic() {
        let cred = test_credential();
        let config = ClientConfig::default();

        let body1 = build_signed_request_with_fixed(
            "GetCallerIdentity",
            &[],
            &cred,
            &config,
            "fixed-nonce",
            "2024-01-01T00:00:00Z",
        )
        .unwrap();
        let body2 = build_signed_request_with_fixed(
            "GetCallerIdentity",
            &[],
            &cred,
            &config,
            "fixed-nonce",
            "2024-01-01T00:00:00Z",
        )
        .unwrap();

        assert_eq!(body1, body2);
    }

    #[test]
    fn build_request_timestamp_format() {
        let body = build_signed_request(
            "GetCallerIdentity",
            &[],
            &test_credential(),
            &ClientConfig::default(),
        )
        .unwrap();

        assert!(body.contains("Timestamp="));
    }
}
