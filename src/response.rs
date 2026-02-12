use serde::Deserialize;

/// Temporary security credentials returned by STS.
///
/// The `Debug` implementation redacts `access_key_secret` and `security_token`
/// to prevent accidental credential leakage in logs.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub security_token: String,
    pub expiration: String,
}

impl Credentials {
    /// Returns the access key ID.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// Returns the access key secret.
    pub fn access_key_secret(&self) -> &str {
        &self.access_key_secret
    }

    /// Returns the security token.
    pub fn security_token(&self) -> &str {
        &self.security_token
    }

    /// Returns the expiration timestamp string.
    pub fn expiration(&self) -> &str {
        &self.expiration
    }

    /// Checks if the credentials have expired.
    ///
    /// Returns `true` if the current time is past the expiration time.
    pub fn is_expired(&self) -> bool {
        if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(&self.expiration) {
            let now = chrono::Utc::now();
            return now >= exp_time.with_timezone(&chrono::Utc);
        }
        // If we can't parse the expiration, assume expired for safety
        true
    }

    /// Returns the remaining time until expiration, if parseable.
    ///
    /// Returns `None` if the expiration time cannot be parsed or credentials are already expired.
    pub fn time_to_expiry(&self) -> Option<std::time::Duration> {
        if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(&self.expiration) {
            let now = chrono::Utc::now();
            let diff = exp_time.with_timezone(&chrono::Utc) - now;
            if diff.num_seconds() > 0 {
                return Some(std::time::Duration::from_secs(diff.num_seconds() as u64));
            }
        }
        None
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"****")
            .field("security_token", &"****")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Response from the AssumeRole API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleResponse {
    pub request_id: String,
    pub assumed_role_user: AssumedRoleUser,
    pub credentials: Credentials,
}

/// Information about the assumed role identity.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumedRoleUser {
    pub arn: String,
    pub assumed_role_id: String,
}

/// Response from the AssumeRoleWithSAML API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleWithSamlResponse {
    pub request_id: String,
    pub credentials: Credentials,
    #[serde(rename = "SAMLAssertionInfo")]
    pub saml_assertion_info: SamlAssertionInfo,
}

/// SAML assertion details.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SamlAssertionInfo {
    pub subject_type: String,
    pub subject: String,
    pub recipient: String,
    pub issuer: String,
}

/// Response from the AssumeRoleWithOIDC API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleWithOidcResponse {
    pub request_id: String,
    pub credentials: Credentials,
    #[serde(rename = "OIDCTokenInfo")]
    pub oidc_token_info: OidcTokenInfo,
}

/// OIDC token details.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OidcTokenInfo {
    pub subject: String,
    pub issuer: String,
    pub client_ids: String,
}

/// Response from the GetCallerIdentity API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetCallerIdentityResponse {
    pub request_id: String,
    pub account_id: String,
    pub arn: String,
    pub principal_id: String,
    pub identity_type: String,
    pub user_id: Option<String>,
    pub role_id: Option<String>,
}

/// Alibaba Cloud API error response body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ApiErrorResponse {
    pub request_id: String,
    pub code: String,
    pub message: String,
    pub recommend: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_redacts_secrets() {
        let creds = Credentials {
            access_key_id: "STS.XXXXXXXXXXXX".to_string(),
            access_key_secret: "super-secret-ak".to_string(),
            security_token: "super-secret-token".to_string(),
            expiration: "2024-01-01T01:00:00Z".to_string(),
        };
        let debug = format!("{:?}", creds);
        assert!(debug.contains("STS.XXXXXXXXXXXX"));
        assert!(debug.contains("****"));
        assert!(debug.contains("2024-01-01T01:00:00Z"));
        assert!(!debug.contains("super-secret-ak"));
        assert!(!debug.contains("super-secret-token"));
    }

    #[test]
    fn deserialize_assume_role_response() {
        let json = r#"{
            "RequestId": "6894B13B-6D71-4EF5-88FA-F32781734A7F",
            "AssumedRoleUser": {
                "Arn": "acs:ram::123456:role/test-role/session-name",
                "AssumedRoleId": "33157794895460****:session-name"
            },
            "Credentials": {
                "AccessKeyId": "STS.XXXXXXXXXXXX",
                "AccessKeySecret": "YYYYYYYYYYYY",
                "SecurityToken": "ZZZZZZZZZZZZ",
                "Expiration": "2024-01-01T01:00:00Z"
            }
        }"#;
        let resp: AssumeRoleResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.request_id, "6894B13B-6D71-4EF5-88FA-F32781734A7F");
        assert_eq!(resp.credentials.access_key_id, "STS.XXXXXXXXXXXX");
        assert_eq!(
            resp.assumed_role_user.assumed_role_id,
            "33157794895460****:session-name"
        );
    }

    #[test]
    fn deserialize_assume_role_with_saml_response() {
        let json = r#"{
            "RequestId": "req-saml-001",
            "Credentials": {
                "AccessKeyId": "STS.SAML_AK",
                "AccessKeySecret": "SAML_SECRET",
                "SecurityToken": "SAML_TOKEN",
                "Expiration": "2024-06-01T12:00:00Z"
            },
            "SAMLAssertionInfo": {
                "SubjectType": "persistent",
                "Subject": "user@example.com",
                "Recipient": "https://signin.aliyun.com/saml-role/sso",
                "Issuer": "https://idp.example.com"
            }
        }"#;
        let resp: AssumeRoleWithSamlResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.saml_assertion_info.subject, "user@example.com");
        assert_eq!(resp.saml_assertion_info.issuer, "https://idp.example.com");
    }

    #[test]
    fn deserialize_assume_role_with_oidc_response() {
        let json = r#"{
            "RequestId": "req-oidc-001",
            "Credentials": {
                "AccessKeyId": "STS.OIDC_AK",
                "AccessKeySecret": "OIDC_SECRET",
                "SecurityToken": "OIDC_TOKEN",
                "Expiration": "2024-06-01T12:00:00Z"
            },
            "OIDCTokenInfo": {
                "Subject": "oidc-user-001",
                "Issuer": "https://oidc.example.com",
                "ClientIds": "client-id-001"
            }
        }"#;
        let resp: AssumeRoleWithOidcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.oidc_token_info.subject, "oidc-user-001");
        assert_eq!(resp.oidc_token_info.client_ids, "client-id-001");
    }

    #[test]
    fn deserialize_get_caller_identity_response() {
        let json = r#"{
            "RequestId": "req-id-001",
            "AccountId": "123456789",
            "Arn": "acs:ram::123456789:user/testuser",
            "PrincipalId": "28877424437521****",
            "IdentityType": "RAMUser",
            "UserId": "28877424437521****"
        }"#;
        let resp: GetCallerIdentityResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.account_id, "123456789");
        assert_eq!(resp.identity_type, "RAMUser");
        assert!(resp.user_id.is_some());
        assert!(resp.role_id.is_none());
    }

    #[test]
    fn deserialize_api_error_response() {
        let json = r#"{
            "RequestId": "err-req-001",
            "Code": "InvalidParameter.RoleArn",
            "Message": "The specified RoleArn is invalid.",
            "Recommend": "https://error-center.aliyun.com/"
        }"#;
        let resp: ApiErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.code, "InvalidParameter.RoleArn");
        assert!(resp.recommend.is_some());
    }
}
