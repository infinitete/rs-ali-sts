use serde::de::DeserializeOwned;

use crate::config::ClientConfig;
use crate::credential::{ChainProvider, Credential, CredentialProvider};
use crate::error::{Result, StsError, truncate_str};
use crate::request::build_signed_request;
use crate::response::ApiErrorResponse;

/// Request parameters for the AssumeRole API.
pub struct AssumeRoleRequest {
    /// ARN of the RAM role to assume.
    pub role_arn: String,
    /// Custom session name for CloudTrail audit logs.
    pub role_session_name: String,
    /// Additional policy to further restrict permissions.
    pub policy: Option<String>,
    /// Token validity duration in seconds (min: 900).
    pub duration_seconds: Option<u64>,
    /// External ID for cross-account role assumption.
    pub external_id: Option<String>,
}

impl AssumeRoleRequest {
    pub(crate) fn to_params(&self) -> Vec<(&str, String)> {
        let mut params = vec![
            ("RoleArn", self.role_arn.clone()),
            ("RoleSessionName", self.role_session_name.clone()),
        ];
        if let Some(ref policy) = self.policy {
            params.push(("Policy", policy.clone()));
        }
        if let Some(duration) = self.duration_seconds {
            params.push(("DurationSeconds", duration.to_string()));
        }
        if let Some(ref external_id) = self.external_id {
            params.push(("ExternalId", external_id.clone()));
        }
        params
    }
}

/// Request parameters for the AssumeRoleWithSAML API.
pub struct AssumeRoleWithSamlRequest {
    /// ARN of the SAML identity provider.
    pub saml_provider_arn: String,
    /// ARN of the RAM role to assume.
    pub role_arn: String,
    /// Base64-encoded SAML assertion.
    pub saml_assertion: String,
    /// Additional policy to further restrict permissions.
    pub policy: Option<String>,
    /// Token validity duration in seconds.
    pub duration_seconds: Option<u64>,
}

impl AssumeRoleWithSamlRequest {
    pub(crate) fn to_params(&self) -> Vec<(&str, String)> {
        let mut params = vec![
            ("SAMLProviderArn", self.saml_provider_arn.clone()),
            ("RoleArn", self.role_arn.clone()),
            ("SAMLAssertion", self.saml_assertion.clone()),
        ];
        if let Some(ref policy) = self.policy {
            params.push(("Policy", policy.clone()));
        }
        if let Some(duration) = self.duration_seconds {
            params.push(("DurationSeconds", duration.to_string()));
        }
        params
    }
}

/// Request parameters for the AssumeRoleWithOIDC API.
pub struct AssumeRoleWithOidcRequest {
    /// ARN of the OIDC identity provider.
    pub oidc_provider_arn: String,
    /// ARN of the RAM role to assume.
    pub role_arn: String,
    /// OIDC token from the external IdP.
    pub oidc_token: String,
    /// Additional policy to further restrict permissions.
    pub policy: Option<String>,
    /// Token validity duration in seconds.
    pub duration_seconds: Option<u64>,
    /// Custom session name.
    pub role_session_name: Option<String>,
}

impl AssumeRoleWithOidcRequest {
    pub(crate) fn to_params(&self) -> Vec<(&str, String)> {
        let mut params = vec![
            ("OIDCProviderArn", self.oidc_provider_arn.clone()),
            ("RoleArn", self.role_arn.clone()),
            ("OIDCToken", self.oidc_token.clone()),
        ];
        if let Some(ref policy) = self.policy {
            params.push(("Policy", policy.clone()));
        }
        if let Some(duration) = self.duration_seconds {
            params.push(("DurationSeconds", duration.to_string()));
        }
        if let Some(ref session) = self.role_session_name {
            params.push(("RoleSessionName", session.clone()));
        }
        params
    }
}

/// Async client for Alibaba Cloud STS API.
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
    credential: Credential,
}

impl Client {
    /// Creates a new client with an explicit credential.
    pub fn new(credential: Credential) -> Self {
        Self::with_config(credential, ClientConfig::default())
    }

    /// Creates a new client with an explicit credential and custom configuration.
    pub fn with_config(credential: Credential, config: ClientConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client");
        Self {
            http,
            config,
            credential,
        }
    }

    /// Creates a new client using the default credential chain (env vars → profile file).
    pub fn from_env() -> Result<Self> {
        let credential = ChainProvider::default_chain().resolve()?;
        Ok(Self::new(credential))
    }

    /// Assumes a RAM role and obtains temporary security credentials.
    pub async fn assume_role(
        &self,
        request: AssumeRoleRequest,
    ) -> Result<crate::response::AssumeRoleResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRole", &params).await
    }

    /// Assumes a RAM role using a SAML assertion for SSO.
    pub async fn assume_role_with_saml(
        &self,
        request: AssumeRoleWithSamlRequest,
    ) -> Result<crate::response::AssumeRoleWithSamlResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRoleWithSAML", &params).await
    }

    /// Assumes a RAM role using an OIDC token for SSO.
    pub async fn assume_role_with_oidc(
        &self,
        request: AssumeRoleWithOidcRequest,
    ) -> Result<crate::response::AssumeRoleWithOidcResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRoleWithOIDC", &params).await
    }

    /// Queries the identity of the current caller.
    pub async fn get_caller_identity(&self) -> Result<crate::response::GetCallerIdentityResponse> {
        self.execute("GetCallerIdentity", &[]).await
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let body = build_signed_request(action, params, &self.credential, &self.config)?;

        let response = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;

        if status.is_success() {
            serde_json::from_str(&text).map_err(StsError::from)
        } else {
            match serde_json::from_str::<ApiErrorResponse>(&text) {
                Ok(api_err) => Err(StsError::Api {
                    request_id: api_err.request_id,
                    code: api_err.code,
                    message: api_err.message,
                    recommend: api_err.recommend,
                }),
                Err(_) => Err(StsError::Http(format!(
                    "HTTP {} with body: {}",
                    status,
                    truncate_str(&text, 200)
                ))),
            }
        }
    }
}
