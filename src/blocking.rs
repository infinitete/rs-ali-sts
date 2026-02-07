//! Synchronous (blocking) client for Alibaba Cloud STS API.
//!
//! This module is only available when the `blocking` feature is enabled.
//! It mirrors the async [`crate::client::Client`] API using `reqwest::blocking`.

use serde::de::DeserializeOwned;

use crate::client::{AssumeRoleRequest, AssumeRoleWithOidcRequest, AssumeRoleWithSamlRequest};
use crate::config::ClientConfig;
use crate::credential::{ChainProvider, Credential, CredentialProvider};
use crate::error::{Result, StsError, truncate_str};
use crate::request::build_signed_request;
use crate::response::ApiErrorResponse;

/// Synchronous client for Alibaba Cloud STS API.
pub struct Client {
    http: reqwest::blocking::Client,
    config: ClientConfig,
    credential: Credential,
}

impl Client {
    /// Creates a new blocking client with an explicit credential.
    pub fn new(credential: Credential) -> Self {
        Self::with_config(credential, ClientConfig::default())
    }

    /// Creates a new blocking client with custom configuration.
    pub fn with_config(credential: Credential, config: ClientConfig) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client");
        Self {
            http,
            config,
            credential,
        }
    }

    /// Creates a new blocking client using the default credential chain.
    pub fn from_env() -> Result<Self> {
        let credential = ChainProvider::default_chain().resolve()?;
        Ok(Self::new(credential))
    }

    /// Assumes a RAM role and obtains temporary security credentials.
    pub fn assume_role(
        &self,
        request: AssumeRoleRequest,
    ) -> Result<crate::response::AssumeRoleResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRole", &params)
    }

    /// Assumes a RAM role using a SAML assertion for SSO.
    pub fn assume_role_with_saml(
        &self,
        request: AssumeRoleWithSamlRequest,
    ) -> Result<crate::response::AssumeRoleWithSamlResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRoleWithSAML", &params)
    }

    /// Assumes a RAM role using an OIDC token for SSO.
    pub fn assume_role_with_oidc(
        &self,
        request: AssumeRoleWithOidcRequest,
    ) -> Result<crate::response::AssumeRoleWithOidcResponse> {
        let owned = request.to_params();
        let params: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.execute("AssumeRoleWithOIDC", &params)
    }

    /// Queries the identity of the current caller.
    pub fn get_caller_identity(&self) -> Result<crate::response::GetCallerIdentityResponse> {
        self.execute("GetCallerIdentity", &[])
    }

    fn execute<T: DeserializeOwned>(&self, action: &str, params: &[(&str, &str)]) -> Result<T> {
        let body = build_signed_request(action, params, &self.credential, &self.config)?;

        let response = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()?;

        let status = response.status();
        let text = response.text()?;

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
