use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::Semaphore;

use crate::config::ClientConfig;
use crate::credential::{ChainProvider, Credential, CredentialProvider};
use crate::error::{Result, StsError};
use crate::exec::{calculate_smoothed_offset, extract_server_time, handle_response};
use crate::request::build_signed_request;

/// Request parameters for the AssumeRole API.
///
/// # Example
///
/// ```
/// use rs_ali_sts::AssumeRoleRequest;
///
/// let request = AssumeRoleRequest::builder()
///     .role_arn("acs:ram::123456789012:role/test-role")
///     .role_session_name("my-session")
///     .duration_seconds(3600)
///     .build();
/// ```
#[derive(Debug, Clone)]
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
    /// Creates a new builder for constructing an AssumeRole request.
    pub fn builder() -> AssumeRoleRequestBuilder {
        AssumeRoleRequestBuilder::default()
    }

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

/// Builder for constructing [`AssumeRoleRequest`] instances.
///
/// # Example
///
/// ```
/// use rs_ali_sts::AssumeRoleRequest;
///
/// let request = AssumeRoleRequest::builder()
///     .role_arn("acs:ram::123456789012:role/test-role")
///     .role_session_name("my-session")
///     .duration_seconds(3600)
///     .build();
/// ```
#[derive(Default)]
pub struct AssumeRoleRequestBuilder {
    role_arn: Option<String>,
    role_session_name: Option<String>,
    policy: Option<String>,
    duration_seconds: Option<u64>,
    external_id: Option<String>,
}

impl AssumeRoleRequestBuilder {
    /// Sets the ARN of the RAM role to assume.
    pub fn role_arn(mut self, arn: impl Into<String>) -> Self {
        self.role_arn = Some(arn.into());
        self
    }

    /// Sets the custom session name for CloudTrail audit logs.
    pub fn role_session_name(mut self, name: impl Into<String>) -> Self {
        self.role_session_name = Some(name.into());
        self
    }

    /// Sets the additional policy to further restrict permissions.
    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Sets the token validity duration in seconds (min: 900, max: 3600).
    pub fn duration_seconds(mut self, seconds: u64) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Sets the external ID for cross-account role assumption.
    pub fn external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }

    /// Builds the [`AssumeRoleRequest`] instance.
    ///
    /// # Panics
    ///
    /// Panics if `role_arn` or `role_session_name` is not set.
    /// For a non-panicking version, use [`try_build`](Self::try_build).
    pub fn build(self) -> AssumeRoleRequest {
        self.try_build()
            .expect("AssumeRoleRequest requires role_arn and role_session_name")
    }

    /// Attempts to build the [`AssumeRoleRequest`] instance.
    ///
    /// Returns an error if required fields are missing.
    ///
    /// # Errors
    ///
    /// Returns [`StsError::Validation`] if `role_arn` or `role_session_name` is not set.
    pub fn try_build(self) -> Result<AssumeRoleRequest> {
        let role_arn = self.role_arn.ok_or_else(|| {
            StsError::Validation("role_arn is required for AssumeRoleRequest".into())
        })?;
        let role_session_name = self.role_session_name.ok_or_else(|| {
            StsError::Validation("role_session_name is required for AssumeRoleRequest".into())
        })?;
        Ok(AssumeRoleRequest {
            role_arn,
            role_session_name,
            policy: self.policy,
            duration_seconds: self.duration_seconds,
            external_id: self.external_id,
        })
    }
}

/// Request parameters for the AssumeRoleWithSAML API.
#[derive(Debug, Clone)]
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
    /// Creates a new builder for constructing an AssumeRoleWithSAML request.
    pub fn builder() -> AssumeRoleWithSamlRequestBuilder {
        AssumeRoleWithSamlRequestBuilder::default()
    }

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

/// Builder for constructing [`AssumeRoleWithSamlRequest`] instances.
#[derive(Default)]
pub struct AssumeRoleWithSamlRequestBuilder {
    saml_provider_arn: Option<String>,
    role_arn: Option<String>,
    saml_assertion: Option<String>,
    policy: Option<String>,
    duration_seconds: Option<u64>,
}

impl AssumeRoleWithSamlRequestBuilder {
    /// Sets the ARN of the SAML identity provider.
    pub fn saml_provider_arn(mut self, arn: impl Into<String>) -> Self {
        self.saml_provider_arn = Some(arn.into());
        self
    }

    /// Sets the ARN of the RAM role to assume.
    pub fn role_arn(mut self, arn: impl Into<String>) -> Self {
        self.role_arn = Some(arn.into());
        self
    }

    /// Sets the Base64-encoded SAML assertion.
    pub fn saml_assertion(mut self, assertion: impl Into<String>) -> Self {
        self.saml_assertion = Some(assertion.into());
        self
    }

    /// Sets the additional policy to further restrict permissions.
    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Sets the token validity duration in seconds.
    pub fn duration_seconds(mut self, seconds: u64) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Builds the [`AssumeRoleWithSamlRequest`] instance.
    ///
    /// # Panics
    ///
    /// Panics if `saml_provider_arn`, `role_arn`, or `saml_assertion` is not set.
    /// For a non-panicking version, use [`try_build`](Self::try_build).
    pub fn build(self) -> AssumeRoleWithSamlRequest {
        self.try_build().expect(
            "AssumeRoleWithSamlRequest requires saml_provider_arn, role_arn, and saml_assertion",
        )
    }

    /// Attempts to build the [`AssumeRoleWithSamlRequest`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`StsError::Validation`] if required fields are missing.
    pub fn try_build(self) -> Result<AssumeRoleWithSamlRequest> {
        let saml_provider_arn = self.saml_provider_arn.ok_or_else(|| {
            StsError::Validation(
                "saml_provider_arn is required for AssumeRoleWithSamlRequest".into(),
            )
        })?;
        let role_arn = self.role_arn.ok_or_else(|| {
            StsError::Validation("role_arn is required for AssumeRoleWithSamlRequest".into())
        })?;
        let saml_assertion = self.saml_assertion.ok_or_else(|| {
            StsError::Validation("saml_assertion is required for AssumeRoleWithSamlRequest".into())
        })?;
        Ok(AssumeRoleWithSamlRequest {
            saml_provider_arn,
            role_arn,
            saml_assertion,
            policy: self.policy,
            duration_seconds: self.duration_seconds,
        })
    }
}

/// Request parameters for the AssumeRoleWithOIDC API.
#[derive(Debug, Clone)]
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
    /// Creates a new builder for constructing an AssumeRoleWithOIDC request.
    pub fn builder() -> AssumeRoleWithOidcRequestBuilder {
        AssumeRoleWithOidcRequestBuilder::default()
    }

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

/// Builder for constructing [`AssumeRoleWithOidcRequest`] instances.
#[derive(Default)]
pub struct AssumeRoleWithOidcRequestBuilder {
    oidc_provider_arn: Option<String>,
    role_arn: Option<String>,
    oidc_token: Option<String>,
    policy: Option<String>,
    duration_seconds: Option<u64>,
    role_session_name: Option<String>,
}

impl AssumeRoleWithOidcRequestBuilder {
    /// Sets the ARN of the OIDC identity provider.
    pub fn oidc_provider_arn(mut self, arn: impl Into<String>) -> Self {
        self.oidc_provider_arn = Some(arn.into());
        self
    }

    /// Sets the ARN of the RAM role to assume.
    pub fn role_arn(mut self, arn: impl Into<String>) -> Self {
        self.role_arn = Some(arn.into());
        self
    }

    /// Sets the OIDC token from the external IdP.
    pub fn oidc_token(mut self, token: impl Into<String>) -> Self {
        self.oidc_token = Some(token.into());
        self
    }

    /// Sets the additional policy to further restrict permissions.
    pub fn policy(mut self, policy: impl Into<String>) -> Self {
        self.policy = Some(policy.into());
        self
    }

    /// Sets the token validity duration in seconds.
    pub fn duration_seconds(mut self, seconds: u64) -> Self {
        self.duration_seconds = Some(seconds);
        self
    }

    /// Sets the custom session name.
    pub fn role_session_name(mut self, name: impl Into<String>) -> Self {
        self.role_session_name = Some(name.into());
        self
    }

    /// Builds the [`AssumeRoleWithOidcRequest`] instance.
    ///
    /// # Panics
    ///
    /// Panics if `oidc_provider_arn`, `role_arn`, or `oidc_token` is not set.
    /// For a non-panicking version, use [`try_build`](Self::try_build).
    pub fn build(self) -> AssumeRoleWithOidcRequest {
        self.try_build().expect(
            "AssumeRoleWithOidcRequest requires oidc_provider_arn, role_arn, and oidc_token",
        )
    }

    /// Attempts to build the [`AssumeRoleWithOidcRequest`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`StsError::Validation`] if required fields are missing.
    pub fn try_build(self) -> Result<AssumeRoleWithOidcRequest> {
        let oidc_provider_arn = self.oidc_provider_arn.ok_or_else(|| {
            StsError::Validation(
                "oidc_provider_arn is required for AssumeRoleWithOidcRequest".into(),
            )
        })?;
        let role_arn = self.role_arn.ok_or_else(|| {
            StsError::Validation("role_arn is required for AssumeRoleWithOidcRequest".into())
        })?;
        let oidc_token = self.oidc_token.ok_or_else(|| {
            StsError::Validation("oidc_token is required for AssumeRoleWithOidcRequest".into())
        })?;
        Ok(AssumeRoleWithOidcRequest {
            oidc_provider_arn,
            role_arn,
            oidc_token,
            policy: self.policy,
            duration_seconds: self.duration_seconds,
            role_session_name: self.role_session_name,
        })
    }
}

/// Async client for Alibaba Cloud STS API.
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
    credential: Credential,
    /// Clock skew offset in seconds (server_time - local_time).
    /// This is used to correct for local clock drift.
    time_offset: Arc<AtomicI64>,
    /// Semaphore for limiting concurrent requests.
    semaphore: Arc<Semaphore>,
}

impl Client {
    /// Creates a new client with an explicit credential.
    pub fn new(credential: Credential) -> Result<Self> {
        Self::with_config(credential, ClientConfig::default())
    }

    /// Creates a new client with an explicit credential and custom configuration.
    pub fn with_config(credential: Credential, config: ClientConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host);

        // Apply TCP keepalive if configured
        if let Some(keepalive) = config.tcp_keepalive {
            builder = builder.tcp_keepalive(keepalive);
        }

        let http = builder.build().map_err(StsError::HttpClient)?;
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
        Ok(Self {
            http,
            config,
            credential,
            time_offset: Arc::new(AtomicI64::new(0)),
            semaphore,
        })
    }

    /// Creates a new client using the default credential chain (env vars → profile file).
    pub fn from_env() -> Result<Self> {
        let credential = ChainProvider::default_chain().resolve()?;
        Self::new(credential)
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

    /// Returns the current clock offset in seconds.
    ///
    /// A positive value means the local clock is behind the server clock.
    /// A negative value means the local clock is ahead of the server clock.
    pub fn time_offset(&self) -> i64 {
        self.time_offset.load(Ordering::Relaxed)
    }

    /// Updates the clock offset based on the server time using exponential smoothing.
    ///
    /// This is called automatically when responses include server time information.
    /// Uses 75% old + 25% new to reduce jitter from network latency variations.
    fn update_time_offset(&self, server_time: i64) {
        let local_time = chrono::Utc::now().timestamp();
        let new_offset = server_time - local_time;
        let current_offset = self.time_offset.load(Ordering::Relaxed);
        let smoothed = calculate_smoothed_offset(current_offset, new_offset);
        self.time_offset.store(smoothed, Ordering::Relaxed);
    }

    async fn execute<T: DeserializeOwned>(
        &self,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        // Acquire semaphore permit for concurrency control
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| crate::error::StsError::Config(format!("Semaphore closed: {}", e)))?;

        let time_offset = self.time_offset.load(Ordering::Relaxed);
        let body =
            build_signed_request(action, params, &self.credential, &self.config, time_offset)?;

        let response = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        // Try to extract server time from response headers for clock skew correction
        if let Some(server_time) = extract_server_time(response.headers()) {
            self.update_time_offset(server_time);
        }

        let status = response.status();
        let text = response.text().await?;

        handle_response(status, text)
    }
}
