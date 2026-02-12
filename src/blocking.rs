//! Synchronous (blocking) client for Alibaba Cloud STS API.
//!
//! This module is only available when the `blocking` feature is enabled.
//! It mirrors the async [`crate::client::Client`] API using `reqwest::blocking`.
//!
//! # When to Use
//!
//! Use the blocking client when:
//! - You don't need concurrent operations
//! - You're writing a CLI tool or simple script
//! - You prefer synchronous code style
//!
//! Use the async [`crate::Client`] when:
//! - You need high concurrency
//! - You're building a web service or API
//! - You want automatic request rate limiting
//!
//! # Differences from Async Client
//!
//! | Feature | Async `Client` | Blocking `Client` |
//! |---------|----------------|-------------------|
//! | Concurrency control | Semaphore limiting | None |
//! | Runtime requirement | Tokio | None |
//! | Best for | Services, high concurrency | Scripts, CLI tools |
//!
//! # Example
//!
//! ```no_run
//! use rs_ali_sts::blocking::Client;
//! use rs_ali_sts::{Credential, AssumeRoleRequest};
//!
//! fn main() -> rs_ali_sts::Result<()> {
//!     let client = Client::new(Credential::new("id", "secret"))?;
//!
//!     let request = AssumeRoleRequest::builder()
//!         .role_arn("acs:ram::123456:role/example")
//!         .role_session_name("session")
//!         .build();
//!
//!     let resp = client.assume_role(request)?;
//!     println!("AK: {}", resp.credentials.access_key_id);
//!     Ok(())
//! }
//! ```

use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::client::{AssumeRoleRequest, AssumeRoleWithOidcRequest, AssumeRoleWithSamlRequest};
use crate::config::ClientConfig;
use crate::credential::{ChainProvider, Credential, CredentialProvider};
use crate::error::{Result, StsError};
use crate::exec::{calculate_smoothed_offset, extract_server_time, handle_response};
use crate::request::build_signed_request;

/// Synchronous client for Alibaba Cloud STS API.
pub struct Client {
    http: reqwest::blocking::Client,
    config: ClientConfig,
    credential: Credential,
    /// Clock skew offset in seconds (server_time - local_time).
    /// This is used to correct for local clock drift.
    time_offset: Arc<AtomicI64>,
}

impl Client {
    /// Creates a new blocking client with an explicit credential.
    pub fn new(credential: Credential) -> Result<Self> {
        Self::with_config(credential, ClientConfig::default())
    }

    /// Creates a new blocking client with custom configuration.
    pub fn with_config(credential: Credential, config: ClientConfig) -> Result<Self> {
        // Build HTTP client with connection pool configuration
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host);

        // Apply TCP keepalive if configured
        if let Some(keepalive) = config.tcp_keepalive {
            builder = builder.tcp_keepalive(keepalive);
        }

        let http = builder
            .build()
            .map_err(|e| StsError::Config(format!("Failed to build HTTP client: {}", e)))?;

        // Initialize clock offset to 0 (no correction)
        let time_offset = Arc::new(AtomicI64::new(0));

        Ok(Self {
            http,
            config,
            credential,
            time_offset,
        })
    }

    /// Creates a new blocking client using the default credential chain.
    pub fn from_env() -> Result<Self> {
        let credential = ChainProvider::default_chain().resolve()?;
        Self::new(credential)
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

    fn execute<T: DeserializeOwned>(&self, action: &str, params: &[(&str, &str)]) -> Result<T> {
        // Get current time offset for clock skew correction
        let time_offset = self.time_offset.load(Ordering::Relaxed);

        let body =
            build_signed_request(action, params, &self.credential, &self.config, time_offset)?;

        let response = self
            .http
            .post(&self.config.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()?;

        // Try to extract server time from response headers for clock skew correction
        if let Some(server_time) = extract_server_time(response.headers()) {
            self.update_time_offset(server_time);
        }

        let status = response.status();
        let text = response.text()?;

        handle_response(status, text)
    }
}
