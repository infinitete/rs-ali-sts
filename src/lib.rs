//! Alibaba Cloud STS (Security Token Service) SDK for Rust.
//!
//! This crate provides both async and sync (blocking) clients for the
//! Alibaba Cloud STS API, supporting all 4 API operations:
//!
//! - [`Client::assume_role`] — Assume a RAM role to get temporary credentials
//! - [`Client::assume_role_with_saml`] — SAML-based SSO role assumption
//! - [`Client::assume_role_with_oidc`] — OIDC-based SSO role assumption
//! - [`Client::get_caller_identity`] — Query current caller identity
//!
//! # Features
//!
//! - **Async and Blocking clients** — Use `Client` for async or `blocking::Client` for sync
//! - **Builder pattern** — Ergonomic request construction with `try_build()` for fallible builds
//! - **Credential chain** — Automatic resolution from environment variables or profile files
//! - **Clock skew correction** — Automatic adjustment for local clock drift
//! - **Concurrent request limiting** — Built-in semaphore for async client
//! - **Security first** — Credentials redacted in debug output
//!
//! # Quick Start
//!
//! ```no_run
//! use rs_ali_sts::{Client, Credential, AssumeRoleRequest};
//!
//! # async fn example() -> rs_ali_sts::Result<()> {
//! // Create client with explicit credential
//! let client = Client::new(Credential::new("access-key-id", "access-key-secret"))?;
//!
//! // Or use the credential chain (env vars -> profile file)
//! // let client = Client::from_env()?;
//!
//! // Build request using builder pattern
//! let request = AssumeRoleRequest::builder()
//!     .role_arn("acs:ram::123456:role/example")
//!     .role_session_name("my-session")
//!     .duration_seconds(3600)
//!     .build();
//!
//! // Execute request
//! let resp = client.assume_role(request).await?;
//!
//! println!("Temporary AK: {}", resp.credentials.access_key_id);
//! println!("Expires: {}", resp.credentials.expiration);
//! # Ok(())
//! # }
//! ```
//!
//! # Blocking Client
//!
//! Enable the `blocking` feature for synchronous usage:
//!
//! ```toml
//! [dependencies]
//! rs-ali-sts = { version = "0.1", features = ["blocking"] }
//! ```
//!
//! ```ignore
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
//!
//! # Error Handling
//!
//! All operations return [`Result<T>`] which wraps [`StsError`]:
//!
//! ```no_run
//! # use rs_ali_sts::{Client, Credential, AssumeRoleRequest, StsError};
//! # async fn example(client: Client) {
//! let request = AssumeRoleRequest::builder()
//!     .role_arn("acs:ram::123456:role/example")
//!     .role_session_name("session")
//!     .build();
//!
//! match client.assume_role(request).await {
//!     Ok(resp) => println!("Success: {}", resp.credentials.access_key_id),
//!     Err(StsError::Api { request_id, code, message, .. }) => {
//!         eprintln!("API error [{}]: {} (RequestId: {})", code, message, request_id);
//!     }
//!     Err(StsError::Validation(msg)) => eprintln!("Invalid request: {}", msg),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # }
//! ```
//!
//! # Security
//!
//! - **Credential redaction**: `access_key_secret` and `security_token` are shown as `****` in debug output
//! - **HTTPS POST**: Credentials never appear in URLs
//! - **HMAC-SHA1**: Signature algorithm compatible with Alibaba Cloud STS
//! - **UUID v4 nonce**: Prevents replay attacks
//!
//! # Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `blocking` | Enables synchronous (`blocking::Client`) |
//!
pub mod client;
pub mod config;
pub mod credential;
pub mod error;
pub mod response;

#[cfg(feature = "blocking")]
pub mod blocking;

mod exec;
mod request;
mod sign;

pub use client::{
    AssumeRoleRequest, AssumeRoleRequestBuilder, AssumeRoleWithOidcRequest,
    AssumeRoleWithOidcRequestBuilder, AssumeRoleWithSamlRequest, AssumeRoleWithSamlRequestBuilder,
    Client,
};
pub use config::ClientConfig;
pub use credential::Credential;
pub use error::{Result, StsError};
pub use response::{
    AssumeRoleResponse, AssumeRoleWithOidcResponse, AssumeRoleWithSamlResponse, AssumedRoleUser,
    Credentials, GetCallerIdentityResponse, OidcTokenInfo, SamlAssertionInfo,
};
pub use sign::SignatureVersion;

// Compile-time assertions: key types must be Send + Sync for use across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<Client>;
    let _ = assert_send_sync::<StsError>;
    let _ = assert_send_sync::<Credential>;
};
