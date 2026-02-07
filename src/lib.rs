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
//! # Quick Start (async)
//!
//! ```no_run
//! use rs_ali_sts::{Client, Credential, AssumeRoleRequest};
//!
//! # async fn example() -> rs_ali_sts::Result<()> {
//! let client = Client::new(Credential {
//!     access_key_id: "your-access-key-id".into(),
//!     access_key_secret: "your-access-key-secret".into(),
//! });
//!
//! let resp = client.assume_role(AssumeRoleRequest {
//!     role_arn: "acs:ram::123456:role/example".into(),
//!     role_session_name: "session".into(),
//!     policy: None,
//!     duration_seconds: Some(3600),
//!     external_id: None,
//! }).await?;
//!
//! println!("Temporary AK: {}", resp.credentials.access_key_id);
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod credential;
pub mod error;
pub mod response;

#[cfg(feature = "blocking")]
pub mod blocking;

mod request;
mod sign;

pub use client::{AssumeRoleRequest, AssumeRoleWithOidcRequest, AssumeRoleWithSamlRequest, Client};
pub use config::ClientConfig;
pub use credential::Credential;
pub use error::{Result, StsError};
pub use response::{
    AssumeRoleResponse, AssumeRoleWithOidcResponse, AssumeRoleWithSamlResponse, AssumedRoleUser,
    Credentials, GetCallerIdentityResponse, OidcTokenInfo, SamlAssertionInfo,
};

// Compile-time assertions: key types must be Send + Sync for use across threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<Client>;
    let _ = assert_send_sync::<StsError>;
    let _ = assert_send_sync::<Credential>;
};
