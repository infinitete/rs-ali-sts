# rs-ali-sts Architecture Design

## 1. System Overview

```
                         ┌─────────────────────────────────┐
                         │          User Code              │
                         └──────────┬──────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │         rs_ali_sts::Client        │
                    │  (async, default)              │
                    │  rs_ali_sts::blocking::Client     │
                    │  (sync, feature = "blocking")  │
                    └───────────────┬───────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │            CredentialProvider              │
              │  Chain: Explicit → Env → Profile File     │
              └─────────────────────┬─────────────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │           Request Builder                  │
              │  Common Params + Action Params + Sign      │
              └─────────────────────┬─────────────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │           Signature (V1)                   │
              │  HMAC-SHA1 → Base64                        │
              └─────────────────────┬─────────────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │         HTTPS POST → sts.aliyuncs.com     │
              └─────────────────────┬─────────────────────┘
                                    │
              ┌─────────────────────▼─────────────────────┐
              │         Response Deserialize (JSON)        │
              │  → Ok(T) / Err(StsError::ApiError)        │
              └───────────────────────────────────────────┘
```

## 2. Module Structure

```
src/
├── lib.rs              # Crate root, public re-exports
├── error.rs            # StsError enum (thiserror)
├── credential.rs       # Credential types + provider chain
├── config.rs           # ClientConfig (endpoint, timeout, etc.)
├── sign.rs             # Alibaba Cloud V1 signature algorithm
├── request.rs          # Request builder (common params + action params)
├── response.rs         # Response types (Credentials, AssumedRoleUser, etc.)
├── client.rs           # Async Client implementation
└── blocking.rs         # Sync Client (feature-gated)
```

## 3. Module Detailed Design

---

### 3.1 `error.rs` — Error Types

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StsError {
    /// HTTP/network layer error
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// Alibaba Cloud API returned a business error
    #[error("API error (RequestId: {request_id}): [{code}] {message}")]
    Api {
        request_id: String,
        code: String,
        message: String,
        recommend: Option<String>,
    },

    /// Signature computation error
    #[error("Signature error: {0}")]
    Signature(String),

    /// Credential not found or invalid
    #[error("Credential error: {0}")]
    Credential(String),

    /// Response deserialization error
    #[error("Deserialization error: {0}")]
    Deserialize(#[from] serde_json::Error),

    /// Config file parse error
    #[error("Config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, StsError>;
```

---

### 3.2 `credential.rs` — Credential & Provider Chain

```rust
/// AccessKey credential (Debug impl redacts secrets)
pub struct Credential {
    pub access_key_id: String,
    pub access_key_secret: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"****")
            .finish()
    }
}

/// Credential provider trait
pub trait CredentialProvider {
    fn resolve(&self) -> Result<Credential>;
}

/// Static credential (explicit)
pub struct StaticProvider { ... }

/// Environment variable provider
/// Reads ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET
pub struct EnvProvider;

/// Profile file provider
/// Reads ~/.alibabacloud/credentials (INI format)
pub struct ProfileProvider { ... }

/// Chain provider — tries providers in order
pub struct ChainProvider {
    providers: Vec<Box<dyn CredentialProvider>>,
}

impl ChainProvider {
    /// Default chain: Static → Env → Profile
    pub fn default_chain(explicit: Option<Credential>) -> Self { ... }
}
```

**Design decisions:**
- `CredentialProvider` is a synchronous trait — credential resolution is local I/O only (env vars, file reads), no async needed
- `Credential` redacts `access_key_secret` in `Debug` output for security
- `ChainProvider` iterates providers, returns the first success, or aggregates errors

---

### 3.3 `config.rs` — Client Configuration

```rust
pub struct ClientConfig {
    /// STS endpoint, default: "https://sts.aliyuncs.com"
    pub endpoint: String,

    /// HTTP request timeout
    pub timeout: std::time::Duration,

    /// Response format, always "JSON" (we don't support XML parsing)
    pub(crate) format: &'static str,

    /// API version, always "2015-04-01"
    pub(crate) api_version: &'static str,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://sts.aliyuncs.com".to_string(),
            timeout: std::time::Duration::from_secs(30),
            format: "JSON",
            api_version: "2015-04-01",
        }
    }
}
```

---

### 3.4 `sign.rs` — Alibaba Cloud V1 Signature

```
Signature Algorithm Steps:
━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: Collect all params (common + action-specific)
        ↓
Step 2: URL-encode each key and value (RFC 3986)
        Space → %20 (NOT +)
        ↓
Step 3: Sort by encoded key (lexicographic ascending)
        ↓
Step 4: Join as "key1=val1&key2=val2&..." → CanonicalizedQueryString
        ↓
Step 5: Build StringToSign:
        POST&%2F&{percentEncode(CanonicalizedQueryString)}
        ↓
Step 6: HMAC-SHA1(key = AccessKeySecret + "&", data = StringToSign)
        ↓
Step 7: Base64 encode → Signature value
```

```rust
/// Percent-encode a string per Alibaba Cloud rules (RFC 3986 variant)
pub(crate) fn percent_encode(s: &str) -> String { ... }

/// Compute the V1 signature for a set of parameters
pub(crate) fn sign_request(
    params: &BTreeMap<String, String>,
    access_key_secret: &str,
    http_method: &str,  // "POST"
) -> Result<String> { ... }
```

**Key rule:** Use `BTreeMap` for parameters to get automatic lexicographic sorting.

---

### 3.5 `request.rs` — Request Builder

```rust
use std::collections::BTreeMap;

/// Common parameters injected into every request
pub(crate) struct CommonParams {
    pub format: String,          // "JSON"
    pub version: String,         // "2015-04-01"
    pub access_key_id: String,
    pub signature_method: String, // "HMAC-SHA1"
    pub signature_version: String, // "1.0"
    pub signature_nonce: String,  // UUID
    pub timestamp: String,        // ISO 8601 UTC, e.g. "2024-01-01T00:00:00Z"
}

/// Build a complete signed request body
pub(crate) fn build_signed_request(
    action: &str,
    action_params: &[(&str, &str)],
    credential: &Credential,
    config: &ClientConfig,
) -> Result<String> {
    // 1. Merge common params + action params into BTreeMap
    // 2. Sign with sign_request()
    // 3. Add Signature to params
    // 4. URL-encode as POST body
    ...
}
```

---

### 3.6 `response.rs` — API Response Types

```rust
use serde::Deserialize;

/// Temporary security credentials
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub security_token: String,
    pub expiration: String,
}

/// AssumeRole response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleResponse {
    pub request_id: String,
    pub assumed_role_user: AssumedRoleUser,
    pub credentials: Credentials,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumedRoleUser {
    pub arn: String,
    pub assumed_role_id: String,
}

/// AssumeRoleWithSAML response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleWithSamlResponse {
    pub request_id: String,
    pub credentials: Credentials,
    #[serde(rename = "SAMLAssertionInfo")]
    pub saml_assertion_info: SamlAssertionInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SamlAssertionInfo {
    pub subject_type: String,
    pub subject: String,
    pub recipient: String,
    pub issuer: String,
}

/// AssumeRoleWithOIDC response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AssumeRoleWithOidcResponse {
    pub request_id: String,
    pub credentials: Credentials,
    #[serde(rename = "OIDCTokenInfo")]
    pub oidc_token_info: OidcTokenInfo,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct OidcTokenInfo {
    pub subject: String,
    pub issuer: String,
    pub client_ids: String,
}

/// GetCallerIdentity response
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

/// Alibaba Cloud API error response
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ApiErrorResponse {
    pub request_id: String,
    pub code: String,
    pub message: String,
    pub recommend: Option<String>,
}
```

---

### 3.7 `client.rs` — Async Client

```rust
pub struct Client {
    http: reqwest::Client,
    config: ClientConfig,
    credential: Credential,
}

impl Client {
    /// Create with explicit credential
    pub fn new(credential: Credential) -> Self { ... }

    /// Create with custom config
    pub fn with_config(credential: Credential, config: ClientConfig) -> Self { ... }

    /// Create using default credential chain (env → profile)
    pub fn from_env() -> Result<Self> { ... }

    /// AssumeRole — obtain temporary credentials by assuming a RAM role
    pub async fn assume_role(
        &self,
        request: AssumeRoleRequest,
    ) -> Result<AssumeRoleResponse> { ... }

    /// AssumeRoleWithSAML — SAML-based SSO role assumption
    pub async fn assume_role_with_saml(
        &self,
        request: AssumeRoleWithSamlRequest,
    ) -> Result<AssumeRoleWithSamlResponse> { ... }

    /// AssumeRoleWithOIDC — OIDC-based SSO role assumption
    pub async fn assume_role_with_oidc(
        &self,
        request: AssumeRoleWithOidcRequest,
    ) -> Result<AssumeRoleWithOidcResponse> { ... }

    /// GetCallerIdentity — query current caller identity
    pub async fn get_caller_identity(
        &self,
    ) -> Result<GetCallerIdentityResponse> { ... }

    /// Internal: execute a signed POST request and deserialize
    async fn execute<T: DeserializeOwned>(
        &self,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<T> { ... }
}
```

**Request structs** (builder pattern):

```rust
pub struct AssumeRoleRequest {
    pub role_arn: String,
    pub role_session_name: String,
    pub policy: Option<String>,
    pub duration_seconds: Option<u64>,
    pub external_id: Option<String>,
}

pub struct AssumeRoleWithSamlRequest {
    pub saml_provider_arn: String,
    pub role_arn: String,
    pub saml_assertion: String,
    pub policy: Option<String>,
    pub duration_seconds: Option<u64>,
}

pub struct AssumeRoleWithOidcRequest {
    pub oidc_provider_arn: String,
    pub role_arn: String,
    pub oidc_token: String,
    pub policy: Option<String>,
    pub duration_seconds: Option<u64>,
    pub role_session_name: Option<String>,
}
```

---

### 3.8 `blocking.rs` — Sync Client (feature-gated)

```rust
/// Only compiled when feature "blocking" is enabled
///
/// Mirrors the async Client API exactly using reqwest::blocking
pub struct Client {
    http: reqwest::blocking::Client,
    config: ClientConfig,
    credential: Credential,
}

impl Client {
    pub fn new(credential: Credential) -> Self { ... }
    pub fn with_config(credential: Credential, config: ClientConfig) -> Self { ... }
    pub fn from_env() -> Result<Self> { ... }

    pub fn assume_role(&self, request: AssumeRoleRequest) -> Result<AssumeRoleResponse> { ... }
    pub fn assume_role_with_saml(&self, request: AssumeRoleWithSamlRequest) -> Result<AssumeRoleWithSamlResponse> { ... }
    pub fn assume_role_with_oidc(&self, request: AssumeRoleWithOidcRequest) -> Result<AssumeRoleWithOidcResponse> { ... }
    pub fn get_caller_identity(&self) -> Result<GetCallerIdentityResponse> { ... }

    fn execute<T: DeserializeOwned>(&self, action: &str, params: &[(&str, &str)]) -> Result<T> { ... }
}
```

---

### 3.9 `lib.rs` — Public API Surface

```rust
pub mod error;
pub mod credential;
pub mod config;
pub mod client;
pub mod response;

// Feature-gated sync module
#[cfg(feature = "blocking")]
pub mod blocking;

// Internal modules
mod sign;
mod request;

// Convenient re-exports
pub use client::Client;
pub use config::ClientConfig;
pub use credential::Credential;
pub use error::{StsError, Result};
pub use response::*;
pub use client::{AssumeRoleRequest, AssumeRoleWithSamlRequest, AssumeRoleWithOidcRequest};
```

---

## 4. Dependency Design

```toml
[package]
name = "rs-ali-sts"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
hmac = "0.12"
sha1 = "0.10"
base64 = "0.22"
chrono = "0.4"
uuid = { version = "1", features = ["v4"] }

[features]
default = []
blocking = ["reqwest/blocking"]

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
mockito = "1"
```

**Rationale:**
- `reqwest` with `rustls-tls` — pure Rust TLS, no OpenSSL dependency
- `uuid` for `SignatureNonce` — guarantees uniqueness per request
- `chrono` for ISO 8601 timestamp generation
- `mockito` for HTTP mocking in tests — no real API calls needed
- `tokio` only in dev-dependencies — the lib doesn't force a runtime on users

---

## 5. Request/Response Flow

```
User calls client.assume_role(request)
    │
    ▼
┌─ execute<AssumeRoleResponse>("AssumeRole", params) ─┐
│                                                       │
│  1. credential_provider.resolve()                     │
│     → Credential { access_key_id, access_key_secret } │
│                                                       │
│  2. build_signed_request("AssumeRole", params, cred)  │
│     ├─ inject common params:                          │
│     │   Format=JSON, Version=2015-04-01,              │
│     │   AccessKeyId=xxx, SignatureMethod=HMAC-SHA1,    │
│     │   SignatureVersion=1.0, SignatureNonce=uuid,     │
│     │   Timestamp=2024-01-01T00:00:00Z                │
│     │   Action=AssumeRole                             │
│     ├─ merge action params:                           │
│     │   RoleArn=xxx, RoleSessionName=xxx, ...         │
│     ├─ sign_request(all_params, secret, "POST")       │
│     │   ├─ sorted_query = "AccessKeyId=...&Action=...&..."
│     │   ├─ string_to_sign = "POST&%2F&" + encode(sorted_query)
│     │   ├─ hmac_sha1(secret + "&", string_to_sign)    │
│     │   └─ base64(hmac_result) → Signature            │
│     └─ return URL-encoded POST body with Signature    │
│                                                       │
│  3. POST https://sts.aliyuncs.com                     │
│     Content-Type: application/x-www-form-urlencoded   │
│     Body: AccessKeyId=...&Action=...&Signature=...    │
│                                                       │
│  4. Check HTTP status                                 │
│     ├─ 2xx → deserialize JSON as AssumeRoleResponse   │
│     └─ 4xx/5xx → deserialize as ApiErrorResponse      │
│         → return Err(StsError::Api { ... })           │
└───────────────────────────────────────────────────────┘
```

---

## 6. Test Strategy

### 6.1 Unit Tests

| Module | Test Cases |
|--------|-----------|
| `sign.rs` | `percent_encode` correctness (spaces→%20, special chars); `sign_request` with known input/output pairs from Alibaba Cloud docs |
| `credential.rs` | `StaticProvider` returns credential; `EnvProvider` reads/fails env vars; `ProfileProvider` parses INI; `ChainProvider` fallback order |
| `request.rs` | `build_signed_request` produces correct param set; timestamp format; nonce uniqueness |
| `response.rs` | Deserialize sample JSON for all 4 response types; error response parsing |
| `error.rs` | Error Display output; From conversions |

### 6.2 Integration Tests (with HTTP mocking)

| Test | Description |
|------|-------------|
| `assume_role_success` | Mock 200 + JSON → returns AssumeRoleResponse |
| `assume_role_api_error` | Mock 403 + error JSON → returns StsError::Api |
| `assume_role_network_error` | Mock connection refused → returns StsError::Http |
| `get_caller_identity_success` | Mock 200 → returns GetCallerIdentityResponse |
| `assume_role_with_saml_success` | Mock 200 → returns AssumeRoleWithSamlResponse |
| `assume_role_with_oidc_success` | Mock 200 → returns AssumeRoleWithOidcResponse |
| `blocking_client_works` | Same tests for blocking::Client (feature-gated) |

### 6.3 Test Organization

```
src/
├── sign.rs           # #[cfg(test)] mod tests { ... }
├── credential.rs     # #[cfg(test)] mod tests { ... }
├── request.rs        # #[cfg(test)] mod tests { ... }
├── response.rs       # #[cfg(test)] mod tests { ... }
tests/
├── integration.rs    # Integration tests with mockito
└── blocking.rs       # #[cfg(feature = "blocking")] integration tests
```

---

## 7. Public API Usage Examples

### Async (default)

```rust
use rs_ali_sts::{Client, Credential, AssumeRoleRequest};

#[tokio::main]
async fn main() -> rs_ali_sts::Result<()> {
    let client = Client::new(Credential {
        access_key_id: "your-id".into(),
        access_key_secret: "your-secret".into(),
    });

    let resp = client.assume_role(AssumeRoleRequest {
        role_arn: "acs:ram::123456:role/test-role".into(),
        role_session_name: "my-session".into(),
        policy: None,
        duration_seconds: Some(3600),
        external_id: None,
    }).await?;

    println!("Temp AK: {}", resp.credentials.access_key_id);
    println!("Expires: {}", resp.credentials.expiration);
    Ok(())
}
```

### Sync (blocking feature)

```rust
use rs_ali_sts::blocking::Client;
use rs_ali_sts::{Credential, AssumeRoleRequest};

fn main() -> rs_ali_sts::Result<()> {
    let client = Client::from_env()?; // reads from env vars

    let identity = client.get_caller_identity()?;
    println!("Account: {}", identity.account_id);
    Ok(())
}
```

---

## 8. Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Response format | JSON (not XML) | Simpler parsing, serde_json is lighter than XML parsers |
| HTTP method | POST only | More secure for credentials, avoids URL length limits |
| TLS backend | rustls | Pure Rust, no system OpenSSL dependency, easier cross-compilation |
| Param sorting | BTreeMap | Natural lexicographic order, fits signature algorithm |
| Nonce | UUID v4 | Guaranteed uniqueness, no collision risk |
| Credential Debug | Redacted | Security: secrets never leak to logs |
| Module visibility | `sign`/`request` are `pub(crate)` | Implementation details, not part of public API |
| Feature flag name | `blocking` | Consistent with reqwest convention |
