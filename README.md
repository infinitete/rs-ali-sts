# rs-ali-sts

[![Crates.io](https://img.shields.io/crates/v/rs-ali-sts.svg)](https://crates.io/crates/rs-ali-sts)
[![Documentation](https://docs.rs/rs-ali-sts/badge.svg)](https://docs.rs/rs-ali-sts)
[![License: MIT](https://img.shields.io/crates/l/rs-ali-sts.svg)](http://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/infinitete/rs-ali-sts/ci.yml?branch=master)](https://github.com/infinitete/rs-ali-sts/actions)

[中文文档](README_CN.md)

Alibaba Cloud STS (Security Token Service) SDK for Rust.

Provides both **async** and **sync (blocking)** clients covering all 4 STS API operations:

- `assume_role` — Assume a RAM role to obtain temporary security credentials
- `assume_role_with_saml` — SAML-based SSO role assumption
- `assume_role_with_oidc` — OIDC-based SSO role assumption
- `get_caller_identity` — Query the identity of the current caller

## Features

- **Async and Blocking** — Choose between async (`Client`) or sync (`blocking::Client`)
- **Builder Pattern** — Ergonomic request construction with `try_build()` for fallible builds
- **Credential Chain** — Automatic credential resolution from environment or profile files
- **Clock Skew Correction** — Automatic adjustment for local clock drift
- **Concurrent Request Limiting** — Built-in semaphore for async client
- **Security First** — Credentials redacted in debug output, HTTPS POST, rustls TLS

## Requirements

- Rust 1.93+ (edition 2024)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rs-ali-sts = "0.1.1"

# For async usage, add a tokio runtime:
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

To use the synchronous (blocking) client:

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["blocking"] }
```

For legacy SHA-1 signature support (not recommended):

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["legacy-signature"] }
```

## Quick Start

### Async (recommended)

```rust
use rs_ali_sts::{Client, Credential, AssumeRoleRequest};

#[tokio::main]
async fn main() -> rs_ali_sts::Result<()> {
    // Create client with credential
    let client = Client::new(Credential::new("your-access-key-id", "your-access-key-secret"))?;

    // Build request using builder pattern
    let request = AssumeRoleRequest::builder()
        .role_arn("acs:ram::123456:role/example-role")
        .role_session_name("my-session")
        .duration_seconds(3600)
        .build();  // or .try_build()? for fallible version

    let resp = client.assume_role(request).await?;

    println!("Temporary AccessKeyId: {}", resp.credentials.access_key_id);
    println!("Expiration: {}", resp.credentials.expiration);
    Ok(())
}
```

### Blocking (sync)

```rust
use rs_ali_sts::blocking::Client;
use rs_ali_sts::{Credential, AssumeRoleRequest};

fn main() -> rs_ali_sts::Result<()> {
    let client = Client::new(Credential::new("your-access-key-id", "your-access-key-secret"))?;

    let request = AssumeRoleRequest::builder()
        .role_arn("acs:ram::123456:role/example-role")
        .role_session_name("my-session")
        .build();

    let resp = client.assume_role(request)?;

    println!("Temporary AccessKeyId: {}", resp.credentials.access_key_id);
    Ok(())
}
```

## Credential Resolution

The SDK supports multiple ways to provide credentials. `Client::from_env()` tries them in order:

**1. Explicit credential**

```rust
let client = Client::new(Credential::new("LTAI5t...", "your-secret"))?;
```

**2. Environment variables**

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5t...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-secret
```

```rust
let client = Client::from_env()?;  // Reads from environment
```

**3. Profile file** (`~/.alibabacloud/credentials`)

```ini
[default]
access_key_id = LTAI5t...
access_key_secret = your-secret

[production]
access_key_id = LTAI5tprod...
access_key_secret = prod-secret
```

```rust
// Uses default chain: Environment -> Profile (default)
let client = Client::from_env()?;
```

## Builder Pattern

All request types support the builder pattern with two build methods:

```rust
// build() - panics if required fields are missing
let request = AssumeRoleRequest::builder()
    .role_arn("acs:ram::123456:role/example")
    .role_session_name("session")
    .build();

// try_build() - returns Result, useful for dynamic input
let request = AssumeRoleRequest::builder()
    .role_arn(user_input_arn)
    .role_session_name(session_name)
    .try_build()?;  // Returns Err if fields are missing
```

## API Reference

### AssumeRole

```rust
let request = AssumeRoleRequest::builder()
    .role_arn("acs:ram::123456:role/my-role")
    .role_session_name("session-name")
    .policy("{\"Version\":\"1\",\"Statement\":[...]}")  // Optional
    .duration_seconds(3600)                              // Optional: 900-43200
    .external_id("external-id")                          // Optional: cross-account
    .build();

let resp = client.assume_role(request).await?;
// resp.credentials.access_key_id
// resp.credentials.access_key_secret
// resp.credentials.security_token
// resp.credentials.expiration
```

### AssumeRoleWithSAML

```rust
let request = AssumeRoleWithSamlRequest::builder()
    .saml_provider_arn("acs:ram::123456:saml-provider/my-idp")
    .role_arn("acs:ram::123456:role/saml-role")
    .saml_assertion("base64-encoded-assertion")
    .build();

let resp = client.assume_role_with_saml(request).await?;
```

### AssumeRoleWithOIDC

```rust
let request = AssumeRoleWithOidcRequest::builder()
    .oidc_provider_arn("acs:ram::123456:oidc-provider/my-oidc")
    .role_arn("acs:ram::123456:role/oidc-role")
    .oidc_token("eyJhbGciOi...")
    .role_session_name("oidc-session")  // Optional
    .build();

let resp = client.assume_role_with_oidc(request).await?;
```

### GetCallerIdentity

```rust
let resp = client.get_caller_identity().await?;
println!("Account ID: {}", resp.account_id);
println!("Identity ARN: {}", resp.arn);
```

## Configuration

```rust
use std::time::Duration;
use rs_ali_sts::{Client, ClientConfig, Credential, SignatureVersion};

let config = ClientConfig::default()
    .with_endpoint("https://sts-vpc.cn-hangzhou.aliyuncs.com")  // VPC endpoint
    .with_timeout(Duration::from_secs(60))
    .with_connect_timeout(Duration::from_secs(10))
    .with_max_concurrent_requests(20)
    .with_signature_version(SignatureVersion::V2_0);

let client = Client::with_config(Credential::new("id", "secret")?, config)?;
```

## Error Handling

```rust
use rs_ali_sts::StsError;

match client.assume_role(request).await {
    Ok(resp) => println!("Success: {}", resp.credentials.access_key_id),
    Err(StsError::Api { request_id, code, message, .. }) => {
        eprintln!("API error [{}]: {} (RequestId: {})", code, message, request_id);
    }
    Err(StsError::Validation(msg)) => eprintln!("Validation error: {}", msg),
    Err(StsError::Credential(msg)) => eprintln!("Credential error: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

| Error Variant | Description |
|---------------|-------------|
| `HttpClient` | Network/connection error |
| `Http` | Non-JSON HTTP response |
| `Api` | Alibaba Cloud API error (with `request_id`, `code`) |
| `Validation` | Request validation error |
| `Credential` | Credential resolution failure |
| `Signature` | Signature computation error |
| `Config` | Configuration error |

## Security Features

| Feature | Description |
|---------|-------------|
| **Credential Redaction** | `access_key_secret` and `security_token` shown as `****` in debug output |
| **HTTPS POST** | Credentials never appear in URLs |
| **rustls TLS** | Pure Rust TLS, no OpenSSL dependency |
| **UUID v4 Nonce** | Prevents replay attacks |
| **HMAC-SHA256** | Secure signature algorithm (default) |
| **File Permission Check** | Warns on insecure credential file permissions (Unix) |

## License

Licensed under the [MIT License](http://opensource.org/licenses/MIT).
