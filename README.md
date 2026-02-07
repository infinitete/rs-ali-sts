# rs-ali-sts

[![Crates.io](https://img.shields.io/crates/v/rs-ali-sts.svg)](https://crates.io/crates/rs-ali-sts)
[![Documentation](https://docs.rs/rs-ali-sts/badge.svg)](https://docs.rs/rs-ali-sts)
[![License: MIT](https://img.shields.io/crates/l/rs-ali-sts.svg)](http://opensource.org/licenses/MIT)

[中文文档](README_CN.md)

Alibaba Cloud STS (Security Token Service) SDK for Rust.

Provides both **async** and **sync (blocking)** clients covering all 4 STS API operations:

- `assume_role` — Assume a RAM role to obtain temporary security credentials
- `assume_role_with_saml` — SAML-based SSO role assumption
- `assume_role_with_oidc` — OIDC-based SSO role assumption
- `get_caller_identity` — Query the identity of the current caller

## Requirements

- Rust 1.85+ (edition 2024)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rs-ali-sts = "0.1"

# For async usage, add a tokio runtime:
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

To use the synchronous (blocking) client:

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["blocking"] }
```

## Quick Start

### Async (default)

```rust
use rs_ali_sts::{Client, Credential, AssumeRoleRequest};

#[tokio::main]
async fn main() -> rs_ali_sts::Result<()> {
    let client = Client::new(Credential {
        access_key_id: "your-access-key-id".into(),
        access_key_secret: "your-access-key-secret".into(),
    });

    let resp = client.assume_role(AssumeRoleRequest {
        role_arn: "acs:ram::123456:role/example-role".into(),
        role_session_name: "my-session".into(),
        policy: None,
        duration_seconds: Some(3600),
        external_id: None,
    }).await?;

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
    let client = Client::new(Credential {
        access_key_id: "your-access-key-id".into(),
        access_key_secret: "your-access-key-secret".into(),
    });

    let resp = client.assume_role(AssumeRoleRequest {
        role_arn: "acs:ram::123456:role/example-role".into(),
        role_session_name: "my-session".into(),
        policy: None,
        duration_seconds: Some(3600),
        external_id: None,
    })?;

    println!("Temporary AccessKeyId: {}", resp.credentials.access_key_id);
    Ok(())
}
```

## Credential Resolution

The SDK supports three ways to provide credentials, and a chain provider that tries them in order.

### 1. Explicit credential

```rust
let client = Client::new(Credential {
    access_key_id: "LTAI5t...".into(),
    access_key_secret: "your-secret".into(),
});
```

### 2. Environment variables

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5t...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-secret
```

```rust
let client = Client::from_env()?;
```

### 3. Profile file

Create `~/.alibabacloud/credentials`:

```ini
[default]
access_key_id = LTAI5t...
access_key_secret = your-secret
```

`Client::from_env()` automatically tries the default credential chain: **Environment variables -> Profile file**.

## API Reference

### AssumeRole

Obtain temporary credentials by assuming a RAM role.

```rust
let resp = client.assume_role(AssumeRoleRequest {
    role_arn: "acs:ram::123456:role/my-role".into(),
    role_session_name: "session-name".into(),
    policy: None,                  // Optional: inline policy JSON
    duration_seconds: Some(3600),  // Optional: 900 ~ 43200 seconds
    external_id: None,             // Optional: for cross-account access
}).await?;

// resp.credentials.access_key_id
// resp.credentials.access_key_secret
// resp.credentials.security_token
// resp.credentials.expiration
// resp.assumed_role_user.arn
// resp.assumed_role_user.assumed_role_id
```

### AssumeRoleWithSAML

Assume a role using a SAML assertion for enterprise SSO.

```rust
let resp = client.assume_role_with_saml(AssumeRoleWithSamlRequest {
    saml_provider_arn: "acs:ram::123456:saml-provider/my-idp".into(),
    role_arn: "acs:ram::123456:role/saml-role".into(),
    saml_assertion: "base64-encoded-saml-assertion".into(),
    policy: None,
    duration_seconds: None,
}).await?;
```

### AssumeRoleWithOIDC

Assume a role using an OIDC token for SSO.

```rust
let resp = client.assume_role_with_oidc(AssumeRoleWithOidcRequest {
    oidc_provider_arn: "acs:ram::123456:oidc-provider/my-oidc".into(),
    role_arn: "acs:ram::123456:role/oidc-role".into(),
    oidc_token: "eyJhbGciOi...".into(),
    policy: None,
    duration_seconds: None,
    role_session_name: Some("oidc-session".into()),
}).await?;
```

### GetCallerIdentity

Query the identity of the current caller (no additional parameters needed).

```rust
let resp = client.get_caller_identity().await?;

println!("Account ID: {}", resp.account_id);
println!("Identity ARN: {}", resp.arn);
println!("Identity Type: {}", resp.identity_type);
```

## Custom Configuration

```rust
use std::time::Duration;
use rs_ali_sts::{Client, ClientConfig, Credential};

let config = ClientConfig::default()
    .with_endpoint("https://sts-vpc.cn-hangzhou.aliyuncs.com")
    .with_timeout(Duration::from_secs(60));

let client = Client::with_config(
    Credential {
        access_key_id: "your-id".into(),
        access_key_secret: "your-secret".into(),
    },
    config,
);
```

## Error Handling

All operations return `rs_ali_sts::Result<T>`, which wraps `StsError`:

```rust
use rs_ali_sts::StsError;

match client.assume_role(request).await {
    Ok(resp) => println!("Success: {}", resp.credentials.access_key_id),
    Err(StsError::Api { request_id, code, message, .. }) => {
        eprintln!("API error [{}]: {} (RequestId: {})", code, message, request_id);
    }
    Err(StsError::HttpClient(e)) => eprintln!("Network error: {}", e),
    Err(StsError::Credential(msg)) => eprintln!("Credential error: {}", msg),
    Err(e) => eprintln!("Other error: {}", e),
}
```

| Variant | Description |
|---------|-------------|
| `HttpClient` | Network / connection error (from reqwest) |
| `Http` | Unexpected HTTP response with non-JSON body |
| `Api` | Alibaba Cloud API business error (includes `request_id`, `code`, `message`) |
| `Credential` | Credential resolution failure |
| `Deserialize` | JSON deserialization error |
| `Signature` | Signature computation error |
| `Config` | Configuration / profile file parse error |

## Security

- Credentials are **redacted** in `Debug` output — `access_key_secret` and `security_token` are printed as `****`
- Uses **HTTPS POST** to send requests — credentials never appear in URLs
- Uses **rustls** for TLS — pure Rust, no OpenSSL dependency
- Each request uses a **UUID v4 nonce** to prevent replay attacks

## License

Licensed under the [MIT License](http://opensource.org/licenses/MIT).
