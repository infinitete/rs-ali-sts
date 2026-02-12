# rs-ali-sts

[![Crates.io](https://img.shields.io/crates/v/rs-ali-sts.svg)](https://crates.io/crates/rs-ali-sts)
[![Documentation](https://docs.rs/rs-ali-sts/badge.svg)](https://docs.rs/rs-ali-sts)
[![License: MIT](https://img.shields.io/crates/l/rs-ali-sts.svg)](http://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/infinitete/rs-ali-sts/ci.yml?branch=master)](https://github.com/infinitete/rs-ali-sts/actions)

[English](README.md)

阿里云 STS (Security Token Service) Rust SDK。

提供 **异步 (async)** 和 **同步 (blocking)** 两种客户端，覆盖全部 4 个 STS API：

- `assume_role` — 扮演 RAM 角色，获取临时安全凭证
- `assume_role_with_saml` — 基于 SAML 断言的 SSO 角色扮演
- `assume_role_with_oidc` — 基于 OIDC Token 的 SSO 角色扮演
- `get_caller_identity` — 查询当前调用者身份

## 特性

- **异步与同步客户端** — 可选择 `Client` (异步) 或 `blocking::Client` (同步)
- **Builder 模式** — 优雅的请求构建，支持 `try_build()` 进行可失败构建
- **凭证链** — 自动从环境变量或配置文件解析凭证
- **时钟偏差校正** — 自动校正本地时钟漂移
- **并发请求限制** — 异步客户端内置信号量控制
- **安全优先** — 凭证在调试输出中自动脱敏

## 环境要求

- Rust 1.93+（edition 2024）

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
rs-ali-sts = "0.1.1"

# 异步模式需要 tokio 运行时：
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

如果需要同步（blocking）客户端：

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["blocking"] }
```

如需旧版 SHA-1 签名支持（不推荐）：

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["legacy-signature"] }
```

## 快速开始

### 异步模式（推荐）

```rust
use rs_ali_sts::{Client, Credential, AssumeRoleRequest};

#[tokio::main]
async fn main() -> rs_ali_sts::Result<()> {
    // 创建客户端（显式指定凭证）
    let client = Client::new(Credential::new("access-key-id", "access-key-secret"))?;

    // 或使用凭证链（环境变量 -> 配置文件）
    // let client = Client::from_env()?;

    // 使用 Builder 模式构建请求
    let request = AssumeRoleRequest::builder()
        .role_arn("acs:ram::123456:role/example-role")
        .role_session_name("my-session")
        .duration_seconds(3600)
        .build();  // 或使用 .try_build()? 进行可失败构建

    let resp = client.assume_role(request).await?;

    println!("临时 AccessKeyId: {}", resp.credentials.access_key_id);
    println!("过期时间: {}", resp.credentials.expiration);
    Ok(())
}
```

### 同步模式

```rust
use rs_ali_sts::blocking::Client;
use rs_ali_sts::{Credential, AssumeRoleRequest};

fn main() -> rs_ali_sts::Result<()> {
    let client = Client::new(Credential::new("access-key-id", "access-key-secret"))?;

    let request = AssumeRoleRequest::builder()
        .role_arn("acs:ram::123456:role/example-role")
        .role_session_name("my-session")
        .build();

    let resp = client.assume_role(request)?;

    println!("临时 AccessKeyId: {}", resp.credentials.access_key_id);
    Ok(())
}
```

## 凭证配置

SDK 支持多种凭证提供方式。`Client::from_env()` 会按顺序尝试：

**1. 显式指定**

```rust
let client = Client::new(Credential::new("LTAI5t...", "your-secret"))?;
```

**2. 环境变量**

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5t...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-secret
```

```rust
let client = Client::from_env()?;  // 从环境变量读取
```

**3. 配置文件** (`~/.alibabacloud/credentials`)

```ini
[default]
access_key_id = LTAI5t...
access_key_secret = your-secret

[production]
access_key_id = LTAI5tprod...
access_key_secret = prod-secret
```

```rust
// 使用默认凭证链：环境变量 -> 配置文件 (default)
let client = Client::from_env()?;
```

## Builder 模式

所有请求类型都支持 Builder 模式，提供两种构建方法：

```rust
// build() - 缺少必填字段时会 panic
let request = AssumeRoleRequest::builder()
    .role_arn("acs:ram::123456:role/example")
    .role_session_name("session")
    .build();

// try_build() - 返回 Result，适用于动态输入
let request = AssumeRoleRequest::builder()
    .role_arn(user_input_arn)
    .role_session_name(session_name)
    .try_build()?;  // 字段缺失时返回 Err
```

## API 说明

### AssumeRole — 角色扮演

```rust
let request = AssumeRoleRequest::builder()
    .role_arn("acs:ram::123456:role/my-role")
    .role_session_name("session-name")
    .policy("{\"Version\":\"1\",\"Statement\":[...]}")  // 可选
    .duration_seconds(3600)                              // 可选: 900-43200
    .external_id("external-id")                          // 可选: 跨账号
    .build();

let resp = client.assume_role(request).await?;
// resp.credentials.access_key_id
// resp.credentials.access_key_secret
// resp.credentials.security_token
// resp.credentials.expiration
```

### AssumeRoleWithSAML — SAML SSO

```rust
let request = AssumeRoleWithSamlRequest::builder()
    .saml_provider_arn("acs:ram::123456:saml-provider/my-idp")
    .role_arn("acs:ram::123456:role/saml-role")
    .saml_assertion("base64-encoded-assertion")
    .build();

let resp = client.assume_role_with_saml(request).await?;
```

### AssumeRoleWithOIDC — OIDC SSO

```rust
let request = AssumeRoleWithOidcRequest::builder()
    .oidc_provider_arn("acs:ram::123456:oidc-provider/my-oidc")
    .role_arn("acs:ram::123456:role/oidc-role")
    .oidc_token("eyJhbGciOi...")
    .role_session_name("oidc-session")  // 可选
    .build();

let resp = client.assume_role_with_oidc(request).await?;
```

### GetCallerIdentity — 查询身份

```rust
let resp = client.get_caller_identity().await?;
println!("账号 ID: {}", resp.account_id);
println!("身份 ARN: {}", resp.arn);
```

## 配置选项

```rust
use std::time::Duration;
use rs_ali_sts::{Client, ClientConfig, Credential, SignatureVersion};

let config = ClientConfig::default()
    .with_endpoint("https://sts-vpc.cn-hangzhou.aliyuncs.com")  // VPC 端点
    .with_timeout(Duration::from_secs(60))
    .with_connect_timeout(Duration::from_secs(10))
    .with_max_concurrent_requests(20)
    .with_signature_version(SignatureVersion::V2_0);

let client = Client::with_config(Credential::new("id", "secret")?, config)?;
```

## 错误处理

```rust
use rs_ali_sts::StsError;

match client.assume_role(request).await {
    Ok(resp) => println!("成功: {}", resp.credentials.access_key_id),
    Err(StsError::Api { request_id, code, message, .. }) => {
        eprintln!("API 错误 [{}]: {} (RequestId: {})", code, message, request_id);
    }
    Err(StsError::Validation(msg)) => eprintln!("验证错误: {}", msg),
    Err(StsError::Credential(msg)) => eprintln!("凭证错误: {}", msg),
    Err(e) => eprintln!("错误: {}", e),
}
```

| 错误类型 | 说明 |
|----------|------|
| `HttpClient` | 网络/连接错误 |
| `Http` | 非 JSON 的 HTTP 响应 |
| `Api` | 阿里云 API 错误（含 `request_id`、`code`） |
| `Validation` | 请求验证错误 |
| `Credential` | 凭证解析失败 |
| `Signature` | 签名计算错误 |
| `Config` | 配置错误 |

## 安全特性

| 特性 | 说明 |
|------|------|
| **凭证脱敏** | `access_key_secret` 和 `security_token` 在调试输出中显示为 `****` |
| **HTTPS POST** | 凭证不会出现在 URL 中 |
| **rustls TLS** | 纯 Rust TLS 实现，无 OpenSSL 依赖 |
| **UUID v4 Nonce** | 防止重放攻击 |
| **HMAC-SHA256** | 安全的签名算法（默认） |
| **文件权限检查** | 凭证文件权限不安全时发出警告（Unix） |

## 许可证

本项目采用 [MIT 许可证](http://opensource.org/licenses/MIT)。
