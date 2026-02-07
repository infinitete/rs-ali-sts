# rs-ali-sts

[English](README.md)

阿里云 STS (Security Token Service) Rust SDK。

提供 **异步 (async)** 和 **同步 (blocking)** 两种客户端，覆盖全部 4 个 STS API：

- `assume_role` — 扮演 RAM 角色，获取临时安全凭证
- `assume_role_with_saml` — 基于 SAML 断言的 SSO 角色扮演
- `assume_role_with_oidc` — 基于 OIDC Token 的 SSO 角色扮演
- `get_caller_identity` — 查询当前调用者身份

## 环境要求

- Rust 1.85+（edition 2024）

## 安装

在 `Cargo.toml` 中添加：

```toml
[dependencies]
rs-ali-sts = "0.1"

# 异步模式需要 tokio 运行时：
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

如果需要同步（blocking）客户端：

```toml
[dependencies]
rs-ali-sts = { version = "0.1", features = ["blocking"] }
```

## 快速开始

### 异步模式（默认）

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

    println!("临时 AccessKeyId: {}", resp.credentials.access_key_id);
    Ok(())
}
```

## 凭证配置

SDK 支持三种凭证提供方式，以及按顺序尝试的链式提供器。

### 1. 显式指定

```rust
let client = Client::new(Credential {
    access_key_id: "LTAI5t...".into(),
    access_key_secret: "your-secret".into(),
});
```

### 2. 环境变量

```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID=LTAI5t...
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-secret
```

```rust
let client = Client::from_env()?;
```

### 3. 配置文件

创建 `~/.alibabacloud/credentials`：

```ini
[default]
access_key_id = LTAI5t...
access_key_secret = your-secret
```

`Client::from_env()` 会自动按默认凭证链查找：**环境变量 -> 配置文件**。

## API 说明

### AssumeRole — 角色扮演

获取临时安全凭证（STS Token）。

```rust
let resp = client.assume_role(AssumeRoleRequest {
    role_arn: "acs:ram::123456:role/my-role".into(),
    role_session_name: "session-name".into(),
    policy: None,                  // 可选：内联权限策略 JSON
    duration_seconds: Some(3600),  // 可选：有效期 900 ~ 43200 秒
    external_id: None,             // 可选：跨账号访问外部 ID
}).await?;

// resp.credentials.access_key_id
// resp.credentials.access_key_secret
// resp.credentials.security_token
// resp.credentials.expiration
// resp.assumed_role_user.arn
// resp.assumed_role_user.assumed_role_id
```

### AssumeRoleWithSAML — SAML SSO 角色扮演

通过 SAML 断言扮演角色，用于企业 SSO 场景。

```rust
let resp = client.assume_role_with_saml(AssumeRoleWithSamlRequest {
    saml_provider_arn: "acs:ram::123456:saml-provider/my-idp".into(),
    role_arn: "acs:ram::123456:role/saml-role".into(),
    saml_assertion: "base64-encoded-saml-assertion".into(),
    policy: None,
    duration_seconds: None,
}).await?;
```

### AssumeRoleWithOIDC — OIDC SSO 角色扮演

通过 OIDC Token 扮演角色，用于 OIDC SSO 场景。

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

### GetCallerIdentity — 查询调用者身份

查询当前 AccessKey 对应的身份信息（无需额外参数）。

```rust
let resp = client.get_caller_identity().await?;

println!("账号 ID: {}", resp.account_id);
println!("身份 ARN: {}", resp.arn);
println!("身份类型: {}", resp.identity_type);
```

## 自定义配置

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

## 错误处理

所有操作返回 `rs_ali_sts::Result<T>`，错误类型为 `StsError`：

```rust
use rs_ali_sts::StsError;

match client.assume_role(request).await {
    Ok(resp) => println!("成功: {}", resp.credentials.access_key_id),
    Err(StsError::Api { request_id, code, message, .. }) => {
        eprintln!("API 错误 [{}]: {} (RequestId: {})", code, message, request_id);
    }
    Err(StsError::HttpClient(e)) => eprintln!("网络错误: {}", e),
    Err(StsError::Credential(msg)) => eprintln!("凭证错误: {}", msg),
    Err(e) => eprintln!("其他错误: {}", e),
}
```

| 变体 | 说明 |
|------|------|
| `HttpClient` | 网络 / 连接错误（来自 reqwest） |
| `Http` | 非预期的 HTTP 响应（响应体非 JSON 格式） |
| `Api` | 阿里云 API 业务错误（含 `request_id`、`code`、`message`） |
| `Credential` | 凭证解析失败 |
| `Deserialize` | JSON 反序列化错误 |
| `Signature` | 签名计算错误 |
| `Config` | 配置 / 凭证文件解析错误 |

## 安全特性

- 凭证在 `Debug` 输出中**自动脱敏** — `access_key_secret` 和 `security_token` 显示为 `****`
- 使用 **HTTPS POST** 发送请求 — 凭证不会出现在 URL 中
- 使用 **rustls** 作为 TLS 后端 — 纯 Rust 实现，无 OpenSSL 依赖
- 每个请求使用 **UUID v4 随机数** 作为签名 Nonce，防止重放攻击

## 许可证

本项目采用 [MIT 许可证](http://opensource.org/licenses/MIT)。
