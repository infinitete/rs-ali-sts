//! Live integration tests using real Alibaba Cloud credentials.
//!
//! These tests are ignored by default. Run with:
//! ```bash
//! # Set environment variables first
//! export ALIBABA_CLOUD_ACCESS_KEY_ID=your-access-key-id
//! export ALIBABA_CLOUD_ACCESS_KEY_SECRET=your-access-key-secret
//! export ALIBABA_CLOUD_ROLE_ARN=acs:ram::123456:role/your-role
//!
//! cargo test --test live -- --ignored --nocapture
//! ```

use rs_ali_sts::{AssumeRoleRequest, Client};

/// Create client using credentials from environment variables
fn live_client() -> Client {
    Client::from_env().expect("failed to create client from environment")
}

/// Get role ARN from environment variable
fn role_arn() -> String {
    std::env::var("ALIBABA_CLOUD_ROLE_ARN")
        .expect("ALIBABA_CLOUD_ROLE_ARN environment variable not set")
}

#[tokio::test]
#[ignore = "requires real Alibaba Cloud credentials"]
async fn live_get_caller_identity() {
    let client = live_client();

    let resp = client
        .get_caller_identity()
        .await
        .expect("get_caller_identity failed");

    println!("=== GetCallerIdentity Response ===");
    println!("RequestId: {}", resp.request_id);
    println!("AccountId: {}", resp.account_id);
    println!("Arn: {}", resp.arn);
    println!("PrincipalId: {}", resp.principal_id);
    println!("IdentityType: {}", resp.identity_type);
    println!("UserId: {:?}", resp.user_id);
    println!("RoleId: {:?}", resp.role_id);

    // Basic assertions
    assert!(
        !resp.request_id.is_empty(),
        "request_id should not be empty"
    );
    assert!(
        !resp.account_id.is_empty(),
        "account_id should not be empty"
    );
    assert!(
        resp.arn.starts_with("acs:ram::"),
        "arn should start with acs:ram::"
    );
}

#[tokio::test]
#[ignore = "requires real Alibaba Cloud credentials"]
async fn live_assume_role() {
    let client = live_client();

    let request = AssumeRoleRequest::builder()
        .role_arn(role_arn())
        .role_session_name("test-session")
        .duration_seconds(3600)
        .build();

    let resp = client
        .assume_role(request)
        .await
        .expect("assume_role failed");

    println!("=== AssumeRole Response ===");
    println!("RequestId: {}", resp.request_id);
    println!();
    println!("AssumedRoleUser:");
    println!("  Arn: {}", resp.assumed_role_user.arn);
    println!(
        "  AssumedRoleId: {}",
        resp.assumed_role_user.assumed_role_id
    );
    println!();
    println!("Credentials:");
    println!("  AccessKeyId: {}", resp.credentials.access_key_id);
    println!("  AccessKeySecret: {}", resp.credentials.access_key_secret);
    println!("  SecurityToken: {}", resp.credentials.security_token);
    println!("  Expiration: {}", resp.credentials.expiration);

    // Basic assertions
    assert!(
        !resp.request_id.is_empty(),
        "request_id should not be empty"
    );
    assert!(
        resp.credentials.access_key_id.starts_with("STS."),
        "temporary access key should start with STS."
    );
    assert!(
        !resp.credentials.access_key_secret.is_empty(),
        "access_key_secret should not be empty"
    );
    assert!(
        !resp.credentials.security_token.is_empty(),
        "security_token should not be empty"
    );
    assert!(
        !resp.credentials.expiration.is_empty(),
        "expiration should not be empty"
    );
}

#[tokio::test]
#[ignore = "requires real Alibaba Cloud credentials"]
async fn live_assume_role_with_builder_try_build() {
    let client = live_client();

    // Test try_build() method
    let request = AssumeRoleRequest::builder()
        .role_arn(role_arn())
        .role_session_name("test-session-try-build")
        .try_build()
        .expect("failed to build request");

    let resp = client
        .assume_role(request)
        .await
        .expect("assume_role failed");

    println!("=== AssumeRole (try_build) Response ===");
    println!("RequestId: {}", resp.request_id);
    println!("AccessKeyId: {}", resp.credentials.access_key_id);
    println!("Expiration: {}", resp.credentials.expiration);

    assert!(
        !resp.request_id.is_empty(),
        "request_id should not be empty"
    );
}

#[tokio::test]
#[ignore = "requires real Alibaba Cloud credentials"]
async fn live_clock_skew_correction() {
    let client = live_client();

    // Initial offset should be 0
    let initial_offset = client.time_offset();
    println!("Initial time offset: {} seconds", initial_offset);

    // Make a request to trigger clock skew correction
    let _ = client
        .get_caller_identity()
        .await
        .expect("get_caller_identity failed");

    // After request, offset might be updated based on server time
    let updated_offset = client.time_offset();
    println!("Updated time offset: {} seconds", updated_offset);

    // The offset might remain 0 if server doesn't return Date header,
    // or it could be a small positive/negative value
    println!(
        "Clock skew correction working: offset changed from {} to {}",
        initial_offset, updated_offset
    );
}
