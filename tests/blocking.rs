#![cfg(feature = "blocking")]

use mockito::Matcher;
use rs_ali_sts::blocking::Client;
use rs_ali_sts::{AssumeRoleRequest, ClientConfig, Credential, StsError};

fn test_credential() -> Credential {
    Credential {
        access_key_id: "test-access-key-id".into(),
        access_key_secret: "test-access-key-secret".into(),
    }
}

fn test_client(endpoint: String) -> Client {
    let config = ClientConfig::default().with_endpoint(endpoint);
    Client::with_config(test_credential(), config).expect("failed to build client")
}

#[test]
fn blocking_assume_role_success() {
    let mut server = mockito::Server::new();

    let mock = server
        .mock("POST", "/")
        .match_header("Content-Type", "application/x-www-form-urlencoded")
        .match_body(Matcher::UrlEncoded("Action".into(), "AssumeRole".into()))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(
            r#"{
                "RequestId": "6894B13B-6D71-4EF5-88FA-F32781734A7F",
                "AssumedRoleUser": {
                    "Arn": "acs:ram::123456:role/test-role/session-name",
                    "AssumedRoleId": "33157794895460****:session-name"
                },
                "Credentials": {
                    "AccessKeyId": "STS.XXXXXXXXXXXX",
                    "AccessKeySecret": "YYYYYYYYYYYY",
                    "SecurityToken": "ZZZZZZZZZZZZ",
                    "Expiration": "2024-01-01T01:00:00Z"
                }
            }"#,
        )
        .create();

    let client = test_client(server.url());

    let resp = client
        .assume_role(AssumeRoleRequest {
            role_arn: "acs:ram::123456789012:role/test-role".into(),
            role_session_name: "session-name".into(),
            policy: None,
            duration_seconds: Some(3600),
            external_id: None,
        })
        .expect("assume_role should succeed");

    assert_eq!(resp.request_id, "6894B13B-6D71-4EF5-88FA-F32781734A7F");
    assert_eq!(
        resp.assumed_role_user.arn,
        "acs:ram::123456:role/test-role/session-name"
    );
    assert_eq!(
        resp.assumed_role_user.assumed_role_id,
        "33157794895460****:session-name"
    );
    assert_eq!(resp.credentials.access_key_id, "STS.XXXXXXXXXXXX");
    assert_eq!(resp.credentials.access_key_secret, "YYYYYYYYYYYY");
    assert_eq!(resp.credentials.security_token, "ZZZZZZZZZZZZ");
    assert_eq!(resp.credentials.expiration, "2024-01-01T01:00:00Z");

    mock.assert();
}

#[test]
fn blocking_assume_role_api_error() {
    let mut server = mockito::Server::new();

    let mock = server
        .mock("POST", "/")
        .match_header("Content-Type", "application/x-www-form-urlencoded")
        .match_body(Matcher::UrlEncoded("Action".into(), "AssumeRole".into()))
        .with_status(400)
        .with_header("Content-Type", "application/json")
        .with_body(
            r#"{
                "RequestId": "err-req-001",
                "Code": "InvalidParameter.RoleArn",
                "Message": "The specified RoleArn is invalid.",
                "Recommend": "https://error-center.aliyun.com/"
            }"#,
        )
        .create();

    let client = test_client(server.url());

    let err = client
        .assume_role(AssumeRoleRequest {
            role_arn: "acs:ram::123456789012:role/nonexistent-role".into(),
            role_session_name: "session-name".into(),
            policy: None,
            duration_seconds: None,
            external_id: None,
        })
        .expect_err("assume_role should fail with API error");

    match err {
        StsError::Api {
            request_id,
            code,
            message,
            recommend,
        } => {
            assert_eq!(request_id, "err-req-001");
            assert_eq!(code, "InvalidParameter.RoleArn");
            assert_eq!(message, "The specified RoleArn is invalid.");
            assert_eq!(
                recommend.as_deref(),
                Some("https://error-center.aliyun.com/")
            );
        }
        other => panic!("expected StsError::Api, got: {:?}", other),
    }

    mock.assert();
}

#[test]
fn blocking_get_caller_identity_success() {
    let mut server = mockito::Server::new();

    let mock = server
        .mock("POST", "/")
        .match_header("Content-Type", "application/x-www-form-urlencoded")
        .match_body(Matcher::UrlEncoded(
            "Action".into(),
            "GetCallerIdentity".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(
            r#"{
                "RequestId": "req-id-001",
                "AccountId": "123456789",
                "Arn": "acs:ram::123456789:user/testuser",
                "PrincipalId": "28877424437521****",
                "IdentityType": "RAMUser",
                "UserId": "28877424437521****"
            }"#,
        )
        .create();

    let client = test_client(server.url());

    let resp = client
        .get_caller_identity()
        .expect("get_caller_identity should succeed");

    assert_eq!(resp.request_id, "req-id-001");
    assert_eq!(resp.account_id, "123456789");
    assert_eq!(resp.arn, "acs:ram::123456789:user/testuser");
    assert_eq!(resp.principal_id, "28877424437521****");
    assert_eq!(resp.identity_type, "RAMUser");
    assert_eq!(resp.user_id.as_deref(), Some("28877424437521****"));
    assert!(resp.role_id.is_none());

    mock.assert();
}
