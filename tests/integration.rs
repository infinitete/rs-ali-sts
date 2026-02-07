use mockito::{Matcher, Server};
use rs_ali_sts::{
    AssumeRoleRequest, AssumeRoleWithOidcRequest, AssumeRoleWithSamlRequest, Client, ClientConfig,
    Credential, StsError,
};

fn test_credential() -> Credential {
    Credential {
        access_key_id: "test-access-key-id".into(),
        access_key_secret: "test-access-key-secret".into(),
    }
}

fn test_client(server_url: String) -> Client {
    let config = ClientConfig::default().with_endpoint(server_url);
    Client::with_config(test_credential(), config)
}

#[tokio::test]
async fn assume_role_success() {
    let mut server = Server::new_async().await;

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
        .create_async()
        .await;

    let client = test_client(server.url());

    let resp = client
        .assume_role(AssumeRoleRequest {
            role_arn: "acs:ram::123456:role/test-role".into(),
            role_session_name: "session-name".into(),
            policy: None,
            duration_seconds: Some(3600),
            external_id: None,
        })
        .await
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

    mock.assert_async().await;
}

#[tokio::test]
async fn assume_role_api_error() {
    let mut server = Server::new_async().await;

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
        .create_async()
        .await;

    let client = test_client(server.url());

    let result = client
        .assume_role(AssumeRoleRequest {
            role_arn: "invalid-arn".into(),
            role_session_name: "session".into(),
            policy: None,
            duration_seconds: None,
            external_id: None,
        })
        .await;

    assert!(result.is_err());

    match result.unwrap_err() {
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

    mock.assert_async().await;
}

#[tokio::test]
async fn get_caller_identity_success() {
    let mut server = Server::new_async().await;

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
        .create_async()
        .await;

    let client = test_client(server.url());

    let resp = client
        .get_caller_identity()
        .await
        .expect("get_caller_identity should succeed");

    assert_eq!(resp.request_id, "req-id-001");
    assert_eq!(resp.account_id, "123456789");
    assert_eq!(resp.arn, "acs:ram::123456789:user/testuser");
    assert_eq!(resp.principal_id, "28877424437521****");
    assert_eq!(resp.identity_type, "RAMUser");
    assert_eq!(resp.user_id.as_deref(), Some("28877424437521****"));
    assert!(resp.role_id.is_none());

    mock.assert_async().await;
}

#[tokio::test]
async fn assume_role_with_saml_success() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/")
        .match_header("Content-Type", "application/x-www-form-urlencoded")
        .match_body(Matcher::UrlEncoded(
            "Action".into(),
            "AssumeRoleWithSAML".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(
            r#"{
                "RequestId": "req-saml-001",
                "Credentials": {
                    "AccessKeyId": "STS.SAML_AK",
                    "AccessKeySecret": "SAML_SECRET",
                    "SecurityToken": "SAML_TOKEN",
                    "Expiration": "2024-06-01T12:00:00Z"
                },
                "SAMLAssertionInfo": {
                    "SubjectType": "persistent",
                    "Subject": "user@example.com",
                    "Recipient": "https://signin.aliyun.com/saml-role/sso",
                    "Issuer": "https://idp.example.com"
                }
            }"#,
        )
        .create_async()
        .await;

    let client = test_client(server.url());

    let resp = client
        .assume_role_with_saml(AssumeRoleWithSamlRequest {
            saml_provider_arn: "acs:ram::123456:saml-provider/test-idp".into(),
            role_arn: "acs:ram::123456:role/saml-role".into(),
            saml_assertion: "base64-encoded-saml-assertion".into(),
            policy: None,
            duration_seconds: None,
        })
        .await
        .expect("assume_role_with_saml should succeed");

    assert_eq!(resp.request_id, "req-saml-001");
    assert_eq!(resp.credentials.access_key_id, "STS.SAML_AK");
    assert_eq!(resp.credentials.access_key_secret, "SAML_SECRET");
    assert_eq!(resp.credentials.security_token, "SAML_TOKEN");
    assert_eq!(resp.credentials.expiration, "2024-06-01T12:00:00Z");
    assert_eq!(resp.saml_assertion_info.subject_type, "persistent");
    assert_eq!(resp.saml_assertion_info.subject, "user@example.com");
    assert_eq!(
        resp.saml_assertion_info.recipient,
        "https://signin.aliyun.com/saml-role/sso"
    );
    assert_eq!(resp.saml_assertion_info.issuer, "https://idp.example.com");

    mock.assert_async().await;
}

#[tokio::test]
async fn assume_role_with_oidc_success() {
    let mut server = Server::new_async().await;

    let mock = server
        .mock("POST", "/")
        .match_header("Content-Type", "application/x-www-form-urlencoded")
        .match_body(Matcher::UrlEncoded(
            "Action".into(),
            "AssumeRoleWithOIDC".into(),
        ))
        .with_status(200)
        .with_header("Content-Type", "application/json")
        .with_body(
            r#"{
                "RequestId": "req-oidc-001",
                "Credentials": {
                    "AccessKeyId": "STS.OIDC_AK",
                    "AccessKeySecret": "OIDC_SECRET",
                    "SecurityToken": "OIDC_TOKEN",
                    "Expiration": "2024-06-01T12:00:00Z"
                },
                "OIDCTokenInfo": {
                    "Subject": "oidc-user-001",
                    "Issuer": "https://oidc.example.com",
                    "ClientIds": "client-id-001"
                }
            }"#,
        )
        .create_async()
        .await;

    let client = test_client(server.url());

    let resp = client
        .assume_role_with_oidc(AssumeRoleWithOidcRequest {
            oidc_provider_arn: "acs:ram::123456:oidc-provider/test-oidc".into(),
            role_arn: "acs:ram::123456:role/oidc-role".into(),
            oidc_token: "eyJhbGciOiJSUzI1NiJ9.test-token".into(),
            policy: None,
            duration_seconds: None,
            role_session_name: Some("oidc-session".into()),
        })
        .await
        .expect("assume_role_with_oidc should succeed");

    assert_eq!(resp.request_id, "req-oidc-001");
    assert_eq!(resp.credentials.access_key_id, "STS.OIDC_AK");
    assert_eq!(resp.credentials.access_key_secret, "OIDC_SECRET");
    assert_eq!(resp.credentials.security_token, "OIDC_TOKEN");
    assert_eq!(resp.credentials.expiration, "2024-06-01T12:00:00Z");
    assert_eq!(resp.oidc_token_info.subject, "oidc-user-001");
    assert_eq!(resp.oidc_token_info.issuer, "https://oidc.example.com");
    assert_eq!(resp.oidc_token_info.client_ids, "client-id-001");

    mock.assert_async().await;
}
