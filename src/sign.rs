use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Result, StsError};

type HmacSha1 = Hmac<Sha1>;

/// Percent-encodes a string per Alibaba Cloud's rules (RFC 3986 variant).
///
/// Unreserved characters (A-Z, a-z, 0-9, '-', '.', '_', '~') are NOT encoded.
/// All other characters are encoded as `%XX` (uppercase hex).
/// Spaces become `%20` (NOT `+`).
pub(crate) fn percent_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}

/// Computes the Alibaba Cloud V1 signature for a set of request parameters.
///
/// Steps:
/// 1. Sort params by key (BTreeMap provides this).
/// 2. Build canonicalized query string: `key1=val1&key2=val2&...` (percent-encoded).
/// 3. Build StringToSign: `{method}&%2F&{percent_encode(canonical_query)}`.
/// 4. HMAC-SHA1 with key = `{access_key_secret}&`.
/// 5. Base64 encode the HMAC result.
pub(crate) fn sign_request(
    params: &BTreeMap<String, String>,
    access_key_secret: &str,
    http_method: &str,
) -> Result<String> {
    // Step 1-2: Build canonicalized query string
    let canonical_query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    // Step 3: Build StringToSign
    let string_to_sign = format!(
        "{}&{}&{}",
        http_method,
        percent_encode("/"),
        percent_encode(&canonical_query)
    );

    // Step 4: HMAC-SHA1
    let signing_key = format!("{}&", access_key_secret);
    let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes())
        .map_err(|e| StsError::Signature(format!("HMAC key error: {}", e)))?;
    mac.update(string_to_sign.as_bytes());
    let result = mac.finalize().into_bytes();

    // Step 5: Base64 encode
    Ok(BASE64.encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_unreserved_chars() {
        assert_eq!(percent_encode("abcXYZ019"), "abcXYZ019");
        assert_eq!(percent_encode("-._~"), "-._~");
    }

    #[test]
    fn percent_encode_spaces() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_special_chars() {
        assert_eq!(percent_encode("/"), "%2F");
        assert_eq!(percent_encode("="), "%3D");
        assert_eq!(percent_encode("&"), "%26");
        assert_eq!(percent_encode("+"), "%2B");
        assert_eq!(percent_encode("*"), "%2A");
    }

    #[test]
    fn percent_encode_chinese() {
        let encoded = percent_encode("中文");
        assert_eq!(encoded, "%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn sign_request_deterministic() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "AssumeRole".to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-04-01".to_string());
        params.insert("AccessKeyId".to_string(), "testid".to_string());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), "fixed-nonce".to_string());
        params.insert("Timestamp".to_string(), "2024-01-01T00:00:00Z".to_string());
        params.insert(
            "RoleArn".to_string(),
            "acs:ram::123456:role/test".to_string(),
        );
        params.insert("RoleSessionName".to_string(), "session".to_string());

        let sig1 = sign_request(&params, "testsecret", "POST").unwrap();
        let sig2 = sign_request(&params, "testsecret", "POST").unwrap();
        assert_eq!(sig1, sig2, "signature must be deterministic");
        assert!(!sig1.is_empty());
    }

    #[test]
    fn sign_request_different_secrets_differ() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "GetCallerIdentity".to_string());
        params.insert("Format".to_string(), "JSON".to_string());

        let sig1 = sign_request(&params, "secret1", "POST").unwrap();
        let sig2 = sign_request(&params, "secret2", "POST").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_request_different_methods_differ() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "GetCallerIdentity".to_string());

        let sig_post = sign_request(&params, "secret", "POST").unwrap();
        let sig_get = sign_request(&params, "secret", "GET").unwrap();
        assert_ne!(sig_post, sig_get);
    }

    #[test]
    fn sign_request_is_base64() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "Test".to_string());

        let sig = sign_request(&params, "key", "POST").unwrap();
        assert!(BASE64.decode(&sig).is_ok());
    }
}
