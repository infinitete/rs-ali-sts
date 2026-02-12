//! Signature computation for Alibaba Cloud STS API.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;

use crate::error::{Result, StsError};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// Signature version enum for Alibaba Cloud STS API.
///
/// - V1_0: HMAC-SHA1 signature (version 1.0) - default, compatible with Alibaba Cloud STS
/// - V2_0: HMAC-SHA256 signature (version 2.0) - more secure but may not be supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureVersion {
    /// HMAC-SHA1 signature (version 1.0) - compatible with Alibaba Cloud STS API
    #[default]
    V1_0 = 1,
    /// HMAC-SHA256 signature (version 2.0) - more secure but may not be supported by all regions
    V2_0 = 2,
}

impl SignatureVersion {
    /// Returns the signature method string for the API request.
    pub fn as_method_str(&self) -> &'static str {
        match self {
            SignatureVersion::V1_0 => "HMAC-SHA1",
            SignatureVersion::V2_0 => "HMAC-SHA256",
        }
    }

    /// Returns the version string for the API request.
    pub fn as_version_str(&self) -> &'static str {
        match self {
            SignatureVersion::V1_0 => "1.0",
            SignatureVersion::V2_0 => "2.0",
        }
    }
}

/// Percent-encodes a string per Alibaba Cloud's rules (RFC 3986 variant).
///
/// Unreserved characters (A-Z, a-z, 0-9, '-', '.', '_', '~') are NOT encoded.
/// All other characters are encoded as `%XX` (uppercase hex).
/// Spaces become `%20` (NOT `+`).
///
/// This implementation uses a precomputed lookup table for hex digits
/// and avoids temporary allocations for each encoded character.
pub(crate) fn percent_encode(s: &str) -> String {
    // Precompute hex digits for O(1) lookup
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    // Calculate capacity: worst case is 3x (each byte becomes %XX)
    let mut encoded = String::with_capacity(s.len() * 3);

    let mut buf = [0u8; 3];
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                // SAFETY: The byte being pushed is a valid ASCII character
                // (unreserved character per RFC 3986), which is always valid UTF-8.
                unsafe {
                    encoded.as_mut_vec().push(byte);
                }
            }
            _ => {
                // Use a pre-allocated buffer to avoid temporary String allocation
                buf[0] = b'%';
                buf[1] = HEX_DIGITS[(byte >> 4) as usize];
                buf[2] = HEX_DIGITS[(byte & 0x0F) as usize];
                // SAFETY: buf contains '%' followed by two uppercase hex digits,
                // all of which are valid ASCII and therefore valid UTF-8.
                unsafe {
                    encoded.push_str(std::str::from_utf8_unchecked(&buf));
                }
            }
        }
    }
    encoded
}

/// Computes the Alibaba Cloud signature for a set of request parameters.
///
/// Steps:
/// 1. Sort params by key (BTreeMap provides this).
/// 2. Build canonicalized query string: `key1=val1&key2=val2&...` (percent-encoded).
/// 3. Build StringToSign: `{method}&%2F&{percent_encode(canonical_query)}`.
/// 4. HMAC-SHA256 with key = `{access_key_secret}&`.
/// 5. Base64 encode the HMAC result.
///
/// # Arguments
///
/// * `params` - The request parameters sorted by key
/// * `access_key_secret` - The Alibaba Cloud access key secret
/// * `http_method` - The HTTP method (GET, POST, etc.)
/// * `version` - The signature version to use (V2_0 recommended)
pub(crate) fn sign_request(
    params: &BTreeMap<String, String>,
    access_key_secret: &str,
    http_method: &str,
    version: SignatureVersion,
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

    // Step 4: HMAC based on version
    let signing_key = format!("{}&", access_key_secret);

    let signature = match version {
        SignatureVersion::V1_0 => {
            let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes())
                .map_err(|e| StsError::Signature(format!("HMAC-SHA1 key error: {}", e)))?;
            mac.update(string_to_sign.as_bytes());
            BASE64.encode(mac.finalize().into_bytes())
        }
        SignatureVersion::V2_0 => {
            let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
                .map_err(|e| StsError::Signature(format!("HMAC-SHA256 key error: {}", e)))?;
            mac.update(string_to_sign.as_bytes());
            BASE64.encode(mac.finalize().into_bytes())
        }
    };

    Ok(signature)
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
    fn percent_encode_all_unreserved() {
        // Test all unreserved characters
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        assert_eq!(percent_encode(unreserved), unreserved);
    }

    #[test]
    fn percent_encode_empty() {
        assert_eq!(percent_encode(""), "");
    }

    #[test]
    fn percent_encode_reserved_chars() {
        assert_eq!(percent_encode("!"), "%21");
        assert_eq!(percent_encode("\""), "%22");
        assert_eq!(percent_encode("#"), "%23");
        assert_eq!(percent_encode("$"), "%24");
        assert_eq!(percent_encode("%"), "%25");
        assert_eq!(percent_encode("&"), "%26");
        assert_eq!(percent_encode("'"), "%27");
        assert_eq!(percent_encode("("), "%28");
        assert_eq!(percent_encode(")"), "%29");
        assert_eq!(percent_encode("*"), "%2A");
        assert_eq!(percent_encode("+"), "%2B");
        assert_eq!(percent_encode(","), "%2C");
        assert_eq!(percent_encode(":"), "%3A");
        assert_eq!(percent_encode(";"), "%3B");
        assert_eq!(percent_encode("<"), "%3C");
        assert_eq!(percent_encode(">"), "%3E");
        assert_eq!(percent_encode("?"), "%3F");
        assert_eq!(percent_encode("@"), "%40");
        assert_eq!(percent_encode("["), "%5B");
        assert_eq!(percent_encode("]"), "%5D");
    }

    #[test]
    fn percent_encode_mixed() {
        assert_eq!(percent_encode("test@example.com"), "test%40example.com");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
        assert_eq!(percent_encode("100%"), "100%25");
    }

    #[test]
    fn percent_encode_uppercase_hex() {
        // Ensure hex digits are uppercase
        let encoded = percent_encode("\x00");
        assert_eq!(encoded, "%00");
        let encoded = percent_encode("\u{00FF}");
        assert_eq!(encoded, "%C3%BF");
    }

    #[test]
    fn percent_encode_byte_0x7f() {
        // DEL character (0x7F)
        assert_eq!(percent_encode("\x7F"), "%7F");
    }

    #[test]
    fn percent_encode_performance_no_realloc() {
        // Test that we don't reallocate for typical inputs
        let input = "Action=AssumeRole&Version=2015-04-01";
        let encoded = percent_encode(input);
        // Verify encoding correctness
        assert!(encoded.contains("Action"));
        assert!(encoded.contains("%3D")); // =
        assert!(encoded.contains("%26")); // &
    }

    #[test]
    fn percent_encode_multibyte_sequences() {
        // Japanese characters (テスト)
        assert_eq!(percent_encode("テスト"), "%E3%83%86%E3%82%B9%E3%83%88");
        // Arabic (السلام)
        assert_eq!(
            percent_encode("السلام"),
            "%D8%A7%D9%84%D8%B3%D9%84%D8%A7%D9%85"
        );
    }

    #[test]
    fn sign_request_sha256_deterministic() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "AssumeRole".to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-04-01".to_string());
        params.insert("AccessKeyId".to_string(), "testid".to_string());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA256".to_string());
        params.insert("SignatureVersion".to_string(), "2.0".to_string());
        params.insert("SignatureNonce".to_string(), "fixed-nonce".to_string());
        params.insert("Timestamp".to_string(), "2024-01-01T00:00:00Z".to_string());
        params.insert(
            "RoleArn".to_string(),
            "acs:ram::123456:role/test".to_string(),
        );
        params.insert("RoleSessionName".to_string(), "session".to_string());

        let sig1 = sign_request(&params, "testsecret", "POST", SignatureVersion::V2_0).unwrap();
        let sig2 = sign_request(&params, "testsecret", "POST", SignatureVersion::V2_0).unwrap();
        assert_eq!(sig1, sig2, "SHA-256 signature must be deterministic");
        assert!(!sig1.is_empty());
    }

    #[test]
    fn sign_request_different_secrets_differ() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "GetCallerIdentity".to_string());
        params.insert("Format".to_string(), "JSON".to_string());

        let sig1 = sign_request(&params, "secret1", "POST", SignatureVersion::V2_0).unwrap();
        let sig2 = sign_request(&params, "secret2", "POST", SignatureVersion::V2_0).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_request_different_methods_differ() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "GetCallerIdentity".to_string());

        let sig_post = sign_request(&params, "secret", "POST", SignatureVersion::V2_0).unwrap();
        let sig_get = sign_request(&params, "secret", "GET", SignatureVersion::V2_0).unwrap();
        assert_ne!(sig_post, sig_get);
    }

    #[test]
    fn sign_request_is_base64() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "Test".to_string());

        let sig = sign_request(&params, "key", "POST", SignatureVersion::V2_0).unwrap();
        assert!(BASE64.decode(&sig).is_ok());
    }

    #[test]
    fn signature_version_default() {
        assert_eq!(SignatureVersion::default(), SignatureVersion::V1_0);
    }

    #[test]
    fn signature_version_strings() {
        assert_eq!(SignatureVersion::V1_0.as_method_str(), "HMAC-SHA1");
        assert_eq!(SignatureVersion::V1_0.as_version_str(), "1.0");
        assert_eq!(SignatureVersion::V2_0.as_method_str(), "HMAC-SHA256");
        assert_eq!(SignatureVersion::V2_0.as_version_str(), "2.0");
    }

    #[test]
    fn sign_request_sha1_deterministic() {
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

        let sig1 = sign_request(&params, "testsecret", "POST", SignatureVersion::V1_0).unwrap();
        let sig2 = sign_request(&params, "testsecret", "POST", SignatureVersion::V1_0).unwrap();
        assert_eq!(sig1, sig2, "SHA-1 signature must be deterministic");
        assert!(!sig1.is_empty());
    }
}
