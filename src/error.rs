use thiserror::Error;

/// Maximum characters to include in error message body for debugging.
pub(crate) const MAX_ERROR_BODY_CHARS: usize = 200;

/// Errors that can occur when using the STS SDK.
#[derive(Debug, Error)]
pub enum StsError {
    /// HTTP/network layer error from reqwest.
    #[error("HTTP request failed: {0}")]
    HttpClient(#[from] reqwest::Error),

    /// Unexpected HTTP response (non-JSON error body).
    #[error("HTTP error: {0}")]
    Http(String),

    /// Alibaba Cloud API returned a business error.
    #[error("API error (RequestId: {request_id}): [{code}] {message}")]
    Api {
        request_id: String,
        code: String,
        message: String,
        recommend: Option<String>,
    },

    /// Signature computation error.
    #[error("signature error: {0}")]
    Signature(String),

    /// Credential not found or invalid.
    #[error("credential error: {0}")]
    Credential(String),

    /// Response deserialization error.
    #[error("deserialization error: {0}")]
    Deserialize(#[from] serde_json::Error),

    /// Config file parse error.
    #[error("config error: {0}")]
    Config(String),

    /// Validation error for request parameters.
    #[error("validation error: {0}")]
    Validation(String),
}

impl StsError {
    /// Returns `true` if the error is potentially recoverable by retrying.
    ///
    /// Retryable errors include:
    /// - Network/HTTP errors (timeouts, connection issues)
    /// - Server errors (5xx)
    ///
    /// Non-retryable errors include:
    /// - Authentication/credential errors
    /// - Validation errors
    /// - Client errors (4xx except 429)
    pub fn is_retryable(&self) -> bool {
        match self {
            // Network errors are generally retryable
            StsError::HttpClient(e) => e.is_timeout() || e.is_connect(),
            StsError::Http(_) => true,

            // API errors: check the code
            StsError::Api { code, .. } => {
                // Rate limiting is retryable
                if code == "Throttling" || code == "ServiceUnavailable" {
                    return true;
                }
                // Server errors (5xx-like) are retryable
                code.starts_with("Internal") || code.starts_with("Service")
            }

            // These are never retryable
            StsError::Signature(_)
            | StsError::Credential(_)
            | StsError::Deserialize(_)
            | StsError::Config(_)
            | StsError::Validation(_) => false,
        }
    }

    /// Returns the request ID if this is an API error.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            StsError::Api { request_id, .. } => Some(request_id),
            _ => None,
        }
    }

    /// Returns the error code if this is an API error.
    pub fn error_code(&self) -> Option<&str> {
        match self {
            StsError::Api { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// A specialized Result type for STS operations.
pub type Result<T> = std::result::Result<T, StsError>;

/// Truncates a string to at most `max_chars` characters on a valid UTF-8 boundary.
pub(crate) fn truncate_str(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_display() {
        let err = StsError::Api {
            request_id: "req-123".to_string(),
            code: "InvalidParameter".to_string(),
            message: "The specified RoleArn is invalid.".to_string(),
            recommend: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("req-123"));
        assert!(msg.contains("InvalidParameter"));
        assert!(msg.contains("The specified RoleArn is invalid."));
    }

    #[test]
    fn http_error_display() {
        let err = StsError::Http("HTTP 502 with body: Bad Gateway".to_string());
        assert_eq!(
            err.to_string(),
            "HTTP error: HTTP 502 with body: Bad Gateway"
        );
    }

    #[test]
    fn credential_error_display() {
        let err = StsError::Credential("no credential found".to_string());
        assert_eq!(err.to_string(), "credential error: no credential found");
    }

    #[test]
    fn signature_error_display() {
        let err = StsError::Signature("HMAC computation failed".to_string());
        assert_eq!(err.to_string(), "signature error: HMAC computation failed");
    }

    #[test]
    fn config_error_display() {
        let err = StsError::Config("invalid INI format".to_string());
        assert_eq!(err.to_string(), "config error: invalid INI format");
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("hello world", 5), "hello");
    }

    #[test]
    fn truncate_str_multibyte() {
        // "中文测试" is 4 characters, each 3 bytes in UTF-8
        let s = "中文测试数据";
        assert_eq!(truncate_str(s, 4), "中文测试");
    }

    #[test]
    fn truncate_str_empty() {
        assert_eq!(truncate_str("", 10), "");
    }
}
