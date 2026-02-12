//! Common execution utilities for async and blocking clients.

use serde::de::DeserializeOwned;

use crate::error::{MAX_ERROR_BODY_CHARS, Result, StsError, truncate_str};
use crate::response::ApiErrorResponse;

/// Extracts server time from HTTP response Date header.
///
/// Returns `Some(server_timestamp)` if the Date header is present and parseable.
pub(crate) fn extract_server_time(headers: &reqwest::header::HeaderMap) -> Option<i64> {
    if let Some(date_header) = headers.get("date")
        && let Ok(date_str) = date_header.to_str()
        && let Ok(server_time) = chrono::DateTime::parse_from_rfc2822(date_str)
    {
        return Some(server_time.timestamp());
    }
    None
}

/// Parses a successful response body.
pub(crate) fn parse_success_response<T: DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_str(text).map_err(StsError::from)
}

/// Parses an error response body and returns appropriate StsError.
pub(crate) fn parse_error_response(status: reqwest::StatusCode, text: &str) -> StsError {
    match serde_json::from_str::<ApiErrorResponse>(text) {
        Ok(api_err) => StsError::Api {
            request_id: api_err.request_id,
            code: api_err.code,
            message: api_err.message,
            recommend: api_err.recommend,
        },
        Err(_) => StsError::Http(format!(
            "HTTP {} with body: {}",
            status,
            truncate_str(text, MAX_ERROR_BODY_CHARS)
        )),
    }
}

/// Handles response parsing for both success and error cases.
pub(crate) fn handle_response<T: DeserializeOwned>(
    status: reqwest::StatusCode,
    text: String,
) -> Result<T> {
    if status.is_success() {
        parse_success_response(&text)
    } else {
        Err(parse_error_response(status, &text))
    }
}

/// Calculates smoothed clock offset using exponential moving average.
///
/// Uses 75% old value + 25% new value to reduce jitter.
pub(crate) fn calculate_smoothed_offset(current_offset: i64, new_offset: i64) -> i64 {
    // Use 75% old + 25% new for smoothing
    (current_offset * 3 + new_offset) / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_smoothed_offset() {
        // Initial offset is 0, new offset is 100
        let smoothed = calculate_smoothed_offset(0, 100);
        assert_eq!(smoothed, 25); // (0*3 + 100) / 4 = 25

        // Gradual convergence
        let smoothed = calculate_smoothed_offset(25, 100);
        assert_eq!(smoothed, 43); // (25*3 + 100) / 4 = 43

        // Large jump is dampened
        let smoothed = calculate_smoothed_offset(100, 1000);
        assert_eq!(smoothed, 325); // (100*3 + 1000) / 4 = 325
    }
}
