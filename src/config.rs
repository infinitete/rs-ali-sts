use std::time::Duration;

/// Configuration for the STS client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// STS API endpoint URL.
    pub endpoint: String,

    /// HTTP request timeout.
    pub timeout: Duration,

    /// Response format (always "JSON").
    pub(crate) format: &'static str,

    /// API version (always "2015-04-01").
    pub(crate) api_version: &'static str,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://sts.aliyuncs.com".to_string(),
            timeout: Duration::from_secs(30),
            format: "JSON",
            api_version: "2015-04-01",
        }
    }
}

impl ClientConfig {
    /// Creates a new configuration with a custom endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Sets the HTTP request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.endpoint, "https://sts.aliyuncs.com");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.format, "JSON");
        assert_eq!(config.api_version, "2015-04-01");
    }

    #[test]
    fn custom_endpoint() {
        let config =
            ClientConfig::default().with_endpoint("https://sts-vpc.cn-hangzhou.aliyuncs.com");
        assert_eq!(config.endpoint, "https://sts-vpc.cn-hangzhou.aliyuncs.com");
    }

    #[test]
    fn custom_timeout() {
        let config = ClientConfig::default().with_timeout(Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(60));
    }
}
