use std::time::Duration;

use crate::sign::SignatureVersion;

/// Configuration for the STS client.
///
/// Use [`ClientConfig::default()`] to create a new configuration,
/// then use the `with_*` methods to customize.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// STS API endpoint URL.
    pub endpoint: String,

    /// HTTP request timeout.
    pub timeout: Duration,

    /// Maximum number of concurrent API requests.
    pub max_concurrent_requests: usize,

    /// Connection timeout for establishing TCP connections.
    pub connect_timeout: Duration,

    /// Pool idle timeout before closing idle connections.
    pub pool_idle_timeout: Duration,

    /// Maximum number of idle connections per host.
    pub pool_max_idle_per_host: usize,

    /// TCP keepalive duration.
    pub tcp_keepalive: Option<Duration>,

    /// Response format (always "JSON").
    pub(crate) format: &'static str,

    /// API version (always "2015-04-01").
    pub(crate) api_version: &'static str,

    /// Signature version to use for API requests.
    pub signature_version: SignatureVersion,
}

/// Default HTTP request timeout (30 seconds).
///
/// This is the maximum time to wait for an API response before
/// timing out. Most STS operations complete within a few seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum number of concurrent API requests.
///
/// This limit prevents overwhelming the STS server with too many
/// simultaneous requests.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 10;

/// Default TCP connection timeout (10 seconds).
///
/// This is the maximum time to establish a new TCP connection
/// to the STS server.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default connection pool idle timeout (90 seconds).
///
/// Idle connections in the pool are closed after this duration
/// to free up resources.
pub const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 90;

/// Default maximum idle connections per host (10).
///
/// Maximum number of idle connections to keep in the pool
/// for each unique host.
pub const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 10;

/// Default TCP keepalive duration (60 seconds).
///
/// Periodically sends keepalive packets to maintain long-lived
/// connections through network equipment that may drop idle connections.
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;

/// Minimum token validity duration in seconds (15 minutes).
///
/// STS temporary credentials are valid for a minimum of 900 seconds
/// (15 minutes) and a maximum of 3600 seconds (1 hour).
pub const MIN_DURATION_SECONDS: u64 = 900;

/// Maximum token validity duration in seconds (1 hour).
///
/// STS temporary credentials expire after a maximum of 3600 seconds
/// (1 hour) from the time of issuance.
pub const MAX_DURATION_SECONDS: u64 = 3600;

/// Minimum role session name length (1 character).
pub const MIN_ROLE_SESSION_NAME_LENGTH: usize = 1;

/// Maximum role session name length (32 characters).
pub const MAX_ROLE_SESSION_NAME_LENGTH: usize = 32;

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://sts.aliyuncs.com".to_string(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            pool_idle_timeout: Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS),
            pool_max_idle_per_host: DEFAULT_POOL_MAX_IDLE_PER_HOST,
            tcp_keepalive: Some(Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS)),
            format: "JSON",
            api_version: "2015-04-01",
            signature_version: SignatureVersion::default(),
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
    ///
    /// # Arguments
    ///
    /// * `timeout` - The timeout duration for HTTP requests
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rs_ali_sts::ClientConfig;
    /// # use std::time::Duration;
    /// let config = ClientConfig::default().with_timeout(Duration::from_secs(60));
    /// ```
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum number of concurrent API requests.
    ///
    /// This limit helps prevent overwhelming the server and manages resource usage.
    /// When the limit is reached, additional requests will wait until a slot becomes available.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum number of concurrent requests (must be > 0)
    ///
    /// # Panics
    ///
    /// Panics if `max` is 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rs_ali_sts::ClientConfig;
    /// let config = ClientConfig::default().with_max_concurrent_requests(5);
    /// ```
    pub fn with_max_concurrent_requests(mut self, max: usize) -> Self {
        assert!(max > 0, "max_concurrent_requests must be greater than 0");
        self.max_concurrent_requests = max;
        self
    }

    /// Sets the connection timeout for establishing TCP connections.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the pool idle timeout before closing idle connections.
    pub fn with_pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.pool_idle_timeout = timeout;
        self
    }

    /// Sets the maximum number of idle connections per host.
    pub fn with_pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.pool_max_idle_per_host = max;
        self
    }

    /// Sets the TCP keepalive duration. Use `None` to disable.
    pub fn with_tcp_keepalive(mut self, duration: Option<Duration>) -> Self {
        self.tcp_keepalive = duration;
        self
    }

    /// Sets the signature version to use for API requests.
    ///
    /// # Arguments
    ///
    /// * `version` - The signature version (V1_0 for SHA-1, V2_0 for SHA-256)
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rs_ali_sts::{ClientConfig, SignatureVersion};
    /// let config = ClientConfig::default()
    ///     .with_signature_version(SignatureVersion::V2_0);
    /// ```
    pub fn with_signature_version(mut self, version: SignatureVersion) -> Self {
        self.signature_version = version;
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
        assert_eq!(config.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(
            config.max_concurrent_requests,
            DEFAULT_MAX_CONCURRENT_REQUESTS
        );
        assert_eq!(
            config.connect_timeout,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            config.pool_idle_timeout,
            Duration::from_secs(DEFAULT_POOL_IDLE_TIMEOUT_SECS)
        );
        assert_eq!(
            config.pool_max_idle_per_host,
            DEFAULT_POOL_MAX_IDLE_PER_HOST
        );
        assert_eq!(
            config.tcp_keepalive,
            Some(Duration::from_secs(DEFAULT_TCP_KEEPALIVE_SECS))
        );
        assert_eq!(config.format, "JSON");
        assert_eq!(config.api_version, "2015-04-01");
        assert_eq!(config.signature_version, SignatureVersion::V1_0);
    }

    #[test]
    fn custom_endpoint() {
        let config =
            ClientConfig::default().with_endpoint("https://sts-vpc.cn-hangzhou.aliyuncs.com");
        assert_eq!(config.endpoint, "https://sts-vpc.cn-hangzhou.aliyuncs.com");
    }

    #[test]
    fn custom_timeout() {
        use std::time::Duration;
        let config = ClientConfig::default().with_timeout(Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn custom_max_concurrent_requests() {
        let config = ClientConfig::default().with_max_concurrent_requests(5);
        assert_eq!(config.max_concurrent_requests, 5);
    }

    #[test]
    #[should_panic(expected = "max_concurrent_requests must be greater than 0")]
    fn zero_max_concurrent_requests_panics() {
        ClientConfig::default().with_max_concurrent_requests(0);
    }

    #[test]
    fn custom_connect_timeout() {
        let config = ClientConfig::default().with_connect_timeout(Duration::from_secs(5));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn custom_pool_idle_timeout() {
        let config = ClientConfig::default().with_pool_idle_timeout(Duration::from_secs(120));
        assert_eq!(config.pool_idle_timeout, Duration::from_secs(120));
    }

    #[test]
    fn custom_pool_max_idle_per_host() {
        let config = ClientConfig::default().with_pool_max_idle_per_host(20);
        assert_eq!(config.pool_max_idle_per_host, 20);
    }

    #[test]
    fn custom_tcp_keepalive() {
        let config = ClientConfig::default().with_tcp_keepalive(Some(Duration::from_secs(30)));
        assert_eq!(config.tcp_keepalive, Some(Duration::from_secs(30)));
    }

    #[test]
    fn disable_tcp_keepalive() {
        let config = ClientConfig::default().with_tcp_keepalive(None);
        assert_eq!(config.tcp_keepalive, None);
    }

    #[test]
    fn custom_signature_version_v1() {
        let config = ClientConfig::default().with_signature_version(SignatureVersion::V1_0);
        assert_eq!(config.signature_version, SignatureVersion::V1_0);
    }

    #[test]
    fn custom_signature_version_v2() {
        let config = ClientConfig::default().with_signature_version(SignatureVersion::V2_0);
        assert_eq!(config.signature_version, SignatureVersion::V2_0);
    }
}
