# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-02-12

### Added

- Add `try_build()` method to all request builders for fallible construction
- Add detailed module documentation for `blocking` client with usage guidelines
- Add SAFETY comments for `unsafe` blocks in `percent_encode` function
- Add Build Status badge to README

### Changed

- Replace `unwrap()` with `expect()` in time handling code with clear error messages
- Improve README documentation with Builder pattern examples
- Enhance `lib.rs` documentation with features, error handling, and security sections
- Add conditional compilation for `V1_0` signature tests

### Fixed

- Fix documentation reference to non-existent `ClientConfig::builder()` method

### Security

- Credentials are automatically redacted in `Debug` output
- File permission warnings for insecure credential files (Unix)
- Default to HMAC-SHA256 signature algorithm

## [0.1.0] - 2026-02-07

### Added

- Initial release
- Async and blocking clients for Alibaba Cloud STS API
- Support for 4 API operations:
  - `AssumeRole` - Assume a RAM role
  - `AssumeRoleWithSAML` - SAML-based SSO
  - `AssumeRoleWithOIDC` - OIDC-based SSO
  - `GetCallerIdentity` - Query caller identity
- Builder pattern for request construction
- Credential chain: Environment variables → Profile file
- Clock skew correction with exponential smoothing
- Concurrent request limiting with semaphore (async client)
- Connection pool configuration
- Comprehensive error handling with `StsError` enum
