use std::env;
use std::fs;
use std::path::PathBuf;

use crate::error::{Result, StsError};

/// Alibaba Cloud AccessKey credential.
///
/// The `Debug` implementation redacts `access_key_secret` to prevent
/// accidental leakage in logs.
#[derive(Clone)]
pub struct Credential {
    pub access_key_id: String,
    pub access_key_secret: String,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"****")
            .finish()
    }
}

/// Resolves a [`Credential`] from a specific source.
pub trait CredentialProvider {
    /// Attempt to resolve a credential from this provider.
    fn resolve(&self) -> Result<Credential>;
}

/// Provides a credential from explicitly specified values.
pub struct StaticProvider {
    credential: Credential,
}

impl StaticProvider {
    pub fn new(access_key_id: impl Into<String>, access_key_secret: impl Into<String>) -> Self {
        Self {
            credential: Credential {
                access_key_id: access_key_id.into(),
                access_key_secret: access_key_secret.into(),
            },
        }
    }
}

impl CredentialProvider for StaticProvider {
    fn resolve(&self) -> Result<Credential> {
        Ok(self.credential.clone())
    }
}

/// Provides a credential from environment variables.
///
/// Reads `ALIBABA_CLOUD_ACCESS_KEY_ID` and `ALIBABA_CLOUD_ACCESS_KEY_SECRET`.
pub struct EnvProvider;

impl CredentialProvider for EnvProvider {
    fn resolve(&self) -> Result<Credential> {
        let id = env::var("ALIBABA_CLOUD_ACCESS_KEY_ID")
            .map_err(|_| StsError::Credential("ALIBABA_CLOUD_ACCESS_KEY_ID not set".into()))?;
        let secret = env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
            .map_err(|_| StsError::Credential("ALIBABA_CLOUD_ACCESS_KEY_SECRET not set".into()))?;

        if id.is_empty() || secret.is_empty() {
            return Err(StsError::Credential(
                "ALIBABA_CLOUD_ACCESS_KEY_ID or ALIBABA_CLOUD_ACCESS_KEY_SECRET is empty".into(),
            ));
        }

        Ok(Credential {
            access_key_id: id,
            access_key_secret: secret,
        })
    }
}

/// Provides a credential from the Alibaba Cloud credentials profile file.
///
/// Reads `~/.alibabacloud/credentials` in INI format. The default profile
/// name is `default`.
pub struct ProfileProvider {
    profile_name: String,
    file_path: Option<PathBuf>,
}

impl Default for ProfileProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileProvider {
    /// Creates a provider that reads the `default` profile.
    pub fn new() -> Self {
        Self {
            profile_name: "default".to_string(),
            file_path: None,
        }
    }

    /// Specifies a custom profile name.
    pub fn with_profile(mut self, name: impl Into<String>) -> Self {
        self.profile_name = name.into();
        self
    }

    /// Specifies a custom file path instead of the default location.
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    fn default_path() -> Result<PathBuf> {
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .map_err(|_| StsError::Config("cannot determine home directory".into()))?;
        Ok(PathBuf::from(home)
            .join(".alibabacloud")
            .join("credentials"))
    }

    fn parse_ini(content: &str, profile: &str) -> Result<Credential> {
        let section_header = format!("[{}]", profile);
        let mut in_section = false;
        let mut access_key_id = None;
        let mut access_key_secret = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_section = line == section_header;
                continue;
            }
            if !in_section || line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();
                match key {
                    "access_key_id" => access_key_id = Some(value.to_string()),
                    "access_key_secret" => access_key_secret = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        match (access_key_id, access_key_secret) {
            (Some(id), Some(secret)) => Ok(Credential {
                access_key_id: id,
                access_key_secret: secret,
            }),
            _ => Err(StsError::Config(format!(
                "profile '{}' missing access_key_id or access_key_secret",
                profile
            ))),
        }
    }
}

impl CredentialProvider for ProfileProvider {
    fn resolve(&self) -> Result<Credential> {
        let path = match &self.file_path {
            Some(p) => p.clone(),
            None => Self::default_path()?,
        };
        let content = fs::read_to_string(&path).map_err(|e| {
            StsError::Config(format!(
                "cannot read credentials file {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::parse_ini(&content, &self.profile_name)
    }
}

/// Tries multiple credential providers in order and returns the first success.
pub struct ChainProvider {
    providers: Vec<Box<dyn CredentialProvider>>,
}

impl ChainProvider {
    /// Creates a chain with the given providers.
    pub fn new(providers: Vec<Box<dyn CredentialProvider>>) -> Self {
        Self { providers }
    }

    /// Creates the default credential chain: Env → Profile.
    pub fn default_chain() -> Self {
        Self {
            providers: vec![Box::new(EnvProvider), Box::new(ProfileProvider::new())],
        }
    }
}

impl CredentialProvider for ChainProvider {
    fn resolve(&self) -> Result<Credential> {
        let mut last_err = StsError::Credential("no credential providers configured".into());
        for provider in &self.providers {
            match provider.resolve() {
                Ok(cred) => return Ok(cred),
                Err(e) => last_err = e,
            }
        }
        Err(StsError::Credential(format!(
            "all credential providers failed, last error: {}",
            last_err
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_provider_returns_credential() {
        let provider = StaticProvider::new("test-id", "test-secret");
        let cred = provider.resolve().unwrap();
        assert_eq!(cred.access_key_id, "test-id");
        assert_eq!(cred.access_key_secret, "test-secret");
    }

    #[test]
    fn credential_debug_redacts_secret() {
        let cred = Credential {
            access_key_id: "LTAI5tXXXX".to_string(),
            access_key_secret: "super-secret-value".to_string(),
        };
        let debug = format!("{:?}", cred);
        assert!(debug.contains("LTAI5tXXXX"));
        assert!(debug.contains("****"));
        assert!(!debug.contains("super-secret-value"));
    }

    #[test]
    fn env_provider_missing_vars() {
        let saved_id = env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").ok();
        let saved_secret = env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok();
        unsafe {
            env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        }

        let result = EnvProvider.resolve();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("ALIBABA_CLOUD_ACCESS_KEY_ID"));

        unsafe {
            if let Some(v) = saved_id {
                env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", v);
            }
            if let Some(v) = saved_secret {
                env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", v);
            }
        }
    }

    #[test]
    fn parse_ini_default_profile() {
        let ini = r#"
[default]
access_key_id = LTAI5tExample
access_key_secret = ExampleSecret123

[other]
access_key_id = other-id
access_key_secret = other-secret
"#;
        let cred = ProfileProvider::parse_ini(ini, "default").unwrap();
        assert_eq!(cred.access_key_id, "LTAI5tExample");
        assert_eq!(cred.access_key_secret, "ExampleSecret123");
    }

    #[test]
    fn parse_ini_named_profile() {
        let ini = r#"
[default]
access_key_id = default-id
access_key_secret = default-secret

[staging]
access_key_id = staging-id
access_key_secret = staging-secret
"#;
        let cred = ProfileProvider::parse_ini(ini, "staging").unwrap();
        assert_eq!(cred.access_key_id, "staging-id");
        assert_eq!(cred.access_key_secret, "staging-secret");
    }

    #[test]
    fn parse_ini_missing_profile() {
        let ini = "[default]\naccess_key_id = id\naccess_key_secret = secret\n";
        let result = ProfileProvider::parse_ini(ini, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn parse_ini_with_comments() {
        let ini = r#"
[default]
# This is a comment
access_key_id = my-id
access_key_secret = my-secret
"#;
        let cred = ProfileProvider::parse_ini(ini, "default").unwrap();
        assert_eq!(cred.access_key_id, "my-id");
    }

    #[test]
    fn chain_provider_returns_first_success() {
        let chain = ChainProvider::new(vec![Box::new(StaticProvider::new(
            "chain-id",
            "chain-secret",
        ))]);
        let cred = chain.resolve().unwrap();
        assert_eq!(cred.access_key_id, "chain-id");
    }

    #[test]
    fn chain_provider_all_fail() {
        let saved_id = env::var("ALIBABA_CLOUD_ACCESS_KEY_ID").ok();
        let saved_secret = env::var("ALIBABA_CLOUD_ACCESS_KEY_SECRET").ok();
        unsafe {
            env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_ID");
            env::remove_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET");
        }

        let chain = ChainProvider::new(vec![Box::new(EnvProvider)]);
        let result = chain.resolve();
        assert!(result.is_err());

        unsafe {
            if let Some(v) = saved_id {
                env::set_var("ALIBABA_CLOUD_ACCESS_KEY_ID", v);
            }
            if let Some(v) = saved_secret {
                env::set_var("ALIBABA_CLOUD_ACCESS_KEY_SECRET", v);
            }
        }
    }
}
