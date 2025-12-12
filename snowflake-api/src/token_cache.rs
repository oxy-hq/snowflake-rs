use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenCacheError {
    #[error("Failed to access cache directory: {0}")]
    CacheDirectoryError(String),

    #[error("Failed to read cache file: {0}")]
    ReadError(String),

    #[error("Failed to write cache file: {0}")]
    WriteError(String),

    #[error("Failed to deserialize cache: {0}")]
    DeserializeError(String),

    #[error("Failed to serialize cache: {0}")]
    SerializeError(String),

    #[error("Failed to set file permissions: {0}")]
    PermissionsError(String),
}

/// Represents a cached authentication token with expiration information
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CachedToken {
    pub token: String,
    /// Unix timestamp (seconds since epoch) when the token was issued
    pub issued_at: u64,
    /// Validity duration in seconds
    pub valid_for_seconds: u64,
}

impl CachedToken {
    pub fn new(token: &str, valid_for_seconds: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token: token.to_string(),
            issued_at: now,
            valid_for_seconds: if valid_for_seconds < 0 {
                u64::MAX
            } else {
                valid_for_seconds as u64
            },
        }
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let elapsed = now.saturating_sub(self.issued_at);
        elapsed >= self.valid_for_seconds
    }

    /// Check if the token is expiring soon (within 5 minutes)
    pub fn is_expiring_soon(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let elapsed = now.saturating_sub(self.issued_at);
        let remaining = self.valid_for_seconds.saturating_sub(elapsed);

        // Consider token expiring soon if less than 5 minutes remaining
        remaining < 300
    }
}

/// Cache entry for Snowflake authentication tokens
#[derive(Serialize, Deserialize, Debug)]
pub struct TokenCacheEntry {
    pub session_token: CachedToken,
    pub master_token: CachedToken,
}

/// Manages token caching to filesystem
pub struct TokenCache {
    cache_dir: PathBuf,
}

impl TokenCache {
    /// Create a new TokenCache with default directory (~/.cache/snowflake or ~/.snowflake)
    pub fn new() -> Result<Self, TokenCacheError> {
        let cache_dir = Self::default_cache_dir()?;
        Ok(Self { cache_dir })
    }

    /// Create a TokenCache with a custom directory
    pub fn with_directory<P: AsRef<Path>>(dir: P) -> Result<Self, TokenCacheError> {
        let cache_dir = dir.as_ref().to_path_buf();
        Ok(Self { cache_dir })
    }

    /// Get the default cache directory
    /// Uses SF_TEMPORARY_CREDENTIAL_CACHE_DIR env var if set,
    /// otherwise ~/.cache/snowflake on Linux/macOS, %APPDATA%\Snowflake on Windows
    fn default_cache_dir() -> Result<PathBuf, TokenCacheError> {
        // Check environment variable first
        if let Ok(env_dir) = std::env::var("SF_TEMPORARY_CREDENTIAL_CACHE_DIR") {
            return Ok(PathBuf::from(env_dir));
        }

        // Use platform-specific default
        let home = dirs::home_dir().ok_or_else(|| {
            TokenCacheError::CacheDirectoryError("Could not determine home directory".to_string())
        })?;

        #[cfg(target_os = "windows")]
        let cache_dir = home.join("AppData").join("Roaming").join("Snowflake");

        #[cfg(not(target_os = "windows"))]
        let cache_dir = home.join(".cache").join("snowflake");

        Ok(cache_dir)
    }

    /// Generate a cache key based on account and username
    fn cache_key(&self, account: &str, username: &str) -> String {
        // Use a simple hash of account+username for the filename
        // This matches the pattern used by other connectors
        format!(
            "{}_{}.json",
            account.to_lowercase(),
            username.to_lowercase()
        )
    }

    /// Get the full path to the cache file for a given account/username
    fn cache_file_path(&self, account: &str, username: &str) -> PathBuf {
        self.cache_dir.join(self.cache_key(account, username))
    }

    /// Ensure the cache directory exists with proper permissions
    fn ensure_cache_dir(&self) -> Result<(), TokenCacheError> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir)
                .map_err(|e| TokenCacheError::CacheDirectoryError(e.to_string()))?;
        }

        // Set directory permissions to 0700 (owner rwx only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&self.cache_dir, perms)
                .map_err(|e| TokenCacheError::PermissionsError(e.to_string()))?;
        }

        Ok(())
    }

    /// Set file permissions to owner-only read/write (0600 on Unix)
    #[cfg(unix)]
    fn set_secure_permissions<P: AsRef<Path>>(&self, path: P) -> Result<(), TokenCacheError> {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| TokenCacheError::PermissionsError(e.to_string()))
    }

    #[cfg(not(unix))]
    fn set_secure_permissions<P: AsRef<Path>>(&self, _path: P) -> Result<(), TokenCacheError> {
        // On Windows, the file inherits ACLs from parent directory
        // Consider using Windows ACL APIs for stricter control
        Ok(())
    }

    /// Load cached tokens for a given account/username
    pub fn load(
        &self,
        account: &str,
        username: &str,
    ) -> Result<Option<TokenCacheEntry>, TokenCacheError> {
        let cache_file = self.cache_file_path(account, username);

        if !cache_file.exists() {
            return Ok(None);
        }

        // Read the file
        let mut file =
            File::open(&cache_file).map_err(|e| TokenCacheError::ReadError(e.to_string()))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| TokenCacheError::ReadError(e.to_string()))?;

        // Deserialize
        let entry: TokenCacheEntry = serde_json::from_str(&contents)
            .map_err(|e| TokenCacheError::DeserializeError(e.to_string()))?;

        // Check if tokens are expired
        if entry.master_token.is_expired() || entry.session_token.is_expired() {
            log::debug!("Cached tokens are expired, removing cache file");
            // Remove expired cache
            let _ = fs::remove_file(&cache_file);
            return Ok(None);
        }

        log::info!(
            "Loaded valid tokens from cache for {}@{}",
            username,
            account
        );
        Ok(Some(entry))
    }

    /// Save tokens to cache for a given account/username
    pub fn save(
        &self,
        account: &str,
        username: &str,
        entry: &TokenCacheEntry,
    ) -> Result<(), TokenCacheError> {
        // Ensure directory exists
        self.ensure_cache_dir()?;

        let cache_file = self.cache_file_path(account, username);

        // Serialize to JSON
        let contents = serde_json::to_string_pretty(entry)
            .map_err(|e| TokenCacheError::SerializeError(e.to_string()))?;

        // Write to file
        let mut file =
            File::create(&cache_file).map_err(|e| TokenCacheError::WriteError(e.to_string()))?;

        file.write_all(contents.as_bytes())
            .map_err(|e| TokenCacheError::WriteError(e.to_string()))?;

        // Set secure permissions
        self.set_secure_permissions(&cache_file)?;

        log::info!("Saved tokens to cache for {}@{}", username, account);
        Ok(())
    }

    /// Remove cached tokens for a given account/username
    pub fn remove(&self, account: &str, username: &str) -> Result<(), TokenCacheError> {
        let cache_file = self.cache_file_path(account, username);

        if cache_file.exists() {
            fs::remove_file(&cache_file).map_err(|e| TokenCacheError::WriteError(e.to_string()))?;
            log::debug!("Removed cached tokens for {}@{}", username, account);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_cached_token_expiry() {
        // Create a token that expires in 10 seconds
        let token = CachedToken::new("test_token", 10);
        assert!(!token.is_expired());

        // Create an already expired token
        let mut expired_token = CachedToken::new("test_token", 10);
        expired_token.issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 20; // 20 seconds ago
        assert!(expired_token.is_expired());
    }

    #[test]
    fn test_cache_key_generation() {
        let temp_dir = env::temp_dir().join("snowflake_test_cache");
        let cache = TokenCache::with_directory(&temp_dir).unwrap();

        let key = cache.cache_key("MY_ACCOUNT", "MY_USER");
        assert_eq!(key, "my_account_my_user.json");
    }
}
