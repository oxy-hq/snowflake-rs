use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::lock::Mutex;
#[cfg(feature = "cert-auth")]
use snowflake_jwt::generate_jwt_token;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Callback type for receiving the SSO URL during external browser authentication.
/// The callback receives the SSO URL as a String parameter.
pub type SsoUrlCallback = Arc<dyn Fn(String) + Send + Sync>;

use crate::connection;
use crate::connection::{Connection, QueryType};
use crate::requests::{
    AuthenticatorRequest, AuthenticatorRequestData, ClientEnvironment, ExternalBrowserLoginRequest,
    ExternalBrowserRequestData, LoginRequest, LoginRequestCommon, PasswordLoginRequest,
    PasswordRequestData, RenewSessionRequest, SessionParameters,
};
#[cfg(feature = "cert-auth")]
use crate::requests::{CertLoginRequest, CertRequestData};
use crate::responses::AuthResponse;
use crate::token_cache::{CachedToken, TokenCache, TokenCacheEntry, TokenCacheError};

#[derive(Error, Debug)]
pub enum AuthError {
    #[error(transparent)]
    #[cfg(feature = "cert-auth")]
    JwtError(#[from] snowflake_jwt::JwtError),

    #[error(transparent)]
    RequestError(#[from] connection::ConnectionError),

    #[error("Environment variable `{0}` is required, but were not set")]
    MissingEnvArgument(String),

    #[error("Password auth was requested, but password wasn't provided")]
    MissingPassword,

    #[error("Certificate auth was requested, but certificate wasn't provided")]
    MissingCertificate,

    #[error("Unexpected API response")]
    UnexpectedResponse,

    // todo: add code mapping to meaningful message and/or refer to docs
    //   eg https://docs.snowflake.com/en/user-guide/key-pair-auth-troubleshooting
    #[error("Failed to authenticate. Error code: {0}. Message: {1}")]
    AuthFailed(String, String),

    #[error("Can not renew closed session token")]
    OutOfOrderRenew,

    #[error("Failed to exchange or request a new token")]
    TokenFetchFailed,

    #[error("Enable the cert-auth feature to use certificate authentication")]
    CertAuthNotEnabled,

    #[error("Browser authentication timed out")]
    BrowserAuthTimeout,

    #[error("Failed to request SSO URL from Snowflake")]
    SsoUrlCallbackError,

    #[error("Failed to start local server: {0}")]
    LocalServerError(String),

    #[error("Failed to open browser: {0}")]
    BrowserOpenError(String),

    #[error("Token cache error: {0}")]
    TokenCacheError(#[from] TokenCacheError),
}

#[derive(Debug)]
struct AuthTokens {
    session_token: AuthToken,
    master_token: AuthToken,
    /// expected by snowflake api for all requests within session to follow sequence id
    sequence_id: u64,
}

impl AuthTokens {
    /// Convert to a cache entry for filesystem storage
    fn to_cache_entry(&self) -> TokenCacheEntry {
        TokenCacheEntry {
            session_token: self.session_token.to_cached_token(),
            master_token: self.master_token.to_cached_token(),
        }
    }

    /// Create from a cache entry
    fn from_cache_entry(entry: TokenCacheEntry) -> Self {
        Self {
            session_token: AuthToken::from_cached_token(entry.session_token),
            master_token: AuthToken::from_cached_token(entry.master_token),
            sequence_id: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthToken {
    token: String,
    valid_for: Duration,
    issued_on: Instant,
}

#[derive(Debug, Clone)]
pub struct AuthParts {
    pub session_token_auth_header: String,
    pub sequence_id: u64,
}

impl AuthToken {
    pub fn new(token: &str, validity_in_seconds: i64) -> Self {
        let token = token.to_string();

        let valid_for = if validity_in_seconds < 0 {
            Duration::from_secs(u64::MAX)
        } else {
            // Note for reviewer: I beliebe this only fails on negative numbers. I imagine we will
            // never get negative numbers, but if we do, is MAX or 0 a more sane default?
            Duration::from_secs(u64::try_from(validity_in_seconds).unwrap_or(u64::MAX))
        };
        let issued_on = Instant::now();

        Self {
            token,
            valid_for,
            issued_on,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.issued_on) >= self.valid_for
    }

    pub fn auth_header(&self) -> String {
        format!("Snowflake Token=\"{}\"", &self.token)
    }

    /// Convert to a cached token for filesystem storage
    fn to_cached_token(&self) -> CachedToken {
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.issued_on.elapsed().as_secs());

        CachedToken {
            token: self.token.clone(),
            issued_at,
            valid_for_seconds: self.valid_for.as_secs(),
        }
    }

    /// Create from a cached token
    fn from_cached_token(cached: CachedToken) -> Self {
        let now_system = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let elapsed = now_system.saturating_sub(cached.issued_at);
        let elapsed_duration = Duration::from_secs(elapsed);

        Self {
            token: cached.token,
            valid_for: Duration::from_secs(cached.valid_for_seconds),
            // Reconstruct the issued_on time by subtracting elapsed time from now
            issued_on: Instant::now()
                .checked_sub(elapsed_duration)
                .unwrap_or_else(Instant::now),
        }
    }
}

enum AuthType {
    Certificate,
    Password,
    ExternalBrowser,
}

/// Requests, caches, and renews authentication tokens.
/// Tokens are given as response to creating new session in Snowflake. Session persists
/// the configuration state and temporary objects (tables, procedures, etc).
// todo: split warehouse-database-schema and username-role-key into its own structs
// todo: close session after object is dropped
pub struct Session {
    connection: Arc<Connection>,

    auth_tokens: Mutex<Option<AuthTokens>>,
    auth_type: AuthType,
    account_identifier: String,

    warehouse: Option<String>,
    database: Option<String>,
    schema: Option<String>,

    username: String,
    role: Option<String>,
    // This is not used with the certificate auth crate
    #[allow(dead_code)]
    private_key_pem: Option<String>,
    password: Option<String>,

    /// Timeout for external browser authentication (in seconds)
    /// Default: 300 seconds (5 minutes)
    browser_auth_timeout_secs: u64,

    /// Enable filesystem token caching for external browser authentication
    /// Default: false (disabled for security)
    /// When enabled, tokens are cached in ~/.cache/snowflake/ (or SF_TEMPORARY_CREDENTIAL_CACHE_DIR)
    enable_token_cache: bool,

    /// Custom directory for token cache (if None, uses default)
    cache_directory: Option<PathBuf>,

    /// Token cache instance (created on-demand)
    token_cache: Option<TokenCache>,

    /// Optional callback to receive the SSO URL during external browser authentication
    sso_url_callback: Option<SsoUrlCallback>,
}

// todo: make builder
impl Session {
    /// Authenticate using private certificate and JWT
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn cert_auth(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        private_key_pem: &str,
    ) -> Self {
        // uppercase everything as this is the convention
        let account_identifier = account_identifier.to_uppercase();

        let database = database.map(str::to_uppercase);
        let schema = schema.map(str::to_uppercase);

        let username = username.to_uppercase();
        let role = role.map(str::to_uppercase);
        let private_key_pem = Some(private_key_pem.to_string());

        Self {
            connection,
            auth_tokens: Mutex::new(None),
            auth_type: AuthType::Certificate,
            private_key_pem,
            account_identifier,
            warehouse: warehouse.map(str::to_uppercase),
            database,
            username,
            role,
            schema,
            password: None,
            browser_auth_timeout_secs: 300,
            enable_token_cache: false,
            cache_directory: None,
            token_cache: None,
            sso_url_callback: None,
        }
    }

    /// Authenticate using password
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn password_auth(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        password: &str,
    ) -> Self {
        let account_identifier = account_identifier.to_uppercase();

        let database = database.map(str::to_uppercase);
        let schema = schema.map(str::to_uppercase);

        let username = username.to_uppercase();
        let password = Some(password.to_string());
        let role = role.map(str::to_uppercase);

        Self {
            connection,
            auth_tokens: Mutex::new(None),
            auth_type: AuthType::Password,
            account_identifier,
            warehouse: warehouse.map(str::to_uppercase),
            database,
            username,
            role,
            password,
            schema,
            private_key_pem: None,
            browser_auth_timeout_secs: 300,
            enable_token_cache: false,
            cache_directory: None,
            token_cache: None,
            sso_url_callback: None,
        }
    }

    /// Authenticate using external browser (SSO)
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn externalbrowser_auth(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
    ) -> Self {
        Self::externalbrowser_auth_with_timeout(
            connection,
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            300,
        )
    }

    /// Authenticate using external browser (SSO) with custom timeout and optional token caching
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn externalbrowser_auth_with_timeout(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        browser_auth_timeout_secs: u64,
    ) -> Self {
        Self::externalbrowser_auth_with_options(
            connection,
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            browser_auth_timeout_secs,
            false,
        )
    }

    /// Authenticate using external browser (SSO) with full options
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn externalbrowser_auth_with_options(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        browser_auth_timeout_secs: u64,
        enable_token_cache: bool,
    ) -> Self {
        Self::externalbrowser_auth_full(
            connection,
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            browser_auth_timeout_secs,
            enable_token_cache,
            None,
            None,
        )
    }

    /// Authenticate using external browser (SSO) with full options including custom cache directory
    // fixme: add builder or introduce structs
    #[allow(clippy::too_many_arguments)]
    pub fn externalbrowser_auth_full(
        connection: Arc<Connection>,
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        browser_auth_timeout_secs: u64,
        enable_token_cache: bool,
        cache_directory: Option<PathBuf>,
        sso_url_callback: Option<SsoUrlCallback>,
    ) -> Self {
        let account_identifier = account_identifier.to_uppercase();

        let database = database.map(str::to_uppercase);
        let schema = schema.map(str::to_uppercase);

        let username = username.to_uppercase();
        let role = role.map(str::to_uppercase);

        // Create token cache if enabled
        let token_cache = if enable_token_cache {
            let cache_result = if let Some(ref dir) = cache_directory {
                TokenCache::with_directory(dir)
            } else {
                TokenCache::new()
            };

            match cache_result {
                Ok(cache) => {
                    log::info!("Token caching enabled");
                    Some(cache)
                }
                Err(e) => {
                    log::warn!("Failed to create token cache, caching disabled: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            connection,
            auth_tokens: Mutex::new(None),
            auth_type: AuthType::ExternalBrowser,
            account_identifier,
            warehouse: warehouse.map(str::to_uppercase),
            database,
            username,
            role,
            password: None,
            schema,
            private_key_pem: None,
            browser_auth_timeout_secs,
            enable_token_cache,
            cache_directory,
            token_cache,
            sso_url_callback,
        }
    }

    /// Clear cached tokens from filesystem
    fn clear_token_cache(&self) {
        if let Some(ref cache) = self.token_cache {
            if let Err(e) = cache.remove(&self.account_identifier, &self.username) {
                log::warn!("Failed to remove cached tokens: {}", e);
            } else {
                log::debug!("Cleared cached tokens due to invalidation");
            }
        }
    }

    /// Invalidate cached tokens. Call this if authentication fails with cached tokens.
    /// This removes the cached tokens from the filesystem and clears in-memory tokens.
    pub async fn invalidate_cache(&mut self) {
        log::info!("Invalidating cached tokens");
        self.clear_token_cache();
        *self.auth_tokens.lock().await = None;
    }

    /// Explicitly trigger authentication flow.
    /// This is useful for pre-configuring authentication in settings pages or verifying credentials
    /// before executing queries. For external browser auth, this will open the browser immediately.
    ///
    /// # Returns
    /// - `Ok(())` if authentication succeeded
    /// - `Err(AuthError)` if authentication failed
    ///
    /// # Example
    /// ```no_run
    /// use snowflake_api::{SnowflakeApi, AuthArgs, AuthType, SnowflakeApiBuilder};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = AuthArgs {
    ///     account_identifier: "account".to_string(),
    ///     username: "user".to_string(),
    ///     auth_type: AuthType::ExternalBrowser,
    ///     warehouse: None,
    ///     database: None,
    ///     schema: None,
    ///     role: None,
    /// };
    ///
    /// let mut api = SnowflakeApiBuilder::new(auth)
    ///     .with_token_cache(true)
    ///     .build()?;
    ///
    /// // Trigger authentication immediately (e.g., in settings page)
    /// api.authenticate().await?;
    ///
    /// // Now authenticated and ready to execute queries
    /// let result = api.exec("SELECT 1").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authenticate(&self) -> Result<(), AuthError> {
        // Trigger get_token which will handle authentication if needed
        self.get_token().await?;
        log::info!("Authentication completed successfully");
        Ok(())
    }

    /// Get cached token or request a new one if old one has expired.
    pub async fn get_token(&self) -> Result<AuthParts, AuthError> {
        let mut auth_tokens = self.auth_tokens.lock().await;
        if auth_tokens.is_none()
            || auth_tokens
                .as_ref()
                .is_some_and(|at| at.master_token.is_expired())
        {
            // Try to load from filesystem cache first (only for external browser auth)
            let mut tokens_loaded_from_cache = false;
            if matches!(self.auth_type, AuthType::ExternalBrowser) && self.token_cache.is_some() {
                if let Some(ref cache) = self.token_cache {
                    match cache.load(&self.account_identifier, &self.username) {
                        Ok(Some(entry)) => {
                            log::info!("Loaded valid tokens from filesystem cache");
                            *auth_tokens = Some(AuthTokens::from_cache_entry(entry));
                            tokens_loaded_from_cache = true;
                        }
                        Ok(None) => {
                            log::debug!("No cached tokens found in filesystem");
                        }
                        Err(e) => {
                            log::warn!("Failed to load tokens from cache: {}", e);
                        }
                    }
                }
            }

            // If we didn't load from cache, create new session
            if !tokens_loaded_from_cache {
                let tokens = match self.auth_type {
                    AuthType::Certificate => {
                        log::info!("Starting session with certificate authentication");
                        if cfg!(feature = "cert-auth") {
                            self.create(self.cert_request_body()?).await
                        } else {
                            Err(AuthError::MissingCertificate)?
                        }
                    }
                    AuthType::Password => {
                        log::info!("Starting session with password authentication");
                        self.create(self.passwd_request_body()?).await
                    }
                    AuthType::ExternalBrowser => {
                        log::info!("Starting session with external browser authentication");
                        self.authenticate_with_browser().await
                    }
                }?;

                // Save to cache if external browser auth and caching is enabled
                if matches!(self.auth_type, AuthType::ExternalBrowser) {
                    if let Some(ref cache) = self.token_cache {
                        let cache_entry = tokens.to_cache_entry();
                        if let Err(e) =
                            cache.save(&self.account_identifier, &self.username, &cache_entry)
                        {
                            log::warn!("Failed to save tokens to cache: {}", e);
                        }
                    }
                }

                *auth_tokens = Some(tokens);
            }
        } else if auth_tokens
            .as_ref()
            .is_some_and(|at| at.session_token.is_expired())
        {
            // Renew old session token
            let old_token = auth_tokens.take().unwrap();

            match self.renew(old_token).await {
                Ok(tokens) => {
                    // Update cache after renewal if external browser auth and caching is enabled
                    if matches!(self.auth_type, AuthType::ExternalBrowser) {
                        if let Some(ref cache) = self.token_cache {
                            let cache_entry = tokens.to_cache_entry();
                            if let Err(e) =
                                cache.save(&self.account_identifier, &self.username, &cache_entry)
                            {
                                log::warn!("Failed to update cached tokens: {}", e);
                            }
                        }
                    }
                    *auth_tokens = Some(tokens);
                }
                Err(e) => {
                    // If renewal failed, the cached token might be invalid (revoked, corrupted, etc.)
                    // For external browser auth, clear the cache and re-trigger authentication
                    if matches!(self.auth_type, AuthType::ExternalBrowser) {
                        log::warn!(
                            "Token renewal failed ({}), clearing cache and re-authenticating",
                            e
                        );
                        self.clear_token_cache();

                        // Re-trigger browser authentication
                        match self.authenticate_with_browser().await {
                            Ok(new_tokens) => {
                                // Save new tokens to cache
                                if let Some(ref cache) = self.token_cache {
                                    let cache_entry = new_tokens.to_cache_entry();
                                    if let Err(cache_err) = cache.save(
                                        &self.account_identifier,
                                        &self.username,
                                        &cache_entry,
                                    ) {
                                        log::warn!(
                                            "Failed to save new tokens to cache: {}",
                                            cache_err
                                        );
                                    }
                                }
                                *auth_tokens = Some(new_tokens);
                            }
                            Err(auth_err) => {
                                log::error!("Re-authentication failed: {}", auth_err);
                                return Err(auth_err);
                            }
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        auth_tokens.as_mut().unwrap().sequence_id += 1;
        Ok(AuthParts {
            session_token_auth_header: auth_tokens.as_ref().unwrap().session_token.auth_header(),
            sequence_id: auth_tokens.as_ref().unwrap().sequence_id,
        })
    }

    pub async fn close(&mut self) -> Result<(), AuthError> {
        if let Some(tokens) = self.auth_tokens.lock().await.take() {
            log::debug!("Closing sessions");

            // Remove cached tokens when closing session
            if let Some(ref cache) = self.token_cache {
                if let Err(e) = cache.remove(&self.account_identifier, &self.username) {
                    log::warn!("Failed to remove cached tokens: {}", e);
                }
            }

            let resp = self
                .connection
                .request::<AuthResponse>(
                    QueryType::CloseSession,
                    &self.account_identifier,
                    &[("delete", "true")],
                    Some(&tokens.session_token.auth_header()),
                    serde_json::Value::default(),
                )
                .await?;

            match resp {
                AuthResponse::Close(_) => Ok(()),
                AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                    e.code.unwrap_or_default(),
                    e.message.unwrap_or_default(),
                )),
                _ => Err(AuthError::UnexpectedResponse),
            }
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "cert-auth")]
    fn cert_request_body(&self) -> Result<CertLoginRequest, AuthError> {
        let full_identifier = format!("{}.{}", &self.account_identifier, &self.username);
        let private_key_pem = self
            .private_key_pem
            .as_ref()
            .ok_or(AuthError::MissingCertificate)?;
        let jwt_token = generate_jwt_token(private_key_pem, &full_identifier)?;

        Ok(CertLoginRequest {
            data: CertRequestData {
                login_request_common: self.login_request_common(),
                authenticator: "SNOWFLAKE_JWT".to_string(),
                token: jwt_token,
            },
        })
    }

    fn passwd_request_body(&self) -> Result<PasswordLoginRequest, AuthError> {
        let password = self.password.as_ref().ok_or(AuthError::MissingPassword)?;

        Ok(PasswordLoginRequest {
            data: PasswordRequestData {
                login_request_common: self.login_request_common(),
                password: password.to_string(),
            },
        })
    }

    /// Start new session, all the Snowflake temporary objects will be scoped towards it,
    /// as well as temporary configuration parameters
    async fn create<T: serde::ser::Serialize>(
        &self,
        body: LoginRequest<T>,
    ) -> Result<AuthTokens, AuthError> {
        let mut get_params = Vec::new();
        if let Some(warehouse) = &self.warehouse {
            get_params.push(("warehouse", warehouse.as_str()));
        }

        if let Some(database) = &self.database {
            get_params.push(("databaseName", database.as_str()));
        }

        if let Some(schema) = &self.schema {
            get_params.push(("schemaName", schema.as_str()));
        }

        if let Some(role) = &self.role {
            get_params.push(("roleName", role.as_str()));
        }

        let resp = self
            .connection
            .request::<AuthResponse>(
                QueryType::LoginRequest,
                &self.account_identifier,
                &get_params,
                None,
                body,
            )
            .await?;
        log::debug!("Auth response: {:?}", resp);

        match resp {
            AuthResponse::Login(lr) => {
                let session_token = AuthToken::new(&lr.data.token, lr.data.validity_in_seconds);
                let master_token =
                    AuthToken::new(&lr.data.master_token, lr.data.master_validity_in_seconds);

                Ok(AuthTokens {
                    session_token,
                    master_token,
                    sequence_id: 0,
                })
            }
            AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                e.code.unwrap_or_default(),
                e.message.unwrap_or_default(),
            )),
            _ => Err(AuthError::UnexpectedResponse),
        }
    }

    fn login_request_common(&self) -> LoginRequestCommon {
        LoginRequestCommon {
            client_app_id: "Go".to_string(),
            client_app_version: "1.6.22".to_string(),
            svn_revision: String::new(),
            account_name: self.account_identifier.clone(),
            login_name: self.username.clone(),
            session_parameters: SessionParameters {
                client_validate_default_parameters: true,
            },
            client_environment: ClientEnvironment {
                application: "Rust".to_string(),
                // todo: detect os
                os: "darwin".to_string(),
                os_version: "gc-arm64".to_string(),
                ocsp_mode: "FAIL_OPEN".to_string(),
            },
        }
    }

    async fn renew(&self, token: AuthTokens) -> Result<AuthTokens, AuthError> {
        log::debug!("Renewing the token");
        let auth = token.master_token.auth_header();
        let body = RenewSessionRequest {
            old_session_token: token.session_token.token.clone(),
            request_type: "RENEW".to_string(),
        };

        let resp = self
            .connection
            .request(
                QueryType::TokenRequest,
                &self.account_identifier,
                &[],
                Some(&auth),
                body,
            )
            .await?;

        match resp {
            AuthResponse::Renew(rs) => {
                let session_token =
                    AuthToken::new(&rs.data.session_token, rs.data.validity_in_seconds_s_t);
                let master_token =
                    AuthToken::new(&rs.data.master_token, rs.data.validity_in_seconds_m_t);

                Ok(AuthTokens {
                    session_token,
                    master_token,
                    sequence_id: token.sequence_id,
                })
            }
            AuthResponse::Error(e) => Err(AuthError::AuthFailed(
                e.code.unwrap_or_default(),
                e.message.unwrap_or_default(),
            )),
            _ => Err(AuthError::UnexpectedResponse),
        }
    }

    /// Main external browser authentication flow
    async fn authenticate_with_browser(&self) -> Result<AuthTokens, AuthError> {
        // Start local HTTP server to receive the callback
        let (listener, port) = Self::start_callback_server().await?;
        log::info!("Local callback server started on port {}", port);

        // Get the SSO URL and proof key from Snowflake
        let (mut body, sso_url) = self.externalbrowser_request_body(port).await?;

        // Call the SSO URL callback if provided
        if let Some(ref callback) = self.sso_url_callback {
            log::debug!("Invoking SSO URL callback");
            callback(sso_url.clone());
        }

        // Open the browser with the SSO URL
        log::info!("Opening browser for authentication: {}", sso_url);
        webbrowser::open(&sso_url).map_err(|e| AuthError::BrowserOpenError(e.to_string()))?;

        // Wait for the browser to redirect back with the token
        let timeout = Duration::from_secs(self.browser_auth_timeout_secs);
        log::debug!(
            "Waiting for browser callback with timeout of {} seconds",
            self.browser_auth_timeout_secs
        );
        let token = Self::receive_saml_token(listener, timeout).await?;
        log::debug!("Received SAML token from browser callback");

        // Update the request body with the received token
        body.data.token = token.clone();
        log::debug!(
            "Completing authentication with token (length: {})",
            token.len()
        );

        // Complete the authentication with the token and proof key
        self.create(body).await
    }

    /// Start a local HTTP server to receive the SAML token callback
    /// Returns (listener, port number)
    async fn start_callback_server() -> Result<(TcpListener, u16), AuthError> {
        // Bind to a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

        let port = listener
            .local_addr()
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?
            .port();

        Ok((listener, port))
    }

    /// Wait for the browser callback with the SAML token
    async fn receive_saml_token(
        listener: TcpListener,
        timeout: Duration,
    ) -> Result<String, AuthError> {
        log::debug!(
            "Waiting for browser callback with timeout of {} seconds...",
            timeout.as_secs()
        );

        // Poll for incoming connection with timeout using tokio::select!
        let (mut stream, _) = tokio::select! {
            result = listener.accept() => {
                result.map_err(|e| AuthError::LocalServerError(e.to_string()))?
            },
            _ = tokio::time::sleep(timeout) => {
                log::warn!(
                    "Browser authentication timed out after {} seconds",
                    timeout.as_secs()
                );
                return Err(AuthError::BrowserAuthTimeout);
            }
        };

        log::debug!("Browser callback received");
        let buf_reader = tokio::io::BufReader::new(&mut stream);
        let request_line = buf_reader
            .lines()
            .next_line()
            .await
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?
            .ok_or_else(|| AuthError::LocalServerError("Empty request".to_string()))?;

        log::debug!("Received request: {}", request_line);

        // Parse the request line: GET /?token=... HTTP/1.1
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "GET" {
            return Err(AuthError::LocalServerError(
                "Invalid HTTP request".to_string(),
            ));
        }

        let path = parts[1];
        let token = if let Some(query_start) = path.find("?token=") {
            let token_start = query_start + 7; // length of "?token="
            let token_end = path[token_start..]
                .find('&')
                .map(|i| token_start + i)
                .unwrap_or(path.len());
            path[token_start..token_end].to_string()
        } else {
            return Err(AuthError::LocalServerError(
                "Token not found in callback".to_string(),
            ));
        };

        // Send success response to browser
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
            <html><body><h1>Authentication Successful</h1>\
            <p>You can close this window and return to your application.</p>\
            </body></html>";

        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

        Ok(token)
    }

    async fn externalbrowser_request_body(
        &self,
        port: u16,
    ) -> Result<(ExternalBrowserLoginRequest, String), AuthError> {
        // First, request the SSO URL from Snowflake using the simple authenticator-request format
        let auth_request = AuthenticatorRequest {
            data: AuthenticatorRequestData {
                authenticator: "EXTERNALBROWSER".to_string(),
                browser_mode_redirect_port: port.to_string(),
            },
        };

        // Make initial request to get SSO URL from /session/authenticator-request
        let auth_resp = self
            .connection
            .request::<crate::responses::AuthenticatorResponse>(
                QueryType::AuthenticatorRequest,
                &self.account_identifier,
                &[],
                None,
                &auth_request,
            )
            .await
            .map_err(|e| {
                log::error!("Failed to request SSO URL: {}", e);
                AuthError::SsoUrlCallbackError
            })?;

        log::debug!("Received SSO URL: {}", auth_resp.data.sso_url);
        log::debug!("Using proof key from server: {}", auth_resp.data.proof_key);

        if !auth_resp.success {
            return Err(AuthError::AuthFailed(
                auth_resp.code.unwrap_or_default(),
                auth_resp.message.unwrap_or_default(),
            ));
        }

        // Prepare the full login request body for the second step
        // Use the proof key returned by Snowflake, not a generated one
        let login_body = ExternalBrowserLoginRequest {
            data: ExternalBrowserRequestData {
                login_request_common: self.login_request_common(),
                authenticator: "EXTERNALBROWSER".to_string(),
                token: String::new(),
                proof_key: auth_resp.data.proof_key,
            },
        };

        Ok((login_body, auth_resp.data.sso_url))
    }
}
