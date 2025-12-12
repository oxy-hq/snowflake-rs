use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::lock::Mutex;
#[cfg(feature = "cert-auth")]
use snowflake_jwt::generate_jwt_token;
use thiserror::Error;

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

    #[error("Failed to start local server: {0}")]
    LocalServerError(String),

    #[error("Failed to open browser: {0}")]
    BrowserOpenError(String),
}

#[derive(Debug)]
struct AuthTokens {
    session_token: AuthToken,
    master_token: AuthToken,
    /// expected by snowflake api for all requests within session to follow sequence id
    sequence_id: u64,
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
        let account_identifier = account_identifier.to_uppercase();

        let database = database.map(str::to_uppercase);
        let schema = schema.map(str::to_uppercase);

        let username = username.to_uppercase();
        let role = role.map(str::to_uppercase);

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
        }
    }

    /// Get cached token or request a new one if old one has expired.
    pub async fn get_token(&self) -> Result<AuthParts, AuthError> {
        let mut auth_tokens = self.auth_tokens.lock().await;
        if auth_tokens.is_none()
            || auth_tokens
                .as_ref()
                .is_some_and(|at| at.master_token.is_expired())
        {
            // Create new session if tokens are absent or can not be exchange
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
            *auth_tokens = Some(tokens);
        } else if auth_tokens
            .as_ref()
            .is_some_and(|at| at.session_token.is_expired())
        {
            // Renew old session token
            let old_token = auth_tokens.take().unwrap();
            let tokens = self.renew(old_token).await?;
            *auth_tokens = Some(tokens);
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
        log::debug!("Auth response: {resp:?}");

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
        let (listener, port) = Self::start_callback_server()?;
        log::info!("Local callback server started on port {}", port);

        // Get the SSO URL and proof key from Snowflake
        let (mut body, sso_url) = self.externalbrowser_request_body(port).await?;

        // Open the browser with the SSO URL
        log::info!("Opening browser for authentication: {}", sso_url);
        webbrowser::open(&sso_url).map_err(|e| AuthError::BrowserOpenError(e.to_string()))?;

        // Wait for the browser to redirect back with the token (5 minute timeout)
        let timeout = Duration::from_secs(300);
        let token = Self::receive_saml_token(listener, timeout)?;
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
    fn start_callback_server() -> Result<(TcpListener, u16), AuthError> {
        // Bind to a random available port
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

        let port = listener
            .local_addr()
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?
            .port();

        // Set read timeout for the listener
        listener
            .set_nonblocking(false)
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

        Ok((listener, port))
    }

    /// Wait for the browser callback with the SAML token
    fn receive_saml_token(listener: TcpListener, timeout: Duration) -> Result<String, AuthError> {
        log::debug!("Waiting for browser callback...");

        let (mut stream, _) = listener.accept().map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                AuthError::BrowserAuthTimeout
            } else {
                AuthError::LocalServerError(e.to_string())
            }
        })?;

        // Set timeout on the stream
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

        let buf_reader = BufReader::new(&stream);
        let request_line = buf_reader
            .lines()
            .next()
            .ok_or_else(|| AuthError::LocalServerError("Empty request".to_string()))?
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;

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
            .map_err(|e| AuthError::LocalServerError(e.to_string()))?;
        stream
            .flush()
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
                account_name: self.account_identifier.clone(),
                login_name: self.username.clone(),
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
            .await?;

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
