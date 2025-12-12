#![doc(
    issue_tracker_base_url = "https://github.com/mycelial/snowflake-rs/issues",
    test(no_crate_inject)
)]
#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
clippy::must_use_candidate,
clippy::missing_errors_doc,
clippy::module_name_repetitions,
clippy::struct_field_names,
clippy::future_not_send, // This one seems like something we should eventually fix
clippy::missing_panics_doc
)]

use std::fmt::{Display, Formatter};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use arrow_ipc::reader::StreamReader;
use base64::Engine;
use bytes::{Buf, Bytes};
use futures::future::try_join_all;
use regex::Regex;
use reqwest_middleware::ClientWithMiddleware;
use thiserror::Error;

// Part of public interface
pub use arrow_array::RecordBatch;
pub use arrow_schema::ArrowError;

use responses::ExecResponse;
use session::{AuthError, Session};

use crate::connection::QueryType;
use crate::connection::{Connection, ConnectionError};
use crate::requests::ExecRequest;
use crate::responses::{ExecResponseRowType, SnowflakeType};
use crate::session::AuthError::MissingEnvArgument;

pub mod connection;
#[cfg(feature = "polars")]
mod polars;
mod put;
mod requests;
mod responses;
mod session;
mod token_cache;

#[derive(Error, Debug)]
pub enum SnowflakeApiError {
    #[error(transparent)]
    RequestError(#[from] ConnectionError),

    #[error(transparent)]
    AuthError(#[from] AuthError),

    #[error(transparent)]
    ResponseDeserializationError(#[from] base64::DecodeError),

    #[error(transparent)]
    ArrowError(#[from] ArrowError),

    #[error("S3 bucket path in PUT request is invalid: `{0}`")]
    InvalidBucketPath(String),

    #[error("Couldn't extract filename from the local path: `{0}`")]
    InvalidLocalPath(String),

    #[error(transparent)]
    LocalIoError(#[from] io::Error),

    #[error(transparent)]
    ObjectStoreError(#[from] object_store::Error),

    #[error(transparent)]
    ObjectStorePathError(#[from] object_store::path::Error),

    #[error(transparent)]
    TokioTaskJoinError(#[from] tokio::task::JoinError),

    #[error("Snowflake API error. Code: `{0}`. Message: `{1}`")]
    ApiError(String, String),

    #[error("Snowflake API empty response could mean that query wasn't executed correctly or API call was faulty")]
    EmptyResponse,

    #[error("No usable rowsets were included in the response")]
    BrokenResponse,

    #[error("Following feature is not implemented yet: {0}")]
    Unimplemented(String),

    #[error("Unexpected API response")]
    UnexpectedResponse,

    #[error(transparent)]
    GlobPatternError(#[from] glob::PatternError),

    #[error(transparent)]
    GlobError(#[from] glob::GlobError),
}

/// Even if Arrow is specified as a return type non-select queries
/// will return Json array of arrays: `[[42, "answer"], [43, "non-answer"]]`.
pub struct JsonResult {
    // todo: can it _only_ be a json array of arrays or something else too?
    pub value: serde_json::Value,
    /// Field ordering matches the array ordering
    pub schema: Vec<FieldSchema>,
}

impl Display for JsonResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Based on the [`ExecResponseRowType`]
pub struct FieldSchema {
    pub name: String,
    // todo: is it a good idea to expose internal response struct to the user?
    pub type_: SnowflakeType,
    pub scale: Option<i64>,
    pub precision: Option<i64>,
    pub nullable: bool,
}

impl From<ExecResponseRowType> for FieldSchema {
    fn from(value: ExecResponseRowType) -> Self {
        FieldSchema {
            name: value.name,
            type_: value.type_,
            scale: value.scale,
            precision: value.precision,
            nullable: value.nullable,
        }
    }
}

/// Container for query result.
/// Arrow is returned by-default for all SELECT statements,
/// unless there is session configuration issue or it's a different statement type.
pub enum QueryResult {
    Arrow(Vec<RecordBatch>),
    Json(JsonResult),
    Empty,
}

/// Raw query result
/// Can be transformed into [`QueryResult`]
pub enum RawQueryResult {
    /// Arrow IPC chunks
    /// see: <https://arrow.apache.org/docs/format/Columnar.html#serialization-and-interprocess-communication-ipc>
    Bytes(Vec<Bytes>),
    /// Json payload is deserialized,
    /// as it's already a part of REST response
    Json(JsonResult),
    Empty,
}

impl RawQueryResult {
    pub fn deserialize_arrow(self) -> Result<QueryResult, ArrowError> {
        match self {
            RawQueryResult::Bytes(bytes) => {
                Self::flat_bytes_to_batches(bytes).map(QueryResult::Arrow)
            }
            RawQueryResult::Json(j) => Ok(QueryResult::Json(j)),
            RawQueryResult::Empty => Ok(QueryResult::Empty),
        }
    }

    fn flat_bytes_to_batches(bytes: Vec<Bytes>) -> Result<Vec<RecordBatch>, ArrowError> {
        let mut res = vec![];
        for b in bytes {
            let mut batches = Self::bytes_to_batches(b)?;
            res.append(&mut batches);
        }
        Ok(res)
    }

    fn bytes_to_batches(bytes: Bytes) -> Result<Vec<RecordBatch>, ArrowError> {
        let record_batches = StreamReader::try_new(bytes.reader(), None)?;
        record_batches.into_iter().collect()
    }
}

pub struct AuthArgs {
    pub account_identifier: String,
    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub username: String,
    pub role: Option<String>,
    pub auth_type: AuthType,
}

impl AuthArgs {
    pub fn from_env() -> Result<AuthArgs, SnowflakeApiError> {
        let auth_type = if let Ok(password) = std::env::var("SNOWFLAKE_PASSWORD") {
            Ok(AuthType::Password(PasswordArgs { password }))
        } else if let Ok(private_key_pem) = std::env::var("SNOWFLAKE_PRIVATE_KEY") {
            Ok(AuthType::Certificate(CertificateArgs { private_key_pem }))
        } else {
            Err(MissingEnvArgument(
                "SNOWFLAKE_PASSWORD or SNOWFLAKE_PRIVATE_KEY".to_owned(),
            ))
        };

        Ok(AuthArgs {
            account_identifier: std::env::var("SNOWFLAKE_ACCOUNT")
                .map_err(|_| MissingEnvArgument("SNOWFLAKE_ACCOUNT".to_owned()))?,
            warehouse: std::env::var("SNOWLFLAKE_WAREHOUSE").ok(),
            database: std::env::var("SNOWFLAKE_DATABASE").ok(),
            schema: std::env::var("SNOWFLAKE_SCHEMA").ok(),
            username: std::env::var("SNOWFLAKE_USER")
                .map_err(|_| MissingEnvArgument("SNOWFLAKE_USER".to_owned()))?,
            role: std::env::var("SNOWFLAKE_ROLE").ok(),
            auth_type: auth_type?,
        })
    }
}

pub enum AuthType {
    Password(PasswordArgs),
    Certificate(CertificateArgs),
    ExternalBrowser,
}

pub struct PasswordArgs {
    pub password: String,
}

pub struct CertificateArgs {
    pub private_key_pem: String,
}

#[must_use]
pub struct SnowflakeApiBuilder {
    pub auth: AuthArgs,
    client: Option<ClientWithMiddleware>,
    /// Enable token caching for external browser authentication (default: false)
    enable_token_cache: bool,
    /// Custom cache directory for token storage (default: None, uses platform default)
    cache_directory: Option<PathBuf>,
    /// Timeout for external browser authentication in seconds (default: 300)
    browser_auth_timeout_secs: u64,
}

impl SnowflakeApiBuilder {
    pub fn new(auth: AuthArgs) -> Self {
        Self {
            auth,
            client: None,
            enable_token_cache: false,
            cache_directory: None,
            browser_auth_timeout_secs: 300,
        }
    }

    pub fn with_client(mut self, client: ClientWithMiddleware) -> Self {
        self.client = Some(client);
        self
    }

    /// Enable token caching for external browser authentication.
    /// WARNING: Tokens are cached on the filesystem and remain valid for up to 4 hours.
    /// Only enable this if you understand the security implications.
    pub fn with_token_cache(mut self, enable: bool) -> Self {
        self.enable_token_cache = enable;
        self
    }

    /// Set a custom cache directory for token storage.
    /// If not set, uses the platform default (~/.cache/snowflake on Linux/macOS).
    pub fn with_cache_directory<P: Into<PathBuf>>(mut self, directory: P) -> Self {
        self.cache_directory = Some(directory.into());
        self
    }

    /// Set the timeout for external browser authentication (in seconds).
    /// Default is 300 seconds (5 minutes).
    pub fn with_browser_timeout(mut self, timeout_secs: u64) -> Self {
        self.browser_auth_timeout_secs = timeout_secs;
        self
    }

    pub fn build(self) -> Result<SnowflakeApi, SnowflakeApiError> {
        let connection = match self.client {
            Some(client) => Arc::new(Connection::new_with_middware(client)),
            None => Arc::new(Connection::new()?),
        };

        let session = match self.auth.auth_type {
            AuthType::Password(args) => Session::password_auth(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
                &args.password,
            ),
            AuthType::Certificate(args) => Session::cert_auth(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
                &args.private_key_pem,
            ),
            AuthType::ExternalBrowser => Session::externalbrowser_auth_full(
                Arc::clone(&connection),
                &self.auth.account_identifier,
                self.auth.warehouse.as_deref(),
                self.auth.database.as_deref(),
                self.auth.schema.as_deref(),
                &self.auth.username,
                self.auth.role.as_deref(),
                self.browser_auth_timeout_secs,
                self.enable_token_cache,
                self.cache_directory,
            ),
        };

        let account_identifier = self.auth.account_identifier.to_uppercase();

        Ok(SnowflakeApi::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }
}

/// Snowflake API, keeps connection pool and manages session for you
pub struct SnowflakeApi {
    connection: Arc<Connection>,
    session: Session,
    account_identifier: String,
}

impl SnowflakeApi {
    /// Create a new `SnowflakeApi` object with an existing connection and session.
    pub fn new(connection: Arc<Connection>, session: Session, account_identifier: String) -> Self {
        Self {
            connection,
            session,
            account_identifier,
        }
    }
    /// Initialize object with password auth. Authentication happens on the first request.
    pub fn with_password_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        password: &str,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::password_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            password,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    /// Initialize object with private certificate auth. Authentication happens on the first request.
    pub fn with_certificate_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        private_key_pem: &str,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::cert_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            private_key_pem,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    /// Initialize object with external browser (SSO) auth. Authentication happens on the first request.
    /// This will open a browser window for the user to authenticate via their SSO provider.
    pub fn with_externalbrowser_auth(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::externalbrowser_auth(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    /// Initialize object with external browser (SSO) auth with full configuration options.
    /// This provides complete control over timeout, token caching, and cache directory.
    ///
    /// # Parameters
    /// - `account_identifier`: Snowflake account identifier
    /// - `warehouse`: Optional warehouse name
    /// - `database`: Optional database name
    /// - `schema`: Optional schema name
    /// - `username`: Snowflake username
    /// - `role`: Optional role name
    /// - `browser_auth_timeout_secs`: Browser authentication timeout in seconds (default: 300)
    /// - `enable_token_cache`: Enable filesystem token caching (default: false, WARNING: security implications)
    /// - `cache_directory`: Optional custom cache directory (uses platform default if None)
    ///
    /// # Example
    /// ```no_run
    /// use snowflake_api::SnowflakeApi;
    /// use std::path::PathBuf;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let api = SnowflakeApi::with_externalbrowser_auth_full(
    ///     "MY_ACCOUNT",
    ///     Some("WAREHOUSE"),
    ///     Some("DATABASE"),
    ///     Some("SCHEMA"),
    ///     "username",
    ///     Some("ROLE"),
    ///     600,  // 10 minute timeout
    ///     true,  // enable token caching
    ///     Some(PathBuf::from("/custom/cache/dir")),  // custom cache directory
    /// )?;
    ///
    /// // Authenticate immediately
    /// api.authenticate().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::too_many_arguments)]
    pub fn with_externalbrowser_auth_full(
        account_identifier: &str,
        warehouse: Option<&str>,
        database: Option<&str>,
        schema: Option<&str>,
        username: &str,
        role: Option<&str>,
        browser_auth_timeout_secs: u64,
        enable_token_cache: bool,
        cache_directory: Option<PathBuf>,
    ) -> Result<Self, SnowflakeApiError> {
        let connection = Arc::new(Connection::new()?);

        let session = Session::externalbrowser_auth_full(
            Arc::clone(&connection),
            account_identifier,
            warehouse,
            database,
            schema,
            username,
            role,
            browser_auth_timeout_secs,
            enable_token_cache,
            cache_directory,
        );

        let account_identifier = account_identifier.to_uppercase();
        Ok(Self::new(
            Arc::clone(&connection),
            session,
            account_identifier,
        ))
    }

    pub fn from_env() -> Result<Self, SnowflakeApiError> {
        SnowflakeApiBuilder::new(AuthArgs::from_env()?).build()
    }

    /// Closes the current session, this is necessary to clean up temporary objects (tables, functions, etc)
    /// which are Snowflake session dependent.
    /// If another request is made the new session will be initiated.
    pub async fn close_session(&mut self) -> Result<(), SnowflakeApiError> {
        self.session.close().await?;
        Ok(())
    }

    /// Invalidate cached authentication tokens.
    /// Call this if you encounter authentication errors and want to force re-authentication.
    /// This is particularly useful with external browser authentication when cached tokens become invalid.
    pub async fn invalidate_token_cache(&mut self) {
        self.session.invalidate_cache().await;
    }

    /// Explicitly trigger the authentication flow.
    ///
    /// This method forces authentication to happen immediately rather than waiting for the first query.
    /// It's particularly useful for:
    /// - Pre-configuring authentication in settings/configuration pages
    /// - Verifying credentials before executing queries
    /// - Triggering external browser authentication proactively
    /// - Testing authentication without executing a query
    ///
    /// For external browser authentication, this will open the browser immediately and cache
    /// the token (if caching is enabled), so subsequent operations won't require re-authentication.
    ///
    /// # Returns
    /// - `Ok(())` if authentication succeeded and tokens are cached
    /// - `Err(SnowflakeApiError)` if authentication failed
    ///
    /// # Example
    /// ```no_run
    /// use snowflake_api::{AuthArgs, AuthType, SnowflakeApiBuilder};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = AuthArgs {
    ///     account_identifier: "MY_ACCOUNT".to_string(),
    ///     username: "my_user".to_string(),
    ///     auth_type: AuthType::ExternalBrowser,
    ///     warehouse: Some("WAREHOUSE".to_string()),
    ///     database: Some("DATABASE".to_string()),
    ///     schema: Some("SCHEMA".to_string()),
    ///     role: Some("ROLE".to_string()),
    /// };
    ///
    /// let mut api = SnowflakeApiBuilder::new(auth)
    ///     .with_token_cache(true)  // Enable token caching
    ///     .build()?;
    ///
    /// // In a settings page: trigger authentication immediately
    /// match api.authenticate().await {
    ///     Ok(()) => println!("Authentication successful! Token cached."),
    ///     Err(e) => println!("Authentication failed: {}", e),
    /// }
    ///
    /// // Later: execute queries without re-authentication
    /// let result = api.exec("SELECT CURRENT_USER()").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authenticate(&self) -> Result<(), SnowflakeApiError> {
        self.session.authenticate().await?;
        Ok(())
    }

    /// Execute a single query against API.
    /// If statement is PUT, then file will be uploaded to the Snowflake-managed storage
    pub async fn exec(&self, sql: &str) -> Result<QueryResult, SnowflakeApiError> {
        let raw = self.exec_raw(sql).await?;
        let res = raw.deserialize_arrow()?;
        Ok(res)
    }

    /// Executes a single query against API.
    /// If statement is PUT, then file will be uploaded to the Snowflake-managed storage
    /// Returns raw bytes in the Arrow response
    pub async fn exec_raw(&self, sql: &str) -> Result<RawQueryResult, SnowflakeApiError> {
        let put_re = Regex::new(r"(?i)^(?:/\*.*\*/\s*)*put\s+").unwrap();

        // put commands go through a different flow and result is side-effect
        if put_re.is_match(sql) {
            log::info!("Detected PUT query");
            self.exec_put(sql).await.map(|()| RawQueryResult::Empty)
        } else {
            self.exec_arrow_raw(sql).await
        }
    }

    async fn exec_put(&self, sql: &str) -> Result<(), SnowflakeApiError> {
        let resp = self
            .run_sql::<ExecResponse>(sql, QueryType::JsonQuery)
            .await?;
        log::debug!("Got PUT response: {resp:?}");

        match resp {
            ExecResponse::Query(_) => Err(SnowflakeApiError::UnexpectedResponse),
            ExecResponse::PutGet(pg) => put::put(pg).await,
            ExecResponse::Error(e) => Err(SnowflakeApiError::ApiError(
                e.data.error_code,
                e.message.unwrap_or_default(),
            )),
        }
    }

    /// Useful for debugging to get the straight query response
    #[cfg(debug_assertions)]
    pub async fn exec_response(&mut self, sql: &str) -> Result<ExecResponse, SnowflakeApiError> {
        self.run_sql::<ExecResponse>(sql, QueryType::ArrowQuery)
            .await
    }

    /// Useful for debugging to get raw JSON response
    #[cfg(debug_assertions)]
    pub async fn exec_json(&mut self, sql: &str) -> Result<serde_json::Value, SnowflakeApiError> {
        self.run_sql::<serde_json::Value>(sql, QueryType::JsonQuery)
            .await
    }

    async fn exec_arrow_raw(&self, sql: &str) -> Result<RawQueryResult, SnowflakeApiError> {
        let resp = self
            .run_sql::<ExecResponse>(sql, QueryType::ArrowQuery)
            .await?;
        log::debug!("Got query response: {resp:?}");

        let resp = match resp {
            // processable response
            ExecResponse::Query(qr) => Ok(qr),
            ExecResponse::PutGet(_) => Err(SnowflakeApiError::UnexpectedResponse),
            ExecResponse::Error(e) => Err(SnowflakeApiError::ApiError(
                e.data.error_code,
                e.message.unwrap_or_default(),
            )),
        }?;

        // if response was empty, base64 data is empty string
        // todo: still return empty arrow batch with proper schema? (schema always included)
        if resp.data.returned == 0 {
            log::debug!("Got response with 0 rows");
            Ok(RawQueryResult::Empty)
        } else if let Some(value) = resp.data.rowset {
            log::debug!("Got JSON response");
            // NOTE: json response could be chunked too. however, go clients should receive arrow by-default,
            // unless user sets session variable to return json. This case was added for debugging and status
            // information being passed through that fields.
            Ok(RawQueryResult::Json(JsonResult {
                value,
                schema: resp.data.rowtype.into_iter().map(Into::into).collect(),
            }))
        } else if let Some(base64) = resp.data.rowset_base64 {
            // fixme: is it possible to give streaming interface?
            let mut chunks = try_join_all(resp.data.chunks.iter().map(|chunk| {
                self.connection
                    .get_chunk(&chunk.url, &resp.data.chunk_headers)
            }))
            .await?;

            // fixme: should base64 chunk go first?
            // fixme: if response is chunked is it both base64 + chunks or just chunks?
            if !base64.is_empty() {
                log::debug!("Got base64 encoded response");
                let bytes = Bytes::from(base64::engine::general_purpose::STANDARD.decode(base64)?);
                chunks.push(bytes);
            }

            Ok(RawQueryResult::Bytes(chunks))
        } else {
            Err(SnowflakeApiError::BrokenResponse)
        }
    }

    async fn run_sql<R: serde::de::DeserializeOwned>(
        &self,
        sql_text: &str,
        query_type: QueryType,
    ) -> Result<R, SnowflakeApiError> {
        log::debug!("Executing: {sql_text}");

        let parts = self.session.get_token().await?;

        let body = ExecRequest {
            sql_text: sql_text.to_string(),
            async_exec: false,
            sequence_id: parts.sequence_id,
            is_internal: false,
        };

        let resp = self
            .connection
            .request::<R>(
                query_type,
                &self.account_identifier,
                &[],
                Some(&parts.session_token_auth_header),
                body,
            )
            .await?;

        Ok(resp)
    }
}
