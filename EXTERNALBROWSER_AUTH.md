# External Browser Authentication (SSO)

This implementation adds support for Snowflake's external browser authentication flow, similar to the [Node.js connector](https://github.com/snowflakedb/snowflake-connector-nodejs/blob/2838e32010bb6eb71adb9ed7a21f8da7b2512383/lib/authentication/auth_web.js).

## Overview

External browser authentication allows users to authenticate through their organization's SSO provider (Okta, ADFS, etc.) via a web browser, rather than using a password or private key.

## How It Works

1. **Proof Key Generation**: A cryptographically random 32-character proof key is generated
2. **Local Server**: A local HTTP server starts on a random port to receive the callback
3. **SSO URL Request**: The client requests an SSO URL from Snowflake, passing the proof key and callback port
4. **Browser Launch**: The user's default browser opens with the SSO URL
5. **User Authentication**: The user authenticates through their SSO provider
6. **Token Callback**: Snowflake redirects back to the local server with a SAML token
7. **Session Creation**: The client completes authentication using the token and proof key

## Usage

### Basic Example

```rust
use snowflake_api::SnowflakeApi;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = SnowflakeApi::with_externalbrowser_auth(
        "YOUR_ACCOUNT",      // account identifier
        Some("WAREHOUSE"),   // warehouse (optional)
        Some("DATABASE"),    // database (optional)
        Some("SCHEMA"),      // schema (optional)
        "USERNAME",          // username
        Some("ROLE"),        // role (optional)
    )?;

    // Execute queries (authentication happens automatically on first query)
    let result = api.exec("SELECT CURRENT_USER()").await?;

    Ok(())
}
```

### Proactive Authentication (Settings Page Pattern)

For applications with settings or configuration pages, you can trigger authentication proactively instead of waiting for the first query:

```rust
use snowflake_api::{AuthArgs, AuthType, SnowflakeApiBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = AuthArgs {
        account_identifier: "YOUR_ACCOUNT".to_string(),
        username: "USERNAME".to_string(),
        auth_type: AuthType::ExternalBrowser,
        warehouse: Some("WAREHOUSE".to_string()),
        database: Some("DATABASE".to_string()),
        schema: Some("SCHEMA".to_string()),
        role: Some("ROLE".to_string()),
    };

    let api = SnowflakeApiBuilder::new(auth)
        .with_token_cache(true)  // Enable token caching
        .build()?;

    // In settings page: trigger browser authentication immediately
    println!("Please authenticate in your browser...");
    match api.authenticate().await {
        Ok(()) => {
            println!("✓ Authentication successful!");
            println!("✓ Token cached for future use");
        }
        Err(e) => {
            println!("✗ Authentication failed: {}", e);
            return Err(e.into());
        }
    }

    // Now execute queries without opening browser again
    let result = api.exec("SELECT CURRENT_USER()").await?;
    println!("Current user: {:?}", result);

    Ok(())
}
```

**Benefits of proactive authentication:**
- Better user experience in configuration/settings UIs
- Immediate feedback on authentication success/failure
- Tokens are cached before any queries are executed
- Subsequent queries execute immediately without browser popups

### Using the Example

Run the provided example:

```bash
cargo run --example externalbrowser_auth -- \
    --account-identifier YOUR_ACCOUNT \
    --username YOUR_USERNAME \
    --warehouse YOUR_WAREHOUSE \
    --database YOUR_DATABASE \
    --schema YOUR_SCHEMA \
    --sql "SELECT CURRENT_USER()"
```

## Configuration

### Timeout

The authentication flow has a default timeout of 5 minutes (300 seconds). This gives users enough time to complete the SSO authentication process.

You can customize the timeout using the `externalbrowser_auth_with_timeout` method:

```rust
use snowflake_api::SnowflakeApi;

let api = SnowflakeApi::with_externalbrowser_auth(
    "YOUR_ACCOUNT",
    Some("WAREHOUSE"),
    Some("DATABASE"),
    Some("SCHEMA"),
    "USERNAME",
    Some("ROLE"),
)?;

// Or with custom timeout (600 seconds = 10 minutes)
let session = Session::externalbrowser_auth_with_timeout(
    connection,
    "YOUR_ACCOUNT",
    Some("WAREHOUSE"),
    Some("DATABASE"),
    Some("SCHEMA"),
    "USERNAME",
    Some("ROLE"),
    600,  // timeout in seconds
);
```

### Token Caching

**IMPORTANT SECURITY NOTICE**: Token caching is **disabled by default** for security reasons. When enabled, authentication tokens are stored on your filesystem and remain valid for up to 4 hours. Only enable this feature if you understand the security implications.

#### Security Considerations

- Cached tokens do not expire for four hours, allowing anyone who accesses a token on your local system to impersonate you until the token naturally expires
- You are responsible for the security of the cached tokens in the designated directory
- Ensure proper file permissions so only you (the file owner) can access the cache
- On Linux/macOS, the cache directory is automatically set to `0700` (owner rwx only) and cache files to `0600` (owner rw only)

#### Enabling Token Caching

##### Using the Builder Pattern (Recommended)

The recommended way to enable token caching is through the `SnowflakeApiBuilder`:

```rust
use snowflake_api::{AuthArgs, AuthType, SnowflakeApiBuilder};

let auth = AuthArgs {
    account_identifier: "YOUR_ACCOUNT".to_string(),
    warehouse: Some("WAREHOUSE".to_string()),
    database: Some("DATABASE".to_string()),
    schema: Some("SCHEMA".to_string()),
    username: "USERNAME".to_string(),
    role: Some("ROLE".to_string()),
    auth_type: AuthType::ExternalBrowser,
};

let api = SnowflakeApiBuilder::new(auth)
    .with_token_cache(true)  // Enable token caching
    .build()?;
```

##### Using a Custom Cache Directory

You can specify a custom directory for token storage:

```rust
use snowflake_api::{AuthArgs, AuthType, SnowflakeApiBuilder};
use std::path::PathBuf;

let auth = AuthArgs {
    account_identifier: "YOUR_ACCOUNT".to_string(),
    warehouse: Some("WAREHOUSE".to_string()),
    database: Some("DATABASE".to_string()),
    schema: Some("SCHEMA".to_string()),
    username: "USERNAME".to_string(),
    role: Some("ROLE".to_string()),
    auth_type: AuthType::ExternalBrowser,
};

let api = SnowflakeApiBuilder::new(auth)
    .with_token_cache(true)
    .with_cache_directory("/custom/path/to/cache")  // Custom cache directory
    .with_browser_timeout(600)  // Optional: custom timeout (10 minutes)
    .build()?;
```

##### Using Session Directly

If you're creating a `Session` directly, use the `externalbrowser_auth_with_options` or `externalbrowser_auth_full` methods:

```rust
use snowflake_api::Session;
use std::sync::Arc;
use std::path::PathBuf;
use snowflake_api::connection::Connection;

let connection = Arc::new(Connection::new()?);

// With default cache directory
let session = Session::externalbrowser_auth_with_options(
    connection.clone(),
    "YOUR_ACCOUNT",
    Some("WAREHOUSE"),
    Some("DATABASE"),
    Some("SCHEMA"),
    "USERNAME",
    Some("ROLE"),
    300,   // timeout in seconds
    true,  // enable token caching
);

// Or with custom cache directory
let session = Session::externalbrowser_auth_full(
    connection,
    "YOUR_ACCOUNT",
    Some("WAREHOUSE"),
    Some("DATABASE"),
    Some("SCHEMA"),
    "USERNAME",
    Some("ROLE"),
    300,   // timeout in seconds
    true,  // enable token caching
    Some(PathBuf::from("/custom/path/to/cache")),  // custom cache directory
);
```

#### Cache Location

By default, tokens are cached in:
- **Linux/macOS**: `~/.cache/snowflake/`
- **Windows**: `%APPDATA%\Snowflake\`

You can customize the cache directory by setting the `SF_TEMPORARY_CREDENTIAL_CACHE_DIR` environment variable:

```bash
export SF_TEMPORARY_CREDENTIAL_CACHE_DIR=/path/to/cache
```

#### How Token Caching Works

1. **First Authentication**: When you authenticate for the first time, you'll be prompted to open your browser for SSO. After successful authentication, tokens are saved to the cache (if enabled).

2. **Subsequent Uses**: On subsequent runs, the library checks the cache first. If valid tokens are found, it uses them without opening the browser.

3. **Token Expiration**: Cached tokens are automatically removed if they've expired. The library will then prompt for browser authentication again.

4. **Invalid Token Handling**: If a cached token is revoked or becomes invalid, the library automatically:
   - Detects the authentication failure
   - Clears the invalid token from the cache
   - Re-triggers browser authentication to get a new valid token
   - Saves the new token to cache

5. **Session Closure**: When you call `session.close()`, cached tokens are automatically removed.

6. **Manual Invalidation**: You can manually invalidate cached tokens if needed:

```rust
// If you encounter auth errors, you can manually clear the cache
api.invalidate_token_cache().await;

// Next API call will trigger browser authentication
let result = api.exec("SELECT 1").await?;
```

#### Benefits of Token Caching

- **Reduced SSO Prompts**: Avoid repetitive browser authentication prompts when running scripts or applications frequently
- **Better Development Experience**: Smoother workflow during development and testing
- **Compliance**: Follows the same pattern as official Snowflake connectors (Python, Node.js, JDBC, .NET)

#### When to Use Token Caching

Token caching is most useful for:
- Development and testing environments
- Automated scripts that run frequently
- CI/CD pipelines with proper security controls
- Applications where user convenience outweighs the security risk

#### When NOT to Use Token Caching

Avoid token caching in:
- Shared systems where multiple users have access
- Production environments with strict security requirements
- Systems where you cannot control file permissions
- Scenarios where immediate token revocation is critical

### Browser

The implementation uses the `webbrowser` crate to reliably open the default browser across different operating systems (macOS, Linux, Windows).

## Error Handling

The implementation includes specific error types for external browser authentication:

- `BrowserAuthTimeout`: The authentication did not complete within the timeout period
- `LocalServerError`: Failed to start or operate the local callback server
- `BrowserOpenError`: Failed to open the default browser

## Security

The implementation follows Snowflake's security best practices:

- Uses cryptographically random proof keys
- Runs local server only on localhost (127.0.0.1)
- Validates the callback token before completing authentication
- Automatically closes the local server after receiving the token

## Dependencies

- `webbrowser` (1.0): Cross-platform browser launching
- `rand` (0.8): Cryptographically secure random number generation

## Comparison with Node.js Implementation

This Rust implementation closely mirrors the Node.js connector's approach:

| Feature | Node.js | Rust (this impl) |
|---------|---------|------------------|
| Proof key generation | ✓ | ✓ |
| Local HTTP server | ✓ | ✓ |
| Browser launch | ✓ | ✓ |
| Timeout handling | ✓ | ✓ (5 min) |
| Token callback parsing | ✓ | ✓ |
| Success response to browser | ✓ | ✓ |

## Limitations

- The browser must be able to connect back to localhost on the callback port
- Headless environments (without a display) are not supported
- Corporate firewalls may interfere with the callback mechanism
