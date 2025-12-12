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

    // Execute queries
    let result = api.exec("SELECT CURRENT_USER()").await?;

    Ok(())
}
```

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
