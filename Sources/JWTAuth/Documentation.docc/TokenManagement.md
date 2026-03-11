# Token Management

This guide covers advanced token management features and best practices.

## Understanding AuthTokens

The `AuthTokens` structure is the core data type for managing JWT tokens:

```swift
let tokens = AuthTokens(
  access: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  refresh: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
)
```

### Token Validation

Check if tokens are expired:

```swift
if tokens.isExpired {
  // Access token has expired
  // The client will automatically refresh when needed
} else {
  // Token is still valid
}
```

### Extracting Claims

Extract data from JWT tokens:

```swift
// String claims
let userId = tokens[string: "user_id"]
let email = tokens[string: "email"]

// Boolean claims
let isAdmin = tokens[boolean: "is_admin"]
let emailVerified = tokens[boolean: "email_verified"]

// Numeric claims
let tokenVersion = tokens[int: "token_version"]
let lastLogin = tokens[date: "last_login"]

// Array claims
let roles = tokens[strings: "roles"]
```

### Converting to Session

Convert tokens to a session state:

```swift
let session = tokens.toSession()
// Returns either .valid(tokens) or .expired(tokens)
```

## Token Storage

### AuthTokensClient

The `AuthTokensClient` manages token persistence:

```swift
@Dependency(\.authTokensClient) var authTokensClient

// Save tokens (updates both memory and keychain)
try await authTokensClient.save(tokens)

// Destroy all tokens
try await authTokensClient.destroy()

// Set tokens (save if not nil, destroy if nil)
try await authTokensClient.set(optionalTokens)
```

### KeychainClient

For lower-level keychain operations:

```swift
@Dependency(\.keychainClient) var keychainClient

// Save individual tokens
try await keychainClient.save("access_token_value", .accessToken)
try await keychainClient.save("refresh_token_value", .refreshToken)

// Load individual tokens
let accessToken = try await keychainClient.load(.accessToken)
let refreshToken = try await keychainClient.load(.refreshToken)

// Load both tokens as AuthTokens
let tokens = try await keychainClient.loadTokens()

// Clean up
try await keychainClient.delete(.accessToken)
try await keychainClient.reset() // Deletes all keychain items
```

## Session Management

### Shared Session State

Access the current session across your app:

```swift
@Shared(.authSession) var session: AuthSession?

// Check session state
switch session {
case .none:
  // No session loaded yet
  showLoadingSpinner()

case .some(.missing):
  // No tokens available
  showLoginScreen()

case .some(.expired(let tokens)):
  // Tokens exist but access token is expired
  showRefreshingIndicator()

case .some(.valid(let tokens)):
  // User is authenticated with valid tokens
  showMainApp()
}
```

### Manual Session Updates

Update the session programmatically:

```swift
@Shared(.authSession) var session

// Set session with new tokens
session = tokens.toSession()

// Clear session
session = .missing

// Direct session assignment
session = .valid(tokens)
session = .expired(tokens)
```

## Token Refresh Strategies

### Automatic Refresh

The default behavior refreshes tokens automatically:

```swift
let response = try await authClient.sendAuthenticated(
  .get("/protected-endpoint"),
  refreshExpiredToken: true  // Default
)
```

### Manual Refresh

Control when tokens are refreshed:

```swift
// Disable automatic refresh
let response = try await authClient.sendAuthenticated(
  .get("/protected-endpoint"),
  refreshExpiredToken: false
)
```

```swift
// Manual refresh trigger
try await authClient.refreshExpiredTokens()
```

### Proactive Refresh

Refresh tokens before they expire:

```swift
@Dependency(\.jwtAuthClient) var authClient
@Shared(.authSession) var session

// Check if token will expire soon (e.g., within 5 minutes)
if let tokens = session?.tokens,
   let expirationDate = tokens[date: "exp"],
   expirationDate.timeIntervalSinceNow < 300 {

  try await authClient.refreshExpiredTokens()
}
```

## Custom Keychain Configuration

### Using a Different Keychain

```swift
// In your app initialization
prepareDependencies {
  $0.simpleKeychain = SimpleKeychain(
    service: "com.yourapp.custom-service",
    accessGroup: "group.yourapp.shared"
  )
}
```

### Custom Keychain Keys

Extend the keychain client with custom keys:

```swift
extension KeychainClient.Keys {
  static let customToken = Self(value: "custom_token")
  static let deviceId = Self(value: "device_id")
}

// Usage
try await keychainClient.save("device_123", .deviceId)
let deviceId = try await keychainClient.load(.deviceId)
```

## Token Security Best Practices

### 1. Never Log Tokens

```swift
// ❌ Don't do this
print("Access token: \(tokens.access)")
logger.debug("Token: \(tokens.access)")

// ✅ Log only metadata
print("Token expires at: \(tokens[date: "exp"] ?? Date())")
logger.debug("Token is expired: \(tokens.isExpired)")
```

### 2. Clear Tokens on Security Events

```swift
// Clear tokens when user changes password
func onPasswordChanged() async throws {
  @Dependency(\.authTokensClient) var authTokensClient
  try await authTokensClient.destroy()
}

// Clear tokens on app uninstall/reset
func resetAppData() async throws {
  @Dependency(\.keychainClient) var keychainClient
  try await keychainClient.reset()
}
```

### 3. Validate Token Integrity

```swift
// Check token claims match expected values
guard let userId = tokens[string: "user_id"],
      userId == currentUser.id else {
  // Token doesn't match current user
  try await authTokensClient.destroy()
  throw AuthenticationError.tokenMismatch
}
```

## Error Handling

### Token-Related Errors

```swift
do {
  try await authTokensClient.save(tokens)
} catch AuthTokens.Error.missingToken {
  // No tokens provided
} catch AuthTokens.Error.invalidToken {
  // Token format is invalid
} catch AuthTokens.Error.expiredToken {
  // Token has expired
} catch KeychainError.savingFailed(let message) {
  // Keychain operation failed
  print("Keychain error: \(message)")
}
```

### Recovery Strategies

```swift
func handleTokenError(_ error: Error) async {
  @Dependency(\.authTokensClient) var authTokensClient

  switch error {
  case AuthTokens.Error.expiredToken:
    // Try to refresh
    try? await authClient.refreshExpiredTokens()

  case AuthTokens.Error.invalidToken,
       AuthTokens.Error.missingToken:
    // Clear invalid tokens and redirect to login
    try? await authTokensClient.destroy()
    redirectToLogin()

  case KeychainError.savingFailed,
       KeychainError.loadingFailed:
    // Keychain issues - try to recover
    try? await keychainClient.reset()
    redirectToLogin()

  default:
    // Other errors
    showError(error.localizedDescription)
  }
}
```

## Testing Token Management

### Mock Token Client

```swift
extension AuthTokensClient {
  static let testValue = Self(
    save: { tokens in
      // Mock save implementation
      print("Saving tokens: \(tokens.access.prefix(10))...")
    },
    destroy: {
      print("Destroying tokens")
    }
  )
}
```

### Test Token Creation

```swift
func createTestTokens() -> AuthTokens {
  return AuthTokens(
    access: createTestJWT(claims: [
      "user_id": "test_user",
      "exp": Date().addingTimeInterval(3600).timeIntervalSince1970
    ]),
    refresh: createTestJWT(claims: [
      "exp": Date().addingTimeInterval(86400).timeIntervalSince1970
    ])
  )
}
```

## Next Steps

- <doc:ErrorHandling> - Comprehensive error handling
- <doc:Testing> - Testing authentication and token management
- <doc:AdvancedUsage> - Advanced patterns and customizations
