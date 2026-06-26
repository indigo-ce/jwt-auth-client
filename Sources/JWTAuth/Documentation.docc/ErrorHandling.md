# Error Handling

This guide covers comprehensive error handling strategies for the JWT Auth Client.

## Migration: Upgrading to the new refresh contract

`JWTAuthClient.refreshExpiredTokens()` previously treated **any** error
from the `refresh` closure as proof that the refresh token was invalid and
destroyed the stored credentials. That meant a transient network failure
silently and permanently logged the user out.

The new contract introduces ``AuthTokens/Error/refreshRejected`` as the
**explicit** signal for "the server definitively rejected the refresh
token." Only that case destroys credentials; anything else (network
errors, decode errors, keychain save failures, etc.) is rethrown and
preserves the stored tokens so a later retry can succeed.

### Before (any error → destroy)

```swift
refresh: { tokens in
  do {
    return try await refreshFromServer(tokens)
  } catch {
    // Library treats any error as a server-side rejection and
    // destroys the stored credentials. A transient URLError
    // here would log the user out.
    throw error
  }
}
```

### After (explicit `.refreshRejected` signal)

```swift
refresh: { tokens in
  do {
    return try await refreshFromServer(tokens)
  } catch let error as APIError where error.statusCode == 401 {
    // Server explicitly said the refresh token is no longer valid.
    // Tell the library to destroy the credentials.
    throw AuthTokens.Error.refreshRejected
  }
  // Any other error (URLError, decode, 5xx, etc.) is treated as
  // transient — the stored tokens are preserved and the error is
  // rethrown so the caller can offer a retry option.
}
```

### Migration checklist for existing consumers

1. **Audit your `refresh` closure** for any path that throws
   ``AuthTokens/Error/expiredToken`` or ``AuthTokens/Error/invalidToken``
   to signal a bad refresh token. Replace those with
   ``AuthTokens/Error/refreshRejected``. The legacy cases are **not**
   treated as rejection aliases — they fall through to the transient
   branch and preserve the stale tokens, which is the correct behavior
   for network/decode/keychain errors but the wrong behavior when the
   server has actually told you the refresh token is dead.

2. **Audit centralized error handlers** that previously called
   `authTokensClient.destroy()` on ``AuthTokens/Error/invalidToken`` or
   ``AuthTokens/Error/expiredToken``. With the new contract, those
   errors are transient — destroying on them will log the user out
   transient-style. Only ``AuthTokens/Error/refreshRejected`` should
   trigger destruction, and `refreshExpiredTokens()` already handles
   that case for you. The example handler in
   <doc:#Centralized-Error-Handling> has been updated accordingly.

3. **Audit your `sendAuthenticated` error handling.** Transient failures
   are now rethrown (network, timeout, decode, keychain save). Surface
   a retry option instead of redirecting to login.

## Error Types

### AuthTokens.Error

Errors related to token validation and processing:

```swift
public enum AuthTokens.Error: LocalizedError {
  case missingToken     // No token available
  case invalidToken     // Token format is invalid
  case expiredToken     // Token has expired
  case refreshRejected  // Server explicitly rejected the refresh token
}
```

Example handling:
```swift
do {
  let jwt = try tokens.toJWT()
} catch AuthTokens.Error.missingToken {
  // Redirect to login
  showLoginScreen()
} catch AuthTokens.Error.invalidToken {
  // Token format is invalid. With the new refresh contract this is
  // not a server-rejection signal — only `.refreshRejected` is. If
  // the closure that called `toJWT()` was a `refresh` closure, treat
  // this as transient and surface a retry instead of logging the
  // user out.
  showRetryAlert(error: error) {
    try await authClient.refreshExpiredTokens()
  }
} catch AuthTokens.Error.expiredToken {
  // Access token is expired. With auto-refresh this shouldn't reach
  // the caller; if it does, treat as transient.
  showRetryAlert(error: error) {
    try await authClient.refreshExpiredTokens()
  }
} catch AuthTokens.Error.refreshRejected {
  // The refresh endpoint told us the refresh token is no longer valid.
  // `authClient.refreshExpiredTokens()` will already have destroyed the
  // stored credentials for you; route the user back to the login screen.
  showLoginScreen()
}
```

### KeychainError

Errors from keychain operations:

```swift
public enum KeychainError: LocalizedError {
  case savingFailed(message: String)
  case loadingFailed(message: String)
}
```

Example handling:
```swift
do {
  try await keychainClient.save("token", .accessToken)
} catch KeychainError.savingFailed(let message) {
  print("Failed to save to keychain: \(message)")
  // Maybe show user an error or use fallback storage
} catch KeychainError.loadingFailed(let message) {
  print("Failed to load from keychain: \(message)")
  // Treat as if no tokens exist
}
```

## Common Error Scenarios

### 1. Network Errors During Token Refresh

`refreshExpiredTokens()` only destroys the stored credentials when the server
**explicitly** rejects the refresh token (via `AuthTokens.Error.refreshRejected`).
Anything else — `URLError.cannotConnectToHost`, `.notConnectedToInternet`,
`.timedOut`, DNS failures, decode errors, 5xx responses — is treated as
transient: the stored tokens are **left intact** and the error is rethrown so
the caller can decide whether to surface a retry option.

```swift
@Dependency(\.jwtAuthClient) var authClient
@Dependency(\.authTokensClient) var authTokensClient

do {
  try await authClient.refreshExpiredTokens()
} catch AuthTokens.Error.missingToken {
  // No tokens in storage — route the user to login.
  redirectToLogin()
} catch AuthTokens.Error.refreshRejected {
  // Server said the refresh token is no longer valid.
  // `refreshExpiredTokens()` has already destroyed the stored credentials,
  // so we just need to react.
  redirectToLogin()
} catch {
  // Transient failure: bad network, timeout, decode error, etc. The
  // stored tokens are still valid — let the user retry.
  if error.isNetworkError {
    showNetworkErrorAlert(retry: {
      try await authClient.refreshExpiredTokens()
    })
  } else {
    showRetryAlert(error: error) {
      try await authClient.refreshExpiredTokens()
    }
  }
}
```

> ⚠️ **Important:** Do **not** call `authTokensClient.destroy()` from your
> generic `catch` block. `refreshExpiredTokens()` already destroys credentials
> when a definitive rejection happens, and you do not want to wipe a still-
> valid refresh token on a transient network blip.

### 2. Server Returns Invalid Tokens

When the refresh endpoint rejects the request, the `refresh` closure should
signal that as `AuthTokens.Error.refreshRejected` so the library knows the
credentials are no longer valid and destroys them. **Do not** call
`authTokensClient.destroy()` from inside `refresh` — that would wipe the
session on every transient failure too.

```swift
extension JWTAuthClient: @retroactive DependencyKey {
  static let liveValue = Self(
    baseURL: { "https://api.example.com" },
    refresh: { tokens in
      do {
        let response = try await refreshTokensFromServer(tokens)
        return AuthTokens(
          access: response.accessToken,
          refresh: response.refreshToken
        )
      } catch let error as APIError where error.statusCode == 401 {
        // Server explicitly rejected the refresh token.
        // Tell the library to destroy the credentials.
        throw AuthTokens.Error.refreshRejected
      }
      // Any other error (URLError, decoding failure, 5xx, etc.) is
      // automatically treated as transient by `refreshExpiredTokens()`
      // and the stored tokens are preserved.
    }
  )
}
```

### 3. Keychain Access Denied

```swift
func handleKeychainAccessDenied() async {
  // Fallback to in-memory storage for this session
  let inMemoryTokens = UserDefaults.standard.string(forKey: "temp_access_token")

  if let tokens = inMemoryTokens {
    // Use fallback tokens but warn user
    showKeychainWarning()
  } else {
    // No fallback available
    redirectToLogin()
  }
}
```

## Centralized Error Handling

### Error Handler Service

Create a centralized error handler:

```swift
@DependencyClient
struct ErrorHandler: Sendable {
  var handleAuthError: @Sendable (Error) async -> Void
  var handleNetworkError: @Sendable (Error) async -> Void
  var handleGeneralError: @Sendable (Error) async -> Void
}

extension ErrorHandler: DependencyKey {
  static let liveValue = Self(
    handleAuthError: { error in
      @Dependency(\.authTokensClient) var authTokensClient

      switch error {
      case AuthTokens.Error.missingToken:
        // No tokens in storage. Destroy is a no-op here; route to login.
        try await authTokensClient.destroy()
        NotificationCenter.default.post(name: .authenticationRequired, object: nil)

      case AuthTokens.Error.refreshRejected:
        // The server rejected the refresh token. `refreshExpiredTokens()`
        // has already destroyed the stored credentials before rethrowing;
        // we just need to route to login.
        NotificationCenter.default.post(name: .authenticationRequired, object: nil)

      case AuthTokens.Error.invalidToken,
           AuthTokens.Error.expiredToken:
        // With the new refresh contract these are not rejection signals —
        // they indicate the access token was malformed/expired (and the
        // library attempted a refresh that also failed transiently) or
        // the refresh closure itself threw one of the legacy cases. In
        // both situations the stored tokens are still potentially
        // valid for a later retry. Surface a retry option.
        NotificationCenter.default.post(name: .retryAuth, object: error)

      default:
        break
      }
    },

    handleNetworkError: { error in
      // Show network error UI
      NotificationCenter.default.post(
        name: .networkError,
        object: error.localizedDescription
      )
    },

    handleGeneralError: { error in
      // Log error and show generic message
      print("Unexpected error: \(error)")
      NotificationCenter.default.post(
        name: .generalError,
        object: "An unexpected error occurred"
      )
    }
  )
}
```

### Using the Error Handler

```swift
struct APIService {
  @Dependency(\.jwtAuthClient) var authClient
  @Dependency(\.errorHandler) var errorHandler

  func fetchUserProfile() async throws -> UserProfile {
    do {
      let response: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
        .get("/user/profile")
      )
      return response.data
    } catch {
      if error.isAuthenticationError {
        await errorHandler.handleAuthError(error)
      } else if error.isNetworkError {
        await errorHandler.handleNetworkError(error)
      } else {
        await errorHandler.handleGeneralError(error)
      }
      throw error
    }
  }
}
```

## User-Friendly Error Messages

### Error Message Mapping

```swift
extension Error {
  var userFriendlyMessage: String {
    switch self {
    case AuthTokens.Error.missingToken:
      return "Please log in to continue"

    case AuthTokens.Error.expiredToken:
      return "Your session has expired. Please log in again"

    case AuthTokens.Error.invalidToken:
      return "Authentication error. Please log in again"

    case AuthTokens.Error.refreshRejected:
      return "Your session is no longer valid. Please log in again"

    case KeychainError.savingFailed:
      return "Unable to securely save your login. Please try again"

    case KeychainError.loadingFailed:
      return "Unable to load your saved login. Please log in again"

    default:
      if isNetworkError {
        return "Network connection error. Please check your internet connection"
      } else {
        return "An unexpected error occurred. Please try again"
      }
    }
  }

  var isNetworkError: Bool {
    if let urlError = self as? URLError {
      return [.notConnectedToInternet, .networkConnectionLost, .timedOut]
        .contains(urlError.code)
    }
    return false
  }

  var isAuthenticationError: Bool {
    return self is AuthTokens.Error
  }
}
```

### Error Alert Helper

```swift
struct ErrorAlert: ViewModifier {
  let error: Error?
  let onDismiss: () -> Void

  func body(content: Content) -> some View {
    content
      .alert("Error", isPresented: .constant(error != nil)) {
        Button("OK") {
          onDismiss()
        }

        if error?.isNetworkError == true {
          Button("Retry") {
            // Retry logic handled by parent
            onDismiss()
          }
        }
      } message: {
        Text(error?.userFriendlyMessage ?? "Unknown error")
      }
  }
}

// Usage
.modifier(ErrorAlert(error: viewModel.error) {
  viewModel.clearError()
})
```

## Error Recovery Strategies

### Automatic Recovery

```swift
struct AuthenticatedRequest<T: Decodable> {
  let endpoint: String
  let maxRetries: Int = 3

  @Dependency(\.jwtAuthClient) var authClient
  @Dependency(\.errorHandler) var errorHandler

  func execute() async throws -> T {
    var lastError: Error?

    for attempt in 1...maxRetries {
      do {
        let response: SuccessResponse<T> = try await authClient.sendAuthenticated(
          .get(endpoint)
        )
        return response.data
      } catch {
        lastError = error

        if error.isAuthenticationError && attempt < maxRetries {
          // Try to recover authentication
          await errorHandler.handleAuthError(error)

          // Wait before retry
          try await Task.sleep(nanoseconds: UInt64(attempt * 1_000_000_000))
          continue
        } else {
          throw error
        }
      }
    }

    throw lastError!
  }
}
```

### Manual Recovery UI

```swift
struct RecoveryView: View {
  let error: Error
  let onRetry: () async -> Void
  let onCancel: () -> Void

  var body: some View {
    VStack(spacing: 20) {
      Image(systemName: "exclamationmark.triangle")
        .font(.largeTitle)
        .foregroundColor(.orange)

      Text("Something went wrong")
        .font(.headline)

      Text(error.userFriendlyMessage)
        .multilineTextAlignment(.center)
        .foregroundColor(.secondary)

      HStack(spacing: 16) {
        Button("Cancel") {
          onCancel()
        }
        .buttonStyle(.bordered)

        Button("Try Again") {
          Task {
            await onRetry()
          }
        }
        .buttonStyle(.borderedProminent)
      }
    }
    .padding()
  }
}
```

## Logging and Debugging

### Error Logging

```swift
enum LogLevel {
  case debug, info, warning, error
}

struct Logger {
  static func log(_ level: LogLevel, _ message: String, error: Error? = nil) {
    let timestamp = DateFormatter.timestamp.string(from: Date())
    let errorInfo = error.map { " | Error: \($0.localizedDescription)" } ?? ""

    print("[\(timestamp)] [\(level)] \(message)\(errorInfo)")

    // In production, send to crash reporting service
    #if DEBUG
    if let error = error {
      print("Full error: \(error)")
    }
    #endif
  }
}

// Usage in error handlers
Logger.log(.error, "Token refresh failed", error: error)
Logger.log(.warning, "Keychain access denied, using fallback")
Logger.log(.info, "User logged out due to authentication error")
```

### Debug Information

```swift
extension AuthTokens {
  var debugInfo: String {
    let jwt = try? toJWT()
    let expiration = jwt?.expiresAt?.description ?? "unknown"
    let claims = jwt?.body.keys.joined(separator: ", ") ?? "none"

    return """
    AuthTokens Debug Info:
    - Expired: \(isExpired)
    - Expiration: \(expiration)
    - Claims: \(claims)
    - Access Token Length: \(access.count)
    - Refresh Token Length: \(refresh.count)
    """
  }
}
```

## Testing Error Scenarios

### Mock Error Responses

```swift
extension JWTAuthClient {
  static let rejectionMock = Self(
    baseURL: { "https://test.api" },
    refresh: { _ in
      throw AuthTokens.Error.refreshRejected
    }
  )

  static let transientErrorMock = Self(
    baseURL: { "https://test.api" },
    refresh: { _ in
      throw URLError(.notConnectedToInternet)
    }
  )
}
```

### Error Testing

```swift
@Test func refreshExpiredTokensDestroysOnRejection() async throws {
  // `.refreshRejected` is the explicit server-rejection signal.
  // `refreshExpiredTokens()` swallows it, destroys the stored
  // credentials, and returns normally — the caller does not see
  // the error. Route the user to login.
  await withDependencies {
    $0.jwtAuthClient = .rejectionMock
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    try await authClient.refreshExpiredTokens()
  }
}

@Test func refreshExpiredTokensRethrowsTransientErrors() async throws {
  // A transient `URLError` is rethrown so the caller can offer
  // a retry. The stored credentials are preserved.
  await withDependencies {
    $0.jwtAuthClient = .transientErrorMock
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    await #expect(throws: URLError.self) {
      try await authClient.refreshExpiredTokens()
    }
  }
}
```

## Best Practices

1. **Handle rejection and transient errors differently.** Only ``AuthTokens/Error/refreshRejected`` should clear tokens and route the user to login — and `refreshExpiredTokens()` already destroys the stored credentials for you. All other errors (network, timeout, decode, keychain save, ``AuthTokens/Error/expiredToken``, ``AuthTokens/Error/invalidToken``) are transient: surface a retry option instead of logging the user out.
2. **Provide user-friendly error messages** instead of technical details
3. **Implement retry logic** for network errors
4. **Log errors appropriately** for debugging without exposing sensitive data
5. **Test error scenarios** thoroughly in your test suite
6. **Gracefully degrade** when keychain access is denied
7. **Never ignore errors** - always handle them appropriately

## Next Steps

- <doc:Testing> - Testing authentication and error scenarios
- <doc:AdvancedUsage> - Advanced patterns and customizations
