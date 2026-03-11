# Error Handling

This guide covers comprehensive error handling strategies for the JWT Auth Client.

## Error Types

### AuthTokens.Error

Errors related to token validation and processing:

```swift
public enum AuthTokens.Error: LocalizedError {
  case missingToken    // No token available
  case invalidToken    // Token format is invalid
  case expiredToken    // Token has expired
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
  // Clear corrupted tokens
  try await authTokensClient.destroy()
  showLoginScreen()
} catch AuthTokens.Error.expiredToken {
  // This usually won't happen with auto-refresh
  try await authClient.refreshExpiredTokens()
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

```swift
@Dependency(\.jwtAuthClient) var authClient

do {
  try await authClient.refreshExpiredTokens()
} catch {
  if error.isNetworkError {
    // Show retry option
    showNetworkErrorAlert(retry: {
      try await authClient.refreshExpiredTokens()
    })
  } else {
    // Authentication failed, clear tokens
    try await authTokensClient.destroy()
    redirectToLogin()
  }
}
```

### 2. Server Returns Invalid Tokens

```swift
// In your refresh implementation
extension JWTAuthClient: @retroactive DependencyKey {
  static let liveValue = Self(
    baseURL: { "https://api.example.com" },
    refresh: { tokens in
      do {
        let response = try await refreshTokensFromServer(tokens)

        // Validate the new tokens before returning
        let newTokens = AuthTokens(
          access: response.accessToken,
          refresh: response.refreshToken
        )

        // This will throw if tokens are invalid
        _ = try newTokens.toJWT()

        return newTokens
      } catch {
        // If refresh fails, clear all tokens
        @Dependency(\.authTokensClient) var authTokensClient
        try await authTokensClient.destroy()
        throw error
      }
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
      case AuthTokens.Error.missingToken,
           AuthTokens.Error.invalidToken:
        try await authTokensClient.destroy()
        NotificationCenter.default.post(name: .authenticationRequired, object: nil)

      case AuthTokens.Error.expiredToken:
        @Dependency(\.jwtAuthClient) var authClient
        try await authClient.refreshExpiredTokens()

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
  static let failingTestValue = Self(
    baseURL: { "https://test.api" },
    refresh: { _ in
      throw AuthTokens.Error.expiredToken
    }
  )

  static let networkErrorTestValue = Self(
    baseURL: { "https://test.api" },
    refresh: { _ in
      throw URLError(.notConnectedToInternet)
    }
  )
}
```

### Error Testing

```swift
func testTokenRefreshFailure() async throws {
  withDependencies {
    $0.jwtAuthClient = .failingTestValue
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient

    do {
      try await authClient.refreshExpiredTokens()
      XCTFail("Expected error")
    } catch AuthTokens.Error.expiredToken {
      // Expected error
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }
}
```

## Best Practices

1. **Always handle authentication errors** by clearing tokens and redirecting to login
2. **Provide user-friendly error messages** instead of technical details
3. **Implement retry logic** for network errors
4. **Log errors appropriately** for debugging without exposing sensitive data
5. **Test error scenarios** thoroughly in your test suite
6. **Gracefully degrade** when keychain access is denied
7. **Never ignore errors** - always handle them appropriately

## Next Steps

- <doc:Testing> - Testing authentication and error scenarios
- <doc:AdvancedUsage> - Advanced patterns and customizations
