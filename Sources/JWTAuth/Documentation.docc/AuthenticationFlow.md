# Authentication Flow

This guide explains how to implement a complete authentication flow using the JWT Auth Client.

## Overview

The JWT Auth Client manages authentication through several key components:

- **AuthTokens**: Container for access and refresh tokens
- **AuthSession**: Represents the current authentication state
- **JWTAuthClient**: Handles API requests and token refresh
- **AuthTokensClient**: Manages token persistence
- **KeychainClient**: Secure storage for tokens

## Login Flow

### 1. User Login

When a user logs in with credentials, exchange them for JWT tokens:

```swift
struct LoginFeature: Reducer {
  @Dependency(\.authTokensClient) var authTokensClient
  @Dependency(\.httpRequestClient) var httpRequestClient

  enum Action {
    case loginButtonTapped
    case loginResponse(Result<LoginResponse, Error>)
  }

  func reduce(into state: inout State, action: Action) -> Effect<Action> {
    switch action {
    case .loginButtonTapped:
      return .run { [credentials = state.credentials] send in
        await send(.loginResponse(Result {
          let response: SuccessResponse<LoginResponse> = try await httpRequestClient.send(
            .post("/auth/login")
            .body(credentials)
          )
          return response.data
        }))
      }

    case let .loginResponse(.success(loginResponse)):
      let tokens = AuthTokens(
        access: loginResponse.accessToken,
        refresh: loginResponse.refreshToken
      )

      return .run { send in
        try await authTokensClient.save(tokens)
        // Navigation handled by parent reducer based on session state
      }

    case let .loginResponse(.failure(error)):
      state.error = error.localizedDescription
      return .none
    }
  }
}
```

### 2. Session Loading

Load the saved session when the app starts:

```swift
struct AppFeature: Reducer {
  @Dependency(\.jwtAuthClient) var authClient

  enum Action {
    case onAppear
    case sessionLoaded
  }

  func reduce(into state: inout State, action: Action) -> Effect<Action> {
    switch action {
    case .onAppear:
      return .run { send in
        try await authClient.loadSession()
        await send(.sessionLoaded)
      }

    case .sessionLoaded:
      // The session is now available via @Shared(.authSession)
      return .none
    }
  }
}
```

## Making Authenticated Requests

### Basic Authenticated Request

```swift
@Dependency(\.jwtAuthClient) var authClient

let userProfile: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
  .get("/user/profile")
)
```

### With Custom Configuration

```swift
let posts: SuccessResponse<[Post]> = try await authClient.sendAuthenticated(
  .get("/posts"),
  refreshExpiredToken: true,  // Default: true
  decoder: customDecoder,
  urlSession: customSession,
  timeoutInterval: 30
) {
  // Custom middleware
  addCustomHeaders()
}
```

### Handling Different Response Types

```swift
// For endpoints that might return errors
let result: Response<UserProfile, APIError> = try await authClient.sendAuthenticated(
  .get("/user/profile")
)

switch result {
case .success(let userProfile):
  // Handle success
  print("User: \(userProfile.name)")

case .failure(let apiError):
  // Handle API error
  print("API Error: \(apiError.message)")
}
```

## Token Refresh

Token refresh is handled automatically by the `sendAuthenticated` methods. However, you can also trigger it manually:

```swift
@Dependency(\.jwtAuthClient) var authClient

do {
  try await authClient.refreshExpiredTokens()
} catch AuthTokens.Error.missingToken {
  // No tokens available, redirect to login
} catch {
  // Refresh failed, tokens may be invalid
  // Clear tokens and redirect to login
  @Dependency(\.authTokensClient) var authTokensClient
  try await authTokensClient.destroy()
}
```

## Logout Flow

### Manual Logout

```swift
struct ProfileFeature: Reducer {
  @Dependency(\.authTokensClient) var authTokensClient

  enum Action {
    case logoutButtonTapped
    case logoutCompleted
  }

  func reduce(into state: inout State, action: Action) -> Effect<Action> {
    switch action {
    case .logoutButtonTapped:
      return .run { send in
        // Optional: Call logout endpoint
        _ = try? await authClient.send(.post("/auth/logout"))

        // Clear local tokens
        try await authTokensClient.destroy()
        await send(.logoutCompleted)
      }

    case .logoutCompleted:
      // Navigation handled by parent based on session state
      return .none
    }
  }
}
```

### Automatic Logout on Token Expiry

When refresh tokens expire, the client automatically clears all tokens:

```swift
// This happens automatically in JWTAuthClient.refreshExpiredTokens()
do {
  let newTokens = try await refresh(tokens)
  try await authTokensClient.set(newTokens)
} catch {
  // Refresh failed, clear all tokens
  try await authTokensClient.destroy()
}
```

## Session State Management

Monitor authentication state across your app:

```swift
struct AppView: View {
  @Shared(.authSession) var session

  var body: some View {
    switch session {
    case .none, .some(.missing):
      LoginView()

    case .some(.expired(let tokens)):
      // Optionally show "refreshing" UI
      // The client will automatically attempt refresh
      ProgressView("Refreshing session...")

    case .some(.valid(let tokens)):
      TabView {
        HomeView()
        ProfileView()
      }
    }
  }
}
```

## Error Handling

Handle various authentication errors:

```swift
do {
  let response = try await authClient.sendAuthenticated(.get("/protected-resource"))
} catch AuthTokens.Error.missingToken {
  // No tokens available
  redirectToLogin()
} catch AuthTokens.Error.expiredToken {
  // Token expired (shouldn't happen with auto-refresh)
  try await authClient.refreshExpiredTokens()
} catch AuthTokens.Error.invalidToken {
  // Token is malformed
  try await authTokensClient.destroy()
  redirectToLogin()
} catch {
  // Other network or API errors
  handleGeneralError(error)
}
```

## Best Practices

1. **Always use `sendAuthenticated`** for protected endpoints
2. **Let the client handle refresh** - don't disable `refreshExpiredToken` unless necessary
3. **Monitor session state** in your main app view
4. **Handle errors gracefully** and provide clear user feedback
5. **Clear tokens on critical errors** to ensure security
6. **Load session early** in your app lifecycle

## Next Steps

- <doc:TokenManagement> - Deep dive into token handling
- <doc:ErrorHandling> - Comprehensive error handling strategies
- <doc:Testing> - Testing authentication flows
