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

Token refresh is handled automatically by the `sendAuthenticated` methods. However, you can also trigger it manually.

`refreshExpiredTokens()` distinguishes between two failure modes:

- **`AuthTokens.Error.refreshRejected`** — the server definitively rejected
  the refresh token (e.g. 401 from `/auth/refresh`). The stored credentials
  are automatically destroyed; the session becomes `.missing`. You can
  observe this either via the thrown error (if the rejection was thrown
  through `refreshExpiredTokens` directly — which currently swallows it and
  lets `session?.tokens` go nil), or simply by watching `@Shared(.authSession)`.
- **Any other error** — a transient failure (no network, timeout, decode
  error, etc.). The stored credentials are **preserved**, and the error is
  rethrown so you can show a retry option instead of silently logging the
  user out.

```swift
@Dependency(\.jwtAuthClient) var authClient

do {
  try await authClient.refreshExpiredTokens()
} catch AuthTokens.Error.missingToken {
  // No tokens in storage — route the user to login.
  redirectToLogin()
} catch {
  // Transient failure (network, timeout, decode, keychain, etc).
  // The stored refresh token is still valid — show a retry option.
  showRetryAlert(error: error) {
    try await authClient.refreshExpiredTokens()
  }
}
```

> ⚠️ **Do not** call `authTokensClient.destroy()` from the generic `catch`
> block. `refreshExpiredTokens()` already destroys credentials when the
> server explicitly rejects the refresh token; wiping them on any other
> failure will log the user out for a transient network hiccup.

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

When the server definitively rejects a refresh token, the client clears all
stored credentials — but only in that case. Transient refresh failures
(network down, timeout, DNS error, etc.) preserve the credentials so a
later retry can succeed.

```swift
// This happens automatically inside JWTAuthClient.refreshExpiredTokens():
do {
  let newTokens = try await refresh(tokens)
  try await authTokensClient.set(newTokens)
} catch AuthTokens.Error.refreshRejected {
  // Server rejected the refresh token — credentials are gone.
  try await authTokensClient.destroy()
} catch {
  // Transient failure — leave the existing tokens alone so a later
  // retry (next launch, next request, etc) can succeed.
  throw error
}
```

To opt into this behavior from your `refresh` closure, throw
`AuthTokens.Error.refreshRejected` when the server explicitly rejects the
refresh token:

```swift
extension JWTAuthClient: @retroactive DependencyKey {
  static let liveValue = Self(
    baseURL: { "https://api.example.com" },
    refresh: { tokens in
      let response: TokenResponse = try await httpClient.send(
        baseURL: host, decoder: .api, urlSession: session
      ) {
        Path("api", "v1", "auth", "refresh")
        post(RefreshTokenRequest(refreshToken: tokens.refresh), encoder: .api)
      }.value

      return AuthTokens(
        access: response.accessToken,
        refresh: response.refreshToken
      )
    }
  )
}
```

If `httpClient.send` throws a `URLError` (e.g. `cannotConnectToHost`) or
any other transport-level error, `refreshExpiredTokens()` will treat it as
transient, preserve the credentials, and rethrow. If it throws because the
server returned a 401, your `refresh` closure should re-throw it as
`AuthTokens.Error.refreshRejected` so the library can destroy the
credentials — for example:

```swift
refresh: { tokens in
  do {
    let response: TokenResponse = try await httpClient.send(
      baseURL: host, decoder: .api, urlSession: session
    ) {
      Path("api", "v1", "auth", "refresh")
      post(RefreshTokenRequest(refreshToken: tokens.refresh), encoder: .api)
    }.value
    return AuthTokens(
      access: response.accessToken,
      refresh: response.refreshToken
    )
  } catch let error as APIError where error.statusCode == 401 {
    // Server explicitly rejected the refresh token.
    throw AuthTokens.Error.refreshRejected
  }
  // Any other error propagates and is treated as transient.
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
} catch AuthTokens.Error.refreshRejected {
  // Server rejected the refresh token. `refreshExpiredTokens()` has
  // already destroyed the credentials — just route to login.
  redirectToLogin()
} catch {
  // Transient failure (network, timeout, decode, etc.). The refresh
  // token is still valid; show a retry option instead of logging out.
  showRetryAlert(error: error) {
    try await authClient.sendAuthenticated(.get("/protected-resource"))
  }
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
