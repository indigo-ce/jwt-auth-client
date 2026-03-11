# Getting Started

This guide will help you integrate `JWTAuthClient` into your TCA application.

## Installation

Add the library to your Swift package:

```swift
.package(url: "https://github.com/indigo-ce/jwt-auth-client", from: "1.0.0")
```

Then add it to your target dependencies:

```swift
.target(
  name: "YourApp",
  dependencies: [
    .product(name: "JWTAuth", package: "jwt-auth-client")
  ]
)
```

## Quick Setup

### 1. Import the Library

```swift
import JWTAuth
import Dependencies
```

### 2. Configure the JWT Auth Client

Create a live implementation of the `JWTAuthClient`:

```swift
extension JWTAuthClient: @retroactive DependencyKey {
  static let liveValue = Self(
    baseURL: {
      "https://your-api.com/api"
    },
    refresh: { tokens in
      // Implement your token refresh logic here. For example:
      let request = URLRequest(url: URL(string: "https://your-api.com/api/auth/refresh")!)
      var request = request
      request.httpMethod = "POST"
      request.setValue("Bearer \(tokens.refresh)", forHTTPHeaderField: "Authorization")

      let (data, _) = try await URLSession.shared.data(for: request)
      let refreshResponse = try JSONDecoder().decode(TokenResponse.self, from: data)

      // Return new tokens
      return AuthTokens(
        access: refreshResponse.accessToken,
        refresh: refreshResponse.refreshToken
      )
    }
  )
}
```

### 3. Load Session on App Launch

In your app's initialization (typically in your `App` structure or main view):

```swift
@main
struct MyApp: App {
  var body: some Scene {
    WindowGroup {
      ContentView()
        .task {
          @Dependency(\.jwtAuthClient) var authClient

          do {
            try await authClient.loadSession()
          } catch {
            print("Failed to load session: \(error)")
          }
        }
    }
  }
}
```

### 4. Access Authentication State

Use the shared authentication session in your views and reducers:

```swift
struct ContentView: View {
  @Shared(.authSession) var session

  var body: some View {
    switch session {
    case .none, .some(.missing):
      LoginView()
    case .some(.expired):
      Text("Session expired. Please log in again.")
    case .some(.valid(let tokens)):
      MainAppView()
    }
  }
}
```

## Making Authenticated Requests

Once you have tokens, you can make authenticated API calls:

```swift
@Dependency(\.jwtAuthClient) var authClient

// The client automatically handles token refresh
let response: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
  .get("/user/profile")
)

let userProfile = response.data
```

## Next Steps

- <doc:AuthenticationFlow> - Detailed authentication implementation
- <doc:TokenManagement> - Managing tokens and sessions
- <doc:ErrorHandling> - Handling authentication errors
- <doc:Testing> - Testing your authentication implementation
