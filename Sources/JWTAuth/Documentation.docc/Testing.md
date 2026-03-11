# Testing JWT Authentication

This guide covers testing strategies for applications using the JWT Auth Client.

## Test Dependencies

### Setting Up Test Dependencies

```swift
import XCTest
import Dependencies
@testable import YourApp
@testable import JWTAuth

class AuthenticationTests: XCTestCase {
  override func setUp() {
    super.setUp()

    // Reset dependencies before each test
    DependencyValues._current = DependencyValues()
  }
}
```

## Mocking Clients

### Mock JWTAuthClient

```swift
extension JWTAuthClient {
  static func mock(
    baseURL: String = "https://test.api",
    refreshResult: Result<AuthTokens, Error> = .success(TestData.validTokens)
  ) -> Self {
    Self(
      baseURL: { baseURL },
      refresh: { _ in
        switch refreshResult {
        case .success(let tokens):
          return tokens
        case .failure(let error):
          throw error
        }
      }
    )
  }

  static let successMock = mock()

  static let failureMock = mock(
    refreshResult: .failure(AuthTokens.Error.expiredToken)
  )

  static let networkErrorMock = mock(
    refreshResult: .failure(URLError(.notConnectedToInternet))
  )
}
```

### Mock AuthTokensClient

```swift
extension AuthTokensClient {
  static func mock(
    saveError: Error? = nil,
    destroyError: Error? = nil
  ) -> Self {
    var savedTokens: AuthTokens?

    return Self(
      save: { tokens in
        if let error = saveError {
          throw error
        }
        savedTokens = tokens
      },
      destroy: {
        if let error = destroyError {
          throw error
        }
        savedTokens = nil
      }
    )
  }
}
```

### Mock KeychainClient

```swift
extension KeychainClient {
  static func mock(
    storage: [String: String] = [:],
    saveError: Error? = nil,
    loadError: Error? = nil
  ) -> Self {
    var mockStorage = storage

    return Self(
      save: { value, key in
        if let error = saveError {
          throw error
        }
        mockStorage[key.value] = value
      },
      load: { key in
        if let error = loadError {
          throw error
        }
        return mockStorage[key.value]
      },
      delete: { key in
        mockStorage.removeValue(forKey: key.value)
      },
      reset: {
        mockStorage.removeAll()
      }
    )
  }
}
```

## Test Data

### Creating Test Tokens

```swift
struct TestData {
  static let validTokens = AuthTokens(
    access: createTestJWT(
      claims: [
        "user_id": "test_user_123",
        "email": "test@example.com",
        "exp": Date().addingTimeInterval(3600).timeIntervalSince1970
      ]
    ),
    refresh: createTestJWT(
      claims: [
        "exp": Date().addingTimeInterval(86400).timeIntervalSince1970
      ]
    )
  )

  static let expiredTokens = AuthTokens(
    access: createTestJWT(
      claims: [
        "user_id": "test_user_123",
        "exp": Date().addingTimeInterval(-3600).timeIntervalSince1970 // Expired 1 hour ago
      ]
    ),
    refresh: createTestJWT(
      claims: [
        "exp": Date().addingTimeInterval(86400).timeIntervalSince1970
      ]
    )
  )

  static let invalidTokens = AuthTokens(
    access: "invalid.jwt.token",
    refresh: "invalid.jwt.token"
  )
}

func createTestJWT(claims: [String: Any]) -> String {
  // This is a simplified JWT creation for testing
  // In practice, you might use a JWT library or create properly signed tokens
  let header = ["alg": "HS256", "typ": "JWT"]
  let headerData = try! JSONSerialization.data(withJSONObject: header)
  let claimsData = try! JSONSerialization.data(withJSONObject: claims)

  let headerBase64 = headerData.base64EncodedString()
  let claimsBase64 = claimsData.base64EncodedString()

  return "\(headerBase64).\(claimsBase64).signature"
}
```

## Testing Authentication Flow

### Login Flow Test

```swift
func testLoginFlow() async throws {
  let mockAuthClient = AuthTokensClient.mock()

  await withDependencies {
    $0.authTokensClient = mockAuthClient
    $0.httpRequestClient = .mock(
      response: LoginResponse(
        accessToken: TestData.validTokens.access,
        refreshToken: TestData.validTokens.refresh
      )
    )
  } operation: {
    let store = TestStore(initialState: LoginFeature.State()) {
      LoginFeature()
    }

    // Test login action
    await store.send(.loginButtonTapped)

    // Verify tokens were saved
    await store.receive(.loginResponse(.success(loginResponse)))

    // Verify session state
    @Shared(.authSession) var session
    XCTAssertEqual(session, .valid(TestData.validTokens))
  }
}
```

### Logout Flow Test

```swift
func testLogoutFlow() async throws {
  // Start with valid session
  @Shared(.authSession) var session = .valid(TestData.validTokens)

  let mockAuthClient = AuthTokensClient.mock()

  await withDependencies {
    $0.authTokensClient = mockAuthClient
  } operation: {
    let store = TestStore(initialState: ProfileFeature.State()) {
      ProfileFeature()
    }

    await store.send(.logoutButtonTapped)
    await store.receive(.logoutCompleted)

    // Verify session was cleared
    XCTAssertEqual(session, .missing)
  }
}
```

## Testing Token Management

### Token Expiration Test

```swift
func testTokenExpiration() {
  let expiredTokens = TestData.expiredTokens
  XCTAssertTrue(expiredTokens.isExpired)

  let validTokens = TestData.validTokens
  XCTAssertFalse(validTokens.isExpired)
}
```

### Token Claims Test

```swift
func testTokenClaims() throws {
  let tokens = TestData.validTokens

  XCTAssertEqual(tokens[string: "user_id"], "test_user_123")
  XCTAssertEqual(tokens[string: "email"], "test@example.com")
  XCTAssertNil(tokens[string: "nonexistent_claim"])
}
```

### Session Conversion Test

```swift
func testSessionConversion() {
  let validTokens = TestData.validTokens
  let validSession = validTokens.toSession()

  if case .valid(let sessionTokens) = validSession {
    XCTAssertEqual(sessionTokens, validTokens)
  } else {
    XCTFail("Expected valid session")
  }

  let expiredTokens = TestData.expiredTokens
  let expiredSession = expiredTokens.toSession()

  if case .expired(let sessionTokens) = expiredSession {
    XCTAssertEqual(sessionTokens, expiredTokens)
  } else {
    XCTFail("Expected expired session")
  }
}
```

## Testing Error Scenarios

### Token Refresh Failure Test

```swift
func testTokenRefreshFailure() async throws {
  await withDependencies {
    $0.jwtAuthClient = .failureMock
    $0.authTokensClient = AuthTokensClient.mock()
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    @Shared(.authSession) var session

    // Set up expired session
    session = .expired(TestData.expiredTokens)

    do {
      try await authClient.refreshExpiredTokens()
      XCTFail("Expected refresh to fail")
    } catch AuthTokens.Error.expiredToken {
      // Expected error
    } catch {
      XCTFail("Unexpected error: \(error)")
    }

    // Verify session was cleared due to refresh failure
    XCTAssertEqual(session, .missing)
  }
}
```

### Keychain Error Test

```swift
func testKeychainSaveError() async throws {
  let keychainError = KeychainError.savingFailed(message: "Access denied")

  await withDependencies {
    $0.keychainClient = KeychainClient.mock(saveError: keychainError)
  } operation: {
    @Dependency(\.keychainClient) var keychainClient

    do {
      try await keychainClient.save("token", .accessToken)
      XCTFail("Expected save to fail")
    } catch KeychainError.savingFailed(let message) {
      XCTAssertEqual(message, "Access denied")
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }
}
```

### Network Error Test

```swift
func testNetworkError() async throws {
  await withDependencies {
    $0.jwtAuthClient = .networkErrorMock
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient

    do {
      try await authClient.refreshExpiredTokens()
      XCTFail("Expected network error")
    } catch let error as URLError {
      XCTAssertEqual(error.code, .notConnectedToInternet)
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
  }
}
```

## Testing HTTP Requests

### Authenticated Request Test

```swift
func testAuthenticatedRequest() async throws {
  let mockHTTPClient = HTTPRequestClient.mock(
    response: UserProfile(id: "123", name: "Test User")
  )

  await withDependencies {
    $0.jwtAuthClient = JWTAuthClient.mock()
    $0.httpRequestClient = mockHTTPClient
    $0.authTokensClient = AuthTokensClient.mock()
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    @Shared(.authSession) var session = .valid(TestData.validTokens)

    let response: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
      .get("/user/profile")
    )

    XCTAssertEqual(response.data.name, "Test User")

    // Verify authorization header was added
    let lastRequest = mockHTTPClient.lastRequest
    XCTAssertEqual(
      lastRequest?.headers["Authorization"],
      "Bearer \(TestData.validTokens.access)"
    )
  }
}
```

### Request Without Authentication Test

```swift
func testRequestWithoutAuthentication() async throws {
  await withDependencies {
    $0.jwtAuthClient = JWTAuthClient.mock()
    $0.httpRequestClient = HTTPRequestClient.mock(response: PublicData())
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient

    let response: SuccessResponse<PublicData> = try await authClient.send(
      .get("/public/data")
    )

    XCTAssertNotNil(response.data)
  }
}
```

## Testing Session State

### Session Loading Test

```swift
func testSessionLoading() async throws {
  let storedTokens = TestData.validTokens

  await withDependencies {
    $0.keychainClient = KeychainClient.mock(storage: [
      "accessToken": storedTokens.access,
      "refreshToken": storedTokens.refresh
    ])
    $0.jwtAuthClient = JWTAuthClient.mock()
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    @Shared(.authSession) var session

    // Initially no session
    XCTAssertNil(session)

    try await authClient.loadSession()

    // Session should be loaded from keychain
    XCTAssertEqual(session, .valid(storedTokens))
  }
}
```

### Session State Changes Test

```swift
func testSessionStateChanges() {
  @Shared(.authSession) var session

  // Test initial state
  XCTAssertNil(session)

  // Test setting valid session
  session = .valid(TestData.validTokens)
  XCTAssertEqual(session?.tokens, TestData.validTokens)
  XCTAssertFalse(session?.isExpired ?? true)

  // Test setting expired session
  session = .expired(TestData.expiredTokens)
  XCTAssertEqual(session?.tokens, TestData.expiredTokens)
  XCTAssertTrue(session?.isExpired ?? false)

  // Test clearing session
  session = .missing
  XCTAssertNil(session?.tokens)
  XCTAssertFalse(session?.isExpired ?? true)
}
```

## Integration Tests

### Full Authentication Flow Test

```swift
func testFullAuthenticationFlow() async throws {
  let mockKeychainClient = KeychainClient.mock()
  let mockAuthTokensClient = AuthTokensClient.mock()

  await withDependencies {
    $0.jwtAuthClient = JWTAuthClient.mock()
    $0.keychainClient = mockKeychainClient
    $0.authTokensClient = mockAuthTokensClient
    $0.httpRequestClient = HTTPRequestClient.mock(
      response: LoginResponse(
        accessToken: TestData.validTokens.access,
        refreshToken: TestData.validTokens.refresh
      )
    )
  } operation: {
    @Dependency(\.jwtAuthClient) var authClient
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session

    // 1. Initial state - no session
    XCTAssertNil(session)

    // 2. Simulate login
    let tokens = TestData.validTokens
    try await authTokensClient.save(tokens)

    // 3. Load session
    try await authClient.loadSession()
    XCTAssertEqual(session, .valid(tokens))

    // 4. Make authenticated request
    let response: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
      .get("/user/profile")
    )
    XCTAssertNotNil(response.data)

    // 5. Logout
    try await authTokensClient.destroy()
    XCTAssertEqual(session, .missing)
  }
}
```

## Performance Tests

### Token Parsing Performance

```swift
func testTokenParsingPerformance() {
  let tokens = TestData.validTokens

  measure {
    for _ in 0..<1000 {
      _ = tokens.isExpired
      _ = tokens[string: "user_id"]
    }
  }
}
```

### Keychain Performance

```swift
func testKeychainPerformance() async throws {
  await withDependencies {
    $0.keychainClient = KeychainClient.mock()
  } operation: {
    @Dependency(\.keychainClient) var keychainClient

    measure {
      Task {
        for i in 0..<100 {
          try await keychainClient.save("token_\(i)", .accessToken)
          _ = try await keychainClient.load(.accessToken)
        }
      }
    }
  }
}
```

## Test Utilities

### Custom Assertions

```swift
func XCTAssertTokensEqual(_ tokens1: AuthTokens?, _ tokens2: AuthTokens?, file: StaticString = #file, line: UInt = #line) {
  guard let tokens1 = tokens1, let tokens2 = tokens2 else {
    XCTAssertEqual(tokens1, tokens2, file: file, line: line)
    return
  }

  XCTAssertEqual(tokens1.access, tokens2.access, file: file, line: line)
  XCTAssertEqual(tokens1.refresh, tokens2.refresh, file: file, line: line)
}

func XCTAssertSessionValid(_ session: AuthSession?, file: StaticString = #file, line: UInt = #line) {
  guard case .valid = session else {
    XCTFail("Expected valid session, got \(session.map(String.init(describing:)) ?? "nil")", file: file, line: line)
    return
  }
}
```

### Test Helpers

```swift
extension TestStore {
  func expectAuthenticationError<Action>(_ action: Action) async where Action: Equatable {
    do {
      await self.send(action)
      XCTFail("Expected authentication error")
    } catch {
      XCTAssertTrue(error is AuthTokens.Error)
    }
  }
}
```

## Best Practices

1. **Use dependency injection** for all external dependencies
2. **Test both success and failure paths** for every authentication operation
3. **Mock network requests** to avoid flaky tests
4. **Test edge cases** like expired tokens and network errors
5. **Verify side effects** like keychain operations and session state changes
6. **Use realistic test data** that matches your production JWT format
7. **Test performance** for operations that might be called frequently
8. **Clean up state** between tests to avoid test interference

## Next Steps

- <doc:AdvancedUsage> - Advanced patterns and customizations
- Review the complete example app in the repository for more testing patterns
