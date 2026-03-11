# Advanced Usage

This guide covers advanced patterns, customizations, and integration strategies for the JWT Auth Client.

## Custom Token Storage

### Implementing Custom Storage

While the default implementation uses keychain storage, you can implement custom storage:

```swift
struct CloudKeychainClient: Sendable {
  let cloudService: CloudStorageService

  func save(_ value: String, as key: KeychainClient.Keys) async throws {
    // Save to cloud storage with encryption
    let encryptedValue = try encrypt(value)
    try await cloudService.store(encryptedValue, forKey: key.value)

    // Also save locally as backup
    try await localKeychain.save(value, key)
  }

  func load(_ key: KeychainClient.Keys) async throws -> String? {
    // Try cloud first, fallback to local
    if let cloudValue = try await cloudService.retrieve(key.value) {
      return try decrypt(cloudValue)
    }

    return try await localKeychain.load(key)
  }
}

// Register the custom client
extension KeychainClient: DependencyKey {
  static let liveValue = KeychainClient { value, key in
    try await CloudKeychainClient().save(value, as: key)
  } load: { key in
    try await CloudKeychainClient().load(key)
  } delete: { key in
    try await cloudService.delete(key.value)
    try await localKeychain.delete(key)
  } reset: {
    try await cloudService.deleteAll()
    try await localKeychain.reset()
  }
}
```

### Multi-User Token Storage

Support multiple user accounts:

```swift
extension KeychainClient.Keys {
  static func accessToken(for userId: String) -> KeychainClient.Keys {
    Self(value: "accessToken_\(userId)")
  }

  static func refreshToken(for userId: String) -> KeychainClient.Keys {
    Self(value: "refreshToken_\(userId)")
  }
}

struct MultiUserAuthTokensClient: Sendable {
  let currentUserId: () -> String?

  @Dependency(\.keychainClient) var keychainClient

  func save(_ tokens: AuthTokens) async throws {
    guard let userId = currentUserId() else {
      throw AuthError.noCurrentUser
    }

    try await keychainClient.save(tokens.access, .accessToken(for: userId))
    try await keychainClient.save(tokens.refresh, .refreshToken(for: userId))

    // Update session for current user
    @Shared(.authSession) var session
    $session.withLock { $0 = tokens.toSession() }
  }

  func loadTokens(for userId: String) async throws -> AuthTokens? {
    let accessToken = try await keychainClient.load(.accessToken(for: userId))
    let refreshToken = try await keychainClient.load(.refreshToken(for: userId))

    guard let accessToken, let refreshToken else { return nil }

    return AuthTokens(access: accessToken, refresh: refreshToken)
  }
}
```

## Advanced Request Middleware

### Request Signing Middleware

Add request signing for additional security:

```swift
func requestSigning(secret: String) -> RequestMiddleware {
  { request in
    let timestamp = String(Int(Date().timeIntervalSince1970))
    let signature = HMAC.sha256(
      message: request.body + timestamp,
      key: secret
    )

    return request
      .header("X-Timestamp", timestamp)
      .header("X-Signature", signature)
  }
}

// Usage
let response = try await authClient.sendAuthenticated(
  .post("/sensitive-operation")
  .body(operationData)
) {
  requestSigning(secret: "your-secret-key")
}
```

### Request Retry Middleware

Implement intelligent retry logic:

```swift
func retryMiddleware(maxRetries: Int = 3) -> RequestMiddleware {
  { request in
    var attempt = 0
    var lastError: Error?

    while attempt < maxRetries {
      do {
        return try await request.execute()
      } catch {
        lastError = error
        attempt += 1

        if shouldRetry(error) && attempt < maxRetries {
          let delay = exponentialBackoff(attempt: attempt)
          try await Task.sleep(nanoseconds: delay)
          continue
        }

        throw error
      }
    }

    throw lastError!
  }
}

func shouldRetry(_ error: Error) -> Bool {
  if let urlError = error as? URLError {
    return [.timedOut, .networkConnectionLost].contains(urlError.code)
  }
  return false
}

func exponentialBackoff(attempt: Int) -> UInt64 {
  let baseDelay: UInt64 = 1_000_000_000 // 1 second in nanoseconds
  return baseDelay * UInt64(pow(2.0, Double(attempt - 1)))
}
```

### Request Caching Middleware

Cache responses for improved performance:

```swift
actor RequestCache {
  private var cache: [String: (data: Data, expiry: Date)] = [:]

  func get(for key: String) -> Data? {
    guard let entry = cache[key], entry.expiry > Date() else {
      cache.removeValue(forKey: key)
      return nil
    }
    return entry.data
  }

  func set(_ data: Data, for key: String, ttl: TimeInterval = 300) {
    cache[key] = (data, Date().addingTimeInterval(ttl))
  }
}

func cachingMiddleware(cache: RequestCache, ttl: TimeInterval = 300) -> RequestMiddleware {
  { request in
    let cacheKey = request.cacheKey

    // Check cache for GET requests
    if request.method == .get,
       let cachedData = await cache.get(for: cacheKey) {
      return try JSONDecoder().decode(Response.self, from: cachedData)
    }

    let response = try await request.execute()

    // Cache successful GET responses
    if request.method == .get,
       let responseData = try? JSONEncoder().encode(response) {
      await cache.set(responseData, for: cacheKey, ttl: ttl)
    }

    return response
  }
}
```

## Token Introspection

### Token Validation Service

Create a service for detailed token validation:

```swift
struct TokenValidator: Sendable {
  @Dependency(\.jwtAuthClient) var authClient

  func validateToken(_ tokens: AuthTokens) async throws -> TokenValidation {
    // Basic JWT validation
    let jwt = try tokens.toJWT()

    var validation = TokenValidation(
      isExpired: jwt.expired,
      expiresAt: jwt.expiresAt,
      claims: jwt.body
    )

    // Server-side validation
    if !validation.isExpired {
      validation.serverValidation = try await validateWithServer(tokens)
    }

    return validation
  }

  private func validateWithServer(_ tokens: AuthTokens) async throws -> ServerValidation {
    let response: SuccessResponse<TokenStatus> = try await authClient.sendAuthenticated(
      .post("/auth/validate")
    )

    return ServerValidation(
      isValid: response.data.valid,
      permissions: response.data.permissions,
      rateLimit: response.data.rateLimit
    )
  }
}

struct TokenValidation {
  let isExpired: Bool
  let expiresAt: Date?
  let claims: [String: Any]
  var serverValidation: ServerValidation?
}

struct ServerValidation {
  let isValid: Bool
  let permissions: [String]
  let rateLimit: RateLimit
}
```

### Token Analytics

Track token usage and performance:

```swift
actor TokenAnalytics {
  private var metrics: [String: TokenMetric] = [:]

  func recordTokenUsage(_ tokens: AuthTokens, for endpoint: String) {
    let key = tokens[string: "user_id"] ?? "unknown"

    if metrics[key] == nil {
      metrics[key] = TokenMetric()
    }

    metrics[key]?.recordRequest(to: endpoint)
  }

  func recordTokenRefresh(successful: Bool, duration: TimeInterval) {
    // Track refresh performance
    let metric = RefreshMetric(
      timestamp: Date(),
      successful: successful,
      duration: duration
    )

    // Send to analytics service
  }

  func getMetrics(for userId: String) -> TokenMetric? {
    return metrics[userId]
  }
}

struct TokenMetric {
  private(set) var requestCount = 0
  private(set) var lastUsed = Date()
  private(set) var endpoints: Set<String> = []

  mutating func recordRequest(to endpoint: String) {
    requestCount += 1
    lastUsed = Date()
    endpoints.insert(endpoint)
  }
}
```

## Advanced Session Management

### Session Migration

Handle session format changes:

```swift
struct SessionMigrator {
  func migrateIfNeeded() async throws {
    let currentVersion = await getCurrentSessionVersion()
    let latestVersion = 2

    if currentVersion < latestVersion {
      try await performMigration(from: currentVersion, to: latestVersion)
    }
  }

  private func performMigration(from: Int, to: Int) async throws {
    switch (from, to) {
    case (1, 2):
      try await migrateV1ToV2()
    default:
      break
    }
  }

  private func migrateV1ToV2() async throws {
    // Load old format tokens
    @Dependency(\.keychainClient) var keychainClient

    if let oldAccessToken = try await keychainClient.load(.init(value: "old_access_token")),
       let oldRefreshToken = try await keychainClient.load(.init(value: "old_refresh_token")) {

      // Convert to new format
      let newTokens = AuthTokens(
        access: oldAccessToken,
        refresh: oldRefreshToken
      )

      // Save in new format
      @Dependency(\.authTokensClient) var authTokensClient
      try await authTokensClient.save(newTokens)

      // Clean up old format
      try await keychainClient.delete(.init(value: "old_access_token"))
      try await keychainClient.delete(.init(value: "old_refresh_token"))
    }

    // Update version
    await setSessionVersion(2)
  }
}
```

### Session Synchronization

Sync sessions across multiple app instances:

```swift
actor SessionSynchronizer {
  private let syncService: SessionSyncService

  func synchronizeSession() async throws {
    @Shared(.authSession) var localSession
    let remoteSession = try await syncService.getRemoteSession()

    // Resolve conflicts (latest wins)
    if let remote = remoteSession,
       let local = localSession,
       remote.lastUpdated > local.lastUpdated {

      localSession = remote.session
      try await saveSessionLocally(remote.session)
    } else if let local = localSession {
      try await syncService.updateRemoteSession(local)
    }
  }

  func observeRemoteChanges() async {
    for await remoteSession in syncService.sessionUpdates {
      @Shared(.authSession) var localSession

      if remoteSession.session != localSession {
        localSession = remoteSession.session
        try await saveSessionLocally(remoteSession.session)
      }
    }
  }
}
```

## Custom Authentication Flows

### Biometric Authentication

Integrate biometric authentication:

```swift
import LocalAuthentication

struct BiometricAuthClient: Sendable {
  func authenticateWithBiometrics() async throws -> Bool {
    let context = LAContext()

    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
      throw BiometricError.notAvailable
    }

    let reason = "Authenticate to access your account"

    return try await context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: reason
    )
  }

  func saveTokensWithBiometricProtection(_ tokens: AuthTokens) async throws {
    guard try await authenticateWithBiometrics() else {
      throw BiometricError.authenticationFailed
    }

    @Dependency(\.authTokensClient) var authTokensClient
    try await authTokensClient.save(tokens)
  }

  func loadTokensWithBiometricProtection() async throws -> AuthTokens? {
    guard try await authenticateWithBiometrics() else {
      throw BiometricError.authenticationFailed
    }

    @Dependency(\.keychainClient) var keychainClient
    return try await keychainClient.loadTokens()
  }
}

enum BiometricError: Error {
  case notAvailable
  case authenticationFailed
}
```

### Multi-Factor Authentication

Handle MFA challenges:

```swift
struct MFAAuthClient: Sendable {
  @Dependency(\.jwtAuthClient) var authClient

  func loginWithMFA(credentials: LoginCredentials) async throws -> AuthResult {
    let response: Response<LoginSuccess, LoginError> = try await authClient.send(
      .post("/auth/login")
      .body(credentials)
    )

    switch response {
    case .success(let success):
      let tokens = AuthTokens(
        access: success.accessToken,
        refresh: success.refreshToken
      )

      @Dependency(\.authTokensClient) var authTokensClient
      try await authTokensClient.save(tokens)

      return .success(tokens)

    case .failure(let error) where error.code == "MFA_REQUIRED":
      return .mfaRequired(
        challenge: error.mfaChallenge,
        sessionId: error.sessionId
      )

    case .failure(let error):
      throw AuthError.loginFailed(error.message)
    }
  }

  func completeMFAChallenge(
    sessionId: String,
    code: String
  ) async throws -> AuthTokens {
    let request = MFARequest(sessionId: sessionId, code: code)

    let response: SuccessResponse<LoginSuccess> = try await authClient.send(
      .post("/auth/mfa/verify")
      .body(request)
    )

    let tokens = AuthTokens(
      access: response.data.accessToken,
      refresh: response.data.refreshToken
    )

    @Dependency(\.authTokensClient) var authTokensClient
    try await authTokensClient.save(tokens)

    return tokens
  }
}

enum AuthResult {
  case success(AuthTokens)
  case mfaRequired(challenge: MFAChallenge, sessionId: String)
}
```

## Performance Optimization

### Token Preloading

Preload tokens to reduce latency:

```swift
actor TokenPreloader {
  private var preloadedTokens: AuthTokens?
  private var preloadTask: Task<AuthTokens?, Never>?

  func preloadTokens() {
    preloadTask = Task {
      @Dependency(\.keychainClient) var keychainClient
      return try? await keychainClient.loadTokens()
    }
  }

  func getPreloadedTokens() async -> AuthTokens? {
    if let tokens = preloadedTokens {
      return tokens
    }

    if let task = preloadTask {
      preloadedTokens = await task.value
      preloadTask = nil
      return preloadedTokens
    }

    return nil
  }
}
```

### Connection Pooling

Optimize network connections:

```swift
extension URLSession {
  static let authOptimized: URLSession = {
    let config = URLSessionConfiguration.default
    config.httpMaximumConnectionsPerHost = 6
    config.requestCachePolicy = .reloadIgnoringLocalCacheData
    config.timeoutIntervalForRequest = 10
    config.timeoutIntervalForResource = 30

    return URLSession(configuration: config)
  }()
}

// Use optimized session
let response = try await authClient.sendAuthenticated(
  .get("/user/profile"),
  urlSession: .authOptimized
)
```

## Integration Patterns

### SwiftUI Integration

Create SwiftUI-specific helpers:

```swift
@propertyWrapper
struct AuthenticatedState<T>: DynamicProperty {
  @Shared(.authSession) private var session
  @Dependency(\.jwtAuthClient) private var authClient
  @State private var state: LoadingState<T> = .idle

  let loader: (AuthTokens) async throws -> T

  var wrappedValue: LoadingState<T> {
    state
  }

  func loadData() async {
    guard case .valid(let tokens) = session else {
      state = .failed(AuthError.notAuthenticated)
      return
    }

    state = .loading

    do {
      let data = try await loader(tokens)
      state = .loaded(data)
    } catch {
      state = .failed(error)
    }
  }
}

enum LoadingState<T> {
  case idle
  case loading
  case loaded(T)
  case failed(Error)
}

// Usage
struct ProfileView: View {
  @AuthenticatedState(loader: { tokens in
    // Load user profile using tokens
    try await APIService.loadProfile(with: tokens)
  }) var profileState

  var body: some View {
    switch profileState {
    case .idle:
      Color.clear.task { await profileState.loadData() }
    case .loading:
      ProgressView()
    case .loaded(let profile):
      ProfileDetailView(profile: profile)
    case .failed(let error):
      ErrorView(error: error) {
        await profileState.loadData()
      }
    }
  }
}
```

### Async Integration

Observe auth session changes using Swift's Observation framework:

```swift
// Observe session changes as an AsyncSequence
let isLoggedIn = Observations {
  @Shared(.authSession) var session
  return session != nil
}

Task {
  for await loggedIn in isLoggedIn {
    print("Auth state changed — logged in:", loggedIn)
  }
}
```

### TCA Integration

Use `Effect.run` with a `for await` loop to trigger reducer actions on session changes. Capture the projected `Shared` value from state so the observation stays live across effect re-entrance:

```swift
@Reducer
struct AppFeature {
  struct State: Equatable {
    @Shared(.authSession) var session: AuthSession?
  }

  enum Action {
    case task
    case authStateChanged(Bool)
  }

  var body: some Reducer<State, Action> {
    Reduce { state, action in
      switch action {
      case .task:
        return .run { [session = state.$session] send in
          for await isLoggedIn in Observations({ session.wrappedValue != nil }) {
            await send(.authStateChanged(isLoggedIn))
          }
        }
        .cancellable(id: CancelID.authObservation)

      case .authStateChanged(let isLoggedIn):
        // update state, trigger navigation, etc.
        return .none
      }
    }
  }

  enum CancelID { case authObservation }
}
```

Start the observation from the view using `.task`:

```swift
.task { await store.send(.task).finish() }
```

## Security Enhancements

### Token Encryption

Add client-side token encryption:

```swift
import CryptoKit

struct EncryptedTokenStorage {
  private let key: SymmetricKey

  init() {
    // Generate or retrieve encryption key
    self.key = SymmetricKey(size: .bits256)
  }

  func encrypt(_ token: String) throws -> Data {
    let data = Data(token.utf8)
    let sealedBox = try AES.GCM.seal(data, using: key)
    return sealedBox.combined!
  }

  func decrypt(_ encryptedData: Data) throws -> String {
    let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
    let decryptedData = try AES.GCM.open(sealedBox, using: key)
    return String(data: decryptedData, encoding: .utf8)!
  }
}
```

### Certificate Pinning

Implement certificate pinning:

```swift
class CertificatePinningDelegate: NSObject, URLSessionDelegate {
  private let pinnedCertificates: [SecCertificate]

  init(certificates: [SecCertificate]) {
    self.pinnedCertificates = certificates
  }

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
      completionHandler(.performDefaultHandling, nil)
      return
    }

    if validateCertificate(serverTrust) {
      completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }

  private func validateCertificate(_ serverTrust: SecTrust) -> Bool {
    // Implement certificate validation logic
    return true // Simplified for example
  }
}
```

This completes the comprehensive documentation for the JWT Auth Client. The guides cover:

1. **Getting Started** - Basic setup and integration
2. **Authentication Flow** - Complete authentication implementation
3. **Token Management** - Advanced token handling
4. **Error Handling** - Comprehensive error strategies
5. **Testing** - Testing patterns and best practices
6. **Advanced Usage** - Advanced patterns and customizations

Each guide builds upon the previous ones and provides practical, real-world examples that developers can use immediately.
