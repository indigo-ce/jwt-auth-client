import Dependencies
import DependenciesMacros
import Foundation
import HTTPRequestBuilder
import HTTPRequestClient
import Pulse
import Sharing

/// A client for handling JWT-based authentication in Swift applications using TCA.
///
/// `JWTAuthClient` provides a comprehensive solution for managing JWT authentication,
/// including token refresh, session management, and authenticated HTTP requests.
///
/// ## Overview
///
/// This client handles:
/// - JWT token validation and refresh
/// - Session persistence and loading
/// - Authenticated HTTP requests with automatic token refresh
/// - Integration with Swift Composable Architecture dependency system
///
/// ## Usage
///
/// ### Setting up the Client
///
/// ```swift
/// extension JWTAuthClient: @retroactive DependencyKey {
///   static let liveValue = Self(
///     baseURL: { "https://api.example.com" },
///     refresh: { tokens in
///       // Your token refresh logic here
///       return try await refreshTokensFromServer(tokens)
///     }
///   )
/// }
/// ```
///
/// ### Making Authenticated Requests
///
/// ```swift
/// @Dependency(\.jwtAuthClient) var authClient
///
/// // Send authenticated request
/// let response: SuccessResponse<UserProfile> = try await authClient.sendAuthenticated(
///   .get("/profile")
/// )
/// ```
///
/// ### Loading Session
///
/// ```swift
/// // Load session from keychain on app launch
/// try await authClient.loadSession()
/// ```
@DependencyClient
public struct JWTAuthClient: Sendable {
  /// The base URL for API requests.
  ///
  /// This closure should return the base URL string for your API.
  /// It's called each time a request is made, allowing for dynamic base URL configuration.
  public var baseURL: @Sendable () throws -> String
  
  /// Refreshes the provided authentication tokens.
  ///
  /// This closure should implement your token refresh logic, typically by calling
  /// your API's token refresh endpoint with the provided refresh token.
  ///
  /// ## Reporting failures
  ///
  /// The error type thrown from this closure controls how
  /// `JWTAuthClient.refreshExpiredTokens()` reacts:
  ///
  /// - Throw ``AuthTokens/Error/refreshRejected`` when the server *explicitly*
  ///   rejected the refresh token — for example, an HTTP 401 from
  ///   `/auth/refresh`, an expired or revoked refresh token, or a server-side
  ///   logout. `refreshExpiredTokens()` will treat this as a definitive
  ///   rejection, destroy the stored credentials, and force the user to log in
  ///   again.
  /// - Throw any other error to indicate a *transient* failure: the network
  ///   is unreachable, the request timed out, DNS failed, the response could
  ///   not be decoded, etc. `refreshExpiredTokens()` will leave the existing
  ///   tokens intact (so a later retry can succeed) and rethrow the error to
  ///   the caller so it can decide whether to surface a retry option.
  ///
  /// Concretely, the typical implementation looks like this:
  ///
  /// ```swift
  /// refresh: { tokens in
  ///   do {
  ///     let response: TokenResponse = try await httpClient.send(
  ///       baseURL: host, decoder: .api, urlSession: session
  ///     ) {
  ///       Path("api", "v1", "auth", "refresh")
  ///       post(RefreshTokenRequest(refreshToken: tokens.refresh), encoder: .api)
  ///     }.value
  ///     return AuthTokens(access: response.accessToken, refresh: response.refreshToken)
  ///   } catch let error as APIError where error.statusCode == 401 {
  ///     // Server explicitly said the refresh token is no longer valid.
  ///     throw AuthTokens.Error.refreshRejected
  ///   }
  ///   // Any other error (URLError, decoding failure, 5xx, etc.) is
  ///   // automatically treated as transient.
  /// }
  /// ```
  ///
  /// - Parameter authTokens: The current tokens to be refreshed
  /// - Returns: New authentication tokens from the server
  /// - Throws:
  ///   - ``AuthTokens/Error/refreshRejected`` to signal a definitive server-side
  ///     rejection (see above).
  ///   - Any other error to signal a transient failure (network, timeout, decode,
  ///     etc.). These are rethrown to the caller of `refreshExpiredTokens()` and
  ///     leave the stored tokens untouched.
  public var refresh: @Sendable (_ authTokens: AuthTokens) async throws -> AuthTokens
}

extension DependencyValues {
  public var jwtAuthClient: JWTAuthClient {
    get { self[JWTAuthClient.self] }
    set { self[JWTAuthClient.self] = newValue }
  }
}

extension JWTAuthClient: TestDependencyKey {
  public static let previewValue = Self(
    baseURL: { "" },
    refresh: { _ in .init(access: "access", refresh: "refresh") }
  )

  public static let testValue = Self()
}

extension JWTAuthClient {
  /// Loads the authentication session from the keychain into memory.
  ///
  /// This method retrieves stored authentication tokens from the keychain and
  /// loads them into the shared session state. It should typically be called
  /// during app initialization to restore the user's authentication state.
  ///
  /// The method will only load the session if no session is currently in memory,
  /// preventing unnecessary keychain operations.
  ///
  /// - Throws: An error if the keychain operation fails
  ///
  /// ## Usage
  ///
  /// ```swift
  /// @Dependency(\.jwtAuthClient) var authClient
  /// 
  /// // Load session on app launch
  /// try await authClient.loadSession()
  /// ```
  public func loadSession() async throws {
    @Shared(.authSession) var session
    @Dependency(\.keychainClient) var keychainClient

    guard
      session == nil
    else { return }

    let tokens = try await keychainClient.loadTokens()
    $session.withLock { $0 = tokens?.toSession() }
  }

  /// Refreshes expired authentication tokens and persists the new tokens.
  ///
  /// This method checks if the current access token is expired and, if so,
  /// attempts to refresh it using the refresh token. The new tokens are
  /// automatically persisted to the keychain and updated in the shared session.
  ///
  /// ## Error handling
  ///
  /// How this method reacts to a failure of the `refresh` closure depends on
  /// *what* error is thrown:
  ///
  /// - If `refresh` throws ``AuthTokens/Error/refreshRejected`` — meaning the
  ///   server definitively rejected the refresh token (e.g. 401 from
  ///   `/auth/refresh`, revoked refresh token) — the stored credentials are
  ///   destroyed, the session becomes `.missing`, and this method returns
  ///   without throwing. Callers that fall through to `session?.tokens` (like
  ///   `sendAuthenticated`) will then see no tokens and throw
  ///   ``AuthTokens/Error/missingToken`` themselves.
  /// - If `refresh` throws *any other* error — meaning the failure is
  ///   transient (no network, timeout, DNS failure, decode error, server
  ///   unreachable, etc.) — the stored credentials are **left intact** so a
  ///   later retry can succeed. The error is rethrown so callers can decide
  ///   whether to surface a retry option instead of silently logging the user
  ///   out. A concurrent session change (logout, new-user login) that lands
  ///   while the refresh is in flight is therefore preserved.
  /// - If `authTokensClient.set(newTokens)` throws (for example a keychain
  ///   save failure), the in-memory session is rolled back to the old
  ///   `.expired(tokens)` — the live `AuthTokensClient` writes the new tokens
  ///   to `@Shared(.authSession)` before attempting the keychain writes, so
  ///   without this rollback memory would be left on the new tokens while the
  ///   keychain is partial. The check-and-rollback is performed atomically
  ///   via `withLock` so a concurrent session change observed during the
  ///   catch is not overwritten — we only roll back when the session still
  ///   holds the new tokens we just persisted.
  ///
  /// In other words: only an explicit rejection from the server destroys the
  /// session. Anything else is treated as a transient hiccup and the user
  /// keeps their session.
  ///
  /// - Throws:
  ///   - ``AuthTokens/Error/missingToken`` if no tokens are available.
  ///   - Any error thrown by `refresh` (other than ``AuthTokens/Error/refreshRejected``)
  ///     — see "Error handling" above.
  ///   - Any error thrown by `authTokensClient.set(newTokens)`, after rolling
  ///     back the in-memory session.
  ///
  /// ## Usage
  ///
  /// ```swift
  /// @Dependency(\.jwtAuthClient) var authClient
  ///
  /// // Manually refresh tokens
  /// try await authClient.refreshExpiredTokens()
  /// ```
  ///
  /// > Important: This method is automatically called by `sendAuthenticated` methods
  /// > when `refreshExpiredToken` is set to `true` (the default behavior).
  public func refreshExpiredTokens() async throws {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session

    try await loadSession()

    guard
      let tokens = session?.tokens
    else {
      throw AuthTokens.Error.missingToken
    }

    do {
      try tokens.validateAccessToken()
    } catch {
      // Step 1: ask the server for fresh tokens. A transient failure
      // here (URLError, timeout, DNS, decode, etc.) just rethrows
      // without touching the session — no memory mutation has happened,
      // and we must not undo a concurrent logout/new-user login that
      // landed while the refresh was in flight.
      let newTokens: AuthTokens
      do {
        newTokens = try await refresh(tokens)
      } catch AuthTokens.Error.refreshRejected {
        // The server explicitly rejected the refresh token (e.g. 401
        // from /auth/refresh, revoked/expired refresh token).
        // Credentials are no longer valid — destroy them so the user
        // is forced to re-authenticate. This branch intentionally
        // does NOT rethrow so that callers like `sendAuthenticated`
        // keep falling through to their existing `session?.tokens`
        // check (which then throws `.missingToken`).
        try await authTokensClient.destroy()
        return
      } catch {
        throw error
      }

      // Step 2: persist the new tokens. The live `AuthTokensClient`
      // writes the new tokens to `@Shared(.authSession)` *before*
      // attempting the keychain writes, so on `set` failure memory
      // would otherwise be left on the new tokens even though the
      // keychain is partial. Roll the in-memory session back to the
      // old `.expired(tokens)` so a later retry has the original
      // refresh token to work with — but only if the session still
      // holds the new tokens we just persisted. withLock makes the
      // check-and-set atomic so a concurrent session change observed
      // during the catch is not overwritten.
      do {
        try await authTokensClient.set(newTokens)
      } catch {
        $session.withLock { current in
          if current?.tokens == newTokens {
            current = .expired(tokens)
          }
        }
        throw error
      }
    }
  }

  /// Sends an HTTP request and returns a successful response.
  ///
  /// - Parameters:
  ///   - request: The request to send.
  ///   - decoder: The JSON decoder to use for decoding the response.
  ///   - urlSession: The URL session to use for sending the request.
  ///   - cachePolicy: The cache policy to use for the request.
  ///   - timeoutInterval: The timeout interval for the request.
  ///   - middleware: The middleware to apply to the request.
  /// - Returns: A successful response containing the decoded data.
  public func send<T>(
    _ request: Request = .init(),
    decoder: JSONDecoder = .init(),
    urlSession: URLSessionProtocol = URLSession.shared,
    cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy,
    timeoutInterval: TimeInterval = 60,
    @RequestBuilder middleware: () -> RequestMiddleware = { identity }
  ) async throws -> SuccessResponse<T> where T: Decodable {
    @Dependency(\.httpRequestClient) var httpRequestClient

    return try await httpRequestClient.send(
      request,
      baseURL: try baseURL(),
      decoder: decoder,
      urlSession: urlSession,
      cachePolicy: cachePolicy,
      timeoutInterval: timeoutInterval,
      middleware: middleware
    )
  }

  /// Sends an authenticated HTTP request and returns a successful response.
  ///
  /// - Parameters:
  ///   - request: The request to send.
  ///   - refreshExpiredToken: Whether to refresh the access token if it has expired.
  ///   - decoder: The JSON decoder to use for decoding the response.
  ///   - urlSession: The URL session to use for sending the request.
  ///   - cachePolicy: The cache policy to use for the request.
  ///   - timeoutInterval: The timeout interval for the request.
  ///   - middleware: The middleware to apply to the request.
  /// - Returns: A successful response containing the decoded data.
  public func sendAuthenticated<T>(
    _ request: Request = .init(),
    refreshExpiredToken: Bool = true,
    decoder: JSONDecoder = .init(),
    urlSession: URLSessionProtocol = URLSession.shared,
    cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy,
    timeoutInterval: TimeInterval = 60,
    @RequestBuilder middleware: () -> RequestMiddleware = { identity }
  ) async throws -> SuccessResponse<T> where T: Decodable {
    @Dependency(\.authTokensClient) var authTokensClient
    @Dependency(\.httpRequestClient) var httpRequestClient
    @Shared(.authSession) var session

    func sendRequest(with accessToken: String) async throws -> SuccessResponse<T> {
      let bearerRequest = try bearerAuth(accessToken)(request)

      return try await httpRequestClient.send(
        bearerRequest,
        baseURL: try baseURL(),
        decoder: decoder,
        urlSession: urlSession,
        cachePolicy: cachePolicy,
        timeoutInterval: timeoutInterval,
        middleware: middleware
      )
    }

    if refreshExpiredToken {
      try await refreshExpiredTokens()
    }

    guard
      let sessionTokens = session?.tokens
    else {
      throw AuthTokens.Error.missingToken
    }

    return try await sendRequest(with: sessionTokens.access)
  }

  /// Sends an HTTP request and returns a response with a success or error value.
  ///
  /// - Parameters:
  ///   - request: The request to send.
  ///   - decoder: The JSON decoder to use for decoding the response.
  ///   - urlSession: The URL session to use for sending the request.
  ///   - cachePolicy: The cache policy to use for the request.
  ///   - timeoutInterval: The timeout interval for the request.
  ///   - middleware: The middleware to apply to the request.
  /// - Returns: A response containing either the decoded success data or the decoded error data.
  public func send<T, ServerError>(
    _ request: Request = .init(),
    decoder: JSONDecoder = .init(),
    urlSession: URLSessionProtocol = URLSession.shared,
    cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy,
    timeoutInterval: TimeInterval = 60,
    @RequestBuilder middleware: () -> RequestMiddleware = { identity }
  ) async throws -> Response<T, ServerError>
  where
    T: Decodable,
    ServerError: Decodable
  {
    @Dependency(\.httpRequestClient) var httpRequestClient

    return try await httpRequestClient.send(
      request,
      decoder: decoder,
      baseURL: try baseURL(),
      urlSession: urlSession,
      cachePolicy: cachePolicy,
      timeoutInterval: timeoutInterval,
      middleware: middleware
    )
  }

  /// Sends an authenticated HTTP request and returns a response with a success or error value.
  ///
  /// - Parameters:
  ///   - request: The request to send.
  ///   - decoder: The JSON decoder to use for decoding the response.
  ///   - refreshExpiredToken: Whether to refresh the access token if it has expired.
  ///   - urlSession: The URL session to use for sending the request.
  ///   - cachePolicy: The cache policy to use for the request.
  ///   - timeoutInterval: The timeout interval for the request.
  ///   - middleware: The middleware to apply to the request.
  /// - Returns: A response containing either the decoded success data or the decoded error data.
  public func sendAuthenticated<T, ServerError>(
    _ request: Request = .init(),
    decoder: JSONDecoder = .init(),
    refreshExpiredToken: Bool = true,
    urlSession: URLSessionProtocol = URLSession.shared,
    cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy,
    timeoutInterval: TimeInterval = 60,
    @RequestBuilder middleware: () -> RequestMiddleware = { identity }
  ) async throws -> Response<T, ServerError>
  where
    T: Decodable,
    ServerError: Decodable
  {
    @Dependency(\.authTokensClient) var authTokensClient
    @Dependency(\.httpRequestClient) var httpRequestClient
    @Shared(.authSession) var session

    func sendRequest(with accessToken: String) async throws -> Response<T, ServerError> {
      let bearerRequest = try bearerAuth(accessToken)(request)

      return try await httpRequestClient.send(
        bearerRequest,
        decoder: decoder,
        baseURL: try baseURL(),
        urlSession: urlSession,
        cachePolicy: cachePolicy,
        timeoutInterval: timeoutInterval,
        middleware: middleware
      )
    }

    if refreshExpiredToken {
      try await refreshExpiredTokens()
    }

    guard
      let sessionTokens = session?.tokens
    else {
      throw AuthTokens.Error.missingToken
    }

    return try await sendRequest(with: sessionTokens.access)
  }
}
