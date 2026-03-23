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
  /// - Parameter authTokens: The current tokens to be refreshed
  /// - Returns: New authentication tokens from the server
  /// - Throws: An error if the refresh operation fails
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
  /// If the refresh operation fails (e.g., refresh token is also expired),
  /// all authentication tokens are destroyed, effectively logging out the user.
  ///
  /// - Throws: `AuthTokens.Error.missingToken` if no tokens are available
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
      do {
        let newTokens = try await refresh(tokens)
        try await authTokensClient.set(newTokens)
      } catch {
        try await authTokensClient.destroy()
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
