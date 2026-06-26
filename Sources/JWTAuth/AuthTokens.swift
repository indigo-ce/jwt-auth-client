import Foundation
import JWTDecode
import Sharing

/// A structure that holds JWT access and refresh tokens for authentication.
///
/// `AuthTokens` encapsulates both access and refresh tokens, providing utilities
/// to validate tokens, extract claims, and manage authentication state.
///
/// ## Overview
///
/// The `AuthTokens` structure is the core data type for managing JWT authentication
/// tokens in your application. It provides:
///
/// - Token validation and expiration checking
/// - Claim extraction from JWT tokens
/// - Conversion to authentication sessions
///
/// ## Usage
///
/// ```swift
/// let tokens = AuthTokens(
///     access: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
///     refresh: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
/// )
///
/// // Check if token is expired
/// if !tokens.isExpired {
///     // Use the tokens
/// }
///
/// // Extract claims
/// let username = tokens[string: "username"]
/// let isAdmin = tokens[boolean: "is_admin"]
/// ```
public struct AuthTokens: Codable, Hashable, Sendable {
  /// The JWT access token used for authenticating API requests.
  public var access: String
  
  /// The JWT refresh token used for obtaining new access tokens.
  public var refresh: String

  /// Creates a new `AuthTokens` instance with the provided access and refresh tokens.
  ///
  /// - Parameters:
  ///   - access: The JWT access token string
  ///   - refresh: The JWT refresh token string
  public init(
    access: String,
    refresh: String
  ) {
    self.access = access
    self.refresh = refresh
  }
}

extension AuthTokens {
  /// Errors that can occur when working with authentication tokens.
  public enum Error: LocalizedError {
    /// The token is missing from the request or storage.
    case missingToken
    /// The token format is invalid or cannot be decoded.
    case invalidToken
    /// The token has expired and is no longer valid.
    case expiredToken
    /// The refresh token was explicitly rejected by the server.
    ///
    /// Throw this from a `JWTAuthClient.refresh` closure to signal that the
    /// server definitively rejected the refresh token — for example, a 401
    /// from `/auth/refresh`, or a refresh token that has expired or been
    /// revoked. `JWTAuthClient.refreshExpiredTokens()` catches this specific
    /// case and destroys the stored credentials; any other thrown error is
    /// treated as transient (the tokens are preserved so a later retry can
    /// succeed) and rethrown to the caller.
    case refreshRejected

    /// A localized message describing what error occurred.
    public var errorDescription: String? {
      switch self {
      case .missingToken: "The token seems to be missing."
      case .invalidToken: "The token is invalid."
      case .expiredToken: "The token is expired."
      case .refreshRejected: "The refresh token was rejected by the server."
      }
    }

    /// A localized title for the error, suitable for display in UI alerts.
    public var title: String {
      return "Session Error"
    }
  }

  /// Converts the access token to a decoded JWT object.
  ///
  /// - Returns: A decoded `JWT` object containing the token's claims
  /// - Throws: An error if the token cannot be decoded
  public func toJWT() throws -> JWT {
    try decode(jwt: self.access)
  }

  /// Indicates whether the access token has expired.
  ///
  /// This property attempts to validate the access token and returns `true`
  /// if the token is expired or if validation fails for any reason.
  public var isExpired: Bool {
    do {
      return try validateAccessToken().expired
    } catch {
      return true
    }
  }

  /// Validates the access token and returns the decoded JWT if valid.
  ///
  /// - Returns: A decoded `JWT` object if the token is valid and not expired
  /// - Throws: `AuthTokens.Error.expiredToken` if the token has expired
  @discardableResult
  func validateAccessToken() throws -> JWT {
    let jwt = try toJWT()

    if jwt.expired {
      throw Error.expiredToken
    }

    return jwt
  }

  /// Extracts a string claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The string value of the claim, or `nil` if the claim doesn't exist or cannot be converted to a string
  public subscript(string claim: String) -> String? {
    try? toJWT().claim(name: claim).string
  }

  /// Extracts a boolean claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The boolean value of the claim, or `nil` if the claim doesn't exist or cannot be converted to a boolean
  public subscript(boolean claim: String) -> Bool? {
    try? toJWT().claim(name: claim).boolean
  }

  /// Extracts an integer claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The integer value of the claim, or `nil` if the claim doesn't exist or cannot be converted to an integer
  public subscript(int claim: String) -> Int? {
    try? toJWT().claim(name: claim).integer
  }

  /// Extracts a double claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The double value of the claim, or `nil` if the claim doesn't exist or cannot be converted to a double
  public subscript(double claim: String) -> Double? {
    try? toJWT().claim(name: claim).double
  }

  /// Extracts a date claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The date value of the claim, or `nil` if the claim doesn't exist or cannot be converted to a date
  public subscript(date claim: String) -> Date? {
    try? toJWT().claim(name: claim).date
  }

  /// Extracts a string array claim from the JWT access token.
  ///
  /// - Parameter claim: The name of the claim to extract
  /// - Returns: The string array value of the claim, or `nil` if the claim doesn't exist or cannot be converted to a string array
  public subscript(strings claim: String) -> [String]? {
    try? toJWT().claim(name: claim).array
  }

  /// Converts the tokens to an authentication session based on their validity.
  ///
  /// - Returns: `.valid(self)` if the access token is not expired, `.expired(self)` otherwise
  public func toSession() -> AuthSession {
    guard !isExpired
    else { return .expired(self) }
    return .valid(self)
  }
}
