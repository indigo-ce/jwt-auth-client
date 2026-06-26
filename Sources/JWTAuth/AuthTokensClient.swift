import Dependencies
import DependenciesMacros
import Foundation
import Sharing

/// A client for managing authentication tokens in both memory and persistent storage.
///
/// `AuthTokensClient` provides a unified interface for saving, loading, and destroying
/// authentication tokens. It handles both in-memory caching and persistent keychain storage,
/// ensuring that authentication state is maintained across app launches.
///
/// ## Overview
///
/// The client manages tokens in two layers:
/// - **Memory**: Fast access via the shared session state
/// - **Keychain**: Persistent storage that survives app restarts
///
/// ## Usage
///
/// ```swift
/// @Dependency(\.authTokensClient) var authTokensClient
/// 
/// // Save tokens
/// try await authTokensClient.save(newTokens)
/// 
/// // Clear all tokens
/// try await authTokensClient.destroy()
/// 
/// // Set tokens (save if present, destroy if nil)
/// try await authTokensClient.set(optionalTokens)
/// ```
@DependencyClient
public struct AuthTokensClient: Sendable {
  /// Saves authentication tokens to persistent storage and updates the in-memory session.
  ///
  /// This operation:
  /// 1. Updates the shared session state in memory
  /// 2. Removes any existing tokens from keychain
  /// 3. Saves the new tokens to keychain
  ///
  /// - Parameter tokens: The authentication tokens to save
  /// - Throws: An error if the keychain operation fails
  public var save: @Sendable (AuthTokens) async throws -> Void
  
  /// Destroys all authentication tokens from both memory and persistent storage.
  ///
  /// This operation:
  /// 1. Clears the shared session state in memory
  /// 2. Removes all tokens from keychain
  ///
  /// Use this method when logging out users or when authentication fails.
  ///
  /// - Throws: An error if the keychain operation fails
  public var destroy: @Sendable () async throws -> Void

  /// Sets authentication tokens, saving them if provided or destroying them if nil.
  ///
  /// This is a convenience method that calls either `save` or `destroy` based on
  /// whether tokens are provided.
  ///
  /// - Parameter tokens: The tokens to save, or `nil` to destroy all tokens
  /// - Throws: An error if the underlying save or destroy operation fails
  ///
  /// ## Usage
  ///
  /// ```swift
  /// // Save new tokens
  /// try await authTokensClient.set(newTokens)
  /// 
  /// // Clear tokens (equivalent to destroy())
  /// try await authTokensClient.set(nil)
  /// ```
  @Sendable public func set(
    _ tokens: AuthTokens?
  ) async throws {
    if let tokens {
      return try await save(tokens)
    } else {
      return try await destroy()
    }
  }
}

extension DependencyValues {
  public var authTokensClient: AuthTokensClient {
    get { self[AuthTokensClient.self] }
    set { self[AuthTokensClient.self] = newValue }
  }
}

extension AuthTokensClient: TestDependencyKey {
  public static let previewValue = Self(
    save: { _ in },
    destroy: {}
  )

  public static let testValue = Self()
}

extension AuthTokensClient: DependencyKey {
  public static let liveValue = { () -> AuthTokensClient in
    @Dependency(\.keychainClient) var keychainClient

    @Sendable
    func persist(_ tokens: AuthTokens?) async throws {
      // Set the tokens in memory cache. We do this before the keychain
      // writes so the in-memory session and persistent state both reflect
      // the new tokens on success.
      @Shared(.authSession) var session
      $session.withLock { $0 = tokens?.toSession() }

      // Save the new tokens to the keychain BEFORE deleting the old ones.
      // `keychainClient.save` replaces any existing entry in place, so on
      // a partial save failure the old tokens remain in the keychain and
      // a later retry can succeed. The previous delete-then-save order
      // wiped both keychain entries before the first save, so any save
      // failure left the keychain empty and silently logged the user out
      // on the next cold launch.
      if let tokens {
        try await keychainClient.save(tokens.access, .accessToken)
        try await keychainClient.save(tokens.refresh, .refreshToken)
      } else {
        // No tokens to save — destroy removes both entries explicitly.
        try await keychainClient.delete(.accessToken)
        try await keychainClient.delete(.refreshToken)
      }
    }

    return Self { token in
      try await persist(token)
    } destroy: {
      try await persist(nil)
    }
  }()
}
