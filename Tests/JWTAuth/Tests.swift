import Dependencies
import Foundation
import Sharing
import Testing

@testable import JWTAuth

// MARK: - JWT Test Helpers

private func jwtWithPayload(_ payloadJSON: String) -> String {
  func base64url(_ string: String) -> String {
    Data(string.utf8).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .trimmingCharacters(in: CharacterSet(charactersIn: "="))
  }

  let header = base64url(#"{"alg":"none","typ":"JWT"}"#)
  let payload = base64url(payloadJSON)
  return "\(header).\(payload).abc"
}

private let validJWT = jwtWithPayload(#"{"exp":9999999999}"#)
private let expiredJWT = jwtWithPayload(#"{"exp":1}"#)
private let claimsJWT = jwtWithPayload(
  #"{"sub":"user123","admin":true,"level":5,"exp":9999999999}"#)

private final class Box<T: Sendable>: @unchecked Sendable {
  var value: T
  init(_ value: T) { self.value = value }
}

@Test func loadSession() async throws {
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in .init(access: "accessToken", refresh: "accessToken") }
  )

  try await withDependencies {
    $0.keychainClient = .init(
      save: { _, _ in },
      load: { _ in "accessToken" },
      delete: { _ in },
      reset: {}
    )

    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var authSession
    #expect(authSession == nil)

    try await client.loadSession()
    #expect(authSession == .expired(.init(access: "accessToken", refresh: "accessToken")))
  }
}

@Test func skipLoadingExistingSession() async throws {
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in .init(access: "accessToken", refresh: "accessToken") }
  )

  try await withDependencies {
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var authSession
    $authSession.withLock {
      $0 = .expired(.init(access: "accessToken", refresh: "accessToken"))
    }

    try await client.loadSession()
    #expect(authSession == .expired(.init(access: "accessToken", refresh: "accessToken")))
  }
}

// MARK: - AuthTokens Tests

@Test func authTokensInitialization() {
  let tokens = AuthTokens(access: "access123", refresh: "refresh456")
  #expect(tokens.access == "access123")
  #expect(tokens.refresh == "refresh456")
}

@Test func authTokensEquality() {
  let tokens1 = AuthTokens(access: "access", refresh: "refresh")
  let tokens2 = AuthTokens(access: "access", refresh: "refresh")
  let tokens3 = AuthTokens(access: "different", refresh: "refresh")

  #expect(tokens1 == tokens2)
  #expect(tokens1 != tokens3)
}

@Test func authTokensHashable() {
  let tokens1 = AuthTokens(access: "access", refresh: "refresh")
  let tokens2 = AuthTokens(access: "access", refresh: "refresh")

  #expect(tokens1.hashValue == tokens2.hashValue)
}

@Test func authTokensToJWTWithInvalidToken() {
  let tokens = AuthTokens(access: "invalid-jwt", refresh: "refresh")

  #expect(throws: (any Error).self) {
    try tokens.toJWT()
  }
}

@Test func authTokensIsExpiredWithInvalidToken() {
  let tokens = AuthTokens(access: "invalid-jwt", refresh: "refresh")
  #expect(tokens.isExpired == true)
}

@Test func authTokensToSessionWithInvalidToken() {
  let tokens = AuthTokens(access: "invalid-jwt", refresh: "refresh")
  let session = tokens.toSession()
  #expect(session == .expired(tokens))
}

@Test func authTokensSubscriptWithInvalidToken() {
  let tokens = AuthTokens(access: "invalid-jwt", refresh: "refresh")

  #expect(tokens[string: "sub"] == nil)
  #expect(tokens[boolean: "admin"] == nil)
  #expect(tokens[int: "exp"] == nil)
  #expect(tokens[double: "score"] == nil)
  #expect(tokens[date: "iat"] == nil)
  #expect(tokens[strings: "roles"] == nil)
}

@Test func authTokensIsExpiredWithValidToken() {
  let tokens = AuthTokens(access: validJWT, refresh: "refresh")
  #expect(tokens.isExpired == false)
}

@Test func authTokensToSessionReturnsValidForNonExpiredToken() {
  let tokens = AuthTokens(access: validJWT, refresh: "refresh")
  #expect(tokens.toSession() == .valid(tokens))
}

@Test func authTokensToSessionReturnsExpiredForExpiredToken() {
  let tokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  #expect(tokens.toSession() == .expired(tokens))
}

@Test func authTokensSubscriptWithValidJWT() {
  let tokens = AuthTokens(access: claimsJWT, refresh: "refresh")
  #expect(tokens[string: "sub"] == "user123")
  #expect(tokens[boolean: "admin"] == true)
  #expect(tokens[int: "level"] == 5)
}

// MARK: - AuthTokens.Error Tests

@Test func authTokensErrorDescriptions() {
  #expect(AuthTokens.Error.missingToken.errorDescription == "The token seems to be missing.")
  #expect(AuthTokens.Error.invalidToken.errorDescription == "The token is invalid.")
  #expect(AuthTokens.Error.expiredToken.errorDescription == "The token is expired.")
}

@Test func authTokensErrorTitle() {
  #expect(AuthTokens.Error.missingToken.title == "Session Error")
  #expect(AuthTokens.Error.invalidToken.title == "Session Error")
  #expect(AuthTokens.Error.expiredToken.title == "Session Error")
}

@Test func authTokensErrorEquality() {
  #expect(AuthTokens.Error.missingToken == AuthTokens.Error.missingToken)
  #expect(AuthTokens.Error.invalidToken == AuthTokens.Error.invalidToken)
  #expect(AuthTokens.Error.expiredToken == AuthTokens.Error.expiredToken)
  #expect(AuthTokens.Error.missingToken != AuthTokens.Error.invalidToken)
}

// MARK: - AuthSession Tests

@Test func authSessionIsExpiredProperty() {
  let tokens = AuthTokens(access: "access", refresh: "refresh")

  #expect(AuthSession.missing.isExpired == false)
  #expect(AuthSession.expired(tokens).isExpired == true)
  #expect(AuthSession.valid(tokens).isExpired == false)
}

@Test func authSessionTokensProperty() {
  let tokens = AuthTokens(access: "access", refresh: "refresh")

  #expect(AuthSession.missing.tokens == nil)
  #expect(AuthSession.expired(tokens).tokens == tokens)
  #expect(AuthSession.valid(tokens).tokens == tokens)
}

@Test func authSessionEquality() {
  let tokens1 = AuthTokens(access: "access1", refresh: "refresh1")
  let tokens2 = AuthTokens(access: "access2", refresh: "refresh2")

  #expect(AuthSession.missing == AuthSession.missing)
  #expect(AuthSession.expired(tokens1) == AuthSession.expired(tokens1))
  #expect(AuthSession.valid(tokens1) == AuthSession.valid(tokens1))

  #expect(AuthSession.missing != AuthSession.expired(tokens1))
  #expect(AuthSession.expired(tokens1) != AuthSession.valid(tokens1))
  #expect(AuthSession.expired(tokens1) != AuthSession.expired(tokens2))
  #expect(AuthSession.valid(tokens1) != AuthSession.valid(tokens2))
}

// MARK: - KeychainClient Tests

@Test func keychainLoadTokensReturnsNilWhenBothMissing() async throws {
  let client = KeychainClient(
    save: { _, _ in },
    load: { _ in nil },
    delete: { _ in },
    reset: {}
  )
  #expect(try await client.loadTokens() == nil)
}

@Test func keychainLoadTokensReturnsNilWhenAccessTokenMissing() async throws {
  let client = KeychainClient(
    save: { _, _ in },
    load: { key in key == .refreshToken ? "refresh" : nil },
    delete: { _ in },
    reset: {}
  )
  #expect(try await client.loadTokens() == nil)
}

@Test func keychainLoadTokensReturnsNilWhenRefreshTokenMissing() async throws {
  let client = KeychainClient(
    save: { _, _ in },
    load: { key in key == .accessToken ? "access" : nil },
    delete: { _ in },
    reset: {}
  )
  #expect(try await client.loadTokens() == nil)
}

@Test func keychainLoadTokensReturnsBothWhenPresent() async throws {
  let client = KeychainClient(
    save: { _, _ in },
    load: { key in key == .accessToken ? "access" : "refresh" },
    delete: { _ in },
    reset: {}
  )
  #expect(try await client.loadTokens() == AuthTokens(access: "access", refresh: "refresh"))
}

// MARK: - KeychainClient.Keys Tests

@Test func keychainKeysEquality() {
  #expect(KeychainClient.Keys.accessToken == KeychainClient.Keys.accessToken)
  #expect(KeychainClient.Keys.refreshToken == KeychainClient.Keys.refreshToken)
  #expect(KeychainClient.Keys.accessToken != KeychainClient.Keys.refreshToken)
}

@Test func keychainKeysHashable() {
  #expect(KeychainClient.Keys.accessToken.hashValue == KeychainClient.Keys.accessToken.hashValue)
}

// MARK: - KeychainError Tests

@Test func keychainErrorDescriptions() {
  #expect(
    KeychainError.savingFailed(message: "oops").errorDescription
      == "Saving to keychain failed. Reason: oops"
  )
  #expect(
    KeychainError.loadingFailed(message: "oops").errorDescription
      == "Loading from keychain failed. Reason: oops"
  )
}

@Test func keychainErrorEquality() {
  #expect(KeychainError.savingFailed(message: "a") == KeychainError.savingFailed(message: "a"))
  #expect(KeychainError.savingFailed(message: "a") != KeychainError.savingFailed(message: "b"))
  #expect(KeychainError.savingFailed(message: "a") != KeychainError.loadingFailed(message: "a"))
}

// MARK: - AuthTokensClient Tests

@Test func authTokensClientSetWithTokensCallsSave() async throws {
  let saveCalled = Box(false)
  let client = AuthTokensClient(
    save: { _ in saveCalled.value = true },
    destroy: {}
  )
  try await client.set(AuthTokens(access: "access", refresh: "refresh"))
  #expect(saveCalled.value)
}

@Test func authTokensClientSetWithNilCallsDestroy() async throws {
  let destroyCalled = Box(false)
  let client = AuthTokensClient(
    save: { _ in },
    destroy: { destroyCalled.value = true }
  )
  try await client.set(nil)
  #expect(destroyCalled.value)
}

@Test func authTokensClientSaveUpdatesSession() async throws {
  let tokens = AuthTokens(access: "access", refresh: "refresh")
  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = nil }
    try await authTokensClient.save(tokens)
    #expect(session == tokens.toSession())
  }
}

@Test func authTokensClientDestroyUpdatesSession() async throws {
  let tokens = AuthTokens(access: "access", refresh: "refresh")
  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(tokens) }
    try await authTokensClient.destroy()
    #expect(session == nil)
  }
}

// MARK: - JWTAuthClient.refreshExpiredTokens Tests

@Test func refreshExpiredTokensThrowsMissingTokenWhenNoSession() async throws {
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in .init(access: "new", refresh: "new") }
  )
  await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(save: { _ in }, destroy: {})
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = nil }
    await #expect(throws: AuthTokens.Error.missingToken) {
      try await client.refreshExpiredTokens()
    }
  }
}

@Test func refreshExpiredTokensSkipsRefreshForValidTokens() async throws {
  let refreshCalled = Box(false)
  let tokens = AuthTokens(access: validJWT, refresh: "refresh")
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in
      refreshCalled.value = true
      return .init(access: "new", refresh: "new")
    }
  )
  try await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(save: { _ in }, destroy: {})
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .valid(tokens) }
    try await client.refreshExpiredTokens()
    #expect(refreshCalled.value == false)
  }
}

@Test func refreshExpiredTokensRefreshesExpiredTokens() async throws {
  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let newTokens = AuthTokens(access: validJWT, refresh: "new-refresh")
  let savedTokens = Box(AuthTokens?.none)
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in newTokens }
  )
  try await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(save: { savedTokens.value = $0 }, destroy: {})
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }
    try await client.refreshExpiredTokens()
    #expect(savedTokens.value == newTokens)
  }
}

@Test func refreshExpiredTokensDestroysTokensWhenRefreshFails() async throws {
  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let destroyCalled = Box(false)
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in throw AuthTokens.Error.invalidToken }
  )
  try await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(save: { _ in }, destroy: { destroyCalled.value = true })
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }
    try await client.refreshExpiredTokens()
    #expect(destroyCalled.value == true)
  }
}
