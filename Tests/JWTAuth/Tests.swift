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
  #expect(AuthTokens.Error.refreshRejected.errorDescription == "The refresh token was rejected by the server.")
}

@Test func authTokensErrorTitle() {
  #expect(AuthTokens.Error.missingToken.title == "Session Error")
  #expect(AuthTokens.Error.invalidToken.title == "Session Error")
  #expect(AuthTokens.Error.expiredToken.title == "Session Error")
  #expect(AuthTokens.Error.refreshRejected.title == "Session Error")
}

@Test func authTokensErrorEquality() {
  #expect(AuthTokens.Error.missingToken == AuthTokens.Error.missingToken)
  #expect(AuthTokens.Error.invalidToken == AuthTokens.Error.invalidToken)
  #expect(AuthTokens.Error.expiredToken == AuthTokens.Error.expiredToken)
  #expect(AuthTokens.Error.refreshRejected == AuthTokens.Error.refreshRejected)
  #expect(AuthTokens.Error.missingToken != AuthTokens.Error.invalidToken)
  #expect(AuthTokens.Error.refreshRejected != AuthTokens.Error.expiredToken)
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

@Test func refreshExpiredTokensDestroysTokensWhenRefreshRejected() async throws {
  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let destroyCalled = Box(false)
  let saveCalled = Box(false)
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in throw AuthTokens.Error.refreshRejected }
  )
  try await withDependencies {
    // Use a wrapping `AuthTokensClient` so we can observe `destroy`/`save`
    // being called while still delegating to the live impl (which is what
    // actually updates `@Shared(.authSession)` and the keychain).
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { tokens in
        saveCalled.value = true
        try await AuthTokensClient.liveValue.save(tokens)
      },
      destroy: {
        destroyCalled.value = true
        try await AuthTokensClient.liveValue.destroy()
      }
    )
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }

    // Server-side rejection: refreshExpiredTokens() should call destroy()
    // and NOT rethrow — so `sendAuthenticated` can keep falling through to
    // its existing `session?.tokens` check.
    try await client.refreshExpiredTokens()

    #expect(destroyCalled.value == true)
    #expect(saveCalled.value == false)
    #expect(session == nil)
  }
}

@Test func refreshExpiredTokensKeepsTokensOnTransportError() async throws {
  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let destroyCalled = Box(false)
  let saveCalled = Box(false)
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in throw URLError(.notConnectedToInternet) }
  )
  try await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { _ in saveCalled.value = true },
      destroy: { destroyCalled.value = true }
    )
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }

    // Network unreachable is a transient failure: refreshExpiredTokens()
    // must NOT destroy the tokens, must rethrow the URLError so the caller
    // can decide to retry, and must leave the session untouched so a later
    // retry can succeed.
    await #expect(throws: URLError.self) {
      try await client.refreshExpiredTokens()
    }

    #expect(destroyCalled.value == false)
    #expect(saveCalled.value == false)
    #expect(session == .expired(expiredTokens))
  }
}

@Test func refreshExpiredTokensKeepsTokensOnGenericError() async throws {
  struct NotAServerRejection: Error, Equatable {}

  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let destroyCalled = Box(false)
  let saveCalled = Box(false)
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in throw NotAServerRejection() }
  )
  try await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { _ in saveCalled.value = true },
      destroy: { destroyCalled.value = true }
    )
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }

    // Any non-`.refreshRejected` error is transient: same expectations as
    // the URLError case.
    await #expect(throws: NotAServerRejection.self) {
      try await client.refreshExpiredTokens()
    }

    #expect(destroyCalled.value == false)
    #expect(saveCalled.value == false)
    #expect(session == .expired(expiredTokens))
  }
}

@Test func refreshExpiredTokensRollsBackSessionOnKeychainSaveFailureAfterRefresh() async throws {
  // Refresh succeeded, but persisting the new tokens to the keychain failed.
  // That's not a server-side rejection — the refresh token is still valid —
  // so we must NOT destroy, must rethrow the keychain error, and must leave
  // the existing (expired) tokens intact so a later retry can succeed.
  //
  // Critically, the live `AuthTokensClient.persist` writes the new tokens
  // to `@Shared(.authSession)` *before* attempting the keychain writes.
  // Without an explicit rollback, memory would be left on the new tokens
  // while the keychain is empty — defeating the retry behavior. This mock
  // reproduces that order so we can verify the rollback actually runs.
  struct KeychainSaveFailed: Error {}

  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let destroyCalled = Box(false)
  let newTokens = AuthTokens(access: validJWT, refresh: "new-refresh")
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in newTokens }
  )
  await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { newTokens in
        // Simulate live persist order: mutate memory first, then throw on
        // the keychain write. Without rollback, `session` would be left
        // on `newTokens` even though the keychain is empty.
        @Shared(.authSession) var session
        $session.withLock { $0 = newTokens.toSession() }
        throw KeychainSaveFailed()
      },
      destroy: { destroyCalled.value = true }
    )
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }

    await #expect(throws: KeychainSaveFailed.self) {
      try await client.refreshExpiredTokens()
    }

    #expect(destroyCalled.value == false)
    // The in-memory session must be rolled back to the old expired tokens
    // so a later retry can use the still-valid refresh token.
    #expect(session == .expired(expiredTokens))
  }
}

@Test func refreshExpiredTokensDoesNotResurrectSessionOnTransientRefreshFailure() async throws {
  // The catch-and-rollback in `refreshExpiredTokens` must only run for
  // failures from `authTokensClient.set(newTokens)`, NOT for failures
  // from `refresh(tokens)`. Otherwise a concurrent session change
  // (logout, new-user login) that lands while a refresh is in flight
  // would be silently undone when the refresh later fails with a
  // transient `URLError`. The mock here simulates that race by
  // mutating the session from inside the `refresh` closure before
  // throwing.
  let userAExpired = AuthTokens(access: expiredJWT, refresh: "user-a-refresh")
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in
      // Simulate the race: while this refresh is in flight, the
      // user logs out (or another user logs in). The session is
      // wiped to nil. The refresh then fails transiently.
      @Shared(.authSession) var session
      $session.withLock { $0 = nil }
      throw URLError(.notConnectedToInternet)
    }
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
    $session.withLock { $0 = .expired(userAExpired) }

    await #expect(throws: URLError.self) {
      try await client.refreshExpiredTokens()
    }

    // The session must remain nil — the rollback that was previously
    // triggered for any non-`.refreshRejected` error would have
    // resurrected user A's old expired tokens here, undoing the
    // logout. The split do-catch keeps the session change intact.
    #expect(session == nil)
  }
}

@Test func authTokensClientLiveValueSaveRestoresOldTokensOnAccessSaveFailure() async throws {
  // When the access-token save fails mid-write, the live
  // `AuthTokensClient.persist` captures the old access and refresh
  // tokens up front and best-effort restores them on partial save
  // failure. That keeps the keychain in a cold-launch-restorable
  // state — the next `loadTokens()` returns the old pair (or nil
  // if there were none originally) rather than nil because one of
  // the new saves was mid-write. Without the restore, the
  // `KeychainClient.save` delete-then-set would leave the access
  // entry empty after the set-throw, and the user would still be
  // silently logged out on the next launch.
  struct AccessSaveFailed: Error {}

  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")
  // Track what's currently in the keychain. The stub mimics the
  // live `keychainClient.save` semantics (delete-then-set on the
  // underlying store) and throws *only* when the new value is being
  // saved — the subsequent restore call with the old value is
  // allowed to succeed.
  let storedValues = Box<[KeychainClient.Keys: String]>([
    .accessToken: oldTokens.access,
    .refreshToken: oldTokens.refresh,
  ])

  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { value, key in
        // Mimic live delete-then-set semantics.
        storedValues.value[key] = nil
        // Throw only on the new-value save; the restore call with
        // the old value goes through cleanly.
        if value == newTokens.access && key == .accessToken {
          throw AccessSaveFailed()
        }
        storedValues.value[key] = value
      },
      load: { key in storedValues.value[key] },
      delete: { key in storedValues.value[key] = nil },
      reset: { storedValues.value.removeAll() }
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Dependency(\.keychainClient) var keychainClient

    await #expect(throws: AccessSaveFailed.self) {
      try await authTokensClient.save(newTokens)
    }

    // Both old tokens are back in the keychain — the access save
    // was restored after the access-save failure, and the refresh
    // was never touched. The keychain is cold-launch-restorable.
    #expect(storedValues.value[.accessToken] == oldTokens.access)
    #expect(storedValues.value[.refreshToken] == oldTokens.refresh)
    let loaded = try await keychainClient.loadTokens()
    #expect(loaded == oldTokens)
  }
}

@Test func authTokensClientLiveValueSaveRestoresOldTokensOnRefreshSaveFailure() async throws {
  // Companion case: when the access-token save succeeds but the
  // refresh-token save fails, the live `AuthTokensClient.persist`
  // best-effort restores the old refresh (and the old access,
  // since the new access overwrote it). The keychain is left in a
  // cold-launch-restorable state with the original old pair — not
  // the new access + empty refresh that the partial fix would have
  // left.
  struct RefreshSaveFailed: Error {}

  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")
  let storedValues = Box<[KeychainClient.Keys: String]>([
    .accessToken: oldTokens.access,
    .refreshToken: oldTokens.refresh,
  ])

  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { value, key in
        // Mimic live delete-then-set semantics.
        storedValues.value[key] = nil
        // Throw only on the new-value save; the subsequent restore
        // call with the old value is allowed to succeed.
        if value == newTokens.refresh && key == .refreshToken {
          throw RefreshSaveFailed()
        }
        storedValues.value[key] = value
      },
      load: { key in storedValues.value[key] },
      delete: { key in storedValues.value[key] = nil },
      reset: { storedValues.value.removeAll() }
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Dependency(\.keychainClient) var keychainClient

    await #expect(throws: RefreshSaveFailed.self) {
      try await authTokensClient.save(newTokens)
    }

    // The new access save overwrote the old access, but the restore
    // step put it back; the new refresh save failed before writing,
    // so the old refresh was untouched. Keychain is the original
    // old pair — cold-launch-restorable.
    #expect(storedValues.value[.accessToken] == oldTokens.access)
    #expect(storedValues.value[.refreshToken] == oldTokens.refresh)
    let loaded = try await keychainClient.loadTokens()
    #expect(loaded == oldTokens)
  }
}
