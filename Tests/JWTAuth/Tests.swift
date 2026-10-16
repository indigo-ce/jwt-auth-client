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

@Test func refreshExpiredTokensKeepsNewTokensInMemoryOnKeychainSaveFailureAfterRefresh() async throws {
  // Refresh succeeded, but persisting the new tokens to the keychain failed.
  // That's not a server-side rejection, so we must NOT destroy and must
  // rethrow the keychain error. But the backend rotates refresh tokens and
  // invalidates the old one immediately (no grace window), so the old
  // expired tokens are already dead server-side — leaving them in memory
  // would make the next refresh a guaranteed 401 that destroys the
  // session. The new tokens are the only valid credentials on device, so
  // `refreshExpiredTokens` publishes them to memory (best-effort,
  // session-only) before rethrowing.
  //
  // This test wires the real live persist path to a failing keychain: the
  // live persist restores the keychain and leaves memory untouched, and
  // the guarded publish in `refreshExpiredTokens` then moves the session
  // onto the new tokens.
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
      save: { _, _ in throw KeychainSaveFailed() },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { tokens in
        // Delegate to the live implementation so the keychain-first
        // ordering (and the untouched memory on failure) is exercised.
        try await AuthTokensClient.liveValue.save(tokens)
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
    // The session must hold the new tokens — the only valid credentials
    // left — so the current session keeps working despite the failed
    // persist.
    #expect(session == .valid(newTokens))
  }
}

@Test func refreshExpiredTokensDoesNotOverwriteConcurrentSessionChangeOnKeychainSaveFailure() async throws {
  // The guarded publish on keychain-save failure must only fire when the
  // session still holds the old tokens. If a concurrent logout or account
  // switch lands while the failing save is in flight, that change wins —
  // the publish must not overwrite it with the new tokens. This mock
  // performs the concurrent change from inside the save closure, before
  // the persist throws.
  struct KeychainSaveFailed: Error {}

  let expiredTokens = AuthTokens(access: expiredJWT, refresh: "refresh")
  let userBTokens = AuthTokens(access: validJWT, refresh: "user-b-refresh")
  let newTokens = AuthTokens(access: validJWT, refresh: "new-refresh")
  let client = JWTAuthClient(
    baseURL: { "https://api.example.com" },
    refresh: { _ in newTokens }
  )
  await withDependencies {
    $0.keychainClient = KeychainClient(
      save: { _, _ in throw KeychainSaveFailed() },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
    $0.authTokensClient = .init(
      save: { tokens in
        // Simulate the race: while the persist is failing, user B signs
        // in on another task and takes over the session.
        @Shared(.authSession) var session
        $session.withLock { $0 = .expired(userBTokens) }
        // The live persist touches only the keychain (and leaves memory
        // untouched on failure), so user B's session survives it.
        try await AuthTokensClient.liveValue.save(tokens)
      },
      destroy: {}
    )
    $0.jwtAuthClient = client
  } operation: {
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(expiredTokens) }

    await #expect(throws: KeychainSaveFailed.self) {
      try await client.refreshExpiredTokens()
    }

    // User B's concurrent session change wins — the guarded publish must
    // not overwrite it with the refreshed tokens.
    #expect(session == .expired(userBTokens))
  }
}

@Test func refreshExpiredTokensDoesNotResurrectSessionOnTransientRefreshFailure() async throws {
  // A failure thrown from `refresh(tokens)` is a transient refresh failure:
  // `refreshExpiredTokens` must not destroy, publish, or otherwise mutate
  // the session in response. Otherwise a concurrent session change
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

    // The session must remain nil — any rollback-style recovery keyed on
    // the pre-refresh tokens would resurrect user A's old expired tokens
    // here, undoing the logout. No such recovery runs for refresh-path
    // failures.
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
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

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
    // Memory is published only after both keychain writes succeed, so
    // the failed save left the in-memory session untouched.
    #expect(session == .expired(oldTokens))
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
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

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
    // Memory is published only after both keychain writes succeed, so
    // the failed save left the in-memory session untouched.
    #expect(session == .expired(oldTokens))
  }
}

@Test func authTokensClientLiveValueSaveLeavesSessionUntouchedOnKeychainFailure() async throws {
  // The live persist writes the keychain first and publishes the new
  // session to `@Shared(.authSession)` only after both writes succeed.
  // A failed save must therefore leave the in-memory session exactly as
  // it was — observers (e.g. a root view that dismisses the auth sheet
  // when a valid session appears) never see tokens that didn't persist.
  struct SaveFailed: Error {}

  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")

  await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in throw SaveFailed() },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

    await #expect(throws: SaveFailed.self) {
      try await authTokensClient.save(newTokens)
    }

    #expect(session == .expired(oldTokens))
  }
}

@Test func authTokensClientLiveValueSavePublishesSessionOnlyAfterKeychainWritesSucceed() async throws {
  // Guard the ordering itself: while the keychain writes are in flight,
  // memory still holds the old session; the new session is published only
  // after the second write completes.
  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")
  let sessionDuringWrites = Box<AuthSession?>(nil)
  let writesStarted = Box(0)

  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in
        writesStarted.value += 1
        // Capture what memory holds while the keychain writes are
        // still in progress (after the first of two writes).
        if writesStarted.value == 1 {
          @Shared(.authSession) var session
          sessionDuringWrites.value = session
        }
      },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

    try await authTokensClient.save(newTokens)

    // While the writes were in flight, memory still held the old
    // session; afterwards it holds the new one.
    #expect(sessionDuringWrites.value == .expired(oldTokens))
    #expect(session == newTokens.toSession())
  }
}

@Test func authTokensClientLiveValueDestroyClearsSessionEvenWhenKeychainDeleteThrows() async throws {
  // Destroy clears the in-memory session *first*, then removes the
  // keychain entries. Even when the keychain delete fails, memory has
  // already been cleared — the user is logged out of the session
  // immediately.
  struct DeleteFailed: Error {}

  let tokens = AuthTokens(access: "access", refresh: "refresh")

  await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in },
      load: { _ in nil },
      delete: { _ in throw DeleteFailed() },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .valid(tokens) }

    await #expect(throws: DeleteFailed.self) {
      try await authTokensClient.destroy()
    }

    // Memory was cleared before the keychain delete threw.
    #expect(session == nil)
  }
}

@Test func authTokensClientLiveValueSaveDoesNotPublishOverConcurrentSessionChange() async throws {
  // The live save publishes the new session only when no concurrent writer
  // changed `@Shared(.authSession)` while the save was suspended on the
  // keychain. Park the first keychain write, clear the session (a
  // "logout") from outside while the save is suspended, then release it:
  // the save must complete without publishing — otherwise it would
  // resurrect a session the user just destroyed.
  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")
  let saveParked = Box(false)
  let releaseSave = Box<CheckedContinuation<Void, Never>?>(nil)

  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, _ in
        // Park on the first keychain write so the test can interleave.
        if !saveParked.value {
          await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            releaseSave.value = continuation
            saveParked.value = true
          }
        }
      },
      load: { _ in nil },
      delete: { _ in },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

    // Copy the resolved client out of the @Dependency wrapper: the Task
    // closures below would otherwise capture the non-Sendable wrapper.
    let client = authTokensClient

    let saveTask = Task { try await client.save(newTokens) }

    // Wait until the save is parked on its first keychain write.
    while !saveParked.value {
      await Task.yield()
    }

    // Concurrent logout: clear the session while the save is suspended.
    $session.withLock { $0 = nil }

    releaseSave.value?.resume()
    try await saveTask.value

    // The save's keychain writes succeeded, but the concurrent logout
    // owns the session — the publication must have been skipped.
    #expect(session == nil)
  }
}

@Test func authTokensClientLiveValueSerializesSaveAfterInFlightDestroy() async throws {
  // Persist operations are serialized: a save started while a destroy is
  // still parked mid-delete must wait for the destroy to finish. Without
  // the gate, the save's keychain writes would land between the destroy's
  // two deletes, leaving the logged-out user's tokens in the keychain
  // after logout completed. The recorded operation order proves the
  // destroy ran to completion before the save began.
  let oldTokens = AuthTokens(access: "old-access", refresh: "old-refresh")
  let newTokens = AuthTokens(access: "new-access", refresh: "new-refresh")
  let order = Box<[String]>([])
  let destroyParked = Box(false)
  let releaseDestroy = Box<CheckedContinuation<Void, Never>?>(nil)

  try await withDependencies {
    $0.authTokensClient = .liveValue
    $0.keychainClient = KeychainClient(
      save: { _, key in
        order.value.append("save:\(key.value)")
      },
      load: { _ in nil },
      delete: { key in
        order.value.append("delete:\(key.value)")
        // Park on the destroy's first keychain delete.
        if key == .accessToken && !destroyParked.value {
          await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            releaseDestroy.value = continuation
            destroyParked.value = true
          }
        }
      },
      reset: {}
    )
  } operation: {
    @Dependency(\.authTokensClient) var authTokensClient
    @Shared(.authSession) var session
    $session.withLock { $0 = .expired(oldTokens) }

    // Copy the resolved client out of the @Dependency wrapper: the Task
    // closures below would otherwise capture the non-Sendable wrapper.
    let client = authTokensClient

    let destroyTask = Task { try await client.destroy() }

    // Wait until the destroy is parked on its first keychain delete.
    while !destroyParked.value {
      await Task.yield()
    }

    // Start a save while the destroy is still parked. The gate must hold
    // it back until the destroy has fully completed.
    let saveTask = Task { try await client.save(newTokens) }

    releaseDestroy.value?.resume()
    try await destroyTask.value
    try await saveTask.value

    // Strict ordering: both destroy deletes, then both save writes.
    #expect(order.value == [
      "delete:accessToken",
      "delete:refreshToken",
      "save:accessToken",
      "save:refreshToken",
    ])

    // The destroy cleared the session first; the save then ran to
    // completion and its publication went through against the cleared
    // session.
    #expect(session == newTokens.toSession())
  }
}
