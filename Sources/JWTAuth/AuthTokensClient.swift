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
  /// 1. Saves the new tokens to keychain, best-effort restoring the previous
  ///    values if a write fails
  /// 2. Updates the shared session state in memory once both keychain writes
  ///    have succeeded
  ///
  /// The in-memory session is published only after the tokens are durably
  /// persisted, and only if no concurrent writer (logout, account switch,
  /// `loadSession`, …) changed the session while the save was in flight.
  /// The live implementation additionally serializes save and destroy
  /// operations, so they can never interleave with each other.
  ///
  /// If a keychain write fails, the previous values are best-effort
  /// restored — restoration itself can fail, in which case the keychain may
  /// be left without the previous credentials and the user must sign in
  /// again — the in-memory session is left untouched, and the error is
  /// thrown. Observers of `@Shared(.authSession)` never see tokens that
  /// aren't persisted.
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
  /// The live implementation serializes save and destroy operations, so a
  /// concurrent save can never interleave with an in-flight destroy.
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

/// A minimal FIFO gate that lets one awaiter run at a time. The live
/// `AuthTokensClient` uses it to serialize persist operations so that a
/// concurrent destroy can never interleave with an in-flight save (e.g.
/// deleting the keychain entries between the save's writes and its session
/// publication, or vice versa).
private final class PersistSerialGate: @unchecked Sendable {
  private let lock = NSLock()
  private var isRunning = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  /// Suspends until it is the caller's turn, then marks the gate busy.
  func acquire() async {
    await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
      let entered = self.lock.withLock {
        if self.isRunning {
          self.waiters.append(continuation)
          return false
        }
        self.isRunning = true
        return true
      }
      // Fast path: the gate was free — resume immediately.
      if entered {
        continuation.resume()
      }
    }
  }

  /// Marks the gate free and resumes the oldest waiter, if any.
  func release() {
    let next = self.lock.withLock { () -> CheckedContinuation<Void, Never>? in
      if self.waiters.isEmpty {
        self.isRunning = false
        return nil
      }
      return self.waiters.removeFirst()
    }
    next?.resume()
  }
}

extension AuthTokensClient: DependencyKey {
  public static let liveValue = { () -> AuthTokensClient in
    @Dependency(\.keychainClient) var keychainClient
    let persistGate = PersistSerialGate()

    @Sendable
    func persist(_ tokens: AuthTokens?) async throws {
      @Shared(.authSession) var session

      // Serialize persist operations: a concurrent destroy must never
      // interleave with an in-flight save (or vice versa), e.g. deleting
      // the keychain entries between the save's writes and its session
      // publication — that would leave memory and the keychain
      // contradicting each other in both directions.
      await persistGate.acquire()
      defer { persistGate.release() }

      // Snapshot the session at entry so the publication below only fires
      // when no *other* writer (logout from outside this client, account
      // switch, loadSession, direct writes) changed it while this save was
      // suspended on the keychain. Persist operations themselves are
      // already serialized by the gate above; this guard covers the rest.
      let startSession = session

      if let tokens {
        // Write the keychain first and publish the in-memory session only
        // after both writes succeed. This keeps `@Shared(.authSession)` a
        // "durably persisted" signal: observers (e.g. a root view that
        // dismisses the auth sheet when a valid session appears) never see
        // tokens that failed to persist.
        //
        // Capture the old values so we can restore them on a partial
        // save failure. `keychainClient.save` does its own delete-then-
        // set under the hood, so a set-throw after the internal delete
        // leaves the corresponding entry empty. Restoring on failure
        // keeps the keychain in a cold-launch-restorable state — the
        // next `loadTokens()` returns the old pair (or nil if there
        // were none originally) instead of nil because one of the
        // new saves was mid-write.
        let oldAccess = try? await keychainClient.load(.accessToken)
        let oldRefresh = try? await keychainClient.load(.refreshToken)

        do {
          try await keychainClient.save(tokens.access, .accessToken)
          try await keychainClient.save(tokens.refresh, .refreshToken)
        } catch {
          // Best-effort restore the old values. Use `try?` so a
          // restore failure doesn't mask the original error.
          if let oldAccess {
            try? await keychainClient.save(oldAccess, .accessToken)
          } else {
            try? await keychainClient.delete(.accessToken)
          }
          if let oldRefresh {
            try? await keychainClient.save(oldRefresh, .refreshToken)
          } else {
            try? await keychainClient.delete(.refreshToken)
          }
          throw error
        }

        // Both keychain writes succeeded — publish to memory now, but only
        // if the session is unchanged since entry (snapshot above). On any
        // failure above, the in-memory session is left untouched.
        $session.withLock { current in
          if current == startSession {
            current = tokens.toSession()
          }
        }
      } else {
        // Destroy clears the in-memory session first so observers see the
        // logout immediately, then removes both keychain entries explicitly.
        $session.withLock { $0 = nil }

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
