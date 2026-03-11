import Dependencies
import DependenciesMacros
import Foundation
@preconcurrency import SimpleKeychain


extension DependencyValues {
  /// Access to the SimpleKeychain instance via the dependency injection system.
  ///
  /// This property provides access to the keychain for secure storage operations.
  /// The SimpleKeychain library is used as the underlying implementation for
  /// all keychain operations in the JWT auth client.
  ///
  /// ## Usage
  ///
  /// ```swift
  /// @Dependency(\.simpleKeychain) var keychain
  /// 
  /// // Direct keychain operations (rarely needed)
  /// try keychain.set("value", forKey: "key")
  /// let value = try keychain.string(forKey: "key")
  /// ```
  ///
  /// > Note: In most cases, you should use `KeychainClient` instead of accessing
  /// > SimpleKeychain directly, as it provides a higher-level, type-safe interface.
  public var simpleKeychain: SimpleKeychain {
    get { self[SimpleKeychainKey.self] }
    set { self[SimpleKeychainKey.self] = newValue }
  }

  /// Private dependency key for SimpleKeychain.
  private enum SimpleKeychainKey: DependencyKey {
    /// The live implementation using the default SimpleKeychain instance.
    public static let liveValue = SimpleKeychain()
  }

  /// Test implementation of SimpleKeychain for testing purposes.
  static var testValue: SimpleKeychain {
    SimpleKeychain()
  }
}
