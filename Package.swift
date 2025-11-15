// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "JWTAuth",
  platforms: [
    .macOS(.v14),
    .iOS(.v17),
    .watchOS(.v9),
    .tvOS(.v17),
  ],
  products: [
    // Products define the executables and libraries a package produces, making them visible to other packages.
    .library(
      name: "JWTAuth",
      targets: ["JWTAuth"])
  ],
  dependencies: [
    .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.10.0"),
    .package(url: "https://github.com/pointfreeco/swift-sharing", from: "2.7.4"),
    .package(url: "https://github.com/auth0/JWTDecode.swift", from: "3.3.0"),
    .package(url: "https://github.com/auth0/SimpleKeychain", from: "1.3.0"),
    .package(url: "https://github.com/indigo-ce/http-request-client", from: "1.5.0"),
    .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.5"),
  ],
  targets: [
    // Targets are the basic building blocks of a package, defining a module or a test suite.
    // Targets can depend on other targets in this package and products from dependencies.
    .target(
      name: "JWTAuth",
      dependencies: [
        .product(name: "Dependencies", package: "swift-dependencies"),
        .product(name: "DependenciesMacros", package: "swift-dependencies"),
        .product(name: "HTTPRequestClient", package: "http-request-client"),
        .product(name: "JWTDecode", package: "JWTDecode.swift"),
        .product(name: "Sharing", package: "swift-sharing"),
        .product(name: "SimpleKeychain", package: "SimpleKeychain"),
      ]
    ),
    .testTarget(
      name: "JWTAuthTests",
      dependencies: ["JWTAuth"]
    ),
  ],
  swiftLanguageModes: [.v6]
)
