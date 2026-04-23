// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "passage-webauthn",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "PassageWebAuthn",
            targets: ["PassageWebAuthn"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.119.2"),
        .package(url: "https://github.com/vapor-community/passage.git", from: "0.3.5"),
        .package(url: "https://github.com/swift-server/webauthn-swift.git", from: "1.0.0-beta.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.8.1"..<"5.0.0"),
        .package(url: "https://github.com/unrelentingtech/SwiftCBOR.git", from: "0.4.7"),
    ],
    targets: [
        .target(name: "PassageWebAuthn", dependencies: [
            .product(name: "Vapor",     package: "vapor"),
            .product(name: "Passage",   package: "passage"),
            .product(name: "WebAuthn",  package: "webauthn-swift"),
        ]),
        .testTarget(name: "PassageWebAuthnTests", dependencies: [
            "PassageWebAuthn",
            .product(name: "VaporTesting", package: "vapor"),
            .product(name: "Crypto",       package: "swift-crypto"),
            "SwiftCBOR",
        ]),
    ]
)
