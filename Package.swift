// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VirgilE3Kit",
    platforms: [
        .macOS(.v10_11), .iOS(.v9), .tvOS(.v9), .watchOS(.v2)
    ],
    products: [
        .library(
            name: "VirgilE3Kit",
            targets: ["VirgilE3Kit"]),
    ],

    dependencies: [
        .package(url: "https://github.com/VirgilSecurity/virgil-pythia-x.git", branch: "develop-spm-test"),
        .package(url: "https://github.com/VirgilSecurity/virgil-ratchet-x.git", branch: "develop-spm")
    ],

    targets: [
        .target(
            name: "VirgilE3Kit",
            dependencies: [
                .product(name: "VirgilSDKRatchet", package: "virgil-ratchet-x"),
                .product(name: "VirgilSDKPythia", package: "virgil-pythia-x"),
            ],
            path: "Source"
        ),
        .testTarget(
            name: "VirgilE3KitTests",
            dependencies: ["VirgilE3Kit"],
            path: "Tests/Swift",
            resources: [
                .process("Data")
            ],
            swiftSettings: [
                .define("SPM_BUILD")
            ]
        )
    ]
)
