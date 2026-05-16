// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "CryptoKitBridge",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "CryptoKitBridge",
            type: .static,
            targets: ["CryptoKitBridge"])
    ],
    targets: [
        .target(
            name: "CryptoKitBridge",
            path: "Sources/CryptoKitBridge",
            publicHeadersPath: "include")
    ]
)
