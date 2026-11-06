// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "wireguard_flutter",
    platforms: [.iOS("15.0"), .macOS("12.0")],   // WireGuardKit's minimums
    products: [
        .library(name: "wireguard-flutter", targets: ["wireguard_flutter"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework"),
        .package(url: "https://github.com/mysteriumnetwork/wireguard-apple.git", exact: "0.6.0")
    ],
    targets: [
        .target(
            name: "wireguard_flutter",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework"),
                .product(name: "WireGuardKit", package: "wireguard-apple")
            ]
        )
    ]
)