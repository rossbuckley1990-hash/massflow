// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "Massflow",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "massflow", targets: ["Massflow"])
    ],
    targets: [
        .target(
            name: "CMassflowKernel",
            publicHeadersPath: "include",
            cSettings: [
                .unsafeFlags(["-O3", "-Wno-deprecated-declarations"])
            ],
            linkerSettings: [
                .linkedLibrary("compression")
            ]
        ),
        .executableTarget(
            name: "Massflow",
            dependencies: ["CMassflowKernel"],
            swiftSettings: [
                .unsafeFlags(["-O", "-warnings-as-errors"])
            ],
            linkerSettings: [
                .linkedFramework("Cocoa"),
                .linkedFramework("CoreGraphics"),
                .linkedFramework("CryptoKit"),
                .linkedFramework("IOKit"),
                .linkedFramework("Foundation")
            ]
        )
    ]
)
