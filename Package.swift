// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Clawdy",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "Clawdy",
            targets: ["Clawdy"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Clawdy",
            dependencies: [],
            path: "Clawdy"
        )
    ]
)
