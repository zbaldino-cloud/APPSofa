// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppSOFACore",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "AppSOFACore", targets: ["AppSOFACore"])
    ],
    targets: [
        .target(
            name: "AppSOFACore",
            path: "Client/AppSOFA",
            exclude: [
                "AppSOFA.swift",
                "Models/ApplicationRequirement.swift",
                "Models/ChromeSecurityRelease.swift",
                "Models/InstalledApplication.swift",
                "Models/SecurityInformation.swift",
                "Services/ApplicationScanner.swift",
                "Services/ChromeVersionService.swift",
                "Services/CISAKEVService.swift",
                "Services/FeedLoader.swift",
                "Services/SecuritySLAService.swift"
            ],
            sources: [
                "Services/FeedFreshnessService.swift",
                "Services/VersonComparator.swift",
                "Services/FeedSignatureVerifier.swift"
            ]
        ),
        .testTarget(
            name: "AppSOFACoreTests",
            dependencies: ["AppSOFACore"],
            path: "Client/AppSOFATests"
        )
    ]
)
