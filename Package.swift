// swift-tools-version: 6.2
// Astor — a BitTorrent client written from scratch for Apple Silicon.
//
// TorrentCore is the portable engine. It only uses BSD sockets, Dispatch,
// CryptoKit and Foundation so it can later ship unchanged on iPhone and iPad
// (A-series / M-series). The `astor` CLI and the `AstorApp` SwiftUI app are the
// macOS front ends (`scripts/make-app.sh` bundles AstorApp into Astor.app).
import PackageDescription

let package = Package(
    name: "Astor",
    platforms: [
        .macOS(.v26),
        .iOS(.v26),
    ],
    products: [
        .library(name: "TorrentCore", targets: ["TorrentCore"]),
        .executable(name: "astor", targets: ["astor"]),
        .executable(name: "AstorApp", targets: ["AstorApp"]),
    ],
    targets: [
        .target(name: "TorrentCore"),
        .executableTarget(
            name: "astor",
            dependencies: ["TorrentCore"]
        ),
        // macOS app (SwiftUI, Liquid Glass). Sources are macOS-only; see docs/APP.md.
        .executableTarget(
            name: "AstorApp",
            dependencies: ["TorrentCore"]
        ),
        .testTarget(
            name: "TorrentCoreTests",
            dependencies: ["TorrentCore"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
