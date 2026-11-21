#if os(macOS)
import Foundation
import TorrentCore

/// UserDefaults keys (shared by `@AppStorage` in the Settings window and by the
/// launch-time `SessionConfig` builder).
enum SettingsKey {
    static let downloadDirectory = "downloadDirectory"
    static let notifyOnCompletion = "notifyOnCompletion"
    static let preventSleep = "preventSleep"
    static let encryption = "encryption"
    static let listenPort = "listenPort"              // 0 = automatic (random, remembered)
    static let maxPeersPerTorrent = "maxPeersPerTorrent"
    static let maxConnections = "maxConnections"
    static let limitDownload = "limitDownload"
    static let downloadLimitKB = "downloadLimitKB"    // kB/s (1000 bytes, like Finder)
    static let limitUpload = "limitUpload"
    static let uploadLimitKB = "uploadLimitKB"
    static let enableDHT = "enableDHT"
    static let enablePEX = "enablePEX"
    static let enableUTP = "enableUTP"
    static let enableLSD = "enableLSD"
    static let enablePortMapping = "enablePortMapping"
    static let extraTrackers = "extraTrackers"
    /// Developer/testing override, never shown in the UI: `open Astor.app --args -stateDirectory /path`.
    static let stateDirectory = "stateDirectory"
}

/// The settings that feed `SessionConfig`. The engine's config is immutable once
/// the session starts, so these are read once at launch; the Settings window
/// compares the live defaults with the launch snapshot to offer a restart.
struct EngineSettings: Equatable, Sendable {
    var encryption: EncryptionPolicy
    var listenPort: Int
    var maxPeersPerTorrent: Int
    var maxConnections: Int
    var downloadLimitKB: Int?     // nil = unlimited
    var uploadLimitKB: Int?
    var enableDHT: Bool
    var enablePEX: Bool
    var enableUTP: Bool
    var enableLSD: Bool
    var enablePortMapping: Bool
    var extraTrackers: Bool

    static func registerDefaults() {
        UserDefaults.standard.register(defaults: [
            SettingsKey.downloadDirectory: SessionConfig.defaultDownloadDirectory.path,
            SettingsKey.notifyOnCompletion: true,
            SettingsKey.preventSleep: true,
            SettingsKey.encryption: EncryptionPolicy.prefer.rawValue,
            SettingsKey.listenPort: 0,
            SettingsKey.maxPeersPerTorrent: 200,
            SettingsKey.maxConnections: 600,
            SettingsKey.limitDownload: false,
            SettingsKey.downloadLimitKB: 5_000,
            SettingsKey.limitUpload: false,
            SettingsKey.uploadLimitKB: 1_000,
            SettingsKey.enableDHT: true,
            SettingsKey.enablePEX: true,
            SettingsKey.enableUTP: true,
            SettingsKey.enableLSD: true,
            SettingsKey.enablePortMapping: true,
            SettingsKey.extraTrackers: true,
        ])
    }

    static func current(_ d: UserDefaults = .standard) -> EngineSettings {
        EngineSettings(
            encryption: EncryptionPolicy(rawValue: d.string(forKey: SettingsKey.encryption) ?? "") ?? .prefer,
            listenPort: d.integer(forKey: SettingsKey.listenPort),
            maxPeersPerTorrent: d.integer(forKey: SettingsKey.maxPeersPerTorrent),
            maxConnections: d.integer(forKey: SettingsKey.maxConnections),
            downloadLimitKB: d.bool(forKey: SettingsKey.limitDownload) ? d.integer(forKey: SettingsKey.downloadLimitKB) : nil,
            uploadLimitKB: d.bool(forKey: SettingsKey.limitUpload) ? d.integer(forKey: SettingsKey.uploadLimitKB) : nil,
            enableDHT: d.bool(forKey: SettingsKey.enableDHT),
            enablePEX: d.bool(forKey: SettingsKey.enablePEX),
            enableUTP: d.bool(forKey: SettingsKey.enableUTP),
            enableLSD: d.bool(forKey: SettingsKey.enableLSD),
            enablePortMapping: d.bool(forKey: SettingsKey.enablePortMapping),
            extraTrackers: d.bool(forKey: SettingsKey.extraTrackers))
    }

    static var stateDirectory: URL {
        if let p = UserDefaults.standard.string(forKey: SettingsKey.stateDirectory), !p.isEmpty {
            return URL(fileURLWithPath: (p as NSString).expandingTildeInPath, isDirectory: true)
        }
        return SessionConfig.defaultStateDirectory
    }

    /// The download folder new torrents go to (applies immediately; passed per add).
    static var downloadDirectory: URL {
        let p = UserDefaults.standard.string(forKey: SettingsKey.downloadDirectory) ?? ""
        return p.isEmpty ? SessionConfig.defaultDownloadDirectory
                         : URL(fileURLWithPath: (p as NSString).expandingTildeInPath, isDirectory: true)
    }

    func sessionConfig() -> SessionConfig {
        var c = SessionConfig(downloadDirectory: EngineSettings.downloadDirectory,
                              stateDirectory: EngineSettings.stateDirectory)
        c.encryption = encryption
        c.listenPort = (1024...65535).contains(listenPort) ? UInt16(listenPort) : 0
        c.maxPeersPerTorrent = max(10, maxPeersPerTorrent)
        c.maxConnectionsGlobal = max(c.maxPeersPerTorrent, maxConnections)
        c.downloadRateLimit = downloadLimitKB.map { max(1, $0) * 1000 } ?? 0
        c.uploadRateLimit = uploadLimitKB.map { max(1, $0) * 1000 } ?? 0
        c.enableDHT = enableDHT
        c.enablePEX = enablePEX
        c.enableUTP = enableUTP
        c.enableLSD = enableLSD
        c.enablePortMapping = enablePortMapping
        if !extraTrackers { c.extraTrackers = [] }
        return c
    }
}

extension EncryptionPolicy {
    var title: String {
        switch self {
        case .prefer: "Prefer encryption (recommended)"
        case .require: "Require encryption"
        case .disabled: "Don't encrypt"
        }
    }

    var explanation: String {
        switch self {
        case .prefer: "Encrypts whenever the other side supports it, and falls back to plain connections so you can still reach everyone."
        case .require: "Only connects to peers that encrypt. Can help if your internet provider slows down BitTorrent, but you'll find fewer peers."
        case .disabled: "Never encrypts. Reaches the same peers with slightly less overhead, but your traffic is easier to recognize and throttle."
        }
    }
}
#endif
