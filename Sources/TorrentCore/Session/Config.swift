import Foundation

/// Client identity (Azureus-style peer id: "-AS0100-" + 12 random bytes).
public enum ClientIdentity {
    public static let name = "Astor"
    public static let version = "0.1.0"
    public static let peerIDPrefix = "-AS0100-"
    /// "v" field of the BEP 10 extension handshake.
    public static var userAgent: String { "\(name) \(version)" }

    public static func makePeerID() -> Data {
        var id = Data(peerIDPrefix.utf8)
        // Printable random suffix (some trackers mangle binary peer ids).
        let alphabet = Array("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".utf8)
        let rnd = Data.random(12)
        for b in rnd { id.append(alphabet[Int(b) % alphabet.count]) }
        return id
    }
}

/// MSE/PE (Message Stream Encryption) policy.
public enum EncryptionPolicy: String, Sendable, CaseIterable {
    /// Never encrypt (plaintext BitTorrent only).
    case disabled
    /// Try encrypted first, fall back to plaintext; accept both incoming.
    case prefer
    /// Only encrypted connections (RC4), both directions. Best against ISP throttling.
    case require
}

/// Where a peer address came from.
public enum PeerSource: String, Sendable, CaseIterable {
    case tracker, dht, pex, lsd, incoming, magnet, resume, holepunch, manual
}

public struct SessionConfig: Sendable {
    /// TCP+UDP listen port (0 = pick a random high port once and persist it).
    public var listenPort: UInt16 = 0
    public var downloadDirectory: URL
    /// Where resume data, DHT state and settings live.
    public var stateDirectory: URL

    // Protocol toggles
    public var enableDHT = true
    public var enableUTP = true
    public var enableTCP = true
    public var enablePEX = true
    public var enableLSD = true
    public var enablePortMapping = true
    public var enableHolepunch = true
    public var enableWebSeeds = true
    public var encryption: EncryptionPolicy = .prefer
    /// Prefer uTP over TCP for outgoing connections to peers known to support it.
    public var preferUTP = false

    // Connection limits — deliberately aggressive defaults for fast swarming.
    public var maxPeersPerTorrent = 200
    public var maxConnectionsGlobal = 600
    /// Max simultaneous outgoing connection attempts (half-open).
    public var maxHalfOpen = 100
    /// New outgoing connection attempts per second per session.
    public var connectionsPerSecond = 50
    public var connectTimeout: Double = 7
    public var uploadSlotsPerTorrent = 8

    // Rate limits in bytes/s (0 = unlimited)
    public var downloadRateLimit = 0
    public var uploadRateLimit = 0

    // Trackers
    /// Announce to every tracker in every tier simultaneously (much faster peer discovery).
    public var announceToAllTrackers = true
    public var announceToAllTiers = true
    /// Extra public trackers appended to non-private torrents.
    public var extraTrackers: [String] = SessionConfig.defaultPublicTrackers
    public var numWant = 200

    // Requests
    /// Seconds of data to keep requested from each peer (libtorrent's request_queue_time).
    public var requestQueueTime: Double = 3
    public var maxOutstandingRequestsPerPeer = 500
    public var minOutstandingRequestsPerPeer = 4

    // DNS
    /// Fall back to DNS-over-HTTPS when the system resolver fails or returns
    /// obviously blocked answers (common with ISP DNS filtering).
    public var dnsOverHTTPSFallback = true

    public init(downloadDirectory: URL, stateDirectory: URL) {
        self.downloadDirectory = downloadDirectory
        self.stateDirectory = stateDirectory
    }

    public static var defaultStateDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return base.appendingPathComponent("Astor", isDirectory: true)
    }

    public static var defaultDownloadDirectory: URL {
        FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first!
    }

    /// Well-known, long-lived open trackers (only added to public torrents).
    public static let defaultPublicTrackers: [String] = [
        "udp://tracker.opentrackr.org:1337/announce",
        "udp://open.demonii.com:1337/announce",
        "udp://open.stealth.si:80/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "udp://exodus.desync.com:6969/announce",
        "udp://tracker.openbittorrent.com:6969/announce",
        "udp://explodie.org:6969/announce",
        "udp://tracker.dler.org:6969/announce",
        "udp://tracker.qu.ax:6969/announce",
        "udp://opentracker.io:6969/announce",
        "https://tracker.tamersunion.org:443/announce",
        "http://tracker.opentrackr.org:1337/announce",
    ]

    public static let dhtBootstrapNodes: [String] = [
        "router.bittorrent.com:6881",
        "dht.transmissionbt.com:6881",
        "router.utorrent.com:6881",
        "dht.libtorrent.org:25401",
        "dht.aelitis.com:6881",
    ]
}
