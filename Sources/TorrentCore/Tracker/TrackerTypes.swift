import Foundation

// MARK: - Public contract types (docs/ARCHITECTURE.md, "Trackers")

/// Announce event (BEP 3). The raw value is the HTTP `event=` parameter value;
/// `.none` means the parameter is omitted (a regular re-announce).
public enum TrackerEvent: String, Sendable {
    case none = "", started, completed, stopped

    /// BEP 15 numeric event code: 0 none, 1 completed, 2 started, 3 stopped.
    public var udpCode: UInt32 {
        switch self {
        case .none: return 0
        case .completed: return 1
        case .started: return 2
        case .stopped: return 3
        }
    }
}

/// One announce of one info hash to one tracker.
public struct AnnounceRequest: Sendable {
    /// 20-byte info hash (v1, or the truncated v2 hash for the v2 swarm).
    public var infoHash: Data
    /// 20-byte peer id.
    public var peerID: Data
    public var port: UInt16
    public var uploaded: Int64
    public var downloaded: Int64
    public var left: Int64
    public var event: TrackerEvent
    /// Peers wanted. <= 0 lets the tracker choose (UDP sends -1, HTTP omits it).
    public var numWant: Int
    /// Per-torrent random key so trackers can recognise us across IP changes.
    public var key: UInt32
    /// Additive to the contract: the `tracker id` a previous HTTP response gave
    /// (sent back as `trackerid=`). Ignored by UDP trackers.
    public var trackerID: String?

    public init(infoHash: Data, peerID: Data, port: UInt16, uploaded: Int64 = 0,
                downloaded: Int64 = 0, left: Int64 = 0, event: TrackerEvent = .none,
                numWant: Int = 200, key: UInt32 = 0, trackerID: String? = nil) {
        self.infoHash = infoHash
        self.peerID = peerID
        self.port = port
        self.uploaded = uploaded
        self.downloaded = downloaded
        self.left = left
        self.event = event
        self.numWant = numWant
        self.key = key
        self.trackerID = trackerID
    }

    /// `left` as sent on the wire. A negative value means "unknown" (magnet link
    /// without metadata yet); like libtorrent we report 16 KiB rather than 0,
    /// because `left=0` tells the tracker we are a seed and many trackers then
    /// return no seeds at all.
    var effectiveLeft: Int64 { left < 0 ? 16 * 1024 : left }
}

/// A successful tracker response.
public struct AnnounceResponse: Sendable {
    /// Seconds until the next regular announce.
    public var interval: Int
    /// Minimum seconds between announces (HTTP only).
    public var minInterval: Int?
    /// IPv4 + IPv6 peers (deduplicated, unusable addresses / port 0 removed).
    public var peers: [PeerAddress]
    public var seeders: Int?
    public var leechers: Int?
    public var warning: String?
    /// Additive to the contract: `tracker id` to echo on later announces (HTTP).
    public var trackerID: String?
    /// Additive to the contract: our address as seen by the tracker
    /// (BEP 24 `external ip`), when the tracker reports it.
    public var externalIP: IPAddress?

    public init(interval: Int, minInterval: Int? = nil, peers: [PeerAddress] = [],
                seeders: Int? = nil, leechers: Int? = nil, warning: String? = nil,
                trackerID: String? = nil, externalIP: IPAddress? = nil) {
        self.interval = interval
        self.minInterval = minInterval
        self.peers = peers
        self.seeders = seeders
        self.leechers = leechers
        self.warning = warning
        self.trackerID = trackerID
        self.externalIP = externalIP
    }
}

/// Snapshot of one tracker URL's state for UI / CLI.
public struct TrackerStatus: Sendable {
    public var url: String
    public var tier: Int
    public var lastError: String?
    public var seeders: Int?
    public var leechers: Int?
    public var lastPeerCount: Int
    /// Seconds until the next scheduled announce (0 when not scheduled / due).
    public var nextAnnounceIn: Double
    public var isUpdating: Bool
    /// Additive to the contract: last `warning message` from the tracker.
    public var warning: String?

    public init(url: String, tier: Int, lastError: String? = nil, seeders: Int? = nil,
                leechers: Int? = nil, lastPeerCount: Int = 0, nextAnnounceIn: Double = 0,
                isUpdating: Bool = false, warning: String? = nil) {
        self.url = url
        self.tier = tier
        self.lastError = lastError
        self.seeders = seeders
        self.leechers = leechers
        self.lastPeerCount = lastPeerCount
        self.nextAnnounceIn = nextAnnounceIn
        self.isUpdating = isUpdating
        self.warning = warning
    }
}

/// Errors produced by the tracker module.
public enum TrackerError: Error, CustomStringConvertible, Sendable, Equatable {
    /// The tracker answered with `failure reason` (HTTP) or action 3 (UDP).
    case failure(String)
    case invalidURL(String)
    case unsupportedScheme(String)
    case invalidRequest(String)
    case timedOut
    case httpStatus(Int)
    case malformed(String)
    case dnsFailed(String)
    case network(String)

    public var description: String {
        switch self {
        case .failure(let m): return "tracker: \(m)"
        case .invalidURL(let u): return "invalid tracker URL: \(u)"
        case .unsupportedScheme(let s): return "unsupported tracker scheme: \(s)"
        case .invalidRequest(let m): return "invalid request: \(m)"
        case .timedOut: return "timed out"
        case .httpStatus(let c): return "HTTP \(c)"
        case .malformed(let m): return "malformed response: \(m)"
        case .dnsFailed(let h): return "could not resolve \(h)"
        case .network(let m): return "network error: \(m)"
        }
    }

    /// Whether the tracker itself answered (so trying another address of the
    /// same host is pointless).
    var isTrackerAnswer: Bool {
        if case .failure = self { return true }
        return false
    }
}

// MARK: - Internal helpers

/// Wraps a loop-confined value so it can ride inside a `@Sendable` closure that
/// hops back to the event loop (e.g. URLSession completion -> `loop.execute`).
struct TrackerUnchecked<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}

/// Parsed tracker URL: `scheme://[userinfo@]host[:port][/path][?query][#frag]`.
struct TrackerURLParts: Equatable, Sendable {
    var scheme: String          // lowercased
    var host: String            // without brackets
    var port: UInt16?
    var pathAndQuery: String    // "" or starts with "/" or "?"

    static func parse(_ raw: String) -> TrackerURLParts? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let sep = s.range(of: "://") else { return nil }
        let scheme = s[..<sep.lowerBound].lowercased()
        guard !scheme.isEmpty, scheme.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." })
        else { return nil }
        var rest = Substring(s[sep.upperBound...])
        if let hash = rest.firstIndex(of: "#") { rest = rest[..<hash] }
        let authEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) ?? rest.endIndex
        var authority = rest[..<authEnd]
        let pathAndQuery = String(rest[authEnd...])
        if let at = authority.lastIndex(of: "@") { authority = authority[authority.index(after: at)...] }
        var host: Substring
        var portStr: Substring?
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { return nil }
            host = authority[authority.index(after: authority.startIndex)..<close]
            let after = authority[authority.index(after: close)...]
            if after.hasPrefix(":") { portStr = after.dropFirst() } else if !after.isEmpty { return nil }
        } else if let colon = authority.lastIndex(of: ":") {
            host = authority[..<colon]
            portStr = authority[authority.index(after: colon)...]
            if host.contains(":") { return nil }
        } else {
            host = authority
        }
        guard !host.isEmpty else { return nil }
        var port: UInt16?
        if let ps = portStr {
            if ps.isEmpty { port = nil } else {
                guard let p = UInt16(ps), p != 0 else { return nil }
                port = p
            }
        }
        return TrackerURLParts(scheme: scheme, host: String(host), port: port, pathAndQuery: pathAndQuery)
    }

    /// Key used to deduplicate tracker URLs (scheme + host case-insensitive).
    static func dedupeKey(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let p = parse(s) else { return s }
        var k = p.scheme + "://" + p.host.lowercased()
        if let port = p.port { k += ":\(port)" }
        return k + p.pathAndQuery
    }
}

/// Retry schedule for failed announces: 30 s, 60 s, 120 s, ... capped at 30 min.
enum TrackerBackoff {
    static let base: Double = 30
    static let maximum: Double = 1800

    /// Delay before the next attempt after `failures` consecutive failures (>= 1).
    static func delay(failures: Int) -> Double {
        guard failures > 0 else { return 0 }
        let exp = min(failures - 1, 16)
        return min(base * Double(1 << exp), maximum)
    }
}
