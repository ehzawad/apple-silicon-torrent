#if os(macOS)
import Foundation
import TorrentCore

/// One row of the torrent table. A small, Equatable value built off the main
/// thread from `TorrentStatus`, so SwiftUI can diff the table cheaply every second.
struct TorrentRow: Identifiable, Equatable, Sendable {
    let id: String              // TorrentStatus.infoHash (v1 hex, or v2 hex for v2-only)
    var name: String
    var state: TorrentState
    var progress: Double
    var downloadRate: Double
    var uploadRate: Double
    var peers: Int
    var seeds: Int
    var eta: Double?
    var size: Int64
    var completed: Int64
    var uploaded: Int64
    var downloaded: Int64
    var error: String?
    var queueIndex: Int

    init(_ s: TorrentStatus, index: Int) {
        id = s.infoHash
        name = s.name
        state = s.state
        progress = s.progress
        downloadRate = s.downloadRate
        uploadRate = s.uploadRate
        peers = s.connectedPeers
        seeds = s.connectedSeeds
        eta = s.eta
        size = s.wantedBytes
        completed = s.completedBytes
        uploaded = s.uploadedTotal
        downloaded = s.downloadedTotal
        error = s.error
        queueIndex = index
    }

    // MARK: Sort keys (Table sorts through KeyPathComparator, so they must be Comparable)

    var stateRank: Int {
        switch state {
        case .downloading: 0
        case .fetchingMetadata: 1
        case .checking: 2
        case .seeding: 3
        case .paused: 4
        case .error: 5
        }
    }
    var etaSortKey: Double { eta ?? .infinity }
    var ratio: Double { Double(uploaded) / Double(max(1, max(downloaded, size))) }

    // MARK: Presentation

    var isPaused: Bool { state == .paused }
    var isActive: Bool { state != .paused && state != .error }
    var isComplete: Bool { size > 0 && completed >= size }

    var statusText: String {
        switch state {
        case .fetchingMetadata: "Getting info…"
        case .checking: "Checking \(Fmt.percent(progress, digits: 0))"
        case .downloading:
            if peers == 0 { "Looking for peers" }
            else if downloadRate < 512 { "Waiting for data" }
            else { "Downloading" }
        case .seeding: isComplete ? "Seeding" : "Done (partial)"
        case .paused: "Paused"
        case .error: "Error"
        }
    }

    var statusSymbol: String {
        switch state {
        case .fetchingMetadata: "magnifyingglass"
        case .checking: "arrow.triangle.2.circlepath"
        case .downloading: "arrow.down.circle.fill"
        case .seeding: "arrow.up.circle.fill"
        case .paused: "pause.circle.fill"
        case .error: "exclamationmark.triangle.fill"
        }
    }

    var etaText: String {
        switch state {
        case .downloading: eta == nil ? (peers == 0 ? "—" : "∞") : Fmt.duration(eta)
        case .seeding: "Done"
        default: "—"
        }
    }

    var peersText: String {
        guard isActive else { return "" }
        return seeds > 0 ? "\(peers) (\(seeds))" : "\(peers)"
    }

    var sizeText: String { size > 0 ? Fmt.bytes(size) : "—" }
}

/// Sidebar filters.
enum TorrentFilter: String, CaseIterable, Identifiable, Sendable {
    case all, downloading, seeding, completed, paused, errors
    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All Torrents"
        case .downloading: "Downloading"
        case .seeding: "Seeding"
        case .completed: "Completed"
        case .paused: "Paused"
        case .errors: "Errors"
        }
    }

    var symbol: String {
        switch self {
        case .all: "tray.full"
        case .downloading: "arrow.down.circle"
        case .seeding: "arrow.up.circle"
        case .completed: "checkmark.circle"
        case .paused: "pause.circle"
        case .errors: "exclamationmark.triangle"
        }
    }

    var emptyText: String {
        switch self {
        case .all: "Add a torrent to get started."
        case .downloading: "Nothing is downloading right now."
        case .seeding: "Nothing is being shared right now."
        case .completed: "No downloads have finished yet."
        case .paused: "No torrents are paused."
        case .errors: "No torrents have problems."
        }
    }

    func includes(_ r: TorrentRow) -> Bool {
        switch self {
        case .all: true
        case .downloading: r.state == .downloading || r.state == .fetchingMetadata || r.state == .checking
        case .seeding: r.state == .seeding
        case .completed: r.isComplete
        case .paused: r.state == .paused
        case .errors: r.state == .error
        }
    }
}

/// Static facts from the torrent's metainfo (fetched once, cached by id).
struct TorrentDetails: Sendable {
    struct File: Identifiable, Sendable {
        let id: Int            // index among non-padding files (what `Torrent.selectFiles` takes)
        let path: String
        let length: Int64
    }

    var name: String
    var infoHashV1: String?
    var infoHashV2: String?
    var version: TorrentVersion
    var isPrivate: Bool
    var isMultiFile: Bool
    var comment: String?
    var createdBy: String?
    var creationDate: Date?
    var announceTiers: [[String]]
    var webSeeds: [String]
    var files: [File]
    var contentLength: Int64
    var pieceLength: Int
    var pieceCount: Int

    init(_ mi: Metainfo) {
        name = mi.name
        infoHashV1 = mi.infoHashes.v1?.hex
        infoHashV2 = mi.infoHashes.v2?.hex
        version = mi.version
        isPrivate = mi.isPrivate
        isMultiFile = mi.isMultiFile
        comment = mi.comment
        createdBy = mi.createdBy
        creationDate = mi.creationDate
        announceTiers = mi.announceTiers
        webSeeds = mi.webSeeds
        var idx = 0
        var out: [File] = []
        for f in mi.files where !f.isPadding {
            out.append(File(id: idx, path: f.path.joined(separator: "/"), length: f.length))
            idx += 1
        }
        files = out
        contentLength = mi.contentLength
        pieceLength = mi.pieceLength
        pieceCount = mi.pieceCount
    }

    /// magnet:?xt=urn:btih:…&xt=urn:btmh:1220…&dn=…&tr=…
    var magnetLink: String {
        var c = URLComponents()
        c.scheme = "magnet"
        var items: [URLQueryItem] = []
        if let v1 = infoHashV1 { items.append(URLQueryItem(name: "xt", value: "urn:btih:\(v1)")) }
        if let v2 = infoHashV2 { items.append(URLQueryItem(name: "xt", value: "urn:btmh:1220\(v2)")) }
        items.append(URLQueryItem(name: "dn", value: name))
        for url in announceTiers.joined() { items.append(URLQueryItem(name: "tr", value: url)) }
        for ws in webSeeds { items.append(URLQueryItem(name: "ws", value: ws)) }
        c.queryItems = items
        return c.string ?? "magnet:?xt=urn:btih:\(infoHashV1 ?? "")"
    }
}

/// Footer / status bar facts.
struct SessionInfo: Equatable, Sendable {
    var downloadRate: Double = 0
    var uploadRate: Double = 0
    var dhtNodes: Int = 0
    var listenPort: UInt16 = 0
    var externalIP: String?
    var connections: Int = 0
    var incomingConnections: Int = 0
    /// Methods with a working mapping, e.g. ["UPnP"], ["NAT-PMP", "PCP"].
    var mappedVia: [String] = []
    var mappingErrors: [String] = []

    init() {}

    init(_ s: SessionStatus) {
        downloadRate = s.downloadRate
        uploadRate = s.uploadRate
        dhtNodes = s.dhtNodesV4 + s.dhtNodesV6
        listenPort = s.listenPort
        externalIP = s.externalIP
        connections = s.connections
        incomingConnections = s.incomingConnections
        var via: [String] = []
        for m in s.portMappings where m.error == nil && m.externalPort != nil && !via.contains(m.method) {
            via.append(m.method)
        }
        mappedVia = via
        mappingErrors = s.portMappings.compactMap { m in m.error.map { "\(m.method) \(m.proto): \($0)" } }
    }
}

/// Everything one poll brings back from the engine.
struct EngineSnapshot: Sendable {
    var session: SessionInfo
    var statuses: [TorrentStatus]
    var rows: [TorrentRow]
}
#endif
