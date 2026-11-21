import Foundation

/// The info-hash(es) identifying a torrent.
///  * v1: SHA-1 of the bencoded info dict (20 bytes)
///  * v2: SHA-256 of the bencoded info dict (32 bytes) — BEP 52
/// A hybrid torrent has both.
public struct InfoHashes: Hashable, Sendable, CustomStringConvertible {
    public var v1: Data?
    public var v2: Data?

    public init(v1: Data?, v2: Data?) {
        precondition(v1 != nil || v2 != nil)
        self.v1 = v1
        self.v2 = v2
    }

    /// 20-byte identifier used on the wire (handshake, DHT, trackers, MSE SKEY):
    /// the v1 hash, or for v2-only torrents the v2 hash truncated to 20 bytes.
    public var primary: Data { v1 ?? v2!.prefix(20) }

    /// Truncated v2 hash (for announcing hybrid torrents in the v2 swarm too).
    public var v2Truncated: Data? { v2.map { Data($0.prefix(20)) } }

    /// All 20-byte identifiers this torrent answers to.
    public var all20: [Data] {
        var out: [Data] = []
        if let v1 { out.append(v1) }
        if let t = v2Truncated { out.append(t) }
        return out
    }

    public var isHybrid: Bool { v1 != nil && v2 != nil }
    public var description: String { (v1 ?? v2!).hex }
}

public enum TorrentVersion: String, Sendable {
    case v1, v2, hybrid
}

/// One entry in the torrent's linear byte space.
public struct TorrentFile: Sendable, Hashable {
    /// Path components relative to the torrent root (without the torrent name for multi-file).
    public var path: [String]
    public var length: Int64
    /// Offset of the first byte in the torrent's linear (piece) space.
    public var offset: Int64
    /// BEP 47 padding file (or an implicit v2 alignment gap) — never written to disk.
    public var isPadding: Bool
    /// v2 Merkle root of this file (nil for empty files / v1-only torrents).
    public var piecesRoot: Data?
    /// BEP 47 attributes: "x" executable, "h" hidden, "l" symlink.
    public var attributes: String
    public var symlinkPath: [String]?

    public var endOffset: Int64 { offset + length }
}

public struct MetainfoError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public init(_ m: String) { message = m }
    public var description: String { "metainfo: \(message)" }
}

/// A parsed .torrent (or the info dictionary obtained through ut_metadata).
public struct Metainfo: Sendable {
    public let infoDict: Data           // raw bencoded info dictionary
    public let info: BValue
    public let infoHashes: InfoHashes
    public let version: TorrentVersion
    public let name: String
    public let pieceLength: Int
    public let pieceCount: Int
    /// v1 SHA-1 piece hashes (20 bytes each). Empty for v2-only.
    public let v1Pieces: [Data]
    /// Files in linear order, including padding entries.
    public let files: [TorrentFile]
    public let totalLength: Int64       // size of the linear piece space (incl. padding)
    public let isPrivate: Bool
    public let isMultiFile: Bool

    // Outside the info dict (not available for magnet-only metadata):
    public var announceTiers: [[String]] = []
    public var webSeeds: [String] = []
    /// v2 piece layers: pieces root -> concatenated 32-byte piece hashes.
    public var pieceLayers: [Data: Data] = [:]
    public var comment: String?
    public var createdBy: String?
    public var creationDate: Date?

    /// Bytes that really live on disk (excludes padding).
    public var contentLength: Int64 { files.filter { !$0.isPadding }.reduce(0) { $0 + $1.length } }

    /// Length of piece `i` in linear space.
    public func pieceSize(_ i: Int) -> Int {
        if i == pieceCount - 1 {
            let rem = Int(totalLength - Int64(pieceLength) * Int64(pieceCount - 1))
            return rem
        }
        return pieceLength
    }

    // MARK: Parsing

    /// Parse a complete .torrent file.
    public init(torrentFile data: Data) throws {
        let (root, rawInfo) = try BDecoder.decode(data, capturing: "info")
        guard let rawInfo else { throw MetainfoError("missing info dictionary") }
        try self.init(infoDict: rawInfo)
        if let a = root["announce-list"]?.list {
            announceTiers = a.compactMap { tier in
                let urls = tier.list?.compactMap { $0.string }.filter { !$0.isEmpty } ?? []
                return urls.isEmpty ? nil : urls
            }
        }
        if announceTiers.isEmpty, let a = root["announce"]?.string, !a.isEmpty {
            announceTiers = [[a]]
        }
        if let ul = root["url-list"] {
            if let s = ul.string { webSeeds = [s] } else { webSeeds = ul.list?.compactMap { $0.string } ?? [] }
        }
        if let layers = root["piece layers"]?.dict {
            for (k, v) in layers { if let d = v.data { pieceLayers[k] = d } }
        }
        comment = root["comment"]?.string
        createdBy = root["created by"]?.string
        if let ts = root["creation date"]?.int { creationDate = Date(timeIntervalSince1970: Double(ts)) }
    }

    /// Parse a raw bencoded info dictionary (e.g. received via BEP 9).
    public init(infoDict raw: Data) throws {
        infoDict = raw
        let info = try BDecoder.decode(raw)
        guard case .dict = info else { throw MetainfoError("info is not a dictionary") }
        self.info = info

        guard let pl = info["piece length"]?.int, pl > 0, pl <= 256 * 1024 * 1024 else {
            throw MetainfoError("invalid piece length")
        }
        pieceLength = Int(pl)
        name = Self.sanitize(info["name"]?.string ?? "unnamed")
        isPrivate = info["private"]?.int == 1

        let metaVersion = info["meta version"]?.int ?? 1
        let hasV2 = metaVersion == 2 && info["file tree"]?.dict != nil
        let hasV1 = info["pieces"]?.data != nil

        guard hasV1 || hasV2 else { throw MetainfoError("neither v1 pieces nor v2 file tree present") }
        version = hasV1 && hasV2 ? .hybrid : (hasV2 ? .v2 : .v1)
        infoHashes = InfoHashes(v1: hasV1 ? Hash.sha1(raw) : nil, v2: hasV2 ? Hash.sha256(raw) : nil)

        if hasV2 {
            guard pieceLength >= 16384, pieceLength & (pieceLength - 1) == 0 else {
                throw MetainfoError("v2 piece length must be a power of two >= 16 KiB")
            }
        }

        var files: [TorrentFile] = []
        if hasV1 {
            // v1 / hybrid: authoritative linear layout including BEP 47 pad files.
            if let list = info["files"]?.list {
                isMultiFile = true
                var off: Int64 = 0
                for f in list {
                    guard let len = f["length"]?.int, len >= 0 else { throw MetainfoError("bad file length") }
                    let comps = (f["path.utf-8"]?.list ?? f["path"]?.list ?? []).compactMap { $0.string }
                    guard !comps.isEmpty else { throw MetainfoError("empty file path") }
                    let attr = f["attr"]?.string ?? ""
                    let isPad = attr.contains("p") || (comps.count >= 2 && comps[comps.count - 2] == ".pad")
                    files.append(TorrentFile(path: comps.map(Self.sanitize), length: len, offset: off,
                                             isPadding: isPad, piecesRoot: nil, attributes: attr,
                                             symlinkPath: f["symlink path"]?.list?.compactMap { $0.string }))
                    off += len
                }
            } else {
                guard let len = info["length"]?.int, len >= 0 else { throw MetainfoError("missing length") }
                isMultiFile = false
                files = [TorrentFile(path: [name], length: len, offset: 0, isPadding: false, piecesRoot: nil,
                                     attributes: info["attr"]?.string ?? "", symlinkPath: nil)]
            }
            let pieces = info["pieces"]!.data!
            guard pieces.count % 20 == 0 else { throw MetainfoError("pieces length not a multiple of 20") }
            v1Pieces = stride(from: 0, to: pieces.count, by: 20).map { Data(pieces[pieces.startIndex + $0 ..< pieces.startIndex + $0 + 20]) }
            if hasV2 {
                // Attach v2 roots to the matching v1 entries (same order, padding skipped).
                let v2files = try Self.flattenFileTree(info["file tree"]!)
                var j = 0
                for i in files.indices where !files[i].isPadding {
                    guard j < v2files.count, v2files[j].length == files[i].length else {
                        throw MetainfoError("hybrid torrent: v1 and v2 file lists disagree")
                    }
                    files[i].piecesRoot = v2files[j].root
                    j += 1
                }
            }
        } else {
            // v2 only: every file starts on a piece boundary; insert implicit alignment gaps.
            v1Pieces = []
            let v2files = try Self.flattenFileTree(info["file tree"]!)
            isMultiFile = !(v2files.count == 1 && v2files[0].path == [name])
            var off: Int64 = 0
            let pl = Int64(pieceLength)
            for (idx, f) in v2files.enumerated() {
                files.append(TorrentFile(path: f.path, length: f.length, offset: off, isPadding: false,
                                         piecesRoot: f.root, attributes: f.attr, symlinkPath: nil))
                off += f.length
                if idx != v2files.count - 1, off % pl != 0 {
                    let gap = pl - off % pl
                    files.append(TorrentFile(path: [".pad", String(gap)], length: gap, offset: off,
                                             isPadding: true, piecesRoot: nil, attributes: "p", symlinkPath: nil))
                    off += gap
                }
            }
        }
        self.files = files
        totalLength = files.last.map { $0.endOffset } ?? 0
        pieceCount = totalLength == 0 ? 0 : Int((totalLength + Int64(pieceLength) - 1) / Int64(pieceLength))
        if hasV1 && v1Pieces.count != pieceCount {
            throw MetainfoError("piece count mismatch: \(v1Pieces.count) hashes for \(pieceCount) pieces")
        }
    }

    struct V2File { var path: [String]; var length: Int64; var root: Data?; var attr: String }

    /// Depth-first, key-sorted walk of a BEP 52 "file tree".
    static func flattenFileTree(_ tree: BValue) throws -> [V2File] {
        var out: [V2File] = []
        func walk(_ node: BValue, _ path: [String], depth: Int) throws {
            guard depth < 64, let d = node.dict else { throw MetainfoError("bad file tree") }
            for key in d.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
                let v = d[key]!
                if key.isEmpty {
                    guard let len = v["length"]?.int, len >= 0 else { throw MetainfoError("file tree leaf without length") }
                    let root = v["pieces root"]?.data
                    if len > 0, root?.count != 32 { throw MetainfoError("missing pieces root") }
                    out.append(V2File(path: path, length: len, root: len > 0 ? root : nil, attr: v["attr"]?.string ?? ""))
                } else {
                    try walk(v, path + [sanitize(String(decoding: key, as: UTF8.self))], depth: depth + 1)
                }
            }
        }
        try walk(tree, [], depth: 0)
        return out
    }

    /// Make a path component safe for the local filesystem (no traversal, no slashes).
    static func sanitize(_ s: String) -> String {
        var c = s.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "\0", with: "")
        if c == "." || c == ".." || c.isEmpty { c = "_" }
        if c.utf8.count > 240 { c = String(c.prefix(200)) }
        return c
    }

    /// v2 piece-layer hashes for `file` (nil when not known / file fits in one piece).
    public func pieceLayer(for file: TorrentFile) -> [Data]? {
        guard let root = file.piecesRoot, let layer = pieceLayers[root] else { return nil }
        return stride(from: 0, to: layer.count, by: 32).map { Data(layer[layer.startIndex + $0 ..< layer.startIndex + $0 + 32]) }
    }

    /// Validate the piece layers against each file's pieces root (BEP 52).
    public func validatePieceLayers() -> Bool {
        for f in files where !f.isPadding && f.length > Int64(pieceLength) {
            guard let layer = pieceLayer(for: f), let root = f.piecesRoot else { continue }
            let expected = Int((f.length + Int64(pieceLength) - 1) / Int64(pieceLength))
            guard layer.count == expected,
                  Merkle.rootFromPieceLayer(layer, pieceLength: pieceLength) == root else { return false }
        }
        return true
    }
}

// MARK: - Magnet links (BEP 9 + BEP 52 + BEP 53)

public struct MagnetLink: Sendable {
    public var infoHashes: InfoHashes
    public var displayName: String?
    public var trackers: [String] = []
    public var webSeeds: [String] = []
    public var peers: [PeerAddress] = []
    /// BEP 53 select-only file indices.
    public var selectOnly: [Int] = []

    public init?(_ uri: String) {
        guard uri.lowercased().hasPrefix("magnet:?"),
              let comps = URLComponents(string: uri.replacingOccurrences(of: "+", with: "%20")) else { return nil }
        var v1: Data?, v2: Data?
        for item in comps.queryItems ?? [] {
            let name = item.name.lowercased()
            guard let value = item.value else { continue }
            let key = name.split(separator: ".").first.map(String.init) ?? name
            switch key {
            case "xt":
                let lower = value.lowercased()
                if lower.hasPrefix("urn:btih:") {
                    let h = String(value.dropFirst(9))
                    if h.count == 40, let d = Data(hex: h) { v1 = d }
                    else if h.count == 32, let d = Base32.decode(h), d.count == 20 { v1 = d }
                } else if lower.hasPrefix("urn:btmh:") {
                    // multihash: 0x12 (sha2-256) 0x20 (32 bytes) + digest
                    let h = String(value.dropFirst(9))
                    if let d = Data(hex: h), d.count == 34, d[0] == 0x12, d[1] == 0x20 { v2 = d.subdata(in: 2..<34) }
                }
            case "dn": displayName = value
            case "tr": trackers.append(value)
            case "ws", "as": webSeeds.append(value)
            case "x":
                if name == "x.pe", let p = PeerAddress(value) { peers.append(p) }
            case "so":
                for part in value.split(separator: ",") {
                    let r = part.split(separator: "-")
                    if r.count == 1, let a = Int(r[0]) { selectOnly.append(a) }
                    else if r.count == 2, let a = Int(r[0]), let b = Int(r[1]), a <= b, b - a < 100_000 { selectOnly.append(contentsOf: a...b) }
                }
            default: break
            }
        }
        guard v1 != nil || v2 != nil else { return nil }
        infoHashes = InfoHashes(v1: v1, v2: v2)
    }
}
