import Foundation
import Darwin

/// Creates .torrent files: v1, v2 (BEP 52) or hybrid (default, BEP 52 + BEP 47 padding).
/// Hashing runs in parallel across all cores (CryptoKit SHA-1/SHA-256 on the ARMv8 SHA units).
public enum TorrentCreator {
    public struct Options: Sendable {
        public var version: TorrentVersion = .hybrid
        public var pieceLength: Int? = nil          // nil = automatic
        public var trackers: [[String]] = []
        public var webSeeds: [String] = []
        public var comment: String?
        public var isPrivate = false
        public var name: String?
        public init() {}
    }

    public struct CreatorError: Error, CustomStringConvertible {
        public let message: String
        public var description: String { message }
    }

    struct InputFile { let url: URL; let path: [String]; let length: Int64 }

    /// Automatic piece size: aim for ~1000–2000 pieces, 16 KiB … 16 MiB, power of two.
    public static func autoPieceLength(totalSize: Int64) -> Int {
        var pl = 16 * 1024
        while pl < 16 * 1024 * 1024 && totalSize / Int64(pl) > 2000 { pl *= 2 }
        return pl
    }

    public static func create(from root: URL, options: Options = Options(),
                              progress: (@Sendable (Double) -> Void)? = nil) throws -> Data {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: root.path, isDirectory: &isDir) else { throw CreatorError(message: "no such file: \(root.path)") }
        let name = options.name ?? root.lastPathComponent
        var inputs: [InputFile] = []
        if isDir.boolValue {
            guard let e = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey]) else {
                throw CreatorError(message: "cannot enumerate \(root.path)")
            }
            for case let u as URL in e {
                let v = try u.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey])
                guard v.isRegularFile == true, v.isSymbolicLink != true else { continue }
                let rel = u.standardizedFileURL.path.dropFirst(root.standardizedFileURL.path.count + 1)
                let comps = rel.split(separator: "/").map(String.init)
                if comps.contains(where: { $0.hasPrefix(".") }) { continue }   // skip hidden files (.DS_Store …)
                inputs.append(InputFile(url: u, path: comps, length: Int64(v.fileSize ?? 0)))
            }
            // BEP 52 file trees are sorted by raw UTF-8 path bytes; v1 order must match for hybrids.
            inputs.sort { a, b in
                for (x, y) in zip(a.path, b.path) where x != y { return Array(x.utf8).lexicographicallyPrecedes(Array(y.utf8)) }
                return a.path.count < b.path.count
            }
            guard !inputs.isEmpty else { throw CreatorError(message: "directory is empty") }
        } else {
            let size = (try fm.attributesOfItem(atPath: root.path)[.size] as? NSNumber)?.int64Value ?? 0
            inputs = [InputFile(url: root, path: [name], length: size)]
        }
        let total = inputs.reduce(0) { $0 + $1.length }
        let pl = options.pieceLength ?? autoPieceLength(totalSize: total)
        guard pl >= 16384, pl & (pl - 1) == 0 else { throw CreatorError(message: "piece length must be a power of two >= 16 KiB") }
        let v1 = options.version != .v2
        let v2 = options.version != .v1
        let aligned = v2   // v2/hybrid: every file starts on a piece boundary

        // Linear layout (with alignment padding for v2/hybrid).
        struct Placed { let file: Int; let offset: Int64 }
        var placed: [Placed] = []
        var off: Int64 = 0
        for (i, f) in inputs.enumerated() {
            placed.append(Placed(file: i, offset: off))
            off += f.length
            if aligned && i != inputs.count - 1 && off % Int64(pl) != 0 { off += Int64(pl) - off % Int64(pl) }
        }
        let linearTotal = off
        let pieceCount = Int((linearTotal + Int64(pl) - 1) / Int64(pl))

        // Open all files once (pread is thread-safe).
        var fds: [Int32] = []
        defer { for fd in fds { close(fd) } }
        for f in inputs {
            let fd = open(f.url.path, O_RDONLY | O_CLOEXEC)
            guard fd >= 0 else { throw CreatorError(message: "cannot open \(f.url.path)") }
            fds.append(fd)
        }

        // Hash every piece in parallel.
        let v1Hashes = UnsafeMutableBufferPointer<Data>.allocate(capacity: pieceCount)
        v1Hashes.initialize(repeating: Data())
        let v2PieceHashes = UnsafeMutableBufferPointer<Data>.allocate(capacity: pieceCount)
        v2PieceHashes.initialize(repeating: Data())
        defer { v1Hashes.deallocate(); v2PieceHashes.deallocate() }
        let done = ManagedCounter()
        let placedCopy = placed, inputsCopy = inputs, fdsCopy = fds
        let failed = ManagedCounter()
        DispatchQueue.concurrentPerform(iterations: pieceCount) { p in
            let start = Int64(p) * Int64(pl)
            let size = Int(min(Int64(pl), linearTotal - start))
            var buf = [UInt8](repeating: 0, count: size)
            // Fill from overlapping files (padding stays zero).
            var v2Len = 0
            for pf in placedCopy {
                let f = inputsCopy[pf.file]
                let fs = pf.offset, fe = pf.offset + f.length
                if fe <= start || fs >= start + Int64(size) { continue }
                let s = max(start, fs), e = min(start + Int64(size), fe)
                let n = Int(e - s)
                let got = buf.withUnsafeMutableBytes { raw in
                    pread(fdsCopy[pf.file], raw.baseAddress! + Int(s - start), n, off_t(s - fs))
                }
                if got != n { _ = failed.increment() }
                if aligned { v2Len = Int(e - start) }   // v2 pieces belong to exactly one file
            }
            if v1 { v1Hashes[p] = buf.withUnsafeBytes { Hash.sha1($0) } }
            if v2 && v2Len > 0 {
                v2PieceHashes[p] = buf.withUnsafeBytes { raw in
                    Merkle.pieceHash(UnsafeRawBufferPointer(rebasing: raw[0..<v2Len]), pieceLength: pl)
                }
            }
            let d = done.increment()
            if d % 64 == 0 { progress?(Double(d) / Double(pieceCount)) }
        }
        if failed.increment() > 1 { throw CreatorError(message: "short read while hashing (files changed?)") }

        // Assemble the info dictionary.
        var info: [Data: BValue] = [:]
        func put(_ k: String, _ v: BValue) { info[Data(k.utf8)] = v }
        put("name", .string(name))
        put("piece length", .int(Int64(pl)))
        if options.isPrivate { put("private", .int(1)) }
        var layers: [Data: BValue] = [:]
        if v2 {
            put("meta version", .int(2))
            // file tree + piece layers
            var tree: [Data: BValue] = [:]
            for (i, f) in inputs.enumerated() {
                var leaf: [Data: BValue] = [Data("length".utf8): .int(f.length)]
                if f.length > 0 {
                    let first = Int(placed[i].offset / Int64(pl))
                    let n = Int((f.length + Int64(pl) - 1) / Int64(pl))
                    let root: Data
                    if f.length <= Int64(pl) {
                        // Small file: root over its own blocks (padded to next power of two).
                        var b = [UInt8](repeating: 0, count: Int(f.length))
                        _ = b.withUnsafeMutableBytes { pread(fds[i], $0.baseAddress!, Int(f.length), 0) }
                        root = b.withUnsafeBytes { Merkle.smallFileRoot($0) }
                    } else {
                        let layer = (first..<(first + n)).map { v2PieceHashes[$0] }
                        root = Merkle.rootFromPieceLayer(layer, pieceLength: pl)
                        layers[root] = .bytes(layer.reduce(into: Data()) { $0.append($1) })
                    }
                    leaf[Data("pieces root".utf8)] = .bytes(root)
                }
                let comps = isDir.boolValue ? f.path : [name]
                insert(&tree, comps, .dict([Data(): .dict(leaf)]))
            }
            put("file tree", .dict(tree))
        }
        if v1 {
            put("pieces", .bytes((0..<pieceCount).reduce(into: Data()) { $0.append(v1Hashes[$1]) }))
            if isDir.boolValue {
                var list: [BValue] = []
                for (i, f) in inputs.enumerated() {
                    list.append(.dict(["length": .int(f.length), "path": .list(f.path.map { .string($0) })]))
                    if aligned && i != inputs.count - 1 {
                        let end = placed[i].offset + f.length
                        let padLen = end % Int64(pl) == 0 ? 0 : Int64(pl) - end % Int64(pl)
                        if padLen > 0 {
                            list.append(.dict(["length": .int(padLen), "attr": .string("p"),
                                               "path": .list([.string(".pad"), .string(String(padLen))])]))
                        }
                    }
                }
                put("files", .list(list))
            } else {
                put("length", .int(inputs[0].length))
            }
        }

        var top: [Data: BValue] = [:]
        func putTop(_ k: String, _ v: BValue) { top[Data(k.utf8)] = v }
        putTop("info", .dict(info))
        if let first = options.trackers.first?.first { putTop("announce", .string(first)) }
        if options.trackers.count > 1 || (options.trackers.first?.count ?? 0) > 1 {
            putTop("announce-list", .list(options.trackers.map { .list($0.map { .string($0) }) }))
        }
        if !options.webSeeds.isEmpty { putTop("url-list", .list(options.webSeeds.map { .string($0) })) }
        if let c = options.comment { putTop("comment", .string(c)) }
        putTop("created by", .string(ClientIdentity.userAgent))
        putTop("creation date", .int(Int64(Date().timeIntervalSince1970)))
        if v2 && !layers.isEmpty { putTop("piece layers", .dict(layers)) }
        progress?(1)
        return BValue.dict(top).encoded
    }

    private static func insert(_ tree: inout [Data: BValue], _ path: [String], _ leaf: BValue) {
        guard let head = path.first else { return }
        let key = Data(head.utf8)
        if path.count == 1 { tree[key] = leaf; return }
        var sub = tree[key]?.dict ?? [:]
        insert(&sub, Array(path.dropFirst()), leaf)
        tree[key] = .dict(sub)
    }
}
