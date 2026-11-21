import Foundation
import Darwin
import Dispatch

public struct StorageError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public init(_ m: String) { message = m }
    public var description: String { message }
}

/// Maps the torrent's linear piece space onto files on disk.
///
/// * Files are created sparse (`ftruncate`) — APFS allocates on write.
/// * Opened with `O_NOFOLLOW | O_CLOEXEC` so a malicious torrent can't redirect writes
///   through symlinks; every path is validated to stay inside the download root.
/// * All file I/O runs on one serial `diskQueue` (ordering guarantees that a piece's
///   blocks are on disk before the piece is read back for hashing). Hashing itself runs
///   on a concurrent queue so verification uses every core.
/// * Padding files (BEP 47 / v2 alignment) are never written; reads return zeros.
public final class Storage: @unchecked Sendable {
    public let metainfo: Metainfo
    public let root: URL                 // directory that contains the torrent's top-level item
    let diskQueue = DispatchQueue(label: "astor.disk", qos: .utility)
    static let hashQueue = DispatchQueue(label: "astor.hash", qos: .utility, attributes: .concurrent)

    private struct Seg { let file: Int; let fileOffset: Int64; let length: Int }
    private var fdCache: [Int: Int32] = [:]          // file index -> fd   (diskQueue only)
    private var fdLRU: [Int] = []
    private let maxOpenFiles = 64
    private let fileStarts: [Int64]
    private let paths: [String]                      // absolute paths (empty for padding)
    private var wanted: [Bool]                       // file selection (diskQueue only)
    /// v2 piece layers learned after creation (BEP 52 hash requests), keyed by pieces root.
    private let layersLock = NSLock()
    private var learnedLayers: [Data: [Data]] = [:]

    func addPieceLayer(root: Data, hashes: [Data]) {
        layersLock.lock(); learnedLayers[root] = hashes; layersLock.unlock()
    }

    private func layer(for f: TorrentFile) -> [Data]? {
        if let l = metainfo.pieceLayer(for: f) { return l }
        guard let r = f.piecesRoot else { return nil }
        layersLock.lock(); defer { layersLock.unlock() }
        return learnedLayers[r]
    }

    public init(metainfo: Metainfo, downloadDirectory: URL) throws {
        self.metainfo = metainfo
        self.root = downloadDirectory.standardizedFileURL
        fileStarts = metainfo.files.map { $0.offset }
        var ps: [String] = []
        let base = metainfo.isMultiFile ? root.appendingPathComponent(metainfo.name, isDirectory: true) : root
        let rootPath = root.path
        for f in metainfo.files {
            if f.isPadding { ps.append(""); continue }
            var u = base
            for c in f.path { u.appendPathComponent(c) }
            let p = u.standardizedFileURL.path
            guard p.hasPrefix(rootPath + "/") else { throw StorageError("unsafe path in torrent: \(f.path)") }
            ps.append(p)
        }
        paths = ps
        wanted = metainfo.files.map { !$0.isPadding }
    }

    deinit {
        for (_, fd) in fdCache { Darwin.close(fd) }
    }

    public func filePath(_ index: Int) -> String { paths[index] }

    /// Restrict which files get created/written (BEP 53 / user selection).
    public func setWanted(_ w: [Bool]) {
        diskQueue.async { self.wanted = w }
    }

    // MARK: Segment mapping

    /// Locate the file containing linear offset `off` (binary search).
    private func fileIndex(at off: Int64) -> Int {
        var lo = 0, hi = fileStarts.count - 1
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            if fileStarts[mid] <= off { lo = mid } else { hi = mid - 1 }
        }
        // skip zero-length files that share the offset
        var i = lo
        while i < metainfo.files.count - 1 && metainfo.files[i].length == 0 { i += 1 }
        return i
    }

    private func segments(offset: Int64, length: Int) -> [Seg] {
        var out: [Seg] = []
        var off = offset
        var left = length
        var i = fileIndex(at: off)
        while left > 0 && i < metainfo.files.count {
            let f = metainfo.files[i]
            if off >= f.endOffset { i += 1; continue }
            let inFile = off - f.offset
            let n = Int(min(Int64(left), f.length - inFile))
            if n > 0 { out.append(Seg(file: i, fileOffset: inFile, length: n)) }
            off += Int64(n)
            left -= n
            i += 1
        }
        return out
    }

    // MARK: File handles (diskQueue)

    private func fd(for file: Int, create: Bool) throws -> Int32? {
        if let fd = fdCache[file] {
            if let idx = fdLRU.firstIndex(of: file) { fdLRU.remove(at: idx) }
            fdLRU.append(file)
            return fd
        }
        let path = paths[file]
        guard !path.isEmpty else { return nil }
        if create {
            let dir = (path as NSString).deletingLastPathComponent
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        let flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | (create ? O_CREAT : 0)
        let fd = Darwin.open(path, flags, 0o644)
        if fd < 0 {
            if !create && errno == ENOENT { return nil }
            throw StorageError("open \(path): \(String(cString: strerror(errno)))")
        }
        if create {
            var st = stat()
            if fstat(fd, &st) == 0, st.st_size < metainfo.files[file].length {
                _ = ftruncate(fd, off_t(metainfo.files[file].length))   // sparse on APFS
            }
        }
        if fdCache.count >= maxOpenFiles, let victim = fdLRU.first {
            fdLRU.removeFirst()
            if let vfd = fdCache.removeValue(forKey: victim) { Darwin.close(vfd) }
        }
        fdCache[file] = fd
        fdLRU.append(file)
        return fd
    }

    // MARK: Write / read (call on diskQueue)

    /// Write `data` at linear offset. Padding regions are skipped.
    func writeSync(offset: Int64, data: Data) throws {
        var pos = 0
        for s in segments(offset: offset, length: data.count) {
            defer { pos += s.length }
            if metainfo.files[s.file].isPadding || !wanted[s.file] { continue }
            guard let fd = try fd(for: s.file, create: true) else { continue }
            try data.withUnsafeBytes { raw in
                var done = 0
                while done < s.length {
                    let n = pwrite(fd, raw.baseAddress! + pos + done, s.length - done, off_t(s.fileOffset) + off_t(done))
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw StorageError("write \(paths[s.file]): \(String(cString: strerror(errno)))")
                    }
                    done += n
                }
            }
        }
    }

    /// Read `length` bytes at linear offset; padding and missing files read as zeros.
    func readSync(offset: Int64, length: Int) throws -> Data {
        var out = Data(count: length)
        var pos = 0
        for s in segments(offset: offset, length: length) {
            defer { pos += s.length }
            if metainfo.files[s.file].isPadding { continue }
            guard let fd = try fd(for: s.file, create: false) else { continue }
            try out.withUnsafeMutableBytes { raw in
                var done = 0
                while done < s.length {
                    let n = pread(fd, raw.baseAddress! + pos + done, s.length - done, off_t(s.fileOffset) + off_t(done))
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw StorageError("read \(paths[s.file]): \(String(cString: strerror(errno)))")
                    }
                    if n == 0 { break } // beyond EOF: zeros
                    done += n
                }
            }
        }
        return out
    }

    // MARK: Async API (completions run on the given loop)

    /// Queue a block write. `onError` runs on the loop only if the write fails.
    func write(piece: Int, offset: Int, data: Data, loop: EventLoop,
               onError: @escaping @Sendable (StorageError) -> Void) {
        let lin = Int64(piece) * Int64(metainfo.pieceLength) + Int64(offset)
        diskQueue.async {
            do { try self.writeSync(offset: lin, data: data) }
            catch let e as StorageError { loop.execute { onError(e) } }
            catch { let e = StorageError("\(error)"); loop.execute { onError(e) } }
        }
    }

    func readBlock(_ r: BlockRequest, loop: EventLoop, completion: @escaping @Sendable (Data?) -> Void) {
        let lin = Int64(r.piece) * Int64(metainfo.pieceLength) + Int64(r.offset)
        diskQueue.async {
            let d = try? self.readSync(offset: lin, length: r.length)
            loop.execute { completion(d) }
        }
    }

    /// Verify a piece after all its writes were queued. Result delivered on the loop.
    /// With `blockHashes`, also returns SHA-1 of every 16 KiB block (smart-ban evidence).
    func verify(piece: Int, loop: EventLoop, blockHashes: Bool = false,
                completion: @escaping @Sendable (Bool, [Data]) -> Void) {
        diskQueue.async {
            let size = self.metainfo.pieceSize(piece)
            let lin = Int64(piece) * Int64(self.metainfo.pieceLength)
            guard let data = try? self.readSync(offset: lin, length: size) else {
                loop.execute { completion(false, []) }
                return
            }
            Storage.hashQueue.async {
                let ok = self.check(piece: piece, data: data)
                let hashes: [Data] = (blockHashes || !ok)
                    ? stride(from: 0, to: data.count, by: Wire.blockSize).map {
                        Hash.sha1(data[$0..<min(data.count, $0 + Wire.blockSize)])
                    }
                    : []
                loop.execute { completion(ok, hashes) }
            }
        }
    }

    /// Hash check of one piece's bytes (v1 SHA-1 and/or v2 Merkle).
    func check(piece: Int, data: Data) -> Bool {
        let mi = metainfo
        var verifiedSomething = false
        if !mi.v1Pieces.isEmpty {
            guard Hash.sha1(data) == mi.v1Pieces[piece] else { return false }
            verifiedSomething = true
        }
        if mi.infoHashes.v2 != nil {
            let start = Int64(piece) * Int64(mi.pieceLength)
            // v2 pieces never span files: find the (non-padding) file holding this piece.
            guard let f = mi.files.first(where: { !$0.isPadding && $0.length > 0 && $0.offset <= start && start < $0.endOffset }) else {
                return verifiedSomething // piece is entirely padding
            }
            let len = Int(min(Int64(mi.pieceLength), f.endOffset - start))
            let ok: Bool? = data.withUnsafeBytes { raw -> Bool? in
                let slice = UnsafeRawBufferPointer(rebasing: raw[0..<len])
                if f.length <= Int64(mi.pieceLength) {
                    guard let root = f.piecesRoot else { return nil }
                    return Merkle.smallFileRoot(slice) == root
                }
                guard let layer = self.layer(for: f) else { return nil }
                let idx = Int((start - f.offset) / Int64(mi.pieceLength))
                guard idx < layer.count else { return false }
                return Merkle.pieceHash(slice, pieceLength: mi.pieceLength) == layer[idx]
            }
            if let ok {
                if !ok { return false }
                verifiedSomething = true
            }
        }
        return verifiedSomething
    }

    // MARK: Full recheck

    /// Hash every piece using all cores. `progress` is called (off-loop) with pieces done.
    func recheck(progress: (@Sendable (Int) -> Void)? = nil) -> Bitfield {
        let n = metainfo.pieceCount
        let result = UnsafeMutableBufferPointer<Bool>.allocate(capacity: n)
        result.initialize(repeating: false)
        defer { result.deallocate() }
        // Read sequentially in large chunks on the disk queue, hash concurrently.
        let chunk = max(1, (8 * 1024 * 1024) / max(1, metainfo.pieceLength))
        let group = DispatchGroup()
        let sema = DispatchSemaphore(value: ProcessInfo.processInfo.activeProcessorCount * 2)
        let counter = ManagedCounter()
        var i = 0
        while i < n {
            let lo = i, hi = min(n, i + chunk)
            i = hi
            var datas: [(Int, Data)] = []
            diskQueue.sync {
                for p in lo..<hi {
                    if let d = try? self.readSync(offset: Int64(p) * Int64(metainfo.pieceLength), length: metainfo.pieceSize(p)) {
                        datas.append((p, d))
                    }
                }
            }
            for (p, d) in datas {
                sema.wait()
                group.enter()
                let resultPtr = result
                Storage.hashQueue.async {
                    resultPtr[p] = self.check(piece: p, data: d)
                    sema.signal()
                    let done = counter.increment()
                    progress?(done)
                    group.leave()
                }
            }
        }
        group.wait()
        var bf = Bitfield(count: n)
        for p in 0..<n where result[p] { bf[p] = true }
        return bf
    }

    /// True if at least one non-padding file exists on disk.
    func anyFileExists() -> Bool {
        paths.contains { !$0.isEmpty && FileManager.default.fileExists(atPath: $0) }
    }

    /// (size, mtime) of each file for fast-resume validation.
    func fileStamps() -> [(Int64, Int64)] {
        paths.map { p in
            guard !p.isEmpty else { return (0, 0) }
            var st = stat()
            guard stat(p, &st) == 0 else { return (-1, 0) }
            return (Int64(st.st_size), Int64(st.st_mtimespec.tv_sec))
        }
    }

    /// Flush file data (resume checkpoints / completion).
    func sync(completion: @escaping @Sendable () -> Void) {
        diskQueue.async {
            for (_, fd) in self.fdCache { _ = fsync(fd) }
            completion()
        }
    }

    func closeAll() {
        diskQueue.async {
            for (_, fd) in self.fdCache { _ = fsync(fd); Darwin.close(fd) }
            self.fdCache.removeAll()
            self.fdLRU.removeAll()
        }
    }
}

final class ManagedCounter: @unchecked Sendable {
    private var v = 0
    private let lock = NSLock()
    func increment() -> Int { lock.lock(); v += 1; let r = v; lock.unlock(); return r }
}
