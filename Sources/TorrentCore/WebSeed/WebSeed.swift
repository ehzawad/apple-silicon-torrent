import Foundation

/// BEP 19 (GetRight-style) web seed: an HTTP(S) server holding the torrent's files.
///
/// Acts like an always-unchoked seed peer for the piece picker: it claims whole
/// pieces, fetches them with HTTP Range requests (one per file segment), and feeds
/// 16 KiB blocks into the torrent like peer data, so hashing/verification and
/// endgame logic are shared. Loop-confined.
final class WebSeed: @unchecked Sendable {
    let url: String
    weak var torrent: Torrent?
    let loop: EventLoop
    private let session: URLSession
    private var inFlight = 0
    private var failures = 0
    private var disabledUntil = 0.0
    private(set) var downMeter = RateMeter()
    var maxInFlight = 8
    /// Picker identity for this web seed.
    var key: ObjectIdentifier { ObjectIdentifier(self) }
    /// Placeholder IP for hash-failure accounting.
    let fakeIP: IPAddress

    init(url: String, torrent: Torrent) {
        self.url = url
        self.torrent = torrent
        self.loop = torrent.loop
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 30
        cfg.httpMaximumConnectionsPerHost = 8
        cfg.httpAdditionalHeaders = ["User-Agent": ClientIdentity.userAgent]
        session = URLSession(configuration: cfg)
        var h = Hasher(); h.combine(url)
        fakeIP = .v6(0xFEED_0000_0000_0000, UInt64(bitPattern: Int64(h.finalize())))
    }

    deinit { session.invalidateAndCancel() }

    var isActive: Bool { inFlight > 0 }
    var downloadRate: Double { downMeter.bytesPerSecond }

    /// URL for a file given its path components.
    func fileURL(for file: TorrentFile, metainfo: Metainfo) -> URL? {
        var base = url
        if metainfo.isMultiFile {
            if !base.hasSuffix("/") { base += "/" }
            let comps = [metainfo.name] + file.path
            base += comps.map { $0.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? $0 }
                .joined(separator: "/")
        } else if base.hasSuffix("/") {
            base += metainfo.name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? metainfo.name
        }
        return URL(string: base)
    }

    func tick() { downMeter.tick() }

    /// Claim pieces from the picker and fetch them.
    func pump() {
        guard let t = torrent, t.state == .downloading, let picker = t.picker, let mi = t.metainfo else { return }
        guard monotonicNow() >= disabledUntil else { return }
        while inFlight < maxInFlight {
            // Ask for a whole piece worth of blocks (the picker returns blocks of one piece first).
            let want = max(1, mi.pieceLength / Wire.blockSize)
            let blocks = picker.pick(peer: key, peerHave: nil, isSeed: true, count: want)
            guard !blocks.isEmpty else { return }
            for (_, group) in Dictionary(grouping: blocks, by: { $0.piece }) {
                fetch(blocks: group, metainfo: mi)
            }
        }
    }

    private struct Span { let url: URL; let start: Int64; let length: Int; let linear: Int64 }

    private func fetch(blocks: [BlockRequest], metainfo mi: Metainfo) {
        // One piece per fetch: request the covering range [first block, last block end).
        let sorted = blocks.sorted { $0.offset < $1.offset }
        let pl = Int64(mi.pieceLength)
        let first = Int64(sorted[0].piece) * pl + Int64(sorted[0].offset)
        let last = sorted.last!
        let end = Int64(last.piece) * pl + Int64(last.offset + last.length)
        // Map the linear range onto files.
        var spans: [Span] = []
        var off = first
        for f in mi.files where f.endOffset > first && f.offset < end {
            let s = max(off, f.offset), e = min(end, f.endOffset)
            if e <= s { continue }
            if !f.isPadding, let u = fileURL(for: f, metainfo: mi) {
                spans.append(Span(url: u, start: s - f.offset, length: Int(e - s), linear: s))
            }
            off = e
        }
        inFlight += 1
        let state = FetchState(buffer: Data(count: Int(end - first)), remaining: spans.count)  // padding stays zero
        if spans.isEmpty { deliver(sorted, buffer: state.buffer, base: first); inFlight -= 1; return }
        let ws = self
        for sp in spans {
            var req = URLRequest(url: sp.url)
            req.setValue("bytes=\(sp.start)-\(sp.start + Int64(sp.length) - 1)", forHTTPHeaderField: "Range")
            session.dataTask(with: req) { data, resp, error in
                let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
                let ok = error == nil && (code == 206 || code == 200) && data?.count == sp.length
                let payload = ok ? data : nil
                ws.loop.execute { ws.spanFinished(state, span: sp, data: payload, blocks: sorted, base: first) }
            }.resume()
        }
    }

    private final class FetchState: @unchecked Sendable {
        var buffer: Data
        var remaining: Int
        var failed = false
        init(buffer: Data, remaining: Int) { self.buffer = buffer; self.remaining = remaining }
    }

    private func spanFinished(_ st: FetchState, span sp: Span, data: Data?, blocks: [BlockRequest], base: Int64) {
        if let data {
            let at = Int(sp.linear - base)
            st.buffer.replaceSubrange(at..<(at + data.count), with: data)
            downMeter.add(data.count)
        } else {
            st.failed = true
        }
        st.remaining -= 1
        guard st.remaining == 0 else { return }
        inFlight -= 1
        if st.failed {
            for b in blocks { torrent?.picker?.abort(b, peer: key) }
            failures += 1
            disabledUntil = monotonicNow() + min(600, 15 * pow(2, Double(min(failures, 6))))
        } else {
            failures = 0
            deliver(blocks, buffer: st.buffer, base: base)
            pump()
        }
    }

    private func deliver(_ blocks: [BlockRequest], buffer: Data, base: Int64) {
        guard let t = torrent, let mi = t.metainfo else { return }
        let pl = Int64(mi.pieceLength)
        for b in blocks {
            let at = Int(Int64(b.piece) * pl + Int64(b.offset) - base)
            let chunk = buffer.subdata(in: at..<(at + b.length))
            t.dataReceived(key: key, ip: fakeIP, request: b, data: chunk)
        }
    }
}
