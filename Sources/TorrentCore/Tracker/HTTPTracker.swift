import Foundation

// MARK: - HTTP(S) tracker codec (BEP 3, 7, 23, 24, 48)

/// Pure functions for building HTTP tracker URLs and parsing responses.
enum HTTPTrackerCodec {
    /// Responses larger than this are rejected (a real tracker reply is a few KiB).
    static let maxBodySize = 8 * 1024 * 1024

    /// RFC 3986 percent-encoding of raw bytes: every byte outside the unreserved
    /// set `A-Z a-z 0-9 - . _ ~` becomes `%XX` (upper-case hex).
    static func percentEncode(_ bytes: some Sequence<UInt8>) -> String {
        let hex: [UInt8] = Array("0123456789ABCDEF".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(60)
        for b in bytes {
            switch b {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."),
                 UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.append(b)
            default:
                out.append(UInt8(ascii: "%"))
                out.append(hex[Int(b >> 4)])
                out.append(hex[Int(b & 0x0F)])
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func percentEncode(_ s: String) -> String { percentEncode(s.utf8) }

    /// Splits off any `#fragment` and returns (base, separator to append a query param).
    private static func querySplice(_ announce: String) -> (String, String) {
        var base = announce.trimmingCharacters(in: .whitespacesAndNewlines)
        if let hash = base.firstIndex(of: "#") { base = String(base[..<hash]) }
        let sep: String
        if !base.contains("?") { sep = "?" }
        else if base.hasSuffix("?") || base.hasSuffix("&") { sep = "" }
        else { sep = "&" }
        return (base, sep)
    }

    /// Full announce URL string. Any query already present in `announce`
    /// (passkeys etc.) is preserved; our parameters are appended.
    static func announceURLString(_ announce: String, _ req: AnnounceRequest) -> String {
        let (base, sep) = querySplice(announce)
        var q: [String] = [
            "info_hash=" + percentEncode(req.infoHash),
            "peer_id=" + percentEncode(req.peerID),
            "port=\(req.port)",
            "uploaded=\(max(0, req.uploaded))",
            "downloaded=\(max(0, req.downloaded))",
            "left=\(req.effectiveLeft)",
        ]
        if req.event != .none { q.append("event=" + req.event.rawValue) }
        q.append("key=" + String(format: "%08X", req.key))
        if req.numWant > 0 || req.event == .stopped { q.append("numwant=\(max(0, req.numWant))") }
        q.append("compact=1")
        q.append("no_peer_id=1")
        q.append("supportcrypto=1")
        if let tid = req.trackerID, !tid.isEmpty { q.append("trackerid=" + percentEncode(tid)) }
        return base + sep + q.joined(separator: "&")
    }

    static func announceURL(_ announce: String, _ req: AnnounceRequest) -> URL? {
        URL(string: announceURLString(announce, req))
    }

    /// BEP 48 scrape URL: the last path component must start with "announce",
    /// which is replaced by "scrape". Returns nil when the tracker does not follow
    /// the convention. The query string (passkey) is preserved.
    static func scrapeURLString(fromAnnounce announce: String) -> String? {
        var s = announce.trimmingCharacters(in: .whitespacesAndNewlines)
        if let hash = s.firstIndex(of: "#") { s = String(s[..<hash]) }
        guard let schemeEnd = s.range(of: "://") else { return nil }
        let queryStart = s.firstIndex(of: "?") ?? s.endIndex
        let beforeQuery = s[..<queryStart]
        guard let slash = beforeQuery.lastIndex(of: "/"), slash >= schemeEnd.upperBound else { return nil }
        let component = s[s.index(after: slash)..<queryStart]
        guard component.hasPrefix("announce") else { return nil }
        let replaceEnd = s.index(slash, offsetBy: 1 + "announce".count)
        var out = s
        out.replaceSubrange(s.index(after: slash)..<replaceEnd, with: "scrape")
        return out
    }

    static func scrapeURLString(_ scrape: String, infoHashes: [Data]) -> String {
        let (base, sep) = querySplice(scrape)
        return base + sep + infoHashes.map { "info_hash=" + percentEncode($0) }.joined(separator: "&")
    }

    // MARK: Response parsing

    /// Decode the bencoded body leniently: trailing garbage (newlines, HTML
    /// footers some trackers append) is ignored.
    static func decodeBody(_ raw: Data) throws -> BValue {
        let body = gunzipIfNeeded(raw)
        guard !body.isEmpty else { throw TrackerError.malformed("empty response") }
        guard body.count <= maxBodySize else { throw TrackerError.malformed("response too large") }
        do {
            return try BDecoder.decodePrefix(body).0
        } catch {
            throw TrackerError.malformed("not bencoded")
        }
    }

    static func parseAnnounceResponse(_ raw: Data) throws -> AnnounceResponse {
        let root = try decodeBody(raw)
        guard root.dict != nil else { throw TrackerError.malformed("response is not a dictionary") }
        if let reason = root["failure reason"] {
            let msg = reason.string ?? reason.int.map { String($0) } ?? "unknown failure"
            throw TrackerError.failure(msg)
        }
        var resp = AnnounceResponse(interval: 1800)
        if let i = root["interval"]?.int { resp.interval = Int(clamping: i) }
        if let mi = root["min interval"]?.int { resp.minInterval = Int(clamping: mi) }
        if let c = root["complete"]?.int, c >= 0 { resp.seeders = Int(clamping: c) }
        if let ic = root["incomplete"]?.int, ic >= 0 { resp.leechers = Int(clamping: ic) }
        resp.warning = root["warning message"]?.string
        if let tid = root["tracker id"]?.string, !tid.isEmpty { resp.trackerID = tid }
        if let ext = root["external ip"]?.data, ext.count == 4 || ext.count == 16 {
            resp.externalIP = IPAddress(bytes: ext)
        }
        var peers: [PeerAddress] = []
        if let p = root["peers"] { peers += parsePeers(p, v6Compact: false) }
        if let p6 = root["peers6"] { peers += parsePeers(p6, v6Compact: true) }
        resp.peers = dedupe(peers)
        return resp
    }

    /// `peers` / `peers6`: compact string (BEP 23 / BEP 7) or list of dicts (BEP 3).
    static func parsePeers(_ v: BValue, v6Compact: Bool) -> [PeerAddress] {
        switch v {
        case .bytes(let d):
            if v6Compact { return PeerAddress.parseCompactList(d, v6: true) }
            // Some trackers put 18-byte entries into "peers"; only when it can't be v4.
            if d.count % 6 != 0 && d.count % 18 == 0 { return PeerAddress.parseCompactList(d, v6: true) }
            return PeerAddress.parseCompactList(d, v6: false)
        case .list(let items):
            var out: [PeerAddress] = []
            out.reserveCapacity(items.count)
            for item in items {
                guard let ipStr = item["ip"]?.string, let port = item["port"]?.int,
                      port > 0, port <= 65535,
                      let ip = IPAddress(ipStr.trimmingCharacters(in: .whitespaces)), !ip.isUnusable
                else { continue }
                out.append(PeerAddress(ip: ip, port: UInt16(port)))
            }
            return out
        default:
            return []
        }
    }

    static func parseScrapeResponse(_ raw: Data) throws -> [Data: (seeders: Int, completed: Int, leechers: Int)] {
        let root = try decodeBody(raw)
        if let reason = root["failure reason"] {
            throw TrackerError.failure(reason.string ?? "unknown failure")
        }
        guard let files = root["files"]?.dict else { throw TrackerError.malformed("missing files") }
        var out: [Data: (seeders: Int, completed: Int, leechers: Int)] = [:]
        for (k, v) in files {
            guard v.dict != nil else { continue }
            var key = k
            if k.count == 40, let h = Data(hex: String(decoding: k, as: UTF8.self)) { key = h }
            guard key.count == 20 else { continue }
            out[key] = (seeders: max(0, Int(clamping: v["complete"]?.int ?? 0)),
                        completed: max(0, Int(clamping: v["downloaded"]?.int ?? 0)),
                        leechers: max(0, Int(clamping: v["incomplete"]?.int ?? 0)))
        }
        return out
    }

    static func dedupe(_ peers: [PeerAddress]) -> [PeerAddress] {
        var seen = Set<PeerAddress>()
        seen.reserveCapacity(peers.count)
        return peers.filter { seen.insert($0).inserted }
    }

    // MARK: gzip

    /// URLSession transparently decodes `Content-Encoding: gzip`. Some trackers
    /// gzip the body without the header; detect the magic and inflate it here.
    static func gunzipIfNeeded(_ d: Data) -> Data {
        guard d.count > 18, d.byte(0) == 0x1F, d.byte(1) == 0x8B, d.byte(2) == 8 else { return d }
        let flags = d.byte(3)
        var p = 10
        if flags & 0x04 != 0 {                      // FEXTRA
            guard p + 2 <= d.count else { return d }
            p += 2 + (Int(d.byte(p)) | Int(d.byte(p + 1)) << 8)
        }
        if flags & 0x08 != 0 {                      // FNAME
            while p < d.count, d.byte(p) != 0 { p += 1 }
            p += 1
        }
        if flags & 0x10 != 0 {                      // FCOMMENT
            while p < d.count, d.byte(p) != 0 { p += 1 }
            p += 1
        }
        if flags & 0x02 != 0 { p += 2 }             // FHCRC
        guard p < d.count - 8 else { return d }
        let deflate = d.subdata(in: (d.startIndex + p)..<(d.endIndex - 8))
        // NSData's .zlib algorithm is raw DEFLATE (RFC 1951), exactly gzip's payload.
        guard let out = try? (deflate as NSData).decompressed(using: .zlib) as Data else { return d }
        return out
    }
}

// MARK: - HTTP transport

/// Thin URLSession wrapper. Completions always run on the loop.
final class HTTPTrackerTransport: @unchecked Sendable {
    private let loop: EventLoop
    private let session: URLSession
    /// Overall request timeout in seconds.
    var timeout: Double = 15

    init(loop: EventLoop) {
        self.loop = loop
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 15
        cfg.timeoutIntervalForResource = 20
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.urlCache = nil
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        cfg.waitsForConnectivity = false
        cfg.httpMaximumConnectionsPerHost = 8
        // URLSession already advertises and transparently decodes gzip; be explicit.
        cfg.httpAdditionalHeaders = [
            "User-Agent": ClientIdentity.userAgent,
            "Accept-Encoding": "gzip",
            "Accept": "*/*",
        ]
        session = URLSession(configuration: cfg)
    }

    deinit { session.finishTasksAndInvalidate() }

    /// GET `url`; yields (status code, body) or a transport error.
    func get(_ url: URL, completion: @escaping (Result<(Int, Data), TrackerError>) -> Void) {
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.timeoutInterval = timeout
        let box = TrackerUnchecked(completion)
        let loop = self.loop
        let task = session.dataTask(with: req) { data, response, error in
            let result: Result<(Int, Data), TrackerError>
            if let error {
                let ns = error as NSError
                if ns.domain == NSURLErrorDomain && ns.code == NSURLErrorTimedOut {
                    result = .failure(.timedOut)
                } else if ns.domain == NSURLErrorDomain && ns.code == NSURLErrorCannotFindHost {
                    result = .failure(.dnsFailed(url.host ?? "?"))
                } else {
                    result = .failure(.network(ns.localizedDescription))
                }
            } else {
                let code = (response as? HTTPURLResponse)?.statusCode ?? 200
                result = .success((code, data ?? Data()))
            }
            loop.execute { box.value(result) }
        }
        task.resume()
    }

    func invalidate() { session.invalidateAndCancel() }
}
