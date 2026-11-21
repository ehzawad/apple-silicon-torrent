import Foundation

/// Stateless tracker transport shared by every torrent of a session.
/// HTTP(S) goes through URLSession; UDP (BEP 15) through one shared ephemeral
/// socket per address family. All completions run on the loop, never
/// synchronously from inside `announce` / `scrape`.
public final class TrackerClient: @unchecked Sendable {
    private let loop: EventLoop
    private let resolver: HostResolver
    private let http: HTTPTrackerTransport
    private var udpTransport: UDPTrackerTransport?
    private var closed = false
    /// Max resolved addresses tried per UDP tracker host (v4 first).
    var maxAddressesPerHost = 4

    public init(loop: EventLoop, resolver: HostResolver) {
        self.loop = loop
        self.resolver = resolver
        self.http = HTTPTrackerTransport(loop: loop)
    }

    var udp: UDPTrackerTransport {
        if let u = udpTransport { return u }
        let u = UDPTrackerTransport(loop: loop)
        udpTransport = u
        return u
    }

    /// Test / tuning hooks.
    var udpRetransmitTimeouts: [Double] {
        get { udp.retransmitTimeouts }
        set { udp.retransmitTimeouts = newValue }
    }
    var httpTimeout: Double {
        get { http.timeout }
        set { http.timeout = newValue }
    }

    /// Additive to the contract: close the UDP sockets and cancel HTTP requests
    /// (session shutdown). Pending completions fire with an error.
    public func close() {
        loop.assertInLoop()
        guard !closed else { return }
        closed = true
        udpTransport?.close()
        udpTransport = nil
        http.invalidate()
    }

    /// Whether `url` uses a scheme this client can announce to.
    public static func isSupported(_ url: String) -> Bool {
        guard let p = TrackerURLParts.parse(url) else { return false }
        return p.scheme == "http" || p.scheme == "https" || p.scheme == "udp"
    }

    // MARK: Announce

    public func announce(url: String, _ req: AnnounceRequest,
                         completion: @escaping (Result<AnnounceResponse, any Error>) -> Void) {
        loop.assertInLoop()
        // A task created on an invalidated URLSession raises; refuse after close().
        guard !closed else { fail(completion, .network("tracker client closed")); return }
        guard req.infoHash.count == 20 else {
            fail(completion, .invalidRequest("info hash must be 20 bytes")); return
        }
        guard req.peerID.count == 20 else {
            fail(completion, .invalidRequest("peer id must be 20 bytes")); return
        }
        guard let parts = TrackerURLParts.parse(url) else { fail(completion, .invalidURL(url)); return }
        switch parts.scheme {
        case "http", "https":
            guard let u = HTTPTrackerCodec.announceURL(url, req) else { fail(completion, .invalidURL(url)); return }
            http.get(u) { r in
                switch r {
                case .failure(let e): completion(.failure(e))
                case .success(let (code, body)):
                    do {
                        // Trackers often send `failure reason` with a 4xx/5xx status;
                        // prefer that message over the bare status code.
                        let resp = try HTTPTrackerCodec.parseAnnounceResponse(body)
                        if (200..<300).contains(code) { completion(.success(resp)) }
                        else { completion(.failure(TrackerError.httpStatus(code))) }
                    } catch let e as TrackerError {
                        if case .failure = e { completion(.failure(e)) }
                        else if !(200..<300).contains(code) { completion(.failure(TrackerError.httpStatus(code))) }
                        else { completion(.failure(e)) }
                    } catch {
                        completion(.failure(TrackerError.malformed("\(error)")))
                    }
                }
            }
        case "udp":
            guard let port = parts.port else { fail(completion, .invalidURL(url)); return }
            let urlData = parts.pathAndQuery
            resolveEndpoints(parts.host, port: port) { [weak self] r in
                guard let self else { return }
                switch r {
                case .failure(let e): completion(.failure(e))
                case .success(let endpoints):
                    self.udpAnnounce(endpoints, index: 0, req, urlData: urlData, lastError: nil) { completion($0.mapError { $0 }) }
                }
            }
        default:
            fail(completion, .unsupportedScheme(parts.scheme))
        }
    }

    /// Try each resolved address in order until one answers. A tracker-level
    /// error (action 3) ends the attempt: the tracker is alive and said no.
    private func udpAnnounce(_ endpoints: [PeerAddress], index: Int, _ req: AnnounceRequest, urlData: String,
                             lastError: TrackerError?,
                             completion: @escaping (Result<AnnounceResponse, TrackerError>) -> Void) {
        guard index < endpoints.count else {
            completion(.failure(lastError ?? .network("no usable address")))
            return
        }
        udp.announce(endpoints[index], req, urlData: urlData) { [weak self] r in
            switch r {
            case .success: completion(r)
            case .failure(let e):
                if e.isTrackerAnswer || self == nil { completion(r); return }
                self?.udpAnnounce(endpoints, index: index + 1, req, urlData: urlData, lastError: e, completion: completion)
            }
        }
    }

    // MARK: Scrape

    public func scrape(url: String, infoHashes: [Data],
                       completion: @escaping (Result<[Data: (seeders: Int, completed: Int, leechers: Int)], any Error>) -> Void) {
        loop.assertInLoop()
        guard !closed else { fail(completion, .network("tracker client closed")); return }
        let hashes = infoHashes.filter { $0.count == 20 }
        guard !hashes.isEmpty else { fail(completion, .invalidRequest("no 20-byte info hashes")); return }
        guard let parts = TrackerURLParts.parse(url) else { fail(completion, .invalidURL(url)); return }
        switch parts.scheme {
        case "http", "https":
            guard let s = HTTPTrackerCodec.scrapeURLString(fromAnnounce: url) else {
                fail(completion, .unsupportedScheme("tracker does not support scrape")); return
            }
            guard let u = URL(string: HTTPTrackerCodec.scrapeURLString(s, infoHashes: hashes)) else {
                fail(completion, .invalidURL(s)); return
            }
            http.get(u) { r in
                switch r {
                case .failure(let e): completion(.failure(e))
                case .success(let (code, body)):
                    do {
                        let rows = try HTTPTrackerCodec.parseScrapeResponse(body)
                        if (200..<300).contains(code) { completion(.success(rows)) }
                        else { completion(.failure(TrackerError.httpStatus(code))) }
                    } catch let e as TrackerError {
                        if case .failure = e { completion(.failure(e)) }
                        else if !(200..<300).contains(code) { completion(.failure(TrackerError.httpStatus(code))) }
                        else { completion(.failure(e)) }
                    } catch {
                        completion(.failure(TrackerError.malformed("\(error)")))
                    }
                }
            }
        case "udp":
            guard let port = parts.port else { fail(completion, .invalidURL(url)); return }
            resolveEndpoints(parts.host, port: port) { [weak self] r in
                guard let self else { return }
                switch r {
                case .failure(let e): completion(.failure(e))
                case .success(let endpoints):
                    self.udpScrapeAll(endpoints, hashes) { completion($0.mapError { $0 }) }
                }
            }
        default:
            fail(completion, .unsupportedScheme(parts.scheme))
        }
    }

    /// Scrape in chunks of `maxScrapeHashes`, merging the rows.
    private func udpScrapeAll(_ endpoints: [PeerAddress], _ hashes: [Data],
                              completion: @escaping (Result<[Data: (seeders: Int, completed: Int, leechers: Int)], TrackerError>) -> Void) {
        let chunks = stride(from: 0, to: hashes.count, by: UDPTrackerCodec.maxScrapeHashes).map {
            Array(hashes[$0..<min($0 + UDPTrackerCodec.maxScrapeHashes, hashes.count)])
        }
        var merged: [Data: (seeders: Int, completed: Int, leechers: Int)] = [:]
        var remaining = chunks.count
        var firstError: TrackerError?
        for chunk in chunks {
            udpScrape(endpoints, index: 0, chunk, lastError: nil) { r in
                switch r {
                case .success(let rows):
                    for (h, row) in zip(chunk, rows) { merged[h] = row }
                case .failure(let e):
                    if firstError == nil { firstError = e }
                }
                remaining -= 1
                if remaining == 0 {
                    if merged.isEmpty, let e = firstError { completion(.failure(e)) } else { completion(.success(merged)) }
                }
            }
        }
    }

    private func udpScrape(_ endpoints: [PeerAddress], index: Int, _ hashes: [Data], lastError: TrackerError?,
                           completion: @escaping (Result<[(seeders: Int, completed: Int, leechers: Int)], TrackerError>) -> Void) {
        guard index < endpoints.count else {
            completion(.failure(lastError ?? .network("no usable address")))
            return
        }
        udp.scrape(endpoints[index], hashes) { [weak self] r in
            switch r {
            case .success: completion(r)
            case .failure(let e):
                if e.isTrackerAnswer || self == nil { completion(r); return }
                self?.udpScrape(endpoints, index: index + 1, hashes, lastError: e, completion: completion)
            }
        }
    }

    // MARK: Helpers

    /// Resolve via HostResolver (system DNS with DoH fallback, never blocking
    /// the loop). IPv4 addresses come first; the list is capped.
    private func resolveEndpoints(_ host: String, port: UInt16,
                                  completion: @escaping (Result<[PeerAddress], TrackerError>) -> Void) {
        let cap = maxAddressesPerHost
        let loop = self.loop
        resolver.resolve(host) { addrs in
            let usable = addrs.filter { !$0.isUnusable }
            let v4 = usable.filter { $0.isV4 }
            let allV6 = usable.filter { $0.isV6 }
            // No IPv6 internet here: IPv6 addresses can't be reached, so don't try them.
            let v6 = allV6.filter { HostResolver.hasGlobalIPv6 || $0.isLoopback || $0.isPrivate }
            if v4.isEmpty && v6.isEmpty && !allV6.isEmpty {
                let box = TrackerUnchecked(completion)
                loop.execute { box.value(.failure(.network("IPv6-only tracker; this network has no IPv6 internet"))) }
                return
            }
            // Keep both families represented when capping (v4 first).
            var picked = Array(v4.prefix(max(cap - min(v6.count, cap / 2), cap / 2)))
            picked += v6.prefix(cap - picked.count)
            if picked.isEmpty {
                // HostResolver may answer synchronously (IP literal): stay async.
                let box = TrackerUnchecked(completion)
                loop.execute { box.value(.failure(.dnsFailed(host))) }
            }
            else { completion(.success(picked.map { PeerAddress(ip: $0, port: port) })) }
        }
    }

    private func fail<T>(_ completion: @escaping (Result<T, any Error>) -> Void, _ e: TrackerError) {
        let box = TrackerUnchecked(completion)
        loop.execute { box.value(.failure(e)) }
    }
}
