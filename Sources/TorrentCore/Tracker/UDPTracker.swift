import Foundation

// MARK: - UDP tracker codec (BEP 15, BEP 41)

/// Pure encode/decode of BEP 15 packets.
enum UDPTrackerCodec {
    static let protocolID: UInt64 = 0x41727101980
    /// Max info hashes per scrape packet (BEP 15: about 74 fit in one datagram).
    static let maxScrapeHashes = 74

    enum Action: UInt32 {
        case connect = 0, announce = 1, scrape = 2, error = 3
    }

    // Requests

    static func connectRequest(transactionID: UInt32) -> Data {
        var d = Data(capacity: 16)
        d.appendBE64(protocolID)
        d.appendBE32(Action.connect.rawValue)
        d.appendBE32(transactionID)
        return d
    }

    /// 98-byte announce followed by BEP 41 options (URLData) when `urlData`
    /// (the announce URL's path + query) is non-empty.
    static func announceRequest(connectionID: UInt64, transactionID: UInt32,
                                _ req: AnnounceRequest, urlData: String?) -> Data {
        var d = Data(capacity: 98 + 64)
        d.appendBE64(connectionID)
        d.appendBE32(Action.announce.rawValue)
        d.appendBE32(transactionID)
        d.append(fixed20(req.infoHash))
        d.append(fixed20(req.peerID))
        d.appendBE64(UInt64(bitPattern: max(0, req.downloaded)))
        d.appendBE64(UInt64(bitPattern: req.effectiveLeft))
        d.appendBE64(UInt64(bitPattern: max(0, req.uploaded)))
        d.appendBE32(req.event.udpCode)
        d.appendBE32(0)                                             // IP: default (source address)
        d.appendBE32(req.key)
        let numWant: Int32 = req.event == .stopped ? 0 : (req.numWant > 0 ? Int32(clamping: req.numWant) : -1)
        d.appendBE32(UInt32(bitPattern: numWant))
        d.appendBE16(req.port)
        if let u = urlData, !u.isEmpty { d.append(urlDataOptions(u)) }
        return d
    }

    /// BEP 41: option type 0x2 (URLData), one-byte length, up to 255 bytes per
    /// option; longer strings are split across consecutive URLData options and the
    /// tracker concatenates them. No EndOfOptions byte (end of packet terminates,
    /// matching libtorrent).
    static func urlDataOptions(_ s: String) -> Data {
        let bytes = Array(s.utf8)
        var out = Data(capacity: bytes.count + 2 * (bytes.count / 255 + 1))
        var i = 0
        while i < bytes.count {
            let n = min(255, bytes.count - i)
            out.append(0x02)
            out.append(UInt8(n))
            out.append(contentsOf: bytes[i..<(i + n)])
            i += n
        }
        return out
    }

    static func scrapeRequest(connectionID: UInt64, transactionID: UInt32, infoHashes: [Data]) -> Data {
        var d = Data(capacity: 16 + 20 * infoHashes.count)
        d.appendBE64(connectionID)
        d.appendBE32(Action.scrape.rawValue)
        d.appendBE32(transactionID)
        for h in infoHashes { d.append(fixed20(h)) }
        return d
    }

    private static func fixed20(_ d: Data) -> Data {
        if d.count == 20 { return d }
        if d.count > 20 { return Data(d.prefix(20)) }
        return d + Data(count: 20 - d.count)
    }

    // Responses

    /// (action, transaction id) of any response, or nil if too short.
    static func header(_ d: Data) -> (action: UInt32, transactionID: UInt32)? {
        guard d.count >= 8 else { return nil }
        return (d.be32(0), d.be32(4))
    }

    static func parseConnect(_ d: Data) -> UInt64? {
        guard d.count >= 16, d.be32(0) == Action.connect.rawValue else { return nil }
        return d.be64(8)
    }

    /// Announce response. Peer entries are 6 bytes for a tracker reached over
    /// IPv4 and 18 bytes for one reached over IPv6 (BEP 15 IPv6 extension).
    static func parseAnnounce(_ d: Data, v6: Bool) -> AnnounceResponse? {
        guard d.count >= 20, d.be32(0) == Action.announce.rawValue else { return nil }
        let interval = Int(d.be32(8))
        let leechers = Int(d.be32(12))
        let seeders = Int(d.be32(16))
        let peerBytes = d.subdata(in: (d.startIndex + 20)..<d.endIndex)
        let peers = HTTPTrackerCodec.dedupe(PeerAddress.parseCompactList(peerBytes, v6: v6))
        return AnnounceResponse(interval: interval, minInterval: nil, peers: peers,
                                seeders: seeders, leechers: leechers, warning: nil)
    }

    /// Scrape response: (seeders, completed, leechers) per requested hash, in order.
    static func parseScrape(_ d: Data) -> [(seeders: Int, completed: Int, leechers: Int)]? {
        guard d.count >= 8, d.be32(0) == Action.scrape.rawValue else { return nil }
        var out: [(seeders: Int, completed: Int, leechers: Int)] = []
        var off = 8
        while off + 12 <= d.count {
            out.append((Int(d.be32(off)), Int(d.be32(off + 4)), Int(d.be32(off + 8))))
            off += 12
        }
        return out
    }

    static func parseError(_ d: Data) -> String? {
        guard d.count >= 8, d.be32(0) == Action.error.rawValue else { return nil }
        let msg = String(decoding: d.subdata(in: (d.startIndex + 8)..<d.endIndex), as: UTF8.self)
            .trimmingCharacters(in: .controlCharacters.union(.whitespacesAndNewlines))
        return msg.isEmpty ? "tracker error" : msg
    }
}

// MARK: - UDP transport

/// All UDP tracker traffic of a session goes through one ephemeral socket per
/// address family; replies are demultiplexed by the 32-bit transaction id.
///
/// Retransmission deliberately deviates from BEP 15's 15·2ⁿ seconds schedule:
/// we wait 4 s, retransmit, wait 8 s, then give up (12 s total), so a dead
/// tracker costs seconds instead of minutes and the next address / tracker is
/// tried quickly. Connection ids are cached for 60 s per tracker endpoint
/// (BEP 15: valid for 1 min client-side, servers accept them for 2 min).
final class UDPTrackerTransport: @unchecked Sendable {
    private let loop: EventLoop
    /// Wait times before each retransmission / final failure.
    var retransmitTimeouts: [Double] = [4, 8]
    var connectionIDLifetime: Double = 60

    private var sock4: UDPSocket?
    private var sock6: UDPSocket?
    private var sock6Failed = false
    private var sock4Failed = false

    private final class Transaction: @unchecked Sendable {
        let id: UInt32
        let endpoint: PeerAddress
        let packet: Data
        var attempt = 0
        var timer: LoopTimer?
        let handler: (Result<Data, TrackerError>) -> Void
        init(id: UInt32, endpoint: PeerAddress, packet: Data, handler: @escaping (Result<Data, TrackerError>) -> Void) {
            self.id = id; self.endpoint = endpoint; self.packet = packet; self.handler = handler
        }
    }
    private var pending: [UInt32: Transaction] = [:]
    private var connCache: [PeerAddress: (id: UInt64, expires: Double)] = [:]
    private var connWaiters: [PeerAddress: [(Result<UInt64, TrackerError>) -> Void]] = [:]

    /// Diagnostics.
    private(set) var packetsSent = 0
    private(set) var packetsReceived = 0
    var pendingCount: Int { pending.count }

    init(loop: EventLoop) { self.loop = loop }

    deinit {
        for t in pending.values { t.timer?.cancel() }
        // UDPSocket.deinit releases the descriptor safely from any thread; close() is loop-only.
    }

    func close() {
        loop.assertInLoop()
        let all = pending.values
        pending.removeAll()
        for t in all { t.timer?.cancel(); t.handler(.failure(.network("closed"))) }
        sock4?.close(); sock4 = nil
        sock6?.close(); sock6 = nil
        connCache.removeAll()
    }

    // MARK: Sockets

    private func socket(v6: Bool) -> UDPSocket? {
        if v6 {
            if let s = sock6 { return s }
            if sock6Failed { return nil }
        } else {
            if let s = sock4 { return s }
            if sock4Failed { return nil }
        }
        do {
            let s = try UDPSocket(port: 0, v6: v6, loop: loop)
            s.onDatagram = { [weak self] data, from in self?.handleDatagram(data, from: from) }
            s.start()
            if v6 { sock6 = s } else { sock4 = s }
            return s
        } catch {
            if v6 { sock6Failed = true } else { sock4Failed = true }
            return nil
        }
    }

    private func newTransactionID() -> UInt32 {
        while true {
            let r = Data.random(4).be32(0)
            if pending[r] == nil { return r }
        }
    }

    // MARK: Datagram demux

    func handleDatagram(_ data: Data, from: PeerAddress) {
        loop.assertInLoop()
        packetsReceived += 1
        guard let (_, tid) = UDPTrackerCodec.header(data), let t = pending[tid] else { return }
        // Accept only replies from the address we sent to (anti-spoofing).
        guard t.endpoint.ip == from.ip else { return }
        pending.removeValue(forKey: tid)
        t.timer?.cancel()
        t.handler(.success(data))
    }

    /// Send a request (built with a fresh transaction id) and wait for the reply,
    /// retransmitting per `retransmitTimeouts`.
    private func transact(_ endpoint: PeerAddress, build: (UInt32) -> Data,
                          handler: @escaping (Result<Data, TrackerError>) -> Void) {
        guard let sock = socket(v6: endpoint.ip.isV6) else {
            fail(handler, .network("no IPv\(endpoint.ip.isV6 ? 6 : 4) UDP socket"))
            return
        }
        let tid = newTransactionID()
        let t = Transaction(id: tid, endpoint: endpoint, packet: build(tid), handler: handler)
        packetsSent += 1
        guard sock.send(t.packet, to: endpoint) else {
            fail(handler, .network("send to \(endpoint) failed"))
            return
        }
        pending[tid] = t
        armTimer(t)
    }

    private func armTimer(_ t: Transaction) {
        let wait = retransmitTimeouts.isEmpty ? 10 : retransmitTimeouts[min(t.attempt, retransmitTimeouts.count - 1)]
        t.timer = loop.schedule(after: wait) { [weak self, weak t] in
            guard let self, let t, self.pending[t.id] === t else { return }
            t.attempt += 1
            if t.attempt >= max(1, self.retransmitTimeouts.count) {
                self.pending.removeValue(forKey: t.id)
                t.handler(.failure(.timedOut))
                return
            }
            if let s = self.socket(v6: t.endpoint.ip.isV6) {
                self.packetsSent += 1
                s.send(t.packet, to: t.endpoint)
            }
            self.armTimer(t)
        }
    }

    /// Deliver an immediate failure asynchronously (never re-enter the caller).
    private func fail<T>(_ handler: @escaping (Result<T, TrackerError>) -> Void, _ e: TrackerError) {
        let box = TrackerUnchecked(handler)
        loop.execute { box.value(.failure(e)) }
    }

    // MARK: Connect (with cache + coalescing)

    /// Returns (connection id, wasCached).
    private func connectionID(_ endpoint: PeerAddress, handler: @escaping (Result<(UInt64, Bool), TrackerError>) -> Void) {
        if let c = connCache[endpoint], c.expires > monotonicNow() {
            let box = TrackerUnchecked(handler)
            loop.execute { box.value(.success((c.id, true))) }
            return
        }
        if connWaiters[endpoint] != nil {
            connWaiters[endpoint]!.append { r in handler(r.map { ($0, false) }) }
            return
        }
        connWaiters[endpoint] = [{ r in handler(r.map { ($0, false) }) }]
        transact(endpoint, build: { UDPTrackerCodec.connectRequest(transactionID: $0) }) { [weak self] r in
            guard let self else { return }
            let result: Result<UInt64, TrackerError>
            switch r {
            case .failure(let e): result = .failure(e)
            case .success(let d):
                if let id = UDPTrackerCodec.parseConnect(d) {
                    self.connCache[endpoint] = (id, monotonicNow() + self.connectionIDLifetime)
                    result = .success(id)
                } else if let msg = UDPTrackerCodec.parseError(d) {
                    result = .failure(.failure(msg))
                } else {
                    result = .failure(.malformed("bad connect response"))
                }
            }
            let waiters = self.connWaiters.removeValue(forKey: endpoint) ?? []
            for w in waiters { w(result) }
        }
    }

    func invalidateConnection(_ endpoint: PeerAddress) { connCache.removeValue(forKey: endpoint) }

    // MARK: Operations on one resolved endpoint

    func announce(_ endpoint: PeerAddress, _ req: AnnounceRequest, urlData: String?,
                  handler: @escaping (Result<AnnounceResponse, TrackerError>) -> Void) {
        announce(endpoint, req, urlData: urlData, retried: false, handler: handler)
    }

    private func announce(_ endpoint: PeerAddress, _ req: AnnounceRequest, urlData: String?, retried: Bool,
                          handler: @escaping (Result<AnnounceResponse, TrackerError>) -> Void) {
        connectionID(endpoint) { [weak self] r in
            guard let self else { return }
            switch r {
            case .failure(let e): handler(.failure(e))
            case .success(let (cid, cached)):
                self.transact(endpoint, build: {
                    UDPTrackerCodec.announceRequest(connectionID: cid, transactionID: $0, req, urlData: urlData)
                }) { [weak self] r in
                    guard let self else { return }
                    switch r {
                    case .failure(let e):
                        if cached { self.invalidateConnection(endpoint) }
                        handler(.failure(e))
                    case .success(let d):
                        if let resp = UDPTrackerCodec.parseAnnounce(d, v6: endpoint.ip.isV6) {
                            handler(.success(resp))
                        } else if let msg = UDPTrackerCodec.parseError(d) {
                            if cached && !retried {
                                // Probably an expired connection id: reconnect once.
                                self.invalidateConnection(endpoint)
                                self.announce(endpoint, req, urlData: urlData, retried: true, handler: handler)
                            } else {
                                handler(.failure(.failure(msg)))
                            }
                        } else {
                            handler(.failure(.malformed("bad announce response")))
                        }
                    }
                }
            }
        }
    }

    func scrape(_ endpoint: PeerAddress, _ hashes: [Data],
                handler: @escaping (Result<[(seeders: Int, completed: Int, leechers: Int)], TrackerError>) -> Void) {
        connectionID(endpoint) { [weak self] r in
            guard let self else { return }
            switch r {
            case .failure(let e): handler(.failure(e))
            case .success(let (cid, cached)):
                self.transact(endpoint, build: {
                    UDPTrackerCodec.scrapeRequest(connectionID: cid, transactionID: $0, infoHashes: hashes)
                }) { [weak self] r in
                    switch r {
                    case .failure(let e):
                        if cached { self?.invalidateConnection(endpoint) }
                        handler(.failure(e))
                    case .success(let d):
                        if let rows = UDPTrackerCodec.parseScrape(d) {
                            handler(.success(rows))
                        } else if let msg = UDPTrackerCodec.parseError(d) {
                            if cached { self?.invalidateConnection(endpoint) }
                            handler(.failure(.failure(msg)))
                        } else {
                            handler(.failure(.malformed("bad scrape response")))
                        }
                    }
                }
            }
        }
    }
}
