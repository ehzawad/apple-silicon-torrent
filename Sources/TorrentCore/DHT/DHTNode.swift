import Foundation
import Dispatch

/// Mainline DHT node (BEP 5) for one address family, with BEP 32 (IPv6 / `want`),
/// BEP 42 (node-id security) and BEP 43 (read-only) support.
///
/// The node does not own a socket: the Session passes it every datagram whose
/// first byte is `'d'` via `handle(_:from:)`, and the node sends through the
/// `send` closure (the shared listen-port UDP socket). Loop-confined: every member
/// must be used on `loop.queue`.
public final class DHTNode: @unchecked Sendable {
    // MARK: Tunables

    static let k = 8
    static let alpha = 8
    static let tickInterval: Double = 0.1
    static let maintenanceInterval: Double = 5
    static let refreshAfter: Double = 15 * 60
    static let seedWait: Double = 20
    static let maxQueued = 2000
    static let maxStoredNodes = 200
    static let maxConcurrentRefreshes = 3
    /// "v" key: two client letters + two version characters.
    static let versionTag = Data("AS01".utf8)
    static let ioQueue = DispatchQueue(label: "astor.dht.io", qos: .utility)

    // MARK: Configuration / collaborators

    let loop: EventLoop
    public let isV6: Bool
    private let resolver: HostResolver
    private let stateFile: URL?
    private let send: (Data, PeerAddress) -> Void

    /// Hard per-query timeout (seconds).
    var queryTimeout: Double = 2.5
    /// After this long an in-flight lookup query stops counting against α.
    var slowAfter: Double = 1.0
    /// BEP 43: when true we flag our queries `ro=1` and do not answer queries.
    var readOnly = false
    /// The other-family DHT instance (answers BEP 32 `want` for the other family).
    weak var sibling: DHTNode?

    public var onExternalAddress: ((IPAddress) -> Void)?

    // MARK: State

    private(set) var ownID: DHTID
    let table: DHTRoutingTable
    private var tokens: DHTTokenManager
    private(set) var store = DHTPeerStore()
    private var voter = DHTIPVoter()
    private var queryLimiter: DHTRateLimiter
    private var responseLimiter: DHTRateLimiter
    private(set) var externalIP: IPAddress?

    enum QueryResult {
        case response(id: DHTID, r: [Data: BValue])
        case error(code: Int, message: String)
        case timeout
    }

    private struct Pending {
        let method: String
        let addr: PeerAddress
        let expectedID: DHTID?
        let deadline: Double
        let callback: (QueryResult) -> Void
    }

    private struct Queued {
        let method: String
        let args: [Data: BValue]
        let addr: PeerAddress
        let expectedID: DHTID?
        let callback: (QueryResult) -> Void
    }

    private var pending: [UInt16: Pending] = [:]
    private var queued: [Queued] = []
    private var queuedHead = 0
    private var deferredFailures: [(QueryResult) -> Void] = []

    private var lookups: [DHTLookup] = []
    private var bootstrapLookup: DHTLookup?
    private var refreshQueue: [DHTID] = []
    private var activeRefreshes = 0

    private var started = false
    private(set) var stopped = false
    private var stateLoaded = false
    private var routers: [PeerAddress] = []
    private var routerSet: Set<PeerAddress> = []
    private var savedNodes: [DHTNodeInfo] = []
    private var hintNodes: [PeerAddress] = []
    private var bootstrapAttempts = 0
    private var nextBootstrapAt: Double = 0
    private(set) var bootstrapped = false

    private var tickTimer: LoopTimer?
    private var lastMaintenance: Double = 0
    private var lastExpire: Double = 0
    private var recentPings: [PeerAddress: Double] = [:]

    struct Stats {
        var queriesSent = 0
        var responsesReceived = 0
        var errorsReceived = 0
        var timeouts = 0
        var queriesReceived = 0
        var queriesDropped = 0
        var tableAdded = 0
        var tableCached = 0
        var tableRejected = 0
    }
    private(set) var stats = Stats()

    // MARK: Public API

    public init(loop: EventLoop, isV6: Bool, resolver: HostResolver,
                stateFile: URL?, send: @escaping (Data, PeerAddress) -> Void) {
        self.loop = loop
        self.isV6 = isV6
        self.resolver = resolver
        self.stateFile = stateFile
        self.send = send
        let now = monotonicNow()
        let id = DHTID.random()
        ownID = id
        table = DHTRoutingTable(ownID: id, k: Self.k, now: now)
        tokens = DHTTokenManager(now: now)
        queryLimiter = DHTRateLimiter(rate: 200, burst: 200, now: now)
        responseLimiter = DHTRateLimiter(rate: 500, burst: 500, now: now)
    }

    deinit { tickTimer?.cancel() }

    /// Start the node: load persisted state, resolve the `"host:port"` bootstrap
    /// entries (never blocking the loop) and bootstrap with find_node(own id).
    public func start(bootstrap: [String]) {
        loop.assertInLoop()
        guard !started, !stopped else { return }
        started = true
        let now = monotonicNow()
        lastMaintenance = now
        lastExpire = now
        tickTimer = loop.every(Self.tickInterval, leeway: 0.02) { [weak self] in self?.tick() }

        if let url = stateFile {
            let loop = self.loop
            Self.ioQueue.async { [weak self] in
                let data = try? Data(contentsOf: url)
                guard let self else { return }
                loop.execute { self.loadState(data) }
            }
        } else {
            stateLoaded = true
        }

        for entry in bootstrap {
            guard let (host, port) = Self.splitHostPort(entry) else { continue }
            resolver.resolve(host) { [weak self] addrs in
                guard let self, !self.stopped else { return }
                let mine = addrs.filter { $0.isV6 == self.isV6 && !$0.isUnusable }.map { PeerAddress(ip: $0, port: port) }
                var fresh: [PeerAddress] = []
                for a in mine where self.routerSet.insert(a).inserted {
                    self.routers.append(a)
                    fresh.append(a)
                }
                self.seedsArrived(fresh)
            }
        }
        bootstrapIfNeeded()
    }

    /// Feed one incoming datagram (first byte `'d'`).
    public func handle(_ datagram: Data, from: PeerAddress) {
        loop.assertInLoop()
        guard started, !stopped, from.ip.isV6 == isV6, from.port != 0, !from.ip.isUnusable else { return }
        guard let msg = KRPCMessage.decode(datagram) else { return }
        switch msg.body {
        case .query(let method, let args):
            handleQuery(msg, method: method, args: args, from: from)
        case .response(let r):
            handleResponse(msg, r: r, from: from)
        case .error(let code, let message):
            handleError(msg, code: code, message: message, from: from)
        }
    }

    /// Iterative get_peers lookup; streams (deduplicated) peers to `onPeers` as they
    /// arrive, then announces to the 8 closest nodes that returned tokens when
    /// `announcePort` is set. `onDone` fires when the lookup ends.
    public func getPeers(infoHash: Data, announcePort: UInt16?, impliedPort: Bool,
                         onPeers: @escaping ([PeerAddress]) -> Void, onDone: (() -> Void)?) {
        loop.assertInLoop()
        guard let target = DHTID(infoHash), !stopped else { onDone?(); return }
        let now = monotonicNow()
        let l = DHTLookup(kind: .getPeers, target: target, now: now)
        configure(l)
        l.announcePort = announcePort
        l.impliedPort = impliedPort
        l.onPeers = onPeers
        l.onDone = onDone
        // Peers announced directly to us are delivered too (asynchronously, on the next step).
        l.undelivered = l.addPeers(store.peers(for: target, max: 200, now: now))
        lookups.append(l)
        guard started else { return }
        seed(l, now: now, includeRouters: false)
        // Send the first wave now; completion is only ever reported asynchronously.
        let (queries, _) = l.nextQueries(now: now)
        for c in queries { sendLookupQuery(l, c) }
    }

    /// A node hint (BEP 5 PORT message, magnet `x.pe`, …): ping it and, if it
    /// answers, it joins the routing table.
    public func addNode(_ addr: PeerAddress) {
        loop.assertInLoop()
        guard !stopped, addr.ip.isV6 == isV6, addr.port != 0, !addr.ip.isUnusable else { return }
        guard !table.contains(addr: addr) else { return }
        if hintNodes.count < 64, !hintNodes.contains(addr) { hintNodes.append(addr) }
        guard started else { return }
        if let l = bootstrapLookup, !l.finished, l.add(id: nil, addr: addr) {
            step(l, now: monotonicNow())   // queried by the bootstrap lookup
        } else {
            ping(addr, id: nil)
        }
    }

    /// Nodes in the routing table (live buckets, excluding replacement caches).
    public var nodeCount: Int { table.count }

    /// Persist the node id and up to 200 good nodes (bencoded) to `stateFile`.
    public func saveState() { saveState(completion: nil) }

    public func stop() {
        loop.assertInLoop()
        guard !stopped else { return }
        stopped = true
        tickTimer?.cancel()
        tickTimer = nil
        pending.removeAll()
        queued.removeAll()
        queuedHead = 0
        deferredFailures.removeAll()
        let ls = lookups
        lookups.removeAll()
        bootstrapLookup = nil
        refreshQueue.removeAll()
        for l in ls where !l.finished {
            l.finished = true
            let done = l.onDone
            l.onDone = nil
            l.onPeers = nil
            done?()
        }
    }

    // MARK: Internal accessors (status / tests)

    var nodeIDData: Data { ownID.data }
    var activeLookupCount: Int { lookups.count }
    var pendingQueryCount: Int { pending.count }

    // MARK: Persistence

    /// Block until queued state writes hit the disk. Call off the loop (e.g. at
    /// process exit after `saveState()`), never on it.
    static func waitForPendingWrites() { ioQueue.sync {} }

    func saveState(completion: (@Sendable () -> Void)?) {
        guard let url = stateFile else { completion?(); return }
        let data = encodeState()
        Self.ioQueue.async {
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? data.write(to: url, options: .atomic)
            completion?()
        }
    }

    func encodeState() -> Data {
        let now = monotonicNow()
        let entries = table.allEntries
            .filter { $0.state(now: now) != .bad }
            .sorted { a, b in
                let ga = a.state(now: now) == .good, gb = b.state(now: now) == .good
                if ga != gb { return ga }
                return a.lastSeen > b.lastSeen
            }
        var nodes = entries.prefix(Self.maxStoredNodes).map(\.info)
        if nodes.count < Self.maxStoredNodes {
            // Keep previously persisted nodes we have not re-verified yet.
            var have = Set(nodes.map(\.addr))
            for n in savedNodes where nodes.count < Self.maxStoredNodes && have.insert(n.addr).inserted {
                nodes.append(n)
            }
        }
        var d: [Data: BValue] = [:]
        d[Data("id".utf8)] = .bytes(ownID.data)
        d[Data((isV6 ? "nodes6" : "nodes").utf8)] = .bytes(CompactNodeInfo.encode(nodes, v6: isV6))
        return BValue.dict(d).encoded
    }

    private func loadState(_ data: Data?) {
        guard !stopped else { return }
        stateLoaded = true
        if let data, let v = try? BDecoder.decode(data) {
            if let id = DHTID(v["id"]?.data), table.count == 0,
               externalIP.map({ BEP42.isExempt($0) || BEP42.isValid(id, for: $0) }) ?? true {
                ownID = id
                table.rebuild(ownID: id, now: monotonicNow())
            }
            if let raw = v[isV6 ? "nodes6" : "nodes"]?.data {
                savedNodes = Array(CompactNodeInfo.decode(raw, v6: isV6).filter { $0.id != ownID }.prefix(Self.maxStoredNodes))
            }
        }
        if let l = bootstrapLookup, !l.finished {
            for n in savedNodes { l.add(id: n.id, addr: n.addr) }
        }
        bootstrapIfNeeded()
    }

    // MARK: Bootstrap / refresh

    private func seedsArrived(_ seeds: [PeerAddress]) {
        guard !seeds.isEmpty else { return }
        if let l = bootstrapLookup, !l.finished {
            for a in seeds { l.add(id: nil, addr: a) }
            step(l, now: monotonicNow())
        } else {
            bootstrapIfNeeded()
        }
    }

    private func bootstrapIfNeeded() {
        guard started, !stopped, stateLoaded, bootstrapLookup == nil, !bootstrapped else { return }
        startBootstrap()
    }

    private func startBootstrap() {
        guard !stopped, bootstrapLookup == nil else { return }
        let now = monotonicNow()
        let l = DHTLookup(kind: .findNode, target: ownID, now: now)
        l.purpose = .bootstrap
        configure(l)
        seed(l, now: now, includeRouters: table.count < Self.k * 2)
        guard !l.isEmpty else {
            nextBootstrapAt = now + 5
            return
        }
        bootstrapAttempts += 1
        bootstrapLookup = l
        lookups.append(l)
        step(l, now: now)
    }

    private func bootstrapFinished() {
        let now = monotonicNow()
        if table.count == 0 {
            let exp = Double(min(max(bootstrapAttempts - 1, 0), 4))
            nextBootstrapAt = now + min(60, 5 * pow(2, exp))
            return
        }
        bootstrapAttempts = 0
        if !bootstrapped {
            bootstrapped = true
            // Fill the far buckets right away rather than waiting for the 15-min refresh.
            refreshQueue.append(contentsOf: table.allBucketTargets())
            pumpRefreshes()
        }
    }

    private func pumpRefreshes() {
        while activeRefreshes < Self.maxConcurrentRefreshes, !refreshQueue.isEmpty, !stopped {
            let target = refreshQueue.removeFirst()
            let now = monotonicNow()
            let l = DHTLookup(kind: .findNode, target: target, now: now)
            l.purpose = .refresh
            configure(l)
            seed(l, now: now, includeRouters: false)
            if l.isEmpty { continue }
            activeRefreshes += 1
            lookups.append(l)
            step(l, now: now)
        }
    }

    private func configure(_ l: DHTLookup) {
        l.k = Self.k
        l.alpha = Self.alpha
        l.slowAfter = slowAfter
    }

    /// Seed a lookup with the closest known nodes; when the table is sparse (or for
    /// bootstrap) also persisted nodes, hints and the bootstrap routers.
    private func seed(_ l: DHTLookup, now: Double, includeRouters: Bool) {
        for e in table.closest(to: l.target, count: Self.k * 2, now: now) { l.add(id: e.id, addr: e.addr) }
        guard includeRouters || table.count < Self.k else { return }
        let saved = savedNodes.sorted { l.target.isCloser($0.id, than: $1.id) }.prefix(Self.k * 2)
        for n in saved { l.add(id: n.id, addr: n.addr) }
        for a in hintNodes { l.add(id: nil, addr: a) }
        // Routers have unknown ids: the lookup queries them at once without letting
        // them occupy a slot among the k closest.
        for a in routers { l.add(id: nil, addr: a) }
    }

    // MARK: Lookups

    private func step(_ l: DHTLookup, now: Double) {
        guard !l.finished, !stopped else { return }
        if !l.undelivered.isEmpty {
            let p = l.undelivered
            l.undelivered = []
            l.onPeers?(p)
            if l.finished || stopped { return }
        }
        if l.isEmpty {
            seed(l, now: now, includeRouters: l.purpose == .bootstrap)
            if l.isEmpty {
                if now - l.startedAt > Self.seedWait { finish(l) }
                return
            }
        }
        let (queries, done) = l.nextQueries(now: now)
        for c in queries { sendLookupQuery(l, c) }
        if done { finish(l) }
    }

    private func sendLookupQuery(_ l: DHTLookup, _ c: DHTLookup.Candidate) {
        var args: [Data: BValue] = [:]
        let method: String
        switch l.kind {
        case .findNode:
            method = "find_node"
            args[KRPCKey.target] = .bytes(l.target.data)
        case .getPeers:
            method = "get_peers"
            args[KRPCKey.infoHash] = .bytes(l.target.data)
        }
        let addr = c.addr
        sendQuery(method, args: args, to: addr, expectedID: c.id) { [weak self, weak l] result in
            guard let self, let l, !l.finished else { return }
            switch result {
            case .response(let id, let r):
                let nodes = self.parseNodes(r, reporter: addr)
                let values = l.kind == .getPeers ? Self.parseValues(r[KRPCKey.values]) : []
                var token = r[KRPCKey.token]?.data
                if let t = token, t.isEmpty || t.count > 64 { token = nil }
                let fresh = l.handleResponse(from: addr, id: id, nodes: nodes, token: token, values: values)
                if !fresh.isEmpty { l.undelivered.append(contentsOf: fresh) }
            case .error, .timeout:
                l.handleFailure(from: addr)
            }
            self.step(l, now: monotonicNow())
        }
    }

    private func finish(_ l: DHTLookup) {
        guard !l.finished else { return }
        l.finished = true
        lookups.removeAll { $0 === l }
        if !l.undelivered.isEmpty {
            let p = l.undelivered
            l.undelivered = []
            l.onPeers?(p)
        }
        if l.kind == .getPeers, let port = l.announcePort, !stopped {
            for c in l.announceTargets(count: Self.k) {
                guard let token = c.token else { continue }
                var args: [Data: BValue] = [
                    KRPCKey.infoHash: .bytes(l.target.data),
                    KRPCKey.port: .int(Int64(port)),
                    KRPCKey.token: .bytes(token),
                ]
                if l.impliedPort { args[KRPCKey.impliedPort] = .int(1) }
                sendQuery("announce_peer", args: args, to: c.addr, expectedID: c.id) { _ in }
            }
        }
        switch l.purpose {
        case .bootstrap:
            if bootstrapLookup === l { bootstrapLookup = nil }
            bootstrapFinished()
        case .refresh:
            activeRefreshes -= 1
            pumpRefreshes()
        case .user:
            break
        }
        let done = l.onDone
        l.onDone = nil
        l.onPeers = nil
        done?()
    }

    /// Nodes of our family from a response; drops our own id, routers and — unless
    /// the reporter is itself local — private/loopback addresses (no reflection into
    /// the local network).
    private func parseNodes(_ r: [Data: BValue], reporter: PeerAddress) -> [DHTNodeInfo] {
        guard let raw = r[isV6 ? KRPCKey.nodes6 : KRPCKey.nodes]?.data else { return [] }
        let reporterLocal = BEP42.isExempt(reporter.ip)
        return CompactNodeInfo.decode(raw, v6: isV6).prefix(32).filter { n in
            n.id != ownID && !routerSet.contains(n.addr) && (reporterLocal || !BEP42.isExempt(n.addr.ip))
        }
    }

    /// `values`: list of 6-byte (IPv4) or 18-byte (IPv6) compact peers.
    static func parseValues(_ v: BValue?) -> [PeerAddress] {
        guard let list = v?.list else { return [] }
        var out: [PeerAddress] = []
        for item in list.prefix(512) {
            guard let d = item.data, d.count == 6 || d.count == 18, let p = PeerAddress(compact: d),
                  p.port != 0, !p.ip.isUnusable else { continue }
            out.append(p)
        }
        return out
    }

    // MARK: Outgoing queries

    func sendQuery(_ method: String, args: [Data: BValue], to addr: PeerAddress, expectedID: DHTID?,
                   callback: @escaping (QueryResult) -> Void) {
        guard !stopped else { return }
        let q = Queued(method: method, args: args, addr: addr, expectedID: expectedID, callback: callback)
        guard addr.ip.isV6 == isV6, addr.port != 0, !addr.ip.isUnusable else {
            deferredFailures.append(callback)
            return
        }
        let now = monotonicNow()
        if queuedHead < queued.count || !queryLimiter.take(now: now) {
            guard queued.count - queuedHead < Self.maxQueued else {
                stats.queriesDropped += 1
                deferredFailures.append(callback)
                return
            }
            queued.append(q)
            return
        }
        transmit(q, now: now)
    }

    private func transmit(_ q: Queued, now: Double) {
        guard let tid = allocateTID() else { deferredFailures.append(q.callback); return }
        var args = q.args
        args[KRPCKey.id] = .bytes(ownID.data)
        let msg = KRPCMessage(transactionID: Data([UInt8(tid >> 8), UInt8(tid & 0xFF)]),
                              body: .query(method: q.method, args: args),
                              version: Self.versionTag, readOnly: readOnly)
        pending[tid] = Pending(method: q.method, addr: q.addr, expectedID: q.expectedID,
                               deadline: now + queryTimeout, callback: q.callback)
        stats.queriesSent += 1
        send(msg.encoded, q.addr)
    }

    private func allocateTID() -> UInt16? {
        guard pending.count < 60_000 else { return nil }
        var t = UInt16.random(in: 0...UInt16.max)
        while pending[t] != nil { t &+= 1 }
        return t
    }

    func ping(_ addr: PeerAddress, id: DHTID?) {
        let now = monotonicNow()
        if let t = recentPings[addr], now - t < 10 { return }
        recentPings[addr] = now
        if let id { table.markPinged(id: id, now: now) }
        sendQuery("ping", args: [:], to: addr, expectedID: id) { _ in }
    }

    // MARK: Timers

    private func tick() {
        guard !stopped else { return }
        let now = monotonicNow()
        if !deferredFailures.isEmpty {
            let f = deferredFailures
            deferredFailures = []
            for cb in f { cb(.timeout) }
        }
        while queuedHead < queued.count, queryLimiter.take(now: now) {
            let q = queued[queuedHead]
            queuedHead += 1
            transmit(q, now: now)
        }
        if queuedHead > 0, queuedHead >= queued.count || queuedHead > 1024 {
            queued.removeFirst(queuedHead)
            queuedHead = 0
        }
        var expired: [(UInt16, Pending)] = []
        for (tid, p) in pending where p.deadline <= now { expired.append((tid, p)) }
        for (tid, p) in expired {
            pending.removeValue(forKey: tid)
            stats.timeouts += 1
            for e in table.failed(id: p.expectedID, addr: p.addr, now: now) { ping(e.addr, id: e.id) }
            p.callback(.timeout)
            if stopped { return }
        }
        for l in lookups { step(l, now: now) }
        if now - lastMaintenance >= Self.maintenanceInterval {
            lastMaintenance = now
            maintenance(now: now)
        }
    }

    private func maintenance(now: Double) {
        tokens.rotateIfNeeded(now: now)
        if now - lastExpire >= 60 {
            lastExpire = now
            store.expire(now: now)
            recentPings = recentPings.filter { now - $0.value < 60 }
        }
        if table.count == 0 { bootstrapped = false }
        if !bootstrapped, bootstrapLookup == nil, stateLoaded, now >= nextBootstrapAt {
            startBootstrap()
        }
        for e in table.nodesNeedingPing(now: now, max: 4) { ping(e.addr, id: e.id) }
        if bootstrapped {
            refreshQueue.append(contentsOf: table.refreshTargets(now: now, staleAfter: Self.refreshAfter))
            pumpRefreshes()
        }
    }

    // MARK: Incoming

    private func transactionKey(_ t: Data) -> UInt16? {
        guard t.count == 2, let a = t.first, let b = t.last else { return nil }
        return UInt16(a) << 8 | UInt16(b)
    }

    private func handleResponse(_ msg: KRPCMessage, r: [Data: BValue], from: PeerAddress) {
        guard let tid = transactionKey(msg.transactionID), let p = pending[tid], p.addr == from else { return }
        pending.removeValue(forKey: tid)
        let now = monotonicNow()
        guard let id = DHTID(r[KRPCKey.id]?.data), id != ownID else {
            stats.errorsReceived += 1
            for e in table.failed(id: p.expectedID, addr: from, now: now) { ping(e.addr, id: e.id) }
            p.callback(.error(code: KRPCErrorCode.protocolError, message: "invalid id"))
            return
        }
        stats.responsesReceived += 1
        if !routerSet.contains(from) {
            let res = table.heard(id: id, addr: from, confirmed: true, now: now)
            switch res.outcome {
            case .added: stats.tableAdded += 1
            case .cached: stats.tableCached += 1
            case .rejected: stats.tableRejected += 1
            case .updated: break
            }
            if let pc = res.pingCandidate { ping(pc.addr, id: pc.id) }
        }
        if let ip = msg.yourIP { vote(reporter: from.ip, reported: ip.ip) }
        p.callback(.response(id: id, r: r))
    }

    private func handleError(_ msg: KRPCMessage, code: Int, message: String, from: PeerAddress) {
        guard let tid = transactionKey(msg.transactionID), let p = pending[tid], p.addr == from else { return }
        pending.removeValue(forKey: tid)
        stats.errorsReceived += 1
        p.callback(.error(code: code, message: message))
    }

    private func handleQuery(_ msg: KRPCMessage, method: String, args: [Data: BValue], from: PeerAddress) {
        stats.queriesReceived += 1
        if readOnly { return }   // BEP 43: read-only nodes never answer
        let now = monotonicNow()
        guard responseLimiter.take(now: now) else { return }
        guard let sender = DHTID(args[KRPCKey.id]?.data) else {
            sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "invalid id", to: from)
            return
        }
        var r: [Data: BValue] = [:]
        switch method {
        case "ping":
            break
        case "find_node":
            guard let target = DHTID(args[KRPCKey.target]?.data) else {
                sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "invalid target", to: from)
                return
            }
            addNodes(to: &r, target: target, want: args[KRPCKey.want], exclude: sender, now: now)
        case "get_peers":
            guard let ih = DHTID(args[KRPCKey.infoHash]?.data) else {
                sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "invalid info_hash", to: from)
                return
            }
            r[KRPCKey.token] = .bytes(tokens.token(for: from.ip))
            // Keep replies below ~1200 bytes (tunnels with MTU 1280-1300).
            let peers = store.peers(for: ih, max: isV6 ? 25 : 50, now: now)
            if !peers.isEmpty { r[KRPCKey.values] = .list(peers.map { .bytes(Data($0.compact)) }) }
            addNodes(to: &r, target: ih, want: args[KRPCKey.want], exclude: sender, now: now)
        case "announce_peer":
            guard let ih = DHTID(args[KRPCKey.infoHash]?.data) else {
                sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "invalid info_hash", to: from)
                return
            }
            guard let token = args[KRPCKey.token]?.data, tokens.validate(token, for: from.ip) else {
                sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "bad token", to: from)
                return
            }
            var port = from.port
            if (args[KRPCKey.impliedPort]?.int ?? 0) == 0 {
                guard let p = args[KRPCKey.port]?.int, p > 0, p <= 65535 else {
                    sendError(msg.transactionID, code: KRPCErrorCode.protocolError, message: "invalid port", to: from)
                    return
                }
                port = UInt16(p)
            }
            store.announce(ih, peer: PeerAddress(ip: from.ip, port: port), now: now)
        default:
            // Forward compatibility (as libtorrent): unknown queries carrying a target
            // are answered like find_node.
            guard let target = DHTID(args[KRPCKey.target]?.data) ?? DHTID(args[KRPCKey.infoHash]?.data) else {
                sendError(msg.transactionID, code: KRPCErrorCode.methodUnknown, message: "method unknown", to: from)
                return
            }
            addNodes(to: &r, target: target, want: args[KRPCKey.want], exclude: sender, now: now)
        }
        r[KRPCKey.id] = .bytes(ownID.data)
        let reply = KRPCMessage(transactionID: msg.transactionID, body: .response(r),
                                version: Self.versionTag, yourIP: from)
        send(reply.encoded, from)

        // Learn about the querier — never read-only nodes (BEP 43) or ourselves.
        if !msg.readOnly && sender != ownID && !routerSet.contains(from) {
            let res = table.heard(id: sender, addr: from, confirmed: false, now: now)
            if res.outcome == .added { ping(from, id: sender) }   // verify it answers queries
            if let pc = res.pingCandidate { ping(pc.addr, id: pc.id) }
        }
    }

    /// BEP 32: `want` = ["n4", "n6"]; without it, nodes of the query's own family.
    private func addNodes(to r: inout [Data: BValue], target: DHTID, want: BValue?, exclude: DHTID, now: Double) {
        var w4 = !isV6, w6 = isV6
        if let list = want?.list {
            let wants = Set(list.compactMap { $0.data.map { String(decoding: $0, as: UTF8.self) } })
            if wants.contains("n4") || wants.contains("n6") {
                w4 = wants.contains("n4")
                w6 = wants.contains("n6")
            }
        }
        if w4, let n = compactNodes(v6: false, target: target, exclude: exclude, now: now) { r[KRPCKey.nodes] = .bytes(n) }
        if w6, let n = compactNodes(v6: true, target: target, exclude: exclude, now: now) { r[KRPCKey.nodes6] = .bytes(n) }
    }

    private func compactNodes(v6: Bool, target: DHTID, exclude: DHTID, now: Double) -> Data? {
        let node: DHTNode? = v6 == isV6 ? self : sibling
        guard let node, node.isV6 == v6 else { return nil }
        let infos = node.table.closestForResponse(to: target, count: Self.k, now: now, excluding: exclude)
        return CompactNodeInfo.encode(infos, v6: v6)
    }

    private func sendError(_ t: Data, code: Int, message: String, to: PeerAddress) {
        let m = KRPCMessage(transactionID: t, body: .error(code: code, message: message),
                            version: Self.versionTag, yourIP: to)
        send(m.encoded, to)
    }

    // MARK: BEP 42 external address

    private func vote(reporter: IPAddress, reported: IPAddress) {
        guard reported.isV6 == isV6, !reported.isUnusable else { return }
        guard let winner = voter.add(voter: reporter, reported: reported) else { return }
        externalIP = winner
        // Only globally routable addresses are reported / used for the node id.
        guard !BEP42.isExempt(winner) else { return }
        if !BEP42.isValid(ownID, for: winner) {
            changeID(BEP42.nodeID(for: winner))
        }
        onExternalAddress?(winner)
    }

    /// Switch to a new node id (keeping all known nodes) and re-announce ourselves
    /// to the part of the keyspace around it.
    func changeID(_ id: DHTID) {
        ownID = id
        table.rebuild(ownID: id, now: monotonicNow())
        guard started && !stopped else { return }
        // A bootstrap still converging on the old id is useless now: drop it (its
        // responders are already in the table) and look up the new id instead.
        if let old = bootstrapLookup {
            old.finished = true
            lookups.removeAll { $0 === old }
            bootstrapLookup = nil
        }
        startBootstrap()
    }

    // MARK: Helpers

    /// "host:port" / "[v6]:port" → (host, port).
    static func splitHostPort(_ s: String) -> (String, UInt16)? {
        let str = s.trimmingCharacters(in: .whitespaces)
        if str.hasPrefix("[") {
            guard let close = str.firstIndex(of: "]") else { return nil }
            let host = String(str[str.index(after: str.startIndex)..<close])
            let rest = str[str.index(after: close)...]
            guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()), p != 0, !host.isEmpty else { return nil }
            return (host, p)
        }
        guard let colon = str.lastIndex(of: ":"), let p = UInt16(str[str.index(after: colon)...]), p != 0 else { return nil }
        let host = String(str[..<colon])
        guard !host.isEmpty, !host.contains(":") else { return nil }
        return (host, p)
    }
}
