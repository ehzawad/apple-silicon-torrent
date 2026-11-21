import Foundation
import Darwin

/// Persisted per-torrent state (bencoded in `<state>/resume/<infohash>.resume`).
public struct ResumeData: Sendable {
    public var infoDict: Data?
    public var bitfield: Data?
    public var savePath: String
    public var uploaded: Int64
    public var downloaded: Int64
    public var stamps: [(Int64, Int64)]
    public var peers: [PeerAddress]
    public var trackers: [[String]]
    public var sequential: Bool
    public var infoHashV1: Data?
    public var infoHashV2: Data?

    init(infoDict: Data?, bitfield: Data?, savePath: String, uploaded: Int64, downloaded: Int64,
         stamps: [(Int64, Int64)], peers: [PeerAddress], trackers: [[String]], sequential: Bool) {
        self.infoDict = infoDict; self.bitfield = bitfield; self.savePath = savePath
        self.uploaded = uploaded; self.downloaded = downloaded; self.stamps = stamps
        self.peers = peers; self.trackers = trackers; self.sequential = sequential
    }

    var encoded: Data {
        var d: [Data: BValue] = [:]
        func put(_ k: String, _ v: BValue) { d[Data(k.utf8)] = v }
        if let infoDict { put("info", .bytes(infoDict)) }
        if let bitfield { put("bitfield", .bytes(bitfield)) }
        put("save_path", .string(savePath))
        put("uploaded", .int(uploaded))
        put("downloaded", .int(downloaded))
        put("stamps", .list(stamps.map { .list([.int($0.0), .int($0.1)]) }))
        put("peers", .bytes(Data(peers.filter { $0.ip.isV4 }.flatMap { $0.compact })))
        put("peers6", .bytes(Data(peers.filter { $0.ip.isV6 }.flatMap { $0.compact })))
        put("trackers", .list(trackers.map { .list($0.map { .string($0) }) }))
        put("sequential", .int(sequential ? 1 : 0))
        if let infoHashV1 { put("ih1", .bytes(infoHashV1)) }
        if let infoHashV2 { put("ih2", .bytes(infoHashV2)) }
        return BValue.dict(d).encoded
    }

    init?(_ data: Data) {
        guard let v = try? BDecoder.decode(data) else { return nil }
        infoDict = v["info"]?.data
        bitfield = v["bitfield"]?.data
        savePath = v["save_path"]?.string ?? ""
        uploaded = v["uploaded"]?.int ?? 0
        downloaded = v["downloaded"]?.int ?? 0
        stamps = (v["stamps"]?.list ?? []).compactMap { e in
            guard let l = e.list, l.count == 2, let a = l[0].int, let b = l[1].int else { return nil }
            return (a, b)
        }
        peers = PeerAddress.parseCompactList(v["peers"]?.data ?? Data(), v6: false)
            + PeerAddress.parseCompactList(v["peers6"]?.data ?? Data(), v6: true)
        trackers = (v["trackers"]?.list ?? []).map { ($0.list ?? []).compactMap { $0.string } }
        sequential = v["sequential"]?.int == 1
        infoHashV1 = v["ih1"]?.data
        infoHashV2 = v["ih2"]?.data
    }
}

public struct SessionStatus: Sendable {
    public var listenPort: UInt16
    public var externalIP: String?
    public var dhtNodesV4: Int
    public var dhtNodesV6: Int
    public var connections: Int
    public var halfOpen: Int
    public var utpConnections: Int
    public var downloadRate: Double
    public var uploadRate: Double
    public var portMappings: [PortMappingStatus]
    public var incomingConnections: Int
    public var hasIPv6: Bool
}

public enum SessionError: Error, CustomStringConvertible {
    case invalidTorrent(String), invalidMagnet, duplicate, notStarted
    public var description: String {
        switch self {
        case .invalidTorrent(let m): return "invalid torrent: \(m)"
        case .invalidMagnet: return "invalid magnet link"
        case .duplicate: return "torrent already added"
        case .notStarted: return "session not started"
        }
    }
}

/// The engine root: owns sockets, DHT, uTP, NAT mapping, LSD, trackers and torrents.
public final class Session: @unchecked Sendable {
    public let loop: EventLoop
    public let config: SessionConfig
    public let peerID: Data
    public private(set) var listenPort: UInt16 = 0

    private var tcpListener: TCPListener?
    private var udp4: UDPSocket?
    private var udp6: UDPSocket?
    private(set) var utp: UTPManager?
    private var dht4: DHTNode?
    private var dht6: DHTNode?
    private var portMapper: PortMapper?
    private var lsd: LocalPeerDiscovery?
    let resolver: HostResolver
    let trackerClient: TrackerClient

    private(set) var torrents: [Torrent] = []
    private var byHash: [Data: Torrent] = [:]
    private var incoming: Set<ObjectIdentifier> = []
    private var incomingHandshakes: [ObjectIdentifier: IncomingHandshake] = [:]
    private var halfOpen = 0
    private var connectTokens = 0.0
    private var connectCursor = 0
    private var downMeter = RateMeter()
    private var upMeter = RateMeter()
    private var externalVotes: [IPAddress: Set<IPAddress>] = [:]
    public private(set) var externalIP: IPAddress?
    private(set) var hasIPv6 = false
    private var localAddresses: Set<IPAddress> = []
    private var timers: [LoopTimer] = []
    private var totalIncoming = 0
    public var onLog: ((String) -> Void)?

    public init(config: SessionConfig) {
        self.config = config
        self.loop = EventLoop()
        self.peerID = ClientIdentity.makePeerID()
        self.resolver = HostResolver(loop: loop, dohFallback: config.dnsOverHTTPSFallback)
        self.trackerClient = TrackerClient(loop: loop, resolver: resolver)
    }

    func log(_ s: String) { onLog?(s) }

    // MARK: Start / stop

    public func start() throws {
        Self.raiseFileDescriptorLimit()
        try FileManager.default.createDirectory(at: config.stateDirectory.appendingPathComponent("resume"),
                                                withIntermediateDirectories: true)
        try loop.sync { try self.startOnLoop() }
    }

    private func startOnLoop() throws {
        localAddresses = Self.localAddresses()
        hasIPv6 = localAddresses.contains { if case .v6(let hi, _) = $0 { return hi >> 61 == 1 } else { return false } }
        var port = config.listenPort
        if port == 0 { port = persistedPort() }
        // Bind TCP and UDP on the same port; retry a few random ports if taken.
        var lastError: (any Error)?
        for attempt in 0..<8 {
            let p = attempt == 0 ? port : UInt16.random(in: 20000...60000)
            do {
                let tcp = try TCPListener(port: p, loop: loop)
                let u4 = try UDPSocket(port: tcp.port, v6: false, loop: loop)
                let u6 = try? UDPSocket(port: tcp.port, v6: true, loop: loop)
                tcpListener = tcp; udp4 = u4; udp6 = u6
                listenPort = tcp.port
                lastError = nil
                break
            } catch {
                lastError = error
                tcpListener?.close(); tcpListener = nil
            }
        }
        if let lastError { throw lastError }
        savePort(listenPort)

        tcpListener!.onAccept = { [weak self] s in self?.accepted(s) }
        if config.enableTCP { tcpListener!.start() }

        if config.enableUTP {
            let m = UTPManager(loop: loop) { [weak self] data, to in
                guard let self else { return }
                if to.ip.isV4 { self.udp4?.send(data, to: to) } else { self.udp6?.send(data, to: to) }
            }
            m.maxPayload = Self.utpPayloadForPathMTU()
            m.onAccept = { [weak self] s in self?.accepted(s) }
            utp = m
        }
        udp4?.onDatagram = { [weak self] d, from in self?.udpReceived(d, from: from) }
        udp6?.onDatagram = { [weak self] d, from in self?.udpReceived(d, from: from) }
        udp4?.start()
        udp6?.start()

        if config.enableDHT {
            let dir = config.stateDirectory
            let d4 = DHTNode(loop: loop, isV6: false, resolver: resolver, stateFile: dir.appendingPathComponent("dht4.dat")) { [weak self] d, to in
                self?.udp4?.send(d, to: to)
            }
            d4.onExternalAddress = { [weak self] ip in self?.observedExternalIP(ip, from: ip, weight: 3) }
            dht4 = d4
            d4.start(bootstrap: SessionConfig.dhtBootstrapNodes)
            if hasIPv6, udp6 != nil {
                let d6 = DHTNode(loop: loop, isV6: true, resolver: resolver, stateFile: dir.appendingPathComponent("dht6.dat")) { [weak self] d, to in
                    self?.udp6?.send(d, to: to)
                }
                dht6 = d6
                d6.sibling = d4          // answer BEP 32 "want" for the other family
                d4.sibling = d6
                d6.start(bootstrap: SessionConfig.dhtBootstrapNodes)
            }
        }
        if config.enablePortMapping {
            let pm = PortMapper(loop: loop)
            pm.onChange = { [weak self] in
                guard let self, let ip = self.portMapper?.externalAddress else { return }
                self.observedExternalIP(ip, from: ip, weight: 5)
            }
            portMapper = pm
            pm.start(port: listenPort)
        }
        if config.enableLSD {
            let l = LocalPeerDiscovery(loop: loop, port: listenPort)
            l.onPeer = { [weak self] ih, addr in
                self?.byHash[ih]?.addPeer(addr, source: .lsd)
            }
            lsd = l
            l.start()
        }
        timers.append(loop.every(1.0) { [weak self] in self?.tick() })
        timers.append(loop.every(0.1, leeway: 0.02) { [weak self] in self?.connectTick() })
        timers.append(loop.every(600) { [weak self] in self?.dht4?.saveState(); self?.dht6?.saveState() })
    }

    public func shutdown(completion: @escaping @Sendable () -> Void) {
        loop.execute {
            for t in self.torrents { t.stop() }
            for t in self.timers { t.cancel() }
            self.timers.removeAll()
            self.dht4?.saveState(); self.dht6?.saveState()
            self.dht4?.stop(); self.dht6?.stop()
            self.portMapper?.stop()
            self.lsd?.stop()
            self.utp?.closeAll()
            self.tcpListener?.close()
            // Give "stopped" announces and port-mapping deletes a moment.
            self.loop.schedule(after: 1.5) {
                self.udp4?.close(); self.udp6?.close()
                completion()
            }
        }
    }

    /// macOS soft RLIMIT_NOFILE defaults to 256 — far too low for hundreds of peers.
    static func raiseFileDescriptorLimit() {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0 else { return }
        let want = rlim_t(10240)   // OPEN_MAX on Darwin
        let target = min(rl.rlim_max, want)
        if rl.rlim_cur < target {
            rl.rlim_cur = target
            _ = setrlimit(RLIMIT_NOFILE, &rl)
        }
    }

    private func persistedPort() -> UInt16 {
        let f = config.stateDirectory.appendingPathComponent("port")
        if let s = try? String(contentsOf: f, encoding: .utf8), let p = UInt16(s.trimmingCharacters(in: .whitespacesAndNewlines)), p > 1024 {
            return p
        }
        return UInt16.random(in: 20000...60000)
    }

    private func savePort(_ p: UInt16) {
        try? String(p).write(to: config.stateDirectory.appendingPathComponent("port"), atomically: true, encoding: .utf8)
    }

    /// Pick a uTP payload size that fits the smallest MTU among active interfaces
    /// (VPN tunnels like WireGuard/WARP commonly use 1280–1420).
    static func utpPayloadForPathMTU() -> Int {
        var minMTU = 1500
        var ifap: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&ifap) == 0, let first = ifap {
            var p: UnsafeMutablePointer<ifaddrs>? = first
            while let cur = p {
                let name = String(cString: cur.pointee.ifa_name)
                let flags = Int32(cur.pointee.ifa_flags)
                if flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, (name.hasPrefix("utun") || name.hasPrefix("en") || name.hasPrefix("ipsec") || name.hasPrefix("ppp")),
                   let data = cur.pointee.ifa_data, cur.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_LINK) {
                    let ifd = data.assumingMemoryBound(to: if_data.self).pointee
                    let mtu = Int(ifd.ifi_mtu)
                    // utun interfaces without an IPv4/IPv6 address are idle system tunnels; only
                    // count tunnels that carry a default route (approximated by having an inet addr).
                    if mtu >= 1280 && (!name.hasPrefix("utun") || hasInetAddress(first, name: name)) { minMTU = min(minMTU, mtu) }
                }
                p = cur.pointee.ifa_next
            }
            freeifaddrs(first)
        }
        // IPv6 header (40) + UDP (8) + uTP header (20) + 2 SACK ext bytes slack (8)
        return max(1000, minMTU - 76)
    }

    private static func hasInetAddress(_ first: UnsafeMutablePointer<ifaddrs>, name: String) -> Bool {
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            if String(cString: cur.pointee.ifa_name) == name, cur.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET) { return true }
            p = cur.pointee.ifa_next
        }
        return false
    }

    static func localAddresses() -> Set<IPAddress> {
        var out = Set<IPAddress>()
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return out }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            if let sa = cur.pointee.ifa_addr, let a = PeerAddress(sockaddr: sa) { out.insert(a.ip) }
            p = cur.pointee.ifa_next
        }
        freeifaddrs(first)
        return out
    }

    // MARK: Adding torrents

    @discardableResult
    public func addTorrent(fileURL: URL, downloadDirectory: URL? = nil,
                           configure: (@Sendable (Torrent) -> Void)? = nil) throws -> Torrent {
        let data = try Data(contentsOf: fileURL)
        let mi: Metainfo
        do { mi = try Metainfo(torrentFile: data) } catch { throw SessionError.invalidTorrent("\(error)") }
        return try add(metainfo: mi, magnet: nil, downloadDirectory: downloadDirectory, configure: configure)
    }

    @discardableResult
    public func addMagnet(_ uri: String, downloadDirectory: URL? = nil,
                          configure: (@Sendable (Torrent) -> Void)? = nil) throws -> Torrent {
        guard let m = MagnetLink(uri) else { throw SessionError.invalidMagnet }
        return try add(metainfo: nil, magnet: m, downloadDirectory: downloadDirectory, configure: configure)
    }

    private func add(metainfo: Metainfo?, magnet: MagnetLink?, downloadDirectory: URL?,
                     configure: (@Sendable (Torrent) -> Void)?) throws -> Torrent {
        try loop.sync {
            let hashes = metainfo?.infoHashes ?? magnet!.infoHashes
            if byHash[hashes.primary] != nil { throw SessionError.duplicate }
            let resume = loadResume(hashes)
            var mi = metainfo
            if mi == nil, let info = resume?.infoDict, var m = try? Metainfo(infoDict: info), m.infoHashes.primary == hashes.primary {
                m.announceTiers = resume?.trackers ?? []
                mi = m
            }
            let dir = downloadDirectory ?? resume.map { URL(fileURLWithPath: $0.savePath) } ?? config.downloadDirectory
            let t = Torrent(session: self, metainfo: mi, magnet: magnet, downloadDirectory: dir)
            configure?(t)
            torrents.append(t)
            for h in t.infoHashes.all20 { byHash[h] = t }
            t.start(resume: resume)
            return t
        }
    }

    /// Pause (disconnect everything, save resume data) or resume a torrent.
    public func setPaused(_ t: Torrent, _ paused: Bool) {
        loop.execute {
            if paused {
                guard t.state != .paused else { return }
                t.stop()
            } else {
                guard t.state == .paused else { return }
                t.restart(resume: self.loadResume(t.infoHashes))
            }
        }
    }

    /// All torrents (snapshot, safe from any thread).
    public var allTorrents: [Torrent] { loop.sync { torrents } }

    /// Find a torrent by its hex info hash (v1 or v2, as shown in `TorrentStatus.infoHash`).
    public func torrent(infoHashHex: String) -> Torrent? {
        loop.sync { torrents.first { $0.infoHashes.description == infoHashHex } }
    }

    /// Remove a torrent. Downloaded files stay on disk; resume data is deleted unless
    /// `keepResumeData` (so re-adding later starts clean and rechecks existing files).
    public func remove(_ t: Torrent, keepResumeData: Bool = false) {
        loop.execute {
            t.stop()
            self.torrents.removeAll { $0 === t }
            for h in t.infoHashes.all20 { self.byHash.removeValue(forKey: h) }
            if !keepResumeData {
                let url = self.resumeURL(t.infoHashes)
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.5) {
                    try? FileManager.default.removeItem(at: url)   // after stop()'s async save lands
                }
            }
        }
    }

    /// Every connected peer of a torrent (not just the dashboard's top 12).
    public func peers(infoHashHex: String) -> [PeerSummary] {
        loop.sync {
            guard let t = torrents.first(where: { $0.infoHashes.description == infoHashHex }) else { return [] }
            return t.peerSummaries(limit: Int.max)
        }
    }

    // MARK: Resume files

    private func resumeURL(_ h: InfoHashes) -> URL {
        config.stateDirectory.appendingPathComponent("resume").appendingPathComponent(h.primary.hex + ".resume")
    }

    func loadResume(_ h: InfoHashes) -> ResumeData? {
        guard let d = try? Data(contentsOf: resumeURL(h)) else { return nil }
        return ResumeData(d)
    }

    func saveResume(_ r: ResumeData, for h: InfoHashes) {
        var r = r
        r.infoHashV1 = h.v1
        r.infoHashV2 = h.v2
        let url = resumeURL(h)
        let data = r.encoded
        DispatchQueue.global(qos: .utility).async { try? data.write(to: url, options: .atomic) }
    }

    // MARK: UDP demux (DHT + uTP share the listen port)

    private func udpReceived(_ d: Data, from: PeerAddress) {
        guard let first = d.first else { return }
        if first == UInt8(ascii: "d") {
            (from.ip.isV4 ? dht4 : dht6)?.handle(d, from: from)
        } else {
            _ = utp?.handle(d, from: from)
        }
    }

    // MARK: DHT / LSD helpers for torrents

    func dhtGetPeers(infoHash: Data, onPeers: @escaping ([PeerAddress]) -> Void) {
        for d in [dht4, dht6].compactMap({ $0 }) {
            d.getPeers(infoHash: infoHash, announcePort: listenPort, impliedPort: true, onPeers: onPeers, onDone: nil)
        }
    }

    var dhtNodeCount: Int { (dht4?.nodeCount ?? 0) + (dht6?.nodeCount ?? 0) }

    func dhtAddNode(_ a: PeerAddress) {
        guard a.port != 0 else { return }
        (a.ip.isV4 ? dht4 : dht6)?.addNode(a)
    }

    func lsdAnnounce(_ hashes: [Data]) { lsd?.announce(infoHashes: hashes) }

    // MARK: External address

    func observedExternalIP(_ ip: IPAddress, from voter: IPAddress, weight: Int = 1) {
        guard !ip.isPrivate, !ip.isUnusable else { return }
        var set = externalVotes[ip] ?? []
        set.insert(voter)
        if weight > 1 { for i in 0..<weight { set.insert(.v4(UInt32(0xFFFF_0000) | UInt32(i))) } }
        externalVotes[ip] = set
        if let best = externalVotes.max(by: { $0.value.count < $1.value.count })?.key { externalIP = best }
    }

    func isSelf(_ a: PeerAddress) -> Bool {
        guard a.port == listenPort else { return false }
        return a.ip == externalIP || localAddresses.contains(a.ip)
    }

    // MARK: Rate limiting

    func downloadMeterAdd(_ n: Int) { downMeter.add(n) }
    func uploadMeterAdd(_ n: Int) { upMeter.add(n) }
    func downloadThrottled() -> Bool { config.downloadRateLimit > 0 && downMeter.bytesPerSecond > Double(config.downloadRateLimit) }
    func uploadThrottled() -> Bool { config.uploadRateLimit > 0 && upMeter.bytesPerSecond > Double(config.uploadRateLimit) }

    // MARK: Periodic

    private func tick() {
        downMeter.tick()
        upMeter.tick()
        let now = monotonicNow()
        for t in torrents { t.tick(now: now) }
    }

    private var totalConnections: Int {
        torrents.reduce(0) { $0 + $1.peers.count + $1.handshaking.count } + halfOpen + incomingHandshakes.count
    }

    private func connectTick() {
        guard !torrents.isEmpty else { return }
        let rate = Double(config.connectionsPerSecond)
        connectTokens = min(connectTokens + rate / 10, max(1, rate / 2))
        let now = monotonicNow()
        var idle = 0
        while connectTokens >= 1 && halfOpen < config.maxHalfOpen && totalConnections < config.maxConnectionsGlobal
                && idle < torrents.count {
            connectCursor = (connectCursor + 1) % torrents.count
            let t = torrents[connectCursor]
            guard let k = t.nextConnectCandidate(now: now) else { idle += 1; continue }
            idle = 0
            connectTokens -= 1
            connect(t, k)
        }
    }

    // MARK: Outgoing connections

    private func connect(_ t: Torrent, _ k: KnownPeer, forceUTP: Bool = false, forcePlaintext: Bool = false) {
        let useUTP = utp != nil && (forceUTP || !config.enableTCP || (config.preferUTP && k.supportsUTP))
        halfOpen += 1
        let addr = k.address
        let finish: (Result<any ByteStream, SocketError>) -> Void = { [weak self, weak t] result in
            guard let self else { return }
            self.halfOpen -= 1
            guard let t else { if case .success(let s) = result { s.close() }; return }
            switch result {
            case .failure(let e):
                // TCP failed: many peers (esp. behind NAT with UDP mappings) only accept uTP.
                if !useUTP, self.utp != nil, var kk = t.known[addr], !kk.triedUTPFallback {
                    kk.triedUTPFallback = true
                    t.known[addr] = kk
                    self.connect(t, kk, forceUTP: true, forcePlaintext: forcePlaintext)
                } else {
                    t.connectFailed(addr, error: "\(e)")
                }
            case .success(let stream):
                self.establish(t, k, stream: stream, plaintext: forcePlaintext || k.plaintextOnly)
            }
        }
        if useUTP {
            utp!.connect(to: addr, timeout: config.connectTimeout) { r in finish(r.map { $0 as any ByteStream }) }
        } else {
            TCPStream.connect(to: addr, loop: loop, timeout: config.connectTimeout) { r in finish(r.map { $0 as any ByteStream }) }
        }
    }

    private func establish(_ t: Torrent, _ k: KnownPeer, stream: any ByteStream, plaintext: Bool) {
        let ih: Data = (k.useV2Hash ? t.infoHashes.v2Truncated : nil) ?? t.infoHashes.primary
        let source = k.sources.first ?? .manual
        if config.encryption == .disabled || (plaintext && config.encryption == .prefer) {
            t.attach(stream: stream, outgoing: true, source: source, infoHash: ih, handshakeSent: false,
                     remoteHandshake: nil, initialData: Data())
            (stream as? TCPStream)?.activate()
            return
        }
        let hs = Wire.Handshake(reserved: .ours(v2: t.infoHashes.v2 != nil), infoHash: ih, peerID: peerID).encoded
        let addr = k.address
        MSE.initiate(stream: stream, skey: ih, initialPayload: hs, allowPlaintext: config.encryption == .prefer,
                     loop: loop, timeout: 12) { [weak self, weak t] result in
            guard let self, let t else { stream.close(); return }
            switch result {
            case .success(let (s2, leftover)):
                t.attach(stream: s2, outgoing: true, source: source, infoHash: ih, handshakeSent: true,
                         remoteHandshake: nil, initialData: leftover)
            case .failure:
                stream.close()
                if self.config.encryption == .prefer, var kk = t.known[addr], !kk.plaintextOnly {
                    // Peer doesn't speak MSE: retry immediately in plaintext.
                    kk.plaintextOnly = true
                    t.known[addr] = kk
                    self.connect(t, kk, forceUTP: stream.transport == .utp, forcePlaintext: true)
                } else {
                    t.connectFailed(addr, error: "encryption handshake failed")
                }
            }
        }
        (stream as? TCPStream)?.activate()
    }

    /// BEP 55: we were introduced to `addr` by a relay — open uTP towards it.
    func holepunchConnect(_ t: Torrent, to addr: PeerAddress) {
        guard let utp, !t.connecting.contains(addr), !t.peers.values.contains(where: { $0.address == addr }) else { return }
        t.connecting.insert(addr)
        halfOpen += 1
        utp.connect(to: addr, timeout: 6) { [weak self, weak t] r in
            guard let self, let t else { return }
            self.halfOpen -= 1
            switch r {
            case .success(let s):
                let k = t.known[addr] ?? KnownPeer(address: addr, sources: [.holepunch])
                self.establish(t, k, stream: s, plaintext: false)
            case .failure(let e):
                t.connectFailed(addr, error: "holepunch: \(e)")
            }
        }
    }

    // MARK: Incoming connections

    private func accepted(_ s: any ByteStream) {
        guard totalConnections < config.maxConnectionsGlobal, !torrents.isEmpty else { s.close(); return }
        totalIncoming += 1
        let h = IncomingHandshake(session: self, stream: s)
        incomingHandshakes[ObjectIdentifier(h)] = h
        h.begin()
        (s as? TCPStream)?.activate()
    }

    fileprivate func incomingFinished(_ h: IncomingHandshake) {
        incomingHandshakes.removeValue(forKey: ObjectIdentifier(h))
    }

    fileprivate func torrent(for infoHash: Data) -> Torrent? { byHash[infoHash] }
    fileprivate var allSkeys: [Data] { Array(byHash.keys) }

    // MARK: Status

    public func status() -> SessionStatus {
        loop.sync { statusOnLoop() }
    }

    func statusOnLoop() -> SessionStatus {
        SessionStatus(
            listenPort: listenPort, externalIP: externalIP?.description,
            dhtNodesV4: dht4?.nodeCount ?? 0, dhtNodesV6: dht6?.nodeCount ?? 0,
            connections: torrents.reduce(0) { $0 + $1.peers.count }, halfOpen: halfOpen,
            utpConnections: utp?.connectionCount ?? 0,
            downloadRate: downMeter.bytesPerSecond, uploadRate: upMeter.bytesPerSecond,
            portMappings: portMapper?.statuses ?? [], incomingConnections: totalIncoming, hasIPv6: hasIPv6)
    }

    public func torrentStatuses() -> [TorrentStatus] {
        loop.sync { torrents.map { $0.status() } }
    }

    public func withLoop(_ body: @escaping @Sendable () -> Void) { loop.execute(body) }
}

/// Classifies a new incoming connection: plaintext handshake or MSE, then routes it.
private final class IncomingHandshake: @unchecked Sendable {
    unowned let session: Session
    var stream: any ByteStream
    var buffer = Data()
    var timer: LoopTimer?
    var done = false
    var encrypted = false

    init(session: Session, stream: any ByteStream) {
        self.session = session
        self.stream = stream
    }

    func begin() {
        stream.onRead = { [weak self] d in self?.received(d) }
        stream.onClose = { [weak self] _ in self?.finish(nil) }
        timer = session.loop.schedule(after: 15) { [weak self] in self?.finish(nil) }
    }

    private func received(_ d: Data) {
        buffer.append(d)
        evaluate()
    }

    private func evaluate() {
        guard !done else { return }
        if buffer.isEmpty { return }
        let prefix = buffer.prefix(20)
        if Wire.Handshake.looksLikeHandshakePrefix(Data(prefix)) {
            guard buffer.count >= Wire.handshakeLength else { return }
            guard let hs = Wire.Handshake.parse(buffer), let t = session.torrent(for: hs.infoHash) else { finish(nil); return }
            if session.config.encryption == .require && !encrypted { finish(nil); return }
            let rest = buffer.subdata(in: (buffer.startIndex + Wire.handshakeLength)..<buffer.endIndex)
            let s = stream
            done = true
            timer?.cancel()
            session.incomingFinished(self)
            t.attach(stream: s, outgoing: false, source: .incoming, infoHash: hs.infoHash, handshakeSent: false,
                     remoteHandshake: hs, initialData: rest)
            return
        }
        // Not a plaintext handshake → MSE (unless disabled or we already decrypted once).
        guard session.config.encryption != .disabled, !encrypted else { finish(nil); return }
        let initial = buffer
        buffer = Data()
        encrypted = true
        let skeys: () -> [Data] = { [weak session] in session?.allSkeys ?? [] }
        MSE.respond(stream: stream, initialBytes: initial, skeys: skeys,
                    allowPlaintext: session.config.encryption != .require,
                    loop: session.loop, timeout: 12) { [weak self] result in
            guard let self, !self.done else { return }
            switch result {
            case .success(let (s2, _, payload)):
                self.stream = s2
                s2.onRead = { [weak self] d in self?.received(d) }
                s2.onClose = { [weak self] _ in self?.finish(nil) }
                self.buffer = payload
                self.evaluate()
            case .failure:
                self.finish(nil)
            }
        }
    }

    private func finish(_ err: SocketError?) {
        guard !done else { return }
        done = true
        timer?.cancel()
        stream.close()
        session.incomingFinished(self)
    }
}
