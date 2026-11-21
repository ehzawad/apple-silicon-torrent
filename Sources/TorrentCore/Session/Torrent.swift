import Foundation

public enum TorrentState: String, Sendable {
    case fetchingMetadata = "metadata"
    case checking
    case downloading
    case seeding
    case paused
    case error
}

/// A peer address we know about (not necessarily connected).
struct KnownPeer {
    var address: PeerAddress
    var sources: Set<PeerSource>
    var failures = 0
    var lastAttempt = 0.0
    var nextAttempt = 0.0
    var connectedOnce = false
    var isSeed = false
    var supportsUTP = false
    var supportsHolepunch = false
    var prefersEncryption = false
    var plaintextOnly = false        // MSE attempt failed → use plaintext next time
    var triedUTPFallback = false
    var useV2Hash = false            // learned via the v2 (truncated) info hash
    var pexFrom: ObjectIdentifier?   // relay candidate for BEP 55 holepunch
}

/// Snapshot for UIs (CLI / SwiftUI). Produced on the loop.
public struct TorrentStatus: Sendable {
    public var name: String
    public var infoHash: String
    public var state: TorrentState
    public var version: TorrentVersion?
    public var progress: Double              // 0...1 of wanted bytes
    public var wantedBytes: Int64
    public var completedBytes: Int64
    public var downloadRate: Double          // payload bytes/s
    public var uploadRate: Double
    public var downloadedTotal: Int64
    public var uploadedTotal: Int64
    public var wastedBytes: Int64
    public var hashFailures: Int
    public var connectedPeers: Int
    public var connectedSeeds: Int
    public var connectingPeers: Int
    public var knownPeers: Int
    public var knownBySource: [PeerSource: Int]
    public var encryptedPeers: Int
    public var utpPeers: Int
    public var incomingPeers: Int
    public var unchokedUs: Int               // peers currently unchoking us
    public var trackerSeeders: Int?
    public var trackerLeechers: Int?
    public var trackers: [TrackerStatus]
    public var pieceCount: Int
    public var pieceLength: Int
    public var piecesHave: Int
    public var distributedCopies: Double
    public var eta: Double?
    public var error: String?
    public var topPeers: [PeerSummary]
    public var savePath: String
    public var webSeeds: Int = 0
    public var webSeedRate: Double = 0
}

public struct PeerSummary: Sendable {
    public var address: String
    public var client: String
    public var downloadRate: Double
    public var uploadRate: Double
    public var flags: String
    public var progress: Double
}

public final class Torrent: @unchecked Sendable {
    unowned let session: Session
    let loop: EventLoop
    public let infoHashes: InfoHashes
    public private(set) var metainfo: Metainfo?
    var magnet: MagnetLink?
    public let downloadDirectory: URL
    var storage: Storage?
    var picker: PiecePicker?
    public private(set) var state: TorrentState
    var errorMessage: String?
    var displayName: String

    var peers: [ObjectIdentifier: PeerConnection] = [:]
    /// Connections whose BitTorrent handshake is still in progress (strongly held here).
    var handshaking: [ObjectIdentifier: PeerConnection] = [:]
    var connecting: Set<PeerAddress> = []
    var known: [PeerAddress: KnownPeer] = [:]
    var banned: Set<IPAddress> = []
    var hashFailuresByIP: [IPAddress: Int] = [:]
    var trackers: TrackerManager?
    var extraTrackerTiers: [[String]] = []
    var webSeeds: [WebSeed] = []

    // Options
    public var sequential = false { didSet { picker?.sequential = sequential } }
    public var seedAfterCompletion = true
    var selectedFiles: Set<Int>?               // indices into non-padding files

    // Stats
    var downMeter = RateMeter()
    var upMeter = RateMeter()
    var downloadedTotal: Int64 = 0
    var uploadedTotal: Int64 = 0
    var wasted: Int64 = 0
    var hashFailures = 0
    var tickCount = 0
    var optimisticPeer: ObjectIdentifier?
    var lastDHTAnnounce = -1e9
    var lastLSDAnnounce = -1e9
    var lastResumeSave = monotonicNow()
    var completedAt: Double?
    public var onComplete: (() -> Void)?

    // Metadata exchange (BEP 9)
    struct MetadataFetch {
        var size: Int
        var pieces: [Data?]
        var requested: [Int: (ObjectIdentifier, Double)] = [:]
        var badPeers: Set<ObjectIdentifier> = []
    }
    var metadataFetch: MetadataFetch?
    var checkingProgress: Int = 0

    var isPrivate: Bool { metainfo?.isPrivate ?? false }
    var isSeeding: Bool { state == .seeding }
    var key: Data { infoHashes.primary }

    init(session: Session, metainfo: Metainfo?, magnet: MagnetLink?, downloadDirectory: URL) {
        self.session = session
        self.loop = session.loop
        self.metainfo = metainfo
        self.magnet = magnet
        self.downloadDirectory = downloadDirectory
        self.infoHashes = metainfo?.infoHashes ?? magnet!.infoHashes
        self.displayName = metainfo?.name ?? magnet?.displayName ?? infoHashes.description
        self.state = metainfo == nil ? .fetchingMetadata : .checking
    }

    // MARK: Lifecycle

    func start(resume: ResumeData?) {
        loop.assertInLoop()
        if let m = magnet {
            for p in m.peers { addPeer(p, source: .magnet) }
            if let sel = m.selectOnly.isEmpty ? nil : Set(m.selectOnly) { selectedFiles = sel }
        }
        if let r = resume {
            for p in r.peers { addPeer(p, source: .resume) }
            uploadedTotal = r.uploaded
            downloadedTotal = r.downloaded
            if r.sequential { sequential = true }
        }
        startTrackers()
        if metainfo != nil {
            initializeStorage(resume: resume)
        }
        announceDHT(force: true)
        announceLSD()
    }

    private func trackerTiers() -> [[String]] {
        var tiers = metainfo?.announceTiers ?? []
        if let m = magnet, !m.trackers.isEmpty { tiers += m.trackers.map { [$0] } }
        tiers += extraTrackerTiers
        if !isPrivate && !session.config.extraTrackers.isEmpty {
            tiers += session.config.extraTrackers.map { [$0] }
        }
        // de-duplicate URLs while keeping tier order
        var seen = Set<String>()
        return tiers.compactMap { tier in
            let t = tier.filter { seen.insert($0).inserted }
            return t.isEmpty ? nil : t
        }
    }

    private func startTrackers() {
        trackers?.stop()
        let tiers = trackerTiers()
        guard !tiers.isEmpty else { trackers = nil; return }
        let tm = TrackerManager(
            loop: loop, client: session.trackerClient, tiers: tiers, infoHashes: infoHashes.all20,
            peerID: session.peerID, announceToAll: session.config.announceToAllTrackers,
            numWant: session.config.numWant,
            port: { [unowned self] in self.session.listenPort },
            stats: { [unowned self] in (self.uploadedTotal, self.downloadedTotal, self.bytesLeft) },
            onPeers: { [weak self] peers in
                guard let self else { return }
                for p in peers { self.addPeer(p, source: .tracker) }
            })
        trackers = tm
        tm.start()
    }

    /// Resume after `stop()`: reopen storage (fast-resume from saved state) and reconnect.
    func restart(resume: ResumeData?) {
        loop.assertInLoop()
        state = metainfo == nil ? .fetchingMetadata : .checking
        storage = nil
        picker = nil
        webSeeds = []
        for k in known.keys { known[k]?.nextAttempt = 0; known[k]?.failures = 0 }
        start(resume: resume)
    }

    func stop() {
        loop.assertInLoop()
        saveResume()
        trackers?.stop()
        for (_, p) in peers { p.disconnect("torrent stopped") }
        for (_, p) in handshaking { p.disconnect("torrent stopped") }
        peers.removeAll()
        handshaking.removeAll()
        storage?.closeAll()
        state = .paused
    }

    var bytesLeft: Int64 {
        guard let mi = metainfo, let picker else { return 1 }
        var left: Int64 = 0
        for i in 0..<mi.pieceCount where picker.isWanted(i) { left += Int64(mi.pieceSize(i)) }
        return left
    }

    // MARK: Storage / checking

    private func initializeStorage(resume: ResumeData?) {
        guard let mi = metainfo else { return }
        do {
            storage = try Storage(metainfo: mi, downloadDirectory: downloadDirectory)
        } catch {
            fail("\(error)")
            return
        }
        let picker = PiecePicker(pieceCount: mi.pieceCount, pieceLength: mi.pieceLength,
                                 totalLength: mi.totalLength, have: Bitfield(count: mi.pieceCount))
        picker.sequential = sequential
        self.picker = picker
        setupLayerFetches()
        applyFileSelection()

        // Fast resume: trust the saved bitfield if file sizes and mtimes still match.
        if let r = resume, let raw = r.bitfield, let bf = Bitfield(wire: raw, count: mi.pieceCount),
           let storage, Self.stampsMatch(r.stamps, storage.fileStamps()) {
            picker.setHave(bf)
            becomeReady()
            return
        }
        if storage?.anyFileExists() == true {
            state = .checking
            let st = storage!
            let lp = loop
            let t = self
            DispatchQueue.global(qos: .userInitiated).async {
                let bf = st.recheck { n in lp.execute { t.checkingProgress = n } }
                lp.execute {
                    guard t.state == .checking else { return }
                    t.picker?.setHave(bf)
                    t.becomeReady()
                }
            }
        } else {
            becomeReady()
        }
    }

    /// Download only these file indices (indices among non-padding files, as `astor info` prints).
    public func selectFiles(_ indices: Set<Int>) {
        selectedFiles = indices
        applyFileSelection()
    }

    static func stampsMatch(_ a: [(Int64, Int64)], _ b: [(Int64, Int64)]) -> Bool {
        guard a.count == b.count else { return false }
        for i in 0..<a.count where a[i].0 != b[i].0 || a[i].1 != b[i].1 { return false }
        return true
    }

    private func applyFileSelection() {
        guard let mi = metainfo, let picker else { return }
        var pri = [UInt8](repeating: 0, count: mi.pieceCount)
        var wanted = [Bool](repeating: false, count: mi.files.count)
        var realIndex = 0
        for (fi, f) in mi.files.enumerated() {
            if f.isPadding { continue }
            defer { realIndex += 1 }
            let layerMissing = f.piecesRoot.map { layerFetches[$0] != nil } ?? false
            let want = (selectedFiles?.contains(realIndex) ?? true)
            wanted[fi] = want
            if layerMissing { continue }   // can't verify yet: download after the layer arrives
            guard want, f.length > 0 else { continue }
            let first = Int(f.offset / Int64(mi.pieceLength))
            let last = Int((f.endOffset - 1) / Int64(mi.pieceLength))
            for i in first...last { pri[i] = 1 }
        }
        picker.setPriorities(pri)
        storage?.setWanted(wanted)
    }

    private func becomeReady() {
        guard let picker else { return }
        if picker.isFinished && layerFetches.isEmpty {
            state = .seeding
            completedAt = monotonicNow()
        } else {
            state = .downloading
        }
        // Process bitfields that arrived before we had metadata.
        for (_, p) in peers {
            if p.peerHasAll { picker.peerAddedSeed() }
            else if let raw = p.pendingBitfield { applyBitfield(p, raw: raw) }
            for h in p.pendingHaves { peerHave(p, piece: h) }
            p.pendingBitfield = nil
            p.pendingHaves.removeAll()
            updateInterest(p)
        }
        if state == .seeding { trackers?.completed() }
        setupWebSeeds()
    }

    private func setupWebSeeds() {
        guard session.config.enableWebSeeds, webSeeds.isEmpty, let mi = metainfo else { return }
        let urls = Set(mi.webSeeds + (magnet?.webSeeds ?? [])).filter { $0.hasPrefix("http://") || $0.hasPrefix("https://") }
        webSeeds = urls.sorted().map { WebSeed(url: $0, torrent: self) }
    }

    private func fail(_ msg: String) {
        errorMessage = msg
        state = .error
        for (_, p) in peers { p.disconnect("torrent error") }
    }

    // MARK: Peers we learn about

    public func addPeer(_ addr: PeerAddress, source: PeerSource, flags: UInt8 = 0, from: ObjectIdentifier? = nil, v2: Bool = false) {
        guard addr.port != 0, !addr.ip.isUnusable, !banned.contains(addr.ip.banKey) else { return }
        if addr.ip.isV6 && !session.hasIPv6 { return }
        if session.isSelf(addr) { return }
        if var k = known[addr] {
            k.sources.insert(source)
            if flags & 0x02 != 0 { k.isSeed = true }
            if flags & 0x04 != 0 { k.supportsUTP = true }
            if flags & 0x08 != 0 { k.supportsHolepunch = true }
            if from != nil { k.pexFrom = from }
            known[addr] = k
            return
        }
        if known.count >= 4000 { pruneKnown() }
        var k = KnownPeer(address: addr, sources: [source])
        k.isSeed = flags & 0x02 != 0
        k.supportsUTP = flags & 0x04 != 0
        k.supportsHolepunch = flags & 0x08 != 0
        k.prefersEncryption = flags & 0x01 != 0
        k.pexFrom = from
        k.useV2Hash = v2
        known[addr] = k
    }

    private func pruneKnown() {
        let connectedAddrs = Set(peers.values.map { $0.address })
        let victims = known.values
            .filter { !connectedAddrs.contains($0.address) && !connecting.contains($0.address) }
            .sorted { $0.failures > $1.failures }
            .prefix(500)
        for v in victims { known.removeValue(forKey: v.address) }
    }

    /// Choose the next peer to connect to. Returns nil if none are eligible.
    func nextConnectCandidate(now: Double) -> KnownPeer? {
        guard state != .paused && state != .error && state != .checking else { return nil }
        guard peers.count + connecting.count < session.config.maxPeersPerTorrent else { return nil }
        if state == .seeding && peers.count >= session.config.maxPeersPerTorrent / 4 { return nil }
        var best: KnownPeer?
        var bestScore = Int.max
        let connectedAddrs = Set(peers.values.map { $0.address })
        for (_, k) in known {
            if k.nextAttempt > now || connecting.contains(k.address) || connectedAddrs.contains(k.address) { continue }
            if state == .seeding && k.isSeed { continue }
            // Lower is better: untried and previously-good peers first; seeds first when downloading.
            var score = k.failures * 100
            if k.connectedOnce { score -= 50 }
            if k.isSeed && state == .downloading { score -= 30 }
            if k.sources.contains(.pex) || k.sources.contains(.incoming) { score -= 10 }
            if k.sources.contains(.lsd) { score -= 60 }
            if score < bestScore { bestScore = score; best = k }
        }
        if var b = best {
            b.lastAttempt = now
            known[b.address] = b
            connecting.insert(b.address)
            return b
        }
        return nil
    }

    func connectFailed(_ addr: PeerAddress, error: String) {
        connecting.remove(addr)
        guard var k = known[addr] else { return }
        k.failures += 1
        let backoff = min(3600, 30 * pow(2, Double(min(k.failures, 7))))
        k.nextAttempt = monotonicNow() + backoff
        known[addr] = k
        if k.failures >= 8 && !k.connectedOnce && !k.sources.contains(.tracker) { known.removeValue(forKey: addr) }
        // BEP 55: ask the peer that told us about it to relay a holepunch.
        if session.config.enableHolepunch, session.config.enableUTP, k.supportsHolepunch, k.failures == 1,
           let relayID = k.pexFrom, let relay = peers[relayID], relay.supportsHolepunch {
            relay.sendExtended("ut_holepunch", Holepunch.encode(type: .rendezvous, addr: addr))
        }
    }

    // MARK: New connections

    /// A connection (outgoing or incoming) finished its handshake. Return false to reject.
    func peerHandshakeCompleted(_ p: PeerConnection) -> Bool {
        connecting.remove(p.address)
        handshaking.removeValue(forKey: ObjectIdentifier(p))
        if state == .paused || state == .error { p.disconnect("torrent not active"); return false }
        if banned.contains(p.address.ip.banKey) { p.disconnect("banned"); return false }
        if peers.values.contains(where: { $0 !== p && $0.remotePeerID == p.remotePeerID }) {
            p.disconnect("duplicate peer id"); return false
        }
        if peers.count >= session.config.maxPeersPerTorrent {
            p.disconnect("too many peers"); return false
        }
        peers[ObjectIdentifier(p)] = p
        let listenAddr = p.outgoing ? p.address : nil
        if let a = listenAddr {
            var k = known[a] ?? KnownPeer(address: a, sources: [p.source])
            k.connectedOnce = true
            k.failures = 0
            k.nextAttempt = 0
            known[a] = k
        }
        return true
    }

    func attach(stream: any ByteStream, outgoing: Bool, source: PeerSource, infoHash: Data,
                handshakeSent: Bool, remoteHandshake: Wire.Handshake?, initialData: Data) {
        let p = PeerConnection(torrent: self, stream: stream, outgoing: outgoing, source: source, infoHash: infoHash,
                               handshakeSent: handshakeSent, remoteHandshake: remoteHandshake, initialData: initialData)
        if !p.closed && peers[ObjectIdentifier(p)] == nil { handshaking[ObjectIdentifier(p)] = p }
    }

    func peerDisconnected(_ p: PeerConnection, reason: String) {
        let id = ObjectIdentifier(p)
        connecting.remove(p.address)
        guard peers.removeValue(forKey: id) != nil else {
            handshaking.removeValue(forKey: id)
            if p.outgoing { connectFailed(p.address, error: reason) }
            return
        }
        if let picker {
            for (r, _) in p.outstanding { picker.abort(r, peer: id) }
            if p.peerHasAll { picker.peerRemovedSeed() } else if let bf = p.peerHave { picker.peerRemoved(bf) }
        }
        p.outstanding.removeAll()
        if var mf = metadataFetch {
            mf.requested = mf.requested.filter { $0.value.0 != id }
            metadataFetch = mf
        }
        if optimisticPeer == id { optimisticPeer = nil }
        if p.outgoing, var k = known[p.address] {
            // Reconnect later; quickly if the connection was useful.
            let lived = monotonicNow() - p.connectedAt
            k.nextAttempt = monotonicNow() + (lived > 60 ? 30 : 120)
            known[p.address] = k
        }
        // Let other peers pick up the aborted blocks.
        for (_, other) in peers where !other.peerChoking { fillRequests(other) }
    }

    // MARK: Interest & requests

    func updateInterest(_ p: PeerConnection) {
        guard let picker else { return }
        let interesting = state == .downloading && picker.isInteresting(p.peerHave, peerIsSeed: p.isSeed)
        p.sendInterested(interesting)
    }

    func fillRequests(_ p: PeerConnection) {
        guard state == .downloading, let picker, !p.closed, p.amInterested else { return }
        let choked = p.peerChoking
        if choked && p.allowedFastIn.isEmpty { return }
        let target = p.requestQueueTarget(config: session.config)
        let need = target - p.outstanding.count
        guard need > 0 else { return }
        if session.downloadThrottled() { return }
        let blocks = picker.pick(peer: ObjectIdentifier(p), peerHave: p.peerHave, isSeed: p.isSeed, count: need,
                                 allowedOnly: choked ? p.allowedFastIn : nil, affinity: p.affinity)
        for b in blocks { p.sendRequest(b) }
    }

    func peerInterestChanged(_ p: PeerConnection) {
        // Unchoke immediately if we have a free slot — faster reciprocation than waiting 10 s.
        if p.peerInterested && p.amChoking && unchokedCount() < session.config.uploadSlotsPerTorrent {
            p.sendChoke(false)
        } else if !p.peerInterested && !p.amChoking && optimisticPeer != ObjectIdentifier(p) {
            p.sendChoke(true)
        }
    }

    private func unchokedCount() -> Int { peers.values.reduce(0) { $0 + ($1.amChoking ? 0 : 1) } }

    // MARK: Piece availability messages

    func peerHave(_ p: PeerConnection, piece: Int) {
        guard let picker else { p.pendingHaves.append(piece); return }
        guard piece >= 0 && piece < picker.pieceCount else { p.disconnect("have out of range"); return }
        if p.peerHave == nil { p.peerHave = Bitfield(count: picker.pieceCount) }
        if p.peerHasAll || p.peerHave![piece] { return }
        p.peerHave![piece] = true
        picker.peerHave(piece)
        if p.peerHave!.isComplete {
            // Became a seed: move its availability into the seed counter.
            picker.peerRemoved(p.peerHave!)
            picker.peerAddedSeed()
            p.peerHasAll = true
            if state == .seeding { p.disconnect("both seeding"); return }
        }
        if !p.amInterested && picker.isWanted(piece) { updateInterest(p); fillRequests(p) }
    }

    func peerBitfield(_ p: PeerConnection, raw: Data) {
        guard picker != nil else { p.pendingBitfield = raw; return }
        applyBitfield(p, raw: raw)
        updateInterest(p)
        fillRequests(p)
    }

    private func applyBitfield(_ p: PeerConnection, raw: Data) {
        guard let picker else { return }
        guard let bf = Bitfield(wire: raw, count: picker.pieceCount) else { p.disconnect("bad bitfield"); return }
        if let old = p.peerHave { picker.peerRemoved(old) }
        if bf.isComplete {
            p.peerHasAll = true
            p.peerHave = bf
            picker.peerAddedSeed()
            if state == .seeding { p.disconnect("both seeding") }
        } else {
            p.peerHave = bf
            picker.peerAdded(bf)
        }
    }

    func peerHaveAll(_ p: PeerConnection) {
        p.peerHasAll = true
        if let picker {
            p.peerHave = Bitfield(count: picker.pieceCount, allSet: true)
            picker.peerAddedSeed()
            if state == .seeding { p.disconnect("both seeding"); return }
            updateInterest(p)
            fillRequests(p)
        }
    }

    func peerHaveNone(_ p: PeerConnection) {
        if let picker { p.peerHave = Bitfield(count: picker.pieceCount) }
    }

    func peerDontHave(_ p: PeerConnection, piece: Int) {
        guard let picker, piece >= 0, piece < picker.pieceCount, p.peerHave?[piece] == true else { return }
        if p.peerHasAll {
            p.peerHasAll = false
            picker.peerRemovedSeed()
            picker.peerAdded(p.peerHave!)
        }
        p.peerHave![piece] = false
        picker.peerLost(piece)
    }

    // MARK: Data

    func blockReceived(_ p: PeerConnection, request r: BlockRequest, data: Data) {
        dataReceived(key: ObjectIdentifier(p), ip: p.address.ip, request: r, data: data)
        fillRequests(p)
    }

    /// Shared data path for peers and web seeds.
    func dataReceived(key: ObjectIdentifier, ip: IPAddress, request r: BlockRequest, data: Data) {
        guard let picker, let storage else { wasted += Int64(data.count); return }
        switch picker.blockReceived(r, from: key, ip: ip) {
        case .unexpected:
            wasted += Int64(data.count)
        case .accepted(let complete, let cancelAt):
            downloadedTotal += Int64(data.count)
            downMeter.add(data.count)
            session.downloadMeterAdd(data.count)
            for other in cancelAt { peers[other]?.sendCancel(r) }
            storage.write(piece: r.piece, offset: r.offset, data: data, loop: loop) { [weak self] err in
                self?.fail("disk write failed: \(err)")
            }
            if complete {
                let piece = r.piece
                let wantHashes = smartBan[piece] != nil
                storage.verify(piece: piece, loop: loop, blockHashes: wantHashes) { [weak self] ok, hashes in
                    self?.pieceChecked(piece, ok: ok, blockHashes: hashes)
                }
            }
        }
    }

    func blockUploaded(_ n: Int) {
        uploadedTotal += Int64(n)
        upMeter.add(n)
        session.uploadMeterAdd(n)
    }

    /// Smart-ban evidence: for pieces that failed, the block hashes and senders of the bad copy.
    var smartBan: [Int: [(block: Int, ip: IPAddress, hash: Data)]] = [:]

    private func ban(_ ip: IPAddress, reason: String) {
        let key = ip.banKey
        guard !banned.contains(key) else { return }
        banned.insert(key)
        session.log("banned \(ip)\(ip.isV6 ? " (/64)" : ""): \(reason)")
        for (_, p) in peers where p.address.ip.banKey == key { p.disconnect("banned: \(reason)") }
        for (_, p) in handshaking where p.address.ip.banKey == key { p.disconnect("banned: \(reason)") }
    }

    private func pieceChecked(_ piece: Int, ok: Bool, blockHashes: [Data]) {
        guard let picker, state == .downloading || state == .seeding else { return }
        if ok {
            // Smart-ban: compare the bad copy's blocks with the now-verified data.
            if let evidence = smartBan.removeValue(forKey: piece), blockHashes.count > 0 {
                for e in evidence where e.block < blockHashes.count && e.hash != blockHashes[e.block] {
                    ban(e.ip, reason: "sent corrupt block \(e.block) of piece \(piece)")
                }
            }
            picker.pieceVerified(piece)
            for (_, p) in peers where !(p.peerHasAll) {
                p.sendHave(piece)
            }
            if picker.isFinished && layerFetches.isEmpty { completed() }
        } else {
            hashFailures += 1
            wasted += Int64(picker.pieceSize(piece))
            let failedSenders = picker.senders(of: piece)
            if !blockHashes.isEmpty, smartBan.count < 256 {
                smartBan[piece] = failedSenders.compactMap { b, ip in
                    b < blockHashes.count ? (block: b, ip: ip, hash: blockHashes[b]) : nil
                }
            }
            let contributors = picker.pieceFailed(piece).contributors
            let who = contributors.map { ip in
                let c = peers.values.first { $0.address.ip == ip }
                return "\(ip) [\(c?.clientName ?? c.map { Self.clientFromPeerID($0.remotePeerID) } ?? "gone")\(c.map { $0.transport == .utp ? ",utp" : "" } ?? "")\(c.map { $0.isEncrypted ? ",enc" : "" } ?? "")]"
            }
            session.log("hash fail piece \(piece) from \(who.joined(separator: ", "))")
            for ip in contributors {
                let n = (hashFailuresByIP[ip] ?? 0) + (contributors.count == 1 ? 3 : 1)
                hashFailuresByIP[ip] = n
                if n >= 6 { ban(ip, reason: "repeated hash failures") }
            }
        }
    }

    private func completed() {
        guard state != .seeding else { return }
        state = .seeding
        completedAt = monotonicNow()
        trackers?.completed()
        storage?.sync { }
        saveResume()
        for (_, p) in peers {
            p.sendInterested(false)
            if p.isSeed || p.uploadOnly { p.disconnect("download complete; peer is a seed") }
        }
        onComplete?()
    }

    // MARK: Extension protocol

    func peerExtensionHandshake(_ p: PeerConnection) {
        if p.outgoing == false, let port = p.remoteListenPort {
            addPeer(PeerAddress(ip: p.address.ip, port: port), source: .incoming)
        }
        if p.uploadOnly && state == .seeding { p.disconnect("both upload-only"); return }
        if metainfo == nil, let size = p.metadataSize, p.remoteExt["ut_metadata"] != nil {
            if metadataFetch == nil || metadataFetch!.size != size {
                let n = (size + 16383) / 16384
                metadataFetch = MetadataFetch(size: size, pieces: [Data?](repeating: nil, count: n))
            }
            requestMetadata(from: p)
        }
    }

    private func requestMetadata(from p: PeerConnection) {
        guard var mf = metadataFetch, metainfo == nil, p.metadataSize == mf.size, !mf.badPeers.contains(ObjectIdentifier(p)) else { return }
        let now = monotonicNow()
        var sent = 0
        for i in 0..<mf.pieces.count where mf.pieces[i] == nil && sent < 4 {
            if let (_, t) = mf.requested[i], now - t < 8 { continue }
            mf.requested[i] = (ObjectIdentifier(p), now)
            let req = BValue.dict(["msg_type": .int(0), "piece": .int(Int64(i))]).encoded
            p.sendExtended("ut_metadata", req)
            sent += 1
        }
        metadataFetch = mf
    }

    func metadataMessage(_ p: PeerConnection, payload: Data) {
        guard let (msg, consumed) = try? BDecoder.decodePrefix(payload), let type = msg["msg_type"]?.int,
              let piece = msg["piece"]?.int, piece >= 0 else { return }
        switch type {
        case 0: // request
            guard let mi = metainfo, !isPrivate else {
                p.sendExtended("ut_metadata", BValue.dict(["msg_type": .int(2), "piece": .int(piece)]).encoded)
                return
            }
            let start = Int(piece) * 16384
            guard start < mi.infoDict.count else { return }
            let end = min(mi.infoDict.count, start + 16384)
            var out = BValue.dict(["msg_type": .int(1), "piece": .int(piece), "total_size": .int(Int64(mi.infoDict.count))]).encoded
            out.append(mi.infoDict.subdata(in: start..<end))
            p.sendExtended("ut_metadata", out)
        case 1: // data
            guard var mf = metadataFetch, Int(piece) < mf.pieces.count else { return }
            let chunk = payload.subdata(in: (payload.startIndex + consumed)..<payload.endIndex)
            let expected = Int(piece) == mf.pieces.count - 1 ? mf.size - Int(piece) * 16384 : 16384
            guard chunk.count == expected else { return }
            mf.pieces[Int(piece)] = chunk
            mf.requested[Int(piece)] = nil
            metadataFetch = mf
            if mf.pieces.allSatisfy({ $0 != nil }) {
                let info = mf.pieces.reduce(into: Data()) { $0.append($1!) }
                metadataComplete(info)
            } else {
                requestMetadata(from: p)
            }
        case 2: // reject
            if var mf = metadataFetch {
                mf.requested[Int(piece)] = nil
                mf.badPeers.insert(ObjectIdentifier(p))
                metadataFetch = mf
            }
        default: break
        }
    }

    private func metadataComplete(_ info: Data) {
        let v1ok = infoHashes.v1.map { Hash.sha1(info) == $0 } ?? true
        let v2ok = infoHashes.v2.map { Hash.sha256(info) == $0 } ?? true
        guard v1ok && v2ok, var mi = try? Metainfo(infoDict: info) else {
            // Corrupt: start over.
            if let s = metadataFetch?.size { metadataFetch = MetadataFetch(size: s, pieces: [Data?](repeating: nil, count: (s + 16383) / 16384)) }
            return
        }
        mi.announceTiers = magnet?.trackers.map { [$0] } ?? []
        mi.webSeeds = magnet?.webSeeds ?? []
        metainfo = mi
        displayName = mi.name
        metadataFetch = nil
        if mi.isPrivate {
            // BEP 27: private torrents must only use their trackers (magnet trackers here).
            for (_, p) in peers where p.source != .tracker { p.disconnect("private torrent") }
        }
        startTrackers()
        initializeStorage(resume: nil)
        saveResume()
    }

    // MARK: PEX (BEP 11)

    func pexMessage(_ p: PeerConnection, payload: Data) {
        guard session.config.enablePEX, !isPrivate, let d = try? BDecoder.decodePrefix(payload).0 else { return }
        let from = ObjectIdentifier(p)
        func ingest(_ key: String, _ fkey: String, v6: Bool) {
            guard let raw = d[key]?.data else { return }
            let flags = d[fkey]?.data.map { [UInt8]($0) } ?? []
            let addrs = PeerAddress.parseCompactList(raw, v6: v6)
            for (i, a) in addrs.prefix(200).enumerated() {
                addPeer(a, source: .pex, flags: i < flags.count ? flags[i] : 0, from: from)
            }
        }
        ingest("added", "added.f", v6: false)
        ingest("added6", "added6.f", v6: true)
    }

    private func sendPEX(now: Double) {
        guard session.config.enablePEX, !isPrivate else { return }
        // Peers we can vouch for: listen endpoints of current connections.
        var current: [PeerAddress: UInt8] = [:]
        for (_, q) in peers {
            guard q.outgoing || q.remoteListenPort != nil else { continue }
            let ep = q.listenEndpoint
            var f: UInt8 = 0
            if q.isEncrypted { f |= 0x01 }
            if q.isSeed || q.uploadOnly { f |= 0x02 }
            if q.transport == .utp { f |= 0x04 }
            if q.supportsHolepunch { f |= 0x08 }
            if q.outgoing { f |= 0x10 }
            current[ep] = f
        }
        for (_, p) in peers where p.supportsPex && now - p.lastPexAt >= 60 {
            p.lastPexAt = now
            let added = current.keys.filter { !p.pexSent.contains($0) && $0 != p.address }.prefix(50)
            let dropped = p.pexSent.filter { current[$0] == nil }.prefix(50)
            if added.isEmpty && dropped.isEmpty { continue }
            var a4 = Data(), f4 = Data(), a6 = Data(), f6 = Data(), d4 = Data(), d6 = Data()
            for a in added {
                if a.ip.isV4 { a4.append(contentsOf: a.compact); f4.append(current[a]!) }
                else { a6.append(contentsOf: a.compact); f6.append(current[a]!) }
                p.pexSent.insert(a)
            }
            for a in dropped {
                if a.ip.isV4 { d4.append(contentsOf: a.compact) } else { d6.append(contentsOf: a.compact) }
                p.pexSent.remove(a)
            }
            let msg = BValue.dict([
                "added": .bytes(a4), "added.f": .bytes(f4), "added6": .bytes(a6), "added6.f": .bytes(f6),
                "dropped": .bytes(d4), "dropped6": .bytes(d6),
            ]).encoded
            p.sendExtended("ut_pex", msg)
        }
    }

    // MARK: BEP 52 hash requests

    /// Piece layers being fetched from peers (v2-only torrents from magnet links).
    struct LayerFetch {
        let root: Data
        let pieces: Int        // real piece count of the file
        let chunk: Int         // hashes per request (power of two)
        let height: Int        // log2(padded layer width)
        var got: [Int: [Data]] = [:]
        var asked: [Int: Double] = [:]
        var chunks: Int { (Merkle.nextPow2(pieces) + chunk - 1) / chunk }
    }
    var layerFetches: [Data: LayerFetch] = [:]

    /// v2-only torrent without piece layers: hold those files back and fetch layers from peers.
    func setupLayerFetches() {
        guard let mi = metainfo, mi.v1Pieces.isEmpty else { return }
        for f in mi.files where !f.isPadding && f.length > Int64(mi.pieceLength) {
            guard let root = f.piecesRoot, mi.pieceLayer(for: f) == nil, layerFetches[root] == nil else { continue }
            let n = Int((f.length + Int64(mi.pieceLength) - 1) / Int64(mi.pieceLength))
            let width = Merkle.nextPow2(n)
            layerFetches[root] = LayerFetch(root: root, pieces: n, chunk: min(512, width), height: Merkle.log2(width))
        }
        if !layerFetches.isEmpty { applyFileSelection() }
    }

    private func requestLayers(now: Double) {
        guard let mi = metainfo, !layerFetches.isEmpty else { return }
        let base = Merkle.log2(mi.pieceLength / Merkle.blockSize)
        let v2peers = peers.values.filter { $0.supportsV2 && !$0.closed }
        guard !v2peers.isEmpty else { return }
        for (root, var lf) in layerFetches {
            for c in 0..<lf.chunks where lf.got[c] == nil && now - (lf.asked[c] ?? 0) > 10 {
                guard let p = v2peers.randomElement() else { break }
                lf.asked[c] = now
                let proof = lf.chunk >= (1 << lf.height) ? 0 : lf.height - 1
                p.sendHashRequest(root: root, base: base, index: c * lf.chunk, length: lf.chunk, proof: proof)
            }
            layerFetches[root] = lf
        }
    }

    /// Verify a 'hashes' reply against the pieces root (subtree root + uncle chain).
    func hashesReceived(root: Data, base: Int, index: Int, length: Int, proof: Int, hashes: Data) {
        guard let mi = metainfo, var lf = layerFetches[root], base == Merkle.log2(mi.pieceLength / Merkle.blockSize),
              length == lf.chunk, index % length == 0, hashes.count % 32 == 0, hashes.count >= length * 32 else { return }
        let all = stride(from: 0, to: hashes.count, by: 32).map { hashes.subdata(in: (hashes.startIndex + $0)..<(hashes.startIndex + $0 + 32)) }
        var level = Array(all[0..<length])
        while level.count > 1 { level = stride(from: 0, to: level.count, by: 2).map { Hash.sha256Pair(level[$0], level[$0 + 1]) } }
        var node = level[0], idx = index / length, height = Merkle.log2(length)
        for u in all[length...] where height < lf.height {
            node = idx & 1 == 0 ? Hash.sha256Pair(node, u) : Hash.sha256Pair(u, node)
            idx >>= 1
            height += 1
        }
        guard height == lf.height, node == root else { return }   // forged or incomplete proof
        lf.got[index / length] = Array(all[0..<length])
        layerFetches[root] = lf
        guard lf.got.count == lf.chunks else { return }
        let layer = Array((0..<lf.chunks).flatMap { lf.got[$0]! }.prefix(lf.pieces))
        storage?.addPieceLayer(root: root, hashes: layer)
        metainfo?.pieceLayers[root] = layer.reduce(into: Data()) { $0.append($1) }
        layerFetches.removeValue(forKey: root)
        applyFileSelection()
        for (_, p) in peers { updateInterest(p); fillRequests(p) }
        session.log("v2 piece layer fetched for \(root.prefix(6).hex)… (\(lf.pieces) pieces)")
    }

    /// Cached Merkle trees (piece layer upwards) per pieces root.
    private var merkleCache: [Data: [[Data]]] = [:]

    /// Answer a hash request from the piece layer we hold (from the .torrent's "piece layers").
    /// Returns nil to reject (unknown root, unsupported layer, malformed range).
    func hashRequest(root: Data, base: Int, index: Int, length: Int, proof: Int) -> Data? {
        guard let mi = metainfo, length >= 2, length <= 8192, length & (length - 1) == 0,
              index >= 0, index % length == 0, proof >= 0, proof < 64 else { return nil }
        let pieceBase = Merkle.log2(mi.pieceLength / Merkle.blockSize)
        guard base == pieceBase,
              let file = mi.files.first(where: { $0.piecesRoot == root && $0.length > Int64(mi.pieceLength) }),
              let layer = mi.pieceLayer(for: file) else { return nil }
        let levels: [[Data]]
        if let c = merkleCache[root] { levels = c } else {
            guard let built = Merkle.levels(pieceLayer: layer, pieceLength: mi.pieceLength), built.last?.first == root else { return nil }
            merkleCache[root] = built
            levels = built
        }
        return Merkle.hashResponse(levels: levels, index: index, length: length, proof: proof)
    }

    // MARK: Holepunch (BEP 55)

    func holepunchMessage(_ p: PeerConnection, payload: Data) {
        guard session.config.enableHolepunch, let m = Holepunch.decode(payload) else { return }
        switch m.type {
        case .rendezvous:
            // We are the relay: introduce p and the target to each other.
            guard let target = peers.values.first(where: { $0.listenEndpoint == m.addr }) else {
                p.sendExtended("ut_holepunch", Holepunch.encode(type: .error, addr: m.addr, error: 2)); return
            }
            guard target.supportsHolepunch else {
                p.sendExtended("ut_holepunch", Holepunch.encode(type: .error, addr: m.addr, error: 3)); return
            }
            target.sendExtended("ut_holepunch", Holepunch.encode(type: .connect, addr: p.listenEndpoint))
            p.sendExtended("ut_holepunch", Holepunch.encode(type: .connect, addr: m.addr))
        case .connect:
            // Simultaneous uTP open towards the peer we were introduced to.
            addPeer(m.addr, source: .holepunch)
            session.holepunchConnect(self, to: m.addr)
        case .error:
            break
        }
    }

    // MARK: DHT / LSD

    func announceDHT(force: Bool = false) {
        guard session.config.enableDHT, !isPrivate else { return }
        let now = monotonicNow()
        let interval: Double = peers.count < 20 ? 300 : 900
        guard force || now - lastDHTAnnounce > interval else { return }
        lastDHTAnnounce = now
        for (idx, h) in infoHashes.all20.enumerated() {
            let isV2 = infoHashes.v1 != nil ? idx == 1 : true
            session.dhtGetPeers(infoHash: h) { [weak self] addrs in
                guard let self else { return }
                for a in addrs { self.addPeer(a, source: .dht, v2: isV2 && self.infoHashes.v1 == nil) }
            }
        }
    }

    func announceLSD() {
        guard session.config.enableLSD, !isPrivate else { return }
        let now = monotonicNow()
        guard now - lastLSDAnnounce > 300 else { return }
        lastLSDAnnounce = now
        session.lsdAnnounce(infoHashes.all20)
    }

    // MARK: Periodic work

    func tick(now: Double) {
        tickCount += 1
        downMeter.tick()
        upMeter.tick()
        for (_, p) in peers { p.tick(now: now) }
        for (_, p) in handshaking { p.tick(now: now) }

        if state == .downloading {
            // Snub detection / request timeouts: hand blocks to other peers.
            for (_, p) in peers where !p.outstanding.isEmpty && now - p.lastPieceAt > 20 {
                p.snubbed = true
                p.requestTimeouts += 1
                for (r, _) in p.outstanding { picker?.abort(r, peer: ObjectIdentifier(p)) }
                for (r, _) in p.outstanding { p.sendCancel(r) }
                p.outstanding.removeAll()
                if p.requestTimeouts > 3 && peers.count > 30 { p.disconnect("snubbed repeatedly") }
            }
            if tickCount % 5 == 0 { for (_, p) in peers { updateInterest(p) } }
            for (_, p) in peers where !p.closed { fillRequests(p) }
            for ws in webSeeds { ws.tick(); ws.pump() }
        }
        if !layerFetches.isEmpty && tickCount % 2 == 0 { requestLayers(now: now) }
        if state == .fetchingMetadata, tickCount % 2 == 0 {
            for (_, p) in peers where p.metadataSize != nil { requestMetadata(from: p) }
        }
        if tickCount % 10 == 0 { runChoker(now: now) }
        if tickCount % 5 == 0 { sendPEX(now: now) }
        // A cold DHT (fresh state, empty routing table) returns almost nothing for the
        // lookup fired at start: repeat it once the table has bootstrapped.
        if [8, 20, 45, 90].contains(tickCount), session.dhtNodeCount > 0, (known.values.filter { $0.sources.contains(.dht) }.count) < 50 {
            announceDHT(force: true)
        }
        if tickCount % 30 == 0 {
            announceDHT()
            announceLSD()
            dropUselessPeers(now: now)
        }
        if now - lastResumeSave > 60 { saveResume() }
    }

    /// Tit-for-tat choker with optimistic unchoke (BEP 3 semantics).
    private func runChoker(now: Double) {
        let slots = session.config.uploadSlotsPerTorrent
        let interested = peers.values.filter { $0.peerInterested && !$0.closed }
        let ranked: [PeerConnection]
        if state == .seeding {
            // Seeding: favour peers we upload fastest to, rotating out long-unchoked ones.
            ranked = interested.sorted { $0.uploadRate > $1.uploadRate }
        } else {
            // Downloading: reciprocate peers that give us the most.
            ranked = interested.sorted { $0.downloadRate > $1.downloadRate }
        }
        var unchoke = Set(ranked.prefix(max(1, slots - 1)).map { ObjectIdentifier($0) })
        // Optimistic unchoke every 30 s: favour newly connected peers.
        if tickCount % 30 == 0 || optimisticPeer == nil || peers[optimisticPeer!] == nil {
            let candidates = interested.filter { !unchoke.contains(ObjectIdentifier($0)) }
            let fresh = candidates.filter { now - $0.connectedAt < 60 }
            optimisticPeer = (fresh.randomElement() ?? candidates.randomElement()).map { ObjectIdentifier($0) }
        }
        if let o = optimisticPeer { unchoke.insert(o) }
        for (id, p) in peers {
            p.sendChoke(!unchoke.contains(id))
        }
    }

    private func dropUselessPeers(now: Double) {
        let limit = session.config.maxPeersPerTorrent
        guard peers.count > limit * 3 / 4 else { return }
        // Drop peers that are neither interesting nor interested for > 2 minutes.
        let useless = peers.values.filter {
            !$0.amInterested && !$0.peerInterested && now - $0.connectedAt > 120
        }.prefix(10)
        for p in useless { p.disconnect("idle") }
    }

    // MARK: Resume

    func saveResume() {
        lastResumeSave = monotonicNow()
        guard metainfo != nil || magnet != nil else { return }
        let r = ResumeData(
            infoDict: metainfo?.infoDict,
            bitfield: picker?.have.data,
            savePath: downloadDirectory.path,
            uploaded: uploadedTotal,
            downloaded: downloadedTotal,
            stamps: storage?.fileStamps() ?? [],
            peers: Array(known.values.filter { $0.connectedOnce }.prefix(200).map { $0.address }),
            trackers: trackerTiers(),
            sequential: sequential)
        session.saveResume(r, for: infoHashes)
    }

    // MARK: Status

    public func status() -> TorrentStatus {
        let mi = metainfo
        var wanted: Int64 = 0, done: Int64 = 0
        if let mi, let picker {
            for i in 0..<mi.pieceCount where picker.priority[i] > 0 {
                let s = Int64(mi.pieceSize(i))
                wanted += s
                if picker.have[i] { done += s }
            }
            done += min(picker.partialBytes, max(0, wanted - done))
        }
        var bySource: [PeerSource: Int] = [:]
        for k in known.values { for s in k.sources { bySource[s, default: 0] += 1 } }
        let ps = Array(peers.values)
        let rate = downMeter.bytesPerSecond
        let progress = state == .checking
            ? Double(checkingProgress) / Double(max(1, mi?.pieceCount ?? 1))
            : (wanted > 0 ? Double(done) / Double(wanted) : 0)
        let top = peerSummaries(limit: 12)
        return TorrentStatus(
            name: displayName, infoHash: infoHashes.description, state: state, version: mi?.version,
            progress: progress, wantedBytes: wanted, completedBytes: done,
            downloadRate: rate, uploadRate: upMeter.bytesPerSecond,
            downloadedTotal: downloadedTotal, uploadedTotal: uploadedTotal, wastedBytes: wasted,
            hashFailures: hashFailures,
            connectedPeers: ps.count, connectedSeeds: ps.filter { $0.isSeed }.count,
            connectingPeers: connecting.count, knownPeers: known.count, knownBySource: bySource,
            encryptedPeers: ps.filter { $0.isEncrypted }.count, utpPeers: ps.filter { $0.transport == .utp }.count,
            incomingPeers: ps.filter { !$0.outgoing }.count,
            unchokedUs: ps.filter { !$0.peerChoking }.count,
            trackerSeeders: trackers?.bestSeeders, trackerLeechers: trackers?.bestLeechers,
            trackers: trackers?.statuses ?? [],
            pieceCount: mi?.pieceCount ?? 0, pieceLength: mi?.pieceLength ?? 0,
            piecesHave: picker?.have.setCount ?? 0, distributedCopies: picker?.distributedCopies ?? 0,
            eta: rate > 1024 && wanted > done ? Double(wanted - done) / rate : nil,
            error: errorMessage, topPeers: top, savePath: downloadDirectory.path,
            webSeeds: webSeeds.count, webSeedRate: webSeeds.reduce(0) { $0 + $1.downloadRate })
    }

    func peerSummaries(limit: Int) -> [PeerSummary] {
        let mi = metainfo
        return peers.values.sorted { $0.downloadRate > $1.downloadRate }.prefix(limit).map { p -> PeerSummary in
            var f = ""
            f += p.outgoing ? "O" : "I"
            f += p.transport == .utp ? "U" : "T"
            if p.isEncrypted { f += "E" }
            if !p.peerChoking { f += "D" } else if p.amInterested { f += "d" }
            if !p.amChoking { f += "u" }
            if p.snubbed { f += "S" }
            let prog = p.isSeed ? 1.0 : Double(p.peerHave?.setCount ?? 0) / Double(max(1, mi?.pieceCount ?? 1))
            return PeerSummary(address: p.address.description, client: p.clientName ?? Self.clientFromPeerID(p.remotePeerID),
                               downloadRate: p.downloadRate, uploadRate: p.uploadRate, flags: f, progress: prog)
        }
    }

    /// Decode Azureus-style peer ids ("-qB4650-" → "qBittorrent 4.6.5").
    static func clientFromPeerID(_ id: Data) -> String {
        guard id.count >= 8, id.byte(0) == UInt8(ascii: "-"), id.byte(7) == UInt8(ascii: "-") else { return "?" }
        let code = String(decoding: id[(id.startIndex + 1)..<(id.startIndex + 3)], as: UTF8.self)
        let ver = String(decoding: id[(id.startIndex + 3)..<(id.startIndex + 7)], as: UTF8.self)
        let names = ["qB": "qBittorrent", "TR": "Transmission", "UT": "µTorrent", "LT": "libtorrent", "DE": "Deluge",
                     "AZ": "Vuze", "BT": "BitTorrent", "lt": "rTorrent", "BI": "BiglyBT", "AS": "Astor", "TX": "Tixati",
                     "FD": "Free Download Manager", "XL": "Xunlei", "SD": "Thunder", "BC": "BitComet", "WW": "WebTorrent",
                     "AG": "Ares", "PI": "PicoTorrent", "FW": "FrostWire", "KT": "KTorrent", "BW": "BitWombat"]
        return "\(names[code] ?? code) \(ver)"
    }
}

/// BEP 55 holepunch message codec.
enum Holepunch {
    enum MsgType: UInt8 { case rendezvous = 0, connect = 1, error = 2 }
    struct Message { var type: MsgType; var addr: PeerAddress; var error: UInt32 }

    static func encode(type: MsgType, addr: PeerAddress, error: UInt32 = 0) -> Data {
        var d = Data([type.rawValue, addr.ip.isV4 ? 0 : 1])
        d.append(contentsOf: addr.ip.bytes)
        d.appendBE16(addr.port)
        if type == .error { d.appendBE32(error) }
        return d
    }

    static func decode(_ d: Data) -> Message? {
        guard d.count >= 2, let t = MsgType(rawValue: d.byte(0)) else { return nil }
        let alen = d.byte(1) == 0 ? 4 : (d.byte(1) == 1 ? 16 : 0)
        guard alen > 0, d.count >= 2 + alen + 2 else { return nil }
        let s = d.startIndex
        guard let ip = IPAddress(bytes: d[(s + 2)..<(s + 2 + alen)]) else { return nil }
        let port = d.be16(2 + alen)
        let err = d.count >= 2 + alen + 6 ? d.be32(2 + alen + 2) : 0
        return Message(type: t, addr: PeerAddress(ip: ip, port: port), error: err)
    }
}
