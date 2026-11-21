import Foundation

/// Our local extension message ids (BEP 10 "m" dictionary).
enum LocalExt {
    static let utMetadata: UInt8 = 1
    static let utPex: UInt8 = 2
    static let uploadOnly: UInt8 = 3
    static let ltDonthave: UInt8 = 4
    static let utHolepunch: UInt8 = 5

    static let names: [(String, UInt8)] = [
        ("ut_metadata", utMetadata), ("ut_pex", utPex), ("upload_only", uploadOnly),
        ("lt_donthave", ltDonthave), ("ut_holepunch", utHolepunch),
    ]
}

/// One BitTorrent peer connection (after transport + optional MSE are established).
/// Loop-confined.
public final class PeerConnection: @unchecked Sendable {
    weak var torrent: Torrent?
    let stream: any ByteStream
    let loop: EventLoop
    public let address: PeerAddress
    public let outgoing: Bool
    public let source: PeerSource
    /// The 20-byte info hash this connection uses (v1 or truncated v2).
    let infoHash: Data

    // Handshake
    private(set) var handshakeDone = false
    private var handshakeSent: Bool
    private(set) var remoteReserved = Wire.Reserved(bytes: [UInt8](repeating: 0, count: 8))
    public private(set) var remotePeerID = Data()
    private var parser = MessageParser()

    // Choke/interest state
    var amChoking = true
    var amInterested = false
    var peerChoking = true
    var peerInterested = false

    // What the peer has
    var peerHave: Bitfield?
    var pendingBitfield: Data?          // received before we knew the piece count
    var peerHasAll = false              // HAVE ALL or complete bitfield
    var pendingHaves: [Int] = []
    var isSeed: Bool { peerHasAll || (peerHave?.isComplete ?? false) }
    var uploadOnly = false

    // Requests we sent: block -> time sent
    var outstanding: [BlockRequest: Double] = [:]
    /// Pieces we have been downloading from this peer (affinity).
    var affinity: [Int] = []
    var allowedFastIn: Set<Int> = []    // pieces we may request while choked
    var allowedFastOut: Set<Int> = []   // pieces we allow the peer while choked
    var snubbed = false
    var lastPieceAt = monotonicNow()
    var requestTimeouts = 0

    // Upload side
    var uploadQueue: [BlockRequest] = []
    private var uploadReadsInFlight = 0

    // Extensions
    var supportsExtensions: Bool { remoteReserved.supportsExtensions }
    var supportsFast: Bool { remoteReserved.supportsFast }
    var supportsDHT: Bool { remoteReserved.supportsDHT }
    var supportsV2: Bool { remoteReserved.supportsV2 }
    var remoteExt: [String: UInt8] = [:]
    var metadataSize: Int?
    var remoteListenPort: UInt16?
    public private(set) var clientName: String?
    var remoteReqq = 250
    var supportsHolepunch: Bool { remoteExt["ut_holepunch"] != nil }
    var supportsPex: Bool { remoteExt["ut_pex"] != nil }
    var pexSent: Set<PeerAddress> = []
    var lastPexAt = 0.0

    // Stats
    var downMeter = RateMeter()
    var upMeter = RateMeter()
    let connectedAt = monotonicNow()
    var lastReceiveAt = monotonicNow()
    var lastSendAt = monotonicNow()
    var optimisticUnchokedAt: Double = 0
    var lastUnchokedAt: Double = 0

    // Outgoing write batching ("cork"): coalesce messages generated in one loop turn.
    private var outbox = Data()
    private var flushScheduled = false
    private(set) var closed = false

    public var transport: TransportKind { stream.transport }
    public var isEncrypted: Bool { stream.isEncrypted }
    public var downloadRate: Double { downMeter.bytesPerSecond }
    public var uploadRate: Double { upMeter.bytesPerSecond }

    init(torrent: Torrent, stream: any ByteStream, outgoing: Bool, source: PeerSource,
         infoHash: Data, handshakeSent: Bool, remoteHandshake: Wire.Handshake?, initialData: Data) {
        self.torrent = torrent
        self.stream = stream
        self.loop = torrent.loop
        self.address = stream.remoteAddress
        self.outgoing = outgoing
        self.source = source
        self.infoHash = infoHash
        self.handshakeSent = handshakeSent
        if let hs = remoteHandshake {
            remoteReserved = hs.reserved
            remotePeerID = hs.peerID
        }
        stream.onRead = { [weak self] d in self?.received(d) }
        stream.onClose = { [weak self] err in self?.streamClosed(err) }
        stream.onWritable = { [weak self] in self?.pumpUploads() }
        if !handshakeSent { sendHandshake() }
        if remoteHandshake != nil {
            handshakeDone = true
            loop.execute { [weak self] in self?.afterHandshake() }
        }
        if !initialData.isEmpty { received(initialData) }
    }

    /// The address other peers can reach this peer at (its listen port for incoming peers).
    var listenEndpoint: PeerAddress {
        if outgoing { return address }
        if let p = remoteListenPort { return PeerAddress(ip: address.ip, port: p) }
        return address
    }

    var description: String { "\(address)(\(transport.rawValue)\(isEncrypted ? ",enc" : ""))" }

    // MARK: Sending

    private func send(_ d: Data) {
        guard !closed else { return }
        outbox.append(d)
        if !flushScheduled {
            flushScheduled = true
            loop.execute { [weak self] in self?.flush() }
        }
    }

    private func flush() {
        flushScheduled = false
        guard !closed, !outbox.isEmpty else { return }
        lastSendAt = monotonicNow()
        let d = outbox
        outbox = Data()
        stream.write(d)
    }

    private func sendHandshake() {
        guard let t = torrent else { return }
        let hs = Wire.Handshake(reserved: .ours(v2: t.infoHashes.v2 != nil), infoHash: infoHash, peerID: t.session.peerID)
        send(hs.encoded)
        handshakeSent = true
    }

    func sendChoke(_ choke: Bool) {
        guard choke != amChoking else { return }
        amChoking = choke
        send(Wire.simple(choke ? .choke : .unchoke))
        if choke {
            // BEP 6: explicitly reject queued requests; otherwise they're implicitly dropped.
            if supportsFast {
                for r in uploadQueue where !allowedFastOut.contains(r.piece) { send(Wire.reject(r)) }
            }
            uploadQueue.removeAll { !allowedFastOut.contains($0.piece) }
        } else {
            lastUnchokedAt = monotonicNow()
        }
    }

    func sendInterested(_ interested: Bool) {
        guard interested != amInterested else { return }
        amInterested = interested
        send(Wire.simple(interested ? .interested : .notInterested))
    }

    func sendHave(_ piece: Int) { send(Wire.have(piece)) }

    func sendRequest(_ r: BlockRequest) {
        outstanding[r] = monotonicNow()
        if affinity.last != r.piece {
            affinity.removeAll { $0 == r.piece }
            affinity.append(r.piece)
            if affinity.count > 8 { affinity.removeFirst() }
        }
        send(Wire.request(r))
    }

    func sendCancel(_ r: BlockRequest) {
        if outstanding.removeValue(forKey: r) != nil { send(Wire.cancel(r)) }
    }

    func sendKeepAlive() { send(Wire.keepAlive) }

    func sendExtended(_ name: String, _ payload: Data) {
        guard let id = remoteExt[name], id != 0 else { return }
        send(Wire.extended(id, payload))
    }

    func sendPort(_ p: UInt16) { send(Wire.port(p)) }

    func sendHashRequest(root: Data, base: Int, index: Int, length: Int, proof: Int) {
        send(Wire.hashMessage(.hashRequest, root: root, baseLayer: base, index: index, length: length, proofLayers: proof))
    }

    // MARK: Receiving

    private func received(_ d: Data) {
        guard !closed else { return }
        lastReceiveAt = monotonicNow()
        parser.append(d)
        if !handshakeDone {
            guard parser.buffered >= Wire.handshakeLength else { return }
            let raw = parser.take(Wire.handshakeLength)!
            guard let hs = Wire.Handshake.parse(raw) else { disconnect("bad handshake"); return }
            guard hs.infoHash == infoHash else { disconnect("info hash mismatch"); return }
            if let t = torrent, hs.peerID == t.session.peerID { disconnect("connected to self"); return }
            remoteReserved = hs.reserved
            remotePeerID = hs.peerID
            handshakeDone = true
            afterHandshake()
            if closed { return }
        }
        do {
            while let m = try parser.next() {
                handle(m)
                if closed { return }
            }
        } catch {
            disconnect("protocol error: \(error)")
        }
    }

    private func afterHandshake() {
        guard let t = torrent, !closed else { return }
        if !t.peerHandshakeCompleted(self) { return }
        if supportsExtensions { sendExtensionHandshake() }
        // Our pieces
        if let picker = t.picker {
            if supportsFast && picker.have.isComplete { send(Wire.simple(.haveAll)) }
            else if supportsFast && picker.have.isEmpty { send(Wire.simple(.haveNone)) }
            else if !picker.have.isEmpty { send(Wire.bitfield(picker.have)) }
            else if supportsFast { send(Wire.simple(.haveNone)) }
        } else if supportsFast {
            send(Wire.simple(.haveNone))
        }
        if supportsDHT, t.session.config.enableDHT { sendPort(t.session.listenPort) }
        // BEP 6 allowed-fast set: let new peers bootstrap a few pieces even while choked.
        if supportsFast, let mi = t.metainfo, let picker = t.picker, !picker.have.isEmpty {
            allowedFastOut = Set(Wire.allowedFastSet(ip: address.ip, infoHash: infoHash, pieceCount: mi.pieceCount, k: 4)
                .filter { picker.have[$0] })
            for p in allowedFastOut { send(Wire.allowedFast(p)) }
        }
    }

    private func sendExtensionHandshake() {
        guard let t = torrent else { return }
        var m: [Data: BValue] = [:]
        for (name, id) in LocalExt.names {
            if name == "ut_pex" && (!t.session.config.enablePEX || t.isPrivate) { continue }
            if name == "ut_holepunch" && !t.session.config.enableHolepunch { continue }
            m[Data(name.utf8)] = .int(Int64(id))
        }
        var d: [Data: BValue] = [
            Data("m".utf8): .dict(m),
            Data("v".utf8): .string(ClientIdentity.userAgent),
            Data("reqq".utf8): .int(Int64(t.session.config.maxOutstandingRequestsPerPeer)),
            Data("p".utf8): .int(Int64(t.session.listenPort)),
            Data("yourip".utf8): .bytes(Data(address.ip.bytes)),
        ]
        if let mi = t.metainfo { d[Data("metadata_size".utf8)] = .int(Int64(mi.infoDict.count)) }
        if t.isSeeding { d[Data("upload_only".utf8)] = .int(1) }
        if t.session.config.encryption != .disabled { d[Data("e".utf8)] = .int(1) }
        send(Wire.extended(0, BValue.dict(d).encoded))
    }

    private func handle(_ m: InboundMessage) {
        guard let t = torrent else { disconnect("torrent gone"); return }
        switch m {
        case .keepAlive: break
        case .choke:
            peerChoking = true
            if !supportsFast {
                // Without the fast extension a choke discards every pending request.
                for (r, _) in outstanding { t.picker?.abort(r, peer: ObjectIdentifier(self)) }
                outstanding.removeAll()
            }
        case .unchoke:
            peerChoking = false
            t.fillRequests(self)
        case .interested:
            peerInterested = true
            t.peerInterestChanged(self)
        case .notInterested:
            peerInterested = false
            t.peerInterestChanged(self)
        case .have(let i):
            t.peerHave(self, piece: i)
        case .bitfield(let raw):
            t.peerBitfield(self, raw: raw)
        case .haveAll:
            guard supportsFast else { disconnect("have_all without fast ext"); return }
            t.peerHaveAll(self)
        case .haveNone:
            guard supportsFast else { disconnect("have_none without fast ext"); return }
            t.peerHaveNone(self)
        case .request(let r):
            handleRequest(r)
        case .cancel(let r):
            uploadQueue.removeAll { $0 == r }
        case .piece(let index, let offset, let data):
            let r = BlockRequest(piece: index, offset: offset, length: data.count)
            outstanding.removeValue(forKey: r)
            lastPieceAt = monotonicNow()
            snubbed = false
            requestTimeouts = 0
            downMeter.add(data.count)
            t.blockReceived(self, request: r, data: data)
        case .reject(let r):
            guard supportsFast else { disconnect("reject without fast ext"); return }
            if outstanding.removeValue(forKey: r) != nil {
                t.picker?.abort(r, peer: ObjectIdentifier(self))
                t.fillRequests(self)
            }
        case .allowedFast(let i):
            guard supportsFast else { return }
            allowedFastIn.insert(i)
            if peerChoking { t.fillRequests(self) }
        case .suggest:
            break // advisory; rarest-first already does well
        case .port(let p):
            t.session.dhtAddNode(PeerAddress(ip: address.ip, port: p))
        case .extended(let id, let payload):
            handleExtended(id: id, payload: payload)
        case .hashRequest(let root, let base, let index, let length, let proof):
            if let hashes = t.hashRequest(root: root, base: base, index: index, length: length, proof: proof) {
                send(Wire.hashMessage(.hashes, root: root, baseLayer: base, index: index, length: length,
                                      proofLayers: proof, hashes: hashes))
            } else {
                send(Wire.hashMessage(.hashReject, root: root, baseLayer: base, index: index, length: length, proofLayers: proof))
            }
        case .hashes(let root, let base, let index, let length, let proof, let hashes):
            t.hashesReceived(root: root, base: base, index: index, length: length, proof: proof, hashes: hashes)
        case .hashReject:
            break
        case .unknown:
            break // ignore unknown messages per spec
        }
    }

    private func handleRequest(_ r: BlockRequest) {
        guard let t = torrent, let picker = t.picker else { return }
        let valid = r.piece >= 0 && r.piece < picker.pieceCount && r.length > 0 && r.length <= 128 * 1024
            && r.offset >= 0 && r.offset + r.length <= picker.pieceSize(r.piece) && picker.have[r.piece]
        let allowed = !amChoking || allowedFastOut.contains(r.piece)
        guard valid && allowed && uploadQueue.count < 1024 else {
            if supportsFast { send(Wire.reject(r)) }
            return
        }
        uploadQueue.append(r)
        pumpUploads()
    }

    /// Serve queued requests while keeping the socket fed (≤ 4 disk reads, ≤ 1 MiB queued).
    func pumpUploads() {
        guard let t = torrent, let storage = t.storage, !closed else { return }
        while !uploadQueue.isEmpty && uploadReadsInFlight < 4 && stream.pendingWriteBytes < 1 << 20 {
            if t.session.uploadThrottled() { break }
            let r = uploadQueue.removeFirst()
            uploadReadsInFlight += 1
            storage.readBlock(r, loop: loop) { [weak self] data in
                guard let self else { return }
                self.uploadReadsInFlight -= 1
                guard !self.closed else { return }
                guard let data, data.count == r.length else { self.disconnect("disk read failed"); return }
                self.send(Wire.pieceHeader(piece: r.piece, offset: r.offset, length: r.length) + data)
                self.upMeter.add(data.count)
                self.torrent?.blockUploaded(data.count)
                self.pumpUploads()
            }
        }
    }

    // MARK: Extensions

    private func handleExtended(id: UInt8, payload: Data) {
        guard let t = torrent else { return }
        if id == 0 {
            guard let hs = try? BDecoder.decodePrefix(payload).0 else { return }
            if let m = hs["m"]?.dict {
                for (k, v) in m {
                    let name = String(decoding: k, as: UTF8.self)
                    if let i = v.int, i >= 0, i <= 255 { remoteExt[name] = UInt8(i) }
                }
                remoteExt = remoteExt.filter { $0.value != 0 }
            }
            if let s = hs["metadata_size"]?.int, s > 0, s < 64 * 1024 * 1024 { metadataSize = Int(s) }
            if let p = hs["p"]?.int, p > 0, p < 65536 { remoteListenPort = UInt16(p) }
            if let v = hs["v"]?.string { clientName = String(v.prefix(64)) }
            if let q = hs["reqq"]?.int, q > 0 { remoteReqq = Int(min(q, 2000)) }
            if hs["upload_only"]?.int == 1 { uploadOnly = true }
            if let ip = hs["yourip"]?.data, let a = IPAddress(bytes: ip) { t.session.observedExternalIP(a, from: address.ip) }
            t.peerExtensionHandshake(self)
            return
        }
        switch id {
        case LocalExt.utMetadata: t.metadataMessage(self, payload: payload)
        case LocalExt.utPex: t.pexMessage(self, payload: payload)
        case LocalExt.uploadOnly:
            uploadOnly = payload.first.map { $0 != 0 } ?? false
        case LocalExt.ltDonthave:
            if payload.count >= 4 { t.peerDontHave(self, piece: Int(payload.be32(0))) }
        case LocalExt.utHolepunch: t.holepunchMessage(self, payload: payload)
        default: break
        }
    }

    // MARK: Lifecycle

    private func streamClosed(_ err: SocketError?) {
        guard !closed else { return }
        closed = true
        torrent?.peerDisconnected(self, reason: err.map { "\($0)" } ?? "closed by peer")
    }

    func disconnect(_ reason: String) {
        guard !closed else { return }
        if !outbox.isEmpty { stream.write(outbox); outbox = Data() }
        closed = true
        stream.close()
        torrent?.peerDisconnected(self, reason: reason)
    }

    /// Called ~1/s by the torrent.
    func tick(now: Double) {
        downMeter.tick()
        upMeter.tick()
        if !handshakeDone && now - connectedAt > 15 { disconnect("handshake timeout"); return }
        if now - lastReceiveAt > 180 { disconnect("inactive"); return }
        if now - lastSendAt > 90 { sendKeepAlive() }
    }

    /// Desired number of outstanding block requests (bandwidth-delay product based).
    func requestQueueTarget(config: SessionConfig) -> Int {
        if snubbed { return 1 }
        let byRate = Int(downMeter.bytesPerSecond * config.requestQueueTime / Double(Wire.blockSize))
        let startup = monotonicNow() - connectedAt < 10 ? 32 : 0
        let target = max(config.minOutstandingRequestsPerPeer, max(byRate, startup))
        return min(target, config.maxOutstandingRequestsPerPeer, remoteReqq)
    }
}
