import Foundation
import Darwin

/// One packet we sent that is not yet acknowledged.
final class UTPOutPacket {
    var datagram: Data          // full encoded packet (header + payload)
    let seq: UInt16
    let payload: Int
    let type: UTPType
    var transmissions = 0
    var sentAt: UInt64 = 0      // µs, last transmission
    var needResend = false      // marked lost by RTO; not counted in the window

    init(datagram: Data, seq: UInt16, payload: Int, type: UTPType) {
        self.datagram = datagram
        self.seq = seq
        self.payload = payload
        self.type = type
    }
}

/// LEDBAT one-way delay tracking: base delay is the minimum over a 2-minute history
/// (two one-minute buckets); the current queuing delay is the minimum of the last
/// three samples above that base (filters jitter). All values are µs, wrapping.
struct UTPDelayHistory {
    private var buckets: [UInt32] = [0, 0]
    private var bucketIdx = 0
    private(set) var base: UInt32 = 0
    private var recent: [UInt32] = [0, 0, 0]
    private var recentIdx = 0
    private var lastRoll: UInt64 = 0
    private(set) var initialized = false

    mutating func add(_ sample: UInt32, now: UInt64) {
        if !initialized {
            initialized = true
            buckets = [sample, sample]
            base = sample
            lastRoll = now
            recent = [0, 0, 0]
        }
        if utpLess32(sample, buckets[bucketIdx]) { buckets[bucketIdx] = sample }
        if utpLess32(sample, base) { base = sample }
        recent[recentIdx] = sample &- base
        recentIdx = (recentIdx + 1) % recent.count
        if now &- lastRoll >= 60_000_000 {
            lastRoll = now
            bucketIdx = (bucketIdx + 1) % buckets.count
            buckets[bucketIdx] = sample
            var b = buckets[0]
            for v in buckets where utpLess32(v, b) { b = v }
            base = b
        }
    }

    /// Current queuing delay estimate in µs (0 when no samples yet).
    var current: UInt32 {
        guard initialized else { return 0 }
        var m = recent[0]
        for v in recent where v < m { m = v }
        return m
    }
}

/// A uTP connection. Implements `ByteStream` (reliable, ordered, back-pressured).
/// Loop-confined. Obtained from `UTPManager.connect` or `UTPManager.onAccept`.
public final class UTPStream: ByteStream, @unchecked Sendable {
    enum State { case synSent, synRecv, connected, destroyed }

    // MARK: ByteStream

    public var onRead: ((Data) -> Void)? {
        didSet { if onRead != nil && !held.isEmpty { scheduleHeldDelivery() } }
    }
    public var onClose: ((SocketError?) -> Void)?
    public var onWritable: (() -> Void)?
    public let remoteAddress: PeerAddress
    public var transport: TransportKind { .utp }
    /// Bytes written but not yet packetised (in-flight bytes are bounded by the window).
    public var pendingWriteBytes: Int { sendQueue.count }

    // MARK: Stats (read-only extras)

    /// Payload bytes acknowledged by the remote.
    public private(set) var bytesSent: Int64 = 0
    /// Payload bytes received in order.
    public private(set) var bytesReceived: Int64 = 0
    public private(set) var retransmits: Int64 = 0
    /// Retransmission timeouts that fired.
    public private(set) var timeouts: Int64 = 0
    /// Smoothed round-trip time in seconds (0 until measured).
    public var roundTripTime: Double { srtt / 1_000_000 }
    /// Congestion window in bytes.
    public var congestionWindow: Int { Int(cwnd) }

    var debugState: String {
        "state=\(state) seq=\(seqNr) una=\(sndUna) ack=\(ackNr) out=\(outCount) resend=\(resendCount) "
            + "cwnd=\(Int(cwnd)) peerWnd=\(peerWnd) srtt=\(Int(srtt))us rto=\(rto)us queued=\(sendQueue.count) "
            + "fin(queued=\(finQueued) acked=\(finAcked)) gotFin=\(gotFin) eof=\(eofConsumed) rtx=\(retransmits) rtos=\(timeouts)"
    }

    // MARK: Tunables

    static let targetDelay = 100_000.0              // LEDBAT target, µs
    static let maxCwndIncreasePerRTT = 3000.0       // LEDBAT gain (bytes per RTT at zero delay)
    static let minRTO: UInt64 = 500_000
    static let maxRTO: UInt64 = 60_000_000
    static let synRTO: UInt64 = 1_000_000
    static let recvWindow = 1 << 20                 // advertised receive buffer
    static let maxCwnd = 4.0 * 1024 * 1024
    static let maxOutstanding = 1000                // < libutp's 1024-entry reorder buffer
    static let maxReorder = 4096                    // packets we buffer beyond ack_nr
    static let keepAlive: UInt64 = 29_000_000
    static let maxTimeouts = 5
    static let maxTimeoutsClosing = 3
    static let closingTimeout: UInt64 = 30_000_000
    static let finLinger: UInt64 = 5_000_000
    static let zeroWindowProbe: UInt64 = 10_000_000
    static let synRecvHold: UInt64 = 2_000_000

    // MARK: Identity

    weak var manager: UTPManager?
    let loop: EventLoop
    let recvID: UInt16
    let sendID: UInt16
    let isInitiator: Bool
    var state: State
    var inDirty = false

    // MARK: Send side

    private var seqNr: UInt16 = 0            // next sequence number to assign
    private var sndUna: UInt16 = 0           // oldest unacknowledged
    private var outRing = UTPSeqRing<UTPOutPacket>(capacity: 64)
    private var outCount = 0                 // packets in outRing
    private var resendCount = 0              // packets marked needResend
    private var curWindow = 0                // payload bytes in flight
    private var cwnd: Double = 0
    private var ssthresh = Double.greatestFiniteMagnitude
    private var slowStart = true
    private var peerWnd = 64 * 1024
    private var zeroWindowSince: UInt64 = 0
    private var sendQueue = UTPByteQueue()
    private var dupAcks = 0
    private var lossSeqNr: UInt16 = 0
    private var lastCwndLimited: UInt64 = 0
    private var srtt = 0.0                   // µs
    private var rttvar = 0.0
    private var rto: UInt64 = UTPStream.synRTO
    private var rtoDeadline: UInt64 = 0
    private var probeDeadline: UInt64 = 0    // tail-loss probe (RFC 8985 TLP)
    private var probesSent = 0
    static let maxProbes = 2
    private var numTimeouts = 0
    private var lastSend: UInt64 = 0

    // MARK: Receive side

    private var ackNr: UInt16 = 0            // last in-order sequence number received
    private var inRing = UTPSeqRing<Data>(capacity: 64)
    private var reorderCount = 0
    private var reorderBytes = 0
    private var replyMicro: UInt32 = 0
    private var needAck = false
    /// ACKs are normally deferred to the end of the receive batch (one per drain); a
    /// STATE is also sent mid-batch every 4 in-order / 2 out-of-order data packets so a
    /// single lost ACK can't stall a whole window (and SACK info reaches the sender fast).
    private var ackCredit = 0
    static let ackCreditLimit = 4
    private var lastAdvertised = 0
    private var delay = UTPDelayHistory()
    private var held: [Data] = []            // received while onRead == nil
    private var heldBytes = 0
    private var heldScheduled = false

    // MARK: Lifecycle

    private var ownerClosed = false
    private var closeNotified = false
    private var finQueued = false
    private var finSeq: UInt16?
    private var finAcked = false
    private var finAckedAt: UInt64 = 0
    private var gotFin = false
    private var eofSeq: UInt16 = 0
    private var eofConsumed = false
    private var eofPendingNotify = false
    private var closingSince: UInt64 = 0
    private var connectCompletion: ((Result<UTPStream, SocketError>) -> Void)?
    private var connectDeadline: UInt64 = 0
    private var synRecvSince: UInt64 = 0
    private var peerSynSeq: UInt16 = 0

    init(manager: UTPManager, remote: PeerAddress, recvID: UInt16, sendID: UInt16, initiator: Bool) {
        self.manager = manager
        self.loop = manager.loop
        self.remoteAddress = remote
        self.recvID = recvID
        self.sendID = sendID
        self.isInitiator = initiator
        self.state = initiator ? .synSent : .synRecv
        self.cwnd = Double(4 * manager.maxPayload)
    }

    // MARK: - Public ByteStream methods

    public func write(_ data: Data) {
        loop.assertInLoop()
        guard !data.isEmpty, !ownerClosed, !finQueued, state != .destroyed else { return }
        sendQueue.append(data)
        manager?.markDirty(self)
    }

    /// Graceful close: queued data is still delivered, then FIN. No callbacks fire afterwards.
    public func close() {
        loop.assertInLoop()
        guard !ownerClosed else { return }
        ownerClosed = true
        clearCallbacks()
        held.removeAll()
        heldBytes = 0
        guard state != .destroyed else { return }
        if state == .synRecv && sendQueue.isEmpty {
            // Nothing was ever exchanged beyond the SYN: just reset.
            manager?.sendReset(to: remoteAddress, connectionID: sendID, ackNr: ackNr)
            destroy()
            return
        }
        beginClosing(now: utpNowMicros())
    }

    // MARK: - Connection setup

    func startConnect(timeout: Double, completion: @escaping (Result<UTPStream, SocketError>) -> Void) {
        let now = utpNowMicros()
        connectCompletion = completion
        connectDeadline = now + UInt64(max(0.05, timeout) * 1_000_000)
        seqNr = UInt16.random(in: 0...UInt16.max)
        sndUna = seqNr
        lossSeqNr = seqNr
        rto = Self.synRTO
        let syn = makePacket(type: .syn, seq: seqNr, payloadCount: 0)
        outRing[seqNr] = syn
        outCount = 1
        seqNr &+= 1
        transmit(syn, now: now)
    }

    func acceptSYN(_ syn: UTPHeader) {
        let now = utpNowMicros()
        peerSynSeq = syn.seqNr
        ackNr = syn.seqNr
        seqNr = UInt16.random(in: 0...UInt16.max)
        sndUna = seqNr
        lossSeqNr = seqNr
        peerWnd = Int(syn.windowSize)
        replyMicro = UInt32(truncatingIfNeeded: now) &- syn.timestamp
        synRecvSince = now
        sendState(now: now)
    }

    // MARK: - Incoming packets

    func incoming(_ pkt: UTPPacket, _ datagram: Data) {
        guard state != .destroyed else { return }
        let h = pkt.header
        let now = utpNowMicros()

        switch h.type {
        case .reset:
            if state == .synSent {
                failConnect(SocketError("utp connect", ECONNREFUSED))
            } else {
                die(SocketError.closed)
            }
            return
        case .syn:
            // Duplicate SYN (our SYN-ACK was lost): re-acknowledge while still half-open.
            if !isInitiator && state == .synRecv && h.seqNr == peerSynSeq {
                replyMicro = UInt32(truncatingIfNeeded: now) &- h.timestamp
                needAck = true
                manager?.markDirty(self)
            }
            return
        default:
            break
        }

        // Acks for packets we never sent are bogus: drop the whole packet.
        let ackA = h.ackNr
        if Int16(bitPattern: ackA &- (seqNr &- 1)) > 0 { return }

        replyMicro = UInt32(truncatingIfNeeded: now) &- h.timestamp
        var justConnected = false
        if state == .synSent {
            guard ackA == sndUna else { return }   // must acknowledge our SYN
            ackNr = h.seqNr &- 1
            state = .connected
            justConnected = true
            needAck = true                         // completes the handshake for the responder
        } else if state == .synRecv {
            state = .connected
            if !sendQueue.isEmpty || finQueued { manager?.markDirty(self) }
        }
        let oldPeerWnd = peerWnd
        peerWnd = Int(h.windowSize)
        if peerWnd > 0 { zeroWindowSince = 0 }
        if peerWnd > oldPeerWnd && (!sendQueue.isEmpty || resendCount > 0 || (finQueued && finSeq == nil)) {
            manager?.markDirty(self)          // window update: resume sending
        }
        if h.timestampDiff != 0 { delay.add(h.timestampDiff, now: now) }

        processAck(pkt, datagram, now: now)
        if state == .destroyed { return }

        if justConnected, let cb = connectCompletion {
            connectCompletion = nil
            cb(.success(self))
            if state == .destroyed { return }
        }

        switch h.type {
        case .data:
            handleData(seq: h.seqNr, datagram: datagram, offset: pkt.payloadOffset, count: pkt.payloadCount)
            if state == .destroyed { return }
            if needAck {
                ackCredit += reorderCount > 0 ? 2 : 1
                if ackCredit >= Self.ackCreditLimit { sendState(now: now) }
            }
        case .fin:
            handleFin(seq: h.seqNr)
        default:
            break
        }
        if state == .destroyed { return }
        if needAck { manager?.markDirty(self) }
        checkFinished(now: now)
    }

    private func processAck(_ pkt: UTPPacket, _ datagram: Data, now: UInt64) {
        let h = pkt.header
        let ackA = h.ackNr
        var newly = 0
        if UTPSeq.lt(sndUna &- 1, ackA) { newly = UTPSeq.dist(sndUna &- 1, ackA) }
        let outstandingBefore = UTPSeq.dist(sndUna, seqNr)
        guard newly <= outstandingBefore else { return }

        var bytesAcked = 0
        var newestSentAt: UInt64 = 0          // newest acked packet sent once (Karn)
        var newestAckedXmit: UInt64 = 0       // newest transmission time of anything acked

        @inline(__always) func ackPacket(_ p: UTPOutPacket) {
            outRing[p.seq] = nil
            outCount -= 1
            if p.needResend {
                p.needResend = false
                resendCount -= 1
            } else {
                curWindow -= p.payload
            }
            bytesAcked += p.payload
            bytesSent += Int64(p.payload)
            if p.transmissions == 1 && p.sentAt > newestSentAt { newestSentAt = p.sentAt }
            if p.sentAt > newestAckedXmit { newestAckedXmit = p.sentAt }
            if p.type == .fin && !finAcked {
                finAcked = true
                finAckedAt = now
            }
        }

        if newly > 0 {
            var s = sndUna
            for _ in 0..<newly {
                if let p = outRing[s] { ackPacket(p) }
                s &+= 1
            }
            sndUna = ackA &+ 1
            dupAcks = 0
            numTimeouts = 0
        } else if h.type == .state && pkt.payloadCount == 0 && ackA == sndUna &- 1 && outCount > 0 {
            dupAcks += 1
        }

        // Selective ACK: free every packet the receiver already holds.
        var sackBits = 0
        if let r = pkt.sack, outCount > 0 {
            sackBits = r.count * 8
            datagram.withUnsafeBytes { raw in
                let outstanding = UTPSeq.dist(sndUna, seqNr)
                for bi in r {
                    let byte = raw[bi]
                    if byte == 0 { continue }
                    for bit in 0..<8 where byte & (1 << UInt8(bit)) != 0 {
                        let seq = ackA &+ 2 &+ UInt16(truncatingIfNeeded: (bi - r.lowerBound) * 8 + bit)
                        guard UTPSeq.dist(sndUna, seq) < outstanding, let p = outRing[seq] else { continue }
                        ackPacket(p)
                    }
                }
            }
        }

        if bytesAcked > 0 || newly > 0 {
            if newestSentAt != 0 { updateRTT(Double(now &- newestSentAt)) }
            rto = computedRTO()
            rtoDeadline = (outCount - resendCount) > 0 ? now + rto : 0
            probesSent = 0
            armProbe(now: now)
            if bytesAcked > 0 { applyLEDBAT(bytesAcked: bytesAcked, now: now) }
            manager?.markDirty(self)          // window opened: send more
        }

        guard outCount > 0 else { return }

        // Loss detection. dupThresh = 3, lowered when too few packets are outstanding
        // to ever generate three duplicate acks (RFC 5827 early retransmit).
        // (With a tiny window we are window-limited, so no new data could be sent to
        // elicit further duplicate acks either.)
        let outstanding = UTPSeq.dist(sndUna, seqNr)
        var dupThresh = 3
        if outstanding < 4 { dupThresh = max(1, outstanding - 1) }
        let reoWnd = UInt64(max(1000.0, srtt / 4))

        if sackBits > 0, let r = pkt.sack {
            var lost: [UTPOutPacket] = []
            datagram.withUnsafeBytes { raw in
                var count = 0
                var i = sackBits - 1
                while i >= -1 {
                    let set = i >= 0 && raw[r.lowerBound + (i >> 3)] & (1 << UInt8(i & 7)) != 0
                    if set {
                        count += 1
                    } else if count > 0 {
                        let seq = ackA &+ 2 &+ UInt16(truncatingIfNeeded: i)
                        if UTPSeq.dist(sndUna, seq) < outstanding, let p = outRing[seq], !p.needResend {
                            if p.transmissions == 1 {
                                if count >= dupThresh { lost.append(p) }
                            } else if newestAckedXmit > p.sentAt &+ reoWnd {
                                lost.append(p)   // the retransmission itself was lost
                            }
                        }
                    }
                    i -= 1
                }
            }
            for p in lost.reversed() { fastRetransmit(p, now: now) }
        } else if dupAcks >= dupThresh, let p = outRing[sndUna], !p.needResend, p.transmissions == 1 {
            fastRetransmit(p, now: now)
        }
    }

    private func fastRetransmit(_ p: UTPOutPacket, now: UInt64) {
        guard state != .destroyed else { return }
        if !UTPSeq.lt(p.seq, lossSeqNr) {
            // One multiplicative decrease per window of data (LEDBAT / RFC 6817).
            let mp = Double(manager?.maxPayload ?? 1200)
            cwnd = max(cwnd * 0.5, 2 * mp)
            ssthresh = cwnd
            slowStart = false
            lossSeqNr = seqNr
        }
        retransmits += 1
        transmit(p, now: now)
    }

    private func handleData(seq: UInt16, datagram: Data, offset: Int, count: Int) {
        if gotFin && !UTPSeq.lt(seq, eofSeq) { return }      // beyond EOF
        let expected = ackNr &+ 1
        let d = UTPSeq.dist(expected, seq)
        needAck = true
        if d == 0 {
            // Flow control: data the owner isn't reading (onRead unset) is held and
            // shrinks our window; refuse to hold more than 2× the window from a sender
            // that ignores it (it will retransmit once we drain).
            if (onRead == nil || !held.isEmpty) && !ownerClosed && !closeNotified
                && heldBytes + count > 2 * Self.recvWindow {
                return
            }
            ackNr = seq
            if reorderCount > 0, let stale = inRing[seq] {
                // Defensive: never leave a consumed sequence number in the ring (it
                // would alias a future sequence number after the window slides).
                inRing[seq] = nil
                reorderCount -= 1
                reorderBytes -= stale.count
            }
            if count > 0 {
                let s = datagram.startIndex + offset
                deliver(datagram.subdata(in: s..<(s + count)))
                if state == .destroyed { return }
            }
            drainReorder()
            if state == .destroyed { return }
            checkEOF()
        } else if d < 0x8000 {
            guard d < Self.maxReorder, reorderBytes + count <= Self.recvWindow else { return }
            inRing.reserve(span: d + 1, base: expected)
            if inRing[seq] == nil {
                let s = datagram.startIndex + offset
                inRing[seq] = count > 0 ? datagram.subdata(in: s..<(s + count)) : Data()
                reorderCount += 1
                reorderBytes += count
            }
        }
        // else: duplicate of data already delivered — just re-ack.
    }

    private func drainReorder() {
        while reorderCount > 0 {
            let next = ackNr &+ 1
            if gotFin && next == eofSeq { break }
            guard let d = inRing[next] else { break }
            inRing[next] = nil
            reorderCount -= 1
            reorderBytes -= d.count
            ackNr = next
            if !d.isEmpty {
                deliver(d)
                if state == .destroyed { return }
            }
        }
    }

    private func handleFin(seq: UInt16) {
        needAck = true
        if !gotFin {
            // A FIN must lie beyond what we've already received.
            guard UTPSeq.lt(ackNr, seq) else { return }
            gotFin = true
            eofSeq = seq
        }
        checkEOF()
    }

    private func checkEOF() {
        guard gotFin, !eofConsumed, ackNr &+ 1 == eofSeq else { return }
        ackNr = eofSeq
        eofConsumed = true
        needAck = true
        if held.isEmpty { notifyEOF() } else { eofPendingNotify = true }
    }

    private func notifyEOF() {
        eofPendingNotify = false
        if !ownerClosed && !closeNotified {
            closeNotified = true
            let cb = onClose
            clearCallbacks()
            cb?(nil)
        }
        if state != .destroyed { beginClosing(now: utpNowMicros()) }
    }

    // MARK: - Delivery to the owner

    private func deliver(_ d: Data) {
        bytesReceived += Int64(d.count)
        if ownerClosed || closeNotified { return }
        if held.isEmpty, let cb = onRead {
            cb(d)
        } else {
            held.append(d)
            heldBytes += d.count
            if onRead != nil { scheduleHeldDelivery() }
        }
    }

    private func scheduleHeldDelivery() {
        guard !heldScheduled else { return }
        heldScheduled = true
        loop.execute { [weak self] in self?.deliverHeld() }
    }

    private func deliverHeld() {
        heldScheduled = false
        guard state != .destroyed || !held.isEmpty else { return }
        let windowWasSmall = lastAdvertised < Self.recvWindow / 2
        var i = 0
        while i < held.count, !ownerClosed, !closeNotified, let cb = onRead {
            let d = held[i]
            i += 1
            heldBytes -= d.count
            cb(d)
        }
        if i >= held.count {
            held.removeAll()
            heldBytes = 0
        } else if i > 0 {
            held.removeFirst(i)
        }
        guard held.isEmpty else { return }
        if eofPendingNotify && state != .destroyed { notifyEOF() }
        if windowWasSmall && state == .connected {
            needAck = true                    // window update
            manager?.markDirty(self)
        }
    }

    // MARK: - Sending

    private func advertisedWindow() -> Int {
        max(0, Self.recvWindow - reorderBytes - heldBytes)
    }

    private func makePacket(type: UTPType, seq: UInt16, payloadCount: Int) -> UTPOutPacket {
        var d = Data(count: UTPHeader.size + payloadCount)
        let connID = type == .syn ? recvID : sendID
        d.withUnsafeMutableBytes { raw in
            let p = raw.baseAddress!
            UTPHeader(type: type, connectionID: connID, seqNr: seq, ackNr: ackNr).write(to: p)
            if payloadCount > 0 { _ = sendQueue.read(into: p + UTPHeader.size, payloadCount) }
        }
        return UTPOutPacket(datagram: d, seq: seq, payload: payloadCount, type: type)
    }

    private func transmit(_ p: UTPOutPacket, now: UInt64) {
        guard let m = manager else { return }
        let wnd = advertisedWindow()
        let ts = UInt32(truncatingIfNeeded: now)
        let reply = replyMicro
        let ack = p.type == .syn ? 0 : ackNr
        p.datagram.withUnsafeMutableBytes { raw in
            UTPHeader.patch(raw.baseAddress!, timestamp: ts, timestampDiff: reply,
                            windowSize: UInt32(wnd), ackNr: ack)
        }
        p.transmissions += 1
        p.sentAt = now
        lastSend = now
        lastAdvertised = wnd
        if reorderCount == 0 && p.type != .syn { needAck = false; ackCredit = 0 }
        if rtoDeadline == 0 { rtoDeadline = now + rto }
        if probeDeadline == 0 { armProbe(now: now) }
        m.sendRaw(p.datagram, to: remoteAddress)
    }

    private func sendState(now: UInt64) {
        guard let m = manager else { return }
        let wnd = advertisedWindow()
        let h = UTPHeader(type: .state, connectionID: sendID, timestamp: UInt32(truncatingIfNeeded: now),
                          timestampDiff: replyMicro, windowSize: UInt32(wnd), seqNr: seqNr, ackNr: ackNr)
        var sack: [UInt8] = []
        if reorderCount > 0 {
            let base = ackNr &+ 1
            let cap = inRing.capacity
            sack = UTPSack.encode(ackNr: ackNr) { s in UTPSeq.dist(base, s) < cap && inRing[s] != nil }
        }
        needAck = false
        ackCredit = 0
        lastSend = now
        lastAdvertised = wnd
        m.sendRaw(UTPCodec.encode(h, sack: sack), to: remoteAddress)
    }

    /// The peer's advertised window; when it is zero, a one-packet probe allowance
    /// is granted once per `zeroWindowProbe` interval (in case a window update was lost).
    private func peerWindowLimit(now: UInt64) -> Int {
        if peerWnd > 0 { return peerWnd }
        if zeroWindowSince == 0 { zeroWindowSince = now }
        guard now &- zeroWindowSince >= Self.zeroWindowProbe else { return 0 }
        zeroWindowSince = now                 // consume the allowance
        return manager?.maxPayload ?? 1200
    }

    /// Sending stopped on the window. Only when cwnd (not the peer's window) is the
    /// binding limit does LEDBAT get to grow it — otherwise cwnd would inflate unused.
    @inline(__always)
    private func noteBlocked(now: UInt64) {
        if Int(cwnd) <= peerWnd { lastCwndLimited = now }
    }

    @inline(__always)
    private func canSend(_ n: Int, now: UInt64) -> Bool {
        let peerLimit = peerWindowLimit(now: now)
        if curWindow + n <= min(Int(cwnd), peerLimit) { return true }
        // Always allow one packet in flight when the peer has any room at all.
        return curWindow == 0 && peerLimit > 0
    }

    /// Send whatever the windows allow: lost packets first, then new data, then FIN.
    func flush(now: UInt64) {
        guard let m = manager else { return }
        if state == .synRecv {
            if needAck { sendState(now: now) }
            return
        }
        guard state == .connected else { return }
        let hadPending = !sendQueue.isEmpty

        if resendCount > 0 {
            var s = sndUna
            while s != seqNr && resendCount > 0 {
                if let p = outRing[s], p.needResend {
                    guard canSend(p.payload, now: now) else { noteBlocked(now: now); break }
                    p.needResend = false
                    resendCount -= 1
                    curWindow += p.payload
                    retransmits += 1
                    transmit(p, now: now)
                }
                s &+= 1
            }
        }

        if resendCount == 0 {
            let mp = m.maxPayload
            while !sendQueue.isEmpty {
                let n = min(sendQueue.count, mp)
                let outstanding = UTPSeq.dist(sndUna, seqNr)
                guard outstanding < Self.maxOutstanding else { break }
                guard canSend(n, now: now) else {
                    noteBlocked(now: now)
                    break
                }
                let seq = seqNr
                outRing.reserve(span: outstanding + 1, base: sndUna)
                let p = makePacket(type: .data, seq: seq, payloadCount: n)
                outRing[seq] = p
                outCount += 1
                seqNr &+= 1
                curWindow += n
                transmit(p, now: now)
            }
            if finQueued && finSeq == nil && sendQueue.isEmpty {
                let outstanding = UTPSeq.dist(sndUna, seqNr)
                if outstanding < Self.maxOutstanding {
                    let seq = seqNr
                    outRing.reserve(span: outstanding + 1, base: sndUna)
                    let p = makePacket(type: .fin, seq: seq, payloadCount: 0)
                    outRing[seq] = p
                    outCount += 1
                    seqNr &+= 1
                    finSeq = seq
                    transmit(p, now: now)
                }
            }
        }

        if hadPending && sendQueue.count < UTPStream.lowWatermark && !ownerClosed, let cb = onWritable {
            cb()
            if state == .destroyed { return }
        }
        if needAck { sendState(now: now) }
    }

    // MARK: - Congestion control (LEDBAT) and RTT

    private func updateRTT(_ r: Double) {
        guard r >= 0, r < 60_000_000 else { return }
        if srtt == 0 {
            srtt = r
            rttvar = r / 2
        } else {
            rttvar += (abs(srtt - r) - rttvar) / 4
            srtt += (r - srtt) / 8
        }
    }

    private func computedRTO() -> UInt64 {
        guard srtt > 0 else { return max(Self.minRTO, min(rto, Self.synRTO)) }
        let v = UInt64(srtt + 4 * rttvar)
        return min(max(v, Self.minRTO), Self.maxRTO)
    }

    private func applyLEDBAT(bytesAcked: Int, now: UInt64) {
        let mp = Double(manager?.maxPayload ?? 1200)
        let ourDelay = min(Double(delay.current), 1_000_000)
        let target = Self.targetDelay
        let offTarget = max(-1.0, (target - ourDelay) / target)
        let acked = Double(bytesAcked)
        let windowFactor = min(acked, cwnd) / max(cwnd, acked)
        var gain = Self.maxCwndIncreasePerRTT * offTarget * windowFactor
        let windowLimited = now &- lastCwndLimited <= 1_000_000
        if gain > 0 && !windowLimited { gain = 0 }   // application-limited: don't inflate
        var next = cwnd + gain
        if slowStart {
            if ourDelay > target * 0.9 {
                slowStart = false
                ssthresh = cwnd
            } else if cwnd + acked > ssthresh {
                slowStart = false
            } else if windowLimited {
                next = max(next, cwnd + acked)
            }
        }
        cwnd = min(max(next, 2 * mp), Self.maxCwnd)
    }

    // MARK: - Timers

    func tick(now: UInt64) {
        switch state {
        case .destroyed:
            return
        case .synSent:
            if now >= connectDeadline {
                failConnect(.timedOut)
                return
            }
            if rtoDeadline != 0 && now >= rtoDeadline, let syn = outRing[sndUna] {
                rto = min(rto * 2, Self.maxRTO)
                rtoDeadline = 0
                transmit(syn, now: now)
            }
        case .synRecv:
            if now &- synRecvSince >= Self.synRecvHold && (!sendQueue.isEmpty || finQueued) {
                state = .connected
                flush(now: now)
            }
        case .connected:
            if rtoDeadline != 0 && now >= rtoDeadline {
                onTimeout(now: now)
                if state == .destroyed { return }
            } else if probeDeadline != 0 && now >= probeDeadline {
                sendProbe(now: now)
            }
            if peerWnd == 0 && !sendQueue.isEmpty && zeroWindowSince != 0
                && now &- zeroWindowSince >= Self.zeroWindowProbe {
                flush(now: now)
            }
            if now &- lastSend >= Self.keepAlive { sendState(now: now) }
            if finQueued && now &- closingSince >= Self.closingTimeout {
                manager?.sendReset(to: remoteAddress, connectionID: sendID, ackNr: ackNr)
                destroy()
                return
            }
            checkFinished(now: now)
        }
    }

    /// Tail-loss probe: if nothing is acknowledged for ~2 RTTs, retransmit the newest
    /// outstanding packet so the receiver answers with an ACK/SACK. Recovers a lost
    /// last packet or a lost final ACK via fast retransmit instead of a full RTO.
    private func armProbe(now: UInt64) {
        guard srtt > 0, probesSent < Self.maxProbes, outCount - resendCount > 0, state == .connected else {
            probeDeadline = 0
            return
        }
        let pto = UInt64(max(2 * srtt, 10_000))
        probeDeadline = now + pto
        if rtoDeadline != 0 && probeDeadline >= rtoDeadline { probeDeadline = 0 }
    }

    private func sendProbe(now: UInt64) {
        probeDeadline = 0
        guard probesSent < Self.maxProbes, outCount - resendCount > 0 else { return }
        var s = seqNr &- 1
        while s != sndUna &- 1 {
            if let p = outRing[s], !p.needResend {
                probesSent += 1
                retransmits += 1
                rtoDeadline = now + rto        // re-arm RTO; transmit() schedules a further probe
                transmit(p, now: now)
                return
            }
            s &-= 1
        }
    }

    private func onTimeout(now: UInt64) {
        rtoDeadline = 0
        probeDeadline = 0
        probesSent = Self.maxProbes   // no tail-loss probe after an RTO until new data is acked
        guard outCount - resendCount > 0 else { return }
        numTimeouts += 1
        timeouts += 1
        let limit = (ownerClosed || finQueued) ? Self.maxTimeoutsClosing : Self.maxTimeouts
        if numTimeouts > limit {
            die(.timedOut)
            return
        }
        let mp = Double(manager?.maxPayload ?? 1200)
        ssthresh = max(cwnd / 2, 2 * mp)
        cwnd = mp
        slowStart = true
        rto = min(rto * 2, Self.maxRTO)
        // Everything in flight is presumed lost; resend in order as the window allows.
        var s = sndUna
        while s != seqNr {
            if let p = outRing[s], !p.needResend {
                p.needResend = true
                resendCount += 1
                curWindow -= p.payload
            }
            s &+= 1
        }
        curWindow = 0
        lossSeqNr = seqNr
        dupAcks = 0
        flush(now: now)
    }

    // MARK: - Teardown

    private func beginClosing(now: UInt64) {
        guard !finQueued else { return }
        finQueued = true
        closingSince = now
        manager?.markDirty(self)
    }

    /// Destroy once our FIN is acknowledged and the peer's FIN consumed (or lingered out).
    func checkFinished(now: UInt64) {
        guard state == .connected, finAcked else { return }
        if eofConsumed || now &- finAckedAt >= Self.finLinger {
            if needAck { sendState(now: now) }
            destroy()
        }
    }

    private func clearCallbacks() {
        onRead = nil
        onClose = nil
        onWritable = nil
    }

    private func destroy() {
        guard state != .destroyed else { return }
        state = .destroyed
        clearCallbacks()
        connectCompletion = nil
        sendQueue.removeAll()
        outRing = UTPSeqRing(capacity: 16)
        inRing = UTPSeqRing(capacity: 16)
        outCount = 0
        resendCount = 0
        reorderCount = 0
        reorderBytes = 0
        held.removeAll()
        heldBytes = 0
        manager?.remove(self)
    }

    /// Fatal error: notify the owner (unless they closed us) and tear down.
    private func die(_ err: SocketError) {
        guard state != .destroyed else { return }
        if state == .synSent { failConnect(err); return }
        let cb = (!ownerClosed && !closeNotified) ? onClose : nil
        closeNotified = true
        destroy()
        cb?(err)
    }

    private func failConnect(_ err: SocketError) {
        let cb = connectCompletion
        connectCompletion = nil
        destroy()
        cb?(.failure(err))
    }

    /// Used by `UTPManager.closeAll()`.
    func abort(error: SocketError, sendReset: Bool) {
        guard state != .destroyed else { return }
        if sendReset && state != .synSent {
            manager?.sendReset(to: remoteAddress, connectionID: sendID, ackNr: ackNr)
        }
        die(error)
    }
}
