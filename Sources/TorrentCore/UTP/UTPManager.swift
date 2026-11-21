import Foundation
import Darwin

/// Microsecond monotonic clock (same time base as `microsNow32()`; uTP header
/// timestamps are its low 32 bits).
@inline(__always)
func utpNowMicros() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1_000 }

/// Demultiplexing key: remote endpoint + the connection id carried by packets we receive.
struct UTPConnKey: Hashable {
    let addr: PeerAddress
    let id: UInt16
}

/// uTP (BEP 29) endpoint multiplexer. One per UDP socket (address family). The owner
/// feeds every datagram that is not DHT to `handle(_:from:)` and transmits whatever
/// the manager hands to `send`. Loop-confined: touch only on `loop.queue`.
public final class UTPManager: @unchecked Sendable {
    public let loop: EventLoop
    let sendFn: (Data, PeerAddress) -> Void

    /// Incoming connection (SYN received and acknowledged). Install callbacks synchronously.
    public var onAccept: ((UTPStream) -> Void)?

    private var _maxPayload = 1200
    /// Max uTP payload bytes per packet (excl. 20-byte header). Datagrams never exceed
    /// `maxPayload + 20` bytes. Clamped to 128...9000.
    public var maxPayload: Int {
        get { _maxPayload }
        set { _maxPayload = min(max(newValue, 128), 9000) }
    }

    /// Live connections (including half-open and gracefully closing ones).
    public var connectionCount: Int { streams.count }

    /// Incoming SYNs beyond this many live connections are answered with RESET.
    public var maxConnections = 4096

    // Stats
    public private(set) var datagramsSent: Int64 = 0
    public private(set) var datagramsReceived: Int64 = 0

    var streams: [UTPConnKey: UTPStream] = [:]
    private var timer: LoopTimer?
    private var dirty: [UTPStream] = []
    private var dirtyScheduled = false

    static let tickInterval = 0.05

    public init(loop: EventLoop, send: @escaping (Data, PeerAddress) -> Void) {
        self.loop = loop
        self.sendFn = send
    }

    deinit { timer?.cancel() }

    // MARK: Public API

    /// Returns true if the datagram was a uTP packet (consumed), false otherwise so the
    /// caller can route it elsewhere. Malformed input never traps.
    @discardableResult
    public func handle(_ datagram: Data, from: PeerAddress) -> Bool {
        loop.assertInLoop()
        guard let pkt = UTPCodec.parse(datagram) else { return false }
        datagramsReceived += 1
        let h = pkt.header

        if h.type == .syn {
            // A SYN carries the initiator's recv id; our recv id is id + 1.
            let key = UTPConnKey(addr: from, id: h.connectionID &+ 1)
            if let s = streams[key] {
                s.incoming(pkt, datagram)      // duplicate SYN: re-acknowledge
            } else {
                accept(pkt.header, from: from, key: key)
            }
            return true
        }

        if let s = streams[UTPConnKey(addr: from, id: h.connectionID)] {
            s.incoming(pkt, datagram)
            return true
        }

        if h.type == .reset {
            // A RESET answering one of our packets carries our *send* id
            // (recv id ± 1 depending on who initiated).
            for cand in [h.connectionID &- 1, h.connectionID &+ 1] {
                if let s = streams[UTPConnKey(addr: from, id: cand)], s.sendID == h.connectionID {
                    s.incoming(pkt, datagram)
                    break
                }
            }
            return true
        }

        // Unknown connection: tell the sender to stop (never answer RESET/STATE).
        if h.type == .data || h.type == .fin {
            sendReset(to: from, connectionID: h.connectionID, ackNr: h.seqNr)
        }
        return true
    }

    /// Open an outgoing uTP connection. `completion` runs on the loop exactly once.
    public func connect(to remote: PeerAddress, timeout: Double,
                        completion: @escaping (Result<UTPStream, SocketError>) -> Void) {
        loop.assertInLoop()
        var recvID = UInt16.random(in: 0...UInt16.max)
        var tries = 0
        while streams[UTPConnKey(addr: remote, id: recvID)] != nil
                || streams[UTPConnKey(addr: remote, id: recvID &+ 1)] != nil {
            tries += 1
            if tries > 64 { completion(.failure(SocketError("utp connect", EADDRINUSE))); return }
            recvID = UInt16.random(in: 0...UInt16.max)
        }
        let s = UTPStream(manager: self, remote: remote, recvID: recvID, sendID: recvID &+ 1, initiator: true)
        streams[UTPConnKey(addr: remote, id: recvID)] = s
        ensureTimer()
        s.startConnect(timeout: timeout, completion: completion)
    }

    /// Abort every connection (RESET to the remote). Streams whose owner has not
    /// closed them get `onClose(error)`; pending connects fail.
    public func closeAll() {
        loop.assertInLoop()
        let all = Array(streams.values)
        streams.removeAll()
        dirty.removeAll()
        for s in all { s.abort(error: SocketError("utp", ECANCELED), sendReset: true) }
        timer?.cancel()
        timer = nil
    }

    // MARK: Internals used by UTPStream

    @inline(__always)
    func sendRaw(_ data: Data, to: PeerAddress) {
        datagramsSent += 1
        sendFn(data, to)
    }

    func sendReset(to: PeerAddress, connectionID: UInt16, ackNr: UInt16) {
        let h = UTPHeader(type: .reset, connectionID: connectionID,
                          timestamp: UInt32(truncatingIfNeeded: utpNowMicros()),
                          seqNr: UInt16.random(in: 0...UInt16.max), ackNr: ackNr)
        sendRaw(UTPCodec.encode(h), to: to)
    }

    func remove(_ s: UTPStream) {
        let key = UTPConnKey(addr: s.remoteAddress, id: s.recvID)
        if let cur = streams[key], cur === s { streams.removeValue(forKey: key) }
    }

    /// Queue `s` for a flush/ack pass at the end of the current loop turn. This
    /// coalesces small writes and batches ACKs for all datagrams drained in one go.
    func markDirty(_ s: UTPStream) {
        if !s.inDirty {
            s.inDirty = true
            dirty.append(s)
        }
        if !dirtyScheduled {
            dirtyScheduled = true
            loop.execute { [weak self] in self?.processDirty() }
        }
    }

    private func processDirty() {
        dirtyScheduled = false
        guard !dirty.isEmpty else { return }
        let list = dirty
        dirty.removeAll(keepingCapacity: true)
        let now = utpNowMicros()
        for s in list {
            s.inDirty = false
            s.flush(now: now)
            s.checkFinished(now: now)
        }
    }

    private func accept(_ syn: UTPHeader, from: PeerAddress, key: UTPConnKey) {
        guard onAccept != nil, streams.count < maxConnections else {
            sendReset(to: from, connectionID: syn.connectionID, ackNr: syn.seqNr)
            return
        }
        let s = UTPStream(manager: self, remote: from, recvID: key.id, sendID: syn.connectionID, initiator: false)
        streams[key] = s
        ensureTimer()
        s.acceptSYN(syn)
        onAccept?(s)
    }

    private func ensureTimer() {
        guard timer == nil else { return }
        timer = loop.every(Self.tickInterval, leeway: 0.01) { [weak self] in self?.tick() }
    }

    private func tick() {
        if streams.isEmpty {
            timer?.cancel()
            timer = nil
            return
        }
        let now = utpNowMicros()
        for s in Array(streams.values) { s.tick(now: now) }
    }
}
