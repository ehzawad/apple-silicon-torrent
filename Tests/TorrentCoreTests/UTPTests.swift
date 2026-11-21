import Testing
import Foundation
import Darwin
@testable import TorrentCore

// MARK: - Helpers

private final class Box<T>: @unchecked Sendable {
    var v: T
    init(_ v: T) { self.v = v }
}

private struct SplitMix64 {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
    mutating func unit() -> Double { Double(next() >> 11) / Double(1 << 53) }
}

/// Deterministic pseudo-random payload.
private func payload(_ n: Int, seed: UInt64) -> Data {
    var d = Data(count: n)
    d.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
        var rng = SplitMix64(state: seed)
        var i = 0
        while i + 8 <= n {
            raw.storeBytes(of: rng.next(), toByteOffset: i, as: UInt64.self)
            i += 8
        }
        while i < n { raw[i] = UInt8(truncatingIfNeeded: rng.next()); i += 1 }
    }
    return d
}

private struct LinkConfig: Sendable {
    var drop = 0.0
    var reorder = 0.0
    var reorderDelay = 0.004
    var seed: UInt64 = 1
}

/// Counters for an impaired link.
private final class LinkStats: @unchecked Sendable {
    var sent = 0, dropped = 0, delayed = 0, maxDatagram = 0, sendFailures = 0, wireSent = 0, received = 0
}

/// A UTPManager wired to a real UDP socket on 127.0.0.1.
///
/// NOTE: endpoints that talk to each other must share ONE EventLoop: the foundation's
/// `ReadScratch.shared` receive buffer is process-global, so sockets drained on two
/// different loops concurrently corrupt each other's datagrams.
private final class Endpoint: @unchecked Sendable {
    let loop: EventLoop
    let socket: UDPSocket
    let manager: UTPManager
    let stats = LinkStats()
    var addr: PeerAddress { PeerAddress(ip: .v4(0x7F00_0001), port: socket.port) }

    init(_ name: String, loop: EventLoop, link: LinkConfig? = nil) throws {
        let sock = try UDPSocket(port: 0, v6: false, loop: loop)
        let rng = Box(SplitMix64(state: link?.seed ?? 1))
        let stats = self.stats
        self.loop = loop
        self.socket = sock
        self.manager = UTPManager(loop: loop) { data, to in
            stats.sent += 1
            stats.maxDatagram = max(stats.maxDatagram, data.count)
            if let link {
                let r = rng.v.unit()
                if r < link.drop { stats.dropped += 1; return }
                if r < link.drop + link.reorder {
                    stats.delayed += 1
                    // Not `loop.schedule`: a discarded LoopTimer is cancelled by its deinit
                    // and never fires (foundation issue), which would turn reorder into loss.
                    loop.queue.asyncAfter(deadline: .now() + link.reorderDelay) {
                        if !sock.send(data, to: to) { stats.sendFailures += 1 } else { stats.wireSent += 1 }
                    }
                    return
                }
            }
            if !sock.send(data, to: to) { stats.sendFailures += 1 } else { stats.wireSent += 1 }
        }
        let m = manager
        sock.onDatagram = { [weak m] d, from in stats.received += 1; _ = m?.handle(d, from: from) }
        loop.sync { sock.start() }   // sockets are loop-confined
    }

    func shutdown() {
        loop.sync {
            manager.closeAll()
            socket.close()
        }
    }
}

/// Poll `cond` on `loop` until true or timeout.
private func waitUntil(_ loop: EventLoop, timeout: Double, _ cond: @escaping () -> Bool) async -> Bool {
    let deadline = monotonicNow() + timeout
    while monotonicNow() < deadline {
        if loop.sync(cond) { return true }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return loop.sync(cond)
}

/// Writes `data` respecting back-pressure (pendingWriteBytes / onWritable).
private final class Pump: @unchecked Sendable {
    let data: Data
    let stream: UTPStream
    var off = 0
    let chunk: Int
    init(_ stream: UTPStream, _ data: Data, chunk: Int = 64 * 1024) {
        self.stream = stream
        self.data = data
        self.chunk = chunk
    }
    func start() {
        stream.onWritable = { [weak self] in self?.run() }
        run()
    }
    func run() {
        while off < data.count && stream.pendingWriteBytes < 256 * 1024 {
            let n = min(chunk, data.count - off)
            stream.write(data.subdata(in: off..<(off + n)))
            off += n
        }
    }
}

/// Bidirectional bulk transfer between two endpoints; returns elapsed seconds.
private func bulkTransfer(size: Int, linkA: LinkConfig?, linkB: LinkConfig?, timeout: Double,
                          maxPayload: Int = 1200) async throws -> (secs: Double, a: Endpoint, b: Endpoint,
                                                                   retransmits: Int64, timeouts: Int64) {
    let loop = EventLoop(label: "utp.test.bulk")
    let a = try Endpoint("A", loop: loop, link: linkA)
    let b = try Endpoint("B", loop: loop, link: linkB)
    let dataAB = payload(size, seed: 0xA11CE)
    let dataBA = payload(size, seed: 0xB0B)
    let recvB = Box(Data(capacity: size))
    let recvA = Box(Data(capacity: size))
    let errB = Box<String?>(nil), errA = Box<String?>(nil)
    let streamA = Box<UTPStream?>(nil), streamB = Box<UTPStream?>(nil)
    let pumps = Box<[Pump]>([])
    let start = monotonicNow()

    b.loop.sync {
        b.manager.maxPayload = maxPayload
        b.manager.onAccept = { s in
            streamB.v = s
            s.onRead = { recvB.v.append($0) }
            s.onClose = { e in errB.v = "B closed: \(String(describing: e))" }
            let p = Pump(s, dataBA)
            pumps.v.append(p)
            p.start()
        }
    }
    let bAddr = b.addr
    a.loop.sync {
        a.manager.maxPayload = maxPayload
        a.manager.connect(to: bAddr, timeout: 5) { r in
            switch r {
            case .success(let s):
                streamA.v = s
                s.onRead = { recvA.v.append($0) }
                s.onClose = { e in errA.v = "A closed: \(String(describing: e))" }
                let p = Pump(s, dataAB)
                pumps.v.append(p)
                p.start()
            case .failure(let e):
                errA.v = "connect failed: \(e)"
            }
        }
    }
    let okB = await waitUntil(b.loop, timeout: timeout) { recvB.v.count >= size || errB.v != nil }
    let okA = await waitUntil(a.loop, timeout: timeout) { recvA.v.count >= size || errA.v != nil }
    let secs = monotonicNow() - start
    #expect(okA && okB, "transfer timed out: A got \(a.loop.sync { recvA.v.count }), B got \(b.loop.sync { recvB.v.count })")
    #expect(a.loop.sync { errA.v } == nil)
    #expect(b.loop.sync { errB.v } == nil)
    let gotB = b.loop.sync { recvB.v }
    let gotA = a.loop.sync { recvA.v }
    #expect(gotB.count == size && gotB == dataAB, "A→B data mismatch")
    #expect(gotA.count == size && gotA == dataBA, "B→A data mismatch")
    let rtx = a.loop.sync { streamA.v?.retransmits ?? 0 } + b.loop.sync { streamB.v?.retransmits ?? 0 }
    let rtos = a.loop.sync { streamA.v?.timeouts ?? 0 } + b.loop.sync { streamB.v?.timeouts ?? 0 }

    // Graceful close from A: B must see a clean EOF, A no callback; both tables drain.
    let aClosedCB = Box(false)
    let bEOF = Box<SocketError??>(nil)
    b.loop.sync { streamB.v?.onClose = { e in bEOF.v = .some(e) } }
    a.loop.sync {
        streamA.v?.onClose = { _ in aClosedCB.v = true }
        streamA.v?.close()
    }
    let eof = await waitUntil(b.loop, timeout: 10) { bEOF.v != nil }
    #expect(eof, "B did not observe EOF")
    #expect(b.loop.sync { bEOF.v.flatMap { $0 } } == nil, "EOF should be clean (nil error)")
    let drainedA = await waitUntil(a.loop, timeout: 10) { a.manager.connectionCount == 0 }
    let drainedB = await waitUntil(b.loop, timeout: 10) { b.manager.connectionCount == 0 }
    #expect(drainedA && drainedB, "connections not torn down after FIN exchange")
    #expect(a.loop.sync { aClosedCB.v } == false, "onClose must not fire after owner close()")
    return (secs, a, b, rtx, rtos)
}

// MARK: - Unit tests

@Suite struct UTPCodecTests {
    @Test func headerRoundTrip() throws {
        let h = UTPHeader(type: .data, connectionID: 0xBEEF, timestamp: 0x0102_0304, timestampDiff: 0xA0B0_C0D0,
                          windowSize: 1 << 20, seqNr: 0xFFFE, ackNr: 7)
        let d = UTPCodec.encode(h, payload: Data([9, 8, 7]))
        #expect(d.count == 23)
        #expect(Array(d.prefix(20)) == [0x01, 0x00, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                                        0xA0, 0xB0, 0xC0, 0xD0, 0x00, 0x10, 0x00, 0x00,
                                        0xFF, 0xFE, 0x00, 0x07])
        let p = try #require(UTPCodec.parse(d))
        #expect(p.header == h)
        #expect(p.sack == nil)
        #expect(p.payloadOffset == 20 && p.payloadCount == 3)

        // Type nibble for each packet type; header byte = type << 4 | 1.
        for (t, b): (UTPType, UInt8) in [(.data, 0x01), (.fin, 0x11), (.state, 0x21), (.reset, 0x31), (.syn, 0x41)] {
            let e = UTPCodec.encode(UTPHeader(type: t, connectionID: 1, seqNr: 2, ackNr: 3))
            #expect(e.first == b)
            #expect(UTPCodec.parse(e)?.header.type == t)
        }
    }

    @Test func extensionChainAndSack() throws {
        let h = UTPHeader(type: .state, connectionID: 5, seqNr: 10, ackNr: 20)
        let d = UTPCodec.encode(h, sack: [0b0000_0101, 0, 0, 0x80])
        #expect(d.count == 20 + 2 + 4)
        #expect(d[1] == 1)   // first extension = selective ack
        let p = try #require(UTPCodec.parse(d))
        let r = try #require(p.sack)
        #expect(Array(d[r]) == [0b0000_0101, 0, 0, 0x80])
        #expect(UTPSack.decode(ackNr: 20, mask: d[r]) == [22, 24, 53])

        // Unknown extension (type 2, 8 bytes) followed by SACK, then payload.
        var raw = Data(UTPCodec.encode(UTPHeader(type: .data, connectionID: 1, seqNr: 1, ackNr: 1)))
        raw[1] = 2
        raw.append(contentsOf: [1, 8, 0, 0, 0, 0, 0, 0, 0, 0])       // ext 2 → next is 1, len 8
        raw.append(contentsOf: [0, 4, 0xFF, 0, 0, 0])               // ext 1 → end, len 4
        raw.append(contentsOf: [0xAA, 0xBB])
        let q = try #require(UTPCodec.parse(raw))
        #expect(q.sack.map { Array(raw[$0]) } == [0xFF, 0, 0, 0])
        #expect(q.payloadCount == 2 && raw[q.payloadOffset] == 0xAA)
    }

    @Test func rejectsGarbage() {
        #expect(UTPCodec.parse(Data()) == nil)
        #expect(UTPCodec.parse(Data(repeating: 0x01, count: 19)) == nil)
        var bad = UTPCodec.encode(UTPHeader(type: .data, connectionID: 1, seqNr: 1, ackNr: 1))
        bad[0] = 0x02                                         // version 2
        #expect(UTPCodec.parse(bad) == nil)
        bad[0] = 0x51                                         // type 5
        #expect(UTPCodec.parse(bad) == nil)
        var trunc = UTPCodec.encode(UTPHeader(type: .data, connectionID: 1, seqNr: 1, ackNr: 1))
        trunc[1] = 1                                          // claims an extension
        #expect(UTPCodec.parse(trunc) == nil)
        trunc.append(contentsOf: [0, 10, 1, 2])               // len 10 but only 2 bytes
        #expect(UTPCodec.parse(trunc) == nil)
        #expect(UTPCodec.parse(Data("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".utf8)) == nil)
    }

    @Test func sequenceWrapMath() {
        #expect(UTPSeq.lt(65535, 0))
        #expect(UTPSeq.lt(65000, 100))
        #expect(!UTPSeq.lt(0, 65535))
        #expect(!UTPSeq.lt(5, 5) && UTPSeq.lte(5, 5))
        #expect(UTPSeq.gt(3, 65533))
        #expect(UTPSeq.dist(65530, 5) == 11)
        #expect(UTPSeq.dist(5, 5) == 0)
        #expect(UTPSeq.dist(10, 9) == 65535)
        #expect(utpLess32(0xFFFF_FFF0, 0x10))
        #expect(!utpLess32(0x10, 0xFFFF_FFF0))
    }

    @Test func sackBitmaskEncodeDecode() {
        // Bit i (byte i/8, LSB first) acknowledges ack_nr + 2 + i, across the wrap.
        // ack 65534 → ack+2 wraps to seq 0, so seq s maps to bit s.
        let ack: UInt16 = 65534
        let have: Set<UInt16> = [0, 1, 7, 39]
        let mask = UTPSack.encode(ackNr: ack) { have.contains($0) }
        #expect(mask == [0b1000_0011, 0, 0, 0, 0x80, 0, 0, 0])   // bit 39 → byte 4, bit 7
        // ack+1 (seq 65535) is never representable; ack itself neither.
        #expect(UTPSack.encode(ackNr: ack) { $0 == 65535 || $0 == 65534 }.isEmpty)
        let decoded = UTPSack.decode(ackNr: ack, mask: mask)
        #expect(Set(decoded) == have)
        #expect(UTPSack.encode(ackNr: 10) { _ in false }.isEmpty)
        // Exactly 32 bits → one word; bit 32 → two words.
        #expect(UTPSack.encode(ackNr: 0) { $0 == 33 }.count == 4)
        #expect(UTPSack.encode(ackNr: 0) { $0 == 34 }.count == 8)
        // Never more than 32 bytes.
        #expect(UTPSack.encode(ackNr: 0) { _ in true }.count == 32)
    }

    @Test func seqRingGrowsAcrossWrap() {
        var ring = UTPSeqRing<Int>(capacity: 16)
        let base: UInt16 = 65530
        for i in 0..<16 { ring[base &+ UInt16(i)] = i }
        ring.reserve(span: 40, base: base)
        #expect(ring.capacity >= 40)
        for i in 0..<16 { #expect(ring[base &+ UInt16(i)] == i) }
        for i in 16..<40 { #expect(ring[base &+ UInt16(i)] == nil) }
    }

    @Test func byteQueueReadsAcrossChunks() {
        var q = UTPByteQueue()
        q.append(Data([1, 2, 3]))
        q.append(Data([4, 5, 6, 7, 8])[1...])   // non-zero startIndex slice
        q.append(Data([9]))
        #expect(q.count == 8)
        var out = [UInt8](repeating: 0, count: 5)
        let n = out.withUnsafeMutableBytes { q.read(into: $0.baseAddress!, 5) }
        #expect(n == 5 && out == [1, 2, 3, 5, 6])
        var rest = [UInt8](repeating: 0, count: 10)
        let m = rest.withUnsafeMutableBytes { q.read(into: $0.baseAddress!, 10) }
        #expect(m == 3 && Array(rest[0..<3]) == [7, 8, 9] && q.isEmpty)
    }

    @Test func delayHistoryTracksBase() {
        var h = UTPDelayHistory()
        h.add(1_000_000, now: 0)
        h.add(1_050_000, now: 1)
        h.add(1_020_000, now: 2)
        h.add(1_030_000, now: 3)
        #expect(h.base == 1_000_000)
        #expect(h.current == 20_000)
        h.add(900_000, now: 4)   // lower base observed
        #expect(h.base == 900_000)
        #expect(h.current == 0)
    }
}

// MARK: - Manager-level behaviour (no sockets)

@Suite struct UTPManagerUnitTests {
    @Test func garbageNeverCrashesAndNonUTPIsNotConsumed() {
        let loop = EventLoop(label: "utp.garbage")
        let sent = Box(0)
        let m = UTPManager(loop: loop) { _, _ in sent.v += 1 }
        let from = PeerAddress(ip: .v4(0x0A00_0001), port: 6881)
        loop.sync {
            m.onAccept = { s in s.close() }
            #expect(m.handle(Data("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".utf8), from: from) == false)
            #expect(m.handle(Data(), from: from) == false)
            var rng = SplitMix64(state: 42)
            for i in 0..<20_000 {
                let len = Int(rng.next() % 64)
                var d = Data(count: len)
                for j in 0..<len { d[j] = UInt8(truncatingIfNeeded: rng.next()) }
                if len >= 1 && i % 2 == 0 {
                    d[0] = UInt8(rng.next() % 5) << 4 | 1   // plausible uTP type/version
                    if len >= 2 && i % 4 == 0 { d[1] = 0 }
                }
                _ = m.handle(d, from: PeerAddress(ip: .v4(UInt32(truncatingIfNeeded: rng.next() % 4)), port: 1))
            }
            m.closeAll()
            #expect(m.connectionCount == 0)
        }
    }

    @Test func unknownConnectionGetsReset() throws {
        let loop = EventLoop(label: "utp.rst")
        let out = Box<[(Data, PeerAddress)]>([])
        let m = UTPManager(loop: loop) { d, to in out.v.append((d, to)) }
        let from = PeerAddress(ip: .v4(0x0A00_0002), port: 1234)
        loop.sync {
            let data = UTPCodec.encode(UTPHeader(type: .data, connectionID: 777, seqNr: 4242, ackNr: 1),
                                       payload: Data([1, 2, 3]))
            #expect(m.handle(data, from: from))
            // STATE and RESET for unknown connections are consumed silently.
            #expect(m.handle(UTPCodec.encode(UTPHeader(type: .state, connectionID: 9, seqNr: 1, ackNr: 1)), from: from))
            #expect(m.handle(UTPCodec.encode(UTPHeader(type: .reset, connectionID: 9, seqNr: 1, ackNr: 1)), from: from))
        }
        let sent = loop.sync { out.v }
        #expect(sent.count == 1)
        let rst = try #require(sent.first.flatMap { UTPCodec.parse($0.0) })
        #expect(rst.header.type == .reset)
        #expect(rst.header.connectionID == 777)
        #expect(rst.header.ackNr == 4242)
        #expect(sent.first?.1 == from)
    }

    @Test func synIsAcceptedWithCorrectConnectionIDs() throws {
        let loop = EventLoop(label: "utp.syn")
        let out = Box<[Data]>([])
        let accepted = Box<UTPStream?>(nil)
        let m = UTPManager(loop: loop) { d, _ in out.v.append(d) }
        let from = PeerAddress(ip: .v4(0x0A00_0003), port: 999)
        loop.sync {
            m.onAccept = { accepted.v = $0 }
            let syn = UTPCodec.encode(UTPHeader(type: .syn, connectionID: 1000, timestamp: microsNow32(),
                                                windowSize: 65536, seqNr: 50, ackNr: 0))
            #expect(m.handle(syn, from: from))
            #expect(m.connectionCount == 1)
            // Duplicate SYN must not create a second connection; it is re-acked.
            #expect(m.handle(syn, from: from))
            #expect(m.connectionCount == 1)
        }
        try? await_(0.05)
        let pkts = loop.sync { out.v }.compactMap { UTPCodec.parse($0) }
        #expect(pkts.count >= 2)
        let synAck = try #require(pkts.first)
        #expect(synAck.header.type == .state)
        #expect(synAck.header.connectionID == 1000)        // responder sends with send_id = SYN id
        #expect(synAck.header.ackNr == 50)
        #expect(pkts[1].header.seqNr == synAck.header.seqNr)
        let s = try #require(loop.sync { accepted.v })
        #expect(s.recvID == 1001 && s.sendID == 1000)
        #expect(s.transport == .utp)
        loop.sync { m.closeAll() }
    }
}

/// Blocking sleep helper for non-async tests (tiny durations only).
private func await_(_ secs: Double) throws { usleep(useconds_t(secs * 1_000_000)) }

/// Two managers on one loop wired directly through closures (no sockets), with a
/// switch to cut the link and a log of every datagram A sends.
private final class WiredPair: @unchecked Sendable {
    let loop = EventLoop(label: "utp.test.wired")
    var a: UTPManager!
    var b: UTPManager!
    let aAddr = PeerAddress(ip: .v4(0x0A00_0001), port: 1111)
    let bAddr = PeerAddress(ip: .v4(0x0A00_0002), port: 2222)
    var linkUp = true
    var aSent: [UTPPacket] = []

    init() {
        a = UTPManager(loop: loop) { [weak self] d, _ in
            guard let self else { return }
            if let p = UTPCodec.parse(d) { self.aSent.append(p) }
            guard self.linkUp else { return }
            self.loop.execute { [weak self] in guard let self else { return }; _ = self.b.handle(d, from: self.aAddr) }
        }
        b = UTPManager(loop: loop) { [weak self] d, _ in
            guard let self, self.linkUp else { return }
            self.loop.execute { [weak self] in guard let self else { return }; _ = self.a.handle(d, from: self.bAddr) }
        }
    }

    /// Connect A→B; returns (A's stream, B's stream).
    func connect() async -> (UTPStream?, UTPStream?) {
        let sa = Box<UTPStream?>(nil), sb = Box<UTPStream?>(nil)
        loop.sync {
            b.onAccept = { sb.v = $0 }
            a.connect(to: bAddr, timeout: 3) { if case .success(let s) = $0 { sa.v = s } }
        }
        _ = await waitUntil(loop, timeout: 3) { sa.v != nil && sb.v != nil }
        return loop.sync { (sa.v, sb.v) }
    }
}

@Suite struct UTPTimerTests {
    @Test func keepAliveAfterIdle() async throws {
        let w = WiredPair()
        let (sa, sb) = await w.connect()
        let a = try #require(sa)
        _ = try #require(sb)
        let n = w.loop.sync { () -> Int in
            let before = w.aSent.count
            a.tick(now: utpNowMicros() + 30_000_000)        // 30 s of silence
            return w.aSent.count - before
        }
        #expect(n == 1)
        let last = try #require(w.loop.sync { w.aSent.last })
        #expect(last.header.type == .state && last.payloadCount == 0)
        w.loop.sync { w.a.closeAll(); w.b.closeAll() }
    }

    @Test func rtoBackoffThenDeath() async throws {
        let w = WiredPair()
        let (sa, _) = await w.connect()
        let a = try #require(sa)
        let err = Box<SocketError??>(nil)
        let sentAt = Box<[Int]>([])
        w.loop.sync {
            a.onClose = { err.v = .some($0) }
            w.linkUp = false
            a.write(Data(repeating: 7, count: 5000))
        }
        try? await Task.sleep(nanoseconds: 20_000_000)      // let the deferred flush run
        // Drive the clock forward; record when each retransmission happens.
        w.loop.sync {
            var t = utpNowMicros()
            var lastCount = w.aSent.count
            for step in 0..<2000 where err.v == nil {
                t += 50_000                                  // 50 ms ticks
                a.tick(now: t)
                if w.aSent.count != lastCount { sentAt.v.append(step); lastCount = w.aSent.count }
            }
        }
        let e = w.loop.sync { err.v.flatMap { $0 } }
        #expect(e?.code == ETIMEDOUT, "connection should die after repeated timeouts")
        // Gaps between retransmission events grow (exponential backoff).
        let steps = w.loop.sync { sentAt.v }
        let gaps = zip(steps.dropFirst(), steps).map { $0 - $1 }
        #expect(gaps.count >= 4)
        // Each gap doubles (RTO backoff), no probes squeezed in between.
        for (g1, g2) in zip(gaps, gaps.dropFirst()) { #expect(g2 >= 2 * g1 - 1, "gaps \(gaps)") }
        #expect(w.loop.sync { w.a.connectionCount } == 0)
        w.loop.sync { w.b.closeAll() }
    }

    /// Protocol-engine throughput without syscalls (both endpoints on one core).
    /// Run with ASTOR_BENCH=1 (ideally `-c release -Xswiftc -enable-testing`).
    @Test(.enabled(if: ProcessInfo.processInfo.environment["ASTOR_BENCH"] == "1"))
    func inMemoryThroughputBenchmark() async throws {
        let w = WiredPair()
        let size = 256 << 20
        let blob = payload(1 << 20, seed: 1)
        let got = Box(0)
        let (sa, sb) = await w.connect()
        let a = try #require(sa)
        let b = try #require(sb)
        w.loop.sync { b.onRead = { got.v += $0.count } }
        let sent = Box(0)
        let t0 = monotonicNow()
        w.loop.sync {
            func pump() {
                while sent.v < size && a.pendingWriteBytes < 1 << 20 { a.write(blob); sent.v += blob.count }
            }
            a.onWritable = { pump() }
            pump()
        }
        #expect(await waitUntil(w.loop, timeout: 120) { got.v >= size })
        let secs = monotonicNow() - t0
        print("uTP in-memory engine: \(size >> 20) MiB in \(String(format: "%.2f", secs)) s = \(String(format: "%.0f", Double(size) / secs / 1_048_576)) MiB/s (sender+receiver on one core); \(w.loop.sync { a.debugState })")
        w.loop.sync { w.a.closeAll(); w.b.closeAll() }
    }

    @Test func receiveWindowFlowControl() async throws {
        let w = WiredPair()
        let (sa, sb) = await w.connect()
        let a = try #require(sa)
        let b = try #require(sb)
        let blob = payload(4 << 20, seed: 77)
        w.loop.sync { a.write(blob) }                       // B has no onRead: data is held
        try? await Task.sleep(nanoseconds: 300_000_000)
        let (acked, pending) = w.loop.sync { (a.bytesSent, a.pendingWriteBytes) }
        #expect(acked <= Int64(UTPStream.recvWindow + 64 * 1024), "sender ignored the receive window: \(acked)")
        #expect(acked >= Int64(UTPStream.recvWindow / 2))
        #expect(pending > 2 << 20)
        let got = Box(Data())
        w.loop.sync { b.onRead = { got.v.append($0) } }     // drain → window update → resume
        #expect(await waitUntil(w.loop, timeout: 5) { got.v.count == blob.count })
        #expect(w.loop.sync { got.v } == blob)
        w.loop.sync { w.a.closeAll(); w.b.closeAll() }
    }

    @Test func dataArrivingBeforeOnReadIsHeld() async throws {
        let w = WiredPair()
        let got = Box(Data())
        let bStream = Box<UTPStream?>(nil)
        let sa = Box<UTPStream?>(nil)
        w.loop.sync {
            w.b.onAccept = { s in bStream.v = s }            // no callbacks installed yet
            w.a.connect(to: w.bAddr, timeout: 3) { r in
                if case .success(let s) = r { sa.v = s; s.write(Data("early bytes".utf8)) }
            }
        }
        #expect(await waitUntil(w.loop, timeout: 3) { bStream.v != nil && sa.v != nil })
        try? await Task.sleep(nanoseconds: 50_000_000)
        w.loop.sync { bStream.v?.onRead = { got.v.append($0) } }
        #expect(await waitUntil(w.loop, timeout: 2) { got.v == Data("early bytes".utf8) })
        w.loop.sync { w.a.closeAll(); w.b.closeAll() }
    }
}

// MARK: - Loopback integration (real UDP sockets on 127.0.0.1)

/// Every suite that opens real UDP sockets runs serially under this parent: the
/// foundation's process-global `ReadScratch` receive buffer is unsafe across EventLoops.
@Suite(.serialized) struct UTPSocketTests {}

extension UTPSocketTests {
@Suite(.serialized) struct Loopback {
    @Test func bulkTransfer16MBBothDirections() async throws {
        let size = 16 << 20
        let r = try await bulkTransfer(size: size, linkA: nil, linkB: nil, timeout: 40)
        let mbps = Double(2 * size) / r.secs / 1_048_576
        print("uTP loopback: 2×16 MiB in \(String(format: "%.2f", r.secs)) s = \(String(format: "%.1f", mbps)) MiB/s aggregate, retransmits \(r.retransmits), RTOs \(r.timeouts), max datagram A \(r.a.stats.maxDatagram) B \(r.b.stats.maxDatagram)")
        #expect(r.a.stats.maxDatagram <= 1220 && r.b.stats.maxDatagram <= 1220)
        r.a.shutdown()
        r.b.shutdown()
    }

    @Test func bulkTransferLossyReorderingLink() async throws {
        let size = 16 << 20
        let la = LinkConfig(drop: 0.04, reorder: 0.03, reorderDelay: 0.003, seed: 7)
        let lb = LinkConfig(drop: 0.04, reorder: 0.03, reorderDelay: 0.003, seed: 11)
        let r = try await bulkTransfer(size: size, linkA: la, linkB: lb, timeout: 90)
        let mbps = Double(2 * size) / r.secs / 1_048_576
        print("uTP lossy (4% drop, 3% reorder each way): 2×16 MiB in \(String(format: "%.2f", r.secs)) s = \(String(format: "%.1f", mbps)) MiB/s, retransmits \(r.retransmits), RTOs \(r.timeouts); A sent \(r.a.stats.sent) dropped \(r.a.stats.dropped) delayed \(r.a.stats.delayed); B sent \(r.b.stats.sent) dropped \(r.b.stats.dropped) delayed \(r.b.stats.delayed)")
        #expect(r.a.stats.dropped > 0 && r.b.stats.delayed > 0)
        // Every datagram handed to the kernel was delivered: losses are only the injected ones.
        #expect(r.a.stats.wireSent == r.b.stats.received && r.b.stats.wireSent == r.a.stats.received)
        r.a.shutdown()
        r.b.shutdown()
    }

    @Test func bulkTransferHarshLink() async throws {
        // 8% loss + 5% reordering (10 ms) both ways, 4 MiB each direction.
        let size = 4 << 20
        let la = LinkConfig(drop: 0.08, reorder: 0.05, reorderDelay: 0.010, seed: 21)
        let lb = LinkConfig(drop: 0.08, reorder: 0.05, reorderDelay: 0.010, seed: 22)
        let r = try await bulkTransfer(size: size, linkA: la, linkB: lb, timeout: 60)
        let mbps = Double(2 * size) / r.secs / 1_048_576
        print("uTP harsh (8% drop, 5% reorder each way): 2×4 MiB in \(String(format: "%.2f", r.secs)) s = \(String(format: "%.1f", mbps)) MiB/s, retransmits \(r.retransmits), RTOs \(r.timeouts)")
        r.a.shutdown()
        r.b.shutdown()
    }

    @Test func smallPayloadSetting() async throws {
        // A lower maxPayload (e.g. a 576-byte path) must be honoured exactly.
        let r = try await bulkTransfer(size: 1 << 20, linkA: nil, linkB: nil, timeout: 20, maxPayload: 500)
        #expect(r.a.stats.maxDatagram <= 520 && r.b.stats.maxDatagram <= 520)
        r.a.shutdown()
        r.b.shutdown()
    }

    @Test func resetTearsDownPeer() async throws {
        let loop = EventLoop(label: "utp.test.rst")
        let a = try Endpoint("RA", loop: loop), b = try Endpoint("RB", loop: loop)
        defer { a.shutdown(); b.shutdown() }
        let aErr = Box<SocketError??>(nil)
        let bErr = Box<SocketError??>(nil)
        let connected = Box(false)
        let accepted = Box(false)
        b.loop.sync {
            b.manager.onAccept = { s in
                accepted.v = true
                s.onRead = { _ in }
                s.onClose = { bErr.v = .some($0) }
            }
        }
        let bAddr = b.addr
        a.loop.sync {
            a.manager.connect(to: bAddr, timeout: 5) { r in
                guard case .success(let s) = r else { return }
                connected.v = true
                s.onRead = { _ in }
                s.onClose = { aErr.v = .some($0) }
                s.write(Data("hello".utf8))
            }
        }
        #expect(await waitUntil(a.loop, timeout: 5) { connected.v })
        #expect(await waitUntil(b.loop, timeout: 5) { accepted.v })
        try? await Task.sleep(nanoseconds: 100_000_000)
        b.loop.sync { b.manager.closeAll() }          // sends RESET
        #expect(await waitUntil(a.loop, timeout: 5) { aErr.v != nil })
        let e = a.loop.sync { aErr.v.flatMap { $0 } }
        #expect(e?.code == ECONNRESET)
        #expect(b.loop.sync { bErr.v.flatMap { $0 }?.code } == ECANCELED)
        #expect(await waitUntil(a.loop, timeout: 2) { a.manager.connectionCount == 0 })
    }

    @Test func connectRefusedByReset() async throws {
        // A manager without onAccept answers SYN with RESET → connect fails fast.
        let loop = EventLoop(label: "utp.test.refused")
        let a = try Endpoint("CA", loop: loop), b = try Endpoint("CB", loop: loop)
        defer { a.shutdown(); b.shutdown() }
        let result = Box<Result<UTPStream, SocketError>?>(nil)
        let bAddr = b.addr
        let t0 = monotonicNow()
        a.loop.sync { a.manager.connect(to: bAddr, timeout: 5) { result.v = $0 } }
        #expect(await waitUntil(a.loop, timeout: 5) { result.v != nil })
        #expect(monotonicNow() - t0 < 1.0)
        if case .failure(let e) = a.loop.sync({ result.v }) { #expect(e.code == ECONNREFUSED) } else { Issue.record("expected failure") }
    }

    @Test func connectTimeoutToDeadPort() async throws {
        let deadLoop = EventLoop(label: "utp.test.dead")
        let a = try Endpoint("TA", loop: deadLoop)
        // A bound UDP socket that silently swallows everything (counts SYNs).
        let dead = try UDPSocket(port: 0, v6: false, loop: deadLoop)
        let syns = Box(0)
        dead.onDatagram = { d, _ in if UTPCodec.parse(d)?.header.type == .syn { syns.v += 1 } }
        deadLoop.sync { dead.start() }
        defer { a.shutdown(); deadLoop.sync { dead.close() } }
        let result = Box<Result<UTPStream, SocketError>?>(nil)
        let target = PeerAddress(ip: .v4(0x7F00_0001), port: dead.port)
        let t0 = monotonicNow()
        a.loop.sync { a.manager.connect(to: target, timeout: 2.5) { result.v = $0 } }
        #expect(await waitUntil(a.loop, timeout: 6) { result.v != nil })
        let elapsed = monotonicNow() - t0
        #expect(elapsed >= 2.4 && elapsed < 3.5, "elapsed \(elapsed)")
        if case .failure(let e) = a.loop.sync({ result.v }) { #expect(e.code == ETIMEDOUT) } else { Issue.record("expected timeout") }
        #expect(deadLoop.sync { syns.v } >= 2, "SYN should be retransmitted")
        #expect(a.loop.sync { a.manager.connectionCount } == 0)
    }

    @Test func remoteCloseDeliversAllDataThenEOF() async throws {
        // Responder writes then closes immediately; initiator must get every byte, then EOF.
        let loop = EventLoop(label: "utp.test.fin")
        let a = try Endpoint("FA", loop: loop, link: LinkConfig(drop: 0.05, reorder: 0.05, seed: 3))
        let b = try Endpoint("FB", loop: loop, link: LinkConfig(drop: 0.05, reorder: 0.05, seed: 5))
        defer { a.shutdown(); b.shutdown() }
        let blob = payload(300_000, seed: 99)
        let got = Box(Data())
        let eof = Box<SocketError??>(nil)
        b.loop.sync {
            b.manager.onAccept = { s in
                s.onRead = { _ in }
                s.write(blob)
                s.close()
            }
        }
        let bAddr = b.addr
        a.loop.sync {
            a.manager.connect(to: bAddr, timeout: 5) { r in
                guard case .success(let s) = r else { return }
                s.onRead = { got.v.append($0) }
                s.onClose = { eof.v = .some($0) }
                s.write(Data("hi".utf8))
            }
        }
        #expect(await waitUntil(a.loop, timeout: 20) { eof.v != nil })
        #expect(a.loop.sync { got.v } == blob)
        #expect(a.loop.sync { eof.v.flatMap { $0 } } == nil)
        #expect(await waitUntil(b.loop, timeout: 10) { b.manager.connectionCount == 0 })
        #expect(await waitUntil(a.loop, timeout: 10) { a.manager.connectionCount == 0 })
    }
}
}

// MARK: - Live interop with Transmission (libutp). Run with ASTOR_LIVE=1.

/// Minimal BitTorrent wire-protocol driver over a uTP stream (test-only).
private final class MiniPeer: @unchecked Sendable {
    let stream: UTPStream
    private var buf = Data()
    private var off = 0
    private(set) var remoteHandshake: Data?
    var onHandshake: ((Data) -> Void)?
    var onMessage: ((UInt8, Data) -> Void)?
    private(set) var closed: String?
    private(set) var received = 0

    init(_ stream: UTPStream) {
        self.stream = stream
        stream.onRead = { [weak self] in self?.feed($0) }
        stream.onClose = { [weak self] e in self?.closed = "closed: \(String(describing: e))" }
    }

    static func handshake(infoHash: Data) -> Data {
        var hs = Data([19])
        hs.append(Data("BitTorrent protocol".utf8))
        hs.append(Data([0, 0, 0, 0, 0, 0x10, 0, 0]))
        hs.append(infoHash)
        hs.append(Data("-AS0100-".utf8))
        hs.append(Data.random(12))
        return hs
    }

    func send(_ id: UInt8, _ payload: Data = Data()) {
        var m = Data(capacity: 5 + payload.count)
        m.appendBE32(UInt32(1 + payload.count))
        m.append(id)
        m.append(payload)
        stream.write(m)
    }

    private func feed(_ d: Data) {
        received += d.count
        buf.append(d)
        if remoteHandshake == nil {
            guard buf.count - off >= 68 else { return }
            let hs = buf.subdata(in: off..<(off + 68))
            off += 68
            remoteHandshake = hs
            onHandshake?(hs)
        }
        while buf.count - off >= 4 {
            let len = Int(buf.be32(off))
            guard buf.count - off >= 4 + len else { break }
            if len > 0 {
                let id = buf.byte(off + 4)
                let payload = buf.subdata(in: (off + 5)..<(off + 4 + len))
                off += 4 + len
                onMessage?(id, payload)
            } else {
                off += 4
            }
        }
        if off > 0 && off >= buf.count / 2 {
            buf.removeSubrange(0..<off)
            off = 0
        }
    }
}

/// A transmission-cli process with an isolated config dir, uTP only.
private final class TransmissionProcess {
    let process = Process()
    let logURL: URL
    let port: UInt16

    init(torrent: URL, downloadDir: URL, workDir: URL) throws {
        let fm = FileManager.default
        let cfg = workDir.appendingPathComponent("config-\(UInt32.random(in: 0...UInt32.max))")
        try fm.createDirectory(at: cfg, withIntermediateDirectories: true)
        port = UInt16.random(in: 40000...59000)
        let settings = """
        {"utp-enabled": true, "tcp-enabled": false, "dht-enabled": false, "lpd-enabled": false,
         "pex-enabled": false, "port-forwarding-enabled": false, "encryption": 1,
         "speed-limit-up-enabled": false, "speed-limit-down-enabled": false,
         "peer-port": \(port), "message-level": 4}
        """
        try settings.write(to: cfg.appendingPathComponent("settings.json"), atomically: true, encoding: .utf8)
        logURL = cfg.appendingPathComponent("tr.log")
        fm.createFile(atPath: logURL.path, contents: nil)
        let log = try FileHandle(forWritingTo: logURL)
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/transmission-cli")
        process.arguments = ["-g", cfg.path, "-p", String(port), "-w", downloadDir.path, "-M", torrent.path]
        process.standardOutput = log
        process.standardError = log
        try process.run()
    }

    var logTail: String {
        let s = (try? String(contentsOf: logURL, encoding: .utf8)) ?? ""
        return String(s.suffix(1500))
    }

    func stop() {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
    }
}

private struct InteropFixture {
    let dir: URL
    let file: URL
    let content: Data
    let torrent: URL
    let meta: Metainfo

    init(size: Int, seed: UInt64) throws {
        let fm = FileManager.default
        dir = fm.temporaryDirectory.appendingPathComponent("astor-utp-\(UInt32.random(in: 0...UInt32.max))")
        let src = dir.appendingPathComponent("seed")
        try fm.createDirectory(at: src, withIntermediateDirectories: true)
        file = src.appendingPathComponent("astor-utp-\(seed).bin")
        content = payload(size, seed: seed)
        try content.write(to: file)
        torrent = dir.appendingPathComponent("t.torrent")
        let create = Process()
        create.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/transmission-create")
        create.arguments = ["-o", torrent.path, "-s", "256", file.path]
        create.standardOutput = FileHandle.nullDevice
        create.standardError = FileHandle.nullDevice
        try create.run()
        create.waitUntilExit()
        meta = try Metainfo(torrentFile: Data(contentsOf: torrent))
    }

    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

/// Connect over uTP, retrying while transmission starts up.
private func connectWithRetry(_ ep: Endpoint, port: UInt16, seconds: Double) async -> (UTPStream?, String) {
    let target = PeerAddress(ip: .v4(0x7F00_0001), port: port)
    let deadline = monotonicNow() + seconds
    var lastErr = "?"
    while monotonicNow() < deadline {
        let res = Box<Result<UTPStream, SocketError>?>(nil)
        ep.loop.sync { ep.manager.connect(to: target, timeout: 2) { res.v = $0 } }
        _ = await waitUntil(ep.loop, timeout: 5) { res.v != nil }
        switch ep.loop.sync({ res.v }) {
        case .success(let s)?: return (s, "")
        case .failure(let e)?: lastErr = "\(e)"
        case nil: lastErr = "no completion"
        }
        try? await Task.sleep(nanoseconds: 300_000_000)
    }
    return (nil, lastErr)
}

extension UTPSocketTests {
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1"))
struct Interop {
    /// Handshake + full download of a 4 MiB torrent FROM transmission (libutp → us).
    @Test func downloadFromTransmissionOverUTP() async throws {
        let fx = try InteropFixture(size: 4 << 20, seed: 1234)
        defer { fx.cleanup() }
        let tr = try TransmissionProcess(torrent: fx.torrent, downloadDir: fx.file.deletingLastPathComponent(),
                                         workDir: fx.dir)
        defer { tr.stop() }
        let ep = try Endpoint("interop.dl", loop: EventLoop(label: "utp.test.interop.dl"))
        defer { ep.shutdown() }

        let (s, err) = await connectWithRetry(ep, port: tr.port, seconds: 30)
        let stream = try #require(s, "uTP connect to transmission failed: \(err)\n\(tr.logTail)")
        let meta = fx.meta
        let pieceLen = meta.pieceLength
        var blocks: [(Int, Int, Int)] = []
        for i in 0..<meta.pieceCount {
            var b = 0
            let ps = meta.pieceSize(i)
            while b < ps { blocks.append((i, b, min(16384, ps - b))); b += 16384 }
        }
        let assembled = Box(Data(count: Int(meta.totalLength)))
        let got = Box(0), next = Box(0), outstanding = Box(0)
        let unchoked = Box(false)
        let tUnchoke = Box(0.0), tLast = Box(0.0)
        let peer: MiniPeer = ep.loop.sync {
            let p = MiniPeer(stream)
            func refill() {
                while unchoked.v && outstanding.v < 64 && next.v < blocks.count {
                    let (i, b, l) = blocks[next.v]
                    var req = Data()
                    req.appendBE32(UInt32(i)); req.appendBE32(UInt32(b)); req.appendBE32(UInt32(l))
                    p.send(6, req)
                    next.v += 1
                    outstanding.v += 1
                }
            }
            p.onHandshake = { _ in p.send(2) }      // interested
            p.onMessage = { id, pl in
                switch id {
                case 0: unchoked.v = false
                case 1:
                    unchoked.v = true
                    if tUnchoke.v == 0 { tUnchoke.v = monotonicNow() }
                    refill()
                case 7:
                    let i = Int(pl.be32(0)), b = Int(pl.be32(4))
                    let blk = pl.subdata(in: 8..<pl.count)
                    assembled.v.replaceSubrange((i * pieceLen + b)..<(i * pieceLen + b + blk.count), with: blk)
                    got.v += 1
                    outstanding.v -= 1
                    tLast.v = monotonicNow()
                    refill()
                default: break
                }
            }
            stream.write(MiniPeer.handshake(infoHash: meta.infoHashes.primary))
            return p
        }
        let hsOK = await waitUntil(ep.loop, timeout: 15) { peer.remoteHandshake != nil || peer.closed != nil }
        #expect(hsOK && ep.loop.sync({ peer.remoteHandshake }) != nil, "no handshake: \(ep.loop.sync { peer.closed } ?? "")\n\(tr.logTail)")
        if let hs = ep.loop.sync({ peer.remoteHandshake }) {
            #expect(hs[0] == 19 && hs.subdata(in: 1..<20) == Data("BitTorrent protocol".utf8))
            #expect(hs.subdata(in: 28..<48) == meta.infoHashes.primary)
        }
        let t0 = monotonicNow()
        let r0 = ep.loop.sync { (ep.manager.datagramsReceived, ep.manager.datagramsSent, peer.received) }
        var done = false
        var lastPrint = t0
        while monotonicNow() - t0 < 60 {
            if ep.loop.sync({ got.v == blocks.count || peer.closed != nil }) { done = true; break }
            try? await Task.sleep(nanoseconds: 20_000_000)
            if ProcessInfo.processInfo.environment["ASTOR_UTP_TRACE"] == "1" && monotonicNow() - lastPrint > 1 {
                lastPrint = monotonicNow()
                let st = ep.loop.sync { (ep.manager.datagramsReceived - r0.0, ep.manager.datagramsSent - r0.1, peer.received - r0.2, stream.debugState) }
                print("trace t=\(String(format: "%.1f", lastPrint - t0)) rx=\(st.0) tx=\(st.1) bytes=\(st.2) avg=\(st.0 > 0 ? st.2 / Int(st.0) : 0) \(st.3)")
            }
        }
        let secs = monotonicNow() - t0
        let xfer = ep.loop.sync { tLast.v - tUnchoke.v }
        let size = Double(meta.totalLength)
        print("interop download: \(ep.loop.sync { got.v })/\(blocks.count) blocks; waited \(String(format: "%.2f", secs - xfer)) s for unchoke, transfer \(String(format: "%.3f", xfer)) s = \(String(format: "%.1f", size / max(xfer, 1e-6) / 1_048_576)) MiB/s; \(ep.loop.sync { stream.debugState })")
        #expect(done && ep.loop.sync({ got.v }) == blocks.count, "\(ep.loop.sync { peer.closed } ?? "")\n\(tr.logTail)")
        #expect(ep.loop.sync { assembled.v } == fx.content, "downloaded data mismatch")
        for i in 0..<meta.pieceCount {
            let piece = fx.content.subdata(in: (i * pieceLen)..<(i * pieceLen + meta.pieceSize(i)))
            #expect(Hash.sha1(piece) == meta.v1Pieces[i])
        }
        ep.loop.sync { stream.close() }
        let torn = await waitUntil(ep.loop, timeout: 10) { ep.manager.connectionCount == 0 }
        print("interop download: after close: \(torn ? "torn down" : ep.loop.sync { stream.debugState })")
        #expect(torn)
    }

    /// Transmission downloads a 4 MiB torrent FROM us (us → libutp).
    @Test func uploadToTransmissionOverUTP() async throws {
        let fx = try InteropFixture(size: 4 << 20, seed: 5678)
        defer { fx.cleanup() }
        let leechDir = fx.dir.appendingPathComponent("leech")
        try FileManager.default.createDirectory(at: leechDir, withIntermediateDirectories: true)
        let tr = try TransmissionProcess(torrent: fx.torrent, downloadDir: leechDir, workDir: fx.dir)
        defer { tr.stop() }
        let ep = try Endpoint("interop.ul", loop: EventLoop(label: "utp.test.interop.ul"))
        defer { ep.shutdown() }

        let (s, err) = await connectWithRetry(ep, port: tr.port, seconds: 30)
        let stream = try #require(s, "uTP connect to transmission failed: \(err)\n\(tr.logTail)")
        let meta = fx.meta
        let content = fx.content
        let served = Box(0), haves = Box(Set<Int>())
        let tFirstReq = Box(0.0), tLastReq = Box(0.0)
        let peer: MiniPeer = ep.loop.sync {
            let p = MiniPeer(stream)
            p.onHandshake = { _ in
                p.send(5, Bitfield(count: meta.pieceCount, allSet: true).data)
                p.send(1)                                   // unchoke
            }
            p.onMessage = { id, pl in
                switch id {
                case 2: p.send(1)
                case 4: haves.v.insert(Int(pl.be32(0)))
                case 6:
                    let i = Int(pl.be32(0)), b = Int(pl.be32(4)), l = Int(pl.be32(8))
                    let start = i * meta.pieceLength + b
                    guard l <= 32768, start >= 0, start + l <= content.count else { return }
                    var msg = Data(capacity: 8 + l)
                    msg.appendBE32(UInt32(i)); msg.appendBE32(UInt32(b))
                    msg.append(content.subdata(in: start..<(start + l)))
                    p.send(7, msg)
                    served.v += 1
                    if tFirstReq.v == 0 { tFirstReq.v = monotonicNow() }
                    tLastReq.v = monotonicNow()
                default: break
                }
            }
            stream.write(MiniPeer.handshake(infoHash: meta.infoHashes.primary))
            return p
        }
        let finalFile = leechDir.appendingPathComponent(fx.file.lastPathComponent)
        let t0 = monotonicNow()
        var complete = false
        while monotonicNow() - t0 < 60 {
            if let d = try? Data(contentsOf: finalFile), d == content { complete = true; break }
            if ep.loop.sync({ peer.closed }) != nil { break }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        let secs = monotonicNow() - t0
        let span = ep.loop.sync { tLastReq.v - tFirstReq.v }
        let firstAfter = ep.loop.sync { tFirstReq.v } - t0
        print("interop upload: transmission complete=\(complete) in \(String(format: "%.2f", secs)) s (first request after \(String(format: "%.2f", firstAfter)) s, requests spanned \(String(format: "%.3f", span)) s), served \(ep.loop.sync { served.v }) blocks, haves \(ep.loop.sync { haves.v.count }); \(ep.loop.sync { stream.debugState })")
        #expect(complete, "transmission did not complete download from us: \(ep.loop.sync { peer.closed } ?? "")\n\(tr.logTail)")
        ep.loop.sync { stream.close() }
        let torn = await waitUntil(ep.loop, timeout: 10) { ep.manager.connectionCount == 0 }
        print("interop upload: after close: \(torn ? "torn down" : ep.loop.sync { stream.debugState })")
        #expect(torn)
    }
}
}
