import Testing
import Foundation
import CryptoKit
@testable import TorrentCore

// MARK: - Test helpers

/// Mutable box for loop-confined test state captured by @Sendable closures.
final class MSEBox<T>: @unchecked Sendable {
    var value: T
    init(_ v: T) { value = v }
}

/// Resolve an async test once from the loop, with a hard timeout.
func mseRunOnLoop<T: Sendable>(_ loop: EventLoop, timeout: Double, fallback: T,
                               _ body: @escaping @Sendable (_ done: @escaping @Sendable (T) -> Void) -> Void) async -> T {
    await withCheckedContinuation { (cont: CheckedContinuation<T, Never>) in
        let fired = MSEBox(false)
        let timer = MSEBox<LoopTimer?>(nil)
        loop.execute {
            let done: @Sendable (T) -> Void = { v in
                guard !fired.value else { return }
                fired.value = true
                timer.value?.cancel()
                cont.resume(returning: v)
            }
            // LoopTimer cancels itself on deinit, so the handle must be retained.
            timer.value = loop.schedule(after: timeout) { done(fallback) }
            body(done)
        }
    }
}

/// In-memory ByteStream pair. Writes made during one loop turn are coalesced
/// (like TCP) and delivered on a later turn in chunks of at most `chunk` bytes.
final class MockStream: ByteStream, @unchecked Sendable {
    var onRead: ((Data) -> Void)?
    var onClose: ((SocketError?) -> Void)?
    var onWritable: (() -> Void)?
    var pendingWriteBytes: Int { outbox.count }
    let remoteAddress: PeerAddress
    var transport: TransportKind { .tcp }

    weak var peer: MockStream?
    let loop: EventLoop
    let chunk: Int
    private var outbox = Data()
    private var flushScheduled = false
    private(set) var closed = false
    /// Every byte written to the wire by this end.
    private(set) var wire = Data()
    var closeCallbackCount = 0

    init(loop: EventLoop, chunk: Int, port: UInt16) {
        self.loop = loop
        self.chunk = chunk
        remoteAddress = PeerAddress(ip: .v4(0x7F00_0001), port: port)
    }

    static func pair(loop: EventLoop, chunkAtoB: Int, chunkBtoA: Int) -> (MockStream, MockStream) {
        let a = MockStream(loop: loop, chunk: chunkAtoB, port: 2)
        let b = MockStream(loop: loop, chunk: chunkBtoA, port: 1)
        a.peer = b
        b.peer = a
        return (a, b)
    }

    func write(_ data: Data) {
        guard !closed, !data.isEmpty else { return }
        wire.append(data)
        outbox.append(data)
        scheduleFlush()
    }

    private func scheduleFlush() {
        guard !flushScheduled else { return }
        flushScheduled = true
        loop.execute { [weak self] in self?.flush() }
    }

    private func flush() {
        flushScheduled = false
        let data = outbox
        outbox = Data()
        var off = 0
        while off < data.count {
            guard let peer, !peer.closed, !closed else { return }
            let n = min(chunk, data.count - off)
            peer.onRead?(data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + n)))
            off += n
        }
        onWritable?()
    }

    func close() {
        guard !closed else { return }
        closed = true
        onRead = nil; onClose = nil; onWritable = nil
        let p = peer
        loop.execute { p?.remoteClosed() }
    }

    func remoteClosed() {
        guard !closed else { return }
        closed = true
        let cb = onClose
        onRead = nil; onClose = nil; onWritable = nil
        closeCallbackCount += 1
        cb?(nil)
    }
}

func btHandshake(infoHash: Data, peerID: Data) -> Data {
    var d = Data([19])
    d.append(Data("BitTorrent protocol".utf8))
    d.append(Data(count: 8))
    d.append(infoHash)
    d.append(peerID)
    return d
}

extension Data {
    func containsSubsequence(_ needle: Data) -> Bool {
        guard !needle.isEmpty, needle.count <= count else { return needle.isEmpty }
        return range(of: needle) != nil
    }
}

// MARK: - Independent slow big-integer reference (UInt32 limbs, schoolbook + bitwise reduction)

enum SlowBig {
    static func from(_ bytes: [UInt8]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: max(1, (bytes.count + 3) / 4))
        for (k, b) in bytes.reversed().enumerated() { out[k / 4] |= UInt32(b) << UInt32(8 * (k % 4)) }
        return trim(out)
    }
    static func trim(_ a: [UInt32]) -> [UInt32] {
        var a = a
        while a.count > 1 && a.last == 0 { a.removeLast() }
        return a
    }
    static func toBytes(_ a: [UInt32], count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        for k in 0..<count where k / 4 < a.count { out[count - 1 - k] = UInt8(truncatingIfNeeded: a[k / 4] >> UInt32(8 * (k % 4))) }
        return out
    }
    static func cmp(_ a: [UInt32], _ b: [UInt32]) -> Int {
        let a = trim(a), b = trim(b)
        if a.count != b.count { return a.count < b.count ? -1 : 1 }
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != b[i] { return a[i] < b[i] ? -1 : 1 }
        return 0
    }
    static func sub(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = a
        var borrow: Int64 = 0
        for i in 0..<out.count {
            var d = Int64(out[i]) - (i < b.count ? Int64(b[i]) : 0) - borrow
            borrow = 0
            if d < 0 { d += 1 << 32; borrow = 1 }
            out[i] = UInt32(d)
        }
        return trim(out)
    }
    static func mul(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: a.count + b.count)
        for i in 0..<a.count {
            var carry: UInt64 = 0
            for j in 0..<b.count {
                let t = UInt64(a[i]) * UInt64(b[j]) + UInt64(out[i + j]) + carry
                out[i + j] = UInt32(truncatingIfNeeded: t)
                carry = t >> 32
            }
            out[i + b.count] = UInt32(carry)
        }
        return trim(out)
    }
    static func mod(_ a: [UInt32], _ m: [UInt32]) -> [UInt32] {
        var r: [UInt32] = [0]
        let bits = a.count * 32
        for bit in stride(from: bits - 1, through: 0, by: -1) {
            // r = 2r + bit
            var carry = (a[bit / 32] >> UInt32(bit % 32)) & 1
            for i in 0..<r.count {
                let next = r[i] >> 31
                r[i] = r[i] << 1 | carry
                carry = next
            }
            if carry != 0 { r.append(carry) }
            if cmp(r, m) >= 0 { r = sub(r, m) }
        }
        return trim(r)
    }
    static func modPow(_ base: [UInt32], _ exp: [UInt32], _ m: [UInt32]) -> [UInt32] {
        var result: [UInt32] = mod([1], m)
        let b = mod(base, m)
        for bit in stride(from: exp.count * 32 - 1, through: 0, by: -1) {
            result = mod(mul(result, result), m)
            if (exp[bit / 32] >> UInt32(bit % 32)) & 1 == 1 { result = mod(mul(result, b), m) }
        }
        return result
    }
}

/// UInt64 square-and-multiply using the hardware 128-bit multiply/divide.
func u64ModPow(_ b: UInt64, _ e: UInt64, _ m: UInt64) -> UInt64 {
    func mulmod(_ x: UInt64, _ y: UInt64) -> UInt64 {
        let p = x.multipliedFullWidth(by: y)
        return m.dividingFullWidth((p.high, p.low)).remainder
    }
    var result: UInt64 = 1 % m, base = b % m, e = e
    while e > 0 {
        if e & 1 == 1 { result = mulmod(result, base) }
        base = mulmod(base, base)
        e >>= 1
    }
    return result
}

// MARK: - RC4

@Suite struct MSECipherTests {
    @Test func rc4KnownAnswers() {
        let vectors: [(String, String, String)] = [
            ("Key", "Plaintext", "bbf316e8d940af0ad3"),
            ("Wiki", "pedia", "1021bf0420"),
            ("Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5"),
        ]
        for (key, plain, cipher) in vectors {
            let rc4 = RC4(key: Array(key.utf8))
            #expect(rc4.processed(Data(plain.utf8)).hex == cipher)
            // Decryption is the same operation with a fresh state.
            #expect(RC4(key: Array(key.utf8)).processed(Data(hex: cipher)!) == Data(plain.utf8))
        }
    }

    @Test func rc4ChunkingAndDiscardAreConsistent() {
        let key = Array(Data.random(20))
        let data = Data.random(10_000)
        let oneShot = RC4(key: key).processed(data)
        // Arbitrary chunk boundaries give the same stream.
        let chunked = RC4(key: key)
        var out = Data()
        var off = 0
        while off < data.count {
            let n = min(Int.random(in: 1...700), data.count - off)
            out.append(chunked.processed(data.subdata(in: off..<(off + n))))
            off += n
        }
        #expect(out == oneShot)
        // discard(1024) == encrypting 1024 bytes and dropping them.
        let a = RC4(key: key); a.discard(1024)
        let b = RC4(key: key); _ = b.processed(Data(count: 1024))
        #expect(a.processed(data) == b.processed(data))
    }

    @Test func rc4Throughput() {
        let n = 64 << 20
        var buf = Data(count: n)
        let rc4 = RC4(key: Array("throughput".utf8))
        let t0 = monotonicNow()
        buf.withUnsafeMutableBytes { rc4.process($0) }
        let dt = monotonicNow() - t0
        let mbps = Double(n) / dt / 1e6
        #if DEBUG
        let build = "debug"
        #else
        let build = "release"
        #endif
        print("[MSE] RC4 throughput (\(build) build): \(String(format: "%.0f", mbps)) MB/s")
        #expect(buf.count == n)
        #expect(mbps > 50)
    }
}

// MARK: - Big integers / DH

@Suite struct MSEBigIntTests {
    func pow(_ b: UInt64, _ e: UInt64, _ m: UInt64) -> UInt64 {
        Montgomery(modulus: [m]).modPow([b], [e])[0]
    }

    @Test func smallKnownValues() {
        #expect(pow(4, 13, 497) == 445)
        #expect(pow(2, 10, 1_000_000_007) == 1024)
        #expect(pow(3, 0, 7) == 1)
        #expect(pow(0, 5, 7) == 0)
        #expect(pow(10, 1, 7) == 3)
        #expect(pow(2, 1_000_000_006, 1_000_000_007) == 1)   // Fermat
        #expect(pow(5, 117, 19) == 1)
        #expect(pow(123_456_789, 987_654_321, 0xFFFF_FFFF_FFFF_FFC5) == u64ModPow(123_456_789, 987_654_321, 0xFFFF_FFFF_FFFF_FFC5))
    }

    @Test func randomSingleLimbAgainstHardwareArithmetic() {
        for _ in 0..<300 {
            let m = UInt64.random(in: 3...UInt64.max) | 1
            let b = UInt64.random(in: 0...UInt64.max)
            let e = UInt64.random(in: 0...UInt64.max)
            #expect(pow(b, e, m) == u64ModPow(b, e, m), "b=\(b) e=\(e) m=\(m)")
        }
    }

    @Test func randomMultiLimbAgainstSlowReference() {
        // Random odd moduli of 2..12 limbs, then the MSE prime itself.
        var cases: [([UInt8], [UInt8], [UInt8])] = []
        for limbs in [2, 3, 5, 12] {
            var m = Array(Data.random(limbs * 8))
            m[0] |= 0x80; m[m.count - 1] |= 1
            cases.append((m, Array(Data.random(limbs * 8 + 3)), Array(Data.random(Int.random(in: 1...12)))))
        }
        let p = Array(Data(hex: MSEDH.primeHex)!)
        for _ in 0..<2 { cases.append((p, Array(Data.random(96)), Array(Data.random(20)))) }
        for (m, b, e) in cases {
            let fast = Montgomery(modulus: BigLimbs.fromBigEndian(m)).modPow(BigLimbs.fromBigEndian(b), BigLimbs.fromBigEndian(e))
            let slow = SlowBig.modPow(SlowBig.from(b), SlowBig.from(e), SlowBig.from(m))
            #expect(Array(BigLimbs.toBigEndian(fast, byteCount: m.count)) == SlowBig.toBytes(slow, count: m.count))
        }
    }

    @Test func fermatOnMSEPrime() {
        // P is prime, so a^(P-1) == 1 (mod P) for 1 < a < P — an independent
        // whole-algorithm check with a full 768-bit exponent.
        for _ in 0..<3 {
            var a = Array(Data.random(96)); a[0] &= 0x7F
            let r = MSEDH.montgomery.modPow(BigLimbs.fromBigEndian(a), MSEDH.primeMinusOne)
            #expect(r == [1] + [UInt64](repeating: 0, count: 11))
        }
        #expect(Data(hex: MSEDH.primeHex)!.count == 96)
        #expect(MSEDH.prime.count == 12)
    }

    @Test func diffieHellmanAgreementAndTiming() {
        for _ in 0..<4 {
            let a = MSEDH.makeKeyPair(), b = MSEDH.makeKeyPair()
            #expect(a.publicKey.count == 96 && b.publicKey.count == 96)
            let sa = MSEDH.sharedSecret(peerPublic: b.publicKey, privateKey: a.privateKey)
            let sb = MSEDH.sharedSecret(peerPublic: a.publicKey, privateKey: b.privateKey)
            #expect(sa != nil && sa == sb && sa!.count == 96)
        }
        // Degenerate peer keys are rejected.
        let x = MSEDH.makeKeyPair().privateKey
        let p = Array(Data(hex: MSEDH.primeHex)!)
        let pm1 = Array(BigLimbs.toBigEndian(MSEDH.primeMinusOne, byteCount: 96))
        for bad in [[UInt8](repeating: 0, count: 96), [UInt8](repeating: 0, count: 95) + [1], pm1, p, [UInt8](repeating: 0xFF, count: 96)] {
            #expect(MSEDH.sharedSecret(peerPublic: bad, privateKey: x) == nil)
        }
        // Timing: two modexps per handshake side.
        let n = 10
        let t0 = monotonicNow()
        for _ in 0..<n { _ = MSEDH.makeKeyPair() }
        let per = (monotonicNow() - t0) / Double(n)
        print("[MSE] 768-bit modexp (160-bit exponent): \(String(format: "%.3f", per * 1000)) ms")
    }
}

// MARK: - Handshake over an in-memory pair

struct HandshakeScenario: Sendable {
    var chunkAtoB = 1
    var chunkBtoA = 1
    var initiatorAllowPlain = false
    var responderAllowPlain = false
    var preferPlaintext = false
    /// Responder reads this many bytes itself before calling `respond` (session peek).
    var peekBytes = 0
    var randomCryptoPads = true
    var keyPad: Int? = nil           // force PadA/PadB length
    var skeyA = Data.random(20)
    var skeysB: [Data] = []
    var ia = btHandshake(infoHash: Data(repeating: 0xAA, count: 20), peerID: Data("-AS0100-aaaaaaaaaaaa".utf8))
    var payloadAtoB = Data.random(3000)
    var payloadBtoA = btHandshake(infoHash: Data(repeating: 0xBB, count: 20), peerID: Data("-AS0100-bbbbbbbbbbbb".utf8)) + Data.random(2000)
    var responderTimeout = 10.0
    var garbageFromA: Data? = nil    // send raw garbage instead of running an initiator
}

struct HandshakeOutcome: Sendable {
    var initiatorError: String?
    var responderError: String?
    var initiatorEncrypted: Bool?
    var responderEncrypted: Bool?
    var matchedSkey: Data?
    var receivedByA = Data()
    var receivedByB = Data()
    var initiatorLeftover = 0
    var wireAtoB = Data()
    var wireBtoA = Data()
    var timedOut = false
}

func runHandshake(_ sc: HandshakeScenario) async -> HandshakeOutcome {
    let loop = EventLoop(label: "mse.test.\(UUID().uuidString)")
    let state = MSEBox(HandshakeOutcome())
    let keep = MSEBox<[AnyObject]>([])
    var fb = HandshakeOutcome(); fb.timedOut = true
    let skeysB = sc.skeysB.isEmpty ? [sc.skeyA] : sc.skeysB
    let expectA = sc.payloadBtoA, expectB = sc.ia + sc.payloadAtoB
    var opts = MSE.Options()
    if sc.randomCryptoPads { opts.cryptoPadLength = { Int.random(in: 0...512) } }
    if let k = sc.keyPad { opts.keyPadLength = { k } }
    opts.preferPlaintext = sc.preferPlaintext
    let options = opts

    var outcome = await mseRunOnLoop(loop, timeout: 15, fallback: fb) { done in
        let (a, b) = MockStream.pair(loop: loop, chunkAtoB: sc.chunkAtoB, chunkBtoA: sc.chunkBtoA)
        keep.value = [a, b]
        func check() {
            let s = state.value
            let aDone = s.initiatorError != nil || (s.initiatorEncrypted != nil && s.receivedByA.count >= expectA.count)
            let bDone = s.responderError != nil || (s.responderEncrypted != nil && s.receivedByB.count >= expectB.count)
            let garbageDone = sc.garbageFromA != nil && s.responderError != nil
            if (aDone && bDone) || garbageDone {
                state.value.wireAtoB = a.wire
                state.value.wireBtoA = b.wire
                done(state.value)
            }
        }

        // Responder (optionally after peeking at the first bytes itself).
        func startResponder(initial: Data) {
            MSE.respond(stream: b, initialBytes: initial, skeys: { skeysB }, allowPlaintext: sc.responderAllowPlain,
                        loop: loop, timeout: sc.responderTimeout, options: options) { r in
                switch r {
                case .failure(let e):
                    state.value.responderError = e.description
                case .success(let (s, skey, payload)):
                    keep.value.append(s as AnyObject)
                    state.value.responderEncrypted = s.isEncrypted
                    state.value.matchedSkey = skey
                    state.value.receivedByB.append(payload)
                    s.onRead = { d in state.value.receivedByB.append(d); check() }
                    s.onClose = { _ in }
                    s.write(sc.payloadBtoA)
                }
                check()
            }
        }
        if sc.peekBytes > 0 {
            let peeked = MSEBox(Data())
            b.onRead = { d in
                peeked.value.append(d)
                if peeked.value.count >= sc.peekBytes { startResponder(initial: peeked.value) }
            }
        } else {
            startResponder(initial: Data())
        }

        if let garbage = sc.garbageFromA {
            a.write(garbage)
            return
        }
        MSE.initiate(stream: a, skey: sc.skeyA, initialPayload: sc.ia, allowPlaintext: sc.initiatorAllowPlain,
                     loop: loop, timeout: 10, options: options) { r in
            switch r {
            case .failure(let e):
                state.value.initiatorError = e.description
            case .success(let (s, leftover)):
                keep.value.append(s as AnyObject)
                state.value.initiatorEncrypted = s.isEncrypted
                state.value.initiatorLeftover = leftover.count
                state.value.receivedByA.append(leftover)
                s.onRead = { d in state.value.receivedByA.append(d); check() }
                s.onClose = { _ in }
                s.write(sc.payloadAtoB)
            }
            check()
        }
    }
    // Snapshot wire bytes even on timeout.
    if outcome.timedOut { outcome.wireAtoB = Data(); outcome.wireBtoA = Data() }
    _ = keep
    return outcome
}

@Suite struct MSEHandshakeTests {
    func expectSuccess(_ sc: HandshakeScenario, _ o: HandshakeOutcome, rc4: Bool,
                       sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(!o.timedOut, sourceLocation: sourceLocation)
        #expect(o.initiatorError == nil, "initiator: \(o.initiatorError ?? "")", sourceLocation: sourceLocation)
        #expect(o.responderError == nil, "responder: \(o.responderError ?? "")", sourceLocation: sourceLocation)
        #expect(o.initiatorEncrypted == rc4, sourceLocation: sourceLocation)
        #expect(o.responderEncrypted == rc4, sourceLocation: sourceLocation)
        #expect(o.receivedByB == sc.ia + sc.payloadAtoB, sourceLocation: sourceLocation)
        #expect(o.receivedByA == sc.payloadBtoA, sourceLocation: sourceLocation)
        #expect(o.matchedSkey == sc.skeyA, sourceLocation: sourceLocation)
        // IA is always RC4-encrypted on the wire; the payload only when RC4 is selected.
        #expect(!o.wireAtoB.containsSubsequence(Data("BitTorrent protocol".utf8)), sourceLocation: sourceLocation)
        // (Only meaningful for payloads long enough not to occur in random bytes by chance.)
        if sc.payloadAtoB.count >= 16 {
            #expect(o.wireAtoB.containsSubsequence(sc.payloadAtoB) == !rc4, sourceLocation: sourceLocation)
        }
        if sc.payloadBtoA.count >= 16 {
            #expect(o.wireBtoA.containsSubsequence(sc.payloadBtoA) == !rc4, sourceLocation: sourceLocation)
        }
    }

    @Test func rc4OneByteChunks() async {
        let sc = HandshakeScenario()
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    @Test func rc4LargeChunksDeliverLeftover() async {
        var sc = HandshakeScenario()
        sc.chunkAtoB = 1 << 20; sc.chunkBtoA = 1 << 20
        let o = await runHandshake(sc)
        expectSuccess(sc, o, rc4: true)
        // B's reply was coalesced with step 4, so A got it as leftover.
        #expect(o.initiatorLeftover == sc.payloadBtoA.count)
    }

    @Test(arguments: [0, 1, 20, 95, 96, 97, 200])
    func responderPeekedInitialBytes(peek: Int) async {
        var sc = HandshakeScenario()
        sc.peekBytes = peek
        sc.chunkAtoB = peek == 200 ? 1 << 20 : 7
        // A sends only Ya + PadA (96 + 0...512 bytes) before waiting for Yb, so a
        // peek beyond 96 bytes needs a long enough PadA or it would wait forever.
        if peek > 96 { sc.keyPad = 512 }
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    @Test func randomPadsAndFragmentation() async {
        for i in 0..<12 {
            var sc = HandshakeScenario()
            sc.chunkAtoB = [1, 2, 3, 13, 100, 1 << 20][i % 6]
            sc.chunkBtoA = [1 << 20, 1, 5, 64, 1, 3][i % 6]
            sc.keyPad = [0, 512, nil, nil, 511, 1][i % 6]
            sc.payloadAtoB = Data.random(Int.random(in: 0...5000))
            sc.payloadBtoA = Data.random(Int.random(in: 1...5000))
            expectSuccess(sc, await runHandshake(sc), rc4: true)
        }
    }

    @Test func plaintextSelected() async {
        var sc = HandshakeScenario()
        sc.initiatorAllowPlain = true
        sc.responderAllowPlain = true
        sc.preferPlaintext = true
        expectSuccess(sc, await runHandshake(sc), rc4: false)
        sc.chunkAtoB = 1 << 20; sc.chunkBtoA = 1 << 20
        let o = await runHandshake(sc)
        expectSuccess(sc, o, rc4: false)
        #expect(o.initiatorLeftover == sc.payloadBtoA.count)
    }

    @Test func rc4PreferredWhenBothOffered() async {
        var sc = HandshakeScenario()
        sc.initiatorAllowPlain = true
        sc.responderAllowPlain = true
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    @Test func emptyIA() async {
        var sc = HandshakeScenario()
        sc.ia = Data()
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    @Test func picksMatchingSkeyAmongMany() async {
        var sc = HandshakeScenario()
        sc.skeysB = (0..<50).map { _ in Data.random(20) } + [sc.skeyA] + [Data.random(20)]
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    @Test func wrongSkeyRejected() async {
        var sc = HandshakeScenario()
        sc.skeysB = [Data.random(20), Data.random(20)]
        let o = await runHandshake(sc)
        #expect(!o.timedOut)
        #expect(o.responderError?.contains("info hash") == true, "\(o.responderError ?? "nil")")
        #expect(o.initiatorError != nil)
        #expect(o.receivedByB.isEmpty)
    }

    @Test func garbageRejectedBySyncWindow() async {
        var sc = HandshakeScenario()
        sc.garbageFromA = Data.random(96 + 532 + 100)
        let o = await runHandshake(sc)
        #expect(!o.timedOut)
        #expect(o.responderError?.contains("req1") == true, "\(o.responderError ?? "nil")")
    }

    @Test func responderTimesOut() async {
        var sc = HandshakeScenario()
        sc.garbageFromA = Data.random(50)   // never completes Ya
        sc.responderTimeout = 0.3
        let o = await runHandshake(sc)
        #expect(!o.timedOut)
        #expect(o.responderError?.contains("timed out") == true, "\(o.responderError ?? "nil")")
    }

    @Test func plaintextPreferringResponderUsesRC4WhenNotOffered() async {
        var sc = HandshakeScenario()
        sc.initiatorAllowPlain = false
        sc.responderAllowPlain = true
        sc.preferPlaintext = true
        // B only selects plaintext if A provided it; A didn't, so RC4 is used.
        expectSuccess(sc, await runHandshake(sc), rc4: true)
    }

    /// A hand-written responder built straight from the spec (DH + SHA-1 + RC4
    /// primitives only) answers with a forged crypto_select. 0x02 is the positive
    /// control (also checks our step-3 wire format independently); everything
    /// else must be rejected because A offered RC4 only.
    @Test(arguments: [UInt32(0x02), 0x01, 0x03, 0x00, 0x04])
    func initiatorValidatesCryptoSelect(select: UInt32) async {
        let loop = EventLoop(label: "mse.forged.\(select)")
        let skey = Data.random(20)
        let ia = Data("initial payload".utf8)
        struct R: Sendable { var error: String?; var succeeded = false; var provide: UInt32 = 0; var ia = Data() }
        let keep = MSEBox<[AnyObject]>([])
        let r = await mseRunOnLoop(loop, timeout: 10, fallback: R(error: "timeout")) { done in
            let (a, b) = MockStream.pair(loop: loop, chunkAtoB: 1 << 20, chunkBtoA: 1 << 20)
            keep.value = [a, b]
            let res = MSEBox(R())
            let buf = MSEBox([UInt8]())
            let sentYb = MSEBox(false)
            let kp = MSEDH.makeKeyPair()
            b.onRead = { d in
                buf.value += d
                let x = buf.value
                guard x.count >= 96 else { return }
                if !sentYb.value { sentYb.value = true; b.write(Data(kp.publicKey)) }   // Yb, no PadB
                guard let s = MSEDH.sharedSecret(peerPublic: x[0..<96], privateKey: kp.privateKey),
                      x.count >= 96 + 20 else { return }
                let req1 = MSE.hash(Array("req1".utf8), s)
                guard let at = (96...(x.count - 20)).first(where: { Array(x[$0..<($0 + 20)]) == req1 }) else { return }
                let req2x3 = zip(MSE.hash(Array("req2".utf8), Array(skey)), MSE.hash(Array("req3".utf8), s)).map { $0 ^ $1 }
                let start = at + 40
                guard x.count >= start + 14 else { return }
                let dec = RC4(key: MSE.hash(Array("keyA".utf8), s, Array(skey)))
                dec.discard(1024)
                var rest = Array(x[start...])
                dec.process(&rest, range: 0..<rest.count)
                let padC = Int(UInt16(rest[12]) << 8 | UInt16(rest[13]))
                guard rest.count >= 14 + padC + 2 else { return }
                let iaLen = Int(UInt16(rest[14 + padC]) << 8 | UInt16(rest[15 + padC]))
                guard rest.count >= 16 + padC + iaLen else { return }
                b.onRead = nil
                guard Array(x[(at + 20)..<(at + 40)]) == req2x3, rest[0..<8].allSatisfy({ $0 == 0 }) else {
                    done(R(error: "fake responder: bad req2^req3 or VC")); return
                }
                res.value.provide = UInt32(rest[8]) << 24 | UInt32(rest[9]) << 16 | UInt32(rest[10]) << 8 | UInt32(rest[11])
                res.value.ia = Data(rest[(16 + padC)..<(16 + padC + iaLen)])
                let enc = RC4(key: MSE.hash(Array("keyB".utf8), s, Array(skey)))
                enc.discard(1024)
                var step4 = Data(count: 8)
                step4.appendBE32(select)
                step4.appendBE16(3)
                step4.append(Data([9, 9, 9]))   // PadD
                b.write(enc.processed(step4))
            }
            MSE.initiate(stream: a, skey: skey, initialPayload: ia, allowPlaintext: false,
                         loop: loop, timeout: 5) { result in
                switch result {
                case .failure(let e): res.value.error = e.description
                case .success(let (s, leftover)):
                    keep.value.append(s as AnyObject)
                    res.value.succeeded = s.isEncrypted && leftover.isEmpty
                }
                done(res.value)
            }
        }
        #expect(r.provide == MSE.cryptoRC4)
        #expect(r.ia == ia)
        if select == MSE.cryptoRC4 {
            #expect(r.error == nil && r.succeeded, "\(r.error ?? "")")
        } else {
            #expect(r.error?.contains("unsupported crypto") == true, "\(r.error ?? "nil")")
        }
    }

    @Test func encryptedStreamCloseSemantics() async {
        let loop = EventLoop(label: "mse.close")
        let timers = MSEBox<[LoopTimer]>([])   // LoopTimer cancels itself on deinit
        let counts = await mseRunOnLoop(loop, timeout: 5, fallback: [-1]) { done in
            let (a, b) = MockStream.pair(loop: loop, chunkAtoB: 3, chunkBtoA: 3)
            let ea = EncryptedStream(inner: a, encryptor: RC4(key: [1]), decryptor: RC4(key: [2]), loop: loop)
            let eb = EncryptedStream(inner: b, encryptor: RC4(key: [2]), decryptor: RC4(key: [1]), loop: loop)
            let closesA = MSEBox(0), closesB = MSEBox(0), got = MSEBox(Data())
            ea.onClose = { _ in closesA.value += 1 }
            eb.onClose = { _ in closesB.value += 1 }
            eb.onRead = { got.value.append($0) }
            ea.write(Data("ping".utf8))
            timers.value.append(loop.schedule(after: 0.05) {
                // Owner closes A: A's onClose must NOT fire; B sees exactly one close.
                ea.close()
                ea.close()
                ea.write(Data("ignored".utf8))
                timers.value.append(loop.schedule(after: 0.05) {
                    done([closesA.value, closesB.value, got.value == Data("ping".utf8) ? 1 : 0,
                          eb.isEncrypted ? 1 : 0, b.closeCallbackCount])
                })
            })
        }
        #expect(counts == [0, 1, 1, 1, 1])
    }
}

// MARK: - Loopback TCP

@Suite struct MSELoopbackTests {
    @Test func loopbackTCP64MB() async throws {
        let loop = EventLoop(label: "mse.tcp")
        let total = 64 << 20
        let block = Data.random(1 << 20)
        var h = Insecure.SHA1()
        for _ in 0..<(total / block.count) { h.update(data: block) }
        let expected = Data(h.finalize())
        let skey = Data.random(20)
        let iaA = btHandshake(infoHash: skey, peerID: Data("-AS0100-loopbackAAAA".utf8))

        struct R: Sendable { var error: String?; var digest = Data(); var received = 0; var seconds = 0.0; var encrypted = false; var ia = Data() }
        let keep = MSEBox<[AnyObject]>([])
        let r = await mseRunOnLoop(loop, timeout: 120, fallback: R(error: "timeout")) { done in
            let listener: TCPListener
            do { listener = try TCPListener(port: 0, loop: loop) } catch { done(R(error: "\(error)")); return }
            keep.value.append(listener)
            let res = MSEBox(R())
            let hasher = MSEBox(Insecure.SHA1())
            let t0 = MSEBox(0.0)
            let streams = MSEBox<[any ByteStream]>([])
            listener.onAccept = { s in
                keep.value.append(s)
                MSE.respond(stream: s, initialBytes: Data(), skeys: { [skey] }, allowPlaintext: false,
                            loop: loop, timeout: 10) { result in
                    switch result {
                    case .failure(let e): done(R(error: "respond: \(e)"))
                    case .success(let (es, _, payload)):
                        streams.value.append(es)
                        res.value.encrypted = es.isEncrypted
                        res.value.ia = payload.prefix(68)
                        func consume(_ d: Data) {
                            hasher.value.update(data: d)
                            res.value.received += d.count
                            if res.value.received >= total {
                                res.value.seconds = monotonicNow() - t0.value
                                res.value.digest = Data(hasher.value.finalize())
                                done(res.value)
                                for st in streams.value { st.close() }
                                streams.value = []
                                listener.close()
                            }
                        }
                        es.onRead = { consume($0) }
                        es.onClose = { e in done(R(error: "server closed: \(String(describing: e))")) }
                        if payload.count > 68 { consume(Data(payload.dropFirst(68))) }
                    }
                }
                s.activate()
            }
            listener.start()
            TCPStream.connect(to: PeerAddress(ip: IPAddress("127.0.0.1")!, port: listener.port), loop: loop) { cr in
                guard case .success(let s) = cr else { done(R(error: "connect failed")); return }
                keep.value.append(s)
                MSE.initiate(stream: s, skey: skey, initialPayload: iaA, allowPlaintext: false,
                             loop: loop, timeout: 10) { result in
                    guard case .success(let (es, _)) = result else { done(R(error: "initiate: \(result)")); return }
                    streams.value.append(es)
                    es.onClose = { e in done(R(error: "client closed: \(String(describing: e))")) }
                    var sent = 0
                    var pumping = false
                    func pump() {
                        if pumping { return }
                        pumping = true
                        while sent < total && es.pendingWriteBytes < 4 << 20 {
                            es.write(block)
                            sent += block.count
                        }
                        pumping = false
                    }
                    es.onWritable = { pump() }
                    t0.value = monotonicNow()
                    pump()
                }
                s.activate()
            }
        }
        _ = keep
        #expect(r.error == nil, "\(r.error ?? "")")
        #expect(r.encrypted)
        #expect(r.ia == iaA)
        #expect(r.received == total)
        #expect(r.digest == expected)
        if r.error == nil {
            #if DEBUG
            let build = "debug"
            #else
            let build = "release"
            #endif
            print("[MSE] loopback TCP + RC4 (\(build) build, both ends on one loop): \(total >> 20) MB in \(String(format: "%.2f", r.seconds)) s = \(String(format: "%.0f", Double(total) / r.seconds / 1e6)) MB/s")
        }
    }
}

// MARK: - Live interop with Transmission (ASTOR_LIVE=1)

/// A throw-away transmission-cli instance (encryption REQUIRED) in a temp dir.
final class TransmissionFixture: @unchecked Sendable {
    let dir: URL
    let torrent: URL
    let meta: Metainfo
    let log: URL
    private let process = Process()
    private let logHandle: FileHandle

    init(seed: Bool, tracker: String, port: UInt16) throws {
        let fm = FileManager.default
        dir = fm.temporaryDirectory.appendingPathComponent("astor-mse-\(UUID().uuidString)")
        let src = dir.appendingPathComponent("src"), dl = dir.appendingPathComponent("dl")
        let config = dir.appendingPathComponent("config")
        for d in [src, dl, config] { try fm.createDirectory(at: d, withIntermediateDirectories: true) }
        // Transmission dials unknown peers over uTP first and only falls back to TCP
        // much later; force TCP and keep the instance hermetic.
        try Data(#"{"utp-enabled": false, "dht-enabled": false, "lpd-enabled": false, "pex-enabled": false}"#.utf8)
            .write(to: config.appendingPathComponent("settings.json"))
        let file = src.appendingPathComponent("astor-mse-payload.bin")
        try Data.random(3 << 20).write(to: file)
        torrent = dir.appendingPathComponent("t.torrent")
        let create = Process()
        create.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/transmission-create")
        create.arguments = ["-o", torrent.path, "-t", tracker, file.path]
        create.standardOutput = FileHandle.nullDevice
        create.standardError = FileHandle.nullDevice
        try create.run()
        create.waitUntilExit()
        guard create.terminationStatus == 0 else { throw MetainfoError("transmission-create failed") }
        meta = try Metainfo(torrentFile: Data(contentsOf: torrent))
        log = dir.appendingPathComponent("transmission.log")
        fm.createFile(atPath: log.path, contents: nil)
        logHandle = try FileHandle(forWritingTo: log)
        process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/transmission-cli")
        process.arguments = ["-er", "-p", "\(port)", "-g", config.path, "-w", (seed ? src : dl).path, "-M", "-B"]
            + (seed ? ["-v"] : []) + [torrent.path]
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()
    }

    func stop() {
        if process.isRunning { process.terminate(); process.waitUntilExit() }
        try? logHandle.close()
        try? FileManager.default.removeItem(at: dir)
    }

    func logTail(_ n: Int = 3000) -> String {
        String(((try? String(contentsOf: log, encoding: .utf8)) ?? "").suffix(n))
    }
}

/// Complete BitTorrent messages in `d` (after the handshake): (id, payload); keep-alives skipped.
func btMessages(_ d: Data) -> [(id: UInt8, payload: Data)] {
    var out: [(UInt8, Data)] = []
    var off = 0
    while off + 4 <= d.count {
        let len = Int(d.be32(off))
        if len == 0 { off += 4; continue }
        guard off + 4 + len <= d.count else { break }
        let s = d.startIndex + off + 5
        out.append((d.byte(off + 4), d.subdata(in: s..<(s + len - 1))))
        off += 4 + len
    }
    return out
}

let btProtocolHeader = Data([19]) + Data("BitTorrent protocol".utf8)

/// First RFC 1918 IPv4 address on an up, non-loopback, non-point-to-point interface.
func localLANIPv4() -> IPAddress? {
    var head: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&head) == 0 else { return nil }
    defer { freeifaddrs(head) }
    var p = head
    while let ifa = p {
        defer { p = ifa.pointee.ifa_next }
        let flags = Int32(ifa.pointee.ifa_flags)
        guard let sa = ifa.pointee.ifa_addr, Int32(sa.pointee.sa_family) == AF_INET,
              flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0,
              let addr = PeerAddress(sockaddr: sa), addr.ip.isPrivate, !addr.ip.isLoopback else { continue }
        return addr.ip
    }
    return nil
}

@Suite(.serialized) struct MSELiveInteropTests {
    static var live: Bool { ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1" }

    /// We initiate (allowPlaintext=false) to a Transmission seed that requires
    /// encryption; we must get its BT handshake and then its bitfield, decrypted.
    @Test(.enabled(if: MSELiveInteropTests.live, "set ASTOR_LIVE=1 to run against transmission-cli"))
    func weInitiateToTransmission() async throws {
        let port = UInt16.random(in: 40000...60000)
        let fx = try TransmissionFixture(seed: true, tracker: "http://127.0.0.1:1/announce", port: port)
        defer { fx.stop() }
        let infoHash = fx.meta.infoHashes.primary
        let expectedBitfield = Bitfield(count: fx.meta.pieceCount, allSet: true).data

        let loop = EventLoop(label: "mse.live.init")
        let peerID = ClientIdentity.makePeerID()
        struct R: Sendable { var error: String?; var reply = Data(); var encrypted = false; var failures: [String] = [] }
        let keep = MSEBox<[AnyObject]>([])
        let deadline = monotonicNow() + 40
        let r = await mseRunOnLoop(loop, timeout: 45, fallback: R(error: "timeout")) { done in
            let failures = MSEBox<[String]>([])
            @Sendable func attempt() {
                let retry: @Sendable (String) -> Void = { why in
                    failures.value.append(why)
                    if monotonicNow() > deadline { done(R(error: "gave up", failures: failures.value)); return }
                    keep.value.append(loop.schedule(after: 1) { attempt() })   // LoopTimer cancels on deinit
                }
                TCPStream.connect(to: PeerAddress(ip: IPAddress("127.0.0.1")!, port: port), loop: loop, timeout: 3) { cr in
                    guard case .success(let s) = cr else {
                        if case .failure(let e) = cr { retry("connect: \(e)") }
                        return
                    }
                    keep.value.append(s)
                    MSE.initiate(stream: s, skey: infoHash, initialPayload: btHandshake(infoHash: infoHash, peerID: peerID),
                                 allowPlaintext: false, loop: loop, timeout: 10) { result in
                        switch result {
                        case .failure(let e):
                            retry("mse: \(e)")
                        case .success(let (es, leftover)):
                            keep.value.append(es as AnyObject)
                            let got = MSEBox(leftover)
                            func check() {
                                guard got.value.count >= 68 else { return }
                                if btMessages(got.value.subdata(in: (got.value.startIndex + 68)..<got.value.endIndex)).contains(where: { $0.id == 5 }) {
                                    done(R(error: nil, reply: got.value, encrypted: es.isEncrypted, failures: failures.value))
                                    es.close()
                                }
                            }
                            es.onRead = { got.value.append($0); check() }
                            es.onClose = { e in retry("closed after MSE: \(String(describing: e)), got \(got.value.count) bytes") }
                            check()
                        }
                    }
                    s.activate()
                }
            }
            attempt()
        }
        _ = keep
        if r.error != nil { print("[MSE] transmission log tail:\n\(fx.logTail())") }
        #expect(r.error == nil, "\(r.error ?? "") \(r.failures)")
        #expect(r.encrypted)
        #expect(r.reply.prefix(20) == btProtocolHeader)
        #expect(r.reply.count >= 68 && r.reply.subdata(in: 28..<48) == infoHash)
        let msgs = r.reply.count >= 68 ? btMessages(r.reply.subdata(in: 68..<r.reply.count)) : []
        #expect(msgs.first(where: { $0.id == 5 })?.payload == expectedBitfield)
        if r.error == nil {
            print("[MSE] we->Transmission interop OK: peer \(String(decoding: r.reply.subdata(in: 48..<56), as: UTF8.self)), "
                  + "messages \(msgs.map(\.id)), earlier failed attempts: \(r.failures)")
        }
    }

    /// Transmission (encryption required, downloading) learns our address from a
    /// fake HTTP tracker and connects to us; our responder must decrypt its IA
    /// (BT handshake) and Transmission must accept our encrypted reply (it then
    /// sends `interested` after our full bitfield).
    @Test(.enabled(if: MSELiveInteropTests.live, "set ASTOR_LIVE=1 to run against transmission-cli"))
    func transmissionInitiatesToUs() async throws {
        let loop = EventLoop(label: "mse.live.resp")
        let peerListener = try TCPListener(port: 0, loop: loop)
        let trackerListener = try TCPListener(port: 0, loop: loop)
        let fx = try TransmissionFixture(seed: false, tracker: "http://127.0.0.1:\(trackerListener.port)/announce",
                                         port: UInt16.random(in: 40000...60000))
        defer { fx.stop() }
        let infoHash = fx.meta.infoHashes.primary
        let pieceCount = fx.meta.pieceCount
        let ourID = ClientIdentity.makePeerID()
        let ourPort = peerListener.port
        // Transmission ignores loopback peers from trackers, so advertise a LAN address
        // (our listener is bound to 0.0.0.0).
        let lan = try #require(localLANIPv4(), "no non-loopback IPv4 interface to advertise")

        struct R: Sendable { var error: String?; var ia = Data(); var encrypted = false; var ids: [UInt8] = []; var announces = 0; var peeked = 0 }
        let keep = MSEBox<[AnyObject]>([peerListener, trackerListener])
        let r = await mseRunOnLoop(loop, timeout: 60, fallback: R(error: "timeout")) { done in
            let announces = MSEBox(0)
            trackerListener.onAccept = { s in
                keep.value.append(s)
                s.onRead = { [weak s] _ in
                    guard let s else { return }
                    announces.value += 1
                    var body = Data("d8:intervali1800e12:min intervali60e5:peers6:".utf8)
                    body.append(contentsOf: PeerAddress(ip: lan, port: ourPort).compact)
                    body.append(Data("e".utf8))
                    var resp = Data("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
                    resp.append(body)
                    s.onRead = nil
                    s.onWritable = { [weak s] in s?.close() }
                    s.write(resp)
                }
                s.onClose = { _ in }
                s.activate()
            }
            peerListener.onAccept = { s in
                keep.value.append(s)
                let peek = MSEBox(Data())
                s.onRead = { d in
                    peek.value.append(d)
                    guard peek.value.count >= 20 else { return }
                    if peek.value.prefix(20) == btProtocolHeader { done(R(error: "Transmission connected in plaintext")); return }
                    let peeked = peek.value.count
                    MSE.respond(stream: s, initialBytes: peek.value, skeys: { [Data.random(20), infoHash] },
                                allowPlaintext: false, loop: loop, timeout: 15) { result in
                        switch result {
                        case .failure(let e):
                            done(R(error: "respond: \(e)"))
                        case .success(let (es, skey, payload)):
                            keep.value.append(es as AnyObject)
                            guard skey == infoHash else { done(R(error: "wrong skey")); return }
                            var res = R(ia: Data(payload.prefix(68)), encrypted: es.isEncrypted, peeked: peeked)
                            var bitfield = Data()
                            let bits = Bitfield(count: pieceCount, allSet: true).data
                            bitfield.appendBE32(UInt32(1 + bits.count))
                            bitfield.append(5)
                            bitfield.append(bits)
                            es.write(btHandshake(infoHash: infoHash, peerID: ourID) + bitfield)
                            let got = MSEBox(Data(payload.dropFirst(68)))
                            func check() {
                                let ids = btMessages(got.value).map(\.id)
                                if ids.contains(2) {
                                    res.ids = ids
                                    res.announces = announces.value
                                    done(res)
                                    es.close()
                                }
                            }
                            es.onRead = { got.value.append($0); check() }
                            es.onClose = { e in
                                done(R(error: "closed after MSE: \(String(describing: e)) ids=\(btMessages(got.value).map(\.id))"))
                            }
                            check()
                        }
                    }
                }
                s.onClose = { _ in }
                s.activate()
            }
            trackerListener.start()
            peerListener.start()
        }
        loop.sync { peerListener.close(); trackerListener.close() }
        _ = keep
        if r.error != nil { print("[MSE] transmission log tail:\n\(fx.logTail())") }
        #expect(r.error == nil, "\(r.error ?? "")")
        #expect(r.encrypted)
        #expect(r.ia.prefix(20) == btProtocolHeader)
        #expect(r.ia.count == 68 && r.ia.subdata(in: 28..<48) == infoHash)
        #expect(r.ids.contains(2))
        if r.error == nil {
            print("[MSE] Transmission->us interop OK: peer \(String(decoding: r.ia.subdata(in: 48..<56), as: UTF8.self)), "
                  + "peeked \(r.peeked) bytes, messages after handshake \(r.ids), tracker announces \(r.announces)")
        }
    }
}
