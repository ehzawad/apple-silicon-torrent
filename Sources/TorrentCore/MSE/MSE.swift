import Foundation

/// MSE/PE — Message Stream Encryption / Protocol Encryption, the de-facto
/// BitTorrent obfuscation (Vuze, uTorrent, libtorrent, Transmission, qBittorrent).
///
/// ```
/// 1 A->B: Ya, PadA
/// 2 B->A: Yb, PadB
/// 3 A->B: HASH('req1', S), HASH('req2', SKEY) xor HASH('req3', S),
///         ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
/// 4 B->A: ENCRYPT(VC, crypto_select, len(PadD), PadD), ENCRYPT2(payload)
/// 5 A->B: ENCRYPT2(payload)
/// ```
///
/// Usage notes:
///  * Both entry points take over the stream's `onRead`/`onClose` until they
///    complete. On success the caller must install its callbacks on the returned
///    stream synchronously inside the completion handler (bytes that arrive later
///    are delivered to whatever `onRead` is installed at that time).
///  * A `TCPStream` from `TCPStream.connect` must be `activate()`d after
///    `initiate` is called (the first handshake bytes are queued and flushed then).
///  * Incoming: classify on the first bytes available (<= 20 are enough to rule
///    out "\u{13}BitTorrent protocol") and call `respond` right away. Never wait
///    for more than 96 bytes: an initiator sends only Ya + PadA (96 + 0...512
///    bytes) and then waits for our Yb.
///  * The completion is always invoked asynchronously on the loop, exactly once.
///    On failure the stream has been closed.
public enum MSE {
    static let cryptoPlaintext: UInt32 = 0x01
    static let cryptoRC4: UInt32 = 0x02
    static let maxPad = 512
    static let vcLength = 8

    /// Internal knobs (tests and tuning). Public entry points use the defaults.
    struct Options: Sendable {
        /// Length of PadA / PadB (random 0...512 defeats length fingerprinting).
        var keyPadLength: @Sendable () -> Int = { Int.random(in: 0...MSE.maxPad) }
        /// Length of PadC / PadD. The spec says "standard practice at this time is
        /// for it to be zero-length", so we send none (we accept up to 512).
        var cryptoPadLength: @Sendable () -> Int = { 0 }
        /// Responder: when the peer offers both and plaintext is allowed, select
        /// plaintext (libtorrent's default). We default to RC4 — the whole point
        /// of MSE for us is to defeat DPI throttling of the payload too.
        var preferPlaintext = false
    }

    /// Outgoing. `skey` = the 20-byte torrent id (InfoHashes.primary).
    /// `initialPayload` = the plaintext BitTorrent handshake, sent as IA.
    /// `allowPlaintext` adds plaintext to crypto_provide; RC4 is always offered.
    /// Completion: the stream to use (EncryptedStream for RC4, or the raw stream if
    /// the peer selected plaintext) and any bytes already received after the
    /// handshake (already decrypted) which the caller must parse first.
    public static func initiate(stream: any ByteStream, skey: Data, initialPayload: Data,
                                allowPlaintext: Bool, loop: EventLoop, timeout: Double,
                                completion: @escaping (Result<(any ByteStream, Data), SocketError>) -> Void) {
        initiate(stream: stream, skey: skey, initialPayload: initialPayload, allowPlaintext: allowPlaintext,
                 loop: loop, timeout: timeout, options: Options(), completion: completion)
    }

    /// Incoming. `initialBytes` = bytes already read (they did NOT start with
    /// "\u{13}BitTorrent protocol"). `skeys` returns all 20-byte ids we serve.
    /// Completion: (stream, matched skey, decrypted IA + any further bytes).
    public static func respond(stream: any ByteStream, initialBytes: Data,
                               skeys: @escaping () -> [Data], allowPlaintext: Bool,
                               loop: EventLoop, timeout: Double,
                               completion: @escaping (Result<(any ByteStream, Data, Data), SocketError>) -> Void) {
        respond(stream: stream, initialBytes: initialBytes, skeys: skeys, allowPlaintext: allowPlaintext,
                loop: loop, timeout: timeout, options: Options(), completion: completion)
    }

    static func initiate(stream: any ByteStream, skey: Data, initialPayload: Data,
                         allowPlaintext: Bool, loop: EventLoop, timeout: Double, options: Options,
                         completion: @escaping (Result<(any ByteStream, Data), SocketError>) -> Void) {
        loop.assertInLoop()
        let hs = MSEHandshake(role: .initiator, stream: stream, loop: loop,
                              allowPlaintext: allowPlaintext, options: options)
        hs.skey = skey
        hs.initialPayload = initialPayload
        hs.initiatorCompletion = completion
        hs.start(timeout: timeout)
    }

    static func respond(stream: any ByteStream, initialBytes: Data,
                        skeys: @escaping () -> [Data], allowPlaintext: Bool,
                        loop: EventLoop, timeout: Double, options: Options,
                        completion: @escaping (Result<(any ByteStream, Data, Data), SocketError>) -> Void) {
        loop.assertInLoop()
        let hs = MSEHandshake(role: .responder, stream: stream, loop: loop,
                              allowPlaintext: allowPlaintext, options: options)
        hs.skeys = skeys
        hs.seed(initialBytes)
        hs.responderCompletion = completion
        hs.start(timeout: timeout)
    }

    static func error(_ what: String, _ code: Int32 = EPROTO) -> SocketError {
        SocketError("mse: \(what)", code)
    }

    /// SHA-1 over the concatenation of `parts`.
    static func hash(_ parts: [UInt8]...) -> [UInt8] {
        var d = Data(capacity: parts.reduce(0) { $0 + $1.count })
        for p in parts { d.append(contentsOf: p) }
        return Array(Hash.sha1(d))
    }
}

// MARK: - Diffie-Hellman

/// The MSE Diffie-Hellman group: the 768-bit Oakley group 1 prime, G = 2,
/// 160-bit private exponents, public values and S as 96-byte big-endian.
enum MSEDH {
    static let keyBytes = 96
    static let privateKeyBytes = 20
    static let primeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563"
    static let prime: [UInt64] = BigLimbs.fromBigEndian(Data(hex: primeHex)!)
    static let primeMinusOne: [UInt64] = { var p = prime; BigLimbs.subtract(&p, [1]); return p }()
    static let montgomery = Montgomery(modulus: prime)

    struct KeyPair: Sendable {
        let privateKey: [UInt64]
        let publicKey: [UInt8]    // 96 bytes
    }

    static func makeKeyPair() -> KeyPair {
        let x = BigLimbs.fromBigEndian(Data.random(privateKeyBytes))
        let y = montgomery.modPow([2], x)
        return KeyPair(privateKey: x, publicKey: Array(BigLimbs.toBigEndian(y, byteCount: keyBytes)))
    }

    /// S = peerY ^ x mod P as 96 bytes, or nil if the peer value is degenerate
    /// (0, 1, >= P-1) — a legitimate peer never sends those.
    static func sharedSecret<C: Collection>(peerPublic: C, privateKey: [UInt64]) -> [UInt8]? where C.Element == UInt8 {
        let y = BigLimbs.fromBigEndian(peerPublic, minLimbs: prime.count)
        guard BigLimbs.compare(y, [1]) > 0, BigLimbs.compare(y, primeMinusOne) < 0 else { return nil }
        let s = montgomery.modPow(y, privateKey)
        return Array(BigLimbs.toBigEndian(s, byteCount: keyBytes))
    }
}

// MARK: - Handshake state machine

/// One in-flight MSE handshake (either role). Loop-confined; keeps itself alive
/// until it completes or times out.
final class MSEHandshake: @unchecked Sendable {
    enum Role { case initiator, responder }

    private enum State: Equatable {
        case waitPeerKey        // 96 bytes of Yb (initiator) / Ya (responder)
        case syncVC             // initiator: find ENCRYPT(VC) within PadB + 8
        case readSelect         // initiator: crypto_select(4) + len(PadD)(2)
        case readPadD(Int)
        case syncReq1           // responder: find HASH('req1', S) within PadA + 20
        case readSKeyHash       // responder: HASH('req2', SKEY) xor HASH('req3', S)
        case readProvide        // responder: VC(8) + crypto_provide(4) + len(PadC)(2)
        case readPadC(Int)      // responder: PadC + len(IA)(2)
        case readIA(Int)
        case done
    }

    let role: Role
    private let stream: any ByteStream
    private let loop: EventLoop
    private let allowPlaintext: Bool
    private let options: MSE.Options

    var skey: Data?
    var initialPayload = Data()
    var skeys: (() -> [Data])?
    var initiatorCompletion: ((Result<(any ByteStream, Data), SocketError>) -> Void)?
    var responderCompletion: ((Result<(any ByteStream, Data, Data), SocketError>) -> Void)?

    private var state: State = .waitPeerKey
    private var buf: [UInt8] = []
    private var pos = 0              // parse cursor into buf
    private var syncStart = 0        // first byte after the peer's DH key
    private var scanFrom = 0         // resume point for the sync scan
    private var keyPair: MSEDH.KeyPair?
    private var secret: [UInt8] = []
    private var encryptor: RC4?
    private var decryptor: RC4?
    private var syncPattern: [UInt8] = []   // ENCRYPT(VC) or HASH('req1', S)
    private var selected: UInt32 = 0
    private var ia: [UInt8] = []
    private var excessPayload = Data()      // initiator: IA beyond 65535 bytes
    private var timer: LoopTimer?
    private var selfRef: MSEHandshake?
    private var processing = false

    init(role: Role, stream: any ByteStream, loop: EventLoop, allowPlaintext: Bool, options: MSE.Options) {
        self.role = role
        self.stream = stream
        self.loop = loop
        self.allowPlaintext = allowPlaintext
        self.options = options
    }

    func seed(_ bytes: Data) { buf.append(contentsOf: bytes) }

    func start(timeout: Double) {
        selfRef = self
        stream.onRead = { [weak self] data in self?.handleRead(data) }
        stream.onClose = { [weak self] err in
            self?.fail(err ?? MSE.error("connection closed during handshake", ECONNRESET), closeStream: false)
        }
        timer = loop.schedule(after: timeout) { [weak self] in
            self?.fail(MSE.error("handshake timed out", ETIMEDOUT))
        }
        // Defer the first write/parse one loop turn so the completion is never
        // invoked re-entrantly from inside initiate()/respond().
        loop.execute { [weak self] in self?.begin() }
    }

    private func begin() {
        guard state != .done else { return }
        // Both sides can send their DH key + random pad immediately.
        let kp = MSEDH.makeKeyPair()
        keyPair = kp
        var out = Data(kp.publicKey)
        out.append(Data.random(clampPad(options.keyPadLength())))
        stream.write(out)
        run()
    }

    private func handleRead(_ data: Data) {
        guard state != .done else { return }
        buf.append(contentsOf: data)
        if keyPair != nil { run() }
    }

    private func run() {
        guard !processing else { return }
        processing = true
        defer { processing = false }
        while state != .done && step() {}
    }

    private func clampPad(_ n: Int) -> Int { min(max(n, 0), MSE.maxPad) }

    /// Decrypt `buf[pos..<pos+n]` in place with the peer's RC4 stream.
    private func decrypt(_ n: Int) {
        decryptor!.process(&buf, range: pos..<(pos + n))
    }

    /// Scan for `syncPattern` starting within `maxPad` bytes after `syncStart`.
    /// Returns the offset of the first byte after the pattern, nil if not (yet) found.
    private func scan() -> Int? {
        let plen = syncPattern.count
        let windowEnd = min(buf.count, syncStart + MSE.maxPad + plen)
        var p = scanFrom
        let first = syncPattern[0]
        while p + plen <= windowEnd {
            if buf[p] == first {
                var k = 1
                while k < plen && buf[p + k] == syncPattern[k] { k += 1 }
                if k == plen { return p + plen }
            }
            p += 1
        }
        scanFrom = p
        return nil
    }

    /// Advance the state machine by one step. Returns true if it made progress.
    private func step() -> Bool {
        let avail = buf.count - pos
        switch state {
        case .done:
            return false

        case .waitPeerKey:
            guard avail >= MSEDH.keyBytes else { return false }
            let peerKey = buf[pos..<(pos + MSEDH.keyBytes)]
            pos += MSEDH.keyBytes
            guard let s = MSEDH.sharedSecret(peerPublic: peerKey, privateKey: keyPair!.privateKey) else {
                fail(MSE.error("invalid DH public key"))
                return false
            }
            secret = s
            syncStart = pos
            scanFrom = pos
            if role == .initiator {
                sendStep3()
                if state == .done { return false }   // write failed synchronously
                state = .syncVC
            } else {
                syncPattern = MSE.hash(Array("req1".utf8), secret)
                state = .syncReq1
            }
            return true

        // ---- initiator ----
        case .syncVC:
            if let after = scan() {
                pos = after
                state = .readSelect
                return true
            }
            if buf.count - syncStart >= MSE.maxPad + MSE.vcLength {
                fail(MSE.error("could not find VC (peer is not MSE or wrong key)"))
            }
            return false

        case .readSelect:
            guard avail >= 6 else { return false }
            decrypt(6)
            let sel = be32(pos)
            let padD = Int(be16(pos + 4))
            pos += 6
            let provided = MSE.cryptoRC4 | (allowPlaintext ? MSE.cryptoPlaintext : 0)
            guard sel == MSE.cryptoRC4 || sel == MSE.cryptoPlaintext, sel & provided != 0 else {
                fail(MSE.error("peer selected unsupported crypto 0x\(String(sel, radix: 16))", EPROTONOSUPPORT))
                return false
            }
            guard padD <= MSE.maxPad else { fail(MSE.error("PadD too long (\(padD))")); return false }
            selected = sel
            state = .readPadD(padD)
            return true

        case .readPadD(let n):
            guard avail >= n else { return false }
            decrypt(n)
            pos += n
            finish()
            return false

        // ---- responder ----
        case .syncReq1:
            if let after = scan() {
                pos = after
                state = .readSKeyHash
                return true
            }
            if buf.count - syncStart >= MSE.maxPad + 20 {
                fail(MSE.error("could not find req1 hash (peer is not MSE)"))
            }
            return false

        case .readSKeyHash:
            guard avail >= 20 else { return false }
            let req3 = MSE.hash(Array("req3".utf8), secret)
            var want = [UInt8](repeating: 0, count: 20)
            for k in 0..<20 { want[k] = buf[pos + k] ^ req3[k] }   // = HASH('req2', SKEY)
            pos += 20
            let candidates = skeys?() ?? []
            guard let match = candidates.first(where: { MSE.hash(Array("req2".utf8), Array($0)) == want }) else {
                fail(MSE.error("no torrent matches the requested info hash", ENOENT))
                return false
            }
            skey = match
            deriveKeys(skey: Array(match))
            state = .readProvide
            return true

        case .readProvide:
            guard avail >= 14 else { return false }
            decrypt(14)
            for k in 0..<MSE.vcLength where buf[pos + k] != 0 {
                fail(MSE.error("bad VC"))
                return false
            }
            let provide = be32(pos + 8)
            let padC = Int(be16(pos + 12))
            pos += 14
            guard padC <= MSE.maxPad else { fail(MSE.error("PadC too long (\(padC))")); return false }
            let rc4 = provide & MSE.cryptoRC4 != 0
            let plain = provide & MSE.cryptoPlaintext != 0 && allowPlaintext
            if plain && (!rc4 || options.preferPlaintext) {
                selected = MSE.cryptoPlaintext
            } else if rc4 {
                selected = MSE.cryptoRC4
            } else {
                fail(MSE.error("no acceptable crypto method offered (0x\(String(provide, radix: 16)))", EPROTONOSUPPORT))
                return false
            }
            sendStep4()
            if state == .done { return false }
            state = .readPadC(padC)
            return true

        case .readPadC(let n):
            guard avail >= n + 2 else { return false }
            decrypt(n + 2)
            let iaLen = Int(be16(pos + n))
            pos += n + 2
            state = .readIA(iaLen)
            return true

        case .readIA(let n):
            guard avail >= n else { return false }
            decrypt(n)
            ia = Array(buf[pos..<(pos + n)])
            pos += n
            finish()
            return false
        }
    }

    // MARK: Sending

    private func deriveKeys(skey: [UInt8]) {
        let keyA = MSE.hash(Array("keyA".utf8), secret, skey)
        let keyB = MSE.hash(Array("keyB".utf8), secret, skey)
        let a = RC4(key: keyA), b = RC4(key: keyB)
        a.discard(1024)
        b.discard(1024)
        if role == .initiator {
            encryptor = a; decryptor = b
        } else {
            encryptor = b; decryptor = a
        }
    }

    private func sendStep3() {
        let sk = Array(skey ?? Data())
        deriveKeys(skey: sk)
        var out = Data(capacity: 40 + 16 + MSE.maxPad + initialPayload.count)
        out.append(contentsOf: MSE.hash(Array("req1".utf8), secret))
        let req2 = MSE.hash(Array("req2".utf8), sk)
        let req3 = MSE.hash(Array("req3".utf8), secret)
        out.append(contentsOf: zip(req2, req3).map { $0 ^ $1 })

        let iaMax = Int(UInt16.max)
        let iaPart = initialPayload.prefix(iaMax)
        if initialPayload.count > iaMax { excessPayload = initialPayload.dropFirst(iaMax) }
        let padC = clampPad(options.cryptoPadLength())
        var enc = Data(count: MSE.vcLength)
        enc.appendBE32(MSE.cryptoRC4 | (allowPlaintext ? MSE.cryptoPlaintext : 0))
        enc.appendBE16(UInt16(padC))
        enc.append(Data.random(padC))
        enc.appendBE16(UInt16(iaPart.count))
        enc.append(iaPart)
        enc.withUnsafeMutableBytes { encryptor!.process($0) }
        out.append(enc)
        stream.write(out)

        // The responder's encrypted VC is the first 8 bytes of its keystream.
        var vc = [UInt8](repeating: 0, count: MSE.vcLength)
        decryptor!.process(&vc, range: 0..<vc.count)
        syncPattern = vc
    }

    private func sendStep4() {
        let padD = clampPad(options.cryptoPadLength())
        var enc = Data(count: MSE.vcLength)
        enc.appendBE32(selected)
        enc.appendBE16(UInt16(padD))
        enc.append(Data.random(padD))
        enc.withUnsafeMutableBytes { encryptor!.process($0) }
        stream.write(enc)
    }

    // MARK: Completion

    private func detach() {
        state = .done
        timer?.cancel()
        timer = nil
        stream.onRead = nil
        stream.onClose = nil
    }

    private func finish() {
        withExtendedLifetime(self) {
            detach()
            var rest = Array(buf[pos...])
            let out: any ByteStream
            if selected == MSE.cryptoRC4 {
                decryptor!.process(&rest, range: 0..<rest.count)
                out = EncryptedStream(inner: stream, encryptor: encryptor!, decryptor: decryptor!, loop: loop)
            } else {
                out = stream
            }
            buf = []
            selfRef = nil
            if role == .initiator {
                let cb = initiatorCompletion
                initiatorCompletion = nil
                if !excessPayload.isEmpty { out.write(excessPayload) }
                cb?(.success((out, Data(rest))))
            } else {
                let cb = responderCompletion
                responderCompletion = nil
                cb?(.success((out, skey ?? Data(), Data(ia + rest))))
            }
        }
    }

    private func fail(_ err: SocketError, closeStream: Bool = true) {
        guard state != .done else { return }
        withExtendedLifetime(self) {
            detach()
            if closeStream { stream.close() }
            buf = []
            selfRef = nil
            let ic = initiatorCompletion, rc = responderCompletion
            initiatorCompletion = nil
            responderCompletion = nil
            ic?(.failure(err))
            rc?(.failure(err))
        }
    }

    // MARK: Helpers

    @inline(__always) private func be32(_ off: Int) -> UInt32 {
        UInt32(buf[off]) << 24 | UInt32(buf[off + 1]) << 16 | UInt32(buf[off + 2]) << 8 | UInt32(buf[off + 3])
    }

    @inline(__always) private func be16(_ off: Int) -> UInt16 {
        UInt16(buf[off]) << 8 | UInt16(buf[off + 1])
    }
}
