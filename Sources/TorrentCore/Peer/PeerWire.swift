import Foundation

/// BitTorrent peer wire protocol constants and codec (BEP 3, 5, 6, 10, 52).
public enum Wire {
    public static let protocolString = Data("BitTorrent protocol".utf8)
    public static let handshakeLength = 68
    public static let blockSize = 16 * 1024
    public static let maxMessageLength = 2 * 1024 * 1024

    public enum MessageID: UInt8 {
        case choke = 0, unchoke = 1, interested = 2, notInterested = 3
        case have = 4, bitfield = 5, request = 6, piece = 7, cancel = 8
        case port = 9                                  // BEP 5
        case suggest = 13, haveAll = 14, haveNone = 15 // BEP 6
        case reject = 16, allowedFast = 17             // BEP 6
        case extended = 20                             // BEP 10
        case hashRequest = 21, hashes = 22, hashReject = 23 // BEP 52
    }

    /// Reserved-bit capabilities exchanged in the handshake.
    public struct Reserved: Sendable, Equatable {
        public var bytes: [UInt8]
        public init(bytes: [UInt8]) { self.bytes = bytes }

        public static func ours(v2: Bool) -> Reserved {
            var b = [UInt8](repeating: 0, count: 8)
            b[5] |= 0x10   // BEP 10 extension protocol
            b[7] |= 0x01   // BEP 5 DHT
            b[7] |= 0x04   // BEP 6 fast extension
            if v2 { b[7] |= 0x10 } // BEP 52 v2 upgrade
            return Reserved(bytes: b)
        }

        public var supportsExtensions: Bool { bytes[5] & 0x10 != 0 }
        public var supportsDHT: Bool { bytes[7] & 0x01 != 0 }
        public var supportsFast: Bool { bytes[7] & 0x04 != 0 }
        public var supportsV2: Bool { bytes[7] & 0x10 != 0 }
    }

    public struct Handshake: Sendable {
        public var reserved: Reserved
        public var infoHash: Data
        public var peerID: Data

        public var encoded: Data {
            var d = Data(capacity: 68)
            d.append(19)
            d.append(protocolString)
            d.append(contentsOf: reserved.bytes)
            d.append(infoHash)
            d.append(peerID)
            return d
        }

        /// Parses the first 68 bytes. Returns nil if the protocol header is wrong.
        public static func parse(_ d: Data) -> Handshake? {
            guard d.count >= 68, d.byte(0) == 19 else { return nil }
            let s = d.startIndex
            guard d[(s + 1)..<(s + 20)] == protocolString[...] else { return nil }
            return Handshake(reserved: Reserved(bytes: Array(d[(s + 20)..<(s + 28)])),
                             infoHash: Data(d[(s + 28)..<(s + 48)]),
                             peerID: Data(d[(s + 48)..<(s + 68)]))
        }

        /// True if `d` (possibly shorter than 20 bytes) is a prefix of a plaintext handshake.
        public static func looksLikeHandshakePrefix(_ d: Data) -> Bool {
            guard !d.isEmpty, d.byte(0) == 19 else { return false }
            let n = min(d.count - 1, 19)
            return d[(d.startIndex + 1)..<(d.startIndex + 1 + n)] == protocolString.prefix(n)[...]
        }
    }

    // MARK: Message builders

    @inline(__always) static func header(_ len: Int, _ id: MessageID) -> Data {
        var d = Data(capacity: 4 + len)
        d.appendBE32(UInt32(len))
        d.append(id.rawValue)
        return d
    }

    public static let keepAlive = Data([0, 0, 0, 0])
    public static func simple(_ id: MessageID) -> Data { header(1, id) }

    public static func have(_ index: Int) -> Data {
        var d = header(5, .have); d.appendBE32(UInt32(index)); return d
    }
    public static func bitfield(_ bf: Bitfield) -> Data {
        var d = header(1 + bf.bytes.count, .bitfield); d.append(contentsOf: bf.bytes); return d
    }
    public static func request(_ r: BlockRequest) -> Data {
        var d = header(13, .request)
        d.appendBE32(UInt32(r.piece)); d.appendBE32(UInt32(r.offset)); d.appendBE32(UInt32(r.length))
        return d
    }
    public static func cancel(_ r: BlockRequest) -> Data {
        var d = header(13, .cancel)
        d.appendBE32(UInt32(r.piece)); d.appendBE32(UInt32(r.offset)); d.appendBE32(UInt32(r.length))
        return d
    }
    public static func reject(_ r: BlockRequest) -> Data {
        var d = header(13, .reject)
        d.appendBE32(UInt32(r.piece)); d.appendBE32(UInt32(r.offset)); d.appendBE32(UInt32(r.length))
        return d
    }
    public static func pieceHeader(piece: Int, offset: Int, length: Int) -> Data {
        var d = header(9 + length, .piece)
        d.appendBE32(UInt32(piece)); d.appendBE32(UInt32(offset))
        return d
    }
    public static func allowedFast(_ index: Int) -> Data {
        var d = header(5, .allowedFast); d.appendBE32(UInt32(index)); return d
    }
    public static func port(_ p: UInt16) -> Data {
        var d = header(3, .port); d.appendBE16(p); return d
    }
    public static func extended(_ id: UInt8, _ payload: Data) -> Data {
        var d = header(2 + payload.count, .extended); d.append(id); d.append(payload); return d
    }
    /// BEP 52 hash request / reject: pieces root(32), base layer, index, length, proof layers.
    public static func hashMessage(_ id: MessageID, root: Data, baseLayer: Int, index: Int, length: Int,
                                   proofLayers: Int, hashes: Data = Data()) -> Data {
        var d = header(1 + 32 + 16 + hashes.count, id)
        d.append(root)
        d.appendBE32(UInt32(baseLayer)); d.appendBE32(UInt32(index))
        d.appendBE32(UInt32(length)); d.appendBE32(UInt32(proofLayers))
        d.append(hashes)
        return d
    }

    /// BEP 6 allowed-fast set generation (canonical algorithm).
    public static func allowedFastSet(ip: IPAddress, infoHash: Data, pieceCount: Int, k: Int = 10) -> [Int] {
        guard case .v4(let a) = ip, pieceCount > 0 else { return [] }
        var x = Data()
        x.appendBE32(a & 0xFFFF_FF00)
        x.append(infoHash)
        var out: [Int] = []
        let want = min(k, pieceCount)
        while out.count < want {
            x = Hash.sha1(x)
            var i = 0
            while i < 5 && out.count < want {
                let y = Int(x.be32(i * 4)) % pieceCount
                if !out.contains(y) { out.append(y) }
                i += 1
            }
        }
        return out
    }
}

/// A 16 KiB (or shorter, at the end) block of a piece.
public struct BlockRequest: Hashable, Sendable {
    public var piece: Int
    public var offset: Int
    public var length: Int
    public init(piece: Int, offset: Int, length: Int) {
        self.piece = piece; self.offset = offset; self.length = length
    }
    public var blockIndex: Int { offset / Wire.blockSize }
}

/// A decoded inbound message.
enum InboundMessage {
    case keepAlive
    case choke, unchoke, interested, notInterested
    case have(Int)
    case bitfield(Data)
    case request(BlockRequest)
    case piece(index: Int, offset: Int, data: Data)
    case cancel(BlockRequest)
    case port(UInt16)
    case suggest(Int)
    case haveAll, haveNone
    case reject(BlockRequest)
    case allowedFast(Int)
    case extended(id: UInt8, payload: Data)
    case hashRequest(root: Data, base: Int, index: Int, length: Int, proof: Int)
    case hashes(root: Data, base: Int, index: Int, length: Int, proof: Int, hashes: Data)
    case hashReject(root: Data, base: Int, index: Int, length: Int, proof: Int)
    case unknown(UInt8)
}

/// Incremental length-prefixed message parser.
struct MessageParser {
    private var buf = Data()
    private var head = 0

    mutating func append(_ d: Data) {
        if head > 0 && head >= buf.count / 2 {
            buf.removeSubrange(buf.startIndex..<(buf.startIndex + head))
            head = 0
        }
        buf.append(d)
    }

    var buffered: Int { buf.count - head }

    /// Pull raw bytes (used for the handshake before message framing starts).
    mutating func take(_ n: Int) -> Data? {
        guard n >= 0, buffered >= n else { return nil }
        let s = buf.startIndex + head
        let out = Data(buf[s..<(s + n)])
        head += n
        return out
    }

    enum ParseError: Error { case tooLong(Int), malformed(UInt8) }

    mutating func next() throws -> InboundMessage? {
        guard buffered >= 4 else { return nil }
        let s = buf.startIndex + head
        let len = Int(UInt32(buf[s]) << 24 | UInt32(buf[s + 1]) << 16 | UInt32(buf[s + 2]) << 8 | UInt32(buf[s + 3]))
        if len > Wire.maxMessageLength { throw ParseError.tooLong(len) }
        guard buffered >= 4 + len else { return nil }
        head += 4 + len
        if len == 0 { return .keepAlive }
        let id = buf[s + 4]
        let p = s + 5            // payload start
        let plen = len - 1
        func u32(_ o: Int) -> Int {
            Int(UInt32(buf[p + o]) << 24 | UInt32(buf[p + o + 1]) << 16 | UInt32(buf[p + o + 2]) << 8 | UInt32(buf[p + o + 3]))
        }
        func block() throws -> BlockRequest {
            guard plen == 12 else { throw ParseError.malformed(id) }
            return BlockRequest(piece: u32(0), offset: u32(4), length: u32(8))
        }
        guard let mid = Wire.MessageID(rawValue: id) else { return .unknown(id) }
        switch mid {
        case .choke, .unchoke, .interested, .notInterested, .haveAll, .haveNone:
            guard plen == 0 else { throw ParseError.malformed(id) }
        case .hashRequest, .hashReject:
            guard plen == 48 else { throw ParseError.malformed(id) }
        case .hashes:
            guard plen > 48, (plen - 48) % 32 == 0 else { throw ParseError.malformed(id) }
        default: break
        }
        switch mid {
        case .choke: return .choke
        case .unchoke: return .unchoke
        case .interested: return .interested
        case .notInterested: return .notInterested
        case .have:
            guard plen == 4 else { throw ParseError.malformed(id) }
            return .have(u32(0))
        case .bitfield: return .bitfield(Data(buf[p..<(p + plen)]))
        case .request: return .request(try block())
        case .cancel: return .cancel(try block())
        case .reject: return .reject(try block())
        case .piece:
            guard plen > 8, plen <= 8 + Wire.blockSize else { throw ParseError.malformed(id) }
            return .piece(index: u32(0), offset: u32(4), data: Data(buf[(p + 8)..<(p + plen)]))
        case .port:
            guard plen == 2 else { throw ParseError.malformed(id) }
            return .port(UInt16(buf[p]) << 8 | UInt16(buf[p + 1]))
        case .suggest:
            guard plen == 4 else { throw ParseError.malformed(id) }
            return .suggest(u32(0))
        case .haveAll: return .haveAll
        case .haveNone: return .haveNone
        case .allowedFast:
            guard plen == 4 else { throw ParseError.malformed(id) }
            return .allowedFast(u32(0))
        case .extended:
            guard plen >= 1 else { throw ParseError.malformed(id) }
            return .extended(id: buf[p], payload: Data(buf[(p + 1)..<(p + plen)]))
        case .hashRequest, .hashes, .hashReject:
            guard plen >= 48 else { throw ParseError.malformed(id) }
            let root = Data(buf[p..<(p + 32)])
            let base = u32(32), index = u32(36), length = u32(40), proof = u32(44)
            switch mid {
            case .hashRequest: return .hashRequest(root: root, base: base, index: index, length: length, proof: proof)
            case .hashReject: return .hashReject(root: root, base: base, index: index, length: length, proof: proof)
            default: return .hashes(root: root, base: base, index: index, length: length, proof: proof,
                                    hashes: Data(buf[(p + 48)..<(p + plen)]))
            }
        }
    }
}

/// Exponentially-weighted transfer rate estimator (bytes/s).
struct RateMeter {
    private var bucket: Double = 0
    private var rate: Double = 0
    private var last = monotonicNow()
    private(set) var total: Int64 = 0

    mutating func add(_ n: Int) {
        bucket += Double(n)
        total += Int64(n)
    }

    /// Call about once per second.
    mutating func tick() {
        let now = monotonicNow()
        let dt = max(0.05, now - last)
        last = now
        let inst = bucket / dt
        bucket = 0
        // ~5 s smoothing, but react quickly upwards from zero.
        rate = rate == 0 ? inst : rate * 0.6 + inst * 0.4
    }

    var bytesPerSecond: Double { rate }
}
