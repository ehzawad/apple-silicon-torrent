import Foundation

/// A 160-bit Kademlia identifier (node id, info hash or lookup target).
///
/// Stored as three big-endian words so that XOR distance, ordering and
/// common-prefix computations are a handful of instructions. Ordering (`<`) is the
/// lexicographic order of the 20 raw bytes, so `(a ^ t) < (b ^ t)` means "a is
/// closer to t than b" under the Kademlia XOR metric.
struct DHTID: Hashable, Comparable, Sendable, CustomStringConvertible {
    var w0: UInt64   // bytes 0..<8
    var w1: UInt64   // bytes 8..<16
    var w2: UInt32   // bytes 16..<20

    static let zero = DHTID(w0: 0, w1: 0, w2: 0)
    static let allOnes = DHTID(w0: .max, w1: .max, w2: .max)

    init(w0: UInt64, w1: UInt64, w2: UInt32) {
        self.w0 = w0
        self.w1 = w1
        self.w2 = w2
    }

    /// From exactly 20 bytes; nil otherwise.
    init?(_ data: Data?) {
        guard let data, data.count == 20 else { return nil }
        self.init(raw: [UInt8](data))
    }

    /// From exactly 20 bytes; nil otherwise.
    init?(bytes: [UInt8]) {
        guard bytes.count == 20 else { return nil }
        self.init(raw: bytes)
    }

    private init(raw b: [UInt8]) {
        var a: UInt64 = 0, c: UInt64 = 0, d: UInt32 = 0
        for i in 0..<8 { a = a << 8 | UInt64(b[i]) }
        for i in 8..<16 { c = c << 8 | UInt64(b[i]) }
        for i in 16..<20 { d = d << 8 | UInt32(b[i]) }
        self.init(w0: a, w1: c, w2: d)
    }

    var bytes: [UInt8] {
        var out = [UInt8](repeating: 0, count: 20)
        for i in 0..<8 { out[i] = UInt8(truncatingIfNeeded: w0 >> UInt64(56 - 8 * i)) }
        for i in 0..<8 { out[8 + i] = UInt8(truncatingIfNeeded: w1 >> UInt64(56 - 8 * i)) }
        for i in 0..<4 { out[16 + i] = UInt8(truncatingIfNeeded: w2 >> UInt32(24 - 8 * i)) }
        return out
    }

    var data: Data { Data(bytes) }
    var description: String { data.hex }

    static func random() -> DHTID { DHTID(raw: [UInt8](Data.random(20))) }

    // MARK: Bit operations

    static func ^ (a: DHTID, b: DHTID) -> DHTID { DHTID(w0: a.w0 ^ b.w0, w1: a.w1 ^ b.w1, w2: a.w2 ^ b.w2) }
    static func & (a: DHTID, b: DHTID) -> DHTID { DHTID(w0: a.w0 & b.w0, w1: a.w1 & b.w1, w2: a.w2 & b.w2) }
    static func | (a: DHTID, b: DHTID) -> DHTID { DHTID(w0: a.w0 | b.w0, w1: a.w1 | b.w1, w2: a.w2 | b.w2) }
    static prefix func ~ (a: DHTID) -> DHTID { DHTID(w0: ~a.w0, w1: ~a.w1, w2: ~a.w2) }

    static func < (a: DHTID, b: DHTID) -> Bool {
        if a.w0 != b.w0 { return a.w0 < b.w0 }
        if a.w1 != b.w1 { return a.w1 < b.w1 }
        return a.w2 < b.w2
    }

    /// Number of leading zero bits (160 for the zero id).
    var leadingZeroBitCount: Int {
        if w0 != 0 { return w0.leadingZeroBitCount }
        if w1 != 0 { return 64 + w1.leadingZeroBitCount }
        if w2 != 0 { return 128 + w2.leadingZeroBitCount }
        return 160
    }

    /// Length of the shared prefix with `other` (160 when equal).
    @inline(__always)
    func commonPrefixLength(with other: DHTID) -> Int { (self ^ other).leadingZeroBitCount }

    /// Bit `i` counting from the most significant bit of byte 0.
    func bit(_ i: Int) -> Bool {
        switch i {
        case 0..<64: return (w0 >> UInt64(63 - i)) & 1 == 1
        case 64..<128: return (w1 >> UInt64(127 - i)) & 1 == 1
        case 128..<160: return (w2 >> UInt32(159 - i)) & 1 == 1
        default: return false
        }
    }

    func flippingBit(_ i: Int) -> DHTID {
        var r = self
        switch i {
        case 0..<64: r.w0 ^= 1 << UInt64(63 - i)
        case 64..<128: r.w1 ^= 1 << UInt64(127 - i)
        case 128..<160: r.w2 ^= 1 << UInt32(159 - i)
        default: break
        }
        return r
    }

    /// Mask with the first `n` bits set.
    static func prefixMask(_ n: Int) -> DHTID {
        let n = Swift.max(0, Swift.min(160, n))
        let a: UInt64 = n >= 64 ? .max : (n == 0 ? 0 : ~(UInt64.max >> UInt64(n)))
        let b: UInt64 = n >= 128 ? .max : (n <= 64 ? 0 : ~(UInt64.max >> UInt64(n - 64)))
        let c: UInt32 = n >= 160 ? .max : (n <= 128 ? 0 : ~(UInt32.max >> UInt32(n - 128)))
        return DHTID(w0: a, w1: b, w2: c)
    }

    /// A random id sharing the first `prefix` bits with `self`. With `exact`, bit
    /// `prefix` is forced to differ so the shared prefix is exactly `prefix` bits
    /// (i.e. the id falls into routing bucket `prefix` of a table owned by `self`).
    func randomID(sharingPrefix prefix: Int, exact: Bool) -> DHTID {
        let m = DHTID.prefixMask(prefix)
        var r = (self & m) | (DHTID.random() & ~m)
        if exact, prefix < 160, r.bit(prefix) == bit(prefix) { r = r.flippingBit(prefix) }
        return r
    }

    /// Treating `self` as the target: is `a` strictly closer than `b`?
    @inline(__always)
    func isCloser(_ a: DHTID, than b: DHTID) -> Bool { (a ^ self) < (b ^ self) }
}

/// BEP 42 — DHT security extension: node ids are derived from the node's external
/// IP so that an attacker cannot choose ids freely (Sybil / eclipse resistance).
enum BEP42 {
    /// CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) lookup table.
    static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? (c >> 1) ^ 0x82F6_3B78 : c >> 1 }
        return c
    }

    static func crc32c(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for b in bytes { crc = crcTable[Int((crc ^ UInt32(b)) & 0xFF)] ^ (crc >> 8) }
        return ~crc
    }

    /// The masked IP bytes fed to CRC-32C: IPv4 & 03 0f 3f ff, the first 8 bytes of
    /// IPv6 & 01 03 07 0f 1f 3f 7f ff, with the 3 low bits of `rand` in the top bits.
    static func crcInput(ip: IPAddress, rand: UInt8) -> [UInt8] {
        var b: [UInt8]
        let mask: [UInt8]
        if ip.isV4 {
            b = ip.bytes
            mask = [0x03, 0x0F, 0x3F, 0xFF]
        } else {
            b = Array(ip.bytes.prefix(8))
            mask = [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF]
        }
        for i in b.indices { b[i] &= mask[i] }
        b[0] |= (rand & 0x07) << 5
        return b
    }

    /// Generate a compliant node id for `ip`: the top 21 bits come from the CRC,
    /// the last byte is `rand`, everything else is random.
    static func nodeID(for ip: IPAddress, rand: UInt8? = nil) -> DHTID {
        let r = rand ?? (Data.random(1).first ?? 0)
        let crc = crc32c(crcInput(ip: ip, rand: r))
        var id = [UInt8](Data.random(20))
        id[0] = UInt8(truncatingIfNeeded: crc >> 24)
        id[1] = UInt8(truncatingIfNeeded: crc >> 16)
        id[2] = (UInt8(truncatingIfNeeded: crc >> 8) & 0xF8) | (id[2] & 0x07)
        id[19] = r
        return DHTID(bytes: id) ?? .random()
    }

    /// Local / private addresses are exempt from BEP 42 checks.
    static func isExempt(_ ip: IPAddress) -> Bool { ip.isPrivate || ip.isLoopback }

    /// True when `id` is a valid BEP 42 id for `ip` (or `ip` is exempt).
    static func isValid(_ id: DHTID, for ip: IPAddress) -> Bool {
        if isExempt(ip) { return true }
        let b = id.bytes
        let crc = crc32c(crcInput(ip: ip, rand: b[19]))
        return b[0] == UInt8(truncatingIfNeeded: crc >> 24)
            && b[1] == UInt8(truncatingIfNeeded: crc >> 16)
            && (b[2] & 0xF8) == (UInt8(truncatingIfNeeded: crc >> 8) & 0xF8)
    }
}
