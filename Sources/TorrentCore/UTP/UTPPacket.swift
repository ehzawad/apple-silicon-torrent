import Foundation

// uTP wire format (BEP 29). All integers are big-endian.
//
//  0       4       8               16              24              32
//  +-------+-------+---------------+---------------+---------------+
//  | type  | ver   | extension     | connection_id                 |
//  +-------+-------+---------------+---------------+---------------+
//  | timestamp_microseconds                                        |
//  +---------------+---------------+---------------+---------------+
//  | timestamp_difference_microseconds                             |
//  +---------------+---------------+---------------+---------------+
//  | wnd_size                                                      |
//  +---------------+---------------+---------------+---------------+
//  | seq_nr                        | ack_nr                        |
//  +---------------+---------------+---------------+---------------+
//
// Followed by an extension chain: [next_ext u8][len u8][len bytes]... and the payload.

/// uTP packet types.
enum UTPType: UInt8, Sendable {
    case data = 0, fin = 1, state = 2, reset = 3, syn = 4
}

/// Fixed 20-byte uTP header.
struct UTPHeader: Equatable, Sendable {
    static let size = 20
    static let version: UInt8 = 1

    var type: UTPType
    /// Type of the first extension in the chain (0 = none). Informational on decode.
    var firstExtension: UInt8 = 0
    var connectionID: UInt16
    var timestamp: UInt32
    var timestampDiff: UInt32
    var windowSize: UInt32
    var seqNr: UInt16
    var ackNr: UInt16

    init(type: UTPType, firstExtension: UInt8 = 0, connectionID: UInt16, timestamp: UInt32 = 0,
         timestampDiff: UInt32 = 0, windowSize: UInt32 = 0, seqNr: UInt16, ackNr: UInt16) {
        self.type = type
        self.firstExtension = firstExtension
        self.connectionID = connectionID
        self.timestamp = timestamp
        self.timestampDiff = timestampDiff
        self.windowSize = windowSize
        self.seqNr = seqNr
        self.ackNr = ackNr
    }

    /// Write the 20-byte header at `p` (which must have room for 20 bytes).
    @inline(__always)
    func write(to p: UnsafeMutableRawPointer) {
        p.storeBytes(of: type.rawValue << 4 | UTPHeader.version, toByteOffset: 0, as: UInt8.self)
        p.storeBytes(of: firstExtension, toByteOffset: 1, as: UInt8.self)
        p.storeBytes(of: connectionID.bigEndian, toByteOffset: 2, as: UInt16.self)
        p.storeBytes(of: timestamp.bigEndian, toByteOffset: 4, as: UInt32.self)
        p.storeBytes(of: timestampDiff.bigEndian, toByteOffset: 8, as: UInt32.self)
        p.storeBytes(of: windowSize.bigEndian, toByteOffset: 12, as: UInt32.self)
        p.storeBytes(of: seqNr.bigEndian, toByteOffset: 16, as: UInt16.self)
        p.storeBytes(of: ackNr.bigEndian, toByteOffset: 18, as: UInt16.self)
    }

    /// Patch the per-transmission fields of an already encoded packet in place.
    @inline(__always)
    static func patch(_ p: UnsafeMutableRawPointer, timestamp: UInt32, timestampDiff: UInt32,
                      windowSize: UInt32, ackNr: UInt16) {
        p.storeBytes(of: timestamp.bigEndian, toByteOffset: 4, as: UInt32.self)
        p.storeBytes(of: timestampDiff.bigEndian, toByteOffset: 8, as: UInt32.self)
        p.storeBytes(of: windowSize.bigEndian, toByteOffset: 12, as: UInt32.self)
        p.storeBytes(of: ackNr.bigEndian, toByteOffset: 18, as: UInt16.self)
    }
}

/// A decoded packet. Ranges are offsets relative to the datagram's `startIndex`.
struct UTPPacket: Sendable {
    var header: UTPHeader
    /// Selective-ACK bitmask bytes (extension type 1), if present.
    var sack: Range<Int>?
    /// Offset of the first payload byte.
    var payloadOffset: Int
    var payloadCount: Int
}

enum UTPCodec {
    static let extSelectiveAck: UInt8 = 1

    /// Decode a datagram. Returns nil for anything that is not a well-formed uTP v1
    /// packet (short, wrong version/type, truncated extension chain). Never traps.
    static func parse(_ datagram: Data) -> UTPPacket? {
        let n = datagram.count
        guard n >= UTPHeader.size else { return nil }
        return datagram.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> UTPPacket? in
            let b0 = raw[0]
            guard b0 & 0x0F == UTPHeader.version, let type = UTPType(rawValue: b0 >> 4) else { return nil }
            @inline(__always) func u16(_ o: Int) -> UInt16 { UInt16(raw[o]) << 8 | UInt16(raw[o + 1]) }
            @inline(__always) func u32(_ o: Int) -> UInt32 {
                UInt32(raw[o]) << 24 | UInt32(raw[o + 1]) << 16 | UInt32(raw[o + 2]) << 8 | UInt32(raw[o + 3])
            }
            let first = raw[1]
            let header = UTPHeader(type: type, firstExtension: first, connectionID: u16(2), timestamp: u32(4),
                                   timestampDiff: u32(8), windowSize: u32(12), seqNr: u16(16), ackNr: u16(18))
            var ext = first
            var off = UTPHeader.size
            var sack: Range<Int>?
            var hops = 0
            while ext != 0 {
                guard off + 2 <= n else { return nil }
                let next = raw[off]
                let len = Int(raw[off + 1])
                guard off + 2 + len <= n else { return nil }
                if ext == extSelectiveAck, sack == nil, len > 0 { sack = (off + 2)..<(off + 2 + len) }
                off += 2 + len
                ext = next
                hops += 1
                if hops > 32 { return nil }
            }
            return UTPPacket(header: header, sack: sack, payloadOffset: off, payloadCount: n - off)
        }
    }

    /// Encode a complete packet (header + optional SACK extension + payload).
    static func encode(_ h: UTPHeader, sack: [UInt8] = [], payload: Data = Data()) -> Data {
        var hdr = h
        let extLen = sack.isEmpty ? 0 : 2 + sack.count
        hdr.firstExtension = sack.isEmpty ? 0 : extSelectiveAck
        var out = Data(count: UTPHeader.size + extLen + payload.count)
        out.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            let p = raw.baseAddress!
            hdr.write(to: p)
            var off = UTPHeader.size
            if !sack.isEmpty {
                p.storeBytes(of: 0, toByteOffset: off, as: UInt8.self)   // no further extension
                p.storeBytes(of: UInt8(sack.count), toByteOffset: off + 1, as: UInt8.self)
                off += 2
                sack.withUnsafeBytes { s in (p + off).copyMemory(from: s.baseAddress!, byteCount: s.count) }
                off += sack.count
            }
            if !payload.isEmpty {
                payload.withUnsafeBytes { s in (p + off).copyMemory(from: s.baseAddress!, byteCount: s.count) }
            }
        }
        return out
    }
}

// MARK: - Sequence number arithmetic (16-bit wrapping)

enum UTPSeq {
    /// a < b in wrapping 16-bit space.
    @inline(__always) static func lt(_ a: UInt16, _ b: UInt16) -> Bool { Int16(bitPattern: a &- b) < 0 }
    @inline(__always) static func lte(_ a: UInt16, _ b: UInt16) -> Bool { Int16(bitPattern: a &- b) <= 0 }
    @inline(__always) static func gt(_ a: UInt16, _ b: UInt16) -> Bool { lt(b, a) }
    /// Forward distance from `a` to `b` (b - a mod 2^16).
    @inline(__always) static func dist(_ a: UInt16, _ b: UInt16) -> Int { Int(b &- a) }
}

/// Wrapping 32-bit comparison for microsecond timestamps / delays.
@inline(__always) func utpLess32(_ a: UInt32, _ b: UInt32) -> Bool { Int32(bitPattern: a &- b) < 0 }

// MARK: - Selective ACK bitmask (extension type 1)

/// Bit `i` of the mask (byte `i / 8`, least significant bit first) acknowledges
/// sequence number `ack_nr + 2 + i`; `ack_nr + 1` is implicitly missing.
enum UTPSack {
    /// Build a bitmask whose length is a multiple of 4 bytes (≤ `maxBytes`), trimmed
    /// to the highest set bit. Returns [] when nothing beyond `ackNr + 1` is held.
    static func encode(ackNr: UInt16, maxBytes: Int = 32, has: (UInt16) -> Bool) -> [UInt8] {
        let maxBits = (maxBytes / 4) * 32
        var mask = [UInt8](repeating: 0, count: maxBits / 8)
        var highest = -1
        for i in 0..<maxBits where has(ackNr &+ 2 &+ UInt16(truncatingIfNeeded: i)) {
            mask[i >> 3] |= 1 << UInt8(i & 7)
            highest = i
        }
        guard highest >= 0 else { return [] }
        let bytes = ((highest / 32) + 1) * 4
        return Array(mask[0..<bytes])
    }

    /// Sequence numbers acknowledged by `mask` relative to `ackNr`.
    static func decode(ackNr: UInt16, mask: some Collection<UInt8>) -> [UInt16] {
        var out: [UInt16] = []
        var i = 0
        for byte in mask {
            if byte != 0 {
                for bit in 0..<8 where byte & (1 << UInt8(bit)) != 0 {
                    out.append(ackNr &+ 2 &+ UInt16(truncatingIfNeeded: i * 8 + bit))
                }
            }
            i += 1
        }
        return out
    }
}

// MARK: - Sequence-indexed ring buffer

/// A growable ring indexed by 16-bit sequence number. All occupied slots must lie in
/// a window `[base, base + capacity)`; `reserve` grows the ring preserving that window.
struct UTPSeqRing<T> {
    private(set) var slots: [T?]
    private var mask: Int

    init(capacity: Int = 64) {
        var c = 16
        while c < capacity { c <<= 1 }
        slots = Array(repeating: nil, count: c)
        mask = c - 1
    }

    var capacity: Int { slots.count }

    @inline(__always) subscript(seq: UInt16) -> T? {
        get { slots[Int(seq) & mask] }
        set { slots[Int(seq) & mask] = newValue }
    }

    /// Ensure `span` slots starting at `base` can be addressed without collision.
    mutating func reserve(span: Int, base: UInt16) {
        guard span > slots.count else { return }
        var c = slots.count
        while c < span { c <<= 1 }
        var fresh = [T?](repeating: nil, count: c)
        let newMask = c - 1
        for i in 0..<slots.count {
            let s = Int(base &+ UInt16(truncatingIfNeeded: i))
            fresh[s & newMask] = slots[s & mask]
        }
        slots = fresh
        mask = newMask
    }

    mutating func removeAll() {
        for i in slots.indices { slots[i] = nil }
    }
}

// MARK: - Send queue (chunk deque, no copying on write)

struct UTPByteQueue {
    private var chunks: [Data] = []
    private var head = 0
    private var headOffset = 0
    private(set) var count = 0

    var isEmpty: Bool { count == 0 }

    mutating func append(_ d: Data) {
        guard !d.isEmpty else { return }
        chunks.append(d)
        count += d.count
    }

    /// Move up to `n` bytes into `dst`, returning the number copied.
    mutating func read(into dst: UnsafeMutableRawPointer, _ n: Int) -> Int {
        var copied = 0
        while copied < n && head < chunks.count {
            let chunk = chunks[head]
            let avail = chunk.count - headOffset
            let take = min(avail, n - copied)
            chunk.withUnsafeBytes { raw in
                (dst + copied).copyMemory(from: raw.baseAddress! + headOffset, byteCount: take)
            }
            copied += take
            headOffset += take
            if headOffset == chunk.count {
                chunks[head] = Data()
                head += 1
                headOffset = 0
            }
        }
        count -= copied
        if head == chunks.count {
            chunks.removeAll(keepingCapacity: chunks.count < 1024)
            head = 0
        } else if head >= 64 && head * 2 >= chunks.count {
            chunks.removeFirst(head)
            head = 0
        }
        return copied
    }

    mutating func removeAll() {
        chunks = []
        head = 0
        headOffset = 0
        count = 0
    }
}
