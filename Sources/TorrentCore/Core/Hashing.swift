import Foundation
import CryptoKit

/// SHA-1 / SHA-256 via CryptoKit (uses the ARMv8 SHA extensions on every Apple
/// Silicon chip — M-series and A-series alike).
public enum Hash {
    @inline(__always)
    public static func sha1(_ data: some DataProtocol) -> Data {
        Data(Insecure.SHA1.hash(data: data))
    }

    @inline(__always)
    public static func sha1(_ raw: UnsafeRawBufferPointer) -> Data {
        { var h = Insecure.SHA1(); h.update(bufferPointer: raw); return Data(h.finalize()) }()
    }

    @inline(__always)
    public static func sha256(_ data: some DataProtocol) -> Data {
        Data(SHA256.hash(data: data))
    }

    @inline(__always)
    public static func sha256(_ raw: UnsafeRawBufferPointer) -> Data {
        { var h = SHA256(); h.update(bufferPointer: raw); return Data(h.finalize()) }()
    }

    /// SHA-256 of the concatenation of two 32-byte nodes (Merkle interior node).
    @inline(__always)
    public static func sha256Pair(_ a: Data, _ b: Data) -> Data {
        var h = SHA256()
        h.update(data: a)
        h.update(data: b)
        return Data(h.finalize())
    }
}

/// BitTorrent v2 (BEP 52) Merkle tree helpers. Leaves are SHA-256 of 16 KiB
/// blocks; missing leaves beyond the end of a file are 32 zero bytes, and pad
/// nodes at higher layers are the roots of all-zero subtrees.
public enum Merkle {
    public static let blockSize = 16 * 1024
    public static let zeroLeaf = Data(count: 32)

    /// Root of a perfect subtree whose leaves are all zero, with `2^height` leaves.
    public static func padHash(height: Int) -> Data {
        var h = zeroLeaf
        if height == 0 { return h }
        for _ in 0..<height { h = Hash.sha256Pair(h, h) }
        return h
    }

    /// Smallest power of two >= n (n >= 1).
    public static func nextPow2(_ n: Int) -> Int {
        var p = 1
        while p < n { p <<= 1 }
        return p
    }

    /// log2 of a power of two.
    public static func log2(_ n: Int) -> Int { n.trailingZeroBitCount }

    /// Merkle root over `leaves`, padding to `width` leaves (power of two) using
    /// pad nodes of the given leaf-level height (0 for real 16 KiB leaves).
    public static func root(leaves: [Data], width: Int, padHeight: Int = 0) -> Data {
        precondition(width >= max(1, leaves.count) && width & (width - 1) == 0)
        var level = leaves
        var pad = padHash(height: padHeight)
        var w = width
        while w > 1 {
            var next: [Data] = []
            next.reserveCapacity(w / 2)
            var i = 0
            while i < w {
                let l = i < level.count ? level[i] : pad
                let r = i + 1 < level.count ? level[i + 1] : pad
                if i >= level.count { break } // everything beyond is pad
                next.append(Hash.sha256Pair(l, r))
                i += 2
            }
            pad = Hash.sha256Pair(pad, pad)
            level = next
            w /= 2
        }
        return level.first ?? pad
    }

    /// Leaf hashes for a contiguous buffer of file data (last block may be short).
    public static func leafHashes(_ data: UnsafeRawBufferPointer) -> [Data] {
        var out: [Data] = []
        out.reserveCapacity((data.count + blockSize - 1) / blockSize)
        var off = 0
        while off < data.count {
            let n = min(blockSize, data.count - off)
            out.append(Hash.sha256(UnsafeRawBufferPointer(rebasing: data[off..<(off + n)])))
            off += n
        }
        return out
    }

    /// Hash of one v2 piece (the piece-layer node) from that piece's file data.
    /// `pieceLength` is the torrent piece length (power of two, >= 16 KiB).
    public static func pieceHash(_ data: UnsafeRawBufferPointer, pieceLength: Int) -> Data {
        let leaves = leafHashes(data)
        return root(leaves: leaves, width: pieceLength / blockSize)
    }

    /// For a file no larger than one piece: the pieces root is computed directly
    /// over its blocks padded to the next power of two.
    public static func smallFileRoot(_ data: UnsafeRawBufferPointer) -> Data {
        let leaves = leafHashes(data)
        return root(leaves: leaves, width: nextPow2(max(1, leaves.count)))
    }

    /// All tree levels from the (padded) piece layer up to the root.
    public static func levels(pieceLayer layer: [Data], pieceLength: Int) -> [[Data]]? {
        guard !layer.isEmpty else { return nil }
        let width = nextPow2(layer.count)
        let pad = padHash(height: log2(pieceLength / blockSize))
        var level = layer + [Data](repeating: pad, count: width - layer.count)
        var all = [level]
        while level.count > 1 {
            level = stride(from: 0, to: level.count, by: 2).map { Hash.sha256Pair(level[$0], level[$0 + 1]) }
            all.append(level)
        }
        return all
    }

    /// BEP 52 'hashes' payload: `length` hashes from level 0 starting at `index`, followed by
    /// uncle hashes for proof layers log2(length)…proof (lower layers are implied).
    public static func hashResponse(levels: [[Data]], index: Int, length: Int, proof: Int) -> Data? {
        guard length >= 2, length & (length - 1) == 0, index >= 0, index % length == 0,
              index + length <= levels[0].count else { return nil }
        var out = Data(capacity: (length + max(0, proof)) * 32)
        for h in levels[0][index..<(index + length)] { out.append(h) }
        let firstUncle = log2(length)
        var idx = index >> firstUncle
        var k = firstUncle
        while k <= proof && k < levels.count - 1 {
            out.append(levels[k][idx ^ 1])
            idx >>= 1
            k += 1
        }
        return out
    }

    /// Pieces root of a multi-piece file from its piece layer.
    public static func rootFromPieceLayer(_ pieceHashes: [Data], pieceLength: Int) -> Data {
        let padHeight = log2(pieceLength / blockSize)
        return root(leaves: pieceHashes, width: nextPow2(pieceHashes.count), padHeight: padHeight)
    }
}

// MARK: - Bitfield

/// Piece bitfield with BitTorrent bit ordering (MSB of byte 0 = piece 0).
public struct Bitfield: Sendable, Equatable {
    public private(set) var bytes: [UInt8]
    public let count: Int
    public private(set) var setCount: Int

    public init(count: Int, allSet: Bool = false) {
        self.count = count
        bytes = [UInt8](repeating: allSet ? 0xFF : 0, count: (count + 7) / 8)
        setCount = allSet ? count : 0
        if allSet { clearSpareBits() }
    }

    /// From wire bytes; returns nil if spare bits are set or length mismatches.
    public init?(wire: some Collection<UInt8>, count: Int) {
        let b = Array(wire)
        guard b.count == (count + 7) / 8 else { return nil }
        self.count = count
        self.bytes = b
        let spare = b.count * 8 - count
        if spare > 0, b.last! & UInt8((1 << spare) - 1) != 0 { return nil }
        setCount = b.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    private mutating func clearSpareBits() {
        let spare = bytes.count * 8 - count
        if spare > 0 { bytes[bytes.count - 1] &= ~UInt8((1 << spare) - 1) }
    }

    @inline(__always)
    public subscript(i: Int) -> Bool {
        get { bytes[i >> 3] & (0x80 >> UInt8(i & 7)) != 0 }
        set {
            let mask = UInt8(0x80) >> UInt8(i & 7)
            let was = bytes[i >> 3] & mask != 0
            if newValue == was { return }
            if newValue { bytes[i >> 3] |= mask; setCount += 1 } else { bytes[i >> 3] &= ~mask; setCount -= 1 }
        }
    }

    public var isComplete: Bool { setCount == count }
    public var isEmpty: Bool { setCount == 0 }
    public var data: Data { Data(bytes) }

    public mutating func setAll() {
        for i in bytes.indices { bytes[i] = 0xFF }
        clearSpareBits()
        setCount = count
    }

    /// Indices set in `self` but not in `other`.
    public func subtracting(_ other: Bitfield) -> [Int] {
        var out: [Int] = []
        for i in 0..<count where self[i] && !other[i] { out.append(i) }
        return out
    }
}

// MARK: - Byte helpers

public extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        func nib(_ c: UInt8) -> UInt8? {
            switch c {
            case 48...57: return c - 48
            case 65...70: return c - 55
            case 97...102: return c - 87
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let h = nib(chars[i]), let l = nib(chars[i + 1]) else { return nil }
            out.append(h << 4 | l)
            i += 2
        }
        self = out
    }

    static func random(_ count: Int) -> Data {
        var d = Data(count: count)
        d.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        return d
    }

    /// Big-endian integer readers (offset relative to startIndex).
    @inline(__always) func be32(_ off: Int) -> UInt32 {
        let s = startIndex + off
        return UInt32(self[s]) << 24 | UInt32(self[s + 1]) << 16 | UInt32(self[s + 2]) << 8 | UInt32(self[s + 3])
    }
    @inline(__always) func be16(_ off: Int) -> UInt16 {
        let s = startIndex + off
        return UInt16(self[s]) << 8 | UInt16(self[s + 1])
    }
    @inline(__always) func be64(_ off: Int) -> UInt64 {
        UInt64(be32(off)) << 32 | UInt64(be32(off + 4))
    }
    @inline(__always) func byte(_ off: Int) -> UInt8 { self[startIndex + off] }

    mutating func appendBE32(_ v: UInt32) {
        append(contentsOf: [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)])
    }
    mutating func appendBE16(_ v: UInt16) { append(contentsOf: [UInt8(v >> 8), UInt8(v & 0xFF)]) }
    mutating func appendBE64(_ v: UInt64) { appendBE32(UInt32(v >> 32)); appendBE32(UInt32(v & 0xFFFF_FFFF)) }
}

import Security

/// RFC 4648 base32 decoding (magnet links may carry 32-char base32 info hashes).
public enum Base32 {
    public static func decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var map = [UInt8: UInt8]()
        for (i, c) in alphabet.enumerated() { map[c] = UInt8(i) }
        var buffer: UInt32 = 0, bits = 0
        var out = Data()
        for c in s.uppercased().utf8 where c != UInt8(ascii: "=") {
            guard let v = map[c] else { return nil }
            buffer = buffer << 5 | UInt32(v)
            bits += 5
            if bits >= 8 {
                out.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bits - 8)))
                bits -= 8
            }
        }
        return out
    }
}
