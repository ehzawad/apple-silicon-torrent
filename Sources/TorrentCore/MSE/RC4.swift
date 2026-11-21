import Foundation

/// RC4 stream cipher (the MSE/PE "RC4-160" payload cipher).
///
/// The state lives in a raw 256-byte buffer and the keystream is XORed in place
/// over raw memory, so there are no bounds checks or allocations in the hot
/// loop (~1.3 GB/s on one M-series core in release builds). Not thread-safe: an
/// instance belongs to one stream direction on one event loop.
final class RC4 {
    private let s: UnsafeMutablePointer<UInt8>
    private var i: UInt8 = 0
    private var j: UInt8 = 0

    init<K: Collection>(key: K) where K.Element == UInt8 {
        let k = Array(key)
        precondition(!k.isEmpty, "RC4 key must not be empty")
        s = UnsafeMutablePointer<UInt8>.allocate(capacity: 256)
        for x in 0..<256 { s[x] = UInt8(x) }
        var jj: UInt8 = 0
        let kc = k.count
        for x in 0..<256 {
            jj = jj &+ s[x] &+ k[x % kc]
            let t = s[x]
            s[x] = s[Int(jj)]
            s[Int(jj)] = t
        }
    }

    deinit { s.deallocate() }

    /// XOR the keystream into `count` bytes at `p`, in place.
    func process(_ p: UnsafeMutablePointer<UInt8>, count: Int) {
        var i = self.i, j = self.j
        let s = self.s
        var k = 0
        while k < count {
            i &+= 1
            let si = s[Int(i)]
            j &+= si
            let sj = s[Int(j)]
            s[Int(i)] = sj
            s[Int(j)] = si
            p[k] ^= s[Int(si &+ sj)]
            k += 1
        }
        self.i = i
        self.j = j
    }

    /// XOR the keystream into a raw buffer, in place.
    @inline(__always)
    func process(_ buf: UnsafeMutableRawBufferPointer) {
        guard let base = buf.baseAddress, buf.count > 0 else { return }
        process(base.assumingMemoryBound(to: UInt8.self), count: buf.count)
    }

    /// XOR the keystream into `bytes[range]`, in place.
    func process(_ bytes: inout [UInt8], range: Range<Int>) {
        guard !range.isEmpty else { return }
        bytes.withUnsafeMutableBufferPointer { bp in
            process(bp.baseAddress! + range.lowerBound, count: range.count)
        }
    }

    /// Encrypt/decrypt a copy of `data`.
    func processed(_ data: Data) -> Data {
        var d = data
        d.withUnsafeMutableBytes { process($0) }
        return d
    }

    /// Advance the keystream by `count` bytes (MSE drops the first 1024).
    func discard(_ count: Int) {
        var i = self.i, j = self.j
        let s = self.s
        for _ in 0..<count {
            i &+= 1
            let si = s[Int(i)]
            j &+= si
            let sj = s[Int(j)]
            s[Int(i)] = sj
            s[Int(j)] = si
        }
        self.i = i
        self.j = j
    }
}
