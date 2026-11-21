import Foundation

/// Minimal unsigned big-integer support for MSE Diffie-Hellman: little-endian
/// 64-bit limbs and Montgomery modular exponentiation for an odd modulus.
///
/// Only what MSE needs is implemented (no general division). The hot path
/// (`montMul`) works on raw pointers with `multipliedFullWidth`, so a 768-bit
/// modulus with a 160-bit exponent costs well under a millisecond.
enum BigLimbs {
    /// Big-endian bytes -> little-endian 64-bit limbs (at least `minLimbs` long).
    static func fromBigEndian<C: Collection>(_ bytes: C, minLimbs: Int = 0) -> [UInt64] where C.Element == UInt8 {
        let b = Array(bytes)
        let n = max(minLimbs, (b.count + 7) / 8, 1)
        var limbs = [UInt64](repeating: 0, count: n)
        var bit = 0
        for idx in stride(from: b.count - 1, through: 0, by: -1) {
            limbs[bit >> 6] |= UInt64(b[idx]) << UInt64(bit & 63)
            bit += 8
        }
        return limbs
    }

    /// Little-endian limbs -> big-endian bytes, left-padded (or truncated from the
    /// top) to exactly `byteCount` bytes.
    static func toBigEndian(_ limbs: [UInt64], byteCount: Int) -> Data {
        var out = Data(count: byteCount)
        out.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self)
            for k in 0..<byteCount {
                let bit = k * 8
                let limb = bit >> 6
                guard limb < limbs.count else { break }
                p[byteCount - 1 - k] = UInt8(truncatingIfNeeded: limbs[limb] >> UInt64(bit & 63))
            }
        }
        return out
    }

    /// Number of significant bits.
    static func bitLength(_ a: [UInt64]) -> Int {
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != 0 {
            return i * 64 + (64 - a[i].leadingZeroBitCount)
        }
        return 0
    }

    /// Compare (lengths may differ). Returns -1, 0, 1.
    static func compare(_ a: [UInt64], _ b: [UInt64]) -> Int {
        let n = max(a.count, b.count)
        for i in stride(from: n - 1, through: 0, by: -1) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y ? -1 : 1 }
        }
        return 0
    }

    /// a -= b in place (requires a >= b, b.count <= a.count). Returns borrow.
    @discardableResult
    static func subtract(_ a: inout [UInt64], _ b: [UInt64]) -> Bool {
        var borrow = false
        for i in 0..<a.count {
            let y = i < b.count ? b[i] : 0
            let (d1, o1) = a[i].subtractingReportingOverflow(y)
            let (d2, o2) = d1.subtractingReportingOverflow(borrow ? 1 : 0)
            a[i] = d2
            borrow = o1 || o2
        }
        return borrow
    }

    /// Generic `a mod m` by binary long division (slow, but only used to reduce
    /// inputs once per exponentiation). Result has `m.count` limbs.
    static func mod(_ a: [UInt64], _ m: [UInt64]) -> [UInt64] {
        let n = m.count
        if compare(a, m) < 0 {
            var r = a
            if r.count < n { r += [UInt64](repeating: 0, count: n - r.count) }
            return Array(r.prefix(n))
        }
        var r = [UInt64](repeating: 0, count: n)
        for bit in stride(from: bitLength(a) - 1, through: 0, by: -1) {
            // r = 2r + bit
            var carry = (a[bit >> 6] >> UInt64(bit & 63)) & 1
            for i in 0..<n {
                let next = r[i] >> 63
                r[i] = r[i] << 1 | carry
                carry = next
            }
            if carry != 0 || compare(r, m) >= 0 { subtract(&r, m) }
        }
        return r
    }
}

/// Precomputed Montgomery parameters for an odd modulus.
struct Montgomery: Sendable {
    let n: Int                 // limb count
    let modulus: [UInt64]      // little-endian, top limb non-zero
    let m0inv: UInt64          // -m^-1 mod 2^64
    let r2: [UInt64]           // R^2 mod m, R = 2^(64n)
    let oneM: [UInt64]         // R mod m (1 in Montgomery form)

    init(modulus m: [UInt64]) {
        var m = m
        while m.count > 1 && m.last == 0 { m.removeLast() }
        precondition(m[0] & 1 == 1, "Montgomery modulus must be odd")
        n = m.count
        modulus = m
        // Newton iteration for m0^-1 mod 2^64 (each step doubles correct bits).
        var inv: UInt64 = 1
        for _ in 0..<6 { inv = inv &* (2 &- m[0] &* inv) }
        m0inv = 0 &- inv
        // R mod m, then R^2 mod m, by repeated modular doubling of 1.
        var x = [UInt64](repeating: 0, count: m.count)
        x[0] = 1
        func double(_ x: inout [UInt64]) {
            var carry: UInt64 = 0
            for i in 0..<x.count {
                let next = x[i] >> 63
                x[i] = x[i] << 1 | carry
                carry = next
            }
            if carry != 0 || BigLimbs.compare(x, m) >= 0 { BigLimbs.subtract(&x, m) }
        }
        if m.count == 1 && m[0] == 1 { x[0] = 0 }
        for _ in 0..<(64 * m.count) { double(&x) }
        oneM = x
        for _ in 0..<(64 * m.count) { double(&x) }
        r2 = x
    }

    /// out = a * b * R^-1 mod m. Requires a, b < m; `t` is scratch of n + 1 limbs.
    ///
    /// Fused multiply/reduce per outer word (FIOS): for each word b[i] the row
    /// a*b[i] is added and q*m (chosen so the low word cancels) is folded in the
    /// same pass while shifting down one word. Invariant: t < 2m, so t[n] <= 1.
    /// Index arithmetic is wrapping to keep overflow traps out of the hot loop.
    @inline(__always)
    private func montMul(_ a: UnsafePointer<UInt64>, _ b: UnsafePointer<UInt64>,
                         _ out: UnsafeMutablePointer<UInt64>, _ t: UnsafeMutablePointer<UInt64>,
                         _ mod: UnsafePointer<UInt64>) {
        let n = self.n
        let m0inv = self.m0inv
        var k = 0
        while k <= n { t[k] = 0; k &+= 1 }
        var i = 0
        while i < n {
            let bi = b[i]
            // Column 0: u = t[0] + a[0]*bi; q makes (u + q*m[0]) ≡ 0 mod 2^64.
            let (h0, l0) = a[0].multipliedFullWidth(by: bi)
            let (u0, ou) = l0.addingReportingOverflow(t[0])
            var c1 = h0 &+ (ou ? 1 : 0)
            let q = u0 &* m0inv
            let (hq, lq) = q.multipliedFullWidth(by: mod[0])
            let (_, oq) = lq.addingReportingOverflow(u0)
            var c2 = hq &+ (oq ? 1 : 0)
            var j = 1
            while j < n {
                let (h, l) = a[j].multipliedFullWidth(by: bi)
                let (s1, o1) = l.addingReportingOverflow(t[j])
                let (s2, o2) = s1.addingReportingOverflow(c1)
                c1 = h &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0)
                let (hm, lm) = q.multipliedFullWidth(by: mod[j])
                let (s3, o3) = lm.addingReportingOverflow(s2)
                let (s4, o4) = s3.addingReportingOverflow(c2)
                c2 = hm &+ (o3 ? 1 : 0) &+ (o4 ? 1 : 0)
                t[j &- 1] = s4
                j &+= 1
            }
            let (s5, o5) = t[n].addingReportingOverflow(c1)
            let (s6, o6) = s5.addingReportingOverflow(c2)
            t[n &- 1] = s6
            t[n] = (o5 ? 1 : 0) &+ (o6 ? 1 : 0)
            i &+= 1
        }
        // Conditional final subtraction: t (n+1 limbs, < 2m) -> [0, m).
        var geq = t[n] != 0
        if !geq {
            geq = true
            var x = n &- 1
            while x >= 0 {
                if t[x] != mod[x] { geq = t[x] > mod[x]; break }
                x &-= 1
            }
        }
        if geq {
            var borrow = false
            var x = 0
            while x < n {
                let (d1, o1) = t[x].subtractingReportingOverflow(mod[x])
                let (d2, o2) = d1.subtractingReportingOverflow(borrow ? 1 : 0)
                out[x] = d2
                borrow = o1 || o2
                x &+= 1
            }
        } else {
            var x = 0
            while x < n { out[x] = t[x]; x &+= 1 }
        }
    }

    /// base^exponent mod m. `base` and `exponent` are little-endian limbs of any length.
    func modPow(_ base: [UInt64], _ exponent: [UInt64]) -> [UInt64] {
        let n = self.n
        if n == 1 && modulus[0] == 1 { return [0] }
        let b = BigLimbs.mod(base, modulus)
        let ebits = BigLimbs.bitLength(exponent)

        // Scratch: 16-entry window table + acc + tmp + t(n+2) + modulus + r2 + plain one.
        let tableCount = 16
        let total = tableCount * n + 2 * n + (n + 2) + 3 * n
        let mem = UnsafeMutablePointer<UInt64>.allocate(capacity: total)
        defer { mem.deallocate() }
        mem.initialize(repeating: 0, count: total)
        let table = mem
        let acc = mem + tableCount * n
        let tmp = acc + n
        let t = tmp + n
        let mod = t + n + 2
        let r2p = mod + n
        let one = r2p + n
        for i in 0..<n { mod[i] = modulus[i]; r2p[i] = r2[i]; table[i] = oneM[i] }
        one[0] = 1

        // table[1] = b * R mod m; table[k] = table[k-1] * table[1].
        b.withUnsafeBufferPointer { bp in montMul(bp.baseAddress!, r2p, table + n, t, mod) }
        for k in 2..<tableCount {
            montMul(table + (k - 1) * n, table + n, table + k * n, t, mod)
        }

        // Left-to-right 4-bit fixed windows.
        for i in 0..<n { acc[i] = oneM[i] }
        let windows = (ebits + 3) / 4
        var w = windows - 1
        while w >= 0 {
            if w != windows - 1 {
                for _ in 0..<4 {
                    montMul(acc, acc, tmp, t, mod)
                    acc.update(from: tmp, count: n)
                }
            }
            let bit = w * 4
            let limb = exponent[bit >> 6]
            let nib = Int((limb >> UInt64(bit & 63)) & 0xF)
            if nib != 0 {
                montMul(acc, table + nib * n, tmp, t, mod)
                acc.update(from: tmp, count: n)
            }
            w -= 1
        }
        // Leave Montgomery form: acc * 1 * R^-1.
        montMul(acc, one, tmp, t, mod)
        return Array(UnsafeBufferPointer(start: tmp, count: n))
    }
}
