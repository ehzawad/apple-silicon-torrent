import Foundation
import Darwin

/// An IPv4 or IPv6 address. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are
/// always normalised to `.v4` so peers are never duplicated across families.
public enum IPAddress: Hashable, Sendable, CustomStringConvertible {
    case v4(UInt32)                 // host byte order: a.b.c.d == a<<24 | b<<16 | c<<8 | d
    case v6(UInt64, UInt64)         // host byte order halves of the 128-bit big-endian value

    public init?(bytes: some Collection<UInt8>) {
        let b = Array(bytes)
        if b.count == 4 {
            self = .v4(UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3]))
        } else if b.count == 16 {
            var hi: UInt64 = 0, lo: UInt64 = 0
            for i in 0..<8 { hi = hi << 8 | UInt64(b[i]) }
            for i in 8..<16 { lo = lo << 8 | UInt64(b[i]) }
            if hi == 0 && (lo >> 32) == 0xFFFF {
                self = .v4(UInt32(truncatingIfNeeded: lo))
            } else {
                self = .v6(hi, lo)
            }
        } else {
            return nil
        }
    }

    /// Parse dotted-quad or IPv6 textual form (brackets allowed).
    public init?(_ string: String) {
        var s = string
        if s.hasPrefix("["), s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        var a4 = in_addr()
        if inet_pton(AF_INET, s, &a4) == 1 {
            self = .v4(UInt32(bigEndian: a4.s_addr))
            return
        }
        var a6 = in6_addr()
        if inet_pton(AF_INET6, s, &a6) == 1 {
            let bytes = withUnsafeBytes(of: &a6) { Array($0) }
            self.init(bytes: bytes)
            return
        }
        return nil
    }

    public var isV4: Bool { if case .v4 = self { return true }; return false }

    /// Identity used for bans: the address itself for IPv4, the /64 prefix for IPv6
    /// (one subscriber's network — abusive peers rotate addresses inside it).
    public var banKey: IPAddress {
        if case .v6(let hi, _) = self { return .v6(hi, 0) }
        return self
    }
    public var isV6: Bool { !isV4 }

    /// Network-order raw bytes (4 or 16).
    public var bytes: [UInt8] {
        switch self {
        case .v4(let a):
            return [UInt8(a >> 24), UInt8(a >> 16 & 0xFF), UInt8(a >> 8 & 0xFF), UInt8(a & 0xFF)]
        case .v6(let hi, let lo):
            var out = [UInt8](repeating: 0, count: 16)
            for i in 0..<8 { out[i] = UInt8(truncatingIfNeeded: hi >> (56 - 8 * UInt64(i))) }
            for i in 0..<8 { out[8 + i] = UInt8(truncatingIfNeeded: lo >> (56 - 8 * UInt64(i))) }
            return out
        }
    }

    public var description: String {
        switch self {
        case .v4(let a):
            return "\(a >> 24).\(a >> 16 & 0xFF).\(a >> 8 & 0xFF).\(a & 0xFF)"
        case .v6:
            var a6 = in6_addr()
            let b = bytes
            withUnsafeMutableBytes(of: &a6) { $0.copyBytes(from: b) }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &a6, &buf, socklen_t(buf.count))
            return String(cString: buf)
        }
    }

    public var isLoopback: Bool {
        switch self {
        case .v4(let a): return a >> 24 == 127
        case .v6(let hi, let lo): return hi == 0 && lo == 1
        }
    }

    /// RFC1918 / link-local / CGNAT / ULA — addresses that are not globally routable.
    public var isPrivate: Bool {
        switch self {
        case .v4(let a):
            let b0 = a >> 24, b1 = a >> 16 & 0xFF
            return b0 == 10 || (b0 == 172 && (16...31).contains(b1)) || (b0 == 192 && b1 == 168)
                || (b0 == 169 && b1 == 254) || (b0 == 100 && (64...127).contains(b1)) || b0 == 127
        case .v6(let hi, _):
            let top16 = hi >> 48
            return (top16 & 0xFE00) == 0xFC00 || (top16 & 0xFFC0) == 0xFE80 || isLoopback
        }
    }

    /// Addresses we must never connect to (unspecified, multicast, broadcast, reserved).
    public var isUnusable: Bool {
        switch self {
        case .v4(let a):
            let b0 = a >> 24
            return a == 0 || b0 == 0 || b0 >= 224
        case .v6(let hi, let lo):
            return (hi == 0 && lo == 0) || (hi >> 56) == 0xFF
        }
    }
}

/// An IP + port endpoint. Used for peers, DHT nodes, trackers and local binds.
public struct PeerAddress: Hashable, Sendable, CustomStringConvertible {
    public var ip: IPAddress
    public var port: UInt16

    public init(ip: IPAddress, port: UInt16) {
        self.ip = ip
        self.port = port
    }

    /// Parse "1.2.3.4:6881" or "[2001:db8::1]:6881".
    public init?(_ string: String) {
        if string.hasPrefix("[") {
            guard let close = string.firstIndex(of: "]") else { return nil }
            let host = String(string[string.index(after: string.startIndex)..<close])
            let rest = string[string.index(after: close)...]
            guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()), let ip = IPAddress(host) else { return nil }
            self.init(ip: ip, port: p)
        } else {
            guard let colon = string.lastIndex(of: ":"), let p = UInt16(string[string.index(after: colon)...]),
                  let ip = IPAddress(String(string[..<colon])) else { return nil }
            self.init(ip: ip, port: p)
        }
    }

    public var description: String {
        ip.isV4 ? "\(ip):\(port)" : "[\(ip)]:\(port)"
    }

    // MARK: Compact encodings (BEP 23 / BEP 5 / BEP 7 / BEP 11)

    /// 6 bytes (IPv4) or 18 bytes (IPv6): address followed by big-endian port.
    public var compact: [UInt8] {
        ip.bytes + [UInt8(port >> 8), UInt8(port & 0xFF)]
    }

    public init?(compact b: some Collection<UInt8>) {
        let a = Array(b)
        guard a.count == 6 || a.count == 18, let ip = IPAddress(bytes: a[0..<(a.count - 2)]) else { return nil }
        self.init(ip: ip, port: UInt16(a[a.count - 2]) << 8 | UInt16(a[a.count - 1]))
    }

    /// Decode a concatenated list of compact peers. `v6` selects 18-byte entries.
    public static func parseCompactList(_ data: Data, v6: Bool) -> [PeerAddress] {
        let stride = v6 ? 18 : 6
        guard data.count >= stride else { return [] }
        var out: [PeerAddress] = []
        out.reserveCapacity(data.count / stride)
        let bytes = [UInt8](data)
        var i = 0
        while i + stride <= bytes.count {
            if let p = PeerAddress(compact: bytes[i..<(i + stride)]), p.port != 0, !p.ip.isUnusable {
                out.append(p)
            }
            i += stride
        }
        return out
    }

    // MARK: sockaddr bridging

    public func withSockAddr<R>(_ body: (UnsafePointer<sockaddr>, socklen_t) throws -> R) rethrows -> R {
        switch ip {
        case .v4(let a):
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            sin.sin_port = port.bigEndian
            sin.sin_addr = in_addr(s_addr: a.bigEndian)
            return try withUnsafePointer(to: &sin) {
                try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    try body($0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        case .v6:
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            sin6.sin6_port = port.bigEndian
            let b = ip.bytes
            withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyBytes(from: b) }
            return try withUnsafePointer(to: &sin6) {
                try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    try body($0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
    }

    /// The pointer must refer to a Darwin sockaddr with at least `sa_len` readable bytes.
    public init?(sockaddr storage: UnsafePointer<sockaddr>) {
        self.init(sockaddr: storage, length: socklen_t(storage.pointee.sa_len))
    }

    init?(sockaddr storage: UnsafePointer<sockaddr>, length: socklen_t) {
        guard length >= 2 else { return nil }
        let header = UnsafeRawPointer(storage)
        let available = min(Int(length), Int(header.load(as: UInt8.self)))
        switch Int32(header.load(fromByteOffset: 1, as: UInt8.self)) {
        case AF_INET:
            guard available >= MemoryLayout<sockaddr_in>.size else { return nil }
            let sin = header.loadUnaligned(as: sockaddr_in.self)
            self.init(ip: .v4(UInt32(bigEndian: sin.sin_addr.s_addr)), port: UInt16(bigEndian: sin.sin_port))
        case AF_INET6:
            guard available >= MemoryLayout<sockaddr_in6>.size else { return nil }
            let sin6 = header.loadUnaligned(as: sockaddr_in6.self)
            var addr = sin6.sin6_addr
            let bytes = withUnsafeBytes(of: &addr) { Array($0) }
            guard let ip = IPAddress(bytes: bytes) else { return nil }
            self.init(ip: ip, port: UInt16(bigEndian: sin6.sin6_port))
        default:
            return nil
        }
    }
}
