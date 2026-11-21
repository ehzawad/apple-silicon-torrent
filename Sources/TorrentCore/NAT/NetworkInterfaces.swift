import Foundation
import Darwin

/// Portable Darwin (macOS + iOS) routing table and interface inspection helpers.
///
/// `<net/route.h>` is not present in the iPhoneOS SDK, even though the XNU
/// `sysctl([CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY])` binary ABI
/// (`struct rt_msghdr`, `RTM_VERSION == 5`, 4-byte sockaddr alignment) is identical
/// across macOS and iOS on Apple Silicon. We decode the binary header directly so
/// `TorrentCore` builds cleanly for both macOS 26 and iOS 26.
enum RouteDiscovery {
    // XNU <net/route.h> stable ABI constants
    static let rtmVersion: UInt8 = 5
    static let rtmGet: UInt8 = 4
    static let rtMsgHdrSize = 92

    static let rtfUp: Int32        = 0x1
    static let rtfGateway: Int32   = 0x2
    static let rtfHost: Int32      = 0x4
    static let rtfReject: Int32    = 0x8
    static let rtfBlackhole: Int32 = 0x1000
    static let rtfIfScope: Int32   = 0x0100_0000
    static let rtfCondemned: Int32 = 0x0200_0000
    static let rtfDead: Int32      = 0x2000_0000

    static let rtaDst: Int32     = 0x1
    static let rtaGateway: Int32 = 0x2
    static let rtaNetmask: Int32 = 0x4
    static let rtaxDst           = 0
    static let rtaxGateway       = 1
    static let rtaxNetmask       = 2
    static let rtaxIfa           = 5
    static let rtaxMax           = 8

    struct GatewayRoute: Equatable, Sendable {
        var gateway: IPAddress
        var interfaceIndex: UInt16
        var interfaceName: String?
        var interfaceAddress: IPAddress?
        var flags: Int32
        var isScoped: Bool { (flags & RouteDiscovery.rtfIfScope) != 0 }
    }

    /// Tunnel, loopback, and virtual interface name prefixes to skip when selecting
    /// a physical LAN interface or default gateway.
    private static let skippedInterfacePrefixes: [String] = [
        "utun", "tun", "tap", "ipsec", "ppp", "gif", "stf", "wg", "zt",
        "lo", "awdl", "llw", "nan", "feth", "pdp_ip", "anpi",
        "vmnet", "vmenet", "vnic", "vboxnet", "pktap", "iptap", "ap",
    ]

    /// True if an interface name or flags indicate a tunnel, loopback, or virtual
    /// non-LAN interface.
    static func isTunnelOrVirtualInterface(_ name: String?, flags: UInt32?) -> Bool {
        if let flags {
            if (flags & UInt32(IFF_LOOPBACK)) != 0 { return true }
            if (flags & UInt32(IFF_POINTOPOINT)) != 0 { return true }
        }
        guard let name, !name.isEmpty else { return false }
        let lower = name.lowercased()
        for prefix in skippedInterfacePrefixes {
            if lower.hasPrefix(prefix) {
                let rest = lower.dropFirst(prefix.count)
                if rest.isEmpty || rest.first?.isNumber == true {
                    return true
                }
            }
        }
        return false
    }

    /// Discover the IPv4 default gateway on a physical interface via the Darwin
    /// `sysctl(NET_RT_FLAGS, RTF_GATEWAY)` routing table dump.
    static func defaultGateway() -> IPAddress? {
        guard let raw = fetchIPv4GatewayRouteTable() else { return nil }
        let ifFlags = LocalNetwork.interfaceFlagsByName()
        return selectDefaultGateway(
            from: raw,
            interfaceName: Self.interfaceName(forIndex:),
            interfaceFlags: { ifFlags[$0] }
        )?.gateway
    }

    /// Fetch the raw XNU routing table buffer for IPv4 gateway routes.
    static func fetchIPv4GatewayRouteTable() -> Data? {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, rtfGateway]
        for _ in 0..<3 {
            var needed: Int = 0
            let rc1 = mib.withUnsafeMutableBufferPointer { ptr in
                sysctl(ptr.baseAddress, UInt32(ptr.count), nil, &needed, nil, 0)
            }
            guard rc1 == 0, needed > 0 else { return nil }

            // Allocate slight headroom in case the table grows slightly between calls.
            var length = needed + 512
            var buf = Data(count: length)
            let rc2 = buf.withUnsafeMutableBytes { rawBuf in
                mib.withUnsafeMutableBufferPointer { ptr in
                    sysctl(ptr.baseAddress, UInt32(ptr.count), rawBuf.baseAddress, &length, nil, 0)
                }
            }
            if rc2 == 0 {
                return buf.prefix(length)
            }
            if errno != ENOMEM { return nil }
        }
        return nil
    }

    /// Parse a Darwin `rt_msghdr` buffer and pick the best physical-interface default gateway.
    /// Factored as a pure function for deterministic offline unit testing.
    static func selectDefaultGateway(
        from data: Data,
        interfaceName: (UInt16) -> String?,
        interfaceFlags: (String) -> UInt32?
    ) -> GatewayRoute? {
        let candidates = parseDefaultGatewayRoutes(
            from: data,
            interfaceName: interfaceName,
            interfaceFlags: interfaceFlags
        )
        guard !candidates.isEmpty else { return nil }
        // Priority:
        // 1. Named interfaces over unnamed routes
        // 2. Non-scoped (global) physical default route before RTF_IFSCOPE route
        // 3. Standard Ethernet/Wi-Fi interfaces (`en*`) before other physical interfaces (e.g. `bridge*`)
        return candidates.min { a, b in
            let aNamed = a.interfaceName != nil
            let bNamed = b.interfaceName != nil
            if aNamed != bNamed { return aNamed }
            if a.isScoped != b.isScoped { return !a.isScoped }
            let aIsEn = a.interfaceName?.hasPrefix("en") == true
            let bIsEn = b.interfaceName?.hasPrefix("en") == true
            if aIsEn != bIsEn { return aIsEn }
            return false
        }
    }

    /// Parse all valid physical-interface IPv4 default gateway routes from a `sysctl` route dump.
    static func parseDefaultGatewayRoutes(
        from data: Data,
        interfaceName: (UInt16) -> String?,
        interfaceFlags: (String) -> UInt32?
    ) -> [GatewayRoute] {
        var results: [GatewayRoute] = []
        let base = data.startIndex
        let total = data.count
        var off = 0

        while off + rtMsgHdrSize <= total {
            let msglen = Int(readLE16(data, base + off))
            guard msglen >= rtMsgHdrSize, off + msglen <= total else { break }

            let version = data[base + off + 2]
            let rtmType = data[base + off + 3]
            let ifIndex = readLE16(data, base + off + 4)
            let flags = Int32(bitPattern: readLE32(data, base + off + 8))
            let addrs = Int32(bitPattern: readLE32(data, base + off + 12))

            defer { off += msglen }

            guard version == rtmVersion, rtmType == rtmGet else { continue }
            guard (flags & rtfUp) != 0, (flags & rtfGateway) != 0 else { continue }
            guard (flags & (rtfHost | rtfReject | rtfBlackhole | rtfDead | rtfCondemned)) == 0 else { continue }
            guard (addrs & rtaDst) != 0, (addrs & rtaGateway) != 0 else { continue }

            let msgEnd = off + msglen
            var saOff = off + rtMsgHdrSize
            var dstSlice: (offset: Int, length: Int)?
            var gwSlice: (offset: Int, length: Int)?
            var maskSlice: (offset: Int, length: Int)?
            var ifaSlice: (offset: Int, length: Int)?
            var truncated = false

            for bit in 0..<rtaxMax {
                guard (addrs & (1 << bit)) != 0 else { continue }
                guard saOff < msgEnd else { truncated = true; break }
                let saLen = Int(data[base + saOff])
                let step = roundUpSockAddrLen(saLen)
                // Reject truncated sockaddrs rather than misinterpreting short slices as /0 masks.
                guard saLen <= msgEnd - saOff, saOff + step <= msgEnd else {
                    truncated = true
                    break
                }
                switch bit {
                case rtaxDst: dstSlice = (saOff, saLen)
                case rtaxGateway: gwSlice = (saOff, saLen)
                case rtaxNetmask: maskSlice = (saOff, saLen)
                case rtaxIfa: ifaSlice = (saOff, saLen)
                default: break
                }
                saOff += step
            }
            guard !truncated else { continue }

            // Verify destination is AF_INET 0.0.0.0 (default route).
            guard let dst = dstSlice, isZeroIPv4SockAddr(data, base: base + dst.offset, length: dst.length) else {
                continue
            }
            // If RTA_NETMASK is advertised, it MUST be present and represent /0 (all zero bits).
            if (addrs & rtaNetmask) != 0 {
                guard let mask = maskSlice, isZeroNetmaskSockAddr(data, base: base + mask.offset, length: mask.length) else {
                    continue
                }
            }
            // Extract IPv4 gateway address.
            guard let gw = gwSlice,
                  let gatewayIP = parseIPv4SockAddr(data, base: base + gw.offset, length: gw.length),
                  !gatewayIP.isUnusable, !gatewayIP.isLoopback else {
                continue
            }

            let ifName: String?
            if ifIndex != 0 {
                guard let resolvedName = interfaceName(ifIndex) else {
                    // Stale/orphan interface index no longer present on the host.
                    continue
                }
                ifName = resolvedName
            } else {
                ifName = nil
            }

            let ifFl = ifName.flatMap(interfaceFlags)
            if let ifFl {
                let required = UInt32(IFF_UP | IFF_RUNNING)
                guard (ifFl & required) == required else { continue }
            }
            if isTunnelOrVirtualInterface(ifName, flags: ifFl) {
                continue
            }

            let ifaIP = ifaSlice.flatMap { parseIPv4SockAddr(data, base: base + $0.offset, length: $0.length) }
            results.append(GatewayRoute(
                gateway: gatewayIP,
                interfaceIndex: ifIndex,
                interfaceName: ifName,
                interfaceAddress: ifaIP,
                flags: flags
            ))
        }

        return results
    }

    /// XNU `ROUNDUP(a)` for routing sockaddrs: 4-byte (`uint32_t`) aligned, 0 -> 4.
    @inline(__always)
    static func roundUpSockAddrLen(_ a: Int) -> Int {
        a > 0 ? (1 + ((a - 1) | 3)) : 4
    }

    private static func isZeroIPv4SockAddr(_ data: Data, base: Int, length: Int) -> Bool {
        guard length >= 8 else { return false }
        let family = Int32(data[base + 1])
        guard family == AF_INET else { return false }
        return data[base + 4] == 0 && data[base + 5] == 0 && data[base + 6] == 0 && data[base + 7] == 0
    }

    private static func isZeroNetmaskSockAddr(_ data: Data, base: Int, length: Int) -> Bool {
        // BSD routing masks are prefix-trimmed: sa_len == 0 or <= 4 means 0.0.0.0/0.
        if length <= 4 { return true }
        let checkEnd = min(length, 8)
        for i in 4..<checkEnd {
            if data[base + i] != 0 { return false }
        }
        return true
    }

    private static func parseIPv4SockAddr(_ data: Data, base: Int, length: Int) -> IPAddress? {
        guard length >= 8, Int32(data[base + 1]) == AF_INET else { return nil }
        return IPAddress(bytes: data[(base + 4)..<(base + 8)])
    }

    private static func readLE16(_ data: Data, _ idx: Int) -> UInt16 {
        UInt16(data[idx]) | (UInt16(data[idx + 1]) << 8)
    }

    private static func readLE32(_ data: Data, _ idx: Int) -> UInt32 {
        UInt32(data[idx])
            | (UInt32(data[idx + 1]) << 8)
            | (UInt32(data[idx + 2]) << 16)
            | (UInt32(data[idx + 3]) << 24)
    }

    static func interfaceName(forIndex index: UInt16) -> String? {
        guard index != 0 else { return nil }
        var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        guard if_indextoname(UInt32(index), &buf) != nil else { return nil }
        let bytes = buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}

/// Local network interface and source-address helpers (macOS + iOS portable).
enum LocalNetwork {
    struct MulticastIPv4Interface: Sendable, Equatable {
        let name: String
        let index: UInt32
        let address: IPAddress
    }

    struct MulticastIPv6Interface: Sendable, Equatable {
        let name: String
        let index: UInt32
    }

    /// Determine the local IPv4 address used by the kernel to reach `destination`.
    /// Uses a UDP `connect()` + `getsockname()` lookup (sends zero packets, non-blocking).
    static func localIPv4Address(for destination: IPAddress) -> IPAddress? {
        guard destination.isV4 else { return nil }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }

        let target = PeerAddress(ip: destination, port: 5351)
        guard target.withSockAddr({ Darwin.connect(fd, $0, $1) }) == 0 else { return nil }

        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let rc = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        guard rc == 0 else { return nil }
        let ip = IPAddress.v4(UInt32(bigEndian: local.sin_addr.s_addr))
        return ip.isUnusable ? nil : ip
    }

    /// Snapshot of current interface flags keyed by interface name.
    static func interfaceFlagsByName() -> [String: UInt32] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [:] }
        defer { freeifaddrs(first) }
        var map: [String: UInt32] = [:]
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            let name = cString(ifa.pointee.ifa_name)
            map[name] = ifa.pointee.ifa_flags
            cur = ifa.pointee.ifa_next
        }
        return map
    }

    /// Active, physical, non-tunnel multicast-capable IPv4 interfaces.
    static func physicalMulticastIPv4Interfaces() -> [MulticastIPv4Interface] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(first) }

        var out: [MulticastIPv4Interface] = []
        var seen = Set<IPAddress>()
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            let flags = ifa.pointee.ifa_flags
            let required = UInt32(IFF_UP | IFF_RUNNING | IFF_MULTICAST)
            guard (flags & required) == required else { continue }
            let name = cString(ifa.pointee.ifa_name)
            guard !RouteDiscovery.isTunnelOrVirtualInterface(name, flags: flags) else { continue }
            guard let sa = ifa.pointee.ifa_addr,
                  Int32(sa.pointee.sa_family) == AF_INET,
                  Int(sa.pointee.sa_len) >= MemoryLayout<sockaddr_in>.size else { continue }
            let sin = UnsafeRawPointer(sa).loadUnaligned(as: sockaddr_in.self)
            let ip = IPAddress.v4(UInt32(bigEndian: sin.sin_addr.s_addr))
            guard !ip.isUnusable, !ip.isLoopback else { continue }
            if seen.insert(ip).inserted {
                out.append(MulticastIPv4Interface(name: name, index: if_nametoindex(name), address: ip))
            }
        }
        return out
    }

    /// Active, physical, non-tunnel multicast-capable IPv6 interfaces.
    static func physicalMulticastIPv6Interfaces() -> [MulticastIPv6Interface] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(first) }

        var out: [MulticastIPv6Interface] = []
        var seen = Set<UInt32>()
        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cur {
            defer { cur = ifa.pointee.ifa_next }
            let flags = ifa.pointee.ifa_flags
            let required = UInt32(IFF_UP | IFF_RUNNING | IFF_MULTICAST)
            guard (flags & required) == required else { continue }
            let name = cString(ifa.pointee.ifa_name)
            guard !RouteDiscovery.isTunnelOrVirtualInterface(name, flags: flags) else { continue }
            guard let sa = ifa.pointee.ifa_addr, Int32(sa.pointee.sa_family) == AF_INET6 else { continue }
            let idx = if_nametoindex(name)
            if idx != 0, seen.insert(idx).inserted {
                out.append(MulticastIPv6Interface(name: name, index: idx))
            }
        }
        return out
    }

    /// Configure `IP_MULTICAST_IF` for an IPv4 UDP socket.
    @discardableResult
    static func setMulticastInterfaceV4(fd: Int32, address: IPAddress) -> Bool {
        guard fd >= 0, case .v4(let raw) = address else { return false }
        var addr = in_addr(s_addr: raw.bigEndian)
        return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &addr, socklen_t(MemoryLayout<in_addr>.size)) == 0
    }

    /// Join an IPv4 multicast group on a specific local interface address.
    @discardableResult
    static func joinMulticastV4(fd: Int32, group: String, interfaceAddress: IPAddress) -> Bool {
        guard fd >= 0, case .v4(let raw) = interfaceAddress else { return false }
        var mreq = ip_mreq()
        guard inet_pton(AF_INET, group, &mreq.imr_multiaddr) == 1 else { return false }
        mreq.imr_interface = in_addr(s_addr: raw.bigEndian)
        return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size)) == 0
    }

    /// Set IPv4 multicast TTL (`u_char` per BSD/Darwin).
    @discardableResult
    static func setMulticastTTLV4(fd: Int32, ttl: UInt8) -> Bool {
        guard fd >= 0 else { return false }
        var v = ttl
        return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &v, socklen_t(MemoryLayout<UInt8>.size)) == 0
    }

    /// Set IPv4 multicast loopback (`u_char` per BSD/Darwin).
    @discardableResult
    static func setMulticastLoopV4(fd: Int32, enabled: Bool) -> Bool {
        guard fd >= 0 else { return false }
        var v: UInt8 = enabled ? 1 : 0
        return setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &v, socklen_t(MemoryLayout<UInt8>.size)) == 0
    }

    /// Join an IPv6 multicast group on a specific interface index (0 = kernel default).
    @discardableResult
    static func joinMulticastV6(fd: Int32, group: String, interfaceIndex: UInt32) -> Bool {
        guard fd >= 0 else { return false }
        var mreq = ipv6_mreq()
        guard inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr) == 1 else { return false }
        mreq.ipv6mr_interface = interfaceIndex
        return setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, socklen_t(MemoryLayout<ipv6_mreq>.size)) == 0
    }

    /// Configure `IPV6_MULTICAST_IF` for an IPv6 UDP socket.
    @discardableResult
    static func setMulticastInterfaceV6(fd: Int32, interfaceIndex: UInt32) -> Bool {
        guard fd >= 0 else { return false }
        var idx = interfaceIndex
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0
    }

    /// Set IPv6 multicast loopback (`u_int` per RFC 3493 / Darwin).
    @discardableResult
    static func setMulticastLoopV6(fd: Int32, enabled: Bool) -> Bool {
        guard fd >= 0 else { return false }
        var v: UInt32 = enabled ? 1 : 0
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &v, socklen_t(MemoryLayout<UInt32>.size)) == 0
    }

    /// Set IPv6 multicast hop limit (`int` per RFC 3493 / Darwin).
    @discardableResult
    static func setMulticastHopsV6(fd: Int32, hops: Int32) -> Bool {
        guard fd >= 0 else { return false }
        var v = hops
        return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &v, socklen_t(MemoryLayout<Int32>.size)) == 0
    }

    private static func cString(_ ptr: UnsafePointer<CChar>?) -> String {
        guard let ptr else { return "" }
        let len = strlen(ptr)
        return String(decoding: UnsafeRawBufferPointer(start: ptr, count: len), as: UTF8.self)
    }
}
