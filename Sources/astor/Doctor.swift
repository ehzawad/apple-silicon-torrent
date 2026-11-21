import Foundation
import Darwin
import TorrentCore

/// `astor doctor` — explains, in plain language, what on this network limits torrent speed.
enum Doctor {
    struct Finding { let ok: Bool?; let title: String; let detail: String }
    nonisolated(unsafe) static var findings: [Finding] = []

    static func report(_ ok: Bool?, _ title: String, _ detail: String) {
        findings.append(Finding(ok: ok, title: title, detail: detail))
        let mark = ok == nil ? "\u{1B}[33m!\u{1B}[0m" : (ok! ? "\u{1B}[32m✔\u{1B}[0m" : "\u{1B}[31m✘\u{1B}[0m")
        print("\(mark) \(title)")
        if !detail.isEmpty { print("    \(detail.replacingOccurrences(of: "\n", with: "\n    "))") }
    }

    static func run() {
        print("astor doctor — checking this Mac's network for BitTorrent\n")
        Session_raiseLimitCheck()
        let tunnels = activeTunnels()
        checkVPN(tunnels)
        let gateway = defaultGatewayIPv4()
        let routerWAN = gateway.flatMap { natpmpExternalAddress(gateway: $0) }
        let publicIP = httpGet("https://api.ipify.org").flatMap { String(data: $0, encoding: .utf8) }
        checkNAT(gateway: gateway, routerWAN: routerWAN, publicIP: publicIP, tunnels: tunnels)
        checkUPnP()
        checkDNS()
        checkUDP()
        checkThroughput()
        summary(tunnels: tunnels, routerWAN: routerWAN, publicIP: publicIP)
    }

    // MARK: - Checks

    static func Session_raiseLimitCheck() {
        var rl = rlimit()
        getrlimit(RLIMIT_NOFILE, &rl)
        let detail = rl.rlim_cur >= 10240
            ? "soft limit \(rl.rlim_cur) — plenty for hundreds of peers"
            : "soft \(rl.rlim_cur), hard \(rl.rlim_max) — astor raises the soft limit to \(min(rl.rlim_max, 10240)) for hundreds of peers"
        report(true, "File descriptor limit", detail)
    }

    struct Tunnel { let name: String; let mtu: Int; let addrs: [String] }

    static func activeTunnels() -> [Tunnel] {
        var byName: [String: (Int, [String])] = [:]
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let first = ifap else { return [] }
        defer { freeifaddrs(first) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            let name = String(cString: cur.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("ppp") || name.hasPrefix("tun") {
                var e = byName[name] ?? (0, [])
                if let sa = cur.pointee.ifa_addr {
                    if sa.pointee.sa_family == UInt8(AF_LINK), let d = cur.pointee.ifa_data {
                        e.0 = Int(d.assumingMemoryBound(to: if_data.self).pointee.ifi_mtu)
                    } else if sa.pointee.sa_family == UInt8(AF_INET), let a = PeerAddress(sockaddr: sa) {
                        e.1.append(a.ip.description)
                    }
                }
                byName[name] = e
            }
            p = cur.pointee.ifa_next
        }
        return byName.filter { !$0.value.1.isEmpty }.map { Tunnel(name: $0.key, mtu: $0.value.0, addrs: $0.value.1) }
    }

    static func checkVPN(_ tunnels: [Tunnel]) {
        let warpFiles = ["/Library/LaunchDaemons/com.cloudflare.1dot1dot1dot1.macos.warp.daemon.plist"]
            .filter { FileManager.default.fileExists(atPath: $0) }
        if tunnels.isEmpty && warpFiles.isEmpty {
            report(true, "No VPN tunnel detected", "Traffic goes straight to your ISP, so peers can connect to you.")
            return
        }
        var d = tunnels.map { "\($0.name) (MTU \($0.mtu)) \($0.addrs.joined(separator: ", "))" }.joined(separator: "\n")
        if tunnels.contains(where: { $0.addrs.contains("172.16.0.2") }) || !warpFiles.isEmpty {
            d += "\nThis looks like Cloudflare WARP. WARP never accepts incoming connections, so peers can't connect to you; that alone often halves torrent speed. Remove or disconnect it while torrenting."
        } else {
            d += "\nA VPN tunnel carries your traffic. Most VPNs block incoming peer connections unless they support port forwarding."
        }
        report(false, "VPN / tunnel is active", d)
    }

    static func checkNAT(gateway: IPAddress?, routerWAN: IPAddress?, publicIP: String?, tunnels: [Tunnel]) {
        guard let gateway else { report(nil, "No default gateway found", ""); return }
        guard let wan = routerWAN else {
            report(nil, "Router does not answer NAT-PMP (\(gateway))", "UPnP may still work (checked below).")
            return
        }
        if case .v4(let a) = wan, a >> 24 == 100, (a >> 16 & 0xFF) >= 64, (a >> 16 & 0xFF) < 128 {
            report(false, "Carrier-grade NAT (CGNAT) detected", "Your router's WAN address \(wan) is shared by many ISP customers. Port forwarding can't make you reachable; ask your ISP for a public IP (often free on request in Bangladesh).")
            return
        }
        if wan.isPrivate {
            report(false, "Double NAT", "Router WAN address \(wan) is private: another router/ONU sits in front of yours. Put the ONU in bridge mode or forward the port on it.")
            return
        }
        var d = "Router WAN address \(wan) is a real public IP — you can be fully reachable with port mapping."
        if let pub = publicIP, pub != wan.description {
            d += "\nBut the internet currently sees you as \(pub) (traffic is leaving through a VPN/tunnel)."
        }
        report(true, "Public IPv4 on the router (no CGNAT)", d)
    }

    static func checkUPnP() {
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(s) }
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        let dst = PeerAddress(ip: IPAddress("239.255.255.250")!, port: 1900)
        _ = msg.withCString { c in dst.withSockAddr { sendto(s, c, strlen(c), 0, $0, $1) } }
        var buf = [UInt8](repeating: 0, count: 2048)
        let n = recv(s, &buf, buf.count, 0)
        if n > 0 {
            let text = String(decoding: buf[0..<n], as: UTF8.self)
            let server = text.split(separator: "\r\n").first { $0.lowercased().hasPrefix("server:") }.map(String.init) ?? ""
            report(true, "UPnP Internet Gateway found", server.trimmingCharacters(in: .whitespaces))
        } else {
            report(nil, "No UPnP gateway answered", "Enable UPnP on the router, or forward the listen port manually.")
        }
    }

    static func checkDNS() {
        let hosts = ["tracker.opentrackr.org", "open.demonii.com", "router.bittorrent.com", "dht.transmissionbt.com"]
        var bad: [String] = []
        for h in hosts {
            var hints = addrinfo(); hints.ai_family = AF_INET
            var res: UnsafeMutablePointer<addrinfo>?
            let ok = getaddrinfo(h, nil, &hints, &res) == 0
            var addrs: [IPAddress] = []
            if ok, let first = res {
                var p: UnsafeMutablePointer<addrinfo>? = first
                while let cur = p { if let sa = cur.pointee.ai_addr, let a = PeerAddress(sockaddr: sa) { addrs.append(a.ip) }; p = cur.pointee.ai_next }
                freeaddrinfo(first)
            }
            if addrs.isEmpty || addrs.allSatisfy({ $0.isPrivate || $0.isUnusable }) { bad.append(h) }
        }
        if bad.isEmpty {
            report(true, "DNS resolves tracker and DHT hostnames", "")
        } else {
            report(false, "DNS blocks: \(bad.joined(separator: ", "))", "astor automatically falls back to DNS-over-HTTPS for these.")
        }
    }

    static func checkUDP() {
        // BEP 15 connect to opentrackr + DHT ping to router.bittorrent.com
        func udpProbe(_ host: String, _ port: UInt16, _ payload: [UInt8]) -> Bool {
            var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, String(port), &hints, &res) == 0, let ai = res else { return false }
            defer { freeaddrinfo(ai) }
            let s = socket(AF_INET, SOCK_DGRAM, 0)
            defer { close(s) }
            var tv = timeval(tv_sec: 3, tv_usec: 0)
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            for _ in 0..<2 {
                _ = sendto(s, payload, payload.count, 0, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
                var buf = [UInt8](repeating: 0, count: 1500)
                if recv(s, &buf, buf.count, 0) > 0 { return true }
            }
            return false
        }
        var connect: [UInt8] = [0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0]
        connect += [0x12, 0x34, 0x56, 0x78]
        let trackerOK = udpProbe("tracker.opentrackr.org", 1337, connect)
        let ping = Array("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".utf8)
        let dhtOK = udpProbe("router.bittorrent.com", 6881, ping) || udpProbe("dht.transmissionbt.com", 6881, ping)
        report(trackerOK, "UDP trackers \(trackerOK ? "reachable" : "NOT reachable")", trackerOK ? "" : "UDP may be blocked or throttled by your ISP; HTTP trackers and TCP still work.")
        report(dhtOK, "DHT \(dhtOK ? "reachable" : "NOT reachable")", dhtOK ? "" : "Without DHT, magnet links and trackerless swarms find far fewer peers.")
    }

    static func checkThroughput() {
        let start = Date()
        guard let d = httpGet("https://speed.cloudflare.com/__down?bytes=25000000", timeout: 30) else {
            report(nil, "Throughput test failed", ""); return
        }
        let secs = Date().timeIntervalSince(start)
        let rate = Double(d.count) / secs
        report(true, String(format: "HTTP download: %.1f MB/s (%.0f Mbit/s)", rate / 1e6, rate * 8 / 1e6),
               "This is roughly the ceiling a torrent can reach on this connection.")
    }

    static func summary(tunnels: [Tunnel], routerWAN: IPAddress?, publicIP: String?) {
        print("\nWhat to do:")
        var n = 1
        if !tunnels.isEmpty {
            print("  \(n). Turn off the VPN (or Cloudflare WARP) while torrenting; it blocks incoming peers."); n += 1
        }
        if let wan = routerWAN, !wan.isPrivate {
            print("  \(n). Keep UPnP / NAT-PMP enabled on the router. astor maps its port automatically, so other peers can connect to you."); n += 1
        }
        print("  \(n). Keep encryption on 'prefer' (default). If speeds collapse after a few seconds (ISP throttling), try: astor download … -e require"); n += 1
        print("  \(n). Leave DHT, PEX and uTP on; they find many more peers than trackers alone.")
    }

    // MARK: - Small network helpers

    static func httpGet(_ url: String, timeout: Double = 8) -> Data? {
        guard let u = URL(string: url) else { return nil }
        let sema = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var out: Data?
        var req = URLRequest(url: u)
        req.timeoutInterval = timeout
        URLSession.shared.dataTask(with: req) { d, r, _ in
            if (r as? HTTPURLResponse)?.statusCode == 200 { out = d }
            sema.signal()
        }.resume()
        _ = sema.wait(timeout: .now() + timeout + 1)
        return out
    }

    static func defaultGatewayIPv4() -> IPAddress? {
        // NET_RT_FLAGS dump filtered by RTF_GATEWAY; first default route on a non-tunnel interface.
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY]
        var len = 0
        guard sysctl(&mib, 6, nil, &len, nil, 0) == 0, len > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: len)
        guard sysctl(&mib, 6, &buf, &len, nil, 0) == 0 else { return nil }
        var off = 0
        while off + MemoryLayout<rt_msghdr>.size <= len {
            let hdr = buf.withUnsafeBytes { $0.load(fromByteOffset: off, as: rt_msghdr.self) }
            defer { off += Int(hdr.rtm_msglen) }
            if hdr.rtm_msglen == 0 { break }
            var ifname = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
            if_indextoname(UInt32(hdr.rtm_index), &ifname)
            let name = String(cString: ifname)
            if name.hasPrefix("utun") || name.hasPrefix("ipsec") { continue }
            // sockaddrs follow the header: RTA_DST then RTA_GATEWAY
            var p = off + MemoryLayout<rt_msghdr>.size
            var dst: IPAddress?, gw: IPAddress?
            for bit in 0..<8 where hdr.rtm_addrs & (1 << bit) != 0 {
                guard p < off + Int(hdr.rtm_msglen) else { break }
                let saLen = Int(buf[p])
                let fam = buf[p + 1]
                if fam == UInt8(AF_INET) {
                    let ip = IPAddress(bytes: buf[(p + 4)..<(p + 8)])
                    if bit == 0 { dst = ip } else if bit == 1 { gw = ip }
                }
                p += saLen > 0 ? (saLen + 3) & ~3 : 4
            }
            if (dst == nil || dst == .v4(0)), let gw, gw != .v4(0) { return gw }
        }
        return nil
    }

    static func natpmpExternalAddress(gateway: IPAddress) -> IPAddress? {
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        defer { close(s) }
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let dst = PeerAddress(ip: gateway, port: 5351)
        let req: [UInt8] = [0, 0]
        for _ in 0..<2 {
            _ = dst.withSockAddr { sendto(s, req, 2, 0, $0, $1) }
            var buf = [UInt8](repeating: 0, count: 16)
            let n = recv(s, &buf, 16, 0)
            if n >= 12, buf[1] == 128, buf[2] == 0, buf[3] == 0 { return IPAddress(bytes: buf[8..<12]) }
        }
        return nil
    }
}
