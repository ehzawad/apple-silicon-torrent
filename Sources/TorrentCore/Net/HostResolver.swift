import Foundation
import Darwin

/// Resolves hostnames for trackers and DHT bootstrap nodes.
///
/// 1. System resolver (getaddrinfo) on a background queue.
/// 2. If that fails, or the answer looks like ISP DNS blocking (0.0.0.0,
///    loopback, private ranges), fall back to DNS-over-HTTPS (Cloudflare,
///    then Google) using URLSession. DoH bypasses ISP DNS filtering.
///
/// Results are cached for 10 minutes. Completion runs on the loop.
public final class HostResolver: @unchecked Sendable {
    private let loop: EventLoop
    private let dohFallback: Bool
    private var cache: [String: (addrs: [IPAddress], expires: Double)] = [:]
    private var waiters: [String: [([IPAddress]) -> Void]] = [:]
    private let session: URLSession

    public init(loop: EventLoop, dohFallback: Bool = true) {
        self.loop = loop
        self.dohFallback = dohFallback
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 6
        cfg.httpAdditionalHeaders = ["Accept": "application/dns-json"]
        session = URLSession(configuration: cfg)
    }

    /// Resolve `host` to IPv4 + IPv6 addresses (IPv4 first). Empty on failure.
    public func resolve(_ host: String, completion: @escaping ([IPAddress]) -> Void) {
        loop.assertInLoop()
        if let ip = IPAddress(host) { completion([ip]); return }
        let key = host.lowercased()
        if let c = cache[key], c.expires > monotonicNow() { completion(c.addrs); return }
        if waiters[key] != nil { waiters[key]!.append(completion); return }
        waiters[key] = [completion]

        DispatchQueue.global(qos: .utility).async { [weak self] in
            let sys = Self.getaddrinfo(host)
            guard let self else { return }
            let local = key == "localhost" || key.hasSuffix(".local") || key.hasSuffix(".lan") || key.hasSuffix(".home.arpa")
            let blocked = !local && (sys.isEmpty || sys.allSatisfy { $0.isPrivate || $0.isUnusable || $0.isLoopback })
            if blocked && self.dohFallback {
                self.doh(host, servers: ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]) { addrs in
                    self.loop.execute { self.finish(key, addrs.isEmpty ? sys : addrs) }
                }
            } else {
                self.loop.execute { self.finish(key, sys) }
            }
        }
    }

    private func finish(_ key: String, _ addrs: [IPAddress]) {
        let sorted = addrs.filter { $0.isV4 } + addrs.filter { $0.isV6 }
        cache[key] = (sorted, monotonicNow() + (sorted.isEmpty ? 30 : 600))
        let ws = waiters.removeValue(forKey: key) ?? []
        for w in ws { w(sorted) }
    }

    /// True if any interface has a global unicast IPv6 address (2000::/3). Cached for 30 s.
    nonisolated(unsafe) private static var v6Cache: (value: Bool, at: Double) = (false, -100)
    private static let v6Lock = NSLock()
    public static var hasGlobalIPv6: Bool {
        v6Lock.lock(); defer { v6Lock.unlock() }
        if monotonicNow() - v6Cache.at < 30 { return v6Cache.value }
        var found = false
        var ifap: UnsafeMutablePointer<ifaddrs>?
        if Darwin.getifaddrs(&ifap) == 0, let first = ifap {
            var p: UnsafeMutablePointer<ifaddrs>? = first
            while let cur = p {
                if Int32(cur.pointee.ifa_flags) & IFF_UP != 0, let sa = cur.pointee.ifa_addr,
                   sa.pointee.sa_family == UInt8(AF_INET6), let a = PeerAddress(sockaddr: sa),
                   case .v6(let hi, _) = a.ip, hi >> 61 == 1 { found = true; break }
                p = cur.pointee.ifa_next
            }
            freeifaddrs(first)
        }
        v6Cache = (found, monotonicNow())
        return found
    }

    static func getaddrinfo(_ host: String) -> [IPAddress] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard Darwin.getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var out: [IPAddress] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let cur = p {
            if let sa = cur.pointee.ai_addr,
               let a = PeerAddress(sockaddr: sa, length: cur.pointee.ai_addrlen), !out.contains(a.ip) {
                out.append(a.ip)
            }
            p = cur.pointee.ai_next
        }
        return out
    }

    private func doh(_ host: String, servers: [String], completion: @escaping @Sendable ([IPAddress]) -> Void) {
        guard let server = servers.first else { completion([]); return }
        let rest = Array(servers.dropFirst())
        let group = DispatchGroup()
        let lock = NSLock()
        nonisolated(unsafe) var results: [IPAddress] = []
        for type in ["A", "AAAA"] {
            guard var comps = URLComponents(string: server) else { continue }
            comps.queryItems = [URLQueryItem(name: "name", value: host), URLQueryItem(name: "type", value: type)]
            guard let url = comps.url else { continue }
            group.enter()
            session.dataTask(with: url) { data, _, _ in
                defer { group.leave() }
                guard let data,
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let answers = obj["Answer"] as? [[String: Any]] else { return }
                let ips = answers.compactMap { ($0["data"] as? String).flatMap(IPAddress.init) }
                lock.lock(); results.append(contentsOf: ips); lock.unlock()
            }.resume()
        }
        group.notify(queue: .global()) { [weak self] in
            let r = lock.withLock { results }
            if r.isEmpty, !rest.isEmpty, let self { self.doh(host, servers: rest, completion: completion) }
            else { completion(r) }
        }
    }
}
