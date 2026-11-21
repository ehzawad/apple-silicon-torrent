import Foundation
import Darwin

/// BEP 14 Local Service Discovery (LSD).
///
/// Announces active torrents and listens for LAN peers on IPv4 multicast
/// `239.192.152.143:6771` (and best-effort IPv6 `[ff15::efc0:988f]:6771`).
/// Uses a random per-instance cookie to ignore our own announces and enforces
/// the BEP 14 rate limit (at least 5 minutes between announces per infohash).
///
/// Threading: loop-confined (`@unchecked Sendable`); all public methods must be
/// called on `loop.queue`.
public final class LocalPeerDiscovery: @unchecked Sendable {
    private let loop: EventLoop
    private let port: UInt16

    /// Per-instance opaque cookie used to filter out our own multicast echoes (BEP 14).
    let cookie: String

    /// Injectable clock & transport hooks for deterministic offline testing.
    var nowProvider: () -> Double = monotonicNow
    var customSend: ((Data, PeerAddress) -> Void)?
    var customSendV6: ((Data, PeerAddress) -> Void)?

    private var socket4: UDPSocket?
    private var socket6: UDPSocket?
    private var isRunning = false
    private var lastAnnounced: [Data: Double] = [:]
    private var _onPeer: ((Data /*infohash*/, PeerAddress) -> Void)?

    public var onPeer: ((Data /*infohash*/, PeerAddress) -> Void)? {
        get {
            loop.assertInLoop()
            return _onPeer
        }
        set {
            loop.assertInLoop()
            _onPeer = newValue
        }
    }

    public init(loop: EventLoop, port: UInt16) {
        self.loop = loop
        self.port = port
        self.cookie = Data.random(8).hex
    }

    public func start() {
        loop.assertInLoop()
        guard !isRunning else { return }
        isRunning = true

        // If a unit test provides custom transport hooks, skip real socket binding.
        if customSend != nil || customSendV6 != nil { return }

        // IPv4 multicast socket on 239.192.152.143:6771.
        let s4 = (try? UDPSocket(port: LSDWire.multicastPort, v6: false, loop: loop, reuse: true))
            ?? (try? UDPSocket(port: 0, v6: false, loop: loop, reuse: true))
        if let s4 {
            s4.joinMulticastV4(LSDWire.multicastIPv4)
            // Also join explicitly on each physical non-tunnel IPv4 interface so LAN LSD
            // continues working even when a VPN/WARP tunnel owns the default multicast route.
            for iface in LocalNetwork.physicalMulticastIPv4Interfaces() {
                LocalNetwork.joinMulticastV4(fd: s4.fileDescriptor, group: LSDWire.multicastIPv4, interfaceAddress: iface.address)
            }
            // Enable multicast loopback so other local clients on this host can discover us;
            // our BEP 14 `cookie` filters out our own echoes.
            LocalNetwork.setMulticastLoopV4(fd: s4.fileDescriptor, enabled: true)
            LocalNetwork.setMulticastTTLV4(fd: s4.fileDescriptor, ttl: 1)
            s4.onDatagram = { [weak self] data, from in
                self?.handleIncoming(data, from: from)
            }
            s4.start()
            socket4 = s4
        }

        // IPv6 multicast socket on [ff15::efc0:988f]:6771 (best effort).
        let s6 = (try? UDPSocket(port: LSDWire.multicastPort, v6: true, loop: loop, reuse: true))
            ?? (try? UDPSocket(port: 0, v6: true, loop: loop, reuse: true))
        if let s6 {
            let v6Ifaces = LocalNetwork.physicalMulticastIPv6Interfaces()
            if v6Ifaces.isEmpty {
                LocalNetwork.joinMulticastV6(fd: s6.fileDescriptor, group: LSDWire.multicastIPv6, interfaceIndex: 0)
            } else {
                for iface in v6Ifaces {
                    LocalNetwork.joinMulticastV6(fd: s6.fileDescriptor, group: LSDWire.multicastIPv6, interfaceIndex: iface.index)
                }
            }
            LocalNetwork.setMulticastLoopV6(fd: s6.fileDescriptor, enabled: true)
            LocalNetwork.setMulticastHopsV6(fd: s6.fileDescriptor, hops: 1)
            s6.onDatagram = { [weak self] data, from in
                self?.handleIncoming(data, from: from)
            }
            s6.start()
            socket6 = s6
        }
    }

    public func stop() {
        loop.assertInLoop()
        guard isRunning else { return }
        isRunning = false
        lastAnnounced.removeAll()
        socket4?.close()
        socket4 = nil
        socket6?.close()
        socket6 = nil
    }

    /// Announce 20-byte infohashes on LAN multicast, rate-limited to at most once every 5 minutes per hash.
    public func announce(infoHashes: [Data]) {
        loop.assertInLoop()
        guard isRunning, port > 0, !infoHashes.isEmpty else { return }
        let hasTransport = customSend != nil || customSendV6 != nil || socket4 != nil || socket6 != nil
        guard hasTransport else { return }

        let now = nowProvider()
        // Periodically prune stale entries so long-running sessions stay bounded.
        if lastAnnounced.count > 512 {
            let cutoff = now - LSDWire.minAnnounceInterval * 2
            lastAnnounced = lastAnnounced.filter { $0.value >= cutoff }
        }

        var eligible: [Data] = []
        var seenInCall = Set<Data>()
        for hash in infoHashes {
            guard hash.count == 20, seenInCall.insert(hash).inserted else { continue }
            if let prev = lastAnnounced[hash], (now - prev) < LSDWire.minAnnounceInterval {
                continue
            }
            lastAnnounced[hash] = now
            eligible.append(hash)
        }
        guard !eligible.isEmpty else { return }

        // Batch into small datagrams (<= 5 infohashes per BEP 14).
        let dest4 = IPAddress(LSDWire.multicastIPv4).map { PeerAddress(ip: $0, port: LSDWire.multicastPort) }
        let dest6 = IPAddress(LSDWire.multicastIPv6).map { PeerAddress(ip: $0, port: LSDWire.multicastPort) }
        let v4Ifaces = (customSend == nil && socket4 != nil) ? LocalNetwork.physicalMulticastIPv4Interfaces() : []
        let v6Ifaces = (customSendV6 == nil && socket6 != nil) ? LocalNetwork.physicalMulticastIPv6Interfaces() : []

        var offset = 0
        while offset < eligible.count {
            let end = min(offset + LSDWire.maxHashesPerPacket, eligible.count)
            let batch = Array(eligible[offset..<end])
            offset = end

            if let dest4 {
                let pkt4 = LSDWire.encode(host: LSDWire.hostHeaderV4, port: port, infoHashes: batch, cookie: cookie)
                if !pkt4.isEmpty {
                    if let customSend {
                        customSend(pkt4, dest4)
                    } else if let s4 = socket4 {
                        if v4Ifaces.isEmpty {
                            s4.send(pkt4, to: dest4)
                        } else {
                            for iface in v4Ifaces {
                                LocalNetwork.setMulticastInterfaceV4(fd: s4.fileDescriptor, address: iface.address)
                                s4.send(pkt4, to: dest4)
                            }
                        }
                    }
                }
            }

            if let dest6 {
                let pkt6 = LSDWire.encode(host: LSDWire.hostHeaderV6, port: port, infoHashes: batch, cookie: cookie)
                if !pkt6.isEmpty {
                    if let customSendV6 {
                        customSendV6(pkt6, dest6)
                    } else if let s6 = socket6 {
                        if v6Ifaces.isEmpty {
                            s6.send(pkt6, to: dest6)
                        } else {
                            for iface in v6Ifaces {
                                LocalNetwork.setMulticastInterfaceV6(fd: s6.fileDescriptor, interfaceIndex: iface.index)
                                s6.send(pkt6, to: dest6)
                            }
                        }
                    }
                }
            }
        }
    }

    func handleIncoming(_ data: Data, from: PeerAddress) {
        guard isRunning else { return }
        guard !from.ip.isUnusable else { return }
        guard let msg = LSDWire.parse(data) else { return }
        if let msgCookie = msg.cookie, msgCookie == cookie {
            return
        }
        let peer = PeerAddress(ip: from.ip, port: msg.port)
        for hash in msg.infoHashes {
            guard isRunning else { break }
            _onPeer?(hash, peer)
        }
    }

    deinit {
        var sockets: [UDPSocket] = []
        if let s4 = socket4 { sockets.append(s4) }
        if let s6 = socket6 { sockets.append(s6) }
        if !sockets.isEmpty {
            let captured = sockets
            loop.run {
                for s in captured { s.close() }
            }
        }
    }
}
