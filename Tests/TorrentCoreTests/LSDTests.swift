import Testing
import Foundation
@testable import TorrentCore

// MARK: - BEP 14 Wire Format Unit Tests

@Suite struct LSDWireTests {

    @Test func encodeAndRoundTripSingleAndMultipleInfoHashes() {
        let h1 = Data(hex: "c12fe1c06bba254a9dc9f519b335aa7c1367a88a")!
        let h2 = Data(hex: "0123456789abcdef0123456789abcdef01234567")!
        let h3 = Data(hex: "fedcba9876543210fedcba9876543210fedcba98")!

        let encoded = LSDWire.encode(
            host: LSDWire.hostHeaderV4,
            port: 51413,
            infoHashes: [h1, h2, h3],
            cookie: "deadbeef01020304"
        )
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(text ==
            "BT-SEARCH * HTTP/1.1\r\n" +
            "Host: 239.192.152.143:6771\r\n" +
            "Port: 51413\r\n" +
            "Infohash: c12fe1c06bba254a9dc9f519b335aa7c1367a88a\r\n" +
            "Infohash: 0123456789abcdef0123456789abcdef01234567\r\n" +
            "Infohash: fedcba9876543210fedcba9876543210fedcba98\r\n" +
            "cookie: deadbeef01020304\r\n" +
            "\r\n\r\n"
        )

        let parsed = LSDWire.parse(encoded)
        #expect(parsed == LSDWire.Message(
            host: "239.192.152.143:6771",
            port: 51413,
            infoHashes: [h1, h2, h3],
            cookie: "deadbeef01020304"
        ))

        // Empty/nil cookie omits cookie header cleanly; 0 valid hashes returns empty Data
        let noCookie = String(decoding: LSDWire.encode(host: LSDWire.hostHeaderV4, port: 6881, infoHashes: [h1], cookie: ""), as: UTF8.self)
        #expect(!noCookie.contains("cookie:"))
        #expect(LSDWire.encode(host: LSDWire.hostHeaderV4, port: 6881, infoHashes: [Data(count: 32)], cookie: "abc").isEmpty)
        #expect(LSDWire.encode(host: LSDWire.hostHeaderV4, port: 0, infoHashes: [h1], cookie: "abc").isEmpty)
    }

    @Test func parseVariantsCaseInsensitiveIPv6AndCrCrLf() {
        let h1 = Data(hex: "c12fe1c06bba254a9dc9f519b335aa7c1367a88a")!

        // Uppercase hex, mixed-case header keys, IPv6 host, extra trailing CRLF, no cookie
        let raw = """
        BT-SEARCH * HTTP/1.1\r
        HOST: [ff15::efc0:988f]:6771\r
        PORT: 6881\r
        INFOHASH: C12FE1C06BBA254A9DC9F519B335AA7C1367A88A\r
        INFOHASH: c12fe1c06bba254a9dc9f519b335aa7c1367a88a\r
        \r
        \r
        """
        let parsed = LSDWire.parse(Data(raw.utf8))
        #expect(parsed == LSDWire.Message(
            host: "[ff15::efc0:988f]:6771",
            port: 6881,
            infoHashes: [h1], // deduplicated
            cookie: nil
        ))

        // Stray \r (\r\r\n) and LF-only with Cookie header
        let crCrLf = "BT-SEARCH * HTTP/1.1\r\r\nHost: 239.192.152.143:6771\r\r\nPort: 49999\r\r\nInfohash: \(h1.hex)\r\r\nCookie: abc123\r\r\n\r\n"
        #expect(LSDWire.parse(Data(crCrLf.utf8)) == LSDWire.Message(
            host: "239.192.152.143:6771",
            port: 49999,
            infoHashes: [h1],
            cookie: "abc123"
        ))
    }

    @Test func rejectMalformedMessages() {
        let validHash = "c12fe1c06bba254a9dc9f519b335aa7c1367a88a"
        let host = "Host: 239.192.152.143:6771\r\n"
        // Empty
        #expect(LSDWire.parse(Data()) == nil)
        // Wrong method
        #expect(LSDWire.parse(Data("GET * HTTP/1.1\r\n\(host)Port: 6881\r\nInfohash: \(validHash)\r\n\r\n".utf8)) == nil)
        // Bogus HTTP version
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.GARBAGE\r\n\(host)Port: 6881\r\nInfohash: \(validHash)\r\n\r\n".utf8)) == nil)
        // Missing required Host header (BEP 14)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\nInfohash: \(validHash)\r\n\r\n".utf8)) == nil)
        // Truncated packet (missing terminating blank line)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 6881\r\nInfohash: \(validHash)".utf8)) == nil)
        // Port = 0 / out of range / missing
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 0\r\nInfohash: \(validHash)\r\n\r\n".utf8)) == nil)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 70000\r\nInfohash: \(validHash)\r\n\r\n".utf8)) == nil)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Infohash: \(validHash)\r\n\r\n".utf8)) == nil)
        // Missing / truncated / non-hex infohash
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 6881\r\n\r\n".utf8)) == nil)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 6881\r\nInfohash: deadbeef\r\n\r\n".utf8)) == nil)
        #expect(LSDWire.parse(Data("BT-SEARCH * HTTP/1.1\r\n\(host)Port: 6881\r\nInfohash: zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\r\n\r\n".utf8)) == nil)
    }
}

// MARK: - LocalPeerDiscovery Behavior Tests

@Suite(.serialized) struct LSDDiscoveryTests {

    @Test func ignoresOwnCookieReportsRemotePeersAndHandlesReentrantStop() {
        let loop = EventLoop(label: "test.lsd.cookie")
        let h1 = Data(repeating: 0x11, count: 20)
        let h2 = Data(repeating: 0x22, count: 20)
        var discovered: [(Data, PeerAddress)] = []

        weak var weakLSD: LocalPeerDiscovery?
        do {
            let lsd = LocalPeerDiscovery(loop: loop, port: 51413)
            weakLSD = lsd

            loop.sync {
                lsd.customSend = { _, _ in }
                lsd.onPeer = { hash, peer in discovered.append((hash, peer)) }
                lsd.start()

                // Self-announce with matching cookie -> MUST BE IGNORED
                let selfPkt = LSDWire.encode(host: LSDWire.hostHeaderV4, port: 51413, infoHashes: [h1], cookie: lsd.cookie)
                lsd.handleIncoming(selfPkt, from: PeerAddress(ip: IPAddress("192.168.1.106")!, port: 6771))
                #expect(discovered.isEmpty)

                // Remote announce with different cookie and two infohashes (UDP src port 43210 != BT port 6889)
                let remotePkt = LSDWire.encode(host: LSDWire.hostHeaderV4, port: 6889, infoHashes: [h1, h2], cookie: "otherpeer")
                lsd.handleIncoming(remotePkt, from: PeerAddress(ip: IPAddress("192.168.1.200")!, port: 43210))

                // Remote announce with no cookie -> MUST DELIVER
                let noCookieRaw = "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 55555\r\nInfohash: \(h1.hex)\r\n\r\n"
                lsd.handleIncoming(Data(noCookieRaw.utf8), from: PeerAddress(ip: IPAddress("192.168.1.201")!, port: 6771))

                // Unusable sender IP (0.0.0.0) -> MUST IGNORE
                lsd.handleIncoming(remotePkt, from: PeerAddress(ip: IPAddress("0.0.0.0")!, port: 6771))

                // IPv6 remote peer announce -> MUST DELIVER with IPv6 PeerAddress
                let v6Pkt = LSDWire.encode(host: LSDWire.hostHeaderV6, port: 6890, infoHashes: [h2], cookie: "v6peer")
                lsd.handleIncoming(v6Pkt, from: PeerAddress(ip: IPAddress("fe80::1")!, port: 6771))

                // Re-entrant stop() inside onPeer must stop delivering remaining hashes from the same datagram
                var reentrantCount = 0
                lsd.onPeer = { [weak lsd] _, _ in
                    reentrantCount += 1
                    lsd?.stop()
                }
                lsd.handleIncoming(remotePkt, from: PeerAddress(ip: IPAddress("192.168.1.203")!, port: 6771))
                #expect(reentrantCount == 1)

                // After stop(), incoming packets must not fire onPeer
                lsd.handleIncoming(remotePkt, from: PeerAddress(ip: IPAddress("192.168.1.202")!, port: 6771))
                #expect(reentrantCount == 1)
            }
        }
        loop.sync {}
        #expect(weakLSD == nil)

        #expect(discovered.count == 4)
        #expect(discovered[0].0 == h1 && discovered[0].1 == PeerAddress(ip: IPAddress("192.168.1.200")!, port: 6889))
        #expect(discovered[1].0 == h2 && discovered[1].1 == PeerAddress(ip: IPAddress("192.168.1.200")!, port: 6889))
        #expect(discovered[2].0 == h1 && discovered[2].1 == PeerAddress(ip: IPAddress("192.168.1.201")!, port: 55555))
        #expect(discovered[3].0 == h2 && discovered[3].1 == PeerAddress(ip: IPAddress("fe80::1")!, port: 6890))
    }

    @Test func enforcesFiveMinutePerTorrentRateLimitBatchingAndIPv6Announce() {
        let loop = EventLoop(label: "test.lsd.ratelimit")
        let lsd = LocalPeerDiscovery(loop: loop, port: 51413)
        var now: Double = 1000.0
        var sentV4: [(Data, PeerAddress)] = []
        var sentV6: [(Data, PeerAddress)] = []

        let h1 = Data(repeating: 0x01, count: 20)
        let h2 = Data(repeating: 0x02, count: 20)
        let h3 = Data(repeating: 0x03, count: 20)
        let badLen = Data(repeating: 0xFF, count: 12)

        loop.sync {
            lsd.nowProvider = { now }
            lsd.customSend = { data, dest in sentV4.append((data, dest)) }
            lsd.customSendV6 = { data, dest in sentV6.append((data, dest)) }

            // Before start(), announce must be a no-op
            lsd.announce(infoHashes: [h1])
            #expect(sentV4.isEmpty && sentV6.isEmpty)

            lsd.start()

            // First announce with duplicate h1 + invalid length hash -> sends [h1, h2] on both v4 and v6
            lsd.announce(infoHashes: [h1, h1, badLen, h2])
            #expect(sentV4.count == 1)
            #expect(sentV6.count == 1)
            let msg1 = LSDWire.parse(sentV4[0].0)
            #expect(msg1?.infoHashes == [h1, h2])
            #expect(msg1?.port == 51413)
            #expect(msg1?.cookie == lsd.cookie)
            #expect(sentV4[0].1 == PeerAddress(ip: IPAddress("239.192.152.143")!, port: 6771))
            let msg1V6 = LSDWire.parse(sentV6[0].0)
            #expect(msg1V6?.host == "[ff15::efc0:988f]:6771")
            #expect(msg1V6?.infoHashes == [h1, h2])
            #expect(sentV6[0].1 == PeerAddress(ip: IPAddress("ff15::efc0:988f")!, port: 6771))

            // 100s later: h1 & h2 still rate-limited; h3 goes through alone
            now = 1100.0
            lsd.announce(infoHashes: [h1, h2, h3])
            #expect(sentV4.count == 2)
            #expect(LSDWire.parse(sentV4[1].0)?.infoHashes == [h3])

            // 299s after t=1000: h1 still blocked
            now = 1299.0
            lsd.announce(infoHashes: [h1])
            #expect(sentV4.count == 2)

            // 300s after t=1000: h1 & h2 eligible again, h3 still blocked (only 200s elapsed)
            now = 1300.0
            lsd.announce(infoHashes: [h1, h2, h3])
            #expect(sentV4.count == 3)
            #expect(LSDWire.parse(sentV4[2].0)?.infoHashes == [h1, h2])

            // Batching: 12 new distinct hashes -> 3 datagrams (5 + 5 + 2)
            let batchHashes = (10..<22).map { Data(repeating: UInt8($0), count: 20) }
            sentV4.removeAll()
            lsd.announce(infoHashes: batchHashes)
            #expect(sentV4.count == 3)
            #expect(LSDWire.parse(sentV4[0].0)?.infoHashes.count == 5)
            #expect(LSDWire.parse(sentV4[1].0)?.infoHashes.count == 5)
            #expect(LSDWire.parse(sentV4[2].0)?.infoHashes.count == 2)

            lsd.stop()
            sentV4.removeAll()
            now = 2000.0
            lsd.announce(infoHashes: [h1])
            #expect(sentV4.isEmpty)
        }
    }

    @Test func realMulticastSocketLifecycleAndCleanDeinit() {
        let loop = EventLoop(label: "test.lsd.socket")
        let hash = Data(repeating: 0xAB, count: 20)
        weak var weakLSD: LocalPeerDiscovery?
        do {
            let lsd = LocalPeerDiscovery(loop: loop, port: 51413)
            weakLSD = lsd
            loop.sync {
                lsd.start()
                lsd.announce(infoHashes: [hash])
                lsd.stop()
            }
        }
        loop.sync {}
        #expect(weakLSD == nil)
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1"))
    func liveMulticastTwoLocalInstancesDiscoverEachOther() {
        let loop = EventLoop(label: "test.lsd.live")
        let sender = LocalPeerDiscovery(loop: loop, port: 51421)
        let receiver = LocalPeerDiscovery(loop: loop, port: 51422)
        let targetHash = Data(hex: "c12fe1c06bba254a9dc9f519b335aa7c1367a88a")!

        let foundSem = DispatchSemaphore(value: 0)
        let box = DiscoveredBox()

        loop.sync {
            receiver.onPeer = { hash, peer in
                if hash == targetHash, peer.port == 51421 {
                    box.peers.append((hash, peer))
                    foundSem.signal()
                }
            }
            sender.onPeer = { hash, peer in
                if hash == targetHash, peer.port == 51421 {
                    box.sawOwnEcho = true
                }
            }
            receiver.start()
            sender.start()
            sender.announce(infoHashes: [targetHash])
        }

        defer {
            loop.sync {
                sender.stop()
                receiver.stop()
            }
        }

        let waitResult = foundSem.wait(timeout: .now() + 2)
        let (peers, sawOwn) = loop.sync { (box.peers, box.sawOwnEcho) }
        print("[ASTOR_LIVE][LSD] Discovered peers: \(peers.map { "\($0.0.hex) @ \($0.1)" }), sawOwnEcho=\(sawOwn)")
        #expect(waitResult == .success, "Expected receiver to discover sender over LAN multicast loopback")
        #expect(!sawOwn, "Sender must filter out its own announce via cookie")
        #expect(peers.contains { $0.0 == targetHash && $0.1.port == 51421 })
    }
}

private final class DiscoveredBox: @unchecked Sendable {
    var peers: [(Data, PeerAddress)] = []
    var sawOwnEcho = false
}
