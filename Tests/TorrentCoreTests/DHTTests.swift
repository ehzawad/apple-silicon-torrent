import Testing
import Foundation
@testable import TorrentCore

// MARK: - Helpers

/// Collects datagrams a DHTNode sends (touched only on the node's loop).
final class DHTPacketBox: @unchecked Sendable {
    var sent: [(Data, PeerAddress)] = []
}

/// Loop-confined result holder for lookups in async tests.
final class DHTLookupBox: @unchecked Sendable {
    var peers: [PeerAddress] = []
    var batches = 0
    var done = false
    var external: [IPAddress] = []
}

private func dhtWaitUntil(_ timeout: Double, _ cond: () -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if cond() { return true }
        try? await Task.sleep(nanoseconds: 50_000_000)
    }
    return cond()
}

private func bkey(_ s: String) -> Data { Data(s.utf8) }

private func publicAddr(_ i: Int, port: UInt16 = 6881) -> PeerAddress {
    PeerAddress(ip: .v4(UInt32(50) << 24 | UInt32(i & 0xFFFF)), port: port)
}

// MARK: - KRPC

@Suite struct DHTKRPCTests {
    @Test func decodesBEP5PingExample() throws {
        let raw = Data("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".utf8)
        let m = try #require(KRPCMessage.decode(raw))
        #expect(m.transactionID == Data("aa".utf8))
        guard case .query(let method, let args) = m.body else { Issue.record("not a query"); return }
        #expect(method == "ping")
        #expect(args[KRPCKey.id]?.data == Data("abcdefghij0123456789".utf8))
        #expect(m.senderID == DHTID(Data("abcdefghij0123456789".utf8)))
        // Re-encoding yields the canonical bytes.
        #expect(m.encoded == raw)
    }

    @Test func decodesBEP5ResponseAndError() throws {
        let r = try #require(KRPCMessage.decode(Data("d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re".utf8)))
        guard case .response(let dict) = r.body else { Issue.record("not a response"); return }
        #expect(dict[KRPCKey.id]?.data == Data("mnopqrstuvwxyz123456".utf8))

        let e = try #require(KRPCMessage.decode(Data("d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee".utf8)))
        #expect(e.body == .error(code: 201, message: "A Generic Error Ocurred"))
    }

    @Test func roundTripWithVersionIPAndReadOnly() throws {
        let id = DHTID.random()
        let ip = PeerAddress("203.0.113.9:51413")!
        let q = KRPCMessage(transactionID: Data([0x12, 0x34]),
                            body: .query(method: "get_peers", args: [KRPCKey.id: .bytes(id.data), KRPCKey.infoHash: .bytes(Data(repeating: 7, count: 20))]),
                            version: Data("AS01".utf8), readOnly: true)
        let dq = try #require(KRPCMessage.decode(q.encoded))
        #expect(dq == q)
        #expect(dq.readOnly)
        #expect(dq.version == Data("AS01".utf8))

        let r = KRPCMessage(transactionID: Data([0x12, 0x34]), body: .response([KRPCKey.id: .bytes(id.data)]),
                            version: Data("AS01".utf8), yourIP: ip)
        let dr = try #require(KRPCMessage.decode(r.encoded))
        #expect(dr.yourIP == ip)
        #expect(dr.senderID == id)

        let ip6 = PeerAddress("[2001:db8::7]:6881")!
        let r6 = KRPCMessage(transactionID: Data("t".utf8), body: .response([:]), yourIP: ip6)
        #expect(KRPCMessage.decode(r6.encoded)?.yourIP == ip6)
    }

    @Test func malformedPacketsNeverCrash() {
        let valid = KRPCMessage(transactionID: Data([1, 2]),
                                body: .query(method: "find_node", args: [KRPCKey.id: .bytes(DHTID.random().data), KRPCKey.target: .bytes(DHTID.random().data)]),
                                version: Data("AS01".utf8)).encoded
        // Truncations of a valid packet.
        for n in 0..<valid.count { _ = KRPCMessage.decode(valid.prefix(n)) }
        // Random byte flips.
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<3000 {
            var d = valid
            for _ in 0..<Int.random(in: 1...6, using: &rng) {
                d[Int.random(in: 0..<d.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
            }
            _ = KRPCMessage.decode(d)
        }
        // Pure noise starting with 'd'.
        for _ in 0..<2000 {
            var d = Data.random(Int.random(in: 1...200, using: &rng))
            d[0] = UInt8(ascii: "d")
            _ = KRPCMessage.decode(d)
        }
        // Structurally wrong but bencode-valid.
        let odd: [String] = [
            "de", "d1:t2:aae", "d1:y1:qe", "d1:t2:aa1:y1:qe", "d1:t2:aa1:y1:xe", "d1:t2:aa1:y1:re",
            "d1:t2:aa1:y1:q1:qi5ee", "d1:t2:aa1:y2:qqe", "d1:eli999999999999999999eee", "d1:t2:aa1:y1:e1:e3:abce",
            "d1:t2:aa1:y1:e1:eli-5eee", "d1:t2:aa1:y1:r1:rli1eee", "d1:ad2:idi5ee1:q4:ping1:t2:aa1:y1:qe",
        ]
        for s in odd { _ = KRPCMessage.decode(Data(s.utf8)) }
        #expect(KRPCMessage.decode(Data("d1:t2:aa1:y1:xe".utf8)) == nil)
        #expect(KRPCMessage.decode(Data("i5e".utf8)) == nil)
        // An error with odd payload still decodes leniently.
        #expect(KRPCMessage.decode(Data("d1:t2:aa1:y1:e1:e3:abce".utf8))?.body == .error(code: 201, message: "abc"))
    }

    @Test func compactNodeInfoV4() {
        let nodes = (0..<5).map { DHTNodeInfo(id: .random(), addr: publicAddr($0, port: UInt16(1000 + $0))) }
        let enc = CompactNodeInfo.encode(nodes, v6: false)
        #expect(enc.count == 5 * 26)
        #expect(CompactNodeInfo.decode(enc, v6: false) == nodes)
        // Trailing partial entry is ignored; port-0 and unusable entries are skipped.
        var bad = enc + Data([1, 2, 3])
        var zeroPort = Data(DHTID.random().bytes); zeroPort.append(contentsOf: [8, 8, 8, 8, 0, 0])
        var multicast = Data(DHTID.random().bytes); multicast.append(contentsOf: [224, 0, 0, 1, 0x1A, 0xE1])
        bad.append(zeroPort); bad.append(multicast)
        #expect(CompactNodeInfo.decode(enc + zeroPort + multicast, v6: false) == nodes)
        #expect(CompactNodeInfo.decode(Data([1, 2, 3]), v6: false).isEmpty)
        // Wrong family entries are not encoded.
        let mixed = nodes + [DHTNodeInfo(id: .random(), addr: PeerAddress("[2001:db8::1]:1")!)]
        #expect(CompactNodeInfo.encode(mixed, v6: false).count == 5 * 26)
    }

    @Test func compactNodeInfoV6() {
        let nodes = (1...4).map { DHTNodeInfo(id: .random(), addr: PeerAddress("[2001:db8::\($0)]:\(6880 + $0)")!) }
        let enc = CompactNodeInfo.encode(nodes, v6: true)
        #expect(enc.count == 4 * 38)
        #expect(CompactNodeInfo.decode(enc, v6: true) == nodes)
        #expect(CompactNodeInfo.decode(enc, v6: false).count != 4)
    }

    @Test func splitHostPort() {
        #expect(DHTNode.splitHostPort("router.bittorrent.com:6881")! == ("router.bittorrent.com", 6881))
        #expect(DHTNode.splitHostPort("[2001:db8::1]:25401")! == ("2001:db8::1", 25401))
        #expect(DHTNode.splitHostPort("1.2.3.4:0") == nil)
        #expect(DHTNode.splitHostPort("nohost") == nil)
        #expect(DHTNode.splitHostPort("2001:db8::1:80") == nil)
    }
}

// MARK: - IDs, distance, routing table

@Suite struct DHTRoutingTests {
    @Test func idBasics() throws {
        let a = try #require(DHTID(Data(hex: "ffffffffffffffffffffffffffffffffffffffff")))
        #expect(a == .allOnes)
        let b = try #require(DHTID(Data(hex: "0000000000000000000000000000000000000001")))
        #expect((a ^ a) == .zero)
        #expect((a ^ b).bytes.last == 0xFE)
        #expect(DHTID.zero.leadingZeroBitCount == 160)
        #expect(b.leadingZeroBitCount == 159)
        #expect(b < a)
        #expect(b.bit(159) && !b.bit(158) && a.bit(0))
        let c = try #require(DHTID(Data(hex: "00000000000000000000ffff0000000000000000")))
        #expect(c.leadingZeroBitCount == 80)
        #expect(DHTID(Data(count: 19)) == nil)
        for n in [0, 1, 7, 63, 64, 65, 127, 128, 129, 159, 160] {
            #expect(DHTID.prefixMask(n).leadingZeroBitCount == (n == 0 ? 160 : 0))
            #expect((~DHTID.prefixMask(n)).leadingZeroBitCount == (n == 160 ? 160 : n))
        }
        let me = DHTID.random()
        for depth in [0, 3, 63, 64, 100, 128, 150, 159] {
            let r = me.randomID(sharingPrefix: depth, exact: true)
            #expect(me.commonPrefixLength(with: r) == depth)
        }
        #expect(me.data.count == 20 && DHTID(me.data) == me)
    }

    @Test func xorDistanceOrdering() {
        let target = DHTID.random()
        let ids = (0..<200).map { _ in DHTID.random() }
        let sorted = ids.sorted { target.isCloser($0, than: $1) }
        for i in 1..<sorted.count {
            #expect((sorted[i - 1] ^ target) <= (sorted[i] ^ target))
        }
        // Longer common prefix with the target ⇒ closer.
        #expect(target.isCloser(target.flippingBit(150), than: target.flippingBit(3)))
    }

    @Test func bucketSplittingKeepsInvariants() {
        let me = DHTID.random()
        let t = DHTRoutingTable(ownID: me, k: 8, now: 0)
        var inserted = 0
        // Private addresses: BEP 42 exempt and no unique-IP restriction.
        for i in 0..<2000 {
            let id = DHTID.random()
            let addr = PeerAddress(ip: .v4(0x0A00_0000 | UInt32(i)), port: 6881)
            if t.heard(id: id, addr: addr, confirmed: true, now: 1).outcome == .added { inserted += 1 }
        }
        #expect(t.count == inserted)
        #expect(t.buckets.count > 5)
        for (i, b) in t.buckets.enumerated() {
            #expect(b.nodes.count <= 8)
            #expect(b.replacements.count <= 8)
            for n in b.nodes {
                let cpl = me.commonPrefixLength(with: n.id)
                if i < t.buckets.count - 1 { #expect(cpl == i) } else { #expect(cpl >= i) }
            }
        }
        // Far buckets are full (random ids land there with high probability).
        #expect(t.buckets[0].nodes.count == 8)
        // Ids sharing a long prefix with us are always accepted (bucket splitting).
        let near = me.randomID(sharingPrefix: 40, exact: true)
        #expect(t.heard(id: near, addr: PeerAddress("10.9.9.9:1")!, confirmed: true, now: 2).outcome == .added)
    }

    @Test func closestMatchesBruteForce() {
        let me = DHTID.random()
        let t = DHTRoutingTable(ownID: me, k: 8, now: 0)
        for i in 0..<600 {
            t.heard(id: .random(), addr: PeerAddress(ip: .v4(0x0A00_0000 | UInt32(i)), port: 1), confirmed: true, now: 1)
        }
        for _ in 0..<20 {
            let target = DHTID.random()
            let got = t.closest(to: target, count: 8, now: 2).map(\.id)
            let brute = t.allEntries.map(\.id).sorted { target.isCloser($0, than: $1) }.prefix(8)
            #expect(got == Array(brute))
        }
    }

    @Test func nodeStatesAndFifteenMinuteRule() {
        let t = DHTRoutingTable(ownID: .random(), k: 8, now: 0)
        let id = DHTID.random(), addr = PeerAddress("10.0.0.1:1")!
        t.heard(id: id, addr: addr, confirmed: false, now: 0)
        #expect(t.entry(id: id)?.state(now: 0) == .questionable)   // never answered us
        t.heard(id: id, addr: addr, confirmed: true, now: 10)
        #expect(t.entry(id: id)?.state(now: 10) == .good)
        #expect(t.entry(id: id)?.state(now: 10 + 14 * 60) == .good)
        #expect(t.entry(id: id)?.state(now: 10 + 16 * 60) == .questionable)
        // A query from it keeps it good (it has answered before).
        t.heard(id: id, addr: addr, confirmed: false, now: 10 + 16 * 60)
        #expect(t.entry(id: id)?.state(now: 10 + 17 * 60) == .good)
        // Two failures in a row → bad (kept while there is no replacement).
        t.failed(id: id, addr: addr, now: 1000)
        #expect(t.entry(id: id)?.state(now: 1000) == .good)
        t.failed(id: id, addr: addr, now: 1001)
        #expect(t.entry(id: id)?.state(now: 1001) == .bad)
        #expect(t.closest(to: id, count: 8, now: 1001).isEmpty)
        // An answer resets the failure count.
        t.heard(id: id, addr: addr, confirmed: true, now: 2002)
        #expect(t.entry(id: id)?.failCount == 0)
    }

    @Test func fullBucketReplacementCacheAndBadNodeEviction() {
        let me = DHTID.random()
        let t = DHTRoutingTable(ownID: me, k: 8, now: 0)
        // Fill bucket 0 first (ids differing in the first bit), then split once by adding near ids.
        var far: [(DHTID, PeerAddress)] = []
        for i in 0..<8 {
            let id = me.randomID(sharingPrefix: 0, exact: true)
            let a = PeerAddress(ip: .v4(0x0A00_0100 | UInt32(i)), port: 1)
            far.append((id, a))
            #expect(t.heard(id: id, addr: a, confirmed: true, now: 1).outcome == .added)
        }
        // Force a split so bucket 0 is no longer the splittable bucket.
        for i in 0..<8 {
            t.heard(id: me.randomID(sharingPrefix: 1 + i, exact: true), addr: PeerAddress(ip: .v4(0x0A00_0200 | UInt32(i)), port: 1), confirmed: true, now: 1)
        }
        #expect(t.buckets.count >= 2)
        #expect(t.buckets[0].nodes.count == 8)
        // A 9th far node goes into the replacement cache and suggests pinging a questionable node.
        let extra = me.randomID(sharingPrefix: 0, exact: true)
        let extraAddr = PeerAddress("10.0.3.1:1")!
        let res = t.heard(id: extra, addr: extraAddr, confirmed: true, now: 1000)
        #expect(res.outcome == .cached)
        #expect(res.pingCandidate != nil)   // nodes are 999 s old → questionable
        #expect(t.buckets[0].replacements.contains { $0.id == extra })
        // When a bucket node goes bad it is replaced by the cached node.
        let victim = far[3]
        t.failed(id: victim.0, addr: victim.1, now: 1001)
        let promoted = t.failed(id: victim.0, addr: victim.1, now: 1002)
        #expect(promoted.isEmpty)   // the cached node had already answered us
        #expect(t.entry(id: victim.0) == nil)
        #expect(t.entry(id: extra) != nil)
        #expect(t.buckets[0].nodes.count == 8)
    }

    @Test func uniqueIPsAndIDHijackProtection() {
        let t = DHTRoutingTable(ownID: .random(), k: 8, now: 0)
        let ip = IPAddress("8.8.4.4")!
        let id1 = BEP42.nodeID(for: ip), id2 = BEP42.nodeID(for: ip)
        #expect(t.heard(id: id1, addr: PeerAddress(ip: ip, port: 1), confirmed: true, now: 1).outcome == .added)
        // Same public IP, different port and id: rejected (one entry per IP).
        #expect(t.heard(id: id2, addr: PeerAddress(ip: ip, port: 2), confirmed: true, now: 1).outcome == .rejected)
        // A good node's id cannot be moved to another endpoint.
        #expect(t.heard(id: id1, addr: publicAddr(9), confirmed: true, now: 2).outcome == .rejected)
        #expect(t.entry(id: id1)?.addr.port == 1)
        // Same endpoint, new id after a confirmed answer = node restarted: entry replaced.
        #expect(t.heard(id: id2, addr: PeerAddress(ip: ip, port: 1), confirmed: true, now: 3).outcome == .added)
        #expect(t.entry(id: id1) == nil && t.entry(id: id2) != nil)
        #expect(t.count == 1)
    }

    @Test func bep42PreferenceOnceTableIsHealthy() {
        let me = DHTID.random()
        let t = DHTRoutingTable(ownID: me, k: 8, now: 0)
        t.sparseThreshold = 0   // treat as healthy immediately
        // Bucket 0 (far half). Non-compliant ids may take at most k/2 slots.
        var nonCompliantAdded = 0
        for i in 0..<8 {
            let id = me.randomID(sharingPrefix: 0, exact: true)
            if t.heard(id: id, addr: publicAddr(100 + i), confirmed: true, now: 1).outcome == .added { nonCompliantAdded += 1 }
        }
        #expect(nonCompliantAdded == 4)
        // Compliant ids fill the rest and then displace non-compliant entries.
        var compliantAdded = 0
        var i = 0
        while compliantAdded < 8 && i < 5000 {
            i += 1
            let addr = publicAddr(1000 + i)
            let id = BEP42.nodeID(for: addr.ip)
            guard me.commonPrefixLength(with: id) == 0 else { continue }
            if t.heard(id: id, addr: addr, confirmed: true, now: 2).outcome == .added { compliantAdded += 1 }
        }
        let b0 = t.buckets[t.bucketIndex(for: me.flippingBit(0))]
        #expect(b0.nodes.count == 8)
        #expect(b0.nodes.allSatisfy { $0.compliant })
        // Sparse tables accept anything.
        let s = DHTRoutingTable(ownID: me, k: 8, now: 0)
        for i in 0..<8 {
            #expect(s.heard(id: me.randomID(sharingPrefix: 0, exact: true), addr: publicAddr(i), confirmed: true, now: 1).outcome == .added)
        }
    }

    @Test func rebuildKeepsNodes() {
        let t = DHTRoutingTable(ownID: .random(), k: 8, now: 0)
        for i in 0..<100 {
            t.heard(id: .random(), addr: PeerAddress(ip: .v4(0x0A00_0000 | UInt32(i)), port: 1), confirmed: true, now: 1)
        }
        let liveBefore = Set(t.allEntries.map(\.id))
        let before = liveBefore.union(t.buckets.flatMap(\.replacements).map(\.id))
        let newID = DHTID.random()
        t.rebuild(ownID: newID, now: 2)
        #expect(t.ownID == newID)
        let after = Set(t.allEntries.map(\.id))
        #expect(after.count == t.count)
        #expect(after.isSubset(of: before))
        #expect(after.count >= min(liveBefore.count, 20))
    }

    @Test func lookupConvergence() {
        let target = DHTID.random()
        let l = DHTLookup(kind: .getPeers, target: target, now: 0)
        l.k = 3
        l.alpha = 2
        let addrs = (0..<10).map { PeerAddress(ip: .v4(0x0A00_0000 | UInt32($0)), port: 1) }
        let ids = (0..<10).map { _ in DHTID.random() }
        for i in 0..<10 { l.add(id: ids[i], addr: addrs[i]) }
        #expect(!l.add(id: ids[0], addr: addrs[0]))   // dedup by endpoint
        let o = (0..<10).sorted { target.isCloser(ids[$0], than: ids[$1]) }
        let (q1, f1) = l.nextQueries(now: 0)
        #expect(q1.map(\.addr) == [addrs[o[0]], addrs[o[1]]] && !f1)
        #expect(l.nextQueries(now: 0.5).queries.isEmpty)        // alpha saturated
        // Slow queries free their alpha and window slots: the next closest are tried.
        let (q2, _) = l.nextQueries(now: 1.5)
        #expect(q2.map(\.addr) == [addrs[o[2]], addrs[o[3]]])
        let peer = PeerAddress("1.2.3.4:5")!
        #expect(l.handleResponse(from: addrs[o[0]], id: ids[o[0]], nodes: [], token: Data([1]), values: [peer]) == [peer])
        #expect(l.handleResponse(from: addrs[o[1]], id: ids[o[1]], nodes: [], token: Data([2]), values: [peer]).isEmpty)
        l.handleFailure(from: addrs[o[2]])
        // Only responders count towards k: with o3 still in flight, alpha allows querying o4 too.
        let (q3, f3) = l.nextQueries(now: 1.6)
        #expect(q3.map(\.addr) == [addrs[o[4]]] && !f3)
        _ = l.handleResponse(from: addrs[o[3]], id: ids[o[3]], nodes: [], token: Data([3]), values: [])
        let (q4, f4) = l.nextQueries(now: 1.7)
        #expect(q4.isEmpty && f4)
        #expect(l.announceTargets(count: 8).map(\.addr) == [addrs[o[0]], addrs[o[1]], addrs[o[3]]])
    }

    @Test func lookupRoutersDoNotBlockWindow() {
        let target = DHTID.random()
        let l = DHTLookup(kind: .findNode, target: target, now: 0)
        l.k = 2
        l.alpha = 1
        let routers = (0..<4).map { PeerAddress(ip: .v4(0x0A01_0000 | UInt32($0)), port: 6881) }
        for r in routers { l.add(id: nil, addr: r) }
        // All id-less endpoints are queried at once, regardless of alpha.
        let (q1, f1) = l.nextQueries(now: 0)
        #expect(Set(q1.map(\.addr)) == Set(routers) && !f1)
        // Only routers in flight (even slow ones): keep waiting.
        #expect(!l.nextQueries(now: 2).finished)
        // One router answers with nodes; the others never do.
        let nodes = (0..<3).map { DHTNodeInfo(id: .random(), addr: PeerAddress(ip: .v4(0x0A02_0000 | UInt32($0)), port: 1)) }
        _ = l.handleResponse(from: routers[0], id: .random(), nodes: nodes, token: nil, values: [])
        let (q2, _) = l.nextQueries(now: 2.1)
        #expect(q2.count == 1 && q2[0].id != nil)               // a real node is queried immediately
        #expect(l.closestResponded(count: 8).count == 1)
        for n in nodes { _ = l.handleResponse(from: n.addr, id: n.id, nodes: [], token: nil, values: []) }
        // k closest responded: finished although routers 1-3 are still outstanding.
        #expect(l.nextQueries(now: 2.2).finished)
    }
}

// MARK: - BEP 42

@Suite struct DHTBEP42Tests {
    static let vectors: [(String, UInt8, String)] = [
        ("124.31.75.21", 1, "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
        ("21.75.31.124", 86, "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"),
        ("65.23.51.170", 22, "a5d43220bc8f112a3d426c84764f8c2a1150e616"),
        ("84.124.73.14", 65, "1b0321dd1bb1fe518101ceef99462b947a01ff41"),
        ("43.213.53.83", 90, "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"),
    ]

    @Test func crc32cKnownValue() {
        #expect(BEP42.crc32c(Array("123456789".utf8)) == 0xE306_9283)
        #expect(BEP42.crc32c([]) == 0)
    }

    @Test func generatesSpecVectors() throws {
        for (ipString, rand, example) in Self.vectors {
            let ip = try #require(IPAddress(ipString))
            let id = BEP42.nodeID(for: ip, rand: rand).bytes
            let ex = try #require(Data(hex: example)).map { $0 }
            // The top 21 bits are determined by the IP and rand; the last byte is rand.
            #expect(id[0] == ex[0] && id[1] == ex[1] && (id[2] & 0xF8) == (ex[2] & 0xF8), "\(ipString)")
            #expect(id[19] == rand)
            #expect(BEP42.isValid(DHTID(bytes: id)!, for: ip))
        }
    }

    @Test func verifiesSpecExampleIDs() throws {
        for (ipString, _, example) in Self.vectors {
            let ip = try #require(IPAddress(ipString))
            let id = try #require(DHTID(Data(hex: example)))
            #expect(BEP42.isValid(id, for: ip), "\(ipString)")
            // Tampering with the CRC prefix or the rand byte breaks validation.
            #expect(!BEP42.isValid(id.flippingBit(3), for: ip))
            #expect(!BEP42.isValid(id.flippingBit(159 - 0), for: ip) || !BEP42.isValid(id.flippingBit(157), for: ip))
            // A different IP does not validate.
            #expect(!BEP42.isValid(id, for: IPAddress("9.9.9.9")!))
        }
    }

    @Test func exemptionsAndIPv6() throws {
        let random = DHTID.random()
        #expect(BEP42.isValid(random, for: IPAddress("192.168.1.5")!))
        #expect(BEP42.isValid(random, for: IPAddress("10.1.2.3")!))
        #expect(BEP42.isValid(random, for: IPAddress("127.0.0.1")!))
        #expect(BEP42.isValid(random, for: IPAddress("::1")!))
        let v6 = try #require(IPAddress("2001:db8:85a3::8a2e:370:7334"))
        for _ in 0..<20 {
            let id = BEP42.nodeID(for: v6)
            #expect(BEP42.isValid(id, for: v6))
        }
        // Only the masked bits of the IP matter: the last 8 bytes of a v6 address are ignored.
        let sibling = try #require(IPAddress("2001:db8:85a3::1"))
        #expect(BEP42.isValid(BEP42.nodeID(for: v6, rand: 3), for: sibling))
    }

    @Test func ipVoterNeedsDistinctMajority() {
        var v = DHTIPVoter()
        let me = IPAddress("203.0.113.7")!
        #expect(v.add(voter: IPAddress("1.1.1.1")!, reported: me) == nil)
        #expect(v.add(voter: IPAddress("1.1.1.1")!, reported: me) == nil)   // same voter twice
        #expect(v.add(voter: IPAddress("1.1.1.2")!, reported: me) == nil)
        #expect(v.add(voter: IPAddress("1.1.1.3")!, reported: IPAddress("198.51.100.1")!) == nil)
        #expect(v.add(voter: IPAddress("1.1.1.4")!, reported: me) == nil)
        #expect(v.add(voter: IPAddress("1.1.1.5")!, reported: me) == me)
        #expect(v.winner == me)
        #expect(v.add(voter: IPAddress("1.1.1.6")!, reported: me) == nil)    // unchanged
    }
}

// MARK: - Tokens / storage

@Suite struct DHTTokenTests {
    @Test func tokensRotateAndAcceptPrevious() {
        var tm = DHTTokenManager(now: 0)
        let ip = IPAddress("203.0.113.5")!, other = IPAddress("203.0.113.6")!
        let tok = tm.token(for: ip)
        #expect(tok.count == 8)
        #expect(tm.validate(tok, for: ip))
        #expect(!tm.validate(tok, for: other))
        #expect(!tm.validate(Data(tok.prefix(4)), for: ip))
        tm.rotateIfNeeded(now: 100)            // too early: no rotation
        #expect(tm.token(for: ip) == tok)
        tm.rotateIfNeeded(now: 301)            // rotated once: previous still valid
        #expect(tm.token(for: ip) != tok)
        #expect(tm.validate(tok, for: ip))
        tm.rotateIfNeeded(now: 602)            // rotated twice: expired
        #expect(!tm.validate(tok, for: ip))
        // Tokens depend on IP only (not port) and are deterministic per secret.
        #expect(DHTTokenManager.make(secret: Data([1]), ip: ip) == DHTTokenManager.make(secret: Data([1]), ip: ip))
    }

    @Test func peerStoreLimitsAndExpiry() {
        var s = DHTPeerStore()
        let h = DHTID.random()
        for i in 0..<150 { s.announce(h, peer: publicAddr(i), now: Double(i)) }
        #expect(s.peers(for: h, max: 1000, now: 150).count == 100)
        // Oldest were evicted.
        #expect(!s.peers(for: h, max: 1000, now: 150).contains(publicAddr(0)))
        #expect(s.peers(for: h, max: 10, now: 150).count == 10)
        // Re-announcing refreshes expiry.
        s.announce(h, peer: publicAddr(149), now: 1500)
        s.expire(now: 149 + 30 * 60 + 1)
        #expect(s.peers(for: h, max: 1000, now: 149 + 30 * 60 + 1) == [publicAddr(149)])
        s.expire(now: 1500 + 30 * 60 + 1)
        #expect(s.hashCount == 0)
    }

    @Test func rateLimiter() {
        var r = DHTRateLimiter(rate: 200, burst: 200, now: 0)
        var n = 0
        while r.take(now: 0) { n += 1 }
        #expect(n == 200)
        let extra = r.take(now: 0.001)
        #expect(!extra)
        var m = 0
        while r.take(now: 0.5) { m += 1 }
        #expect(m == 100)
    }
}

// MARK: - Server side (answering other nodes)

@Suite struct DHTServerTests {
    /// A started node whose outgoing packets are captured.
    final class Harness: @unchecked Sendable {
        let loop = EventLoop(label: "astor.dht.server-test")
        let box = DHTPacketBox()
        var node: DHTNode!
        let clientID = DHTID.random()
        var tid: UInt16 = 0

        init(v6: Bool = false) {
            loop.sync {
                let resolver = HostResolver(loop: loop, dohFallback: false)
                node = DHTNode(loop: loop, isV6: v6, resolver: resolver, stateFile: nil) { [box] d, a in
                    box.sent.append((d, a))
                }
                node.start(bootstrap: [])
            }
        }

        deinit { loop.sync { node.stop() } }

        /// Send a query from `from` and return the first reply addressed to it.
        func query(_ method: String, _ args: [Data: BValue], from: PeerAddress, id: DHTID? = nil,
                   readOnly: Bool = false) -> KRPCMessage? {
            loop.sync {
                tid &+= 1
                box.sent.removeAll()
                var a = args
                a[KRPCKey.id] = .bytes((id ?? clientID).data)
                let msg = KRPCMessage(transactionID: Data([UInt8(tid >> 8), UInt8(tid & 0xFF)]),
                                      body: .query(method: method, args: a), readOnly: readOnly)
                node.handle(msg.encoded, from: from)
                let replies = box.sent.filter { $0.1 == from }.compactMap { KRPCMessage.decode($0.0) }
                return replies.first { !$0.isQuery && $0.transactionID == msg.transactionID }
            }
        }

        func raw(_ data: Data, from: PeerAddress) -> Int {
            loop.sync {
                box.sent.removeAll()
                node.handle(data, from: from)
                return box.sent.count
            }
        }

        /// Pre-populate the routing table with confirmed BEP 42-compliant public nodes.
        func populate(_ n: Int) -> [DHTNodeInfo] {
            loop.sync {
                var out: [DHTNodeInfo] = []
                for i in 0..<n {
                    let addr = publicAddr(500 + i, port: UInt16(7000 + i))
                    let id = BEP42.nodeID(for: addr.ip)
                    if node.table.heard(id: id, addr: addr, confirmed: true, now: monotonicNow()).outcome == .added {
                        out.append(DHTNodeInfo(id: id, addr: addr))
                    }
                }
                return out
            }
        }
    }

    let client = PeerAddress("203.0.113.10:5555")!

    @Test func answersPingWithIDVersionAndIP() throws {
        let h = Harness()
        let r = try #require(h.query("ping", [:], from: client))
        guard case .response(let dict) = r.body else { Issue.record("expected response"); return }
        #expect(dict[KRPCKey.id]?.data == h.loop.sync { h.node.nodeIDData })
        #expect(r.yourIP == client)                         // BEP 42 "ip"
        #expect(r.version == Data("AS01".utf8))             // "v"
        // The querier joined the routing table and is being pinged for verification.
        h.loop.sync {
            #expect(h.node.nodeCount == 1)
            #expect(h.box.sent.contains { p in
                if case .query(let m, _) = KRPCMessage.decode(p.0)?.body { return m == "ping" && p.1 == client }
                return false
            })
        }
    }

    @Test func readOnlyQueriersAreNotAdded() throws {
        let h = Harness()
        let r = try #require(h.query("ping", [:], from: client, readOnly: true))
        #expect(!r.isQuery)
        #expect(h.loop.sync { h.node.nodeCount } == 0)
    }

    @Test func findNodeReturnsClosest() throws {
        let h = Harness()
        let known = h.populate(40)
        #expect(known.count >= 16)
        let target = DHTID.random()
        let r = try #require(h.query("find_node", [KRPCKey.target: .bytes(target.data)], from: client))
        guard case .response(let dict) = r.body, let raw = dict[KRPCKey.nodes]?.data else {
            Issue.record("missing nodes"); return
        }
        #expect(raw.count == 8 * 26)
        #expect(dict[KRPCKey.nodes6] == nil)
        let got = CompactNodeInfo.decode(raw, v6: false)
        let expected = known.sorted { target.isCloser($0.id, than: $1.id) }.prefix(8)
        #expect(got == Array(expected))
        // Missing / malformed target → protocol error 203.
        let e = try #require(h.query("find_node", [KRPCKey.target: .bytes(Data([1, 2, 3]))], from: client))
        #expect(e.body == .error(code: 203, message: "invalid target"))
    }

    @Test func getPeersAnnounceFlow() throws {
        let h = Harness()
        _ = h.populate(12)
        let ih = DHTID.random()
        // 1) get_peers on an unknown hash: token + nodes, no values.
        let r1 = try #require(h.query("get_peers", [KRPCKey.infoHash: .bytes(ih.data)], from: client))
        guard case .response(let d1) = r1.body else { Issue.record("expected response"); return }
        let token = try #require(d1[KRPCKey.token]?.data)
        #expect(token.count == 8)
        #expect(d1[KRPCKey.values] == nil)
        #expect((d1[KRPCKey.nodes]?.data?.count ?? 0) == 8 * 26)

        // 2) announce_peer with a bad token → 203.
        let bad = try #require(h.query("announce_peer", [KRPCKey.infoHash: .bytes(ih.data), KRPCKey.port: .int(6881),
                                                          KRPCKey.token: .bytes(Data(repeating: 0, count: 8))], from: client))
        #expect(bad.body == .error(code: 203, message: "bad token"))
        // The token is bound to the requester's IP.
        let other = PeerAddress("203.0.113.11:5555")!
        let stolen = try #require(h.query("announce_peer", [KRPCKey.infoHash: .bytes(ih.data), KRPCKey.port: .int(6881),
                                                             KRPCKey.token: .bytes(token)], from: other))
        #expect(stolen.body == .error(code: 203, message: "bad token"))

        // 3) valid announce with an explicit port.
        let ok = try #require(h.query("announce_peer", [KRPCKey.infoHash: .bytes(ih.data), KRPCKey.port: .int(6881),
                                                         KRPCKey.token: .bytes(token)], from: client))
        guard case .response = ok.body else { Issue.record("announce rejected: \(ok.body)"); return }
        // 4) implied_port uses the UDP source port.
        let client2 = PeerAddress("203.0.113.12:40000")!
        let r2 = try #require(h.query("get_peers", [KRPCKey.infoHash: .bytes(ih.data)], from: client2))
        let token2 = try #require(r2.payload[KRPCKey.token]?.data)
        _ = try #require(h.query("announce_peer", [KRPCKey.infoHash: .bytes(ih.data), KRPCKey.port: .int(1),
                                                    KRPCKey.impliedPort: .int(1), KRPCKey.token: .bytes(token2)], from: client2))
        // Invalid port without implied_port → 203.
        let badPort = try #require(h.query("announce_peer", [KRPCKey.infoHash: .bytes(ih.data), KRPCKey.port: .int(70000),
                                                              KRPCKey.token: .bytes(token)], from: client))
        #expect(badPort.body == .error(code: 203, message: "invalid port"))

        // 5) get_peers now returns both peers as values.
        let r3 = try #require(h.query("get_peers", [KRPCKey.infoHash: .bytes(ih.data)], from: PeerAddress("198.51.100.1:1")!))
        let values = DHTNode.parseValues(r3.payload[KRPCKey.values])
        #expect(Set(values) == [PeerAddress("203.0.113.10:6881")!, PeerAddress("203.0.113.12:40000")!])
        #expect(r3.payload[KRPCKey.token] != nil)
    }

    @Test func wantKeyAndSibling() throws {
        let h = Harness()
        _ = h.populate(10)
        // v6 sibling with a few nodes.
        let v6 = h.loop.sync { () -> DHTNode in
            let n = DHTNode(loop: h.loop, isV6: true, resolver: HostResolver(loop: h.loop, dohFallback: false),
                            stateFile: nil) { _, _ in }
            for i in 1...5 {
                let a = PeerAddress("[2001:db8::\(i)]:6881")!
                n.table.heard(id: BEP42.nodeID(for: a.ip), addr: a, confirmed: true, now: monotonicNow())
            }
            h.node.sibling = n
            return n
        }
        let target = DHTID.random().data
        let both = try #require(h.query("find_node", [KRPCKey.target: .bytes(target),
                                                       KRPCKey.want: .list([.string("n4"), .string("n6")])], from: client))
        #expect((both.payload[KRPCKey.nodes]?.data?.count ?? 0) == 8 * 26)
        #expect((both.payload[KRPCKey.nodes6]?.data?.count ?? 0) == 5 * 38)
        let only6 = try #require(h.query("find_node", [KRPCKey.target: .bytes(target),
                                                        KRPCKey.want: .list([.string("n6")])], from: client))
        #expect(only6.payload[KRPCKey.nodes] == nil)
        #expect(only6.payload[KRPCKey.nodes6] != nil)
        _ = v6
    }

    @Test func errorsForBadQueries() throws {
        let h = Harness()
        // Missing id.
        let noID = h.loop.sync { () -> KRPCMessage? in
            h.box.sent.removeAll()
            let m = KRPCMessage(transactionID: Data("zz".utf8), body: .query(method: "ping", args: [:]))
            h.node.handle(m.encoded, from: client)
            return h.box.sent.first.flatMap { KRPCMessage.decode($0.0) }
        }
        #expect(noID?.body == .error(code: 203, message: "invalid id"))
        #expect(noID?.yourIP == client)
        // Unknown method without a target → 204; with a target → answered like find_node.
        let unknown = try #require(h.query("frobnicate", [:], from: client))
        #expect(unknown.body == .error(code: 204, message: "method unknown"))
        let fwd = try #require(h.query("sample_infohashes", [KRPCKey.target: .bytes(DHTID.random().data)], from: client))
        #expect(fwd.payload[KRPCKey.nodes] != nil)
        // Garbage, wrong family and responses to unknown transactions produce nothing.
        #expect(h.raw(Data("garbage".utf8), from: client) == 0)
        #expect(h.raw(Data("d1:rd2:id20:abcdefghij0123456789e1:t2:qq1:y1:re".utf8), from: client) == 0)
        #expect(h.raw(Data("d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe".utf8),
                      from: PeerAddress("[2001:db8::5]:1")!) == 0)
        // Fuzzed datagrams never crash the node.
        let base = KRPCMessage(transactionID: Data([9, 9]),
                               body: .query(method: "get_peers", args: [KRPCKey.id: .bytes(DHTID.random().data),
                                                                        KRPCKey.infoHash: .bytes(DHTID.random().data)])).encoded
        for _ in 0..<2000 {
            var d = base
            for _ in 0..<3 { d[Int.random(in: 0..<d.count)] = UInt8.random(in: 0...255) }
            _ = h.raw(d, from: client)
        }
        #expect(h.loop.sync { !h.node.stopped })
    }

    @Test func externalAddressVoteRegeneratesBEP42ID() throws {
        let h = Harness()
        let box = DHTLookupBox()
        let external = IPAddress("203.0.113.77")!
        h.loop.sync { h.node.onExternalAddress = { box.external.append($0) } }
        let voters = (0..<5).map { publicAddr(900 + $0, port: 6881) }
        for v in voters {
            h.loop.sync {
                h.box.sent.removeAll()
                h.node.addNode(v)
                // Answer the ping with an "ip" field.
                guard let ping = h.box.sent.first(where: { $0.1 == v }).flatMap({ KRPCMessage.decode($0.0) }) else {
                    Issue.record("no ping sent"); return
                }
                let reply = KRPCMessage(transactionID: ping.transactionID,
                                        body: .response([KRPCKey.id: .bytes(BEP42.nodeID(for: v.ip).data)]),
                                        yourIP: PeerAddress(ip: external, port: 6881))
                h.node.handle(reply.encoded, from: v)
            }
        }
        h.loop.sync {
            #expect(box.external == [external])
            #expect(h.node.externalIP == external)
            #expect(BEP42.isValid(DHTID(h.node.nodeIDData)!, for: external))
            #expect(h.node.nodeCount == 5)          // all voters answered → confirmed nodes
            #expect(h.node.stats.responsesReceived == 5)
        }
    }

    @Test func statePersistenceRoundTrip() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("astor-dht-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("dht.dat")
        let loop = EventLoop(label: "astor.dht.persist-test")
        let saved = DHTLookupBox()
        let (node, nodes) = loop.sync { () -> (DHTNode, [DHTNodeInfo]) in
            let n = DHTNode(loop: loop, isV6: false, resolver: HostResolver(loop: loop, dohFallback: false),
                            stateFile: file) { _, _ in }
            var infos: [DHTNodeInfo] = []
            for i in 0..<30 {
                let a = publicAddr(300 + i, port: 6881)
                let id = BEP42.nodeID(for: a.ip)
                if n.table.heard(id: id, addr: a, confirmed: true, now: monotonicNow()).outcome == .added {
                    infos.append(DHTNodeInfo(id: id, addr: a))
                }
            }
            n.saveState(completion: { loop.execute { saved.done = true } })
            return (n, infos)
        }
        #expect(await dhtWaitUntil(5) { loop.sync { saved.done } })
        let data = try Data(contentsOf: file)
        let v = try BDecoder.decode(data)
        #expect(v["id"]?.data == loop.sync { node.nodeIDData })
        let restored = CompactNodeInfo.decode(v["nodes"]?.data ?? Data(), v6: false)
        #expect(Set(restored) == Set(nodes))

        // A new node loads the id and uses the saved nodes as bootstrap seeds.
        let box = DHTPacketBox()
        let node2 = loop.sync { () -> DHTNode in
            let n = DHTNode(loop: loop, isV6: false, resolver: HostResolver(loop: loop, dohFallback: false),
                            stateFile: file) { [box] d, a in box.sent.append((d, a)) }
            n.start(bootstrap: [])
            return n
        }
        let expectedID = loop.sync { node.nodeIDData }
        #expect(await dhtWaitUntil(5) { loop.sync { node2.nodeIDData == expectedID && !box.sent.isEmpty } })
        loop.sync {
            let targets = Set(box.sent.map(\.1))
            #expect(targets.isSubset(of: Set(nodes.map(\.addr))))
            #expect(box.sent.allSatisfy {
                if case .query(let m, _) = KRPCMessage.decode($0.0)?.body { return m == "find_node" }
                return false
            })
            node2.stop()
        }
    }
}

// MARK: - Offline multi-node swarm over real loopback UDP sockets

@Suite(.serialized) struct DHTSwarmTests {
    final class Swarm: @unchecked Sendable {
        let loop: EventLoop
        var sockets: [UDPSocket] = []
        var nodes: [DHTNode] = []
        let v6: Bool

        init(count: Int, v6: Bool) throws {
            self.v6 = v6
            loop = EventLoop(label: "astor.dht.swarm\(v6 ? "6" : "4")")
            try loop.sync {
                let resolver = HostResolver(loop: loop, dohFallback: false)
                for _ in 0..<count {
                    let s = try UDPSocket(port: 0, v6: v6, loop: loop)
                    let n = DHTNode(loop: loop, isV6: v6, resolver: resolver, stateFile: nil) { [weak s] d, a in
                        s?.send(d, to: a)
                    }
                    s.onDatagram = { [weak n] d, from in
                        if d.first == UInt8(ascii: "d") { n?.handle(d, from: from) }
                    }
                    s.start()
                    sockets.append(s)
                    nodes.append(n)
                }
            }
        }

        func addr(_ i: Int) -> PeerAddress {
            PeerAddress(ip: v6 ? .v6(0, 1) : .v4(0x7F00_0001), port: sockets[i].port)
        }

        func hostPort(_ i: Int) -> String { v6 ? "[::1]:\(sockets[i].port)" : "127.0.0.1:\(sockets[i].port)" }

        func start() {
            loop.sync {
                nodes[0].start(bootstrap: [])
                for i in 1..<nodes.count {
                    nodes[i].start(bootstrap: [hostPort(0)])
                    // Also a PORT-message style hint to a random earlier node.
                    nodes[i].addNode(addr(Int.random(in: 0..<i)))
                }
            }
        }

        func shutdown() {
            loop.sync {
                for n in nodes { n.stop() }
                for s in sockets { s.close() }
            }
        }
    }

    private func runSwarm(count: Int, v6: Bool) async throws {
        let swarm = try Swarm(count: count, v6: v6)
        defer { swarm.shutdown() }
        let t0 = Date()
        swarm.start()
        let converged = await dhtWaitUntil(15) {
            swarm.loop.sync { swarm.nodes.allSatisfy { $0.nodeCount >= 6 } }
        }
        let counts = swarm.loop.sync { swarm.nodes.map(\.nodeCount) }
        print("[DHT swarm \(v6 ? "v6" : "v4")] \(count) nodes, table sizes after \(String(format: "%.2f", Date().timeIntervalSince(t0))) s: min \(counts.min()!) avg \(counts.reduce(0, +) / counts.count) max \(counts.max()!)")
        #expect(converged)

        // Announce from node A.
        let infoHash = Data.random(20)
        let target = DHTID(infoHash)!
        let a = 3
        let announcePort: UInt16 = 41_234
        let aBox = DHTLookupBox()
        swarm.loop.sync {
            swarm.nodes[a].getPeers(infoHash: infoHash, announcePort: announcePort, impliedPort: false,
                                    onPeers: { aBox.peers += $0 }, onDone: { aBox.done = true })
        }
        #expect(await dhtWaitUntil(10) { swarm.loop.sync { aBox.done } })
        // Let the announce_peer queries land.
        let storing = await { () async -> [Int] in
            var s: [Int] = []
            _ = await dhtWaitUntil(3) {
                s = swarm.loop.sync {
                    swarm.nodes.indices.filter { !swarm.nodes[$0].store.peers(for: target, max: 10, now: monotonicNow()).isEmpty }
                }
                return s.count >= 3
            }
            return s
        }()
        let byDistance = swarm.loop.sync {
            swarm.nodes.indices.sorted { target.isCloser(DHTID(swarm.nodes[$0].nodeIDData)!, than: DHTID(swarm.nodes[$1].nodeIDData)!) }
        }
        print("[DHT swarm \(v6 ? "v6" : "v4")] announce stored on nodes \(storing); 8 closest overall: \(Array(byDistance.prefix(8)))")
        #expect(storing.count >= 3)
        // The closest node that can store it (not the announcer; node 0 is everyone's
        // bootstrap router and therefore never enters routing tables) must have it.
        let closestEligible = byDistance.first { $0 != a && $0 != 0 }!
        #expect(storing.contains(closestEligible))

        // Look it up from a node that does not store it itself.
        let b = try #require(swarm.nodes.indices.reversed().first { $0 != a && !storing.contains($0) })
        let bBox = DHTLookupBox()
        let t1 = Date()
        swarm.loop.sync {
            swarm.nodes[b].getPeers(infoHash: infoHash, announcePort: nil, impliedPort: false,
                                    onPeers: { bBox.peers += $0; bBox.batches += 1 }, onDone: { bBox.done = true })
        }
        #expect(await dhtWaitUntil(10) { swarm.loop.sync { bBox.done } })
        let found = swarm.loop.sync { bBox.peers }
        print("[DHT swarm \(v6 ? "v6" : "v4")] node \(b) found \(found) in \(String(format: "%.3f", Date().timeIntervalSince(t1))) s")
        let expectedPeer = PeerAddress(ip: swarm.addr(a).ip, port: announcePort)
        #expect(found.contains(expectedPeer))
        #expect(found.count == Set(found).count)   // deduplicated
    }

    @Test func offlineSwarmIPv4() async throws {
        try await runSwarm(count: 48, v6: false)
    }

    @Test func offlineSwarmIPv6() async throws {
        try await runSwarm(count: 12, v6: true)
    }
}

// MARK: - Live (real Mainline DHT) — run with ASTOR_LIVE=1

@Suite(.serialized) struct DHTLiveTests {
    static var enabled: Bool { ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1" }

    /// The v1 info hash of the current Ubuntu LTS desktop ISO torrent from releases.ubuntu.com.
    static func ubuntuInfoHash() async throws -> (String, Data) {
        let base = URL(string: "https://releases.ubuntu.com/")!
        func fetch(_ url: URL) async throws -> Data {
            let (d, resp) = try await URLSession.shared.data(from: url)
            guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            return d
        }
        let index = String(decoding: try await fetch(base), as: UTF8.self)
        let dirRegex = try NSRegularExpression(pattern: #"href="(\d\d\.\d\d)/""#)
        var dirs = Set<String>()
        for m in dirRegex.matches(in: index, range: NSRange(index.startIndex..., in: index)) {
            if let r = Range(m.range(at: 1), in: index) { dirs.insert(String(index[r])) }
        }
        // Newest LTS first (most seeded), then other releases.
        let ordered = dirs.sorted { ($0.hasSuffix(".04") ? 1 : 0, $0) > ($1.hasSuffix(".04") ? 1 : 0, $1) }
        let fileRegex = try NSRegularExpression(pattern: #"href="(ubuntu-[0-9.]+-desktop-amd64\.iso\.torrent)""#)
        for dir in ordered.prefix(3) {
            let listing = String(decoding: try await fetch(base.appendingPathComponent(dir + "/")), as: UTF8.self)
            var names: [String] = []
            for m in fileRegex.matches(in: listing, range: NSRange(listing.startIndex..., in: listing)) {
                if let r = Range(m.range(at: 1), in: listing) { names.append(String(listing[r])) }
            }
            guard let name = names.max(by: { $0.compare($1, options: .numeric) == .orderedAscending }) else { continue }
            let torrent = try await fetch(base.appendingPathComponent(dir + "/" + name))
            let meta = try Metainfo(torrentFile: torrent)
            if let v1 = meta.infoHashes.v1 { return (name, v1) }
        }
        throw URLError(.fileDoesNotExist)
    }

    @Test(.enabled(if: DHTLiveTests.enabled), .timeLimit(.minutes(2)))
    func liveBootstrapAndGetPeers() async throws {
        let (name, infoHash) = try await Self.ubuntuInfoHash()
        print("[DHT live] torrent \(name) v1 info hash \(infoHash.hex)")

        let loop = EventLoop(label: "astor.dht.live")
        let box = DHTLookupBox()
        let (socket, node) = try loop.sync { () throws -> (UDPSocket, DHTNode) in
            let s = try UDPSocket(port: 0, v6: false, loop: loop)
            let n = DHTNode(loop: loop, isV6: false, resolver: HostResolver(loop: loop), stateFile: nil) { [weak s] d, a in
                s?.send(d, to: a)
            }
            s.onDatagram = { [weak n] d, from in if d.first == UInt8(ascii: "d") { n?.handle(d, from: from) } }
            n.onExternalAddress = { box.external.append($0) }
            s.start()
            n.start(bootstrap: SessionConfig.dhtBootstrapNodes)
            return (s, n)
        }
        defer { loop.sync { node.stop(); socket.close() } }

        let t0 = Date()
        var timeline: [String] = []
        // Bootstrap: report node count once a second (up to 12 s or ≥ 40 nodes).
        for _ in 0..<12 {
            try await Task.sleep(nanoseconds: 1_000_000_000)
            let (n, st, lk, ext) = loop.sync { (node.nodeCount, node.stats, node.activeLookupCount, box.external.last) }
            timeline.append("t=\(Int(Date().timeIntervalSince(t0)))s nodes=\(n) sent=\(st.queriesSent) resp=\(st.responsesReceived) timeouts=\(st.timeouts) lookups=\(lk) external=\(ext.map(\.description) ?? "-")")
            print("[DHT live] " + timeline.last!)
            if n >= 40 { break }
        }
        let bootNodes = loop.sync { node.nodeCount }
        #expect(bootNodes > 0)

        let tLookup = Date()
        var firstPeerAt: Double?
        loop.sync {
            node.getPeers(infoHash: infoHash, announcePort: nil, impliedPort: false,
                          onPeers: { box.peers += $0; box.batches += 1 }, onDone: { box.done = true })
        }
        while Date().timeIntervalSince(tLookup) < 30 {
            try await Task.sleep(nanoseconds: 500_000_000)
            let (peers, done, n) = loop.sync { (box.peers.count, box.done, node.nodeCount) }
            if peers > 0 && firstPeerAt == nil { firstPeerAt = Date().timeIntervalSince(tLookup) }
            print("[DHT live] lookup t=\(String(format: "%.1f", Date().timeIntervalSince(tLookup)))s peers=\(peers) nodes=\(n) done=\(done)")
            if done { break }
        }
        // Keep watching the routing table grow (background bucket refreshes) until t = 30 s.
        while Date().timeIntervalSince(t0) < 30 {
            try await Task.sleep(nanoseconds: 2_000_000_000)
            let (n, st, lk) = loop.sync { (node.nodeCount, node.stats, node.activeLookupCount) }
            print("[DHT live] t=\(Int(Date().timeIntervalSince(t0)))s nodes=\(n) sent=\(st.queriesSent) resp=\(st.responsesReceived) timeouts=\(st.timeouts) lookups=\(lk)")
        }
        let (peers, n, st, ext, id) = loop.sync { (box.peers, node.nodeCount, node.stats, box.external, node.nodeIDData) }
        print("[DHT live] RESULT: nodes=\(n) peers=\(peers.count) (unique \(Set(peers).count)) firstPeerAfter=\(firstPeerAt.map { String(format: "%.2f s", $0) } ?? "never") lookupDone=\(loop.sync { box.done }) total=\(String(format: "%.1f", Date().timeIntervalSince(t0))) s")
        print("[DHT live] stats: sent=\(st.queriesSent) responses=\(st.responsesReceived) errors=\(st.errorsReceived) timeouts=\(st.timeouts) incomingQueries=\(st.queriesReceived) table added/cached/rejected=\(st.tableAdded)/\(st.tableCached)/\(st.tableRejected)")
        let buckets = loop.sync { node.table.buckets.map { "\($0.nodes.count)+\($0.replacements.count)" } }
        print("[DHT live] buckets (live+replacements): \(buckets.joined(separator: " "))")
        print("[DHT live] external address votes → \(ext.map(\.description)); node id \(id.hex) BEP42-valid=\(ext.last.map { BEP42.isValid(DHTID(id)!, for: $0) } ?? false)")
        print("[DHT live] sample peers: \(peers.prefix(8).map(\.description))")
        #expect(peers.count > 0)
    }
}
