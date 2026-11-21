import Testing
import Foundation
@testable import TorrentCore

// MARK: - Shared test environment

/// All tracker tests share one loop (socket read scratch buffers are per
/// process, so concurrent loops in one test process could race).
enum TrackerTestEnv {
    static let loop = EventLoop(label: "astor.tracker.tests")

    static func makeClient(retransmit: [Double] = [0.25, 0.4]) -> (TrackerClient, HostResolver) {
        loop.sync {
            let r = HostResolver(loop: loop, dohFallback: false)
            let c = TrackerClient(loop: loop, resolver: r)
            c.udpRetransmitTimeouts = retransmit
            return (c, r)
        }
    }

    /// Poll `cond` on the loop until true or timeout.
    static func waitUntil(_ timeout: Double = 5, _ cond: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if loop.sync(cond) { return true }
            try? await Task.sleep(for: .milliseconds(15))
        }
        return loop.sync(cond)
    }

    static func announce(_ c: TrackerClient, _ url: String, _ req: AnnounceRequest) async -> Result<AnnounceResponse, any Error> {
        await withCheckedContinuation { cont in
            loop.execute { c.announce(url: url, req) { cont.resume(returning: $0) } }
        }
    }

    static func scrape(_ c: TrackerClient, _ url: String, _ hashes: [Data]) async
        -> Result<[Data: (seeders: Int, completed: Int, leechers: Int)], any Error> {
        await withCheckedContinuation { cont in
            loop.execute { c.scrape(url: url, infoHashes: hashes) { cont.resume(returning: $0) } }
        }
    }

    static let peerID = Data("-AS0100-abcdefghijkl".utf8)
    static func hash(_ b: UInt8) -> Data { Data(repeating: b, count: 20) }

    static func request(_ h: Data = hash(0xAA), event: TrackerEvent = .started) -> AnnounceRequest {
        AnnounceRequest(infoHash: h, peerID: peerID, port: 6881, uploaded: 1, downloaded: 2,
                        left: 3, event: event, numWant: 50, key: 0xDEADBEEF)
    }
}

// MARK: - Fake UDP tracker (BEP 15 server side)

final class FakeUDPTracker: @unchecked Sendable {
    struct Announce {
        var connectionID: UInt64; var infoHash: Data; var peerID: Data
        var downloaded: UInt64; var left: UInt64; var uploaded: UInt64
        var event: UInt32; var key: UInt32; var numWant: Int32; var port: UInt16; var options: Data
    }
    let sock: UDPSocket
    let v6: Bool
    var connects = 0
    var announces: [Announce] = []
    var droppedAnnounces = 0
    var scrapes: [[Data]] = []
    var issued = Set<UInt64>()
    // behaviour
    var dead = false
    var dropNextAnnounces = 0
    var errorMessage: String?
    var peers: [PeerAddress] = []
    var interval: UInt32 = 1800
    var seeders: UInt32 = 11
    var leechers: UInt32 = 22

    init(v6: Bool = false) throws {
        self.v6 = v6
        sock = try UDPSocket(port: 0, v6: v6, loop: TrackerTestEnv.loop)
        sock.onDatagram = { [weak self] d, from in self?.handle(d, from) }
        let s = sock
        TrackerTestEnv.loop.sync { s.start() }   // sockets are loop-confined
    }

    var host: String { v6 ? "[::1]" : "127.0.0.1" }
    func url(_ path: String = "/announce") -> String { "udp://\(host):\(sock.port)\(path)" }

    func eventCounts(_ code: UInt32) -> Int { announces.filter { $0.event == code }.count }

    private func handle(_ d: Data, _ from: PeerAddress) {
        guard !dead, d.count >= 16 else { return }
        let action = d.be32(8), tid = d.be32(12)
        var out = Data()
        switch action {
        case 0:
            guard d.be64(0) == 0x41727101980 else { return }
            connects += 1
            let cid = Data.random(8).be64(0)
            issued.insert(cid)
            out.appendBE32(0); out.appendBE32(tid); out.appendBE64(cid)
        case 1:
            guard d.count >= 98 else { return }
            let a = Announce(connectionID: d.be64(0), infoHash: d.subdata(in: 16..<36), peerID: d.subdata(in: 36..<56),
                             downloaded: d.be64(56), left: d.be64(64), uploaded: d.be64(72), event: d.be32(80),
                             key: d.be32(88), numWant: Int32(bitPattern: d.be32(92)), port: d.be16(96),
                             options: d.subdata(in: 98..<d.count))
            if dropNextAnnounces > 0 { dropNextAnnounces -= 1; droppedAnnounces += 1; return }
            announces.append(a)
            if let e = errorMessage {
                out.appendBE32(3); out.appendBE32(tid); out.append(Data(e.utf8))
            } else {
                guard issued.contains(a.connectionID) else { return }   // unknown id: silently drop
                out.appendBE32(1); out.appendBE32(tid)
                out.appendBE32(interval); out.appendBE32(leechers); out.appendBE32(seeders)
                for p in peers where p.ip.isV6 == v6 { out.append(contentsOf: p.compact) }
            }
        case 2:
            var hashes: [Data] = []
            var off = 16
            while off + 20 <= d.count { hashes.append(d.subdata(in: off..<(off + 20))); off += 20 }
            scrapes.append(hashes)
            out.appendBE32(2); out.appendBE32(tid)
            for (i, _) in hashes.enumerated() {
                out.appendBE32(seeders + UInt32(i)); out.appendBE32(100); out.appendBE32(leechers)
            }
        default:
            return
        }
        sock.send(out, to: from)
    }
}

// MARK: - Fake HTTP tracker (TCPListener based)

final class FakeHTTPTracker: @unchecked Sendable {
    let listener: TCPListener
    var requests: [String] = []          // request targets ("/announce?…")
    var userAgents: [String] = []
    var headers: [[String: String]] = []  // lower-cased names
    var extraResponseHeaders = ""
    var respond: (String) -> (Int, Data) = { _ in (200, Data("d8:intervali1800e5:peers0:e".utf8)) }
    private var streams: [ObjectIdentifier: TCPStream] = [:]

    init() throws {
        listener = try TCPListener(port: 0, loop: TrackerTestEnv.loop)
        listener.onAccept = { [weak self] s in self?.accept(s) }
        let l = listener
        TrackerTestEnv.loop.sync { l.start() }   // sockets are loop-confined
    }

    var base: String { "http://127.0.0.1:\(listener.port)" }

    private func accept(_ s: TCPStream) {
        let id = ObjectIdentifier(s)
        streams[id] = s
        var buf = Data()
        s.onRead = { [weak self, weak s] chunk in
            guard let self, let s else { return }
            buf.append(chunk)
            guard let end = buf.range(of: Data("\r\n\r\n".utf8)) else { return }
            let head = String(decoding: buf[..<end.lowerBound], as: UTF8.self)
            let lines = head.components(separatedBy: "\r\n")
            let parts = lines.first?.split(separator: " ") ?? []
            let target = parts.count >= 2 ? String(parts[1]) : ""
            self.requests.append(target)
            var hdrs: [String: String] = [:]
            for l in lines.dropFirst() {
                guard let c = l.firstIndex(of: ":") else { continue }
                hdrs[l[..<c].lowercased()] = l[l.index(after: c)...].trimmingCharacters(in: .whitespaces)
            }
            self.headers.append(hdrs)
            if let ua = hdrs["user-agent"] { self.userAgents.append(ua) }
            let (code, body) = self.respond(target)
            var resp = Data("HTTP/1.1 \(code) X\r\nContent-Type: text/plain\r\n\(self.extraResponseHeaders)Content-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
            resp.append(body)
            s.write(resp)
            s.close()
            self.streams[id] = nil
        }
        s.onClose = { [weak self] _ in self?.streams[id] = nil }
        s.activate()
    }
}

final class PeerSink: @unchecked Sendable {
    var batches: [[PeerAddress]] = []
    var all: [PeerAddress] { batches.flatMap { $0 } }
}

// MARK: - Pure codec tests

@Suite struct TrackerHTTPCodecTests {
    @Test func percentEncodesBinaryInfoHash() {
        // Canonical example from the BitTorrent protocol documentation.
        let h = Data([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
                      0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a])
        #expect(HTTPTrackerCodec.percentEncode(h) == "%124Vx%9A%BC%DE%F1%23Eg%89%AB%CD%EF%124Vx%9A")
        // Unreserved characters stay; everything else (incl. space, +, /, ~ kept) is escaped.
        #expect(HTTPTrackerCodec.percentEncode(Data("aZ09-._~ +/%".utf8)) == "aZ09-._~%20%2B%2F%25")
        #expect(HTTPTrackerCodec.percentEncode(Data([0x00, 0xFF])) == "%00%FF")
    }

    @Test func announceURLContainsAllParameters() throws {
        var req = TrackerTestEnv.request()
        req.trackerID = "tid 1"
        let s = HTTPTrackerCodec.announceURLString("https://t.example.org/announce", req)
        #expect(s.hasPrefix("https://t.example.org/announce?info_hash=%AA%AA"))
        let q = Set(s.split(separator: "?", maxSplits: 1)[1].split(separator: "&").map(String.init))
        for p in ["peer_id=-AS0100-abcdefghijkl", "port=6881", "uploaded=1", "downloaded=2", "left=3",
                  "event=started", "key=DEADBEEF", "numwant=50", "compact=1", "no_peer_id=1",
                  "supportcrypto=1", "trackerid=tid%201"] {
            #expect(q.contains(p), "missing \(p) in \(s)")
        }
        #expect(HTTPTrackerCodec.announceURL("https://t.example.org/announce", req) != nil)
    }

    @Test func announceURLPreservesExistingQueryAndOmitsNoneEvent() {
        let req = TrackerTestEnv.request(event: .none)
        let s = HTTPTrackerCodec.announceURLString("http://t.example/announce.php?passkey=AbC#frag", req)
        #expect(s.hasPrefix("http://t.example/announce.php?passkey=AbC&info_hash="))
        #expect(!s.contains("event="))
        #expect(!s.contains("#"))
        let s2 = HTTPTrackerCodec.announceURLString("http://t.example/a?x=1&", req)
        #expect(s2.hasPrefix("http://t.example/a?x=1&info_hash="))
        // Unknown "left" (magnet without metadata) is not reported as 0 (= seed).
        var m = req; m.left = -1
        #expect(HTTPTrackerCodec.announceURLString("http://t/announce", m).contains("left=16384"))
    }

    @Test func scrapeURLDerivation() {
        let cases: [(String, String?)] = [
            ("http://example.com/announce", "http://example.com/scrape"),
            ("http://example.com/x/announce", "http://example.com/x/scrape"),
            ("http://example.com/announce.php", "http://example.com/scrape.php"),
            ("http://example.com/announce?x2%0644", "http://example.com/scrape?x2%0644"),
            ("http://example.com/announce?pk=/announce", "http://example.com/scrape?pk=/announce"),
            ("http://example.com/a", nil),
            ("http://example.com/announce?x=2/4", "http://example.com/scrape?x=2/4"),
            ("http://example.com/x%064announce", nil),
            ("http://example.com/announce/", nil),
            ("http://example.com", nil),
        ]
        for (a, s) in cases {
            #expect(HTTPTrackerCodec.scrapeURLString(fromAnnounce: a) == s, "\(a)")
        }
        let full = HTTPTrackerCodec.scrapeURLString("http://e.com/scrape?pk=1",
                                                    infoHashes: [TrackerTestEnv.hash(1), TrackerTestEnv.hash(2)])
        #expect(full.hasPrefix("http://e.com/scrape?pk=1&info_hash=%01%01"))
        #expect(full.components(separatedBy: "info_hash=").count == 3)
    }

    @Test func parsesCompactAndPeers6Response() throws {
        var body = Data("d8:intervali1800e12:min intervali900e8:completei5e10:incompletei7e10:tracker id2:T1".utf8)
        body += Data("15:warning message4:slow11:external ip4:".utf8) + Data([9, 8, 7, 6])
        body += Data("5:peers12:".utf8) + Data([1, 2, 3, 4, 0x1A, 0xE1, 5, 6, 7, 8, 0, 80])
        let v6 = PeerAddress("[2001:db8::1]:51413")!
        body += Data("6:peers618:".utf8) + Data(v6.compact) + Data("e".utf8)
        let r = try HTTPTrackerCodec.parseAnnounceResponse(body)
        #expect(r.interval == 1800)
        #expect(r.minInterval == 900)
        #expect(r.seeders == 5)
        #expect(r.leechers == 7)
        #expect(r.trackerID == "T1")
        #expect(r.warning == "slow")
        #expect(r.externalIP == IPAddress("9.8.7.6"))
        #expect(r.peers.map(\.description) == ["1.2.3.4:6881", "5.6.7.8:80", "[2001:db8::1]:51413"])
    }

    @Test func parsesDictionaryPeerList() throws {
        let parts: [String] = [
            "d8:intervali60e5:peersl",
            "d2:ip7:1.2.3.47:peer id20:xxxxxxxxxxxxxxxxxxxx4:porti6881ee",
            "d2:ip11:2001:db8::24:porti51413ee",
            "d2:ip11:example.com4:porti1ee",      // hostnames are skipped
            "d2:ip7:1.2.3.44:porti0ee",            // port 0 skipped
            "d2:ip7:1.2.3.44:porti6881ee",         // duplicate
            "i5e",                                 // junk entry
            "ee",
        ]
        let body = Data(parts.joined().utf8)
        let r = try HTTPTrackerCodec.parseAnnounceResponse(body)
        #expect(r.interval == 60)
        #expect(r.minInterval == nil)
        #expect(r.seeders == nil)
        #expect(r.peers.map { $0.description } == ["1.2.3.4:6881", "[2001:db8::2]:51413"])
    }

    @Test func failureReasonAndMalformedBodies() {
        #expect(throws: TrackerError.failure("unregistered torrent")) {
            try HTTPTrackerCodec.parseAnnounceResponse(Data("d14:failure reason20:unregistered torrente".utf8))
        }
        for junk in ["", "<html>nope</html>", "i42e", "d8:intervali", "le"] {
            #expect(throws: TrackerError.self) { try HTTPTrackerCodec.parseAnnounceResponse(Data(junk.utf8)) }
        }
        // Trailing garbage after a valid dict is tolerated; odd-length compact peers are cut.
        let r = try? HTTPTrackerCodec.parseAnnounceResponse(Data("d8:intervali30e5:peers7:\u{1}\u{2}\u{3}\u{4}\u{0}\u{50}Xe\r\n".utf8))
        #expect(r?.peers.map(\.description) == ["1.2.3.4:80"])
        // Missing interval falls back to the default.
        #expect((try? HTTPTrackerCodec.parseAnnounceResponse(Data("de".utf8)))?.interval == 1800)
    }

    @Test func gzipBodyWithoutContentEncodingIsInflated() throws {
        let plain = Data("d8:intervali900e5:peers6:".utf8) + Data([10, 0, 0, 1, 0x1A, 0xE1]) + Data("e".utf8)
        let deflated = try (plain as NSData).compressed(using: .zlib) as Data
        var gz = Data([0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 3]) + Data("name\0".utf8)
        gz += deflated + Data(count: 8)   // CRC / ISIZE are not verified
        #expect(HTTPTrackerCodec.gunzipIfNeeded(gz) == plain)
        let r = try HTTPTrackerCodec.parseAnnounceResponse(gz)
        #expect(r.interval == 900)
        #expect(r.peers.first?.description == "10.0.0.1:6881")
    }

    @Test func parsesScrapeResponse() throws {
        let h = TrackerTestEnv.hash(0x11)
        var body = Data("d5:filesd20:".utf8) + h + Data("d8:completei3e10:downloadedi50e10:incompletei4eeee".utf8)
        var r = try HTTPTrackerCodec.parseScrapeResponse(body)
        #expect(r[h]?.seeders == 3)
        #expect(r[h]?.completed == 50)
        #expect(r[h]?.leechers == 4)
        body = Data("d14:failure reason4:nopee".utf8)
        #expect(throws: TrackerError.failure("nope")) { r = try HTTPTrackerCodec.parseScrapeResponse(body) }
    }
}

@Suite struct TrackerUDPCodecTests {
    @Test func connectRequestLayout() {
        let d = UDPTrackerCodec.connectRequest(transactionID: 0x01020304)
        #expect(Array(d) == [0, 0, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0, 1, 2, 3, 4])
        var resp = Data(); resp.appendBE32(0); resp.appendBE32(0x01020304); resp.appendBE64(0x1122334455667788)
        #expect(UDPTrackerCodec.header(resp)! == (0, 0x01020304))
        #expect(UDPTrackerCodec.parseConnect(resp) == 0x1122334455667788)
        #expect(UDPTrackerCodec.parseConnect(resp.prefix(12)) == nil)
    }

    @Test func announceRequestLayout() {
        var req = TrackerTestEnv.request(event: .completed)
        req.uploaded = 0x0102; req.downloaded = 0x0304; req.left = 0x0506
        let d = UDPTrackerCodec.announceRequest(connectionID: 0xAABBCCDDEEFF0011, transactionID: 7, req, urlData: nil)
        #expect(d.count == 98)
        #expect(d.be64(0) == 0xAABBCCDDEEFF0011)
        #expect(d.be32(8) == 1)
        #expect(d.be32(12) == 7)
        #expect(d.subdata(in: 16..<36) == req.infoHash)
        #expect(d.subdata(in: 36..<56) == req.peerID)
        #expect(d.be64(56) == 0x0304)   // downloaded
        #expect(d.be64(64) == 0x0506)   // left
        #expect(d.be64(72) == 0x0102)   // uploaded
        #expect(d.be32(80) == 1)        // completed
        #expect(d.be32(84) == 0)        // IP
        #expect(d.be32(88) == 0xDEADBEEF)
        #expect(Int32(bitPattern: d.be32(92)) == 50)
        #expect(d.be16(96) == 6881)
        // Event codes and default num_want.
        #expect([TrackerEvent.none, .completed, .started, .stopped].map(\.udpCode) == [0, 1, 2, 3])
        req.numWant = 0
        req.event = .started
        let d2 = UDPTrackerCodec.announceRequest(connectionID: 1, transactionID: 2, req, urlData: "")
        #expect(d2.count == 98)
        #expect(Int32(bitPattern: d2.be32(92)) == -1)
        req.event = .stopped; req.numWant = 200
        #expect(UDPTrackerCodec.announceRequest(connectionID: 1, transactionID: 2, req, urlData: nil).be32(92) == 0)
    }

    @Test func bep41URLDataOptions() {
        let o = UDPTrackerCodec.urlDataOptions("/announce?passkey=xyz")
        #expect(Array(o) == [0x02, 21] + Array("/announce?passkey=xyz".utf8))
        let long = "/" + String(repeating: "a", count: 299)
        let o2 = UDPTrackerCodec.urlDataOptions(long)
        #expect(o2.count == 300 + 4)
        #expect(o2[0] == 0x02 && o2[1] == 255)
        #expect(o2[257] == 0x02 && o2[258] == 45)
        #expect(Data(o2[2..<257]) + Data(o2[259...]) == Data(long.utf8))
        #expect(UDPTrackerCodec.urlDataOptions("").isEmpty)
        let req = TrackerTestEnv.request()
        let d = UDPTrackerCodec.announceRequest(connectionID: 1, transactionID: 2, req, urlData: "/ann")
        #expect(Array(d[98...]) == [0x02, 4] + Array("/ann".utf8))
    }

    @Test func announceResponseV4AndV6() {
        var r = Data(); r.appendBE32(1); r.appendBE32(9); r.appendBE32(1800); r.appendBE32(3); r.appendBE32(4)
        r.append(contentsOf: [1, 2, 3, 4, 0x1A, 0xE1, 0, 0, 0, 0, 0, 1, 5, 6, 7, 8, 0, 0])  // 2nd unusable, 3rd port 0
        let a = UDPTrackerCodec.parseAnnounce(r, v6: false)!
        #expect(a.interval == 1800 && a.leechers == 3 && a.seeders == 4)
        #expect(a.peers.map(\.description) == ["1.2.3.4:6881"])

        var r6 = Data(); r6.appendBE32(1); r6.appendBE32(9); r6.appendBE32(60); r6.appendBE32(0); r6.appendBE32(1)
        let p6 = PeerAddress("[2001:db8::7]:6881")!
        r6.append(contentsOf: p6.compact)
        r6.append(contentsOf: [1, 2, 3])                                                     // trailing junk
        #expect(UDPTrackerCodec.parseAnnounce(r6, v6: true)!.peers == [p6])
        #expect(UDPTrackerCodec.parseAnnounce(r6.prefix(19), v6: true) == nil)
        #expect(UDPTrackerCodec.parseAnnounce(Data(), v6: false) == nil)
    }

    @Test func scrapeAndErrorPackets() {
        let hashes = [TrackerTestEnv.hash(1), TrackerTestEnv.hash(2)]
        let req = UDPTrackerCodec.scrapeRequest(connectionID: 5, transactionID: 6, infoHashes: hashes)
        #expect(req.count == 16 + 40)
        #expect(req.be32(8) == 2)
        #expect(req.subdata(in: 36..<56) == hashes[1])
        var resp = Data(); resp.appendBE32(2); resp.appendBE32(6)
        for v: UInt32 in [1, 2, 3, 4, 5, 6] { resp.appendBE32(v) }
        let rows = UDPTrackerCodec.parseScrape(resp)!
        #expect(rows.count == 2)
        #expect(rows[1].seeders == 4 && rows[1].completed == 5 && rows[1].leechers == 6)
        var err = Data(); err.appendBE32(3); err.appendBE32(6); err.append(Data("bad info_hash\0".utf8))
        #expect(UDPTrackerCodec.parseError(err) == "bad info_hash")
        #expect(UDPTrackerCodec.parseError(resp) == nil)
        #expect(UDPTrackerCodec.parseScrape(err) == nil)
    }
}

@Suite struct TrackerMiscTests {
    @Test func backoffSchedule() {
        let s = (1...9).map { TrackerBackoff.delay(failures: $0) }
        #expect(s == [30, 60, 120, 240, 480, 960, 1800, 1800, 1800])
        #expect(TrackerBackoff.delay(failures: 0) == 0)
        #expect(TrackerBackoff.delay(failures: 1000) == 1800)
    }

    @Test func urlParsing() {
        let a = TrackerURLParts.parse("udp://tracker.opentrackr.org:1337/announce")!
        #expect(a == TrackerURLParts(scheme: "udp", host: "tracker.opentrackr.org", port: 1337, pathAndQuery: "/announce"))
        let b = TrackerURLParts.parse(" UDP://[2001:db8::1]:6969?x=1#f ")!
        #expect(b == TrackerURLParts(scheme: "udp", host: "2001:db8::1", port: 6969, pathAndQuery: "?x=1"))
        let c = TrackerURLParts.parse("https://user:pw@t.example/announce")!
        #expect(c.host == "t.example" && c.port == nil && c.pathAndQuery == "/announce")
        #expect(TrackerURLParts.parse("udp://host:0/") == nil)
        #expect(TrackerURLParts.parse("udp://host:99999/") == nil)
        #expect(TrackerURLParts.parse("not a url") == nil)
        #expect(TrackerURLParts.parse("udp://:80") == nil)
        #expect(TrackerClient.isSupported("udp://a:1/announce"))
        #expect(TrackerClient.isSupported("HTTPS://a/announce"))
        #expect(!TrackerClient.isSupported("wss://tracker.webtorrent.dev"))
        #expect(TrackerURLParts.dedupeKey("UDP://Tracker.Example:80/announce") ==
                TrackerURLParts.dedupeKey(" udp://tracker.example:80/announce"))
    }
}

// MARK: - TrackerClient against local fake trackers

@Suite struct TrackerClientTests {
    let loop = TrackerTestEnv.loop

    @Test func udpAnnounceConnectionCacheAndURLData() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        loop.sync { fake.peers = [PeerAddress("1.1.1.1:1000")!, PeerAddress("2.2.2.2:2000")!] }
        let url = fake.url("/announce?passkey=k1")
        let t0 = Date()
        let r1 = try await TrackerTestEnv.announce(client, url, TrackerTestEnv.request()).get()
        let ms = Int(Date().timeIntervalSince(t0) * 1000)
        #expect(r1.interval == 1800 && r1.seeders == 11 && r1.leechers == 22)
        #expect(Set(r1.peers.map(\.description)) == ["1.1.1.1:1000", "2.2.2.2:2000"])
        _ = try await TrackerTestEnv.announce(client, url, TrackerTestEnv.request(event: .none)).get()
        let (connects, anns) = loop.sync { (fake.connects, fake.announces) }
        #expect(connects == 1, "connection id must be cached")
        #expect(anns.count == 2)
        #expect(anns[0].event == 2 && anns[1].event == 0)
        #expect(anns[0].port == 6881 && anns[0].key == 0xDEADBEEF && anns[0].numWant == 50)
        #expect(anns[0].left == 3 && anns[0].downloaded == 2 && anns[0].uploaded == 1)
        #expect(anns[0].options == Data([0x02, 20]) + Data("/announce?passkey=k1".utf8))
        print("[tracker] local UDP announce round-trip: \(ms) ms")
    }

    @Test func udpResolvesHostnameViaResolver() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        let r = await TrackerTestEnv.announce(client, "udp://localhost:\(fake.sock.port)", TrackerTestEnv.request())
        #expect((try? r.get()) != nil)
        #expect(loop.sync { fake.announces.first?.options.isEmpty } == true)  // no path -> no BEP 41 option
    }

    @Test func udpIPv6TrackerUses18BytePeers() async throws {
        guard let fake = try? loop.sync({ try FakeUDPTracker(v6: true) }) else { return }
        let (client, _) = TrackerTestEnv.makeClient()
        let p6 = PeerAddress("[2001:db8::42]:6881")!
        loop.sync { fake.peers = [p6] }
        let r = await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request())
        switch r {
        case .success(let resp):
            #expect(resp.peers == [p6])
            print("[tracker] IPv6 UDP tracker on [::1] answered with 18-byte peers: \(resp.peers)")
        case .failure(let e):
            // Hosts without IPv6 loopback can't run this test.
            #expect(loop.sync { fake.connects } == 0, "unexpected failure \(e)")
        }
    }

    @Test func udpRetransmitsAfterLoss() async throws {
        let (client, _) = TrackerTestEnv.makeClient(retransmit: [0.3, 0.6])
        let fake = try loop.sync { try FakeUDPTracker() }
        loop.sync { fake.dropNextAnnounces = 1 }
        let t0 = Date()
        let r = await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request())
        let dt = Date().timeIntervalSince(t0)
        #expect((try? r.get()) != nil)
        #expect(loop.sync { (fake.droppedAnnounces, fake.announces.count) } == (1, 1))
        #expect(dt >= 0.25 && dt < 2)
    }

    @Test func udpDeadTrackerTimesOut() async throws {
        let (client, _) = TrackerTestEnv.makeClient(retransmit: [0.2, 0.3])
        let fake = try loop.sync { try FakeUDPTracker() }
        loop.sync { fake.dead = true }
        let t0 = Date()
        let r = await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request())
        let dt = Date().timeIntervalSince(t0)
        #expect(throws: TrackerError.timedOut) { try r.get() }
        #expect(dt >= 0.45 && dt < 2, "took \(dt)")
        #expect(loop.sync { client.udp.pendingCount } == 0)
    }

    @Test func udpErrorAction() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        loop.sync { fake.errorMessage = "torrent not registered" }
        let r = await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request())
        #expect(throws: TrackerError.failure("torrent not registered")) { try r.get() }
    }

    @Test func udpExpiredConnectionIDIsRenewed() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        _ = try await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request()).get()
        // Tracker restarts and forgets all ids: it replies with an error to the stale id.
        loop.sync { fake.issued.removeAll(); fake.errorMessage = "Connection ID missmatch." }
        let r = await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request(event: .none))
        #expect(throws: TrackerError.self) { try r.get() }
        #expect(loop.sync { fake.connects } == 2, "stale id should trigger exactly one reconnect")
        loop.sync { fake.errorMessage = nil }
        _ = try await TrackerTestEnv.announce(client, fake.url(), TrackerTestEnv.request(event: .none)).get()
    }

    @Test func udpScrape() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        let hs = [TrackerTestEnv.hash(1), TrackerTestEnv.hash(2)]
        let r = try await TrackerTestEnv.scrape(client, fake.url(), hs).get()
        #expect(r[hs[0]]?.seeders == 11 && r[hs[1]]?.seeders == 12)
        #expect(r[hs[1]]?.completed == 100 && r[hs[1]]?.leechers == 22)
    }

    @Test func invalidInputsFailAsynchronously() async {
        let (client, _) = TrackerTestEnv.makeClient()
        var bad = TrackerTestEnv.request(); bad.infoHash = Data(count: 32)
        let r1 = await TrackerTestEnv.announce(client, "udp://127.0.0.1:1/a", bad)
        #expect(throws: TrackerError.self) { try r1.get() }
        let r2 = await TrackerTestEnv.announce(client, "wss://t.example/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.unsupportedScheme("wss")) { try r2.get() }
        let r3 = await TrackerTestEnv.announce(client, "udp://127.0.0.1/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.self) { try r3.get() }
        let r4 = await TrackerTestEnv.announce(client, "garbage", TrackerTestEnv.request())
        #expect(throws: TrackerError.self) { try r4.get() }
    }

    @Test func httpAnnounceAndScrape() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeHTTPTracker() }
        let h = Data([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45,
                      0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a])
        loop.sync {
            fake.respond = { target in
                if target.hasPrefix("/scrape") {
                    return (200, Data("d5:filesd20:".utf8) + h + Data("d8:completei9e10:downloadedi8e10:incompletei7eeee".utf8))
                }
                return (200, Data("d8:intervali900e8:completei2e10:incompletei3e5:peers6:".utf8)
                        + Data([10, 1, 2, 3, 0x1A, 0xE1]) + Data("e".utf8))
            }
        }
        let t0 = Date()
        let r = try await TrackerTestEnv.announce(client, fake.base + "/announce?pk=s3cret", TrackerTestEnv.request(h)).get()
        let ms = Int(Date().timeIntervalSince(t0) * 1000)
        #expect(r.interval == 900 && r.seeders == 2 && r.leechers == 3)
        #expect(r.peers.map(\.description) == ["10.1.2.3:6881"])
        let (target, ua) = loop.sync { (fake.requests.first ?? "", fake.userAgents.first ?? "") }
        #expect(target.hasPrefix("/announce?pk=s3cret&info_hash=%124Vx%9A%BC%DE%F1%23Eg%89%AB%CD%EF%124Vx%9A&"))
        #expect(target.contains("&compact=1") && target.contains("&event=started") && target.contains("&supportcrypto=1"))
        #expect(ua == ClientIdentity.userAgent)
        let s = try await TrackerTestEnv.scrape(client, fake.base + "/announce?pk=s3cret", [h]).get()
        #expect(s[h]?.seeders == 9 && s[h]?.completed == 8 && s[h]?.leechers == 7)
        #expect(loop.sync { fake.requests.last?.hasPrefix("/scrape?pk=s3cret&info_hash=%124Vx") } == true)
        print("[tracker] local HTTP announce round-trip: \(ms) ms")
    }

    @Test func httpGzipContentEncodingEndToEnd() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeHTTPTracker() }
        let plain = Data("d8:intervali777e5:peers6:".utf8) + Data([10, 9, 8, 7, 0x1A, 0xE1]) + Data("e".utf8)
        let deflated = try (plain as NSData).compressed(using: .zlib) as Data
        let gz = Data([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3]) + deflated + Data(count: 8)
        loop.sync {
            fake.extraResponseHeaders = "Content-Encoding: gzip\r\n"
            fake.respond = { _ in (200, gz) }
        }
        let r = await TrackerTestEnv.announce(client, fake.base + "/announce", TrackerTestEnv.request())
        // Either URLSession inflates it (Content-Encoding) or our fallback does.
        #expect((try? r.get())?.interval == 777)
        #expect((try? r.get())?.peers.first?.description == "10.9.8.7:6881")
        #expect(loop.sync { fake.headers.first?["accept-encoding"]?.contains("gzip") } == true)
    }

    @Test func closedClientRefusesRequests() async {
        let (client, _) = TrackerTestEnv.makeClient()
        loop.sync { client.close() }
        let r = await TrackerTestEnv.announce(client, "http://127.0.0.1:1/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.network("tracker client closed")) { try r.get() }
    }

    @Test func httpFailureReasonWinsOverStatus() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeHTTPTracker() }
        loop.sync { fake.respond = { _ in (400, Data("d14:failure reason7:bad keye".utf8)) } }
        let r = await TrackerTestEnv.announce(client, fake.base + "/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.failure("bad key")) { try r.get() }
        loop.sync { fake.respond = { _ in (503, Data("<html>busy</html>".utf8)) } }
        let r2 = await TrackerTestEnv.announce(client, fake.base + "/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.httpStatus(503)) { try r2.get() }
        loop.sync { fake.respond = { _ in (200, Data("<html>login</html>".utf8)) } }
        let r3 = await TrackerTestEnv.announce(client, fake.base + "/announce", TrackerTestEnv.request())
        #expect(throws: TrackerError.malformed("not bencoded")) { try r3.get() }
    }
}

// MARK: - TrackerManager

@Suite struct TrackerManagerTests {
    let loop = TrackerTestEnv.loop

    func makeManager(_ client: TrackerClient, tiers: [[String]], hashes: [Data], all: Bool,
                     sink: PeerSink, left: Int64 = 1000) -> TrackerManager {
        loop.sync {
            TrackerManager(loop: loop, client: client, tiers: tiers, infoHashes: hashes,
                           peerID: TrackerTestEnv.peerID, announceToAll: all, numWant: 77,
                           port: { 51413 }, stats: { (0, 0, left) },
                           onPeers: { sink.batches.append($0) })
        }
    }

    @Test func announceToAllHitsEveryTierDedupesAndSkipsUnsupported() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let (a, b) = try loop.sync { (try FakeUDPTracker(), try FakeUDPTracker()) }
        let shared = PeerAddress("9.9.9.9:9999")!
        loop.sync {
            a.peers = [shared, PeerAddress("1.0.0.1:1")!]
            b.peers = [shared, PeerAddress("1.0.0.2:2")!]
            b.seeders = 500; b.leechers = 600
        }
        let h1 = TrackerTestEnv.hash(1), h2 = TrackerTestEnv.hash(2)   // hybrid: v1 + truncated v2
        let sink = PeerSink()
        let mgr = makeManager(client, tiers: [[a.url()], [b.url(), " " + a.url() + " "], ["wss://tracker.example/announce"]],
                              hashes: [h1, h2], all: true, sink: sink)
        loop.sync { mgr.start() }
        let ok = await TrackerTestEnv.waitUntil { mgr.statuses.allSatisfy { !$0.isUpdating } && a.announces.count == 2 && b.announces.count == 2 }
        #expect(ok)
        loop.sync {
            #expect(Set(a.announces.map(\.infoHash)) == [h1, h2])
            #expect(Set(b.announces.map(\.infoHash)) == [h1, h2])
            #expect(a.announces.allSatisfy { $0.event == 2 && $0.numWant == 77 && $0.port == 51413 })
            let st = mgr.statuses
            #expect(st.count == 3)
            #expect(st.map(\.tier) == [0, 1, 2])
            #expect(st[2].lastError == "unsupported tracker scheme")
            #expect(st[0].lastError == nil && st[0].lastPeerCount == 2 && st[0].seeders == 11)
            #expect(st[1].seeders == 500 && st[1].leechers == 600)
            #expect(st[0].nextAnnounceIn > 1700 && st[0].nextAnnounceIn <= 1800)
            #expect(mgr.bestSeeders == 500 && mgr.bestLeechers == 600)
            let all = sink.all
            #expect(all.count == Set(all).count, "peers must be deduplicated")
            #expect(Set(all) == [shared, PeerAddress("1.0.0.1:1")!, PeerAddress("1.0.0.2:2")!])
            mgr.stop()
        }
    }

    @Test func bep12TriesTiersInOrderAndPromotes() async throws {
        let (client, _) = TrackerTestEnv.makeClient(retransmit: [0.15, 0.2])
        let (dead, g1, g2) = try loop.sync { (try FakeUDPTracker(), try FakeUDPTracker(), try FakeUDPTracker()) }
        loop.sync { dead.dead = true; g1.peers = [PeerAddress("3.3.3.3:3")!]; g2.peers = [PeerAddress("3.3.3.3:3")!] }
        let sink = PeerSink()
        let mgr = makeManager(client, tiers: [[dead.url()], [g1.url(), g2.url()]], hashes: [TrackerTestEnv.hash(7)],
                              all: false, sink: sink)
        let t0 = Date()
        loop.sync { mgr.start() }
        let ok = await TrackerTestEnv.waitUntil { g1.announces.count + g2.announces.count >= 1 && !sink.batches.isEmpty }
        #expect(ok)
        let dt = Date().timeIntervalSince(t0)
        try? await Task.sleep(for: .milliseconds(300))
        loop.sync {
            #expect(g1.announces.count + g2.announces.count == 1, "only one tracker of the tier is used")
            let winner = g1.announces.isEmpty ? g2.url() : g1.url()
            #expect(mgr.tierOrder[1].first == winner, "successful tracker is promoted to the front")
            let st = mgr.statuses
            #expect(st.first { $0.url == dead.url() }?.lastError == "timed out")
            #expect(st.first { $0.url == winner }?.lastError == nil)
            #expect(st.first { $0.url == winner }.map { $0.nextAnnounceIn > 1700 } == true)
            #expect(sink.all == [PeerAddress("3.3.3.3:3")!])
            mgr.stop()
        }
        #expect(dt >= 0.3, "dead tier-0 tracker must be tried first (\(dt))")
    }

    @Test func completedOnceAndStoppedOnStop() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        let sink = PeerSink()
        let mgr = makeManager(client, tiers: [[fake.url()]], hashes: [TrackerTestEnv.hash(3)], all: true, sink: sink)
        loop.sync { mgr.start() }
        #expect(await TrackerTestEnv.waitUntil { fake.eventCounts(2) == 1 && !mgr.statuses[0].isUpdating })
        loop.sync { mgr.completed(); mgr.completed() }
        #expect(await TrackerTestEnv.waitUntil { fake.eventCounts(1) == 1 && !mgr.statuses[0].isUpdating })
        loop.sync { mgr.completed() }
        try? await Task.sleep(for: .milliseconds(200))
        #expect(loop.sync { fake.eventCounts(1) } == 1, "completed is sent once")
        loop.sync { mgr.stop() }
        #expect(await TrackerTestEnv.waitUntil { fake.eventCounts(3) == 1 })
        loop.sync {
            #expect(fake.announces.last?.numWant == 0)
            #expect(mgr.statuses[0].nextAnnounceIn == 0)
            mgr.reannounceNow()   // no-op once stopped
        }
        try? await Task.sleep(for: .milliseconds(150))
        #expect(loop.sync { fake.announces.count } == 3)
    }

    @Test func seedingAtStartNeverSendsCompleted() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        let mgr = makeManager(client, tiers: [[fake.url()]], hashes: [TrackerTestEnv.hash(4)], all: true,
                              sink: PeerSink(), left: 0)
        loop.sync { mgr.start() }
        #expect(await TrackerTestEnv.waitUntil { fake.eventCounts(2) == 1 && !mgr.statuses[0].isUpdating })
        loop.sync { mgr.completed() }
        try? await Task.sleep(for: .milliseconds(200))
        #expect(loop.sync { fake.eventCounts(1) } == 0)
        loop.sync { mgr.stop() }
    }

    @Test func reannounceRespectsMinIntervalAndEchoesTrackerID() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let (strict, lax) = try loop.sync { (try FakeHTTPTracker(), try FakeHTTPTracker()) }
        loop.sync {
            strict.respond = { _ in (200, Data("d8:intervali1800e12:min intervali900e5:peers0:e".utf8)) }
            lax.respond = { _ in (200, Data("d8:intervali1800e12:min intervali0e10:tracker id3:xyz5:peers0:e".utf8)) }
        }
        let m1 = makeManager(client, tiers: [[strict.base + "/announce"]], hashes: [TrackerTestEnv.hash(5)],
                             all: true, sink: PeerSink())
        let m2 = makeManager(client, tiers: [[lax.base + "/announce"]], hashes: [TrackerTestEnv.hash(5)],
                             all: true, sink: PeerSink())
        loop.sync { m2.minIntervalFloor = 0; m1.start(); m2.start() }
        #expect(await TrackerTestEnv.waitUntil {
            strict.requests.count == 1 && lax.requests.count == 1 && !m1.statuses[0].isUpdating && !m2.statuses[0].isUpdating
        })
        loop.sync { m1.reannounceNow(); m2.reannounceNow() }
        #expect(await TrackerTestEnv.waitUntil { lax.requests.count == 2 })
        try? await Task.sleep(for: .milliseconds(200))
        loop.sync {
            #expect(strict.requests.count == 1, "min interval must be respected")
            let next = m1.statuses[0].nextAnnounceIn
            #expect(next > 880 && next <= 900, "rescheduled at min interval, got \(next)")
            let second = lax.requests[1]
            #expect(second.contains("trackerid=xyz"))
            #expect(!second.contains("event="))
            #expect(lax.requests[0].contains("event=started"))
            m1.stop(); m2.stop()
        }
        #expect(await TrackerTestEnv.waitUntil { strict.requests.count == 2 && lax.requests.count == 3 })
        #expect(loop.sync { strict.requests[1].contains("event=stopped") && lax.requests[2].contains("trackerid=xyz") })
    }

    @Test func failuresBackOff() async throws {
        let (client, _) = TrackerTestEnv.makeClient()
        let fake = try loop.sync { try FakeUDPTracker() }
        loop.sync { fake.errorMessage = "go away" }
        let mgr = makeManager(client, tiers: [[fake.url()]], hashes: [TrackerTestEnv.hash(6)], all: true, sink: PeerSink())
        loop.sync { mgr.start() }
        #expect(await TrackerTestEnv.waitUntil { mgr.statuses[0].lastError != nil && !mgr.statuses[0].isUpdating })
        loop.sync {
            let st = mgr.statuses[0]
            #expect(st.lastError == "tracker: go away")
            #expect(st.nextAnnounceIn > 28 && st.nextAnnounceIn <= 30)
            // reannounceNow after a failure waits for the failure gap (30 s) too.
            mgr.reannounceNow()
        }
        try? await Task.sleep(for: .milliseconds(150))
        #expect(loop.sync { fake.announces.count } == 1)
        loop.sync { mgr.stop() }
    }

    @Test func bep12AllFailingBacksOffRound() async throws {
        let (client, _) = TrackerTestEnv.makeClient(retransmit: [0.1, 0.1])
        let (d1, d2) = try loop.sync { (try FakeUDPTracker(), try FakeUDPTracker()) }
        loop.sync { d1.dead = true; d2.errorMessage = "nope" }
        let mgr = makeManager(client, tiers: [[d1.url()], [d2.url(), "wss://x.example/a"]], hashes: [TrackerTestEnv.hash(8)],
                              all: false, sink: PeerSink())
        loop.sync { mgr.start() }
        #expect(await TrackerTestEnv.waitUntil { d2.announces.count == 1 && mgr.statuses.allSatisfy { !$0.isUpdating } })
        try? await Task.sleep(for: .milliseconds(100))
        loop.sync {
            let st = mgr.statuses
            #expect(st.first { $0.url == d1.url() }?.lastError == "timed out")
            #expect(st.first { $0.url == d2.url() }?.lastError == "tracker: nope")
            #expect(st.filter { $0.url != "wss://x.example/a" }.allSatisfy { $0.nextAnnounceIn > 28 && $0.nextAnnounceIn <= 30 })
            mgr.stop()
        }
    }
}

// MARK: - Live (network) test — run with ASTOR_LIVE=1

@Suite(.enabled(if: ProcessInfo.processInfo.environment["ASTOR_LIVE"] == "1"))
struct TrackerLiveTests {
    /// Finds the newest Ubuntu release that publishes a desktop .torrent.
    static func fetchUbuntuTorrent() async throws -> (String, Data) {
        let root = URL(string: "https://releases.ubuntu.com/")!
        let (idx, _) = try await URLSession.shared.data(from: root)
        let html = String(decoding: idx, as: UTF8.self)
        let re = try Regex(#"href="(\d{2}\.\d{2}(?:\.\d+)?)/""#)
        var versions = Set<String>()
        for m in html.matches(of: re) { if let v = m.output[1].substring { versions.insert(String(v)) } }
        let sorted = versions.sorted { a, b in
            a.split(separator: ".").map { Int($0) ?? 0 }.lexicographicallyPrecedes(b.split(separator: ".").map { Int($0) ?? 0 })
        }
        for v in sorted.reversed() {
            let dir = root.appendingPathComponent(v + "/")
            guard let (listing, _) = try? await URLSession.shared.data(from: dir) else { continue }
            let page = String(decoding: listing, as: UTF8.self)
            let fre = try Regex(#"href="(ubuntu-[0-9.]+-desktop-amd64\.iso\.torrent)""#)
            if let m = page.firstMatch(of: fre), let name = m.output[1].substring {
                let (t, _) = try await URLSession.shared.data(from: dir.appendingPathComponent(String(name)))
                return (String(name), t)
            }
        }
        throw TrackerError.malformed("no Ubuntu desktop torrent found")
    }

    @Test(.timeLimit(.minutes(2))) func announceToRealTrackers() async throws {
        let (name, data) = try await Self.fetchUbuntuTorrent()
        let meta = try Metainfo(torrentFile: data)
        let hash = meta.infoHashes.primary
        print("[live] \(name): \(meta.infoHashes) size=\(meta.totalLength) tiers=\(meta.announceTiers)")
        let loop = TrackerTestEnv.loop
        let (client, resolver) = loop.sync {
            let r = HostResolver(loop: loop)
            return (TrackerClient(loop: loop, resolver: r), r)
        }
        _ = resolver
        let peerID = ClientIdentity.makePeerID()
        let urls = meta.announceTiers.flatMap { $0 } + ["udp://tracker.opentrackr.org:1337/announce",
                                                         "udp://open.demonii.com:1337/announce"]
        struct Row: Sendable { let url: String; let ms: Int; let result: String; let peers: [PeerAddress] }
        let rows: [Row] = await withTaskGroup(of: Row.self) { group in
            for url in urls {
                group.addTask {
                    let req = AnnounceRequest(infoHash: hash, peerID: peerID, port: 6881, uploaded: 0, downloaded: 0,
                                              left: meta.totalLength, event: .started, numWant: 200, key: 0x5A5A1234)
                    let t0 = Date()
                    let r: Result<AnnounceResponse, any Error> = await withCheckedContinuation { cont in
                        loop.execute { client.announce(url: url, req) { cont.resume(returning: $0) } }
                    }
                    let ms = Int(Date().timeIntervalSince(t0) * 1000)
                    switch r {
                    case .success(let a):
                        let v6 = a.peers.filter { $0.ip.isV6 }.count
                        return Row(url: url, ms: ms, result: "OK seeders=\(a.seeders.map(String.init) ?? "?") leechers=\(a.leechers.map(String.init) ?? "?") peers=\(a.peers.count) (v6 \(v6)) interval=\(a.interval)s min=\(a.minInterval.map(String.init) ?? "-")\(a.warning.map { " warning=\($0)" } ?? "")", peers: a.peers)
                    case .failure(let e):
                        return Row(url: url, ms: ms, result: "FAIL \(e)", peers: [])
                    }
                }
            }
            var out: [Row] = []
            for await r in group { out.append(r) }
            return out
        }
        for r in rows.sorted(by: { $0.url < $1.url }) { print("[live] \(r.url) — \(r.ms) ms — \(r.result)") }
        let union = Set(rows.flatMap(\.peers))
        let (sent, recv) = loop.sync { (client.udp.packetsSent, client.udp.packetsReceived) }
        print("[live] unique peers across trackers: \(union.count); UDP datagrams sent=\(sent) received=\(recv) (sent > received means a retransmit happened)")

        // UDP scrape against opentrackr for completeness.
        let s: Result<[Data: (seeders: Int, completed: Int, leechers: Int)], any Error> = await withCheckedContinuation { cont in
            loop.execute { client.scrape(url: "udp://tracker.opentrackr.org:1337/announce", infoHashes: [hash]) { cont.resume(returning: $0) } }
        }
        switch s {
        case .success(let m): print("[live] opentrackr scrape: \(m[hash].map { "seeders=\($0.seeders) completed=\($0.completed) leechers=\($0.leechers)" } ?? "missing")")
        case .failure(let e): print("[live] opentrackr scrape failed: \(e)")
        }
        // Be polite: tell the trackers we're gone.
        for url in urls {
            let req = AnnounceRequest(infoHash: hash, peerID: peerID, port: 6881, left: meta.totalLength,
                                      event: .stopped, numWant: 0, key: 0x5A5A1234)
            loop.execute { client.announce(url: url, req) { _ in } }
        }
        try? await Task.sleep(for: .milliseconds(500))
        #expect(rows.contains { $0.result.hasPrefix("OK") }, "at least one tracker must answer")
        #expect(!union.isEmpty)
    }

    @Test(.timeLimit(.minutes(2))) func managerAnnounceToAllLive() async throws {
        let (_, data) = try await Self.fetchUbuntuTorrent()
        let meta = try Metainfo(torrentFile: data)
        let loop = TrackerTestEnv.loop
        let sink = PeerSink()
        let tiers = meta.announceTiers + [["udp://tracker.opentrackr.org:1337/announce"], ["udp://open.demonii.com:1337/announce"]]
        let mgr = loop.sync {
            let client = TrackerClient(loop: loop, resolver: HostResolver(loop: loop))
            return TrackerManager(loop: loop, client: client, tiers: tiers, infoHashes: meta.infoHashes.all20,
                                  peerID: ClientIdentity.makePeerID(), announceToAll: true, numWant: 200,
                                  port: { 6881 }, stats: { (0, 0, meta.totalLength) },
                                  onPeers: { sink.batches.append($0) })
        }
        let t0 = Date()
        loop.sync { mgr.start() }
        var firstPeerMs: Int?
        let deadline = Date().addingTimeInterval(25)
        while Date() < deadline {
            let (n, busy) = loop.sync { (sink.all.count, mgr.statuses.contains { $0.isUpdating }) }
            if n > 0 && firstPeerMs == nil { firstPeerMs = Int(Date().timeIntervalSince(t0) * 1000) }
            if !busy { break }
            try? await Task.sleep(for: .milliseconds(50))
        }
        let total = Int(Date().timeIntervalSince(t0) * 1000)
        loop.sync {
            for s in mgr.statuses {
                print("[live-mgr] tier \(s.tier) \(s.url): err=\(s.lastError ?? "-") S=\(s.seeders.map(String.init) ?? "?") L=\(s.leechers.map(String.init) ?? "?") peers=\(s.lastPeerCount) next=\(Int(s.nextAnnounceIn))s")
            }
            print("[live-mgr] delivered \(sink.all.count) unique peers in \(sink.batches.count) batches; first peers after \(firstPeerMs.map { "\($0) ms" } ?? "never"); all trackers done after \(total) ms; best S/L = \(mgr.bestSeeders.map(String.init) ?? "?")/\(mgr.bestLeechers.map(String.init) ?? "?")")
            #expect(sink.all.count == Set(sink.all).count)
            mgr.stop()
        }
        try? await Task.sleep(for: .milliseconds(500))
        #expect(loop.sync { !sink.all.isEmpty })
    }
}
