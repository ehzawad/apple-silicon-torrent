import Testing
import Foundation
@testable import TorrentCore

@Suite struct BencodeTests {
    @Test func roundTrip() throws {
        let v: BValue = .dict(["a": .int(-42), "b": .string("spam"), "c": .list([.int(1), .string("x")])])
        let enc = v.encoded
        #expect(String(decoding: enc, as: UTF8.self) == "d1:ai-42e1:b4:spam1:cli1e1:xee")
        #expect(try BDecoder.decode(enc) == v)
    }

    @Test func rejectsGarbage() {
        #expect(throws: BencodeError.self) { try BDecoder.decode(Data("i12".utf8)) }
        #expect(throws: BencodeError.self) { try BDecoder.decode(Data("5:abc".utf8)) }
        #expect(throws: BencodeError.self) { try BDecoder.decode(Data("i1ei2e".utf8)) }
    }

    @Test func capturesInfoSpan() throws {
        let doc = Data("d8:announce3:url4:infod4:name1:xee".utf8)
        let (_, raw) = try BDecoder.decode(doc, capturing: "info")
        #expect(raw.map { String(decoding: $0, as: UTF8.self) } == "d4:name1:xe")
    }

    @Test func prefixDecode() throws {
        let d = Data("d8:msg_typei1e5:piecei0eeRAWDATA".utf8)
        let (v, n) = try BDecoder.decodePrefix(d)
        #expect(v["piece"]?.int == 0)
        #expect(String(decoding: d[n...], as: UTF8.self) == "RAWDATA")
    }
}

@Suite struct AddressTests {
    @Test func compactV4() {
        let p = PeerAddress(ip: IPAddress("1.2.3.4")!, port: 6881)
        #expect(p.compact == [1, 2, 3, 4, 0x1A, 0xE1])
        #expect(PeerAddress(compact: p.compact) == p)
        #expect(p.description == "1.2.3.4:6881")
    }

    @Test func compactV6AndMapped() {
        let p = PeerAddress("[2001:db8::1]:51413")!
        #expect(p.compact.count == 18)
        #expect(PeerAddress(compact: p.compact) == p)
        #expect(IPAddress("::ffff:10.0.0.1") == IPAddress("10.0.0.1"))
        #expect(IPAddress("192.168.1.2")!.isPrivate)
        #expect(!IPAddress("8.8.8.8")!.isPrivate)
    }
}

@Suite struct MerkleTests {
    @Test func smallFileRootMatchesManual() {
        let data = Data(repeating: 0xAB, count: 16384 * 3 + 100)
        let root = data.withUnsafeBytes { Merkle.smallFileRoot($0) }
        let l = (0..<4).map { i -> Data in
            let s = i * 16384
            return Hash.sha256(data[s..<min(s + 16384, data.count)])
        }
        let manual = Hash.sha256Pair(Hash.sha256Pair(l[0], l[1]), Hash.sha256Pair(l[2], l[3]))
        #expect(root == manual)
    }

    @Test func pieceLayerRootUsesPadSubtrees() {
        // 3 pieces of 32 KiB (2 leaves each) -> layer padded to 4 with pad(height 1)
        let pieces = (0..<3).map { Hash.sha256(Data([UInt8($0)])) }
        let pad1 = Hash.sha256Pair(Merkle.zeroLeaf, Merkle.zeroLeaf)
        let expected = Hash.sha256Pair(Hash.sha256Pair(pieces[0], pieces[1]), Hash.sha256Pair(pieces[2], pad1))
        #expect(Merkle.rootFromPieceLayer(pieces, pieceLength: 32768) == expected)
    }
}

@Suite struct MagnetTests {
    @Test func hexAndBase32AndV2() {
        let m = MagnetLink("magnet:?xt=urn:btih:c12fe1c06bba254a9dc9f519b335aa7c1367a88a&dn=Test+Name&tr=udp%3A%2F%2Ftracker.example%3A1337&x.pe=1.2.3.4:5")!
        #expect(m.infoHashes.v1?.hex == "c12fe1c06bba254a9dc9f519b335aa7c1367a88a")
        #expect(m.displayName == "Test Name")
        #expect(m.trackers == ["udp://tracker.example:1337"])
        #expect(m.peers.first?.description == "1.2.3.4:5")
        let b32 = MagnetLink("magnet:?xt=urn:btih:YEX6DQDLXISUVHOJ6UM3GNNKPQJWPKEK")!
        #expect(b32.infoHashes.v1?.hex == "c12fe1c06bba254a9dc9f519b335aa7c1367a88a")
        let v2 = MagnetLink("magnet:?xt=urn:btmh:1220caf1e1c30e81cb361b9ee167c4aa64228a7fa4fa9f6105232b28ad099f3a302e")!
        #expect(v2.infoHashes.v2?.count == 32 && v2.infoHashes.v1 == nil)
    }
}

@Suite struct BitfieldTests {
    @Test func wireOrderAndSpareBits() {
        var b = Bitfield(count: 10)
        b[0] = true; b[9] = true
        #expect(b.bytes == [0x80, 0x40])
        #expect(b.setCount == 2)
        #expect(Bitfield(wire: [0xFF, 0xFF], count: 10) == nil) // spare bits set
        #expect(Bitfield(count: 10, allSet: true).bytes == [0xFF, 0xC0])
    }
}

@Suite struct HashServingTests {
    /// Build a hybrid torrent in memory and check hash responses verify against the pieces root.
    @Test func piecesLayerResponsesVerify() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("astor-hash-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("big.bin")
        try Data((0..<(16384 * 37 + 5)).map { UInt8(truncatingIfNeeded: $0 &* 31) }).write(to: file)
        var opt = TorrentCreator.Options(); opt.pieceLength = 32768
        let mi = try Metainfo(torrentFile: TorrentCreator.create(from: file, options: opt))
        #expect(mi.validatePieceLayers())
        let f = mi.files[0]
        let layer = mi.pieceLayer(for: f)!            // 19 pieces → padded to 32
        let levels = try #require(Merkle.levels(pieceLayer: layer, pieceLength: mi.pieceLength))
        #expect(levels.last?.first == f.piecesRoot)
        func serve(_ index: Int, _ length: Int, _ proof: Int) -> [Data] {
            let d = Merkle.hashResponse(levels: levels, index: index, length: length, proof: proof)!
            return stride(from: 0, to: d.count, by: 32).map { d.subdata(in: $0..<($0 + 32)) }
        }
        // Verify: rebuild the subtree from hashes, climb with uncles, compare with the root.
        for (index, length) in [(0, 2), (8, 8), (16, 16), (0, 32)] {
            let hs = serve(index, length, 10)
            var level = Array(hs[0..<length])
            while level.count > 1 { level = stride(from: 0, to: level.count, by: 2).map { Hash.sha256Pair(level[$0], level[$0 + 1]) } }
            var node = level[0], idx = index / length
            for u in hs[length...] { node = idx & 1 == 0 ? Hash.sha256Pair(node, u) : Hash.sha256Pair(u, node); idx >>= 1 }
            #expect(node == f.piecesRoot)
        }
    }
}
