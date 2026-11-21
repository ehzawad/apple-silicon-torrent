import Testing
import Foundation
@testable import TorrentCore

@Suite struct PiecePickerTests {
    final class Key {}   // stand-in peer identity
    let ipA = IPAddress("10.0.0.1")!, ipB = IPAddress("10.0.0.2")!

    func picker(pieces: Int = 8, pieceLen: Int = 32 * 1024) -> PiecePicker {
        PiecePicker(pieceCount: pieces, pieceLength: pieceLen, totalLength: Int64(pieces * pieceLen - 1000),
                    have: Bitfield(count: pieces))
    }

    @Test func rarestFirstAndPartialCompletionFirst() {
        let p = picker()
        // Two peers have every piece except 5; one peer has only piece 5 → piece 5 is rarest.
        var most = Bitfield(count: 8, allSet: true); most[5] = false
        var only5 = Bitfield(count: 8); only5[5] = true
        p.peerAdded(most); p.peerAdded(most); p.peerAdded(only5)
        let a = Key()
        let first = p.pick(peer: ObjectIdentifier(a), peerHave: nil, isSeed: true, count: 1)
        #expect(first.first?.piece == 5)
        // The partially requested piece is finished before a new piece is started.
        let next = p.pick(peer: ObjectIdentifier(a), peerHave: nil, isSeed: true, count: 1)
        #expect(next.first?.piece == 5 && next.first?.offset == Wire.blockSize)
    }

    @Test func endgameDuplicatesAtMostTwiceAndCancels() {
        let p = picker(pieces: 1)
        let a = Key(), b = Key(), c = Key()
        let blocksA = p.pick(peer: ObjectIdentifier(a), peerHave: nil, isSeed: true, count: 10)
        #expect(blocksA.count == 2)            // 32 KiB - 1000 bytes → 2 blocks
        #expect(p.inEndgame)
        let blocksB = p.pick(peer: ObjectIdentifier(b), peerHave: nil, isSeed: true, count: 10)
        #expect(blocksB.count == 2)            // duplicates
        let blocksC = p.pick(peer: ObjectIdentifier(c), peerHave: nil, isSeed: true, count: 10)
        #expect(blocksC.isEmpty)               // max two holders per block
        guard case .accepted(let complete, let cancelAt) = p.blockReceived(blocksA[0], from: ObjectIdentifier(a), ip: ipA) else {
            Issue.record("expected accepted"); return
        }
        #expect(!complete)
        #expect(cancelAt == [ObjectIdentifier(b)])
        if case .unexpected = p.blockReceived(blocksB[0], from: ObjectIdentifier(b), ip: ipB) {} else { Issue.record("duplicate accepted") }
        guard case .accepted(let done, _) = p.blockReceived(blocksB[1], from: ObjectIdentifier(b), ip: ipB) else {
            Issue.record("expected accepted"); return
        }
        #expect(done)
        #expect(p.senders(of: 0) == [0: ipA, 1: ipB])
        let failed = p.pieceFailed(0)
        #expect(failed.contributors == [ipA, ipB])
        #expect(failed.senders[1] == ipB)
        #expect(!p.have[0])
    }

    @Test func abortReturnsBlocksAndLateArrivalStillCounts() {
        let p = picker(pieces: 2)
        let a = Key(), b = Key()
        let req = p.pick(peer: ObjectIdentifier(a), peerHave: nil, isSeed: true, count: 1)
        p.abort(req[0], peer: ObjectIdentifier(a))
        let again = p.pick(peer: ObjectIdentifier(b), peerHave: nil, isSeed: true, count: 1)
        #expect(again == req)                  // freed block is handed to the next peer
        if case .accepted = p.blockReceived(req[0], from: ObjectIdentifier(a), ip: ipA) {} else { Issue.record("late block rejected") }
    }

    @Test func wantedSelectionAndInterest() {
        let p = picker(pieces: 4)
        p.setPriorities([0, 1, 0, 0])
        var peerHas = Bitfield(count: 4); peerHas[0] = true
        #expect(!p.isInteresting(peerHas, peerIsSeed: false))
        peerHas[1] = true
        #expect(p.isInteresting(peerHas, peerIsSeed: false))
        let picks = p.pick(peer: ObjectIdentifier(Key()), peerHave: peerHas, isSeed: false, count: 10)
        #expect(picks.allSatisfy { $0.piece == 1 })
    }
}
