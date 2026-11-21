import Foundation

/// Decides which blocks to request from which peer.
///
/// * rarest-first with random tie-breaking (or sequential for streaming)
/// * finishes partially downloaded pieces before starting new ones
/// * per-peer piece affinity to keep the number of partial pieces small
/// * endgame mode: duplicate the last outstanding blocks (max 2 holders), cancel on arrival
///
/// Loop-confined.
final class PiecePicker: @unchecked Sendable {
    typealias PeerKey = ObjectIdentifier

    let pieceCount: Int
    let pieceLength: Int
    let lastPieceLength: Int
    private(set) var have: Bitfield
    /// How many connected peers have each piece (excluding seeds, counted in `seedCount`).
    private(set) var availability: [UInt16]
    private(set) var seedCount = 0
    /// 0 = don't download, 1..7 = priority (higher first within the same rarity class).
    private(set) var priority: [UInt8]
    var sequential = false

    struct Partial {
        enum State: UInt8 { case free, requested, received }
        var states: [State]
        var holders: [Int: [PeerKey]] = [:]   // block -> peers it is requested from
        var receivedCount = 0
        var freeCount: Int
        var lastActivity = monotonicNow()
        /// IPs that delivered data for this piece (for hash-failure banning).
        var contributors: Set<IPAddress> = []
        /// Which IP delivered each block (smart-ban).
        var senders: [Int: IPAddress] = [:]
    }
    private(set) var partials: [Int: Partial] = [:]
    /// Pieces fully received and currently being hashed.
    private(set) var verifying: Set<Int> = []

    private var order: [Int] = []
    private var orderDirty = true
    private var lastOrderBuild = 0.0
    private var rng = SystemRandomNumberGenerator()

    init(pieceCount: Int, pieceLength: Int, totalLength: Int64, have: Bitfield) {
        self.pieceCount = pieceCount
        self.pieceLength = pieceLength
        let rem = Int(totalLength - Int64(pieceLength) * Int64(max(0, pieceCount - 1)))
        self.lastPieceLength = pieceCount == 0 ? 0 : rem
        self.have = have
        availability = [UInt16](repeating: 0, count: pieceCount)
        priority = [UInt8](repeating: 1, count: pieceCount)
    }

    // MARK: Geometry

    func pieceSize(_ i: Int) -> Int { i == pieceCount - 1 ? lastPieceLength : pieceLength }
    func blockCount(_ i: Int) -> Int { (pieceSize(i) + Wire.blockSize - 1) / Wire.blockSize }
    func blockLength(_ piece: Int, _ block: Int) -> Int {
        min(Wire.blockSize, pieceSize(piece) - block * Wire.blockSize)
    }

    // MARK: Wanted set

    func setPriorities(_ p: [UInt8]) {
        precondition(p.count == pieceCount)
        priority = p
        orderDirty = true
    }

    func isWanted(_ i: Int) -> Bool { priority[i] > 0 && !have[i] }

    var wantedRemaining: Int {
        var n = 0
        for i in 0..<pieceCount where isWanted(i) { n += 1 }
        return n
    }

    /// True when every wanted piece is downloaded (may still have unwanted pieces missing).
    var isFinished: Bool {
        for i in 0..<pieceCount where priority[i] > 0 && !have[i] { return false }
        return true
    }

    /// Does `peer` have anything we want?
    func isInteresting(_ peerHave: Bitfield?, peerIsSeed: Bool) -> Bool {
        if peerIsSeed { return !isFinished }
        guard let ph = peerHave else { return false }
        let a = ph.bytes, h = have.bytes
        for byteIdx in 0..<a.count {
            let cand = a[byteIdx] & ~h[byteIdx]
            if cand == 0 { continue }
            for bit in 0..<8 where cand & (0x80 >> UInt8(bit)) != 0 {
                let i = byteIdx * 8 + bit
                if i < pieceCount, priority[i] > 0 { return true }
            }
        }
        return false
    }

    // MARK: Availability

    func peerAddedSeed() { seedCount += 1 }
    func peerRemovedSeed() { seedCount = max(0, seedCount - 1) }

    func peerAdded(_ bf: Bitfield) {
        for i in 0..<pieceCount where bf[i] { availability[i] &+= 1 }
        orderDirty = true
    }

    func peerRemoved(_ bf: Bitfield) {
        for i in 0..<pieceCount where bf[i] && availability[i] > 0 { availability[i] -= 1 }
        orderDirty = true
    }

    func peerHave(_ i: Int) {
        guard i >= 0 && i < pieceCount else { return }
        availability[i] &+= 1
        orderDirty = true
    }

    func peerLost(_ i: Int) {
        guard i >= 0 && i < pieceCount, availability[i] > 0 else { return }
        availability[i] -= 1
        orderDirty = true
    }

    /// Distributed copies (like Transmission's "availability"): min availability over missing pieces.
    var distributedCopies: Double {
        var minA = Int.max, countAtMin = 0, total = 0
        for i in 0..<pieceCount {
            let a = Int(availability[i]) + seedCount
            if a < minA { minA = a; countAtMin = 1 } else if a == minA { countAtMin += 1 }
            total += 1
        }
        guard total > 0, minA != Int.max else { return 0 }
        return Double(minA) + Double(total - countAtMin) / Double(total)
    }

    // MARK: Ordering

    private func rebuildOrderIfNeeded() {
        let now = monotonicNow()
        guard orderDirty || order.isEmpty, now - lastOrderBuild > 1.0 || order.isEmpty else { return }
        lastOrderBuild = now
        orderDirty = false
        var cands: [(Int, UInt32)] = []
        cands.reserveCapacity(pieceCount)
        for i in 0..<pieceCount where isWanted(i) {
            if sequential {
                cands.append((i, UInt32(i)))
            } else {
                // key: higher priority first, then rarest, then random
                let pri = UInt32(7 - min(7, priority[i]))
                let avail = UInt32(min(Int(availability[i]), 4095))
                let r = UInt32.random(in: 0..<4096, using: &rng)
                cands.append((i, pri << 24 | avail << 12 | r))
            }
        }
        cands.sort { $0.1 < $1.1 }
        order = cands.map { $0.0 }
    }

    // MARK: Picking

    /// Pick up to `count` blocks for a peer.
    /// - Parameters:
    ///   - peerHave: the peer's bitfield (nil if seed / have-all).
    ///   - allowedOnly: when the peer is choking us, the BEP 6 allowed-fast pieces.
    ///   - affinity: pieces this peer is already working on (tried first).
    func pick(peer: PeerKey, peerHave: Bitfield?, isSeed: Bool, count: Int,
              allowedOnly: Set<Int>? = nil, affinity: [Int] = []) -> [BlockRequest] {
        guard count > 0 else { return [] }
        var out: [BlockRequest] = []
        out.reserveCapacity(count)

        func peerHas(_ i: Int) -> Bool {
            if let a = allowedOnly, !a.contains(i) { return false }
            return isSeed || (peerHave?[i] ?? false)
        }

        func takeFree(from i: Int) {
            guard var p = partials[i], p.freeCount > 0 else { return }
            for b in 0..<p.states.count where p.states[b] == .free {
                p.states[b] = .requested
                p.holders[b] = [peer]
                p.freeCount -= 1
                out.append(BlockRequest(piece: i, offset: b * Wire.blockSize, length: blockLength(i, b)))
                if out.count >= count { break }
            }
            p.lastActivity = monotonicNow()
            partials[i] = p
        }

        // 1. Pieces this peer is already downloading.
        for i in affinity where out.count < count && partials[i] != nil && peerHas(i) {
            takeFree(from: i)
        }
        // 2. Other partial pieces, most complete first (sequential: lowest index first).
        if out.count < count, !partials.isEmpty {
            let keys = partials.keys.filter { partials[$0]!.freeCount > 0 && peerHas($0) }
            let sorted = sequential ? keys.sorted() : keys.sorted { partials[$0]!.freeCount < partials[$1]!.freeCount }
            for i in sorted where out.count < count { takeFree(from: i) }
        }
        // 3. New pieces in rarest-first (or sequential) order.
        if out.count < count {
            rebuildOrderIfNeeded()
            for i in order where out.count < count {
                if have[i] || partials[i] != nil || verifying.contains(i) || priority[i] == 0 || !peerHas(i) { continue }
                let n = blockCount(i)
                partials[i] = Partial(states: [Partial.State](repeating: .free, count: n), freeCount: n)
                takeFree(from: i)
            }
        }
        // 4. Endgame: everything wanted is requested; duplicate outstanding blocks (≤ 2 holders).
        if out.isEmpty {
            for (i, var p) in partials where out.count < count && peerHas(i) && p.freeCount == 0 {
                var changed = false
                for b in 0..<p.states.count where p.states[b] == .requested && out.count < count {
                    var h = p.holders[b] ?? []
                    if h.count >= 2 || h.contains(peer) { continue }
                    h.append(peer)
                    p.holders[b] = h
                    changed = true
                    out.append(BlockRequest(piece: i, offset: b * Wire.blockSize, length: blockLength(i, b)))
                }
                if changed { partials[i] = p }
            }
        }
        return out
    }

    /// True when no free (never-requested) wanted blocks remain.
    var inEndgame: Bool {
        if partials.values.contains(where: { $0.freeCount > 0 }) { return false }
        for i in 0..<pieceCount where isWanted(i) && partials[i] == nil && !verifying.contains(i) { return false }
        return true
    }

    // MARK: Events

    enum ReceiveResult {
        case unexpected          // not requested / already have it
        case accepted(pieceComplete: Bool, cancelAt: [PeerKey])
    }

    func blockReceived(_ r: BlockRequest, from peer: PeerKey, ip: IPAddress) -> ReceiveResult {
        guard r.piece >= 0, r.piece < pieceCount, !have[r.piece], var p = partials[r.piece] else { return .unexpected }
        let b = r.blockIndex
        guard b < p.states.count, r.offset % Wire.blockSize == 0, r.length == blockLength(r.piece, b) else { return .unexpected }
        if p.states[b] == .received { return .unexpected }
        if p.states[b] == .free { p.freeCount -= 1 } // late arrival after timeout/abort: still useful
        p.states[b] = .received
        p.receivedCount += 1
        p.contributors.insert(ip)
        p.senders[b] = ip
        p.lastActivity = monotonicNow()
        let others = (p.holders.removeValue(forKey: b) ?? []).filter { $0 != peer }
        let complete = p.receivedCount == p.states.count
        partials[r.piece] = p
        if complete {
            verifying.insert(r.piece)
        }
        return .accepted(pieceComplete: complete, cancelAt: others)
    }

    /// The peer will not deliver this block (reject, choke, timeout, disconnect).
    func abort(_ r: BlockRequest, peer: PeerKey) {
        guard var p = partials[r.piece] else { return }
        let b = r.blockIndex
        guard b < p.states.count, p.states[b] == .requested else { return }
        var h = p.holders[b] ?? []
        h.removeAll { $0 == peer }
        if h.isEmpty {
            p.holders[b] = nil
            p.states[b] = .free
            p.freeCount += 1
        } else {
            p.holders[b] = h
        }
        partials[r.piece] = p
    }

    /// Returns contributor IPs and per-block senders of the failed piece (for banning).
    func pieceFailed(_ i: Int) -> (contributors: Set<IPAddress>, senders: [Int: IPAddress]) {
        verifying.remove(i)
        let p = partials[i]
        partials[i] = nil
        orderDirty = true
        return (p?.contributors ?? [], p?.senders ?? [:])
    }

    /// Per-block senders of a piece that is currently being verified.
    func senders(of i: Int) -> [Int: IPAddress] { partials[i]?.senders ?? [:] }

    func pieceVerified(_ i: Int) {
        verifying.remove(i)
        partials[i] = nil
        have[i] = true
        orderDirty = true
    }

    /// Mark pieces as had without downloading (resume / recheck).
    func setHave(_ bf: Bitfield) {
        have = bf
        partials.removeAll()
        verifying.removeAll()
        orderDirty = true
    }

    /// Bytes downloaded but not yet verified (for progress display).
    var partialBytes: Int64 {
        var n: Int64 = 0
        for (_, p) in partials { n += Int64(p.receivedCount * Wire.blockSize) }
        return n
    }
}
