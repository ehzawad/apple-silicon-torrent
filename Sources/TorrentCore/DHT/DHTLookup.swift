import Foundation

/// State of one iterative Kademlia lookup (find_node or get_peers).
///
/// The lookup only decides *whom* to query next and *when* it is finished; the
/// owning `DHTNode` sends the queries and feeds results back. Candidates are kept
/// sorted by XOR distance to the target. Up to `alpha` queries are outstanding at
/// once (queries older than `slowAfter` stop counting against `alpha` so a slow
/// node never stalls progress). The lookup finishes when the `k` closest
/// non-failed candidates have all responded, or nothing is left to query.
final class DHTLookup {
    enum Kind: Sendable { case findNode, getPeers }
    enum Purpose: Sendable { case user, bootstrap, refresh }
    enum CandidateState: Sendable { case fresh, inflight, responded, failed }

    struct Candidate {
        var id: DHTID?            // nil for bootstrap routers until they answer
        var addr: PeerAddress
        var distance: DHTID
        var state: CandidateState = .fresh
        var sentAt: Double = 0
        var token: Data?
    }

    let kind: Kind
    let target: DHTID
    let startedAt: Double
    var purpose: Purpose = .user
    var k = 8
    var alpha = 8
    var slowAfter: Double = 1.0
    var maxCandidates = 128
    var maxDuration: Double = 60

    private(set) var candidates: [Candidate] = []
    private var seen: Set<PeerAddress> = []
    private(set) var foundPeers: Set<PeerAddress> = []
    /// Peers found but not yet delivered to `onPeers`.
    var undelivered: [PeerAddress] = []
    var finished = false

    var announcePort: UInt16?
    var impliedPort = false
    var onPeers: (([PeerAddress]) -> Void)?
    var onDone: (() -> Void)?

    private(set) var queriesSent = 0
    private(set) var responses = 0
    private(set) var failures = 0

    init(kind: Kind, target: DHTID, now: Double) {
        self.kind = kind
        self.target = target
        self.startedAt = now
    }

    var isEmpty: Bool { candidates.isEmpty }

    /// Add a candidate (ignored if its endpoint was already seen in this lookup).
    /// Candidates with unknown ids sort last until they answer.
    @discardableResult
    func add(id: DHTID?, addr: PeerAddress) -> Bool {
        guard !seen.contains(addr) else { return false }
        let dist = id.map { $0 ^ target } ?? .allOnes
        let idx = insertionIndex(dist)
        if candidates.count >= maxCandidates {
            guard idx < candidates.count else { return false }
            candidates.removeLast()
        }
        seen.insert(addr)
        candidates.insert(Candidate(id: id, addr: addr, distance: dist), at: idx)
        return true
    }

    /// First index whose distance is greater than `d` (stable insertion point).
    private func insertionIndex(_ d: DHTID) -> Int {
        var lo = 0, hi = candidates.count
        while lo < hi {
            let mid = (lo + hi) / 2
            if candidates[mid].distance <= d { lo = mid + 1 } else { hi = mid }
        }
        return lo
    }

    /// Choose the next candidates to query (marking them in flight) and report
    /// whether the lookup has converged.
    ///
    /// Walking the candidates closest-first (like libtorrent's traversal): only
    /// nodes that *responded* count towards the `k` results; in-flight and failed
    /// ones do not, so up to `alpha` queries stay outstanding until the `k`
    /// closest responders are known. Queries slower than `slowAfter` stop counting
    /// against `alpha` (and stop blocking completion) so a dead node never stalls
    /// the lookup until its hard timeout. Endpoints whose id is unknown (bootstrap
    /// routers, hints) are queried at once and are not part of the ranking until
    /// they answer. Finished when no fresh / fast in-flight candidate is closer
    /// than the k-th responder and either `k` nodes responded or nothing at all is
    /// still in flight.
    func nextQueries(now: Double) -> (queries: [Candidate], finished: Bool) {
        if now - startedAt > maxDuration { return ([], true) }
        var active = 0
        var inflight = 0
        for c in candidates where c.state == .inflight {
            inflight += 1
            if now - c.sentAt < slowAfter { active += 1 }
        }
        var out: [Candidate] = []
        var responded = 0
        var blocking = false
        for i in candidates.indices {
            let c = candidates[i]
            if c.id == nil {
                if c.state == .fresh {
                    candidates[i].state = .inflight
                    candidates[i].sentAt = now
                    out.append(candidates[i])
                    inflight += 1
                }
                continue
            }
            if responded >= k { continue }   // keep scanning only for id-less endpoints
            switch c.state {
            case .failed:
                continue
            case .responded:
                responded += 1
            case .inflight:
                if now - c.sentAt < slowAfter { blocking = true }
            case .fresh:
                blocking = true
                if active < alpha {
                    candidates[i].state = .inflight
                    candidates[i].sentAt = now
                    out.append(candidates[i])
                    active += 1
                    inflight += 1
                }
            }
        }
        queriesSent += out.count
        return (out, !blocking && (responded >= k || inflight == 0))
    }

    /// A candidate answered. Adds the returned nodes and returns the newly seen peers.
    func handleResponse(from addr: PeerAddress, id: DHTID, nodes: [DHTNodeInfo], token: Data?,
                        values: [PeerAddress]) -> [PeerAddress] {
        responses += 1
        if let i = candidates.firstIndex(where: { $0.addr == addr }) {
            var c = candidates.remove(at: i)
            c.state = .responded
            c.token = token
            c.id = id
            c.distance = id ^ target
            candidates.insert(c, at: insertionIndex(c.distance))
        }
        for n in nodes { add(id: n.id, addr: n.addr) }
        return addPeers(values)
    }

    /// Record peers (deduplicated); returns the ones not seen before.
    func addPeers(_ values: [PeerAddress]) -> [PeerAddress] {
        var fresh: [PeerAddress] = []
        for p in values where foundPeers.insert(p).inserted { fresh.append(p) }
        return fresh
    }

    func handleFailure(from addr: PeerAddress) {
        failures += 1
        if let i = candidates.firstIndex(where: { $0.addr == addr }) { candidates[i].state = .failed }
    }

    /// Closest responding candidates that gave us a write token (announce targets).
    func announceTargets(count: Int) -> [Candidate] {
        Array(candidates.lazy.filter { $0.state == .responded && $0.token != nil && $0.id != nil }.prefix(count))
    }

    /// Closest responding nodes (result of a find_node lookup).
    func closestResponded(count: Int) -> [DHTNodeInfo] {
        Array(candidates.lazy.filter { $0.state == .responded }.compactMap { c in
            c.id.map { DHTNodeInfo(id: $0, addr: c.addr) }
        }.prefix(count))
    }
}
