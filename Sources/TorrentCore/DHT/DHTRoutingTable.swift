import Foundation

/// BEP 5 node liveness.
enum DHTNodeState: Sendable {
    /// Responded to one of our queries within 15 min, or has responded at some point
    /// and sent us a message within 15 min.
    case good
    /// No activity for 15 minutes (or never answered one of our queries).
    case questionable
    /// Failed to respond to several queries in a row.
    case bad
}

struct DHTRoutingEntry: Sendable {
    var id: DHTID
    var addr: PeerAddress
    var firstSeen: Double
    /// Last time we received any message from this node.
    var lastSeen: Double
    /// Last time it answered one of our queries (0 = never).
    var lastResponse: Double = 0
    /// Last time we sent it a liveness ping.
    var lastPinged: Double = 0
    /// Consecutive unanswered queries.
    var failCount = 0
    /// BEP 42: id matches the node's IP (or the IP is exempt).
    var compliant: Bool

    var confirmed: Bool { lastResponse > 0 }
    var info: DHTNodeInfo { DHTNodeInfo(id: id, addr: addr) }

    func state(now: Double) -> DHTNodeState {
        if failCount >= DHTRoutingTable.badFailCount { return .bad }
        if confirmed, now - lastResponse < DHTRoutingTable.goodWindow || now - lastSeen < DHTRoutingTable.goodWindow {
            return .good
        }
        return .questionable
    }
}

struct DHTBucket: Sendable {
    var nodes: [DHTRoutingEntry] = []
    /// Nodes we would add if a live slot frees up (most useful kept).
    var replacements: [DHTRoutingEntry] = []
    /// Last time a node was added to / answered from this bucket.
    var lastChanged: Double
}

/// Kademlia routing table (BEP 5): k-buckets indexed by the length of the common
/// prefix with our own id. Only the last bucket (the one containing our own id)
/// is ever split, so the table holds at most 160 buckets.
///
/// Loop-confined (owned by `DHTNode`). All time-dependent calls take `now` so the
/// logic is deterministic under test.
final class DHTRoutingTable {
    static let goodWindow: Double = 15 * 60
    static let badFailCount = 2
    static let removeFailCount = 4
    static let maxBuckets = 160

    let k: Int
    private(set) var ownID: DHTID
    private(set) var buckets: [DHTBucket]
    /// Below this many nodes the table counts as sparse and accepts any node id.
    /// Above it, non-BEP 42 ids are limited to half of each bucket and compliant
    /// nodes displace them.
    var sparseThreshold: Int
    /// At most one routing entry per public IP (Sybil resistance; private/loopback exempt).
    var enforceUniqueIPs = true

    private var byAddr: [PeerAddress: DHTID] = [:]
    private var ipCount: [IPAddress: Int] = [:]
    private(set) var count = 0

    init(ownID: DHTID, k: Int = 8, now: Double) {
        self.ownID = ownID
        self.k = k
        self.sparseThreshold = k * 8
        buckets = [DHTBucket(lastChanged: now)]
    }

    enum Outcome: Sendable, Equatable { case added, updated, cached, rejected }

    struct InsertResult {
        var outcome: Outcome
        /// A questionable node in the full target bucket that should be pinged so
        /// that, if dead, the cached newcomer can replace it.
        var pingCandidate: DHTRoutingEntry?
        init(_ outcome: Outcome, ping: DHTRoutingEntry? = nil) {
            self.outcome = outcome
            self.pingCandidate = ping
        }
    }

    func bucketIndex(for id: DHTID) -> Int {
        min(ownID.commonPrefixLength(with: id), buckets.count - 1)
    }

    func entry(id: DHTID) -> DHTRoutingEntry? {
        buckets[bucketIndex(for: id)].nodes.first { $0.id == id }
    }

    func entry(addr: PeerAddress) -> DHTRoutingEntry? {
        byAddr[addr].flatMap { entry(id: $0) }
    }

    func contains(addr: PeerAddress) -> Bool { byAddr[addr] != nil }

    var allEntries: [DHTRoutingEntry] { buckets.flatMap(\.nodes) }
    var replacementCount: Int { buckets.reduce(0) { $0 + $1.replacements.count } }

    func count(state: DHTNodeState, now: Double) -> Int {
        buckets.reduce(0) { acc, b in acc + b.nodes.reduce(0) { $0 + ($1.state(now: now) == state ? 1 : 0) } }
    }

    // MARK: Insertion

    /// Record that we heard from a node. `confirmed` = it answered one of our
    /// queries (as opposed to merely querying us).
    @discardableResult
    func heard(id: DHTID, addr: PeerAddress, confirmed: Bool, now: Double) -> InsertResult {
        guard id != ownID, addr.port != 0, !addr.ip.isUnusable else { return InsertResult(.rejected) }
        let b = bucketIndex(for: id)
        if let i = buckets[b].nodes.firstIndex(where: { $0.id == id }) {
            var e = buckets[b].nodes[i]
            if e.addr != addr {
                // Same id from a new endpoint: follow it only if the new endpoint really
                // answered us and the old one is not known-good (anti-hijack).
                guard confirmed, e.state(now: now) != .good, byAddr[addr] == nil,
                      ipAllowed(addr.ip, replacing: e.addr.ip) else { return InsertResult(.rejected) }
                unindex(e)
                e.addr = addr
                e.compliant = BEP42.isValid(id, for: addr.ip)
                index(e)
            }
            e.lastSeen = now
            if confirmed {
                e.lastResponse = now
                e.failCount = 0
                buckets[b].lastChanged = now
            }
            buckets[b].nodes[i] = e
            return InsertResult(.updated)
        }
        if let other = byAddr[addr] {
            // The endpoint is in the table under a different id (node restarted).
            guard confirmed else { return InsertResult(.rejected) }
            remove(id: other, now: now)
        }
        var e = DHTRoutingEntry(id: id, addr: addr, firstSeen: now, lastSeen: now,
                                compliant: BEP42.isValid(id, for: addr.ip))
        if confirmed { e.lastResponse = now }
        return place(e, now: now)
    }

    private func place(_ entry: DHTRoutingEntry, now: Double) -> InsertResult {
        var e = entry
        guard ipAllowed(e.addr.ip, replacing: nil) else { return InsertResult(.rejected) }
        while true {
            let b = bucketIndex(for: e.id)
            if let r = buckets[b].replacements.firstIndex(where: { $0.id == e.id }) {
                let old = buckets[b].replacements.remove(at: r)
                e.firstSeen = min(e.firstSeen, old.firstSeen)
                e.lastResponse = max(e.lastResponse, old.lastResponse)
                e.lastSeen = max(e.lastSeen, old.lastSeen)
            }
            let sparse = count < sparseThreshold
            if buckets[b].nodes.count < k {
                let nonCompliant = buckets[b].nodes.reduce(0) { $0 + ($1.compliant ? 0 : 1) }
                if e.compliant || sparse || nonCompliant < k / 2 {
                    insert(e, bucket: b, now: now)
                    return InsertResult(.added)
                }
                cache(e, bucket: b)
                return InsertResult(.cached)
            }
            if b == buckets.count - 1 && buckets.count < Self.maxBuckets {
                split(now: now)
                continue
            }
            // Full bucket. 1) bad nodes are always replaced.
            if let i = worstIndex(in: b, where: { $0.state(now: now) == .bad }) {
                replace(bucket: b, index: i, with: e, now: now)
                return InsertResult(.added)
            }
            if e.confirmed {
                // 2) BEP 42: verified ids displace unverified ones once the table is healthy.
                if e.compliant && !sparse, let i = worstIndex(in: b, where: { !$0.compliant }) {
                    replace(bucket: b, index: i, with: e, now: now)
                    return InsertResult(.added)
                }
                // 3) A node that just answered beats one that recently failed to.
                if let i = worstIndex(in: b, where: { $0.failCount > 0 }) {
                    replace(bucket: b, index: i, with: e, now: now)
                    return InsertResult(.added)
                }
            }
            cache(e, bucket: b)
            let ping = buckets[b].nodes
                .filter { $0.state(now: now) == .questionable && now - $0.lastPinged > 30 }
                .min { $0.lastSeen < $1.lastSeen }
            return InsertResult(.cached, ping: ping)
        }
    }

    /// Index of the "worst" node matching `pred` (most failures, then least recently seen).
    private func worstIndex(in b: Int, where pred: (DHTRoutingEntry) -> Bool) -> Int? {
        var best: Int?
        for (i, n) in buckets[b].nodes.enumerated() where pred(n) {
            if let j = best {
                let o = buckets[b].nodes[j]
                if n.failCount > o.failCount || (n.failCount == o.failCount && n.lastSeen < o.lastSeen) { best = i }
            } else {
                best = i
            }
        }
        return best
    }

    private func insert(_ e: DHTRoutingEntry, bucket b: Int, now: Double) {
        buckets[b].nodes.append(e)
        buckets[b].lastChanged = now
        index(e)
        count += 1
    }

    private func replace(bucket b: Int, index i: Int, with e: DHTRoutingEntry, now: Double) {
        let old = buckets[b].nodes[i]
        unindex(old)
        buckets[b].nodes[i] = e
        buckets[b].lastChanged = now
        index(e)
        if old.state(now: now) != .bad { cache(old, bucket: b) }
    }

    private func cache(_ e: DHTRoutingEntry, bucket b: Int) {
        if let i = buckets[b].replacements.firstIndex(where: { $0.id == e.id || $0.addr == e.addr }) {
            var m = e
            m.lastResponse = max(m.lastResponse, buckets[b].replacements[i].lastResponse)
            buckets[b].replacements[i] = m
            return
        }
        if buckets[b].replacements.count >= k {
            // Drop an unconfirmed entry first, otherwise the least recently seen one.
            let reps = buckets[b].replacements
            if let victim = reps.indices.min(by: { (reps[$0].confirmed ? 1 : 0, reps[$0].lastSeen) < (reps[$1].confirmed ? 1 : 0, reps[$1].lastSeen) }) {
                buckets[b].replacements.remove(at: victim)
            }
        }
        buckets[b].replacements.append(e)
    }

    private func split(now: Double) {
        let n = buckets.count   // index of the new bucket
        var old = buckets[n - 1]
        var fresh = DHTBucket(lastChanged: old.lastChanged)
        var keep: [DHTRoutingEntry] = []
        for e in old.nodes {
            if ownID.commonPrefixLength(with: e.id) >= n { fresh.nodes.append(e) } else { keep.append(e) }
        }
        old.nodes = keep
        var keepR: [DHTRoutingEntry] = []
        for e in old.replacements {
            if ownID.commonPrefixLength(with: e.id) >= n { fresh.replacements.append(e) } else { keepR.append(e) }
        }
        old.replacements = keepR
        buckets[n - 1] = old
        buckets.append(fresh)
        fill(bucket: n - 1, now: now)
        fill(bucket: n, now: now)
    }

    /// Promote replacement-cache entries into free live slots. Returns the promoted entries.
    @discardableResult
    private func fill(bucket b: Int, now: Double) -> [DHTRoutingEntry] {
        var promoted: [DHTRoutingEntry] = []
        while buckets[b].nodes.count < k, !buckets[b].replacements.isEmpty {
            let reps = buckets[b].replacements
            // Best: confirmed first, then most recently seen.
            guard let i = reps.indices.max(by: { (reps[$0].confirmed ? 1 : 0, reps[$0].lastSeen) < (reps[$1].confirmed ? 1 : 0, reps[$1].lastSeen) }) else { break }
            let e = buckets[b].replacements.remove(at: i)
            guard byAddr[e.addr] == nil, ipAllowed(e.addr.ip, replacing: nil), e.id != ownID else { continue }
            insert(e, bucket: b, now: now)
            promoted.append(e)
        }
        return promoted
    }

    // MARK: Failure / removal

    /// A query to this node timed out. Returns replacement entries that were promoted
    /// and have never answered us (the caller should ping them).
    @discardableResult
    func failed(id: DHTID?, addr: PeerAddress, now: Double) -> [DHTRoutingEntry] {
        guard let theID = id ?? byAddr[addr] else { return [] }
        let b = bucketIndex(for: theID)
        if let i = buckets[b].nodes.firstIndex(where: { $0.id == theID && $0.addr == addr }) {
            buckets[b].nodes[i].failCount += 1
            let e = buckets[b].nodes[i]
            if e.state(now: now) == .bad, !buckets[b].replacements.isEmpty || e.failCount >= Self.removeFailCount {
                return remove(id: theID, now: now).filter { !$0.confirmed }
            }
            return []
        }
        if let r = buckets[b].replacements.firstIndex(where: { $0.id == theID && $0.addr == addr }) {
            buckets[b].replacements.remove(at: r)
        }
        return []
    }

    /// Remove a node; returns replacement entries promoted into the freed slot.
    @discardableResult
    func remove(id: DHTID, now: Double) -> [DHTRoutingEntry] {
        let b = bucketIndex(for: id)
        guard let i = buckets[b].nodes.firstIndex(where: { $0.id == id }) else { return [] }
        let e = buckets[b].nodes.remove(at: i)
        unindex(e)
        count -= 1
        return fill(bucket: b, now: now)
    }

    func markPinged(id: DHTID, now: Double) {
        let b = bucketIndex(for: id)
        if let i = buckets[b].nodes.firstIndex(where: { $0.id == id }) { buckets[b].nodes[i].lastPinged = now }
    }

    // MARK: Queries

    /// The `count` closest non-bad nodes to `target`.
    func closest(to target: DHTID, count n: Int, now: Double) -> [DHTRoutingEntry] {
        var all: [(DHTID, DHTRoutingEntry)] = []
        all.reserveCapacity(self.count)
        for b in buckets {
            for e in b.nodes where e.state(now: now) != .bad { all.append((e.id ^ target, e)) }
        }
        all.sort { $0.0 < $1.0 }
        return all.prefix(n).map(\.1)
    }

    /// Closest nodes for answering find_node / get_peers: nodes that have answered us
    /// are preferred; unverified ones only fill remaining slots.
    func closestForResponse(to target: DHTID, count n: Int, now: Double, excluding: DHTID? = nil) -> [DHTNodeInfo] {
        let sorted = closest(to: target, count: n * 3, now: now).filter { $0.id != excluding }
        var out = sorted.filter(\.confirmed).prefix(n).map(\.info)
        if out.count < n {
            for e in sorted where !e.confirmed {
                out.append(e.info)
                if out.count == n { break }
            }
            out.sort { target.isCloser($0.id, than: $1.id) }
        }
        return out
    }

    /// Nodes due for a liveness ping: never-confirmed first, then questionable nodes
    /// by least recently seen.
    func nodesNeedingPing(now: Double, max: Int, minInterval: Double = 60) -> [DHTRoutingEntry] {
        let due = allEntries.filter {
            ($0.state(now: now) != .good) && now - $0.lastPinged > minInterval
        }
        return Array(due.sorted {
            ($0.confirmed ? 1 : 0, $0.lastSeen) < ($1.confirmed ? 1 : 0, $1.lastSeen)
        }.prefix(max))
    }

    /// Random lookup targets for buckets that have not changed for `staleAfter`
    /// seconds. Marks those buckets refreshed.
    func refreshTargets(now: Double, staleAfter: Double) -> [DHTID] {
        var out: [DHTID] = []
        for i in buckets.indices where now - buckets[i].lastChanged > staleAfter {
            out.append(ownID.randomID(sharingPrefix: i, exact: i < buckets.count - 1))
            buckets[i].lastChanged = now
        }
        return out
    }

    /// One random target per bucket (used right after bootstrap to fill the table).
    func allBucketTargets() -> [DHTID] {
        buckets.indices.map { ownID.randomID(sharingPrefix: $0, exact: $0 < buckets.count - 1) }
    }

    /// Re-key the table under a new own id (BEP 42 id change), keeping all nodes.
    func rebuild(ownID newID: DHTID, now: Double) {
        let live = buckets.flatMap(\.nodes)
        let reps = buckets.flatMap(\.replacements)
        ownID = newID
        buckets = [DHTBucket(lastChanged: now)]
        byAddr = [:]
        ipCount = [:]
        count = 0
        for e in live.sorted(by: { ($0.confirmed ? 1 : 0, $0.lastSeen) > ($1.confirmed ? 1 : 0, $1.lastSeen) })
            where e.id != newID && byAddr[e.addr] == nil {
            _ = place(e, now: now)
        }
        for e in reps where e.id != newID && byAddr[e.addr] == nil {
            _ = place(e, now: now)
        }
    }

    // MARK: Indexes

    private func index(_ e: DHTRoutingEntry) {
        byAddr[e.addr] = e.id
        ipCount[e.addr.ip, default: 0] += 1
    }

    private func unindex(_ e: DHTRoutingEntry) {
        if byAddr[e.addr] == e.id { byAddr.removeValue(forKey: e.addr) }
        if let c = ipCount[e.addr.ip] {
            if c <= 1 { ipCount.removeValue(forKey: e.addr.ip) } else { ipCount[e.addr.ip] = c - 1 }
        }
    }

    private func ipAllowed(_ ip: IPAddress, replacing old: IPAddress?) -> Bool {
        guard enforceUniqueIPs, !BEP42.isExempt(ip) else { return true }
        let c = ipCount[ip] ?? 0
        return old == ip ? c <= 1 : c == 0
    }
}
