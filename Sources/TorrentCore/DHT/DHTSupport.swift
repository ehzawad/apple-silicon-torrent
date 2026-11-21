import Foundation

/// announce_peer write tokens (BEP 5): `SHA1(secret || requester IP)` truncated to
/// 8 bytes. The secret rotates every 5 minutes and tokens made with the previous
/// secret are still accepted, so a token stays valid for 5–10 minutes.
struct DHTTokenManager {
    static let rotationInterval: Double = 5 * 60
    static let tokenLength = 8

    private(set) var current: Data
    private(set) var previous: Data
    private(set) var rotatedAt: Double

    init(now: Double) {
        current = Data.random(16)
        previous = Data.random(16)
        rotatedAt = now
    }

    mutating func rotateIfNeeded(now: Double) {
        if now - rotatedAt >= Self.rotationInterval { rotate(now: now) }
    }

    mutating func rotate(now: Double) {
        previous = current
        current = Data.random(16)
        rotatedAt = now
    }

    func token(for ip: IPAddress) -> Data { Self.make(secret: current, ip: ip) }

    func validate(_ token: Data, for ip: IPAddress) -> Bool {
        guard token.count == Self.tokenLength else { return false }
        return token == Self.make(secret: current, ip: ip) || token == Self.make(secret: previous, ip: ip)
    }

    static func make(secret: Data, ip: IPAddress) -> Data {
        var buf = secret
        buf.append(contentsOf: ip.bytes)
        return Data(Hash.sha1(buf).prefix(tokenLength))
    }
}

/// Peers announced to us via announce_peer, per info hash, with expiry.
struct DHTPeerStore {
    var maxPeersPerHash = 100
    var maxHashes = 5000
    var ttl: Double = 30 * 60

    /// info hash → (peer → expiry time)
    private(set) var torrents: [DHTID: [PeerAddress: Double]] = [:]

    var hashCount: Int { torrents.count }
    var peerCount: Int { torrents.values.reduce(0) { $0 + $1.count } }

    mutating func announce(_ infoHash: DHTID, peer: PeerAddress, now: Double) {
        if torrents[infoHash] == nil && torrents.count >= maxHashes { return }
        var peers = torrents[infoHash] ?? [:]
        if peers[peer] == nil && peers.count >= maxPeersPerHash,
           let oldest = peers.min(by: { $0.value < $1.value })?.key {
            peers.removeValue(forKey: oldest)
        }
        peers[peer] = now + ttl
        torrents[infoHash] = peers
    }

    /// Up to `max` random live peers for `infoHash`.
    func peers(for infoHash: DHTID, max: Int, now: Double) -> [PeerAddress] {
        guard let p = torrents[infoHash] else { return [] }
        let live = p.compactMap { $0.value > now ? $0.key : nil }
        if live.count <= max { return live }
        return Array(live.shuffled().prefix(max))
    }

    mutating func expire(now: Double) {
        for (h, peers) in torrents {
            let live = peers.filter { $0.value > now }
            if live.isEmpty { torrents.removeValue(forKey: h) } else if live.count != peers.count { torrents[h] = live }
        }
    }
}

/// Majority vote over the BEP 42 `ip` fields reported by distinct remote nodes.
struct DHTIPVoter {
    /// Minimum number of distinct voters agreeing before an address is adopted.
    var minVotes = 4
    /// Only the most recent `maxVoters` voters are remembered.
    var maxVoters = 64

    private var votes: [IPAddress: IPAddress] = [:]   // voter IP → address it reported
    private var order: [IPAddress] = []
    private(set) var winner: IPAddress?

    var voterCount: Int { votes.count }

    /// Record a vote; returns the new winner when the consensus changes.
    mutating func add(voter: IPAddress, reported: IPAddress) -> IPAddress? {
        if votes[voter] == nil {
            order.append(voter)
            if order.count > maxVoters {
                let old = order.removeFirst()
                votes.removeValue(forKey: old)
            }
        }
        votes[voter] = reported
        var tally: [IPAddress: Int] = [:]
        for v in votes.values { tally[v, default: 0] += 1 }
        guard let best = tally.max(by: { $0.value < $1.value }),
              best.value >= minVotes, best.value * 2 > votes.count else { return nil }
        if best.key != winner {
            winner = best.key
            return best.key
        }
        return nil
    }
}

/// Token bucket used to cap outgoing query (and response) rates.
struct DHTRateLimiter {
    var rate: Double
    var burst: Double
    private var tokens: Double
    private var last: Double

    init(rate: Double, burst: Double, now: Double) {
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last = now
    }

    mutating func take(now: Double) -> Bool {
        tokens = min(burst, tokens + max(0, now - last) * rate)
        last = now
        if tokens >= 1 {
            tokens -= 1
            return true
        }
        return false
    }
}
