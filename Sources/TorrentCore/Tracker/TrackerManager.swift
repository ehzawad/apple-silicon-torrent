import Foundation

/// Per-torrent tracker scheduler (BEP 3 events, BEP 12 tiers).
///
/// * `announceToAll == true`: every supported URL of every tier is announced to
///   concurrently and independently (each with its own interval / backoff).
///   Duplicate URLs are announced once; unsupported schemes (wss://, …) are
///   listed in `statuses` but never contacted.
/// * `announceToAll == false`: strict BEP 12. Trackers within a tier are
///   shuffled once; every announce round walks tier 0 → tier N in order until
///   one tracker answers, which is then moved to the front of its tier.
///
/// Every URL is announced once per entry of `infoHashes` (hybrid torrents:
/// v1 hash + truncated v2 hash). Events: the first successful announce to a
/// tracker carries `started`; `completed()` sends `completed` once to trackers
/// that saw us as a leecher; `stop()` sends `stopped` (best effort) to every
/// tracker that knows us and cancels all timers. Failures back off 30 s, 60 s,
/// 120 s … 30 min. Loop-confined.
public final class TrackerManager: @unchecked Sendable {
    // MARK: Tunables (internal so tests can shrink them)

    /// Interval used when a tracker gives none / an invalid one.
    var defaultInterval: Double = 1800
    /// Lower / upper bound applied to tracker intervals.
    var intervalFloor: Double = 60
    var intervalCeiling: Double = 3 * 3600
    /// `min interval` assumed when the tracker sends none (UDP never does).
    var defaultMinInterval: Double = 60
    /// Lower bound applied to `min interval`.
    var minIntervalFloor: Double = 10
    /// After a failure, `reannounceNow` waits at least this long since the last attempt.
    var reannounceFailureGap: Double = 30
    /// A peer already delivered is not re-delivered within this window.
    var peerRedeliveryWindow: Double = 300

    // MARK: State

    private final class HashState {
        var needStarted = true      // tracker has not acknowledged `started` yet
        var completedSent = false   // `completed` delivered (or we started as a seed)
        var registered = false      // tracker knows us (send `stopped` on stop)
        var trackerID: String?
    }

    private final class Entry: @unchecked Sendable {
        let url: String
        let tier: Int
        let supported: Bool
        var hashes: [Data: HashState] = [:]
        var inFlight = false
        var lastError: String?
        var warning: String?
        var seeders: Int?
        var leechers: Int?
        var lastPeerCount = 0
        var interval: Double = 1800
        var minInterval: Double = 60
        var lastAttemptAt: Double?
        var lastSuccessAt: Double?
        var failures = 0
        var nextAnnounceAt: Double?
        var timer: LoopTimer?
        var announceAgain = false   // an event arrived while in flight
        init(url: String, tier: Int, supported: Bool) {
            self.url = url; self.tier = tier; self.supported = supported
        }
    }

    /// Collects the per-info-hash results of one announce to one URL.
    private final class Round {
        var remaining: Int
        var successes: [AnnounceResponse] = []
        var errors: [any Error] = []
        var peers = Set<PeerAddress>()
        init(_ n: Int) { remaining = n }
    }

    private let loop: EventLoop
    private let client: TrackerClient
    private let infoHashes: [Data]
    private let peerID: Data
    private let announceToAll: Bool
    private let numWant: Int
    private let port: () -> UInt16
    private let stats: () -> (uploaded: Int64, downloaded: Int64, left: Int64)
    private let onPeers: ([PeerAddress]) -> Void
    private let key: UInt32

    private var tiers: [[Entry]] = []
    private var running = false
    private var generation = 0
    private var completedCalled = false
    private var completedPending = false
    private var recentPeers: [PeerAddress: Double] = [:]

    // BEP 12 mode
    private var roundInFlight = false
    private var roundAgain = false
    private var roundFailures = 0
    private var roundTimer: LoopTimer?
    private var roundNextAt: Double?
    private var active: Entry?

    public init(loop: EventLoop, client: TrackerClient, tiers: [[String]],
                infoHashes: [Data], peerID: Data, announceToAll: Bool, numWant: Int,
                port: @escaping () -> UInt16,
                stats: @escaping () -> (uploaded: Int64, downloaded: Int64, left: Int64),
                onPeers: @escaping ([PeerAddress]) -> Void) {
        self.loop = loop
        self.client = client
        var seenHash = Set<Data>()
        self.infoHashes = infoHashes.filter { $0.count == 20 && seenHash.insert($0).inserted }
        self.peerID = peerID
        self.announceToAll = announceToAll
        self.numWant = numWant
        self.port = port
        self.stats = stats
        self.onPeers = onPeers
        self.key = Data.random(4).be32(0)

        var seen = Set<String>()
        var built: [[Entry]] = []
        for (t, tier) in tiers.enumerated() {
            var row: [Entry] = []
            for raw in tier {
                let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !url.isEmpty, seen.insert(TrackerURLParts.dedupeKey(url)).inserted else { continue }
                let e = Entry(url: url, tier: t, supported: TrackerClient.isSupported(url))
                for h in self.infoHashes { e.hashes[h] = HashState() }
                row.append(e)
            }
            if !row.isEmpty { built.append(announceToAll ? row : row.shuffled()) }
        }
        self.tiers = built
    }

    deinit {
        roundTimer?.cancel()
        for tier in tiers { for e in tier { e.timer?.cancel() } }
    }

    private var allEntries: [Entry] { tiers.flatMap { $0 } }
    private var order: [Entry] { allEntries.filter { $0.supported } }

    // MARK: Public API

    public func start() {
        loop.assertInLoop()
        guard !running else { return }
        running = true
        generation += 1
        completedCalled = false
        completedPending = false
        roundFailures = 0
        roundAgain = false
        recentPeers.removeAll()
        for e in allEntries { e.failures = 0; e.announceAgain = false }
        guard !infoHashes.isEmpty else { return }
        if announceToAll {
            for e in order { announce(e, done: nil) }
        } else {
            runRound(from: 0)
        }
    }

    public func completed() {
        loop.assertInLoop()
        guard running, !completedCalled else { return }
        completedCalled = true
        completedPending = true
        if announceToAll {
            for e in order {
                let needs = e.hashes.values.contains { $0.needStarted || !$0.completedSent }
                guard needs else { continue }
                if e.inFlight { e.announceAgain = true }
                else if e.failures == 0 { announce(e, done: nil) }
                // failing trackers send it with their next (backed-off) attempt
            }
        } else {
            if roundInFlight { roundAgain = true } else { runRound(from: 0) }
        }
    }

    public func stop() {
        loop.assertInLoop()
        guard running else { return }
        running = false
        generation += 1
        roundTimer?.cancel(); roundTimer = nil
        roundNextAt = nil
        roundInFlight = false
        roundAgain = false
        let st = stats()
        let p = port()
        for e in allEntries {
            e.timer?.cancel(); e.timer = nil
            e.nextAnnounceAt = nil
            let wasInFlight = e.inFlight
            e.inFlight = false
            e.announceAgain = false
            guard e.supported else { continue }
            for h in infoHashes {
                guard let hs = e.hashes[h] else { continue }
                if hs.registered || wasInFlight {
                    let req = AnnounceRequest(infoHash: h, peerID: peerID, port: p, uploaded: st.uploaded,
                                              downloaded: st.downloaded, left: st.left, event: .stopped,
                                              numWant: 0, key: key, trackerID: hs.trackerID)
                    client.announce(url: e.url, req) { _ in }
                }
                hs.needStarted = true
                hs.completedSent = false
                hs.registered = false
            }
        }
    }

    public func reannounceNow() {
        loop.assertInLoop()
        guard running, !infoHashes.isEmpty else { return }
        let now = monotonicNow()
        if announceToAll {
            for e in order where !e.inFlight {
                let earliest = earliestAllowed(e)
                if earliest <= now {
                    announce(e, done: nil)
                } else if (e.nextAnnounceAt ?? .infinity) > earliest {
                    schedule(e, after: earliest - now)
                }
            }
        } else {
            guard !roundInFlight, let target = active ?? order.first else { return }
            let earliest = earliestAllowed(target)
            if earliest <= now {
                runRound(from: 0)
            } else if (roundNextAt ?? .infinity) > earliest {
                scheduleRound(after: earliest - now)
            }
        }
    }

    public var statuses: [TrackerStatus] {
        loop.assertInLoop()
        let now = monotonicNow()
        return allEntries.map { e in
            TrackerStatus(url: e.url, tier: e.tier,
                          lastError: e.supported ? e.lastError : "unsupported tracker scheme",
                          seeders: e.seeders, leechers: e.leechers, lastPeerCount: e.lastPeerCount,
                          nextAnnounceIn: e.nextAnnounceAt.map { max(0, $0 - now) } ?? 0,
                          isUpdating: e.inFlight, warning: e.warning)
        }
    }

    public var bestSeeders: Int? { loop.assertInLoop(); return allEntries.compactMap(\.seeders).max() }
    public var bestLeechers: Int? { loop.assertInLoop(); return allEntries.compactMap(\.leechers).max() }

    /// Current tier order (after BEP 12 shuffling / promotion). For tests and UI.
    var tierOrder: [[String]] { tiers.map { $0.map(\.url) } }

    // MARK: Announce one URL (all info hashes)

    /// Returns false if the announce could not be started.
    @discardableResult
    private func announce(_ e: Entry, done: ((Bool) -> Void)?) -> Bool {
        guard running, e.supported, !e.inFlight, !infoHashes.isEmpty else { return false }
        let gen = generation
        e.timer?.cancel(); e.timer = nil
        e.nextAnnounceAt = nil
        e.inFlight = true
        e.announceAgain = false
        e.lastAttemptAt = monotonicNow()
        let st = stats()
        let p = port()
        let round = Round(infoHashes.count)
        for h in infoHashes {
            guard let hs = e.hashes[h] else { round.remaining -= 1; continue }
            let event: TrackerEvent
            if hs.needStarted { event = .started }
            else if completedPending && !hs.completedSent { event = .completed }
            else { event = .none }
            let req = AnnounceRequest(infoHash: h, peerID: peerID, port: p, uploaded: st.uploaded,
                                      downloaded: st.downloaded, left: st.left, event: event,
                                      numWant: numWant, key: key, trackerID: hs.trackerID)
            client.announce(url: e.url, req) { [weak self] result in
                guard let self, self.running, self.generation == gen else { return }
                switch result {
                case .success(let r):
                    hs.registered = true
                    if event == .started {
                        hs.needStarted = false
                        // Started as a seed (or completion happened before `started`
                        // got through): the tracker never saw us leeching.
                        if st.left == 0 || self.completedPending { hs.completedSent = true }
                    }
                    if event == .completed { hs.completedSent = true }
                    if let t = r.trackerID { hs.trackerID = t }
                    round.successes.append(r)
                    round.peers.formUnion(r.peers)
                    self.deliver(r.peers)
                case .failure(let err):
                    round.errors.append(err)
                }
                round.remaining -= 1
                if round.remaining == 0 {
                    self.finish(e, round)
                    done?(!round.successes.isEmpty)
                }
            }
        }
        return true
    }

    private func finish(_ e: Entry, _ round: Round) {
        e.inFlight = false
        if round.successes.isEmpty {
            e.failures += 1
            e.lastError = round.errors.first.map { ($0 as? TrackerError)?.description ?? "\($0)" } ?? "failed"
        } else {
            e.failures = 0
            e.lastError = nil
            e.lastSuccessAt = e.lastAttemptAt
            var interval = 0.0, minInterval = 0.0
            for r in round.successes {
                let i = r.interval > 0 ? Double(r.interval) : defaultInterval
                interval = max(interval, min(max(i, intervalFloor), intervalCeiling))
                minInterval = max(minInterval, r.minInterval.map(Double.init) ?? defaultMinInterval)
            }
            e.interval = interval
            e.minInterval = min(max(minInterval, minIntervalFloor), interval)
            e.seeders = round.successes.compactMap(\.seeders).max()
            e.leechers = round.successes.compactMap(\.leechers).max()
            e.warning = round.successes.compactMap(\.warning).first
            e.lastPeerCount = round.peers.count
        }
        if announceToAll {
            let delay: Double
            if e.failures > 0 { delay = TrackerBackoff.delay(failures: e.failures) }
            else if e.announceAgain { delay = 0 }
            else { delay = e.interval }
            e.announceAgain = false
            schedule(e, after: delay)
        }
    }

    private func schedule(_ e: Entry, after delay: Double) {
        e.timer?.cancel()
        let d = max(0, delay)
        e.nextAnnounceAt = monotonicNow() + d
        e.timer = loop.schedule(after: d) { [weak self, weak e] in
            guard let self, let e else { return }
            e.timer = nil
            self.announce(e, done: nil)
        }
    }

    private func earliestAllowed(_ e: Entry) -> Double {
        guard let last = e.lastAttemptAt else { return -.infinity }
        return last + (e.failures > 0 ? reannounceFailureGap : e.minInterval)
    }

    // MARK: BEP 12 rounds

    private func runRound(from pos: Int) {
        guard running else { return }
        roundTimer?.cancel(); roundTimer = nil
        roundNextAt = nil
        let order = self.order
        guard !order.isEmpty else { return }
        guard pos < order.count else {
            roundInFlight = false
            roundFailures += 1
            active = nil
            scheduleRound(after: TrackerBackoff.delay(failures: roundFailures))
            return
        }
        roundInFlight = true
        let e = order[pos]
        for o in order { o.nextAnnounceAt = nil }
        let gen = generation
        let started = announce(e) { [weak self] ok in
            guard let self, self.running, self.generation == gen else { return }
            if ok {
                self.roundFailures = 0
                self.promote(e)
                self.active = e
                self.roundInFlight = false
                let again = self.roundAgain
                self.roundAgain = false
                self.scheduleRound(after: again ? 0 : e.interval)
            } else {
                self.runRound(from: pos + 1)
            }
        }
        if !started { runRound(from: pos + 1) }
    }

    private func scheduleRound(after delay: Double) {
        roundTimer?.cancel()
        let d = max(0, delay)
        let at = monotonicNow() + d
        roundNextAt = at
        let order = self.order
        // Trackers that the next round will contact (up to the active one).
        let last = active.flatMap { a in order.firstIndex { $0 === a } } ?? (order.count - 1)
        for (i, e) in order.enumerated() { e.nextAnnounceAt = i <= last ? at : nil }
        roundTimer = loop.schedule(after: d) { [weak self] in
            guard let self else { return }
            self.roundTimer = nil
            self.runRound(from: 0)
        }
    }

    private func promote(_ e: Entry) {
        for t in tiers.indices {
            if let i = tiers[t].firstIndex(where: { $0 === e }), i > 0 {
                tiers[t].remove(at: i)
                tiers[t].insert(e, at: 0)
            }
        }
    }

    // MARK: Peers

    private func deliver(_ peers: [PeerAddress]) {
        guard !peers.isEmpty else { return }
        let now = monotonicNow()
        var fresh: [PeerAddress] = []
        fresh.reserveCapacity(peers.count)
        for p in peers {
            if let t = recentPeers[p], now - t < peerRedeliveryWindow { continue }
            recentPeers[p] = now
            fresh.append(p)
        }
        if recentPeers.count > 20_000 {
            recentPeers = recentPeers.filter { now - $0.value < peerRedeliveryWindow }
        }
        if !fresh.isEmpty { onPeers(fresh) }
    }
}
