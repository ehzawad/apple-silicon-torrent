import Foundation
import Dispatch

/// Threading model for the whole engine
/// ------------------------------------
/// All networking state (sockets, peers, torrents, DHT, uTP, trackers) is confined
/// to ONE serial dispatch queue owned by an `EventLoop`, exactly like libtorrent's
/// single network thread. Objects bound to the loop are `@unchecked Sendable` and
/// must only be touched from `loop.queue`. CPU heavy work (SHA-1/SHA-256 piece
/// verification) and disk I/O run on separate queues and post results back with
/// `loop.execute { ... }`.
///
/// This keeps the hot path lock-free, avoids actor hops per packet, and is fully
/// portable to iOS/iPadOS (Dispatch is available everywhere).
public final class EventLoop: @unchecked Sendable {
    public let queue: DispatchQueue
    private let key = DispatchSpecificKey<UInt8>()
    lazy var readScratch = ReadScratch()

    public init(label: String = "astor.net") {
        queue = DispatchQueue(label: label, qos: .userInitiated)
        queue.setSpecific(key: key, value: 1)
    }

    /// True when the caller is already running on this loop's queue.
    public var inLoop: Bool { DispatchQueue.getSpecific(key: key) == 1 }

    /// Run `work` on the loop (asynchronously, always).
    public func execute(_ work: @escaping @Sendable () -> Void) {
        queue.async(execute: work)
    }

    /// Run `work` on the loop now if already on it, otherwise asynchronously.
    public func run(_ work: @escaping @Sendable () -> Void) {
        if inLoop { work() } else { queue.async(execute: work) }
    }

    /// Synchronize with the loop, or execute inline when already on it.
    public func sync<T>(_ work: () throws -> T) rethrows -> T {
        if inLoop { return try work() }
        return try queue.sync(execute: work)
    }

    /// One-shot timer. Retains itself until it fires or is cancelled; the handle may be discarded.
    @discardableResult
    public func schedule(after seconds: Double, _ work: @escaping @Sendable () -> Void) -> LoopTimer {
        let t = LoopTimer(queue: queue, interval: nil, delay: seconds, work: work)
        t.start()
        return t
    }

    /// Repeating timer. Keep the returned handle alive while it should fire.
    @discardableResult
    public func every(_ seconds: Double, leeway: Double = 0.05, _ work: @escaping @Sendable () -> Void) -> LoopTimer {
        let t = LoopTimer(queue: queue, interval: seconds, delay: seconds, leeway: leeway, work: work)
        t.start()
        return t
    }

    public func assertInLoop(file: StaticString = #fileID, line: UInt = #line) {
        #if DEBUG
        dispatchPrecondition(condition: .onQueue(queue))
        #endif
    }
}

/// A cancellable timer backed by a DispatchSourceTimer on the loop's queue.
public final class LoopTimer: @unchecked Sendable {
    private let source: any DispatchSourceTimer
    /// Self-retain while scheduled so a discarded one-shot handle still fires. Released
    /// by the cancel handler, which Dispatch runs on the loop queue after `cancel()`.
    private var keepAlive: LoopTimer?

    init(queue: DispatchQueue, interval: Double?, delay: Double, leeway: Double = 0.01,
         work: @escaping @Sendable () -> Void) {
        source = DispatchSource.makeTimerSource(queue: queue)
        let lw = DispatchTimeInterval.microseconds(Int(max(0, leeway) * 1_000_000))
        if let interval {
            source.schedule(deadline: .now() + delay, repeating: interval, leeway: lw)
        } else {
            source.schedule(deadline: .now() + delay, repeating: .never, leeway: lw)
        }
        source.setEventHandler { [weak self] in
            guard let self, !self.source.isCancelled else { return }
            if interval == nil { self.cancel() }
            work()
        }
    }

    fileprivate func start() {
        keepAlive = self
        source.setCancelHandler { [weak self] in self?.keepAlive = nil }
        source.resume()
    }

    public func cancel() {
        source.cancel()
    }

    deinit { source.cancel() }
}

/// Monotonic awake time in seconds, on the same time base as DispatchTime.
@inline(__always)
public func monotonicNow() -> Double {
    Double(clock_gettime_nsec_np(CLOCK_UPTIME_RAW)) / 1_000_000_000
}

/// Microsecond timestamp used by uTP (wraps at 2^32).
@inline(__always)
public func microsNow32() -> UInt32 {
    UInt32(truncatingIfNeeded: clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1_000)
}
