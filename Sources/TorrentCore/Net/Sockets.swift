import Foundation
import Darwin
import Dispatch

public enum TransportKind: String, Sendable {
    case tcp, utp
}

public struct SocketError: Error, CustomStringConvertible, Sendable {
    public let code: Int32
    public let op: String
    public init(_ op: String, _ code: Int32 = errno) { self.op = op; self.code = code }
    public var description: String { "\(op): \(String(cString: strerror(code))) (\(code))" }
    public static let timedOut = SocketError("connect", ETIMEDOUT)
    public static let closed = SocketError("io", ECONNRESET)
}

/// A reliable, ordered byte stream to a peer. Implemented by TCP (`TCPStream`),
/// uTP (`UTPStream`) and wrapped by MSE/PE encryption (`EncryptedStream`).
///
/// Contract (all members are loop-confined, i.e. touched only on the owning
/// EventLoop's queue):
///  * `onRead` is invoked with each chunk of received bytes, in order.
///  * `onClose` is invoked exactly once when the stream dies (nil = clean EOF).
///    After `close()` is called by the owner, `onClose` is NOT invoked.
///  * `write` never blocks; bytes are queued. `pendingWriteBytes` reports the queue
///    so callers can apply back-pressure. `onWritable` fires when the queue drains
///    below `lowWatermark`.
public protocol ByteStream: AnyObject {
    var onRead: ((Data) -> Void)? { get set }
    var onClose: ((SocketError?) -> Void)? { get set }
    var onWritable: (() -> Void)? { get set }
    var pendingWriteBytes: Int { get }
    var remoteAddress: PeerAddress { get }
    var transport: TransportKind { get }
    var isEncrypted: Bool { get }
    func write(_ data: Data)
    func close()
}

public extension ByteStream {
    var isEncrypted: Bool { false }
    static var lowWatermark: Int { 64 * 1024 }
}

// MARK: - Low level helpers

private func configureSocket(_ fd: Int32, suppressSIGPIPE: Bool = false) throws(SocketError) {
    let flags = fcntl(fd, F_GETFL, 0)
    guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
        throw SocketError("fcntl O_NONBLOCK")
    }
    guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw SocketError("fcntl FD_CLOEXEC") }
    if suppressSIGPIPE, setOpt(fd, SOL_SOCKET, SO_NOSIGPIPE, 1) != 0 {
        throw SocketError("setsockopt SO_NOSIGPIPE")
    }
}

@inline(__always)
@discardableResult
func setOpt(_ fd: Int32, _ level: Int32, _ name: Int32, _ value: Int32) -> Int32 {
    var v = value
    return setsockopt(fd, level, name, &v, socklen_t(MemoryLayout<Int32>.size))
}

/// One 256 KiB receive scratch buffer per serial loop.
final class ReadScratch {
    let size = 256 * 1024
    let ptr: UnsafeMutableRawPointer
    init() { ptr = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 16) }
    deinit { ptr.deallocate() }
}

// MARK: - TCP stream

/// Non-blocking TCP connection driven by DispatchSource read/write events on the loop queue.
public final class TCPStream: ByteStream, @unchecked Sendable {
    public var onRead: ((Data) -> Void)?
    public var onClose: ((SocketError?) -> Void)?
    public var onWritable: (() -> Void)?
    public let remoteAddress: PeerAddress
    public var transport: TransportKind { .tcp }

    let loop: EventLoop
    private(set) var fd: Int32
    private var readSource: (any DispatchSourceRead)?
    private var writeSource: (any DispatchSourceWrite)?
    private var writeSourceActive = false
    private var sourceCancellation: DispatchGroup?
    /// Contiguous outbound buffer; bytes before `outHead` are already written.
    private var outBuf = Data()
    private var outHead = 0
    public var pendingWriteBytes: Int { outBuf.count - outHead }
    private var closed = false

    /// Total bytes moved on this socket (for stats).
    public private(set) var bytesRead: Int64 = 0
    public private(set) var bytesWritten: Int64 = 0

    init(fd: Int32, remote: PeerAddress, loop: EventLoop) {
        self.fd = fd
        self.remoteAddress = remote
        self.loop = loop
        setOpt(fd, IPPROTO_TCP, TCP_NODELAY, 1)
        // Darwin TCP autotuning remains enabled when buffer sizes are left alone.
    }

    /// Start reading. Must be called on the loop after callbacks are installed.
    func start() {
        loop.assertInLoop()
        guard !closed, readSource == nil else { return }
        let cancellation = DispatchGroup()
        sourceCancellation = cancellation
        let rs = DispatchSource.makeReadSource(fileDescriptor: fd, queue: loop.queue)
        cancellation.enter()
        rs.setCancelHandler { cancellation.leave() }
        rs.setEventHandler { [weak self] in self?.handleReadable() }
        readSource = rs
        rs.activate()
        let ws = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: loop.queue)
        cancellation.enter()
        ws.setCancelHandler { cancellation.leave() }
        ws.setEventHandler { [weak self] in self?.flush() }
        writeSource = ws
        // write source starts suspended; resumed when the kernel buffer fills
        if pendingWriteBytes > 0 { flush() }
    }

    private func handleReadable() {
        guard !closed else { return }
        let scratch = loop.readScratch
        // Drain up to a bounded amount per event so one fast peer can't starve others.
        var loops = 0
        while loops < 8 {
            loops += 1
            let n = Darwin.read(fd, scratch.ptr, scratch.size)
            if n > 0 {
                bytesRead += Int64(n)
                let chunk = Data(bytes: scratch.ptr, count: n)
                onRead?(chunk)
                if closed { return }
                if n < scratch.size { return }
            } else if n == 0 {
                fail(nil)
                return
            } else {
                let e = errno
                if e == EINTR { continue }
                if e == EAGAIN || e == EWOULDBLOCK { return }
                fail(SocketError("read", e))
                return
            }
        }
    }

    public func write(_ data: Data) {
        loop.assertInLoop()
        guard !closed, !data.isEmpty else { return }
        if outHead > 0 && outHead >= outBuf.count / 2 {
            outBuf.removeSubrange(0..<outHead)   // compact
            outHead = 0
        }
        outBuf.append(data)
        if !writeSourceActive && readSource != nil { flush() }
    }

    private func flush() {
        guard !closed, pendingWriteBytes > 0 else { return }
        while outHead < outBuf.count {
            let n = outBuf.withUnsafeBytes { raw -> Int in
                Darwin.write(fd, raw.baseAddress!.advanced(by: outHead), raw.count - outHead)
            }
            if n < 0 {
                let e = errno
                if e == EINTR { continue }
                if e == EAGAIN || e == EWOULDBLOCK { armWriteSource(); return }
                fail(SocketError("write", e))
                return
            }
            if n == 0 { armWriteSource(); return }
            outHead += n
            bytesWritten += Int64(n)
        }
        outBuf.removeAll(keepingCapacity: outBuf.count <= 1 << 20)
        outHead = 0
        disarmWriteSource()
        onWritable?()
    }

    private func armWriteSource() {
        if !writeSourceActive, let ws = writeSource {
            writeSourceActive = true
            ws.resume()
        }
    }

    private func disarmWriteSource() {
        if writeSourceActive, let ws = writeSource {
            writeSourceActive = false
            ws.suspend()
        }
    }

    private func fail(_ err: SocketError?) {
        guard !closed else { return }
        teardown()
        let cb = onClose
        clearCallbacks()
        cb?(err)
    }

    public func close() {
        loop.assertInLoop()
        guard !closed else { return }
        teardown()
        clearCallbacks()
    }

    private func clearCallbacks() {
        onRead = nil
        onClose = nil
        onWritable = nil
    }

    private func teardown() {
        closed = true
        outBuf = Data()
        outHead = 0
        let descriptor = fd
        fd = -1
        readSource?.cancel()
        if let ws = writeSource {
            ws.cancel()
            if !writeSourceActive { ws.resume() } // Balance initial inactivity or suspension.
        }
        readSource = nil
        writeSource = nil
        if let cancellation = sourceCancellation {
            cancellation.notify(queue: loop.queue) { Darwin.close(descriptor) }
            sourceCancellation = nil
        } else {
            Darwin.close(descriptor)
        }
    }

    deinit {
        if fd >= 0 { teardown() }
    }

    // MARK: Connect

    /// Open an outgoing TCP connection. `completion` runs on the loop.
    public static func connect(to remote: PeerAddress, loop: EventLoop, timeout: Double = 8,
                               completion: @escaping (Result<TCPStream, SocketError>) -> Void) {
        loop.assertInLoop()
        guard timeout.isFinite, timeout >= 0 else {
            completion(.failure(SocketError("connect timeout", EINVAL)))
            return
        }
        let family = remote.ip.isV4 ? AF_INET : AF_INET6
        let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { completion(.failure(SocketError("socket"))); return }
        do {
            try configureSocket(fd, suppressSIGPIPE: true)
        } catch {
            Darwin.close(fd)
            completion(.failure(error))
            return
        }
        let rc = remote.withSockAddr { Darwin.connect(fd, $0, $1) }
        if rc == 0 {
            let s = TCPStream(fd: fd, remote: remote, loop: loop)
            completion(.success(s))
            return
        }
        let e = errno
        guard e == EINPROGRESS || e == EINTR else {
            Darwin.close(fd)
            completion(.failure(SocketError("connect", e)))
            return
        }
        let pending = PendingConnect(fd: fd, remote: remote, loop: loop, completion: completion)
        pending.arm(timeout: timeout)
    }
}

/// Tracks one in-flight non-blocking connect().
private final class PendingConnect: @unchecked Sendable {
    let fd: Int32
    let remote: PeerAddress
    let loop: EventLoop
    var completion: ((Result<TCPStream, SocketError>) -> Void)?
    var source: (any DispatchSourceWrite)?
    var timer: LoopTimer?
    var outcome: Result<Void, SocketError>?

    init(fd: Int32, remote: PeerAddress, loop: EventLoop,
         completion: @escaping (Result<TCPStream, SocketError>) -> Void) {
        self.fd = fd
        self.remote = remote
        self.loop = loop
        self.completion = completion
    }

    func arm(timeout: Double) {
        let ws = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: loop.queue)
        ws.setEventHandler { [weak self] in self?.connected() }
        ws.setCancelHandler { self.deliverResult() }
        source = ws
        ws.activate()
        timer = loop.schedule(after: timeout) { [weak self] in self?.finish(.failure(.timedOut)) }
    }

    private func connected() {
        var err: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 {
            finish(.failure(SocketError("getsockopt SO_ERROR")))
        } else if err != 0 {
            finish(.failure(SocketError("connect", err)))
        } else {
            finish(.success(()))
        }
    }

    private func finish(_ result: Result<Void, SocketError>) {
        guard outcome == nil else { return }
        outcome = result
        timer?.cancel()
        timer = nil
        source?.cancel()
        source = nil
    }

    private func deliverResult() {
        guard let outcome, let cb = completion else { return }
        completion = nil
        switch outcome {
        case .failure(let error):
            Darwin.close(fd)
            cb(.failure(error))
        case .success:
            cb(.success(TCPStream(fd: fd, remote: remote, loop: loop)))
        }
    }
}

extension TCPStream {
    /// Begin I/O after the owner has installed callbacks.
    public func activate() { start() }
}

// MARK: - TCP listener

/// Accepts incoming TCP connections on IPv4 and IPv6 for a given port.
public final class TCPListener: @unchecked Sendable {
    public var onAccept: ((TCPStream) -> Void)?
    public let port: UInt16
    private let loop: EventLoop
    private var fds: [Int32] = []
    private var sources: [any DispatchSourceRead] = []
    private var acceptRetry: LoopTimer?

    public init(port: UInt16, loop: EventLoop) throws {
        self.loop = loop
        var boundPort = port
        // IPv4
        let fd4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd4 >= 0 else { throw SocketError("socket") }
        do { try configureSocket(fd4) }
        catch { Darwin.close(fd4); throw error }
        setOpt(fd4, SOL_SOCKET, SO_REUSEADDR, 1)
        let any4 = PeerAddress(ip: .v4(0), port: port)
        if any4.withSockAddr({ bind(fd4, $0, $1) }) != 0 {
            let e = errno; Darwin.close(fd4); throw SocketError("bind tcp/\(port)", e)
        }
        if boundPort == 0 { boundPort = Self.localPort(fd4) }
        guard listen(fd4, 512) == 0 else { let e = errno; Darwin.close(fd4); throw SocketError("listen", e) }
        fds.append(fd4)
        // IPv6 (best effort)
        let fd6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        if fd6 >= 0 {
            setOpt(fd6, SOL_SOCKET, SO_REUSEADDR, 1)
            let any6 = PeerAddress(ip: .v6(0, 0), port: boundPort)
            if (try? configureSocket(fd6)) != nil,
               setOpt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, 1) == 0,
               any6.withSockAddr({ bind(fd6, $0, $1) }) == 0, listen(fd6, 512) == 0 {
                fds.append(fd6)
            } else {
                Darwin.close(fd6)
            }
        }
        self.port = boundPort
    }

    public func start() {
        loop.assertInLoop()
        guard sources.isEmpty else { return }
        for fd in fds {
            let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: loop.queue)
            src.setEventHandler { [weak self] in self?.acceptAll(fd) }
            src.setCancelHandler { Darwin.close(fd) }
            sources.append(src)
            src.activate()
        }
    }

    private func acceptAll(_ lfd: Int32) {
        for _ in 0..<64 {
            guard !fds.isEmpty, acceptRetry == nil else { return }
            var storage = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let cfd = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(lfd, $0, &len) }
            }
            if cfd < 0 {
                switch errno {
                case EINTR, ECONNABORTED: continue
                case EAGAIN, EWOULDBLOCK: return
                default: pauseAccepting(); return
                }
            }
            let remote = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { PeerAddress(sockaddr: $0, length: len) }
            }
            guard let remote else { Darwin.close(cfd); continue }
            do { try configureSocket(cfd, suppressSIGPIPE: true) }
            catch { Darwin.close(cfd); pauseAccepting(); return }
            let s = TCPStream(fd: cfd, remote: remote, loop: loop)
            onAccept?(s)
        }
    }

    public func close() {
        loop.assertInLoop()
        stop()
        onAccept = nil
    }

    private func pauseAccepting() {
        for source in sources { source.suspend() }
        acceptRetry = loop.schedule(after: 0.1) { [weak self] in
            guard let self else { return }
            self.acceptRetry = nil
            for source in self.sources { source.resume() }
        }
    }

    private func stop() {
        if sources.isEmpty {
            for fd in fds { Darwin.close(fd) }
        } else {
            for source in sources {
                source.cancel()
                if acceptRetry != nil { source.resume() }
            }
        }
        acceptRetry?.cancel()
        acceptRetry = nil
        sources.removeAll()
        fds.removeAll()
    }

    deinit { stop() }

    static func localPort(_ fd: Int32) -> UInt16 {
        var storage = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard result == 0 else { return 0 }
        return withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { PeerAddress(sockaddr: $0, length: len)?.port ?? 0 }
        }
    }
}

// MARK: - UDP socket

/// A non-blocking UDP socket (one address family). The Session owns one per family
/// on the listen port, shared by DHT and uTP (demultiplexed by first byte), plus
/// ephemeral ones for UDP trackers / NAT-PMP / LSD.
public final class UDPSocket: @unchecked Sendable {
    public var onDatagram: ((Data, PeerAddress) -> Void)?
    public let isV6: Bool
    public private(set) var port: UInt16 = 0
    private let loop: EventLoop
    private var fd: Int32
    private var source: (any DispatchSourceRead)?
    public private(set) var bytesSent: Int64 = 0
    public private(set) var bytesReceived: Int64 = 0

    /// - Parameters:
    ///   - port: 0 for an ephemeral port.
    ///   - reuse: allow multiple sockets on the same port (needed for LSD multicast).
    public init(port: UInt16, v6: Bool, loop: EventLoop, reuse: Bool = false) throws {
        self.loop = loop
        self.isV6 = v6
        fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw SocketError("socket") }
        do {
            try configureSocket(fd)
            if reuse, (setOpt(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0 ||
                       setOpt(fd, SOL_SOCKET, SO_REUSEPORT, 1) != 0) {
                throw SocketError("setsockopt UDP reuse")
            }
            if v6, setOpt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1) != 0 {
                throw SocketError("setsockopt IPV6_V6ONLY")
            }
        } catch {
            Darwin.close(fd)
            fd = -1
            throw error
        }
        setOpt(fd, SOL_SOCKET, SO_RCVBUF, 4 * 1024 * 1024)
        setOpt(fd, SOL_SOCKET, SO_SNDBUF, 2 * 1024 * 1024)
        let bindAddr = PeerAddress(ip: v6 ? .v6(0, 0) : .v4(0), port: port)
        if bindAddr.withSockAddr({ bind(fd, $0, $1) }) != 0 {
            let e = errno; Darwin.close(fd); fd = -1
            throw SocketError("bind udp/\(port)", e)
        }
        self.port = TCPListener.localPort(fd)
    }

    /// Borrowed descriptor, valid on the loop until `close()`.
    public var fileDescriptor: Int32 { fd }

    public func start() {
        loop.assertInLoop()
        guard fd >= 0, source == nil else { return }
        let descriptor = fd
        let src = DispatchSource.makeReadSource(fileDescriptor: fd, queue: loop.queue)
        src.setEventHandler { [weak self] in self?.drain() }
        src.setCancelHandler { Darwin.close(descriptor) }
        source = src
        src.activate()
    }

    private func drain() {
        let scratch = loop.readScratch
        var storage = sockaddr_storage()
        for _ in 0..<64 {
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, scratch.ptr, 65536, 0, $0, &len)
                }
            }
            if n < 0 {
                if errno == EINTR { continue }
                return
            }
            bytesReceived += Int64(n)
            let from = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { PeerAddress(sockaddr: $0, length: len) }
            }
            guard let from else { continue }
            onDatagram?(Data(bytes: scratch.ptr, count: n), from)
            if fd < 0 { return }
        }
    }

    /// Send a datagram. Returns false if the kernel buffer is full (packet dropped).
    @discardableResult
    public func send(_ data: Data, to: PeerAddress) -> Bool {
        loop.assertInLoop()
        guard fd >= 0, to.ip.isV6 == isV6 else { return false }
        let n = data.withUnsafeBytes { raw in
            to.withSockAddr { address, length in
                var sent: Int
                repeat { sent = sendto(fd, raw.baseAddress, raw.count, 0, address, length) }
                while sent < 0 && errno == EINTR
                return sent
            }
        }
        if n > 0 { bytesSent += Int64(n) }
        return n == data.count
    }

    /// Join an IPv4 multicast group (LSD).
    public func joinMulticastV4(_ group: String) {
        loop.assertInLoop()
        guard fd >= 0, !isV6 else { return }
        var mreq = ip_mreq()
        guard inet_pton(AF_INET, group, &mreq.imr_multiaddr) == 1 else { return }
        mreq.imr_interface.s_addr = INADDR_ANY
        if setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size)) == 0 {
            setOpt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, 0)
        }
    }

    public func close() {
        loop.assertInLoop()
        stop()
        onDatagram = nil
    }

    private func stop() {
        guard fd >= 0 else { return }
        let descriptor = fd
        fd = -1
        if let source { source.cancel() } else { Darwin.close(descriptor) }
        source = nil
    }

    deinit { stop() }
}
