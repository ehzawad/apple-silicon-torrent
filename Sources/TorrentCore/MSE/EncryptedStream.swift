import Foundation

/// A `ByteStream` that RC4-encrypts everything written and RC4-decrypts
/// everything read, on top of an inner stream (TCP or uTP), after a successful
/// MSE/PE handshake that selected RC4.
///
/// Loop-confined like every `ByteStream`. It takes over the inner stream's
/// `onRead`/`onClose`/`onWritable`; the owner must only use this wrapper.
/// `onClose` fires exactly once when the inner stream dies and never after the
/// owner calls `close()`.
public final class EncryptedStream: ByteStream, @unchecked Sendable {
    public var onRead: ((Data) -> Void)?
    public var onClose: ((SocketError?) -> Void)?
    public var onWritable: (() -> Void)?

    /// The wrapped transport stream.
    public let inner: any ByteStream
    public var pendingWriteBytes: Int { inner.pendingWriteBytes }
    public var remoteAddress: PeerAddress { inner.remoteAddress }
    public var transport: TransportKind { inner.transport }
    public var isEncrypted: Bool { true }

    private let loop: EventLoop
    private let encryptor: RC4
    private let decryptor: RC4
    private var closed = false

    /// Plaintext bytes moved through the cipher (for stats/tests).
    public private(set) var bytesEncrypted: Int64 = 0
    public private(set) var bytesDecrypted: Int64 = 0

    /// `encryptor`/`decryptor` must already be positioned right after the
    /// handshake bytes they processed (MSE keeps one continuous RC4 stream per
    /// direction for the whole connection).
    init(inner: any ByteStream, encryptor: RC4, decryptor: RC4, loop: EventLoop) {
        self.inner = inner
        self.encryptor = encryptor
        self.decryptor = decryptor
        self.loop = loop
        inner.onRead = { [weak self] chunk in self?.handleRead(chunk) }
        inner.onClose = { [weak self] err in self?.handleClose(err) }
        inner.onWritable = { [weak self] in
            guard let self, !self.closed else { return }
            self.onWritable?()
        }
    }

    private func handleRead(_ chunk: Data) {
        guard !closed, !chunk.isEmpty else { return }
        var d = chunk
        d.withUnsafeMutableBytes { decryptor.process($0) }
        bytesDecrypted += Int64(d.count)
        onRead?(d)
    }

    private func handleClose(_ err: SocketError?) {
        guard !closed else { return }
        closed = true
        let cb = onClose
        clearCallbacks()
        cb?(err)
    }

    public func write(_ data: Data) {
        loop.assertInLoop()
        guard !closed, !data.isEmpty else { return }
        var d = data
        d.withUnsafeMutableBytes { encryptor.process($0) }
        bytesEncrypted += Int64(d.count)
        inner.write(d)
    }

    public func close() {
        loop.assertInLoop()
        guard !closed else { return }
        closed = true
        clearCallbacks()
        inner.onRead = nil
        inner.onClose = nil
        inner.onWritable = nil
        inner.close()
    }

    private func clearCallbacks() {
        onRead = nil
        onClose = nil
        onWritable = nil
    }
}
