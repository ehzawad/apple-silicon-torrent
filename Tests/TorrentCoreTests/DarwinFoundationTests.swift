import Darwin
import Dispatch
import Foundation
import Testing
@testable import TorrentCore

@Suite(.serialized)
struct DarwinFoundationTests {
    @Test func tcpConnectAcceptAndDrainAfterBackpressure() throws {
        let loop = EventLoop()
        let listener = try TCPListener(port: 0, loop: loop)
        let accepted = DispatchSemaphore(value: 0)
        let connected = DispatchSemaphore(value: 0)
        let received = DispatchSemaphore(value: 0)
        let data = Data((0..<(16 * 1024)).map { UInt8(truncatingIfNeeded: $0 / 23) })
        let target = Data(repeating: 0xA5, count: 4 * 1024 * 1024) + data
        let remote = PeerAddress(ip: .v4(0x7f000001), port: listener.port)
        var reader: TCPStream?
        var writer: TCPStream?
        var result = Data()
        var ownerCloseCalls = 0
        defer {
            loop.sync {
                reader?.close()
                writer?.close()
                listener.close()
            }
        }
        loop.sync {
            listener.onAccept = { stream in
                reader = stream
                accepted.signal()
            }
            listener.start()
            listener.start()
            TCPStream.connect(to: remote, loop: loop) { outcome in
                defer { connected.signal() }
                guard case .success(let stream) = outcome else {
                    Issue.record("Unexpected connect outcome: \(outcome)")
                    return
                }
                writer = stream
                #expect(fcntl(stream.fd, F_GETFL) & O_NONBLOCK != 0)
                #expect(fcntl(stream.fd, F_GETFD) & FD_CLOEXEC != 0)
                var noSIGPIPE: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                #expect(getsockopt(stream.fd, SOL_SOCKET, SO_NOSIGPIPE, &noSIGPIPE, &length) == 0)
                #expect(noSIGPIPE == 1)
                #expect(setOpt(stream.fd, SOL_SOCKET, SO_SNDBUF, 64 * 1024) == 0)
                stream.onClose = { _ in ownerCloseCalls += 1 }
                stream.activate()
                stream.activate()
                stream.write(target)
                #expect(stream.pendingWriteBytes > 0)
            }
        }
        #expect(connected.wait(timeout: .now() + 4) == .success)
        #expect(accepted.wait(timeout: .now() + 4) == .success)
        let descriptors = try loop.sync {
            let writer = try #require(writer)
            let reader = try #require(reader)
            reader.onRead = { chunk in
                result.append(chunk)
                if result.count >= target.count { received.signal() }
            }
            reader.activate()
            return (writer.fd, reader.fd)
        }
        #expect(received.wait(timeout: .now() + 4) == .success)
        loop.sync {
            #expect(result == target)
            #expect(writer?.pendingWriteBytes == 0)
            writer?.close()
            reader?.close()
            #expect(ownerCloseCalls == 0)
            // Both descriptors must still be live during the closing queue turn.
            #expect(fcntl(descriptors.0, F_GETFD) >= 0)
            #expect(fcntl(descriptors.1, F_GETFD) >= 0)
        }
        // Eventual closure isn't asserted by fd number: with suites running in parallel,
        // another test may legitimately reuse the number right after Dispatch closes it.
        loop.sync {
            #expect(writer?.fd == -1)
            #expect(reader?.fd == -1)
        }
    }

    @Test(arguments: [false, true])
    func tcpConnectReportsRefusalOrTimeout(keepBound: Bool) throws {
        let loop = EventLoop()
        // On Darwin a bound TCP port without listen() can silently drop the SYN.
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        try #require(fd >= 0)
        let loopback = IPAddress.v4(0x7f000001)
        let bindAddress = PeerAddress(ip: loopback, port: 0)
        let bound = bindAddress.withSockAddr { bind(fd, $0, $1) }
        let port = TCPListener.localPort(fd)
        if !keepBound { Darwin.close(fd) }
        defer { if keepBound { Darwin.close(fd) } }
        try #require(bound == 0)
        try #require(port != 0)
        let completed = DispatchSemaphore(value: 0)
        var completions = 0
        loop.sync {
            TCPStream.connect(to: PeerAddress(ip: loopback, port: port), loop: loop, timeout: 0.1) { outcome in
                if case .failure(let error) = outcome {
                    if keepBound { #expect(error.code == ETIMEDOUT || error.code == ECONNREFUSED) }
                    else { #expect(error.code == ECONNREFUSED) }
                } else {
                    Issue.record("Connection unexpectedly succeeded")
                }
                completions += 1
                completed.signal()
            }
        }
        #expect(completed.wait(timeout: .now() + 2) == .success)
        #expect(completed.wait(timeout: .now() + 0.2) == .timedOut)
        loop.sync { #expect(completions == 1) }
    }

    @Test(arguments: [false, true])
    func udpRoundTripWithCloseInCallback(v6: Bool) throws {
        let loop = EventLoop()
        let receiver = try UDPSocket(port: 0, v6: v6, loop: loop)
        let sender = try UDPSocket(port: 0, v6: v6, loop: loop)
        let ip: IPAddress = v6 ? .v6(0, 1) : .v4(0x7f000001)
        let delivered = DispatchSemaphore(value: 0)
        defer { loop.sync { receiver.close(); sender.close() } }
        loop.sync {
            let descriptor = receiver.fileDescriptor
            receiver.onDatagram = { data, source in
                #expect(data.isEmpty)
                #expect(source == PeerAddress(ip: ip, port: sender.port))
                receiver.close()
                #expect(receiver.fileDescriptor == -1)
                #expect(fcntl(descriptor, F_GETFD) >= 0)
                delivered.signal()
            }
            receiver.start()
            receiver.start()
            #expect(sender.send(Data(), to: PeerAddress(ip: ip, port: receiver.port)))
        }
        #expect(delivered.wait(timeout: .now() + 2) == .success)
        loop.sync { #expect(receiver.bytesReceived == 0) }
    }

    @Test func abandoningUnstartedListenerReleasesPort() throws {
        let loop = EventLoop()
        let port: UInt16
        do {
            let listener = try TCPListener(port: 0, loop: loop)
            port = listener.port
            try #require(port != 0)
        }
        let replacement = try TCPListener(port: port, loop: loop)
        loop.sync { replacement.close() }
    }

    @Test func cancelledTimerRemainsQuiet() {
        let loop = EventLoop()
        let fired = DispatchSemaphore(value: 0)
        let timer = loop.schedule(after: 0.05) { fired.signal() }
        DispatchQueue.concurrentPerform(iterations: 32) { _ in timer.cancel() }
        #expect(fired.wait(timeout: .now() + 0.1) == .timedOut)
    }

    @Test func addressLengthAndResolverAreConsistent() throws {
        let ip = try #require(IPAddress("::1"))
        let address = PeerAddress(ip: ip, port: 65534)
        address.withSockAddr { pointer, length in
            #expect(PeerAddress(sockaddr: pointer, length: length) == address)
            #expect(PeerAddress(sockaddr: pointer, length: 16) == nil)
        }
        let hasLoopback = HostResolver.getaddrinfo("localhost").contains { $0.isLoopback }
        #expect(hasLoopback)
    }

    @Test func fragmentedPeerWireWithNonzeroDataIndices() throws {
        let expected = Wire.Handshake(reserved: .ours(v2: true),
                                      infoHash: Data(repeating: 0x77, count: 20),
                                      peerID: Data(repeating: 0x99, count: 20))
        let block = Data([1, 2, 3, 4])
        let wire = Data([0xFF]) + expected.encoded + Wire.keepAlive
            + Wire.pieceHeader(piece: 42, offset: 16_384, length: block.count) + block
        let input = wire.dropFirst()
        try #require(input.startIndex != 0)
        #expect(Wire.Handshake.looksLikeHandshakePrefix(input))
        var parser = MessageParser()
        parser.append(input.prefix(Wire.handshakeLength + 5))
        let handshake = parser.take(Wire.handshakeLength)
        #expect(Wire.Handshake.parse(try #require(handshake))?.infoHash == expected.infoHash)
        guard case .keepAlive? = try parser.next() else { Issue.record("Missing keepalive"); return }
        #expect(try parser.next() == nil)
        parser.append(input.dropFirst(Wire.handshakeLength + 5))
        guard case .piece(let index, let offset, let content)? = try parser.next() else {
            Issue.record("Missing piece")
            return
        }
        #expect(index == 42)
        #expect(offset == 16_384)
        #expect(content == block)
        #expect(parser.buffered == 0)
    }

    @Test func rejectsMalformedControlAndHashFrames() {
        let bad = [
            Data([0, 0, 0, 2, Wire.MessageID.choke.rawValue, 7]),
            Wire.pieceHeader(piece: 0, offset: 0, length: 0),
            Wire.hashMessage(.hashReject, root: Data(repeating: 0, count: 32), baseLayer: 0,
                             index: 0, length: 2, proofLayers: 0, hashes: Data([1])),
            Wire.hashMessage(.hashes, root: Data(repeating: 0, count: 32), baseLayer: 0,
                             index: 0, length: 2, proofLayers: 0, hashes: Data([1]))
        ]
        for frame in bad {
            var parser = MessageParser()
            parser.append(frame)
            #expect(throws: MessageParser.ParseError.self) { try parser.next() }
        }
    }
}
