# Astor architecture & module contracts

Astor is a BitTorrent client written from scratch in Swift 6 for Apple Silicon.
`TorrentCore` is the engine (portable to iOS/iPadOS: only BSD sockets, Dispatch,
CryptoKit, Foundation, Security — **no AppKit, no `Process`, no third-party deps**).
`astor` is the macOS CLI.

## Threading model (MUST follow)

* One serial `EventLoop` (`Sources/TorrentCore/Core/EventLoop.swift`) owns all
  networking state. Classes bound to it are `final class X: @unchecked Sendable`
  and are only touched on `loop.queue`. Call `loop.assertInLoop()` at public entry
  points.
* Never block the loop: no synchronous DNS, no disk I/O, no sleeping. CPU-heavy
  hashing/disk run on other queues and post back with `loop.execute { }`.
* Timers: `loop.schedule(after:)` / `loop.every(_:)` return a `LoopTimer`. Timers
  retain themselves until they fire (one-shot) or are cancelled, so a discarded
  one-shot handle still fires; keep repeating-timer handles and cancel them on stop.
  Capture `[weak self]` in timer/socket closures.
* Sockets are loop-confined: `start()`, `send()`, `close()`, `activate()` assert they
  run on the loop (DEBUG). Descriptors are closed only after the DispatchSource cancel
  handlers ran (no fd-number reuse while Dispatch still references it); `deinit` is
  safe from any thread.
* Each `EventLoop` owns its receive scratch buffer (several loops may coexist).
* Swift 6 language mode. Closures passed to `loop.execute` are `@Sendable`; capturing
  loop-confined `@unchecked Sendable` objects is fine.

## Foundation (already implemented — use these, do not duplicate)

| File | Provides |
|---|---|
| `Core/EventLoop.swift` | `EventLoop`, `LoopTimer`, `monotonicNow()`, `microsNow32()` |
| `Core/Hashing.swift` | `Hash.sha1/sha256`, `Merkle` (BEP 52), `Bitfield`, `Data.hex`, `Data(hex:)`, `Data.random(n)`, `be16/be32/be64`, `appendBE16/32/64`, `Base32` |
| `Net/Address.swift` | `IPAddress` (.v4/.v6, mapped-v4 normalised), `PeerAddress` (compact 6/18-byte encoding, sockaddr bridging, `parseCompactList`) |
| `Net/Sockets.swift` | `ByteStream` protocol, `TCPStream` (+ `connect`), `TCPListener`, `UDPSocket`, `SocketError`, `TransportKind` |
| `Net/HostResolver.swift` | `HostResolver.resolve(host) { [IPAddress] }` — system DNS + DoH fallback |
| `Bencode/Bencode.swift` | `BValue`, `BDecoder.decode`, `BDecoder.decodePrefix`, `.encoded` |
| `Metainfo/Metainfo.swift` | `Metainfo` (v1/v2/hybrid), `InfoHashes`, `TorrentFile`, `MagnetLink` |
| `Session/Config.swift` | `SessionConfig`, `EncryptionPolicy`, `PeerSource`, `ClientIdentity` |

### `ByteStream` contract
```swift
public protocol ByteStream: AnyObject {
    var onRead: ((Data) -> Void)? { get set }        // in-order chunks
    var onClose: ((SocketError?) -> Void)? { get set } // once; nil error = clean EOF; NOT called after owner's close()
    var onWritable: (() -> Void)? { get set }         // write queue drained
    var pendingWriteBytes: Int { get }
    var remoteAddress: PeerAddress { get }
    var transport: TransportKind { get }              // .tcp / .utp
    var isEncrypted: Bool { get }
    func write(_ data: Data)                          // never blocks; queues
    func close()
}
```
`TCPStream` returned from `TCPStream.connect` / `TCPListener.onAccept` must be
`activate()`d after callbacks are installed.

## UDP port sharing

The Session binds one `UDPSocket` per family on the listen port (same number as
TCP). Incoming datagrams are demultiplexed:
* first byte `0x64` (`'d'`) → DHT (bencoded KRPC)
* otherwise → `UTPManager.handle(_:from:)` (uTP header byte = type<<4 | 1)

UDP trackers, NAT-PMP/PCP, SSDP and LSD use their own sockets.

## Module contracts (to implement)

All modules live under `Sources/TorrentCore/<Module>/` with tests in
`Tests/TorrentCoreTests/<Module>Tests.swift` using **Swift Testing** (`import Testing`,
`@Test`, `#expect`). Public API below is binding; internals are free.

### uTP — BEP 29 (`UTP/`)
```swift
public final class UTPManager: @unchecked Sendable {
    public init(loop: EventLoop, send: @escaping (Data, PeerAddress) -> Void)
    public var onAccept: ((UTPStream) -> Void)?            // incoming connection established
    /// Returns true if the datagram was a uTP packet (consumed).
    @discardableResult public func handle(_ datagram: Data, from: PeerAddress) -> Bool
    public func connect(to: PeerAddress, timeout: Double,
                        completion: @escaping (Result<UTPStream, SocketError>) -> Void)
    /// Max uTP payload bytes per packet (excl. 20-byte header). Default 1200 —
    /// safe for tunnels with MTU 1280-1300. Session may raise it from the path MTU.
    public var maxPayload: Int
    public var connectionCount: Int { get }
    public func closeAll()
}
public final class UTPStream: ByteStream, @unchecked Sendable { ... } // transport == .utp
```
Requirements: SYN/STATE/DATA/FIN/RESET, 16-bit seq/ack wrap, selective ACK
extension, LEDBAT congestion control (target 100 ms, gain, min/max cwnd),
RTT/RTO estimation (RFC 6298 style, min RTO 500 ms), fast retransmit on 3 dup acks
or SACK evidence, receive window advertisement, Nagle-like coalescing,
keep-alive, timeouts, graceful FIN and RESET handling. Connection IDs per BEP 29
(recv_id = send_id ± 1). The manager owns its own timer (e.g. every 50–100 ms).
Must interoperate with libtorrent/uTorrent/qBittorrent/Transmission (libutp).

### DHT — BEP 5, BEP 32 (IPv6), BEP 42 (security), BEP 43 read-only (`DHT/`)
```swift
public final class DHTNode: @unchecked Sendable {
    public init(loop: EventLoop, isV6: Bool, resolver: HostResolver,
                stateFile: URL?, send: @escaping (Data, PeerAddress) -> Void)
    public func start(bootstrap: [String])     // "host:port" list; also loads stateFile nodes
    public func handle(_ datagram: Data, from: PeerAddress)
    /// Iterative get_peers lookup; streams peers as found; then announce_peer to the
    /// closest nodes that returned tokens if `announcePort` != nil (implied_port=1
    /// when `impliedPort`). `onDone` fires when the lookup ends.
    public func getPeers(infoHash: Data, announcePort: UInt16?, impliedPort: Bool,
                         onPeers: @escaping ([PeerAddress]) -> Void, onDone: (() -> Void)?)
    public func addNode(_ addr: PeerAddress)   // BEP 5 PORT message hint / magnet nodes
    public var nodeCount: Int { get }           // nodes in routing table
    public var onExternalAddress: ((IPAddress) -> Void)?  // from "ip" field of replies (BEP 42)
    public func saveState()
    public func stop()
}
```
Requirements: k=8 bucketed routing table with bucket splitting, node liveness
(good/questionable/bad, 15-min ping), token generation with rotating secrets,
answering ping/find_node/get_peers/announce_peer from other nodes (store peers per
infohash with expiry), iterative lookups with α parallelism (use 8 for speed),
transaction IDs + timeouts, BEP 42 node-id generation from the external IP when known,
`ip` key in responses, "v" version key, compact node info (26-byte v4 / 38-byte v6),
`nodes`/`nodes6` and `values`, `want` key. Persist good nodes + node id to `stateFile`
(bencoded). Rate-limit outgoing queries.

### MSE/PE — Message Stream Encryption (`MSE/`)
```swift
public enum MSE {
    /// Outgoing. `skey` = the 20-byte torrent id (InfoHashes.primary).
    /// `initialPayload` = the plaintext BitTorrent handshake, sent as IA.
    /// `allowPlaintext` adds plaintext to crypto_provide; RC4 is always offered.
    /// Completion: the stream to use (EncryptedStream for RC4, or the raw stream if
    /// the peer selected plaintext) and any bytes already received after the
    /// handshake (already decrypted) which the caller must parse first.
    public static func initiate(stream: any ByteStream, skey: Data, initialPayload: Data,
                                allowPlaintext: Bool, loop: EventLoop, timeout: Double,
                                completion: @escaping (Result<(any ByteStream, Data), SocketError>) -> Void)
    /// Incoming. `initialBytes` = bytes already read (they did NOT start with
    /// "\u{13}BitTorrent protocol"). `skeys` returns all 20-byte ids we serve.
    /// Completion: (stream, matched skey, decrypted IA + any further bytes).
    public static func respond(stream: any ByteStream, initialBytes: Data,
                               skeys: @escaping () -> [Data], allowPlaintext: Bool,
                               loop: EventLoop, timeout: Double,
                               completion: @escaping (Result<(any ByteStream, Data, Data), SocketError>) -> Void)
}
public final class EncryptedStream: ByteStream, @unchecked Sendable { ... } // isEncrypted == true
```
Spec: 768-bit DH prime P (the standard MSE prime), G=2, 160-bit private keys,
PadA/PadB 0–512 random bytes, `HASH('req1', S)`, `HASH('req2', SKEY) xor HASH('req3', S)`,
VC = 8 zero bytes, crypto_provide bitfield (0x01 plaintext, 0x02 RC4), RC4 keys
`HASH('keyA', S, SKEY)` / `HASH('keyB', S, SKEY)` with first 1024 bytes discarded,
synchronisation scanning for VC / req1 within the 532-byte window, len(PadC)/len(PadD),
IA. Needs a minimal big-integer modular exponentiation (implement, no deps).

### Trackers — BEP 3, 7, 12, 15, 23, 41, 48 (`Tracker/`)
```swift
public enum TrackerEvent: String, Sendable { case none = "", started, completed, stopped }
public struct AnnounceRequest: Sendable {
    public var infoHash: Data; public var peerID: Data; public var port: UInt16
    public var uploaded: Int64; public var downloaded: Int64; public var left: Int64
    public var event: TrackerEvent; public var numWant: Int; public var key: UInt32
}
public struct AnnounceResponse: Sendable {
    public var interval: Int; public var minInterval: Int?
    public var peers: [PeerAddress]; public var seeders: Int?; public var leechers: Int?
    public var warning: String?
}
public final class TrackerClient: @unchecked Sendable {   // stateless transport, shared by all torrents
    public init(loop: EventLoop, resolver: HostResolver)
    public func announce(url: String, _ req: AnnounceRequest,
                         completion: @escaping (Result<AnnounceResponse, any Error>) -> Void)
    public func scrape(url: String, infoHashes: [Data],
                       completion: @escaping (Result<[Data: (seeders: Int, completed: Int, leechers: Int)], any Error>) -> Void)
}
public struct TrackerStatus: Sendable {
    public var url: String; public var tier: Int; public var lastError: String?
    public var seeders: Int?; public var leechers: Int?; public var lastPeerCount: Int
    public var nextAnnounceIn: Double; public var isUpdating: Bool
}
public final class TrackerManager: @unchecked Sendable {   // one per torrent
    public init(loop: EventLoop, client: TrackerClient, tiers: [[String]],
                infoHashes: [Data], peerID: Data, announceToAll: Bool, numWant: Int,
                port: @escaping () -> UInt16,
                stats: @escaping () -> (uploaded: Int64, downloaded: Int64, left: Int64),
                onPeers: @escaping ([PeerAddress]) -> Void)
    public func start()            // event=started
    public func completed()        // event=completed
    public func stop()             // event=stopped (best effort), cancels timers
    public func reannounceNow()
    public var statuses: [TrackerStatus] { get }
    public var bestSeeders: Int? { get }; public var bestLeechers: Int? { get }
}
```
HTTP(S) via URLSession (`compact=1&no_peer_id=1&supportcrypto=1`, `numwant`,
`key`, `ipv6=` not required; percent-encode raw bytes), parse `peers` (compact &
dict forms), `peers6`, `failure reason`, `warning message`, `interval`,
`min interval`, `complete`/`incomplete`. UDP (BEP 15): connect id cache (1 min),
transaction ids, retransmit (use 4 s, 8 s, then fail — faster than spec's 15·2ⁿ),
IPv4 and IPv6 responses, BEP 41 URL path option, scrape. Announce each info hash
in `infoHashes` (hybrid torrents announce both the v1 and truncated v2 hash).
Honour intervals; retry failures with backoff (e.g. 30 s, 60 s, 120 s… max 30 min).
When `announceToAll`, announce to every URL in every tier concurrently; otherwise
BEP 12 tier semantics.

### NAT traversal + LSD (`NAT/`, `LSD/`)
```swift
public struct PortMappingStatus: Sendable {
    public var method: String          // "PCP", "NAT-PMP", "UPnP"
    public var proto: String           // "TCP" / "UDP"
    public var internalPort: UInt16; public var externalPort: UInt16?
    public var externalAddress: IPAddress?; public var error: String?
}
public final class PortMapper: @unchecked Sendable {
    public init(loop: EventLoop)
    public func start(port: UInt16)    // maps TCP+UDP; renews before lease expiry
    public func stop()                 // best-effort delete mappings
    public var statuses: [PortMappingStatus] { get }
    public var externalAddress: IPAddress? { get }
    public var onChange: (() -> Void)?
    public static func defaultGateway() -> IPAddress?   // sysctl route table
}
public final class LocalPeerDiscovery: @unchecked Sendable {   // BEP 14
    public init(loop: EventLoop, port: UInt16)
    public func start(); public func stop()
    public func announce(infoHashes: [Data])      // hex, rate-limited (≥ 5 min per hash)
    public var onPeer: ((Data /*infohash*/, PeerAddress) -> Void)?
}
```
NAT-PMP (RFC 6886) and PCP (RFC 6887) to the default gateway on UDP 5351; UPnP
IGD v1/v2 via SSDP M-SEARCH → rootDesc.xml → WANIPConnection/WANPPPConnection
`AddPortMapping` / `GetExternalIPAddress` / `DeletePortMapping` SOAP (URLSession for
HTTP; XMLParser is fine). Lease 1 h, renew at 50 %.

## Integration notes (learned while merging)

* Incoming connections: if the first bytes are not a plaintext handshake prefix, the
  session starts `MSE.respond` immediately (the MSE initiator only sends Ya+PadA and then
  waits, so the responder must not wait for more than 96 bytes).
* MSE responder selects RC4 whenever offered (hides payload from DPI).
* Hybrid torrents announce both the v1 hash and the truncated v2 hash (trackers + DHT).
* v2-only torrents from `btmh` magnets fetch piece layers with BEP 52 hash requests and
  verify them against each file's pieces root before downloading that file.
* Disk and hash queues run at `.utility` QoS; the network loop at `.userInitiated`.

## Core (Session / Torrent / Peer / Storage / PiecePicker) — owned by the lead

`Session` owns the loop, listen sockets, UDP demux, DHT, uTP, PortMapper, LSD,
TrackerClient and all `Torrent`s. `Torrent` owns storage, picker, peers, trackers.
`PeerConnection` speaks the wire protocol (BEP 3, 6 fast, 10 extensions, 9 metadata,
11 PEX, 21 upload-only, 52 v2 hash messages, 54 lt_donthave, 55 holepunch).
