import Foundation
import Darwin
import TorrentCore

// MARK: - Formatting helpers

func fmtBytes(_ n: Double) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"]
    var v = n, i = 0
    while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? "\(Int(v)) B" : String(format: "%.2f %@", v, units[i])
}
func fmtRate(_ n: Double) -> String { fmtBytes(n) + "/s" }
func fmtETA(_ s: Double?) -> String {
    guard let s, s.isFinite, s > 0 else { return "∞" }
    let t = Int(s)
    if t >= 86400 { return "\(t / 86400)d \(t % 86400 / 3600)h" }
    if t >= 3600 { return "\(t / 3600)h \(t % 3600 / 60)m" }
    return "\(t / 60)m \(t % 60)s"
}
func bar(_ p: Double, width: Int = 40) -> String {
    let filled = Int((p * Double(width)).rounded(.down))
    return String(repeating: "█", count: max(0, min(width, filled))) + String(repeating: "░", count: max(0, width - filled))
}
func pad(_ s: String, _ n: Int) -> String { s.count >= n ? String(s.prefix(n)) : s + String(repeating: " ", count: n - s.count) }

let isTTY = isatty(STDOUT_FILENO) != 0
func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

// MARK: - Argument parsing

struct Options {
    var command = ""
    var target = ""
    var output: URL = SessionConfig.defaultDownloadDirectory
    var port: UInt16 = 0
    var encryption: EncryptionPolicy = .prefer
    var utp = true, dht = true, pex = true, lsd = true, upnp = true, extraTrackers = true, tcp = true
    var preferUTP = false
    var sequential = false
    var seed = false
    var peers: [String] = []
    var maxPeers = 200
    var select: Set<Int>?
    var verbose = false
    var stateDir: URL = SessionConfig.defaultStateDirectory
    var downLimit = 0, upLimit = 0
    var exitAfter: Double = 0
    var createOut: String?
    var createVersion: TorrentVersion = .hybrid
    var trackers: [String] = []
    var webSeeds: [String] = []
    var pieceKiB: Int?
    var isPrivate = false
    var comment: String?
}

func usage() -> Never {
    print("""
    astor — a BitTorrent client for Apple Silicon (v\(ClientIdentity.version))

    USAGE
      astor download <file.torrent | magnet:?...> [options]
      astor info <file.torrent>
      astor create <file|dir> [-o out.torrent] [--v1|--v2] [--tracker URL]… [--web-seed URL]… [--piece-size KiB] [--private] [--comment TEXT]
      astor doctor                 diagnose why torrents are slow on this network

    DOWNLOAD OPTIONS
      -o, --output DIR             save directory (default ~/Downloads)
      -p, --port N                 listen port (TCP+UDP; default: random, remembered)
      -e, --encryption MODE        prefer (default) | require | disabled
          --sequential             download in order (streaming)
          --seed                   keep seeding after the download completes
          --select 0,2,5           only download these file indices (see `astor info`)
          --peer IP:PORT           add a peer manually (repeatable)
          --max-peers N            connections per torrent (default 200)
          --down-limit KiB/s       --up-limit KiB/s
          --no-utp --no-tcp --prefer-utp --no-dht --no-pex --no-lsd --no-upnp --no-extra-trackers
          --state DIR              state directory (resume data, DHT nodes)
          --exit-after SECONDS     stop after N seconds (benchmarking)
      -v, --verbose
    """)
    exit(2)
}

func parseArgs() -> Options {
    var o = Options()
    var args = Array(CommandLine.arguments.dropFirst())
    guard !args.isEmpty else { usage() }
    o.command = args.removeFirst()
    func value(_ name: String) -> String {
        guard !args.isEmpty else { err("missing value for \(name)"); exit(2) }
        return args.removeFirst()
    }
    while !args.isEmpty {
        let a = args.removeFirst()
        switch a {
        case "-o", "--output":
            let v = (value(a) as NSString).expandingTildeInPath
            o.output = URL(fileURLWithPath: v, isDirectory: true)
            o.createOut = v
        case "--v1": o.createVersion = .v1
        case "--v2": o.createVersion = .v2
        case "--tracker": o.trackers.append(value(a))
        case "--web-seed": o.webSeeds.append(value(a))
        case "--piece-size": o.pieceKiB = Int(value(a))
        case "--private": o.isPrivate = true
        case "--comment": o.comment = value(a)
        case "-p", "--port": o.port = UInt16(value(a)) ?? 0
        case "-e", "--encryption":
            guard let e = EncryptionPolicy(rawValue: value(a)) else { err("encryption must be prefer|require|disabled"); exit(2) }
            o.encryption = e
        case "--sequential": o.sequential = true
        case "--seed": o.seed = true
        case "--select": o.select = Set(value(a).split(separator: ",").compactMap { Int($0) })
        case "--peer": o.peers.append(value(a))
        case "--max-peers": o.maxPeers = Int(value(a)) ?? 200
        case "--down-limit": o.downLimit = (Int(value(a)) ?? 0) * 1024
        case "--up-limit": o.upLimit = (Int(value(a)) ?? 0) * 1024
        case "--no-utp": o.utp = false
        case "--no-tcp": o.tcp = false
        case "--prefer-utp": o.preferUTP = true
        case "--no-dht": o.dht = false
        case "--no-pex": o.pex = false
        case "--no-lsd": o.lsd = false
        case "--no-upnp": o.upnp = false
        case "--no-extra-trackers": o.extraTrackers = false
        case "--state": o.stateDir = URL(fileURLWithPath: (value(a) as NSString).expandingTildeInPath, isDirectory: true)
        case "--exit-after": o.exitAfter = Double(value(a)) ?? 0
        case "-v", "--verbose": o.verbose = true
        case "-h", "--help": usage()
        default:
            if a.hasPrefix("-") { err("unknown option \(a)"); usage() }
            o.target = a
        }
    }
    return o
}

// MARK: - Commands

func cmdInfo(_ o: Options) {
    guard let data = FileManager.default.contents(atPath: o.target) else { err("cannot read \(o.target)"); exit(1) }
    do {
        let mi = try Metainfo(torrentFile: data)
        print("Name:          \(mi.name)")
        print("Version:       \(mi.version.rawValue)\(mi.isPrivate ? "  (private)" : "")")
        if let v1 = mi.infoHashes.v1 { print("Info hash v1:  \(v1.hex)") }
        if let v2 = mi.infoHashes.v2 { print("Info hash v2:  \(v2.hex)") }
        print("Size:          \(fmtBytes(Double(mi.contentLength))) in \(mi.files.filter { !$0.isPadding }.count) file(s)")
        print("Pieces:        \(mi.pieceCount) × \(fmtBytes(Double(mi.pieceLength)))")
        if mi.version != .v1 { print("Piece layers:  \(mi.validatePieceLayers() ? "valid" : "INVALID")") }
        if let c = mi.createdBy { print("Created by:    \(c)") }
        if let c = mi.comment { print("Comment:       \(c)") }
        print("Trackers:")
        for (i, tier) in mi.announceTiers.enumerated() { for t in tier { print("  [\(i)] \(t)") } }
        if !mi.webSeeds.isEmpty { print("Web seeds:"); for w in mi.webSeeds { print("  \(w)") } }
        print("Files:")
        var idx = 0
        for f in mi.files where !f.isPadding {
            print("  \(pad(String(idx), 4)) \(pad(fmtBytes(Double(f.length)), 12)) \(f.path.joined(separator: "/"))")
            idx += 1
        }
    } catch {
        err("\(error)"); exit(1)
    }
}

final class Dashboard: @unchecked Sendable {
    var lastLines = 0
    let verbose: Bool
    init(verbose: Bool) { self.verbose = verbose }

    func render(_ s: SessionStatus, _ ts: [TorrentStatus]) {
        var lines: [String] = []
        for t in ts {
            let pct = String(format: "%5.1f%%", t.progress * 100)
            lines.append("\u{1B}[1m\(t.name)\u{1B}[0m")
            lines.append("  \(bar(t.progress)) \(pct)  \(t.state.rawValue.uppercased())  \(t.version.map { $0.rawValue } ?? "")")
            lines.append("  ↓ \(pad(fmtRate(t.downloadRate), 13)) ↑ \(pad(fmtRate(t.uploadRate), 13)) ETA \(fmtETA(t.eta))   \(fmtBytes(Double(t.completedBytes))) / \(fmtBytes(Double(t.wantedBytes)))")
            let sw = [t.trackerSeeders.map { "S:\($0)" }, t.trackerLeechers.map { "L:\($0)" }].compactMap { $0 }.joined(separator: " ")
            lines.append("  peers \(t.connectedPeers) (seeds \(t.connectedSeeds), unchoking us \(t.unchokedUs), in \(t.incomingPeers))  connecting \(t.connectingPeers)  known \(t.knownPeers)  swarm \(sw.isEmpty ? "?" : sw)")
            let src = PeerSource.allCases.compactMap { s in t.knownBySource[s].map { "\(s.rawValue) \($0)" } }.joined(separator: ", ")
            lines.append("  sources: \(src.isEmpty ? "-" : src)   encrypted \(t.encryptedPeers)  uTP \(t.utpPeers)\(t.webSeeds > 0 ? "  web seeds \(t.webSeeds) ↓\(fmtRate(t.webSeedRate))" : "")")
            lines.append("  pieces \(t.piecesHave)/\(t.pieceCount) × \(fmtBytes(Double(t.pieceLength)))  copies \(String(format: "%.2f", t.distributedCopies))  wasted \(fmtBytes(Double(t.wastedBytes)))  hashfail \(t.hashFailures)")
            if let e = t.error { lines.append("  \u{1B}[31merror: \(e)\u{1B}[0m") }
            if verbose {
                let working = t.trackers.filter { $0.lastError == nil && $0.lastPeerCount > 0 }.count
                lines.append("  trackers: \(working)/\(t.trackers.count) answering")
                for p in t.topPeers.prefix(8) {
                    lines.append("    \(pad(p.address, 24)) \(pad(p.client, 20)) \(pad(p.flags, 7)) ↓\(pad(fmtRate(p.downloadRate), 12)) ↑\(pad(fmtRate(p.uploadRate), 12)) \(Int(p.progress * 100))%")
                }
            }
        }
        let pm = s.portMappings.first { $0.error == nil && $0.externalPort != nil }
        lines.append("  ── port \(s.listenPort)  ext \(s.externalIP ?? "?")  \(pm.map { "mapped via \($0.method)" } ?? "not mapped")  DHT \(s.dhtNodesV4)\(s.hasIPv6 ? "/\(s.dhtNodesV6)" : "") nodes  incoming \(s.incomingConnections)  total ↓ \(fmtRate(s.downloadRate))")
        if isTTY {
            var out = ""
            if lastLines > 0 { out += "\u{1B}[\(lastLines)A" }
            for l in lines { out += "\u{1B}[2K" + l + "\n" }
            out += "\u{1B}[J"
            FileHandle.standardOutput.write(Data(out.utf8))
            lastLines = lines.count
        } else {
            print(lines.joined(separator: "\n"))
        }
    }
}

func cmdDownload(_ o: Options) {
    guard !o.target.isEmpty else { usage() }
    var cfg = SessionConfig(downloadDirectory: o.output, stateDirectory: o.stateDir)
    cfg.listenPort = o.port
    cfg.encryption = o.encryption
    cfg.enableUTP = o.utp
    cfg.enableTCP = o.tcp
    cfg.preferUTP = o.preferUTP
    cfg.enableDHT = o.dht
    cfg.enablePEX = o.pex
    cfg.enableLSD = o.lsd
    cfg.enablePortMapping = o.upnp
    cfg.maxPeersPerTorrent = o.maxPeers
    cfg.downloadRateLimit = o.downLimit
    cfg.uploadRateLimit = o.upLimit
    if !o.extraTrackers { cfg.extraTrackers = [] }
    try? FileManager.default.createDirectory(at: o.output, withIntermediateDirectories: true)

    let session = Session(config: cfg)
    if o.verbose { session.onLog = { err("[astor] \($0)") } }
    do { try session.start() } catch { err("failed to start: \(error)"); exit(1) }

    let seed = o.seed
    let sequential = o.sequential
    let select = o.select
    let manualPeers = o.peers.compactMap { PeerAddress($0) }
    let configure: @Sendable (Torrent) -> Void = { t in
        t.sequential = sequential
        t.seedAfterCompletion = seed
        if let select { t.selectFiles(select) }
        for p in manualPeers { t.addPeer(p, source: .manual) }
    }
    let torrent: Torrent
    do {
        if o.target.lowercased().hasPrefix("magnet:") {
            torrent = try session.addMagnet(o.target, configure: configure)
        } else {
            torrent = try session.addTorrent(fileURL: URL(fileURLWithPath: o.target), configure: configure)
        }
    } catch {
        err("\(error)"); exit(1)
    }

    let dash = Dashboard(verbose: o.verbose)
    let started = Date()
    if isTTY { FileHandle.standardOutput.write(Data("\u{1B}[?25l".utf8)) } // hide cursor

    @Sendable func finish(_ code: Int32) {
        if isTTY { FileHandle.standardOutput.write(Data("\u{1B}[?25h".utf8)) }
        session.shutdown { exit(code) }
    }

    session.withLoop {
        torrent.onComplete = {
            let secs = Date().timeIntervalSince(started)
            let st = torrent.status()
            print("\n✔ Completed \(st.name) — \(fmtBytes(Double(st.wantedBytes))) in \(fmtETA(secs)) (avg \(fmtRate(Double(st.wantedBytes) / max(1, secs))))")
            if !seed { finish(0) }
        }
    }

    let ui = DispatchSource.makeTimerSource(queue: .main)
    ui.schedule(deadline: .now() + 1, repeating: 1)
    let exitAfter = o.exitAfter
    ui.setEventHandler {
        let s = session.status()
        let ts = session.torrentStatuses()
        dash.render(s, ts)
        if exitAfter > 0 && Date().timeIntervalSince(started) > exitAfter {
            ui.cancel()
            finish(0)
        }
    }
    ui.resume()

    signal(SIGINT, SIG_IGN)
    let sig = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    sig.setEventHandler {
        print("\nStopping (saving resume data, notifying trackers)…")
        finish(130)
    }
    sig.resume()
    withExtendedLifetime((ui, sig)) { dispatchMain() }
}

func cmdCreate(_ o: Options) {
    guard !o.target.isEmpty else { usage() }
    let src = URL(fileURLWithPath: (o.target as NSString).expandingTildeInPath)
    var opt = TorrentCreator.Options()
    opt.version = o.createVersion
    opt.trackers = o.trackers.map { [$0] }
    opt.webSeeds = o.webSeeds
    opt.pieceLength = o.pieceKiB.map { $0 * 1024 }
    opt.isPrivate = o.isPrivate
    opt.comment = o.comment
    let out = o.createOut ?? (src.lastPathComponent + ".torrent")
    let start = Date()
    do {
        let data = try TorrentCreator.create(from: src, options: opt) { p in
            if isTTY { FileHandle.standardError.write(Data(String(format: "\rhashing %5.1f%%", p * 100).utf8)) }
        }
        try data.write(to: URL(fileURLWithPath: out))
        let mi = try Metainfo(torrentFile: data)
        let secs = Date().timeIntervalSince(start)
        print("\r✔ \(out)  (\(mi.version.rawValue), \(mi.pieceCount) × \(fmtBytes(Double(mi.pieceLength))), \(fmtBytes(Double(mi.contentLength))) hashed at \(fmtRate(Double(mi.contentLength) / max(0.001, secs))))")
        if let v1 = mi.infoHashes.v1 { print("  v1 \(v1.hex)") }
        if let v2 = mi.infoHashes.v2 { print("  v2 \(v2.hex)") }
        if mi.version != .v1 { print("  piece layers \(mi.validatePieceLayers() ? "valid" : "INVALID")") }
    } catch {
        err("\(error)"); exit(1)
    }
}

// MARK: - Entry

let opts = parseArgs()
switch opts.command {
case "download", "dl", "get": cmdDownload(opts)
case "info": cmdInfo(opts)
case "create": cmdCreate(opts)
case "doctor": Doctor.run()
default: usage()
}
