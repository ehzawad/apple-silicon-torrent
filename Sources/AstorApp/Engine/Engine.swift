#if os(macOS)
import Foundation
import TorrentCore

/// Thread-safe facade over `TorrentCore.Session` for the UI.
///
/// The session's snapshot and lookup calls hop onto the engine's event loop
/// *synchronously* (`loop.sync`). They are cheap, but they must never run on the
/// main actor, so every call here is funnelled through one private serial queue
/// and resumed with a continuation. Loop-confined `Torrent` properties
/// (`metainfo`, `sequential`, `onComplete`, …) are only touched inside
/// `session.loop.sync` / `session.withLoop`.
final class Engine: Sendable {
    let session: Session
    let config: SessionConfig
    /// `<state>/app/torrents`: copies of added .torrent files so they can be re-added on launch.
    let torrentsDirectory: URL
    private let queue = DispatchQueue(label: "com.astor.torrent.engine", qos: .userInitiated)

    enum AddSource: Sendable {
        case torrentFile(URL)
        case magnet(String)
    }

    struct AddRequest: Sendable {
        var source: AddSource
        var downloadDirectory: URL
        var sequential = false
        var selectedFiles: Set<Int>?
        var startPaused = false
    }

    struct AddResult: Sendable {
        var id: String
        var name: String
        /// Where the .torrent copy lives (nil for magnets).
        var storedTorrentFile: String?
    }

    init(config: SessionConfig) {
        self.config = config
        self.session = Session(config: config)
        self.torrentsDirectory = config.stateDirectory
            .appendingPathComponent("app", isDirectory: true)
            .appendingPathComponent("torrents", isDirectory: true)
    }

    // MARK: Plumbing

    private func run<T: Sendable>(_ body: @escaping @Sendable (Session) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            queue.async { [session] in
                do { cont.resume(returning: try body(session)) } catch { cont.resume(throwing: error) }
            }
        }
    }

    private func run<T: Sendable>(_ body: @escaping @Sendable (Session) -> T) async -> T {
        await withCheckedContinuation { cont in
            queue.async { [session] in cont.resume(returning: body(session)) }
        }
    }

    /// Looks up torrents by id inside one loop hop.
    private static func torrents(_ s: Session, _ ids: Set<String>) -> [Torrent] {
        s.allTorrents.filter { ids.contains($0.infoHashes.description) }
    }

    // MARK: Lifecycle

    func start() async throws {
        let dirs = [config.downloadDirectory, torrentsDirectory]
        try await run { s in
            for d in dirs { try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true) }
            try s.start()
        }
    }

    /// Stops every torrent (saves resume data, sends tracker "stopped"), then calls back.
    func shutdown(completion: @escaping @Sendable () -> Void) {
        queue.async { [session] in session.shutdown(completion: completion) }
    }

    // MARK: Snapshots

    func snapshot() async -> EngineSnapshot {
        await run { s in
            let status = s.status()
            let statuses = s.torrentStatuses()
            let rows = statuses.enumerated().map { TorrentRow($0.element, index: $0.offset) }
            return EngineSnapshot(session: SessionInfo(status), statuses: statuses, rows: rows)
        }
    }

    /// Metainfo-derived details for the given ids (ids still fetching metadata are omitted).
    func details(for ids: Set<String>) async -> [String: TorrentDetails] {
        await run { s in
            let ts = Self.torrents(s, ids)
            let pairs: [(String, Metainfo?)] = s.loop.sync { ts.map { ($0.infoHashes.description, $0.metainfo) } }
            var out: [String: TorrentDetails] = [:]
            for (id, mi) in pairs { if let mi { out[id] = TorrentDetails(mi) } }
            return out
        }
    }

    // MARK: Adding

    func add(_ req: AddRequest, onComplete: @escaping @Sendable (String) -> Void) async throws -> AddResult {
        let torrentsDir = torrentsDirectory
        return try await run { s in
            let sequential = req.sequential
            let selected = req.selectedFiles
            let configure: @Sendable (Torrent) -> Void = { t in
                // Runs on the event loop before the torrent starts.
                let id = t.infoHashes.description
                t.sequential = sequential
                if let selected { t.selectFiles(selected) }
                t.onComplete = { onComplete(id) }
            }
            let torrent: Torrent
            var stored: String?
            switch req.source {
            case .torrentFile(let url):
                let data = try Data(contentsOf: url)
                let mi: Metainfo
                do { mi = try Metainfo(torrentFile: data) } catch { throw SessionError.invalidTorrent("\(error)") }
                let dest = torrentsDir.appendingPathComponent(mi.infoHashes.description + ".torrent")
                if dest.standardizedFileURL.path != url.standardizedFileURL.path {
                    try FileManager.default.createDirectory(at: torrentsDir, withIntermediateDirectories: true)
                    try data.write(to: dest, options: .atomic)
                }
                stored = dest.lastPathComponent
                torrent = try s.addTorrent(fileURL: dest, downloadDirectory: req.downloadDirectory, configure: configure)
            case .magnet(let uri):
                torrent = try s.addMagnet(uri, downloadDirectory: req.downloadDirectory, configure: configure)
            }
            if req.startPaused { s.setPaused(torrent, true) }
            let name = s.loop.sync { torrent.status().name }
            return AddResult(id: torrent.infoHashes.description, name: name, storedTorrentFile: stored)
        }
    }

    /// Parses a magnet link or .torrent without adding it (for previews and duplicate checks).
    static func peekID(of source: AddSource) -> (id: String, name: String?)? {
        switch source {
        case .magnet(let uri):
            guard let m = MagnetLink(uri) else { return nil }
            return (m.infoHashes.description, m.displayName)
        case .torrentFile(let url):
            guard let d = try? Data(contentsOf: url), let mi = try? Metainfo(torrentFile: d) else { return nil }
            return (mi.infoHashes.description, mi.name)
        }
    }

    // MARK: Control

    func setPaused(_ ids: Set<String>, _ paused: Bool) async {
        await run { s in for t in Self.torrents(s, ids) { s.setPaused(t, paused) } }
    }

    func remove(_ ids: Set<String>) async {
        await run { s in for t in Self.torrents(s, ids) { s.remove(t) } }
    }

    func setSequential(_ ids: Set<String>, _ on: Bool) async {
        await run { s in
            for t in Self.torrents(s, ids) { s.withLoop { t.sequential = on } }
        }
    }

    func selectFiles(_ id: String, _ files: Set<Int>) async {
        await run { s in
            for t in Self.torrents(s, [id]) { s.withLoop { t.selectFiles(files) } }
        }
    }
}

extension SessionError {
    var friendlyDescription: String {
        switch self {
        case .invalidTorrent: "This file isn't a valid torrent."
        case .invalidMagnet: "This doesn't look like a valid magnet link."
        case .duplicate: "This torrent is already in your list."
        case .notStarted: "Astor's engine isn't running."
        }
    }
}
#endif
