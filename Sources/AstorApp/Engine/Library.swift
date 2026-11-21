#if os(macOS)
import Foundation

/// The app's list of torrents, persisted as JSON in `<state>/app/library.json`.
///
/// The engine keeps per-torrent resume data (`<state>/resume/*.resume`) but does
/// not re-add torrents by itself on start, so the app remembers what to re-add
/// (a stored copy of the .torrent file, or the magnet link — the engine then
/// restores the info dictionary from its resume file) plus UI-level choices.
struct LibraryEntry: Codable, Sendable, Identifiable {
    enum Source: Codable, Sendable {
        case torrentFile(String)   // file name inside `Engine.torrentsDirectory`
        case magnet(String)
    }

    var id: String
    var name: String
    var source: Source
    var downloadDirectory: String
    var paused = false
    var sequential = false
    var selectedFiles: [Int]?
    var addedAt = Date()
}

struct Library: Sendable {
    private(set) var entries: [LibraryEntry] = []
    let fileURL: URL

    init(stateDirectory: URL) {
        fileURL = stateDirectory
            .appendingPathComponent("app", isDirectory: true)
            .appendingPathComponent("library.json")
    }

    static func load(stateDirectory: URL) -> Library {
        var lib = Library(stateDirectory: stateDirectory)
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        if let data = try? Data(contentsOf: lib.fileURL),
           let entries = try? dec.decode([LibraryEntry].self, from: data) {
            lib.entries = entries
        }
        return lib
    }

    subscript(id: String) -> LibraryEntry? {
        entries.first { $0.id == id }
    }

    mutating func upsert(_ e: LibraryEntry) {
        if let i = entries.firstIndex(where: { $0.id == e.id }) { entries[i] = e } else { entries.append(e) }
    }

    mutating func update(_ id: String, _ body: (inout LibraryEntry) -> Void) {
        guard let i = entries.firstIndex(where: { $0.id == id }) else { return }
        body(&entries[i])
    }

    mutating func remove(_ ids: Set<String>) {
        entries.removeAll { ids.contains($0.id) }
    }

    /// Writes atomically on a background queue (or synchronously at quit).
    func save(synchronously: Bool = false) {
        let url = fileURL
        let entries = entries
        let write: @Sendable () -> Void = {
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            enc.dateEncodingStrategy = .iso8601
            guard let data = try? enc.encode(entries) else { return }
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? data.write(to: url, options: .atomic)
        }
        if synchronously { write() } else { Library.ioQueue.async(execute: write) }
    }

    private static let ioQueue = DispatchQueue(label: "com.astor.torrent.library", qos: .utility)
}
#endif
