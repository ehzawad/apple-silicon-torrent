#if os(macOS)
import AppKit
import Foundation
import Observation
import TorrentCore
import UniformTypeIdentifiers

struct AppAlert: Identifiable {
    let id = UUID()
    var title: String
    var message: String
}

/// The app's single source of truth. Lives for the whole app (owned by the
/// AppDelegate) and is observed by every window.
///
/// Engine work never runs here directly: `Engine` executes it on its own queue
/// and this model only assigns the resulting value snapshots, once per second.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case starting, running, stopping
        case failed(String)
    }

    // MARK: Observed state

    private(set) var phase: Phase = .starting
    /// Filtered + sorted rows shown in the table.
    private(set) var visibleRows: [TorrentRow] = []
    private(set) var filterCounts: [TorrentFilter: Int] = [:]
    private(set) var sessionInfo = SessionInfo()
    /// Full status of the single selected torrent (drives the inspector).
    private(set) var selectedStatus: TorrentStatus?
    /// Metainfo facts per torrent id; filled lazily once metadata is known.
    private(set) var details: [String: TorrentDetails] = [:]
    private(set) var library: Library
    private(set) var totalTorrents = 0
    /// Becomes true ~25 s after launch: port mapping has had time to succeed.
    private(set) var startupGraceOver = false
    let launchSettings: EngineSettings
    let startedAt = Date()

    var filter: TorrentFilter = .all { didSet { if oldValue != filter { recompute() } } }
    var searchText = "" { didSet { if oldValue != searchText { recompute() } } }
    var sortOrder: [KeyPathComparator<TorrentRow>] = [KeyPathComparator(\TorrentRow.queueIndex)] {
        didSet { recompute() }
    }
    var selection: Set<String> = [] { didSet { if oldValue != selection { refreshSelectedStatus() } } }

    var showInspector = true
    var showingOpenPanel = false
    var showingAddMagnet = false
    var magnetDraft = ""
    var showingCreateTorrent = false
    /// Non-nil while the "Remove torrents?" confirmation is up.
    var pendingRemoval: Set<String>?
    var alert: AppAlert?

    // MARK: Private state

    @ObservationIgnored private var engine: Engine?
    @ObservationIgnored private var rows: [TorrentRow] = []
    @ObservationIgnored private var statuses: [String: TorrentStatus] = [:]
    @ObservationIgnored private var pollTask: Task<Void, Never>?
    @ObservationIgnored private var pendingURLs: [URL] = []
    @ObservationIgnored private var detailAttempts: [String: Date] = [:]
    @ObservationIgnored private var detailsInFlight = false
    @ObservationIgnored private var snapshotSequence = 0
    @ObservationIgnored private var shutdownCompletion: (@MainActor () -> Void)?
    @ObservationIgnored private let notifier = Notifier()
    @ObservationIgnored private var activity: (any NSObjectProtocol)?
    @ObservationIgnored private var activityLevel = ActivityLevel.idle

    static let torrentType = UTType(filenameExtension: "torrent", conformingTo: .data) ?? .data

    init() {
        EngineSettings.registerDefaults()
        launchSettings = EngineSettings.current()
        library = Library(stateDirectory: EngineSettings.stateDirectory)
    }

    var isRunning: Bool { phase == .running }

    // MARK: Lifecycle

    func start() {
        guard engine == nil else { return }
        let config = launchSettings.sessionConfig()
        let engine = Engine(config: config)
        self.engine = engine
        library = Library.load(stateDirectory: config.stateDirectory)
        Task {
            do {
                try await engine.start()
            } catch {
                phase = .failed("Astor couldn't start its network engine: \(error)")
                return
            }
            phase = .running
            await restoreLibrary()
            startPolling()
            let pending = pendingURLs
            pendingURLs = []
            open(pending)
        }
    }

    /// Saves everything and lets the engine send "stopped" announces before quitting.
    func shutdown(_ done: @escaping @MainActor () -> Void) {
        pollTask?.cancel()
        library.save(synchronously: true)
        guard let engine, phase == .running else { done(); return }
        phase = .stopping
        shutdownCompletion = done
        // AppKit waits for the reply inside a nested run loop. If terminate was
        // called from a main-queue block (signal handler, Task), main-queue work
        // can't run until it returns, so hop back with run-loop primitives
        // (RunLoop.perform / Timer), never with Task/DispatchQueue.main.
        engine.shutdown {
            RunLoop.main.perform(inModes: [.common, .modalPanel]) {
                MainActor.assumeIsolated { self.finishShutdown() }
            }
        }
        // Never hang the quit if something in the engine stalls.
        let fallback = Timer(timeInterval: 8, repeats: false) { _ in
            MainActor.assumeIsolated { self.finishShutdown() }
        }
        RunLoop.main.add(fallback, forMode: .common)
        RunLoop.main.add(fallback, forMode: .modalPanel)
    }

    private func finishShutdown() {
        let done = shutdownCompletion
        shutdownCompletion = nil
        done?()
    }

    /// Relaunches the app so engine settings take effect.
    func relaunch() {
        let bundle = Bundle.main.bundleURL
        guard bundle.pathExtension == "app" else { NSApp.terminate(nil); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        // Wait for this process to exit (after the engine's clean shutdown), then reopen.
        p.arguments = ["-c", "while /bin/kill -0 \"$1\" 2>/dev/null; do /bin/sleep 0.2; done; /usr/bin/open \"$2\"",
                       "sh", String(ProcessInfo.processInfo.processIdentifier), bundle.path]
        try? p.run()
        NSApp.terminate(nil)
    }

    private func restoreLibrary() async {
        guard let engine else { return }
        var failed: [String] = []
        var dropped: Set<String> = []
        for entry in library.entries {
            let source: Engine.AddSource
            switch entry.source {
            case .torrentFile(let file):
                let url = engine.torrentsDirectory.appendingPathComponent(file)
                guard FileManager.default.fileExists(atPath: url.path) else {
                    failed.append(entry.name); dropped.insert(entry.id); continue
                }
                source = .torrentFile(url)
            case .magnet(let uri):
                source = .magnet(uri)
            }
            let req = Engine.AddRequest(source: source,
                                        downloadDirectory: URL(fileURLWithPath: entry.downloadDirectory, isDirectory: true),
                                        sequential: entry.sequential,
                                        selectedFiles: entry.selectedFiles.map(Set.init),
                                        startPaused: entry.paused)
            do {
                _ = try await engine.add(req, onComplete: completionHandler)
            } catch SessionError.duplicate {
                continue
            } catch {
                failed.append(entry.name)
                dropped.insert(entry.id)
            }
        }
        if !dropped.isEmpty {
            library.remove(dropped)
            library.save()
        }
        if !failed.isEmpty {
            show("Some torrents couldn't be restored",
                 "Their saved files are missing or damaged:\n" + failed.joined(separator: "\n"))
        }
    }

    // MARK: Polling

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshNow()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// One snapshot round-trip (off the main thread) and apply.
    func refreshNow() async {
        guard let engine, phase == .running else { return }
        snapshotSequence += 1
        let seq = snapshotSequence
        let snap = await engine.snapshot()
        // Action-triggered refreshes overlap the 1 s poll; only the newest wins.
        guard phase == .running, seq == snapshotSequence else { return }
        apply(snap)
    }

    private func apply(_ snap: EngineSnapshot) {
        if sessionInfo != snap.session { sessionInfo = snap.session }
        if !startupGraceOver && Date().timeIntervalSince(startedAt) > 25 { startupGraceOver = true }
        var byID: [String: TorrentStatus] = [:]
        byID.reserveCapacity(snap.statuses.count)
        for s in snap.statuses { byID[s.infoHash] = s }
        statuses = byID
        if rows != snap.rows {
            rows = snap.rows
            if totalTorrents != rows.count { totalTorrents = rows.count }
            recompute()
        }
        refreshSelectedStatus()
        fetchMissingDetails()
        updateActivity()
    }

    private enum ActivityLevel { case idle, active, downloading }

    /// Opts out of App Nap while torrents are active (otherwise macOS throttles the
    /// engine's timers and sockets when Astor is in the background), and keeps the
    /// Mac from idle-sleeping while something is downloading, if the user wants that.
    private func updateActivity() {
        let downloading = rows.contains { $0.state == .downloading || $0.state == .fetchingMetadata || $0.state == .checking }
        let keepAwake = UserDefaults.standard.bool(forKey: SettingsKey.preventSleep)
        let level: ActivityLevel = rows.contains(where: { $0.isActive })
            ? (downloading && keepAwake ? .downloading : .active) : .idle
        guard level != activityLevel else { return }
        activityLevel = level
        if let activity { ProcessInfo.processInfo.endActivity(activity) }
        activity = nil
        switch level {
        case .idle: break
        case .active:
            activity = ProcessInfo.processInfo.beginActivity(options: .userInitiatedAllowingIdleSystemSleep,
                                                             reason: "Sharing torrents")
        case .downloading:
            activity = ProcessInfo.processInfo.beginActivity(options: .userInitiated,
                                                             reason: "Downloading torrents")
        }
    }

    private func recompute() {
        var counts: [TorrentFilter: Int] = [:]
        for f in TorrentFilter.allCases { counts[f] = 0 }
        for r in rows { for f in TorrentFilter.allCases where f.includes(r) { counts[f, default: 0] += 1 } }
        if counts != filterCounts { filterCounts = counts }

        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        var v = rows.filter { filter.includes($0) && (query.isEmpty || $0.name.localizedCaseInsensitiveContains(query)) }
        v.sort(using: sortOrder + [KeyPathComparator(\TorrentRow.queueIndex)])
        if v != visibleRows { visibleRows = v }

        let visibleIDs = Set(v.map(\.id))
        if !selection.isSubset(of: visibleIDs) { selection = selection.intersection(visibleIDs) }
    }

    private func refreshSelectedStatus() {
        guard selection.count == 1, let id = selection.first else {
            if selectedStatus != nil { selectedStatus = nil }
            return
        }
        selectedStatus = statuses[id]
    }

    private func fetchMissingDetails() {
        guard let engine, !detailsInFlight else { return }
        let now = Date()
        let missing = Set(rows.lazy
            .filter { self.details[$0.id] == nil && $0.state != .fetchingMetadata }
            .filter { now.timeIntervalSince(self.detailAttempts[$0.id] ?? .distantPast) > 5 }
            .map(\.id))
        guard !missing.isEmpty else { return }
        for id in missing { detailAttempts[id] = now }
        detailsInFlight = true
        Task {
            let found = await engine.details(for: missing)
            detailsInFlight = false
            guard !found.isEmpty else { return }
            details.merge(found) { _, new in new }
            for (id, d) in found where library[id]?.name != d.name {
                library.update(id) { $0.name = d.name }
            }
            library.save()
        }
    }

    // MARK: Lookup helpers

    func row(_ id: String) -> TorrentRow? { visibleRows.first { $0.id == id } }
    var selectedRows: [TorrentRow] { visibleRows.filter { selection.contains($0.id) } }
    func canPause(_ ids: Set<String>) -> Bool { visibleRows.contains { ids.contains($0.id) && !$0.isPaused } }
    func canResume(_ ids: Set<String>) -> Bool { visibleRows.contains { ids.contains($0.id) && $0.isPaused } }
    func isSequential(_ ids: Set<String>) -> Bool { !ids.isEmpty && ids.allSatisfy { library[$0]?.sequential == true } }

    /// "3 downloading · 2 seeding" for the window subtitle.
    var summary: String {
        guard totalTorrents > 0 else { return isRunning ? "No torrents" : "" }
        var parts: [String] = []
        let down = filterCounts[.downloading] ?? 0
        let seed = filterCounts[.seeding] ?? 0
        let paused = filterCounts[.paused] ?? 0
        if down > 0 { parts.append("\(down) downloading") }
        if seed > 0 { parts.append("\(seed) seeding") }
        if paused > 0 { parts.append("\(paused) paused") }
        return parts.isEmpty ? "\(totalTorrents) torrents" : parts.joined(separator: " · ")
    }

    // MARK: Adding torrents

    /// Entry point for Finder / browser opens, drag and drop, and the file picker.
    func open(_ urls: [URL]) {
        guard !urls.isEmpty else { return }
        guard isRunning else { pendingURLs.append(contentsOf: urls); return }
        for url in urls {
            if url.scheme?.lowercased() == "magnet" {
                add(.magnet(url.absoluteString))
            } else if url.isFileURL, url.pathExtension.lowercased() == "torrent" {
                add(.torrentFile(url))
            }
        }
    }

    func addMagnets(_ text: String) {
        let links = Self.magnetLinks(in: text)
        if links.isEmpty {
            show("Not a magnet link", "Magnet links start with “magnet:?”. Copy the whole link from your browser and try again.")
            return
        }
        for l in links { add(.magnet(l)) }
    }

    static func magnetLinks(in text: String) -> [String] {
        text.split(whereSeparator: \.isWhitespace)
            .map(String.init)
            .filter { $0.lowercased().hasPrefix("magnet:?") }
    }

    private func add(_ source: Engine.AddSource) {
        guard let engine else { return }
        let dir = EngineSettings.downloadDirectory
        let completion = completionHandler
        Task {
            let accessing: URL? = {
                if case .torrentFile(let u) = source, u.startAccessingSecurityScopedResource() { return u }
                return nil
            }()
            defer { accessing?.stopAccessingSecurityScopedResource() }
            do {
                let result = try await engine.add(Engine.AddRequest(source: source, downloadDirectory: dir),
                                                  onComplete: completion)
                let entrySource: LibraryEntry.Source
                switch source {
                case .magnet(let uri): entrySource = .magnet(uri)
                case .torrentFile: entrySource = .torrentFile(result.storedTorrentFile ?? "\(result.id).torrent")
                }
                library.upsert(LibraryEntry(id: result.id, name: result.name, source: entrySource,
                                            downloadDirectory: dir.path))
                library.save()
                await refreshNow()
                if filter != .all && filter != .downloading { filter = .all }
                selection = [result.id]
            } catch let e as SessionError {
                if case .duplicate = e, let peek = Engine.peekID(of: source) {
                    selection = [peek.id]
                    show("Already added", "“\(peek.name ?? "This torrent")” is already in your list.")
                } else {
                    show("Couldn't add torrent", Self.describe(source) + "\n" + e.friendlyDescription)
                }
            } catch {
                show("Couldn't add torrent", Self.describe(source) + "\n" + error.localizedDescription)
            }
        }
    }

    private static func describe(_ s: Engine.AddSource) -> String {
        switch s {
        case .torrentFile(let u): "“\(u.lastPathComponent)”"
        case .magnet(let m): MagnetLink(m)?.displayName.map { "“\($0)”" } ?? "Magnet link"
        }
    }

    /// Called on the engine loop when a download finishes.
    private var completionHandler: @Sendable (String) -> Void {
        { [weak self] id in
            Task { @MainActor in self?.torrentCompleted(id) }
        }
    }

    private func torrentCompleted(_ id: String) {
        let name = details[id]?.name ?? rows.first { $0.id == id }?.name ?? "A torrent"
        notifier.downloadFinished(name: name, id: id)
    }

    /// ⌘V in the torrent list: .torrent files or magnet links on the clipboard.
    func pasteFromClipboard() {
        let pb = NSPasteboard.general
        let files = (pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? [])
            .filter { $0.pathExtension.lowercased() == "torrent" }
        let text = [pb.string(forType: .string), (pb.readObjects(forClasses: [NSURL.self]) as? [URL])?.map(\.absoluteString).joined(separator: "\n")]
            .compactMap { $0 }.joined(separator: "\n")
        let magnets = Self.magnetLinks(in: text)
        if files.isEmpty && magnets.isEmpty {
            showAddMagnet()
            return
        }
        open(files)
        var seen = Set<String>()
        for m in magnets where seen.insert(m).inserted { add(.magnet(m)) }
    }

    func showAddMagnet() {
        let clip = NSPasteboard.general.string(forType: .string) ?? ""
        magnetDraft = Self.magnetLinks(in: clip).joined(separator: "\n")
        showingAddMagnet = true
    }

    // MARK: Controlling torrents

    func setPaused(_ ids: Set<String>, _ paused: Bool) {
        guard let engine, !ids.isEmpty else { return }
        for id in ids { library.update(id) { $0.paused = paused } }
        library.save()
        Task {
            await engine.setPaused(ids, paused)
            await refreshNow()
        }
    }

    func pauseAll() { setPaused(Set(rows.filter { !$0.isPaused }.map(\.id)), true) }
    func resumeAll() { setPaused(Set(rows.filter(\.isPaused).map(\.id)), false) }

    func setSequential(_ ids: Set<String>, _ on: Bool) {
        guard let engine, !ids.isEmpty else { return }
        for id in ids { library.update(id) { $0.sequential = on } }
        library.save()
        Task { await engine.setSequential(ids, on) }
    }

    func selectedFiles(_ id: String) -> Set<Int>? { library[id]?.selectedFiles.map(Set.init) }

    func setSelectedFiles(_ id: String, _ files: Set<Int>) {
        guard let engine else { return }
        let all = details[id]?.files.count ?? 0
        library.update(id) { $0.selectedFiles = files.count == all ? nil : files.sorted() }
        library.save()
        Task { await engine.selectFiles(id, files) }
    }

    func requestRemove(_ ids: Set<String>) {
        guard !ids.isEmpty else { return }
        pendingRemoval = ids
    }

    func remove(_ ids: Set<String>, trashFiles: Bool) {
        guard let engine, !ids.isEmpty else { return }
        let targets = trashFiles ? ids.compactMap(downloadedItemURL) : []
        let stored: [URL] = ids.compactMap { id in
            guard case .torrentFile(let f)? = library[id]?.source else { return nil }
            return engine.torrentsDirectory.appendingPathComponent(f)
        }
        library.remove(ids)
        library.save()
        selection.subtract(ids)
        Task {
            await engine.remove(ids)
            for u in stored { try? FileManager.default.removeItem(at: u) }
            if !targets.isEmpty {
                // Give the engine a moment to close its file handles before moving data.
                try? await Task.sleep(for: .milliseconds(300))
                NSWorkspace.shared.recycle(targets) { _, _ in }
            }
            await refreshNow()
        }
    }

    /// `<save path>/<torrent name>` if it exists on disk.
    func downloadedItemURL(_ id: String) -> URL? {
        guard let s = statuses[id] else { return nil }
        let name = details[id]?.name ?? s.name
        let url = URL(fileURLWithPath: s.savePath, isDirectory: true).appendingPathComponent(name)
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    func revealInFinder(_ ids: Set<String>) {
        var items: [URL] = []
        for id in ids {
            if let u = downloadedItemURL(id) { items.append(u) }
            else if let s = statuses[id] { NSWorkspace.shared.open(URL(fileURLWithPath: s.savePath, isDirectory: true)) }
        }
        if !items.isEmpty { NSWorkspace.shared.activateFileViewerSelecting(items) }
    }

    func copyMagnetLinks(_ ids: Set<String>) {
        let links = orderedIDs(ids).map { id -> String in
            if let d = details[id] { return d.magnetLink }
            if case .magnet(let m)? = library[id]?.source { return m }
            return id.count == 64 ? "magnet:?xt=urn:btmh:1220\(id)" : "magnet:?xt=urn:btih:\(id)"
        }
        copy(links.joined(separator: "\n"))
    }

    func copyInfoHashes(_ ids: Set<String>) {
        copy(orderedIDs(ids).joined(separator: "\n"))
    }

    func copy(_ string: String) {
        guard !string.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }

    private func orderedIDs(_ ids: Set<String>) -> [String] {
        visibleRows.map(\.id).filter(ids.contains) + ids.subtracting(visibleRows.map(\.id)).sorted()
    }

    // MARK: Created torrents

    /// Adds a torrent we just created, seeding from the folder that holds its content.
    func seedCreatedTorrent(_ torrentFile: URL, contentParent: URL) {
        guard let engine else { return }
        let completion = completionHandler
        Task {
            do {
                let r = try await engine.add(Engine.AddRequest(source: .torrentFile(torrentFile),
                                                               downloadDirectory: contentParent),
                                             onComplete: completion)
                library.upsert(LibraryEntry(id: r.id, name: r.name,
                                            source: .torrentFile(r.storedTorrentFile ?? "\(r.id).torrent"),
                                            downloadDirectory: contentParent.path))
                library.save()
                await refreshNow()
                filter = .all
                selection = [r.id]
            } catch {
                show("Couldn't start seeding", (error as? SessionError)?.friendlyDescription ?? error.localizedDescription)
            }
        }
    }

    /// Closes every sheet/dialog (AppKit won't quit while a sheet is attached).
    func dismissPresentations() {
        showingAddMagnet = false
        showingCreateTorrent = false
        showingOpenPanel = false
        pendingRemoval = nil
        alert = nil
    }

    // MARK: Alerts

    func show(_ title: String, _ message: String) {
        if let a = alert, a.title == title {
            alert = AppAlert(title: title, message: a.message + "\n\n" + message)
        } else {
            alert = AppAlert(title: title, message: message)
        }
    }
}
#endif
