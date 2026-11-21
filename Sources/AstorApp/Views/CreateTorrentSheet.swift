#if os(macOS)
import AppKit
import SwiftUI
import TorrentCore

/// State for the Create Torrent sheet. Hashing runs on a background queue
/// (TorrentCreator parallelises across all cores); progress hops back here.
@MainActor
@Observable
final class TorrentCreation {
    struct Created {
        var file: URL
        var name: String
        var magnet: String
        var summary: String
    }

    var source: URL? { didSet { if source != oldValue { measureSource() } } }
    var sourceSummary = ""
    var version: TorrentVersion = .hybrid
    var trackersText = ""
    var webSeedsText = ""
    var comment = ""
    var isPrivate = false
    var startSeeding = true
    private(set) var progress: Double = 0
    private(set) var isWorking = false
    private(set) var created: Created?
    var error: String?
    @ObservationIgnored private var cancelled = false

    var trackers: [[String]] { lines(trackersText).map { [$0] } }
    var canCreate: Bool { source != nil && !isWorking && (!isPrivate || !trackers.isEmpty) }

    private func lines(_ s: String) -> [String] {
        s.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    func chooseSource() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose"
        panel.message = "Choose the file or folder you want to share."
        if panel.runModal() == .OK, let url = panel.url { source = url }
    }

    func addPublicTrackers() {
        var existing = lines(trackersText)
        for t in SessionConfig.defaultPublicTrackers where !existing.contains(t) { existing.append(t) }
        trackersText = existing.joined(separator: "\n")
    }

    private func measureSource() {
        sourceSummary = ""
        guard let src = source else { return }
        Task {
            let summary = await Self.describe(src)
            if source == src { sourceSummary = summary }
        }
    }

    @concurrent
    nonisolated private static func describe(_ url: URL) async -> String { describeNow(url) }

    nonisolated private static func describeNow(_ url: URL) -> String {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { return "Not found" }
        guard isDir.boolValue else {
            let size = (try? fm.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
            return Fmt.bytes(size)
        }
        var count = 0
        var total: Int64 = 0
        if let e = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                                 options: [.skipsHiddenFiles]) {
            for case let u as URL in e {
                guard let v = try? u.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]), v.isRegularFile == true else { continue }
                count += 1
                total += Int64(v.fileSize ?? 0)
            }
        }
        return "\(Fmt.count(count)) files · \(Fmt.bytes(total))"
    }

    /// Asks where to save, hashes, writes the .torrent and optionally starts seeding.
    func create(model: AppModel) {
        guard let src = source, canCreate else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [AppModel.torrentType]
        panel.nameFieldStringValue = src.lastPathComponent + ".torrent"
        panel.directoryURL = src.deletingLastPathComponent()
        panel.message = "Choose where to save the new .torrent file."
        guard panel.runModal() == .OK, let dest = panel.url else { return }

        var opts = TorrentCreator.Options()
        opts.version = version
        opts.trackers = trackers
        opts.webSeeds = lines(webSeedsText)
        opts.isPrivate = isPrivate
        let c = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        opts.comment = c.isEmpty ? nil : c

        isWorking = true
        progress = 0
        error = nil
        cancelled = false
        let seed = startSeeding
        let started = Date()
        Task {
            do {
                let data = try await Self.hash(src, opts) { p in
                    Task { @MainActor in self.progress = max(self.progress, p) }
                }
                guard !cancelled else { return }
                try data.write(to: dest, options: .atomic)
                let mi = try Metainfo(torrentFile: data)
                let secs = max(0.001, Date().timeIntervalSince(started))
                created = Created(file: dest, name: mi.name, magnet: TorrentDetails(mi).magnetLink,
                                  summary: "\(Fmt.version(mi.version)) · \(Fmt.count(mi.pieceCount)) pieces of \(Fmt.bytes(Int64(mi.pieceLength))) · hashed \(Fmt.bytes(mi.contentLength)) in \(Fmt.duration(secs))")
                if seed { model.seedCreatedTorrent(dest, contentParent: src.deletingLastPathComponent()) }
            } catch {
                self.error = "\(error)"
            }
            isWorking = false
        }
    }

    func cancel() { cancelled = true }

    @concurrent
    nonisolated private static func hash(_ src: URL, _ opts: TorrentCreator.Options,
                             progress: @escaping @Sendable (Double) -> Void) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do { cont.resume(returning: try TorrentCreator.create(from: src, options: opts, progress: progress)) }
                catch { cont.resume(throwing: error) }
            }
        }
    }
}

struct CreateTorrentSheet: View {
    let model: AppModel
    @State private var creation = TorrentCreation()
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            if let done = creation.created {
                CreatedView(done: done, seeding: creation.startSeeding, model: model) { dismiss() }
            } else {
                form
                Divider()
                buttons
                    .padding(16)
            }
        }
        .frame(width: 560)
    }

    private var form: some View {
        @Bindable var c = creation
        return Form {
            Section {
                LabeledContent("Share") {
                    HStack {
                        if let src = c.source {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: src.path))
                                .resizable()
                                .frame(width: 20, height: 20)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(src.lastPathComponent).lineLimit(1).truncationMode(.middle)
                                if !c.sourceSummary.isEmpty {
                                    Text(c.sourceSummary).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        } else {
                            Text("No file or folder chosen").foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(c.source == nil ? "Choose…" : "Change…") { c.chooseSource() }
                    }
                }
                VStack(alignment: .leading, spacing: 6) {
                    Picker("Format", selection: $c.version) {
                        Text("Hybrid (recommended)").tag(TorrentVersion.hybrid)
                        Text("v1").tag(TorrentVersion.v1)
                        Text("v2").tag(TorrentVersion.v2)
                    }
                    .pickerStyle(.segmented)
                    Text(versionHelp)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Create a Torrent")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text("Make a .torrent file so others can download your files from you.")
                        .font(.callout)
                }
            }

            Section {
                TextEditor(text: $c.trackersText)
                    .font(.system(.callout, design: .monospaced))
                    .frame(height: 52)
                    .accessibilityLabel("Tracker addresses")
                HStack {
                    Text("One address per line (optional).")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Add Public Trackers") { c.addPublicTrackers() }
                        .disabled(c.isPrivate)
                }
            } header: {
                Text("Trackers")
            }

            Section {
                Toggle(isOn: $c.startSeeding) {
                    Text("Start seeding right away")
                    Text("Adds the torrent to Astor so others can download from you.")
                }
                Toggle(isOn: $c.isPrivate) {
                    Text("Private torrent")
                    Text("Only share through the trackers above (no DHT, peer exchange or local discovery). Needs a tracker.")
                }
                DisclosureGroup("More Options") {
                    TextField("Web seeds", text: $c.webSeedsText, prompt: Text("https://example.com/files/ (optional)"))
                    TextField("Comment", text: $c.comment, prompt: Text("Optional"))
                }
            }
        }
        .formStyle(.grouped)
        .frame(minHeight: 300, idealHeight: 500, maxHeight: 500)
    }

    private var versionHelp: String {
        switch creation.version {
        case .hybrid: "Works with every BitTorrent app and adds the newer v2 integrity checks."
        case .v1: "The classic format. Every BitTorrent app can open it."
        case .v2: "The newer format with stronger per-file checks. Some older apps can't open it."
        }
    }

    private var buttons: some View {
        HStack(spacing: 10) {
            if creation.isWorking {
                ProgressView(value: creation.progress)
                    .frame(width: 160)
                Text("Hashing… \(Fmt.percent(creation.progress, digits: 0))")
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            } else if let err = creation.error {
                Label(err, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .lineLimit(2)
            }
            Spacer()
            Button("Cancel", role: .cancel) {
                creation.cancel()
                dismiss()
            }
            .keyboardShortcut(.cancelAction)
            Button("Create…") { creation.create(model: model) }
                .keyboardShortcut(.defaultAction)
                .disabled(!creation.canCreate)
        }
    }
}

private struct CreatedView: View {
    let done: TorrentCreation.Created
    let seeding: Bool
    let model: AppModel
    let close: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 44))
                .foregroundStyle(.green)
            Text("Created “\(done.file.lastPathComponent)”")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(done.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Text(seeding ? "Astor is now seeding it. Share the .torrent file or the magnet link with others."
                         : "Share the .torrent file or the magnet link with others.")
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([done.file]) }
                Button("Copy Magnet Link") { model.copy(done.magnet) }
                Spacer()
                Button("Done", action: close)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.top, 6)
        }
        .padding(24)
    }
}
#endif
