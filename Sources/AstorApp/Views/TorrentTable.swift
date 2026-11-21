#if os(macOS)
import SwiftUI
import TorrentCore

/// The sortable, multi-select torrent list.
struct TorrentTable: View {
    @Bindable var model: AppModel
    @State private var columns = ColumnStore.load()

    var body: some View {
        Table(model.visibleRows, selection: $model.selection, sortOrder: $model.sortOrder,
              columnCustomization: $columns) {
            TableColumn("Name", value: \.name) { row in
                NameCell(row: row)
            }
            .width(min: 140, ideal: 210)
            .customizationID("name")
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Progress", value: \.progress) { row in
                ProgressCell(row: row)
            }
            .width(min: 80, ideal: 110)
            .customizationID("progress")

            TableColumn("Status", value: \.stateRank) { row in
                Text(row.statusText)
                    .foregroundStyle(row.state == .error ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                    .help(row.error ?? row.statusText)
            }
            .width(min: 70, ideal: 104)
            .customizationID("status")

            TableColumn("Down", value: \.downloadRate) { row in
                Text(Fmt.cellRate(row.downloadRate)).monospacedDigit()
            }
            .width(min: 52, ideal: 70)
            .alignment(.trailing)
            .customizationID("down")

            TableColumn("Up", value: \.uploadRate) { row in
                Text(Fmt.cellRate(row.uploadRate)).monospacedDigit()
            }
            .width(min: 52, ideal: 70)
            .alignment(.trailing)
            .customizationID("up")

            TableColumn("Peers", value: \.peers) { row in
                Text(row.peersText).monospacedDigit()
                    .help("\(row.peers) connected peers, \(row.seeds) of them have the whole torrent")
            }
            .width(min: 40, ideal: 50)
            .alignment(.trailing)
            .customizationID("peers")

            TableColumn("Time Left", value: \.etaSortKey) { row in
                Text(row.etaText).monospacedDigit().foregroundStyle(.secondary)
            }
            .width(min: 56, ideal: 72)
            .alignment(.trailing)
            .customizationID("eta")

            TableColumn("Size", value: \.size) { row in
                Text(row.sizeText).monospacedDigit()
            }
            .width(min: 52, ideal: 66)
            .alignment(.trailing)
            .customizationID("size")

            TableColumn("Ratio", value: \.ratio) { row in
                Text(row.ratio.formatted(.number.precision(.fractionLength(2)))).monospacedDigit()
            }
            .width(min: 44, ideal: 56)
            .alignment(.trailing)
            .customizationID("ratio")
            .defaultVisibility(.hidden)
        }
        .contextMenu(forSelectionType: String.self) { ids in
            TorrentContextMenu(model: model, ids: ids)
        } primaryAction: { ids in
            model.revealInFinder(ids)
        }
        .onDeleteCommand { model.requestRemove(model.selection) }
        .onPasteCommand(of: [.fileURL, .url, .plainText]) { _ in model.pasteFromClipboard() }
        .onChange(of: columns) { _, new in ColumnStore.save(new) }
        .overlay { EmptyStateOverlay(model: model) }
    }
}

/// Persists which columns are shown and their widths/order.
private enum ColumnStore {
    static let key = "torrentTableColumns"

    static func load() -> TableColumnCustomization<TorrentRow> {
        guard let data = UserDefaults.standard.data(forKey: key),
              let c = try? JSONDecoder().decode(TableColumnCustomization<TorrentRow>.self, from: data) else { return .init() }
        return c
    }

    static func save(_ c: TableColumnCustomization<TorrentRow>) {
        if let data = try? JSONEncoder().encode(c) { UserDefaults.standard.set(data, forKey: key) }
    }
}

extension TorrentRow {
    var tint: Color {
        switch state {
        case .downloading: .accentColor
        case .seeding: .green
        case .checking: .orange
        case .fetchingMetadata: .purple
        case .paused: .gray
        case .error: .red
        }
    }
}

private struct NameCell: View {
    let row: TorrentRow

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: row.statusSymbol)
                .foregroundStyle(row.tint)
                .accessibilityLabel(row.statusText)
            Text(row.name)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .help(row.error.map { "\(row.name)\n\($0)" } ?? row.name)
    }
}

private struct ProgressCell: View {
    let row: TorrentRow

    var body: some View {
        HStack(spacing: 6) {
            ProgressView(value: min(max(row.progress, 0), 1))
                .progressViewStyle(.linear)
                .controlSize(.small)
                .tint(row.tint)
            Text(Fmt.percent(row.progress, digits: row.progress >= 0.999 || row.progress == 0 ? 0 : 1))
                .font(.caption)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(minWidth: 38, alignment: .trailing)
        }
        .accessibilityElement(children: .combine)
    }
}

/// Context menu for the table (works on the clicked row or the whole selection).
struct TorrentContextMenu: View {
    let model: AppModel
    let ids: Set<String>

    var body: some View {
        if ids.isEmpty {
            Button("Add Torrent File…", systemImage: "plus") { model.showingOpenPanel = true }
            Button("Add Magnet Link…", systemImage: "link") { model.showAddMagnet() }
        } else {
            Button("Resume", systemImage: "play") { model.setPaused(ids, false) }
                .disabled(!model.canResume(ids))
            Button("Pause", systemImage: "pause") { model.setPaused(ids, true) }
                .disabled(!model.canPause(ids))
            Divider()
            Toggle("Download in Order", isOn: Binding(get: { model.isSequential(ids) },
                                                      set: { model.setSequential(ids, $0) }))
            Divider()
            Button("Show in Finder", systemImage: "folder") { model.revealInFinder(ids) }
            Button("Copy Magnet Link", systemImage: "link") { model.copyMagnetLinks(ids) }
            Button("Copy Info Hash", systemImage: "number") { model.copyInfoHashes(ids) }
            Divider()
            Button("Remove…", systemImage: "trash", role: .destructive) { model.requestRemove(ids) }
        }
    }
}

/// Empty states drawn over the (still focusable) table so ⌘V keeps working.
private struct EmptyStateOverlay: View {
    let model: AppModel

    var body: some View {
        if model.phase == .starting {
            ProgressView("Starting…")
        } else if model.isRunning && model.totalTorrents == 0 {
            ContentUnavailableView {
                Label("No Torrents Yet", systemImage: "arrow.down.circle")
            } description: {
                Text("Drag a .torrent file into this window, paste a magnet link with ⌘V, or use the buttons below.")
            } actions: {
                Button("Open Torrent File…") { model.showingOpenPanel = true }
                Button("Add Magnet Link…") { model.showAddMagnet() }
            }
        } else if model.isRunning && model.visibleRows.isEmpty {
            if model.searchText.isEmpty {
                ContentUnavailableView("Nothing Here", systemImage: model.filter.symbol,
                                       description: Text(model.filter.emptyText))
            } else {
                ContentUnavailableView.search(text: model.searchText)
            }
        }
    }
}
#endif
