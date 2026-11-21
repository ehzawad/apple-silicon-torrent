#if os(macOS)
import SwiftUI
import TorrentCore

enum InspectorTab: String, CaseIterable, Identifiable {
    case overview, peers, trackers, files
    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: "Overview"
        case .peers: "Peers"
        case .trackers: "Trackers"
        case .files: "Files"
        }
    }
}

/// Trailing inspector for the selected torrent.
struct InspectorView: View {
    let model: AppModel
    @AppStorage("inspectorTab") private var tab: InspectorTab = .overview

    var body: some View {
        Group {
            if let status = model.selectedStatus {
                content(status)
                    .safeAreaBar(edge: .top) {
                        Picker("Section", selection: $tab) {
                            ForEach(InspectorTab.allCases) { Text($0.title).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }
            } else if model.selection.count > 1 {
                ContentUnavailableView("\(model.selection.count) Torrents Selected",
                                       systemImage: "square.stack.3d.up",
                                       description: Text("Select a single torrent to see its details."))
            } else {
                ContentUnavailableView("No Selection", systemImage: "info.circle",
                                       description: Text("Select a torrent to see its details."))
            }
        }
    }

    @ViewBuilder
    private func content(_ status: TorrentStatus) -> some View {
        let details = model.details[status.infoHash]
        switch tab {
        case .overview: OverviewTab(model: model, status: status, details: details)
        case .peers: PeersTab(status: status)
        case .trackers: TrackersTab(status: status)
        case .files: FilesTab(model: model, id: status.infoHash, details: details)
        }
    }
}
#endif
