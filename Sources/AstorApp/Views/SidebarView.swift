#if os(macOS)
import SwiftUI

/// Sidebar filters with live counts.
struct SidebarView: View {
    @Bindable var model: AppModel

    private var filters: [TorrentFilter] {
        TorrentFilter.allCases.filter { $0 != .errors || (model.filterCounts[.errors] ?? 0) > 0 }
    }

    var body: some View {
        List(selection: Binding(get: { Optional(model.filter) },
                                set: { if let f = $0 { model.filter = f } })) {
            Section("Torrents") {
                ForEach(filters) { f in
                    Label(f.title, systemImage: f.symbol)
                        .badge(model.filterCounts[f] ?? 0)
                        .tag(f)
                }
            }
        }
        .listStyle(.sidebar)
    }
}
#endif
