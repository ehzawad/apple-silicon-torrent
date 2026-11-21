#if os(macOS)
import SwiftUI
import TorrentCore

/// The main window: filters sidebar · torrent table + status bar · inspector.
struct MainView: View {
    @Bindable var model: AppModel
    @State private var isDropTargeted = false
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        NavigationSplitView {
            SidebarView(model: model)
                .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 280)
        } detail: {
            DetailView(model: model)
        }
        .inspector(isPresented: $model.showInspector) {
            InspectorView(model: model)
                .inspectorColumnWidth(min: 300, ideal: 360, max: 680)
        }
        .navigationTitle("Astor")
        .navigationSubtitle(model.summary)
        // Drop .torrent files (or magnet links) anywhere on the window.
        .dropDestination(for: URL.self, isEnabled: model.isRunning) { urls, _ in
            isDropTargeted = false
            model.open(urls)
        }
        .onDropSessionUpdated { session in
            switch session.phase {
            case .entering, .active: isDropTargeted = true
            default: isDropTargeted = false
            }
        }
        .overlay {
            if isDropTargeted { DropOverlay() }
        }
        .animation(.easeOut(duration: 0.15), value: isDropTargeted)
        .fileImporter(isPresented: $model.showingOpenPanel,
                      allowedContentTypes: [AppModel.torrentType],
                      allowsMultipleSelection: true) { result in
            if case .success(let urls) = result { model.open(urls) }
        }
        .fileDialogMessage("Choose one or more .torrent files to download.")
        .fileDialogConfirmationLabel("Add")
        .sheet(isPresented: $model.showingAddMagnet) {
            AddMagnetSheet(model: model)
        }
        .sheet(isPresented: $model.showingCreateTorrent) {
            CreateTorrentSheet(model: model)
        }
        .confirmationDialog(removalTitle,
                            isPresented: Binding(get: { model.pendingRemoval != nil },
                                                 set: { if !$0 { model.pendingRemoval = nil } }),
                            presenting: model.pendingRemoval) { ids in
            Button("Remove") { model.remove(ids, trashFiles: false) }
            Button("Remove and Move Files to Trash", role: .destructive) { model.remove(ids, trashFiles: true) }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("Downloaded files stay on your Mac unless you also move them to the Trash.")
        }
        .task(id: model.isRunning) {
            // Developer aid for screenshots/UI checks without clicking:
            //   open Astor.app --args -presentOnLaunch select,createTorrent
            guard model.isRunning, let list = UserDefaults.standard.string(forKey: "presentOnLaunch") else { return }
            try? await Task.sleep(for: .seconds(1.5))
            for item in list.split(separator: ",") {
                switch item {
                case "select": if let first = model.visibleRows.first { model.selection = [first.id] }
                case "addMagnet": model.showAddMagnet()
                case "createTorrent": model.showingCreateTorrent = true
                case "settings": openSettings()
                default: break
                }
            }
        }
        .alert(model.alert?.title ?? "",
               isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } }),
               presenting: model.alert) { _ in
            Button("OK") {}
        } message: { alert in
            Text(alert.message)
        }
    }

    private var removalTitle: String {
        guard let ids = model.pendingRemoval else { return "" }
        if ids.count == 1, let id = ids.first, let row = model.row(id) { return "Remove “\(row.name)”?" }
        return "Remove \(ids.count) torrents?"
    }
}

/// Detail column: the torrent table, a status bar pinned below it, and the toolbar.
private struct DetailView: View {
    @Bindable var model: AppModel

    var body: some View {
        Group {
            switch model.phase {
            case .failed(let message):
                ContentUnavailableView {
                    Label("Astor Couldn't Start", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(message)
                } actions: {
                    SettingsLink { Text("Open Settings…") }
                    Button("Quit") { NSApp.terminate(nil) }
                }
            default:
                TorrentTable(model: model)
                    .safeAreaBar(edge: .bottom) {
                        StatusBar(model: model)
                    }
            }
        }
        .searchable(text: $model.searchText, placement: .toolbar, prompt: "Search Torrents")
        .toolbar { MainToolbar(model: model) }
    }
}

private struct MainToolbar: ToolbarContent {
    let model: AppModel

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            Button("Add Torrent File", systemImage: "plus") { model.showingOpenPanel = true }
                .help("Add a .torrent file (⌘O)")
            Button("Add Magnet Link", systemImage: "link") { model.showAddMagnet() }
                .help("Add a magnet link (⌘U)")
        }

        ToolbarItemGroup {
            let ids = model.selection
            Button("Resume", systemImage: "play.fill") { model.setPaused(ids, false) }
                .help("Resume the selected torrents")
                .disabled(!model.canResume(ids))
            Button("Pause", systemImage: "pause.fill") { model.setPaused(ids, true) }
                .help("Pause the selected torrents")
                .disabled(!model.canPause(ids))
            Button("Remove", systemImage: "trash") { model.requestRemove(ids) }
                .help("Remove the selected torrents")
                .disabled(ids.isEmpty)
        }

        ToolbarSpacer(.fixed)

        ToolbarItem {
            Button("Create Torrent", systemImage: "doc.badge.plus") { model.showingCreateTorrent = true }
                .help("Create a new torrent from your files (⌘N)")
                .disabled(!model.isRunning)
        }

        ToolbarSpacer(.fixed)

        ToolbarItem {
            Button("Inspector", systemImage: "sidebar.trailing") { model.showInspector.toggle() }
                .help(model.showInspector ? "Hide details" : "Show details")
        }
    }
}

private struct DropOverlay: View {
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color.accentColor.opacity(0.08))
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [10, 6]))
            Label("Drop to add torrents", systemImage: "arrow.down.doc")
                .font(.title2.weight(.semibold))
                .foregroundStyle(Color.accentColor)
        }
        .padding(12)
        .allowsHitTesting(false)
        .transition(.opacity)
    }
}
#endif
