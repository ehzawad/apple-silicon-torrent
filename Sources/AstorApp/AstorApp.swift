#if os(macOS)
import SwiftUI

@main
struct AstorApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        // One main window (a torrent client has a single list); closing it keeps
        // downloads running, and the Dock icon reopens it.
        Window("Astor", id: "main") {
            MainView(model: appDelegate.model)
                .frame(minWidth: 760, minHeight: 420)
                // Route .torrent files and magnet: links from Finder/browsers here
                // instead of spawning new windows.
                .handlesExternalEvents(preferring: ["*"], allowing: ["*"])
                .onOpenURL { url in appDelegate.model.open([url]) }
        }
        .defaultSize(width: 1320, height: 740)
        .windowResizability(.contentMinSize)
        .handlesExternalEvents(matching: ["*"])
        .commands {
            AstorCommands(model: appDelegate.model)
            SidebarCommands()
            InspectorCommands()
        }

        Settings {
            SettingsView(model: appDelegate.model)
        }
    }
}

/// Menu bar commands (File additions + a Torrent menu).
struct AstorCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Group {
                Button("Open Torrent File…") { model.showingOpenPanel = true }
                    .keyboardShortcut("o")
                Button("Add Magnet Link…") { model.showAddMagnet() }
                    .keyboardShortcut("u")
                Divider()
                Button("Create Torrent…") { model.showingCreateTorrent = true }
                    .keyboardShortcut("n")
            }
            .disabled(!model.isRunning)
        }

        CommandMenu("Torrent") {
            let ids = model.selection
            Button("Resume") { model.setPaused(ids, false) }
                .keyboardShortcut("/")
                .disabled(!model.canResume(ids))
            Button("Pause") { model.setPaused(ids, true) }
                .keyboardShortcut(".")
                .disabled(!model.canPause(ids))
            Divider()
            Button("Resume All") { model.resumeAll() }
                .keyboardShortcut("/", modifiers: [.command, .option])
            Button("Pause All") { model.pauseAll() }
                .keyboardShortcut(".", modifiers: [.command, .option])
            Divider()
            Toggle("Download in Order", isOn: Binding(
                get: { model.isSequential(ids) },
                set: { model.setSequential(ids, $0) }))
                .disabled(ids.isEmpty)
            Divider()
            Button("Show in Finder") { model.revealInFinder(ids) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(ids.isEmpty)
            Button("Copy Magnet Link") { model.copyMagnetLinks(ids) }
                .keyboardShortcut("c", modifiers: [.command, .shift])
                .disabled(ids.isEmpty)
            Button("Copy Info Hash") { model.copyInfoHashes(ids) }
                .disabled(ids.isEmpty)
            Divider()
            Button("Remove…") { model.requestRemove(ids) }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(ids.isEmpty)
        }
    }
}
#else
// The app target is macOS-only; keep the package buildable for other platforms.
@main
enum AstorAppUnsupported {
    static func main() {}
}
#endif
