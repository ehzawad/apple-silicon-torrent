#if os(macOS)
import AppKit

/// Owns the model for the app's whole lifetime and makes quitting clean: the
/// engine gets to save resume data and send tracker "stopped" announces first.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private var sigterm: (any DispatchSourceSignal)?

    func applicationWillFinishLaunching(_ notification: Notification) {
        model.start()
        installTerminationSignalHandler()
    }

    /// Keep downloading with the window closed; the Dock icon brings it back.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard model.isRunning else { return .terminateNow }
        model.shutdown {
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// `kill <pid>` (or launchd) gets the same clean shutdown as ⌘Q. AppKit refuses
    /// to terminate while a sheet is attached, so close our sheets first.
    private func installTerminationSignalHandler() {
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler { [weak self] in
            MainActor.assumeIsolated {
                self?.model.dismissPresentations()
                Task { @MainActor in
                    try? await Task.sleep(for: .milliseconds(600))
                    for w in NSApp.windows { if let s = w.attachedSheet { w.endSheet(s) } }
                    NSApp.terminate(nil)
                }
            }
        }
        source.resume()
        sigterm = source
    }
}
#endif
