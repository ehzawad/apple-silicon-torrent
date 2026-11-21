#if os(macOS)
import Foundation
import UserNotifications

/// "Download finished" notifications. Permission is requested lazily, the first
/// time a download actually completes, so testing or browsing never prompts.
@MainActor
final class Notifier {
    private let delegate = PresentationDelegate()
    private var configured = false

    /// UNUserNotificationCenter needs a real app bundle (not `swift run`).
    private var available: Bool { Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app" }

    func downloadFinished(name: String, id: String) {
        guard available, UserDefaults.standard.bool(forKey: SettingsKey.notifyOnCompletion) else { return }
        let center = UNUserNotificationCenter.current()
        if !configured {
            center.delegate = delegate
            configured = true
        }
        Task {
            let granted = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = "Download finished"
            content.body = name
            content.sound = .default
            content.threadIdentifier = "downloads"
            let request = UNNotificationRequest(identifier: "complete-\(id)", content: content, trigger: nil)
            try? await center.add(request)
        }
    }
}

/// Shows banners even while Astor is the frontmost app.
private final class PresentationDelegate: NSObject, UNUserNotificationCenterDelegate, Sendable {
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}
#endif
