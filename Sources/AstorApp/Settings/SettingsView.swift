#if os(macOS)
import AppKit
import SwiftUI
import TorrentCore

/// The Settings window (⌘,). Values persist in UserDefaults via `@AppStorage`.
/// The download folder and notifications apply immediately; everything that
/// configures the network engine applies after Astor restarts.
enum SettingsTab: String {
    case general, speed, peers, network, privacy
}

struct SettingsView: View {
    let model: AppModel
    @AppStorage("settingsTab") private var tab: SettingsTab = .general

    var body: some View {
        TabView(selection: $tab) {
            Tab("General", systemImage: "gearshape", value: .general) {
                GeneralSettings(model: model)
                    .frame(height: 320)
            }
            Tab("Speed", systemImage: "speedometer", value: .speed) {
                SpeedSettings(model: model)
                    .frame(height: 330)
            }
            Tab("Peers", systemImage: "person.2", value: .peers) {
                PeerSettings(model: model)
                    .frame(height: 430)
            }
            Tab("Network", systemImage: "network", value: .network) {
                NetworkSettings(model: model)
                    .frame(height: 470)
            }
            Tab("Privacy", systemImage: "lock", value: .privacy) {
                PrivacySettings(model: model)
                    .frame(height: 470)
            }
        }
        .frame(width: 580)
    }
}

/// "Changes apply after restart" banner with a one-click restart. It reads every
/// engine setting through `@AppStorage` so it updates as soon as any of them change.
private struct RestartNotice: View {
    let model: AppModel
    @AppStorage(SettingsKey.encryption) private var encryption: EncryptionPolicy = .prefer
    @AppStorage(SettingsKey.listenPort) private var listenPort = 0
    @AppStorage(SettingsKey.maxPeersPerTorrent) private var maxPeers = 200
    @AppStorage(SettingsKey.maxConnections) private var maxConnections = 600
    @AppStorage(SettingsKey.limitDownload) private var limitDownload = false
    @AppStorage(SettingsKey.downloadLimitKB) private var downloadLimit = 5_000
    @AppStorage(SettingsKey.limitUpload) private var limitUpload = false
    @AppStorage(SettingsKey.uploadLimitKB) private var uploadLimit = 1_000
    @AppStorage(SettingsKey.enableDHT) private var dht = true
    @AppStorage(SettingsKey.enablePEX) private var pex = true
    @AppStorage(SettingsKey.enableUTP) private var utp = true
    @AppStorage(SettingsKey.enableLSD) private var lsd = true
    @AppStorage(SettingsKey.enablePortMapping) private var portMapping = true
    @AppStorage(SettingsKey.extraTrackers) private var extraTrackers = true

    private var current: EngineSettings {
        EngineSettings(encryption: encryption, listenPort: listenPort, maxPeersPerTorrent: maxPeers,
                       maxConnections: maxConnections,
                       downloadLimitKB: limitDownload ? downloadLimit : nil,
                       uploadLimitKB: limitUpload ? uploadLimit : nil,
                       enableDHT: dht, enablePEX: pex, enableUTP: utp, enableLSD: lsd,
                       enablePortMapping: portMapping, extraTrackers: extraTrackers)
    }

    var body: some View {
        let pending = current != model.launchSettings
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: pending ? "arrow.clockwise.circle.fill" : "info.circle")
                .foregroundStyle(pending ? Color.orange : Color.secondary)
            Text(pending ? "You changed settings that apply after Astor restarts."
                         : "Network and speed settings apply after Astor restarts.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            if pending {
                Button("Restart Astor") { model.relaunch() }
            }
        }
        .font(.callout)
    }
}

private struct GeneralSettings: View {
    let model: AppModel
    @AppStorage(SettingsKey.downloadDirectory) private var downloadDirectory = SessionConfig.defaultDownloadDirectory.path
    @AppStorage(SettingsKey.notifyOnCompletion) private var notify = true
    @AppStorage(SettingsKey.preventSleep) private var preventSleep = true

    var body: some View {
        Form {
            Section {
                LabeledContent("Save downloads to") {
                    HStack {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: downloadDirectory))
                            .resizable()
                            .frame(width: 18, height: 18)
                        Text((downloadDirectory as NSString).abbreviatingWithTildeInPath)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Choose…", action: chooseFolder)
                    }
                }
            } footer: {
                Text("New torrents go here. Torrents you already added keep their folder.")
            }

            Section {
                Toggle("Notify me when a download finishes", isOn: $notify)
                Toggle(isOn: $preventSleep) {
                    Text("Keep my Mac awake while downloading")
                    Text("Your Mac can still sleep when you close the lid, or once nothing is downloading.")
                }
            }
        }
        .formStyle(.grouped)
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose"
        panel.directoryURL = URL(fileURLWithPath: downloadDirectory, isDirectory: true)
        if panel.runModal() == .OK, let url = panel.url { downloadDirectory = url.path }
    }
}

private struct PrivacySettings: View {
    let model: AppModel
    @AppStorage(SettingsKey.encryption) private var encryption: EncryptionPolicy = .prefer

    var body: some View {
        Form {
            Section {
                Picker("Encryption", selection: $encryption) {
                    ForEach([EncryptionPolicy.prefer, .require, .disabled], id: \.self) { p in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.title)
                            Text(p.explanation)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(.vertical, 3)
                        .tag(p)
                    }
                }
                .pickerStyle(.radioGroup)
                .labelsHidden()
            } header: {
                Text("Connection Encryption")
            } footer: {
                Text("Encryption hides what kind of traffic this is from your internet provider. It doesn't make you anonymous: other peers still see your IP address.")
            }

            Section {
                RestartNotice(model: model)
            }
        }
        .formStyle(.grouped)
    }
}

private struct PeerSettings: View {
    let model: AppModel
    @AppStorage(SettingsKey.enableDHT) private var dht = true
    @AppStorage(SettingsKey.enablePEX) private var pex = true
    @AppStorage(SettingsKey.enableLSD) private var lsd = true
    @AppStorage(SettingsKey.extraTrackers) private var extraTrackers = true

    var body: some View {
        Form {
            Section("Finding Peers") {
                Toggle(isOn: $dht) {
                    Text("Distributed hash table (DHT)")
                    Text("Find peers without trackers. Needed for most magnet links.")
                }
                Toggle(isOn: $pex) {
                    Text("Peer exchange (PEX)")
                    Text("Peers you're connected to tell you about other peers.")
                }
                Toggle(isOn: $lsd) {
                    Text("Local peer discovery")
                    Text("Find people sharing the same torrent on your home or office network.")
                }
                Toggle(isOn: $extraTrackers) {
                    Text("Add public trackers to public torrents")
                    Text("Also asks a few well-known open trackers, which usually finds more peers.")
                }
            }

            Section {
                RestartNotice(model: model)
            }
        }
        .formStyle(.grouped)
    }
}

private struct NetworkSettings: View {
    let model: AppModel
    @AppStorage(SettingsKey.listenPort) private var listenPort = 0
    @AppStorage(SettingsKey.maxPeersPerTorrent) private var maxPeers = 200
    @AppStorage(SettingsKey.maxConnections) private var maxConnections = 600
    @AppStorage(SettingsKey.enableUTP) private var utp = true
    @AppStorage(SettingsKey.enablePortMapping) private var portMapping = true

    private var automaticPort: Binding<Bool> {
        Binding {
            listenPort == 0
        } set: { auto in
            let current = Int(model.sessionInfo.listenPort)
            listenPort = auto ? 0 : (current >= 1024 ? current : 51413)
        }
    }

    var body: some View {
        Form {
            Section {
                Toggle("Choose a port automatically", isOn: automaticPort)
                if listenPort != 0 {
                    LabeledContent("Listening port") {
                        TextField("Port", value: $listenPort, format: .number.grouping(.never))
                            .labelsHidden()
                            .multilineTextAlignment(.trailing)
                            .frame(width: 80)
                    }
                }
                Toggle(isOn: $portMapping) {
                    Text("Open the port on my router automatically")
                    Text("Uses UPnP and NAT-PMP so others can connect to you, which usually makes downloads faster.")
                }
            } header: {
                Text("Incoming Connections")
            } footer: {
                if model.sessionInfo.listenPort > 0 {
                    Text("Astor is using port \(String(model.sessionInfo.listenPort)) for TCP and UDP.")
                }
            }

            Section("Connections") {
                NumberStepper(title: "Peers per torrent", value: $maxPeers, range: 10...1000, step: 10)
                NumberStepper(title: "Connections overall", value: $maxConnections, range: 50...3000, step: 50)
                Toggle(isOn: $utp) {
                    Text("Use µTP")
                    Text("A connection type that backs off when your network is busy, so browsing stays smooth.")
                }
            }

            Section {
                RestartNotice(model: model)
            }
        }
        .formStyle(.grouped)
    }
}

private struct SpeedSettings: View {
    let model: AppModel
    @AppStorage(SettingsKey.limitDownload) private var limitDownload = false
    @AppStorage(SettingsKey.downloadLimitKB) private var downloadLimit = 5_000
    @AppStorage(SettingsKey.limitUpload) private var limitUpload = false
    @AppStorage(SettingsKey.uploadLimitKB) private var uploadLimit = 1_000

    var body: some View {
        Form {
            Section {
                Toggle("Limit download speed", isOn: $limitDownload)
                if limitDownload {
                    LimitField(title: "Download limit", value: $downloadLimit)
                }
                Toggle("Limit upload speed", isOn: $limitUpload)
                if limitUpload {
                    LimitField(title: "Upload limit", value: $uploadLimit)
                }
            } footer: {
                Text("Limits help if Astor makes video calls or browsing slow. 1,000 KB/s is about 8 Mbit/s.")
            }

            Section {
                RestartNotice(model: model)
            }
        }
        .formStyle(.grouped)
    }
}

private struct NumberStepper: View {
    let title: String
    @Binding var value: Int
    let range: ClosedRange<Int>
    let step: Int

    var body: some View {
        LabeledContent(title) {
            HStack(spacing: 6) {
                Text("\(value)").monospacedDigit()
                Stepper(title, value: $value, in: range, step: step)
                    .labelsHidden()
            }
        }
    }
}

private struct LimitField: View {
    let title: String
    @Binding var value: Int

    var body: some View {
        LabeledContent(title) {
            HStack(spacing: 6) {
                TextField(title, value: $value, format: .number)
                    .labelsHidden()
                    .multilineTextAlignment(.trailing)
                    .frame(width: 90)
                Text("KB/s").foregroundStyle(.secondary)
                Stepper(title, value: $value, in: 10...1_000_000, step: 100)
                    .labelsHidden()
            }
        }
    }
}
#endif
