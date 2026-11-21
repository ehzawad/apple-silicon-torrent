#if os(macOS)
import SwiftUI

/// Footer with totals and network health, in plain language.
struct StatusBar: View {
    let model: AppModel

    var body: some View {
        let info = model.sessionInfo
        HStack(spacing: 14) {
            Label(Fmt.rate(info.downloadRate), systemImage: "arrow.down")
                .help("Total download speed")
            Label(Fmt.rate(info.uploadRate), systemImage: "arrow.up")
                .help("Total upload speed")

            // Secondary facts drop out (least important first) when space is tight.
            ViewThatFits(in: .horizontal) {
                details(info, port: true, ip: true)
                details(info, port: true, ip: false)
                details(info, port: false, ip: false)
                Color.clear.frame(width: 0, height: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            ReachabilityButton(model: model)
                .fixedSize()
                .layoutPriority(1)
        }
        .labelStyle(StatusLabelStyle())
        .font(.callout)
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
    }

    private func details(_ info: SessionInfo, port: Bool, ip: Bool) -> some View {
        HStack(spacing: 14) {
            Divider().frame(height: 14)
            Label("DHT \(Fmt.count(info.dhtNodes))", systemImage: "point.3.connected.trianglepath.dotted")
                .help(model.launchSettings.enableDHT
                      ? "Nodes in the distributed network Astor uses to find peers without trackers"
                      : "DHT is turned off in Settings")
            if port && info.listenPort > 0 {
                Label("Port \(String(info.listenPort))", systemImage: "network")
                    .help("Astor listens for incoming connections on this port (TCP and UDP)")
            }
            if ip, let addr = info.externalIP {
                Label(addr, systemImage: "globe")
                    .help("Your public IP address, as other peers see it")
            }
        }
        .fixedSize()
    }
}

private struct StatusLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 4) {
            configuration.icon.imageScale(.small)
            configuration.title.monospacedDigit()
        }
    }
}

/// Whether other peers can connect to us, with a plain-language explanation.
enum Reachability: Equatable {
    case checking
    case mapped([String])
    case incoming
    case mappingDisabled
    case unreachable

    init(info: SessionInfo, mappingEnabled: Bool, settled: Bool) {
        if !info.mappedVia.isEmpty { self = .mapped(info.mappedVia) }
        else if info.incomingConnections > 0 { self = .incoming }
        else if !mappingEnabled { self = .mappingDisabled }
        else if !settled { self = .checking }
        else { self = .unreachable }
    }

    var isReachable: Bool {
        switch self {
        case .mapped, .incoming: true
        default: false
        }
    }

    var title: String {
        switch self {
        case .checking: "Checking connection…"
        case .mapped(let via): "Reachable via \(via.joined(separator: " / "))"
        case .incoming: "Reachable"
        case .mappingDisabled, .unreachable: "Not reachable"
        }
    }

    var symbol: String {
        switch self {
        case .checking: "circle.dotted"
        case .mapped, .incoming: "checkmark.circle.fill"
        case .mappingDisabled, .unreachable: "exclamationmark.triangle.fill"
        }
    }

    var tint: Color {
        switch self {
        case .checking: .secondary
        case .mapped, .incoming: .green
        case .mappingDisabled, .unreachable: .orange
        }
    }
}

private struct ReachabilityButton: View {
    let model: AppModel
    @State private var showingHelp = false

    var body: some View {
        let info = model.sessionInfo
        let state = Reachability(info: info, mappingEnabled: model.launchSettings.enablePortMapping,
                                 settled: model.startupGraceOver)
        Button {
            showingHelp.toggle()
        } label: {
            Label(state.title, systemImage: state.symbol)
                .foregroundStyle(state.tint)
        }
        .buttonStyle(.plain)
        .help("Can other people connect to you? Click for details.")
        .popover(isPresented: $showingHelp, arrowEdge: .top) {
            ReachabilityHelp(state: state, info: info)
        }
    }
}

private struct ReachabilityHelp: View {
    let state: Reachability
    let info: SessionInfo

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(state.title, systemImage: state.symbol)
                .font(.headline)
                .foregroundStyle(state.tint)
            Text(explanation)
                .fixedSize(horizontal: false, vertical: true)
            if !state.isReachable && state != .checking {
                Text(fix)
                    .fixedSize(horizontal: false, vertical: true)
                if !info.mappingErrors.isEmpty {
                    DisclosureGroup("Technical details") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(info.mappingErrors, id: \.self) { Text($0) }
                        }
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(16)
        .frame(width: 360)
    }

    private var port: String { info.listenPort > 0 ? String(info.listenPort) : "Astor's port" }

    private var explanation: String {
        switch state {
        case .checking:
            "Astor is asking your router to open a port so other people can connect to you. This takes a few seconds."
        case .mapped(let via):
            "Your router opened port \(port) for Astor using \(via.joined(separator: " and ")). Other people can connect to you directly, which helps downloads go faster."
        case .incoming:
            "Other people are connecting to you on port \(port), so your network is letting them in."
        case .mappingDisabled:
            "Automatic port opening (UPnP / NAT-PMP) is turned off in Settings, and nobody has connected to you yet. Downloads still work, but you can only reach people who are themselves reachable, which can be slower."
        case .unreachable:
            "Other people can't start connections to you. Downloads still work, but you can only reach people who are themselves reachable, which can be slower."
        }
    }

    private var fix: String {
        "To fix this, turn on UPnP or NAT-PMP in your router's settings (often under “Advanced” or “NAT”), or forward port \(port) for both TCP and UDP to this Mac. Then restart Astor. If you use a VPN, its port forwarding feature does the same job."
    }
}
#endif
