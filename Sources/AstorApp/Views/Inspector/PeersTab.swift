#if os(macOS)
import SwiftUI
import TorrentCore

private struct PeerRow: Identifiable, Equatable {
    let id: String          // address
    let client: String
    let flags: String
    let down: Double
    let up: Double
    let progress: Double

    init(_ p: PeerSummary) {
        id = p.address; client = p.client; flags = p.flags
        down = p.downloadRate; up = p.uploadRate; progress = p.progress
    }
}

struct PeersTab: View {
    let status: TorrentStatus
    @State private var sortOrder = [KeyPathComparator(\PeerRow.down, order: .reverse)]

    private var rows: [PeerRow] {
        var seen = Set<String>()
        return status.topPeers.map(PeerRow.init).filter { seen.insert($0.id).inserted }.sorted(using: sortOrder)
    }

    var body: some View {
        if status.topPeers.isEmpty {
            ContentUnavailableView("No Peers Connected", systemImage: "person.2.slash",
                                   description: Text(status.state == .paused ? "This torrent is paused." : "Astor is looking for people sharing this torrent."))
        } else {
            table
        }
    }

    private var table: some View {
        // Narrow inspector: address on top, "client · flags" underneath.
        Table(rows, sortOrder: $sortOrder) {
            TableColumn("Peer", value: \.id) { p in
                VStack(alignment: .leading, spacing: 1) {
                    Text(p.id)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    HStack(spacing: 4) {
                        Text(p.client).lineLimit(1)
                        Text(p.flags).font(.system(.caption, design: .monospaced))
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                .help("\(p.id)\n\(p.client)\n\(Self.describe(p.flags))")
            }
            .width(min: 96, ideal: 118)
            TableColumn("Down", value: \.down) { p in
                Text(Fmt.cellRate(p.down)).monospacedDigit()
            }
            .width(min: 50, ideal: 58)
            .alignment(.trailing)
            TableColumn("Up", value: \.up) { p in
                Text(Fmt.cellRate(p.up)).monospacedDigit()
            }
            .width(min: 50, ideal: 58)
            .alignment(.trailing)
            TableColumn("Has", value: \.progress) { p in
                Text(Fmt.percent(p.progress, digits: 0)).monospacedDigit()
                    .help("How much of the torrent this peer has")
            }
            .width(min: 32, ideal: 36)
            .alignment(.trailing)
        }
        .safeAreaBar(edge: .bottom) {
            VStack(alignment: .leading, spacing: 2) {
                if status.connectedPeers > status.topPeers.count {
                    Text("Showing the \(status.topPeers.count) fastest of \(status.connectedPeers) connected peers.")
                }
                Text("Flags: O outgoing · I incoming · T TCP · U µTP · E encrypted · D downloading · d want data · u uploading · S snubbed")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
    }

    static func describe(_ flags: String) -> String {
        flags.compactMap { c -> String? in
            switch c {
            case "O": "You connected to them"
            case "I": "They connected to you"
            case "T": "TCP"
            case "U": "µTP"
            case "E": "Encrypted"
            case "D": "Downloading from them"
            case "d": "You want data, waiting for them"
            case "u": "Uploading to them"
            case "S": "Snubbed (stopped sending)"
            default: nil
            }
        }.joined(separator: "\n")
    }
}
#endif
