#if os(macOS)
import SwiftUI
import TorrentCore

private struct TrackerRow: Identifiable {
    let id: String
    let url: String
    let host: String
    let tier: Int
    let status: String
    let isError: Bool
    let seeders: Int
    let leechers: Int
    let peers: Int
    let next: Double

    init(_ t: TrackerStatus) {
        id = "\(t.tier)|\(t.url)"
        url = t.url
        host = Fmt.trackerHost(t.url)
        tier = t.tier
        seeders = t.seeders ?? -1
        leechers = t.leechers ?? -1
        peers = t.lastPeerCount
        next = t.nextAnnounceIn
        if t.isUpdating {
            status = "Updating…"; isError = false
        } else if let e = t.lastError {
            status = e; isError = true
        } else if let w = t.warning {
            status = w; isError = false
        } else if t.seeders != nil || t.lastPeerCount > 0 {
            status = "Working"; isError = false
        } else {
            status = "Waiting"; isError = false
        }
    }
}

struct TrackersTab: View {
    let status: TorrentStatus
    @State private var sortOrder = [KeyPathComparator(\TrackerRow.tier)]

    private var rows: [TrackerRow] {
        var seen = Set<String>()
        return status.trackers.map(TrackerRow.init).filter { seen.insert($0.id).inserted }.sorted(using: sortOrder)
    }

    var body: some View {
        // Narrow inspector: the URL carries its status on a second line.
        Table(rows, sortOrder: $sortOrder) {
            TableColumn("Tracker", value: \.host) { t in
                VStack(alignment: .leading, spacing: 1) {
                    Text(t.host).lineLimit(1).truncationMode(.middle)
                    Text(t.status)
                        .font(.caption)
                        .lineLimit(1)
                        .foregroundStyle(t.isError ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                }
                .help("\(t.url)\nTier \(t.tier + 1)\n\(t.status)\nPeers received: \(t.peers)")
            }
            .width(min: 110, ideal: 160)
            TableColumn("Seeds", value: \.seeders) { t in
                VStack(alignment: .trailing, spacing: 1) {
                    Text(t.seeders >= 0 ? Fmt.count(t.seeders) : "—")
                    Text(t.leechers >= 0 ? Fmt.count(t.leechers) : "—")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .monospacedDigit()
                .help("Seeders (top) and leechers (bottom) reported by this tracker")
            }
            .width(min: 44, ideal: 54)
            .alignment(.trailing)
            TableColumn("Next", value: \.next) { t in
                Text(t.next > 0 ? Fmt.duration(t.next) : "—").monospacedDigit().foregroundStyle(.secondary)
                    .help("Time until Astor asks this tracker for peers again")
            }
            .width(min: 50, ideal: 62)
            .alignment(.trailing)
        }
        .overlay {
            if status.trackers.isEmpty {
                ContentUnavailableView("No Trackers", systemImage: "antenna.radiowaves.left.and.right.slash",
                                       description: Text("This torrent finds peers through DHT, peer exchange and the local network."))
            }
        }
        .safeAreaBar(edge: .bottom) {
            Text(footer)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
        }
    }

    private var footer: String {
        let working = rows.filter { $0.status == "Working" }.count
        let failing = rows.filter(\.isError).count
        return "\(rows.count) trackers · \(working) working · \(failing) not responding"
    }
}
#endif
