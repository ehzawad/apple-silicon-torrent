#if os(macOS)
import SwiftUI
import TorrentCore

struct OverviewTab: View {
    let model: AppModel
    let status: TorrentStatus
    let details: TorrentDetails?

    private var row: TorrentRow { TorrentRow(status, index: 0) }

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(status.name)
                        .font(.headline)
                        .lineLimit(3)
                        .textSelection(.enabled)
                    Label(row.statusText, systemImage: row.statusSymbol)
                        .foregroundStyle(row.tint)
                    ProgressView(value: min(max(status.progress, 0), 1))
                        .tint(row.tint)
                    Text(progressLine)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
                .padding(.vertical, 2)
            }

            if let error = status.error {
                Section("Problem") {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }
            }

            Section("Transfer") {
                LabeledContent("Download speed", value: Fmt.rate(status.downloadRate))
                LabeledContent("Upload speed", value: Fmt.rate(status.uploadRate))
                LabeledContent("Time left", value: row.etaText)
                LabeledContent("Downloaded", value: Fmt.bytes(status.downloadedTotal))
                LabeledContent("Uploaded", value: Fmt.bytes(status.uploadedTotal))
                LabeledContent("Share ratio", value: Fmt.ratio(uploaded: status.uploadedTotal,
                                                               downloaded: status.downloadedTotal,
                                                               size: status.wantedBytes))
                if status.wastedBytes > 0 || status.hashFailures > 0 {
                    LabeledContent("Discarded", value: "\(Fmt.bytes(status.wastedBytes)) · \(status.hashFailures) bad pieces")
                }
            }

            Section("Torrent") {
                LabeledContent("Format", value: Fmt.version(status.version ?? details?.version))
                HashRow(title: "Info hash v1", hash: details?.infoHashV1 ?? (status.infoHash.count == 40 ? status.infoHash : nil),
                        model: model)
                if let v2 = details?.infoHashV2 ?? (status.infoHash.count == 64 ? status.infoHash : nil) {
                    HashRow(title: "Info hash v2", hash: v2, model: model)
                }
                if status.pieceCount > 0 {
                    LabeledContent("Pieces", value: "\(Fmt.count(status.piecesHave)) of \(Fmt.count(status.pieceCount)) × \(Fmt.bytes(Int64(status.pieceLength)))")
                    LabeledContent("Availability", value: status.distributedCopies.formatted(.number.precision(.fractionLength(2))) + " copies")
                        .help("How many complete copies of the torrent the connected peers have between them")
                }
                if let d = details {
                    LabeledContent("Files", value: "\(Fmt.count(d.files.count)) · \(Fmt.bytes(d.contentLength))")
                    if d.isPrivate {
                        LabeledContent("Private", value: "Yes — peers only from its trackers")
                    }
                    if let by = d.createdBy { LabeledContent("Created by", value: by) }
                    if let date = d.creationDate { LabeledContent("Created on", value: date.formatted(date: .abbreviated, time: .shortened)) }
                    if let c = d.comment, !c.isEmpty {
                        LabeledContent("Comment") { Text(c).textSelection(.enabled).multilineTextAlignment(.trailing) }
                    }
                } else if status.state == .fetchingMetadata {
                    LabeledContent("Files", value: "Getting torrent info from peers…")
                }
            }

            Section("Location") {
                LabeledContent("Saved in") {
                    Text((status.savePath as NSString).abbreviatingWithTildeInPath)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Button("Show in Finder", systemImage: "folder") { model.revealInFinder([status.infoHash]) }
            }

            Section("Swarm") {
                LabeledContent("Trackers", value: trackerSummary)
                if status.trackerSeeders != nil || status.trackerLeechers != nil {
                    LabeledContent("Swarm size", value: "\(status.trackerSeeders.map(Fmt.count) ?? "?") seeds · \(status.trackerLeechers.map(Fmt.count) ?? "?") downloading")
                }
                LabeledContent("Connected", value: "\(status.connectedPeers) peers (\(status.connectedSeeds) seeds)")
                LabeledContent("Sending to you", value: "\(status.unchokedUs) peers")
                LabeledContent("Connecting", value: "\(status.connectingPeers)")
                LabeledContent("Encrypted", value: "\(status.encryptedPeers) of \(status.connectedPeers)")
                LabeledContent("Over µTP", value: "\(status.utpPeers) of \(status.connectedPeers)")
                LabeledContent("Incoming", value: "\(status.incomingPeers) of \(status.connectedPeers)")
                LabeledContent("Web seeds", value: webSeedSummary)
            }

            Section("Where Peers Came From") {
                let sources = PeerSource.allCases.filter { (status.knownBySource[$0] ?? 0) > 0 }
                if sources.isEmpty {
                    Text("No peers found yet").foregroundStyle(.secondary)
                } else {
                    ForEach(sources, id: \.self) { s in
                        LabeledContent(Fmt.source(s), value: Fmt.count(status.knownBySource[s] ?? 0))
                    }
                }
                LabeledContent("Known peers", value: Fmt.count(status.knownPeers))
            }
        }
        .formStyle(.grouped)
    }

    private var progressLine: String {
        if status.state == .fetchingMetadata { return "Waiting for torrent info from peers" }
        let pct = Fmt.percent(status.progress)
        guard status.wantedBytes > 0 else { return pct }
        return "\(pct) — \(Fmt.bytes(status.completedBytes)) of \(Fmt.bytes(status.wantedBytes))"
    }

    private var trackerSummary: String {
        let total = status.trackers.count
        guard total > 0 else { return "None" }
        let working = status.trackers.filter { $0.lastError == nil && ($0.seeders != nil || $0.lastPeerCount > 0) }.count
        return "\(working) of \(total) working"
    }

    private var webSeedSummary: String {
        guard status.webSeeds > 0 else { return "None" }
        return "\(status.webSeeds) · \(Fmt.rate(status.webSeedRate))"
    }
}

/// Long hex hash with a copy button (hashes don't fit a label/value row).
private struct HashRow: View {
    let title: String
    let hash: String?
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(title)
                Spacer()
                if let hash {
                    Button("Copy", systemImage: "doc.on.doc") { model.copy(hash) }
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .help("Copy \(title.lowercased())")
                }
            }
            Text(hash ?? "—")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
#endif
