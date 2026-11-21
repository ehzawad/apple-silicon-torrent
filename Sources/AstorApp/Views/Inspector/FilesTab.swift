#if os(macOS)
import SwiftUI

/// Per-file download choices (`Torrent.selectFiles`).
struct FilesTab: View {
    let model: AppModel
    let id: String
    let details: TorrentDetails?

    var body: some View {
        if let details {
            FileList(model: model, id: id, details: details)
                .id(id)
        } else {
            ContentUnavailableView("Waiting for Torrent Info", systemImage: "hourglass",
                                   description: Text("The file list appears once Astor has received the torrent's details from peers."))
        }
    }
}

private struct FileList: View {
    let model: AppModel
    let id: String
    let details: TorrentDetails
    @State private var selected: Set<Int> = []

    var body: some View {
        List {
            ForEach(details.files) { f in
                Toggle(isOn: binding(f.id)) {
                    HStack {
                        Text(f.path)
                            .lineLimit(2)
                            .truncationMode(.middle)
                            .help(f.path)
                        Spacer()
                        Text(Fmt.bytes(f.length))
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.checkbox)
                .disabled(selected == [f.id])   // keep at least one file wanted
            }
        }
        .safeAreaBar(edge: .bottom) {
            HStack {
                Text(summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if details.files.count > 1 {
                    Button("Select All") { apply(Set(details.files.map(\.id))) }
                        .disabled(selected.count == details.files.count)
                }
            }
            .controlSize(.small)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .onAppear {
            selected = model.selectedFiles(id) ?? Set(details.files.map(\.id))
        }
    }

    private var summary: String {
        let size = details.files.filter { selected.contains($0.id) }.reduce(Int64(0)) { $0 + $1.length }
        return "\(selected.count) of \(details.files.count) files · \(Fmt.bytes(size))"
    }

    private func binding(_ fileID: Int) -> Binding<Bool> {
        Binding {
            selected.contains(fileID)
        } set: { on in
            var s = selected
            if on { s.insert(fileID) } else { s.remove(fileID) }
            guard !s.isEmpty else { return }
            apply(s)
        }
    }

    private func apply(_ s: Set<Int>) {
        selected = s
        model.setSelectedFiles(id, s)
    }
}
#endif
