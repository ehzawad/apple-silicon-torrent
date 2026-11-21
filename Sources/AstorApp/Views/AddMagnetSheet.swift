#if os(macOS)
import SwiftUI
import TorrentCore

struct AddMagnetSheet: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @FocusState private var editorFocused: Bool

    private struct Parsed: Identifiable {
        let id: Int
        let text: String
        let magnet: MagnetLink?
    }

    private var parsed: [Parsed] {
        model.magnetDraft
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .enumerated()
            .map { Parsed(id: $0.offset, text: $0.element, magnet: MagnetLink($0.element)) }
    }

    var body: some View {
        let items = parsed
        let valid = items.filter { $0.magnet != nil }
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Add Magnet Link")
                    .font(.title2.weight(.semibold))
                Text("Paste one or more magnet links, one per line. They start with “magnet:?”.")
                    .foregroundStyle(.secondary)
            }

            TextEditor(text: $model.magnetDraft)
                .font(.system(.callout, design: .monospaced))
                .focused($editorFocused)
                .scrollContentBackground(.hidden)
                .padding(6)
                .frame(minHeight: 96, maxHeight: 160)
                .background(.background, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(.separator)
                }
                .accessibilityLabel("Magnet links")

            if !items.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(items.prefix(6)) { item in
                        if let m = item.magnet {
                            Label(m.displayName ?? "Torrent \(m.infoHashes.description.prefix(12))…",
                                  systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        } else {
                            Label("Not a magnet link: \(item.text.prefix(40))", systemImage: "xmark.circle.fill")
                                .foregroundStyle(.red)
                        }
                    }
                    if items.count > 6 {
                        Text("and \(items.count - 6) more").foregroundStyle(.secondary)
                    }
                }
                .font(.callout)
                .lineLimit(1)
                .truncationMode(.middle)
            }

            Label {
                Text("Saves to \((EngineSettings.downloadDirectory.path as NSString).abbreviatingWithTildeInPath)")
            } icon: {
                Image(systemName: "folder")
            }
            .font(.callout)
            .foregroundStyle(.secondary)

            HStack {
                SettingsLink { Text("Change Folder…") }
                    .buttonStyle(.link)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(valid.count > 1 ? "Add \(valid.count) Torrents" : "Add") {
                    model.addMagnets(valid.map(\.text).joined(separator: "\n"))
                    model.magnetDraft = ""
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(valid.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 540)
        .onAppear { editorFocused = true }
    }
}
#endif
