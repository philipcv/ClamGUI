import SwiftUI
import AppKit

struct QuarantineView: View {
    @EnvironmentObject var quarantine: QuarantineManager
    @State private var selection: Set<QuarantineEntry.ID> = []
    @State private var actionError: String?
    @State private var confirmDeleteAll = false

    var body: some View {
        Group {
            if quarantine.entries.isEmpty {
                ContentUnavailableView(
                    "Quarantine Empty",
                    systemImage: "lock.shield",
                    description: Text("Files quarantined from scan results appear here.")
                )
            } else {
                Table(quarantine.entries, selection: $selection) {
                    TableColumn("Signature") { entry in
                        Text(entry.signature).font(.callout.monospaced()).foregroundStyle(.red)
                    }
                    .width(min: 160, ideal: 240)

                    TableColumn("Original Path") { entry in
                        Text(entry.originalPath)
                            .font(.callout.monospaced())
                            .lineLimit(1).truncationMode(.middle)
                            .help(entry.originalPath)
                    }

                    TableColumn("Size") { entry in
                        Text(ByteCountFormatter.string(fromByteCount: entry.fileSize, countStyle: .file))
                            .font(.caption.monospacedDigit())
                    }
                    .width(80)

                    TableColumn("Quarantined") { entry in
                        Text(entry.quarantinedAt, format: .dateTime.day().month().hour().minute())
                            .font(.caption)
                    }
                    .width(130)

                    TableColumn("SHA-256") { entry in
                        Text(entry.sha256)
                            .font(.caption2.monospaced())
                            .lineLimit(1).truncationMode(.middle)
                            .textSelection(.enabled)
                            .help(entry.sha256)
                    }
                    .width(min: 120, ideal: 160)
                }
                .contextMenu(forSelectionType: QuarantineEntry.ID.self) { ids in
                    Button("Restore") { performOnSelection(ids, op: quarantine.restore) }
                    Button("Copy SHA-256") {
                        let hashes = quarantine.entries
                            .filter { ids.contains($0.id) }
                            .map(\.sha256).joined(separator: "\n")
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(hashes, forType: .string)
                    }
                    Divider()
                    Button("Delete Permanently", role: .destructive) {
                        performOnSelection(ids, op: quarantine.delete)
                    }
                }
            }
        }
        .navigationTitle("Quarantine")
        .toolbar {
            ToolbarItemGroup {
                Button(role: .destructive) {
                    confirmDeleteAll = true
                } label: { Label("Delete All", systemImage: "trash") }
                .disabled(quarantine.entries.isEmpty)
            }
        }
        .confirmationDialog(
            "Permanently delete all \(quarantine.entries.count) quarantined files?",
            isPresented: $confirmDeleteAll
        ) {
            Button("Delete All", role: .destructive) { quarantine.deleteAll() }
        }
        .alert("Operation Failed", isPresented: .init(
            get: { actionError != nil },
            set: { if !$0 { actionError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: { Text(actionError ?? "") }
    }

    private func performOnSelection(_ ids: Set<QuarantineEntry.ID>,
                                    op: (QuarantineEntry) throws -> Void) {
        for entry in quarantine.entries.filter({ ids.contains($0.id) }) {
            do { try op(entry) } catch { actionError = error.localizedDescription }
        }
    }
}
