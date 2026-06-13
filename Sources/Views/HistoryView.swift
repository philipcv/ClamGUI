import SwiftUI

struct HistoryView: View {
    @EnvironmentObject var history: HistoryStore
    @State private var selection: ScanRecord.ID?
    @State private var confirmClear = false

    private var selectedRecord: ScanRecord? {
        history.records.first { $0.id == selection }
    }

    var body: some View {
        VStack(spacing: 0) {
            statsHeader
            Divider()
            if history.records.isEmpty {
                ContentUnavailableView(
                    "No Scan History",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Completed scans are recorded here automatically.")
                )
            } else {
                VSplitView {
                    recordsTable
                        .frame(minHeight: 240, idealHeight: 460, maxHeight: .infinity)
                    threatDetail
                        .frame(minHeight: 140, idealHeight: 200, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle("History")
        .toolbar {
            ToolbarItem {
                Button(role: .destructive) {
                    confirmClear = true
                } label: { Label("Clear History", systemImage: "trash") }
                .disabled(history.records.isEmpty)
            }
        }
        .confirmationDialog("Delete all scan history?", isPresented: $confirmClear) {
            Button("Clear All", role: .destructive) { history.clearAll() }
        }
    }

    private var statsHeader: some View {
        HStack(spacing: 24) {
            stat(value: "\(history.stats.totalScans)", label: "Scans")
            stat(value: "\(history.stats.totalThreats)", label: "Threats found")
            stat(value: history.stats.totalFilesScanned.formatted(), label: "Files scanned")
            stat(
                value: history.stats.lastScan.map {
                    $0.formatted(.relative(presentation: .named))
                } ?? "—",
                label: "Last scan"
            )
            Spacer()
            if history.persistenceFailed {
                Label("History database unavailable — records are session-only",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    private func stat(value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.title3.monospacedDigit().weight(.semibold))
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }

    private var recordsTable: some View {
        Table(history.records, selection: $selection) {
            TableColumn("Date") { record in
                Text(record.startedAt, format: .dateTime.day().month().year().hour().minute())
                    .font(.callout)
            }
            .width(150)

            TableColumn("Result") { record in
                if record.cancelled {
                    Label("Cancelled", systemImage: "minus.circle")
                        .foregroundStyle(.secondary)
                } else if record.exitCode == 0 {
                    Label("Clean", systemImage: "checkmark.seal").foregroundStyle(.green)
                } else if record.exitCode == 1 {
                    Label("\(record.threatsFound) threat(s)", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                } else {
                    Label("Error (\(record.exitCode))", systemImage: "xmark.octagon")
                        .foregroundStyle(.orange)
                }
            }
            .width(130)

            TableColumn("Targets") { record in
                Text(record.targets.joined(separator: ", "))
                    .font(.callout.monospaced())
                    .lineLimit(1).truncationMode(.middle)
                    .help(record.targets.joined(separator: "\n"))
            }

            TableColumn("Files") { record in
                Text("\(record.filesScanned)").font(.callout.monospacedDigit())
            }
            .width(70)

            TableColumn("Duration") { record in
                Text(Duration.seconds(record.duration)
                    .formatted(.time(pattern: .minuteSecond)))
                    .font(.callout.monospacedDigit())
            }
            .width(80)

            TableColumn("Profile") { record in
                Text(record.profile ?? "Custom")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .width(90)
        }
        .contextMenu(forSelectionType: ScanRecord.ID.self) { ids in
            Button("Delete Record", role: .destructive) {
                for record in history.records.filter({ ids.contains($0.id) }) {
                    history.delete(record)
                }
            }
        }
    }

    @ViewBuilder
    private var threatDetail: some View {
        if let record = selectedRecord {
            let threats = history.threats(for: record.id)
            if threats.isEmpty {
                ContentUnavailableView(
                    record.cancelled ? "Scan was cancelled" : "No threats in this scan",
                    systemImage: record.cancelled ? "minus.circle" : "checkmark.seal"
                )
            } else {
                Table(threats) {
                    TableColumn("Signature") { threat in
                        Text(threat.signature).font(.callout.monospaced()).foregroundStyle(.red)
                    }
                    .width(min: 180, ideal: 260)
                    TableColumn("Path") { threat in
                        Text(threat.path).font(.callout.monospaced())
                            .lineLimit(1).truncationMode(.middle)
                            .help(threat.path)
                            .textSelection(.enabled)
                    }
                }
            }
        } else {
            ContentUnavailableView(
                "Select a scan",
                systemImage: "cursorarrow.click",
                description: Text("Threat details for the selected scan appear here.")
            )
        }
    }
}
