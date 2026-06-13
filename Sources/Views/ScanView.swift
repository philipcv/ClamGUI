import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ScanView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var scanner: ScanEngine
    @EnvironmentObject var quarantine: QuarantineManager
    @EnvironmentObject var profiles: ProfileStore

    @State private var targets: [URL] = []
    @State private var isDropTargeted = false
    @State private var quarantineError: String?

    var body: some View {
        VSplitView {
            topPane
                .frame(minHeight: 220, idealHeight: 320, maxHeight: .infinity)
            bottomPane
                .frame(minHeight: 220, idealHeight: 320, maxHeight: .infinity)
        }
        .navigationTitle("Scan")
        .toolbar { toolbarContent }
        .alert("Quarantine Failed", isPresented: .init(
            get: { quarantineError != nil },
            set: { if !$0 { quarantineError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(quarantineError ?? "")
        }
    }

    // MARK: - Top: targets + live status

    private var topPane: some View {
        VStack(spacing: 0) {
            targetList
            statusBar
        }
    }

    private var targetList: some View {
        Group {
            if targets.isEmpty {
                ContentUnavailableView {
                    Label("Drop Files or Folders", systemImage: "arrow.down.doc")
                } description: {
                    Text("Drag scan targets here, or use the + button.")
                }
            } else {
                List {
                    ForEach(targets, id: \.self) { url in
                        HStack {
                            Image(systemName: url.hasDirectoryPath ? "folder" : "doc")
                                .foregroundStyle(.secondary)
                            Text(url.path).font(.callout.monospaced()).lineLimit(1)
                                .truncationMode(.middle)
                            Spacer()
                            Button {
                                targets.removeAll { $0 == url }
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.tertiary)
                            }
                            .buttonStyle(.plain)
                            .disabled(scanner.state.isRunning)
                        }
                    }
                }
                .listStyle(.inset)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleDrop(providers)
        }
        .overlay {
            if isDropTargeted {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6]))
                    .padding(4)
            }
        }
    }

    private var statusBar: some View {
        HStack(spacing: 12) {
            switch scanner.state {
            case .idle:
                Text("Ready").foregroundStyle(.secondary)
            case .running(let currentPath):
                ProgressView().controlSize(.small)
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(scanner.filesScanned) files scanned · \(scanner.threats.count) threats")
                        .font(.caption.monospacedDigit())
                    Text(currentPath ?? "Starting scan…")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            case .finished(let code):
                Image(systemName: code == 0 ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(code == 0 ? .green : (code == 1 ? .red : .orange))
                summaryText
            case .cancelled:
                Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                Text("Scan cancelled").font(.caption).foregroundStyle(.secondary)
            case .failed(let message):
                Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                Text(message).font(.caption)
            }
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.bar)
    }

    private var summaryText: some View {
        let s = scanner.summary
        var parts: [String] = []
        if let f = s.scannedFiles { parts.append("\(f) files") }
        if let i = s.infectedFiles { parts.append("\(i) infected") }
        if let d = s.dataScanned { parts.append("\(d) scanned") }
        if let t = s.duration { parts.append(t) }
        return Text(parts.joined(separator: " · "))
            .font(.caption.monospacedDigit())
            .foregroundStyle(.secondary)
    }

    // MARK: - Bottom: tabs for threats / raw log

    private var bottomPane: some View {
        TabView {
            threatTable
                .tabItem { Label("Threats (\(scanner.threats.count))", systemImage: "ladybug") }
            logView
                .tabItem { Label("Log", systemImage: "terminal") }
        }
        .padding(8)
    }

    private var threatTable: some View {
        Table(scanner.threats) {
            TableColumn("Signature") { threat in
                Text(threat.signature).font(.callout.monospaced()).foregroundStyle(.red)
            }
            .width(min: 180, ideal: 260)
            TableColumn("Path") { threat in
                Text(threat.path).font(.callout.monospaced())
                    .lineLimit(1).truncationMode(.middle)
                    .help(threat.path)
            }
            TableColumn("") { threat in
                HStack {
                    Button("Quarantine") { quarantineThreat(threat) }
                        .controlSize(.small)
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: threat.path)])
                    } label: { Image(systemName: "magnifyingglass") }
                    .controlSize(.small)
                    .help("Reveal in Finder")
                }
            }
            .width(160)
        }
    }

    private var logView: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(scanner.log) { line in
                        Text(line.text)
                            .font(.caption.monospaced())
                            .foregroundStyle(color(for: line.kind))
                            .textSelection(.enabled)
                            .id(line.id)
                    }
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Color(nsColor: .textBackgroundColor))
            .onChange(of: scanner.log.count) {
                if let last = scanner.log.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
    }

    private func color(for kind: LogLine.Kind) -> Color {
        switch kind {
        case .info: return .secondary
        case .hit: return .red
        case .error: return .orange
        case .summary: return .primary
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup {
            profileMenu

            Button {
                addTargetsViaPanel()
            } label: { Label("Add Targets", systemImage: "plus") }
            .disabled(scanner.state.isRunning)

            if scanner.state.isRunning {
                Button(role: .destructive) {
                    scanner.cancelScan()
                } label: { Label("Stop", systemImage: "stop.fill") }
            } else {
                Button {
                    appState.startScan(targets: targets)
                } label: { Label("Scan", systemImage: "play.fill") }
                .disabled(targets.isEmpty || appState.toolchain == nil)
                .keyboardShortcut("r", modifiers: .command)
            }
        }
    }

    private var profileMenu: some View {
        Menu {
            ForEach(profiles.profiles) { profile in
                Button {
                    appState.apply(profile: profile)
                } label: {
                    if appState.activeProfileID == profile.id {
                        Label(profile.name, systemImage: "checkmark")
                    } else {
                        Text(profile.name)
                    }
                }
            }
            Divider()
            SettingsLink { Text("Manage Profiles…") }
        } label: {
            Label(appState.activeProfileName ?? "Custom", systemImage: "slider.horizontal.3")
        }
        .disabled(scanner.state.isRunning)
        .help("Scan profile (edit in Settings)")
    }

    // MARK: - Actions

    private func addTargetsViaPanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Add to Scan"
        if panel.runModal() == .OK {
            merge(urls: panel.urls)
        }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        for provider in providers {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in merge(urls: [url]) }
            }
        }
        return true
    }

    private func merge(urls: [URL]) {
        for url in urls where !targets.contains(url) {
            targets.append(url)
        }
    }

    private func quarantineThreat(_ threat: DetectedThreat) {
        do {
            try quarantine.quarantine(threat: threat)
            scanner.threats.removeAll { $0.id == threat.id }
        } catch {
            quarantineError = "\(threat.path): \(error.localizedDescription)"
        }
    }
}
