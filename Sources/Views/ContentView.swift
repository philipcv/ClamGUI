import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case scan = "Scan"
    case quarantine = "Quarantine"
    case history = "History"
    case updates = "Signatures"

    var id: String { rawValue }
    var systemImage: String {
        switch self {
        case .scan: return "magnifyingglass.circle"
        case .quarantine: return "lock.shield"
        case .history: return "clock.arrow.circlepath"
        case .updates: return "arrow.triangle.2.circlepath"
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var quarantine: QuarantineManager

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $appState.selectedTab) { item in
                Label {
                    HStack {
                        Text(item.rawValue)
                        if item == .quarantine && !quarantine.entries.isEmpty {
                            Spacer()
                            Text("\(quarantine.entries.count)")
                                .font(.caption2.monospacedDigit())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.red.opacity(0.85), in: Capsule())
                                .foregroundStyle(.white)
                        }
                    }
                } icon: {
                    Image(systemName: item.systemImage)
                }
                .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
            .safeAreaInset(edge: .bottom) { toolchainStatusFooter }
        } detail: {
            if appState.toolchain == nil {
                MissingClamAVView()
            } else {
                switch appState.selectedTab ?? .scan {
                case .scan: ScanView()
                case .quarantine: QuarantineView()
                case .history: HistoryView()
                case .updates: UpdateView()
                }
            }
        }
    }

    private var toolchainStatusFooter: some View {
        VStack(alignment: .leading, spacing: 4) {
            Divider()
            HStack(spacing: 6) {
                Circle()
                    .fill(appState.toolchain != nil ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(appState.toolchain != nil ? "Engine ready" : "ClamAV not found")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if appState.clamdAvailable {
                HStack(spacing: 6) {
                    Circle().fill(Color.green).frame(width: 8, height: 8)
                    Text("clamd running").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(10)
    }
}

struct MissingClamAVView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        ContentUnavailableView {
            Label("ClamAV Not Found", systemImage: "exclamationmark.shield")
        } description: {
            Text("""
            No clamscan/freshclam binaries were found in /opt/homebrew/bin, \
            /usr/local/bin, or /opt/local/bin.

            Install with:  brew install clamav
            Then configure freshclam.conf and run an initial signature update.
            """)
            .font(.callout)
            .multilineTextAlignment(.center)
        } actions: {
            Button("Re-detect") { appState.relocateToolchain() }
            SettingsLink { Text("Set Custom Path…") }
        }
    }
}
