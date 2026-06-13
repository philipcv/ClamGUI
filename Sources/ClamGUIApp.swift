import SwiftUI
import AppKit

@main
struct ClamGUIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var appState = AppState()
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        Window("ClamGUI", id: "main") {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.scanner)
                .environmentObject(appState.quarantine)
                .environmentObject(appState.updater)
                .environmentObject(appState.history)
                .environmentObject(appState.profiles)
                .frame(minWidth: 900, minHeight: 580)
                // The AppDelegate's reopen handler posts this when the Dock icon is
                // clicked with no visible window — SwiftUI's openWindow lives here.
                .onReceive(NotificationCenter.default.publisher(for: .reopenMainWindow)) { _ in
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: "main")
                }
        }
        .windowStyle(.automatic)
        .commands {
            CommandGroup(replacing: .newItem) {} // no Cmd-N document semantics
        }

        MenuBarExtra(isInserted: $showMenuBarExtra) {
            MenuBarContent()
                .environmentObject(appState)
                .environmentObject(appState.scanner)
        } label: {
            // Rendered through NSImage so we get explicit pointSize + template
            // behavior — Image(systemName:) inside MenuBarExtra ignores .font and
            // ends up smaller than system items (Wi-Fi, Battery).
            Image(nsImage: Self.makeMenuBarIcon(symbol: menuBarSymbol))
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView()
                .environmentObject(appState)
                .environmentObject(appState.profiles)
        }
    }

    private var menuBarSymbol: String {
        if appState.scanner.state.isRunning { return "shield.lefthalf.filled" }
        return appState.scanner.threats.isEmpty ? "shield.fill" : "xmark.shield.fill"
    }

    private static func makeMenuBarIcon(symbol: String) -> NSImage {
        let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .regular)
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?
            .withSymbolConfiguration(config) ?? NSImage()
        image.isTemplate = true
        return image
    }
}

// MARK: - AppDelegate

/// Keeps the app alive after the main window closes (we still have the menu bar
/// status item), and re-opens the window when the user clicks the Dock icon.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            NotificationCenter.default.post(name: .reopenMainWindow, object: nil)
        }
        return true
    }
}

extension Notification.Name {
    static let reopenMainWindow = Notification.Name("ClamGUI.reopenMainWindow")
}

// MARK: - Menu bar dropdown

struct MenuBarContent: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var scanner: ScanEngine
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            switch scanner.state {
            case .running:
                Text("Scanning… \(scanner.filesScanned) files, \(scanner.threats.count) threats")
            case .finished(let code):
                Text(code == 0 ? "Last scan: clean" : "Last scan: \(scanner.threats.count) threat(s)")
            case .cancelled:
                Text("Last scan cancelled")
            case .failed:
                Text("Last scan failed")
            case .idle:
                Text(appState.toolchain != nil ? "Engine ready" : "ClamAV not found")
            }

            Divider()

            Button("Open ClamGUI") {
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "main")
            }

            if scanner.state.isRunning {
                Button("Stop Scan") { scanner.cancelScan() }
            }

            Button("Update Signatures") {
                appState.selectedTab = .updates
                NSApp.activate(ignoringOtherApps: true)
                openWindow(id: "main")
                if let tc = appState.toolchain {
                    appState.updater.runUpdate(toolchain: tc)
                }
            }
            .disabled(appState.toolchain == nil || appState.updater.isUpdating)

            Divider()

            Button("Quit ClamGUI") {
                NSApp.terminate(nil)
            }
        }
    }
}

// MARK: - App state

@MainActor
final class AppState: ObservableObject {
    let scanner = ScanEngine()
    let quarantine = QuarantineManager()
    let updater = FreshclamManager()
    let history = HistoryStore()
    let profiles = ProfileStore()

    @AppStorage("binaryPrefixOverride") var binaryPrefixOverride: String = ""
    @Published var toolchain: ClamAVLocator.Toolchain?
    @Published var clamdAvailable = false

    /// Bound to the sidebar selection in ContentView, lifted here so the menu
    /// bar (e.g., "Update Signatures") can route the user to a specific tab.
    @Published var selectedTab: SidebarItem? = .scan

    /// nil = "Custom" (options diverged from any saved profile)
    @Published var activeProfileID: UUID? {
        didSet {
            UserDefaults.standard.set(activeProfileID?.uuidString, forKey: "activeProfileID")
        }
    }

    var activeProfileName: String? {
        profiles.profile(id: activeProfileID)?.name
    }

    @Published var options: ScanOptions {
        didSet {
            persistOptions()
            // Editing options detaches from the named profile unless they still match.
            if let active = profiles.profile(id: activeProfileID), active.options != options {
                activeProfileID = nil
            }
        }
    }

    private var terminationObserver: NSObjectProtocol?

    init() {
        if let data = UserDefaults.standard.data(forKey: "scanOptions"),
           let decoded = try? JSONDecoder().decode(ScanOptions.self, from: data) {
            options = decoded
        } else {
            options = ScanOptions()
        }
        if let idString = UserDefaults.standard.string(forKey: "activeProfileID") {
            activeProfileID = UUID(uuidString: idString)
        }
        relocateToolchain()

        // History + notifications on every completed scan.
        scanner.onScanFinished = { [weak self] outcome in
            guard let self else { return }
            self.history.insert(outcome: outcome)
            guard !outcome.cancelled else { return }
            if outcome.exitCode == 1 {
                NotificationManager.notify(
                    title: "Threats detected",
                    body: "\(outcome.threats.count) threat(s) in \(outcome.filesScanned) files. Open ClamGUI to review.")
            } else if outcome.exitCode == 0 {
                NotificationManager.notify(
                    title: "Scan complete",
                    body: "No threats found in \(outcome.filesScanned) files.")
            } else {
                NotificationManager.notify(
                    title: "Scan error",
                    body: "Scanner exited with code \(outcome.exitCode). Check the log.")
            }
        }

        // Reap children at quit. willTerminate can fire on a non-main thread late
        // in teardown, so this goes through the lock-based registry, not actors.
        terminationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification,
            object: nil, queue: nil
        ) { _ in
            ChildProcessRegistry.shared.terminateAll()
        }
    }

    func apply(profile: ScanProfile) {
        activeProfileID = profile.id   // set first so options.didSet sees a matching profile
        options = profile.options
    }

    func startScan(targets: [URL]) {
        guard let tc = toolchain else { return }
        scanner.startScan(targets: targets, toolchain: tc,
                          options: options, profileName: activeProfileName)
    }

    func relocateToolchain() {
        toolchain = ClamAVLocator.locate(
            userOverridePrefix: binaryPrefixOverride.isEmpty ? nil : binaryPrefixOverride
        )
        Task {
            if let tc = toolchain {
                clamdAvailable = await ClamAVLocator.clamdIsReachable(clamdscanPath: tc.clamdscan)
                await updater.refreshVersion(toolchain: tc)
            } else {
                clamdAvailable = false
            }
        }
    }

    private func persistOptions() {
        if let data = try? JSONEncoder().encode(options) {
            UserDefaults.standard.set(data, forKey: "scanOptions")
        }
    }
}
