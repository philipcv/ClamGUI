import SwiftUI
import AppKit
import UniformTypeIdentifiers

// MARK: - Signature updates

struct UpdateView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var updater: FreshclamManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Engine") {
                HStack {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.title2)
                        .foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(updater.engineVersionString ?? "Version unknown")
                            .font(.callout.monospaced())
                        Text("Format: engine / daily.cvd version / daily.cvd build date")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(6)
            }

            GroupBox("Signature Update") {
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        if updater.isUpdating {
                            ProgressView().controlSize(.small)
                            Button("Cancel") { updater.cancel() }
                        } else {
                            Button {
                                guard let tc = appState.toolchain else { return }
                                updater.runUpdate(toolchain: tc)
                            } label: {
                                Label("Run freshclam", systemImage: "arrow.triangle.2.circlepath")
                            }
                        }
                        if let result = updater.lastResult {
                            Text(result).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }

                    if !updater.output.isEmpty {
                        ScrollViewReader { proxy in
                            ScrollView {
                                LazyVStack(alignment: .leading, spacing: 2) {
                                    ForEach(updater.output) { line in
                                        Text(line.text)
                                            .font(.caption.monospaced())
                                            .foregroundStyle(line.kind == .error ? .orange : .secondary)
                                            .textSelection(.enabled)
                                            .id(line.id)
                                    }
                                }
                                .padding(6)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .frame(height: 240)
                            .background(Color(nsColor: .textBackgroundColor))
                            .onChange(of: updater.output.count) {
                                if let last = updater.output.last {
                                    proxy.scrollTo(last.id, anchor: .bottom)
                                }
                            }
                        }
                    }
                }
                .padding(6)
            }

            Text("""
            Tip: for hands-off updates run `brew services start clamav` (launches clamd) and \
            schedule freshclam via launchd; this button is for on-demand refreshes.
            """)
            .font(.caption)
            .foregroundStyle(.tertiary)

            Spacer()
        }
        .padding(20)
        .navigationTitle("Signatures")
        .task {
            if let tc = appState.toolchain {
                await updater.refreshVersion(toolchain: tc)
            }
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var profiles: ProfileStore
    @State private var excludeText = ""

    var body: some View {
        TabView {
            scanTab
                .tabItem { Label("Scanning", systemImage: "magnifyingglass") }
            limitsTab
                .tabItem { Label("Limits", systemImage: "gauge.medium") }
            ProfilesSettingsTab()
                .tabItem { Label("Profiles", systemImage: "slider.horizontal.3") }
            engineTab
                .tabItem { Label("Engine", systemImage: "cpu") }
            generalTab
                .tabItem { Label("General", systemImage: "gearshape") }
        }
        .frame(width: 520, height: 440)
        .onAppear { excludeText = appState.options.excludePatterns.joined(separator: "\n") }
    }

    // MARK: General

    @AppStorage("notificationsEnabled") private var notificationsEnabled = true
    @AppStorage("showMenuBarExtra") private var showMenuBarExtra = true

    private var generalTab: some View {
        Form {
            Toggle("Show menu bar icon", isOn: $showMenuBarExtra)
            Toggle("Notify on scan completion and threats", isOn: $notificationsEnabled)
            Text("Notifications also require permission in System Settings → Notifications.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .formStyle(.grouped)
        .padding()
    }

    private var scanTab: some View {
        Form {
            Toggle("Recursive directory scan", isOn: $appState.options.recursive)
            Toggle("Scan archives (zip, rar, 7z, …)", isOn: $appState.options.scanArchives)
            Toggle("Scan mail files", isOn: $appState.options.scanMail)
            Toggle("Scan OLE2 (Office docs/macros)", isOn: $appState.options.scanOLE2)
            Toggle("Scan PDF", isOn: $appState.options.scanPDF)
            Toggle("Heuristic alerts", isOn: $appState.options.heuristicAlerts)
            Toggle("Detect PUA (potentially unwanted applications)", isOn: $appState.options.detectPUA)
            Toggle("Alert on encrypted archives/docs", isOn: $appState.options.alertEncrypted)
            Section("Exclude patterns (regex, one per line)") {
                TextEditor(text: $excludeText)
                    .font(.callout.monospaced())
                    .frame(height: 70)
                    .onChange(of: excludeText) {
                        appState.options.excludePatterns = excludeText
                            .split(separator: "\n")
                            .map { String($0).trimmingCharacters(in: .whitespaces) }
                            .filter { !$0.isEmpty }
                    }
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private var limitsTab: some View {
        Form {
            Stepper("Max file size: \(appState.options.maxFileSizeMB) MB",
                    value: $appState.options.maxFileSizeMB, in: 1...4000, step: 25)
            Stepper("Max scan size: \(appState.options.maxScanSizeMB) MB",
                    value: $appState.options.maxScanSizeMB, in: 1...4000, step: 50)
            Stepper("Max archive recursion: \(appState.options.maxRecursion)",
                    value: $appState.options.maxRecursion, in: 1...50)
            Toggle("Cross filesystem boundaries", isOn: $appState.options.crossFilesystems)
            Toggle("Follow directory symlinks", isOn: $appState.options.followDirSymlinks)
            Toggle("Follow file symlinks", isOn: $appState.options.followFileSymlinks)
        }
        .formStyle(.grouped)
        .padding()
    }

    private var engineTab: some View {
        Form {
            Section {
                Toggle("Use clamd (clamdscan --fdpass --multiscan)", isOn: $appState.options.useClamd)
                    .disabled(!appState.clamdAvailable)
                if !appState.clamdAvailable {
                    Text("clamd not reachable. Start it with `brew services start clamav` " +
                         "(requires clamd.conf configured).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text("clamd keeps signatures resident in memory — dramatically faster for repeated scans. " +
                     "Scan limit options are governed by clamd.conf, not this app, when enabled.")
                    .font(.caption)
            }
            Section("Binary location") {
                TextField("Custom prefix (e.g. /usr/local/clamav/bin)",
                          text: $appState.binaryPrefixOverride)
                    .font(.callout.monospaced())
                Button("Re-detect Toolchain") { appState.relocateToolchain() }
                if let tc = appState.toolchain {
                    LabeledContent("clamscan", value: tc.clamscan)
                        .font(.caption.monospaced())
                    LabeledContent("clamdscan", value: tc.clamdscan ?? "not found")
                        .font(.caption.monospaced())
                    LabeledContent("freshclam", value: tc.freshclam)
                        .font(.caption.monospaced())
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}


// MARK: - Profile management

struct ProfilesSettingsTab: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var profiles: ProfileStore
    @State private var newProfileName = ""
    @State private var importExportMessage: String?

    var body: some View {
        Form {
            Section("Saved profiles") {
                if profiles.profiles.isEmpty {
                    Text("No profiles yet.").foregroundStyle(.secondary)
                }
                ForEach(profiles.profiles) { profile in
                    HStack {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(profile.name)
                            Text(summary(for: profile.options))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if appState.activeProfileID == profile.id {
                            Text("Active").font(.caption).foregroundStyle(.tint)
                        }
                        Button("Apply") { appState.apply(profile: profile) }
                            .controlSize(.small)
                        Button(role: .destructive) {
                            if appState.activeProfileID == profile.id {
                                appState.activeProfileID = nil
                            }
                            profiles.remove(profile)
                        } label: { Image(systemName: "trash") }
                        .controlSize(.small)
                    }
                }
            }

            Section("Save current options as profile") {
                HStack {
                    TextField("Profile name", text: $newProfileName)
                    Button("Save") {
                        let profile = profiles.add(name: newProfileName, options: appState.options)
                        appState.activeProfileID = profile.id
                        newProfileName = ""
                    }
                    .disabled(newProfileName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }

            Section {
                HStack {
                    Button("Export All…") { exportProfiles() }
                    Button("Import…") { importProfiles() }
                    if let message = importExportMessage {
                        Text(message).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func summary(for options: ScanOptions) -> String {
        var parts: [String] = []
        parts.append(options.recursive ? "recursive" : "non-recursive")
        if options.scanArchives { parts.append("archives") }
        if options.detectPUA { parts.append("PUA") }
        if options.useClamd { parts.append("clamd") }
        parts.append("≤\(options.maxFileSizeMB)MB/file")
        return parts.joined(separator: " · ")
    }

    private func exportProfiles() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "clamgui-profiles.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try profiles.exportData().write(to: url, options: .atomic)
            importExportMessage = "Exported \(profiles.profiles.count) profile(s)."
        } catch {
            importExportMessage = "Export failed: \(error.localizedDescription)"
        }
    }

    private func importProfiles() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let count = try profiles.importData(Data(contentsOf: url))
            importExportMessage = "Imported \(count) profile(s)."
        } catch {
            importExportMessage = "Import failed: not a valid profiles JSON file."
        }
    }
}
