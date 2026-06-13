import Foundation
import Combine
import UserNotifications

// MARK: - Profiles

struct ScanProfile: Identifiable, Codable, Equatable {
    var id: UUID
    var name: String
    var options: ScanOptions

    init(id: UUID = UUID(), name: String, options: ScanOptions) {
        self.id = id
        self.name = name
        self.options = options
    }
}

/// Named ScanOptions sets, persisted as JSON (atomic writes) with import/export.
@MainActor
final class ProfileStore: ObservableObject {

    @Published private(set) var profiles: [ScanProfile] = []

    private let fm = FileManager.default
    private var fileURL: URL {
        fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClamGUI", isDirectory: true)
            .appendingPathComponent("profiles.json")
    }

    init() {
        load()
        if profiles.isEmpty {
            profiles = Self.builtInDefaults()
            save()
        }
    }

    static func builtInDefaults() -> [ScanProfile] {
        var quick = ScanOptions()
        quick.scanArchives = false
        quick.scanMail = false
        quick.maxFileSizeMB = 25
        quick.maxScanSizeMB = 100

        var deep = ScanOptions()
        deep.detectPUA = true
        deep.alertEncrypted = true
        deep.maxFileSizeMB = 1000
        deep.maxScanSizeMB = 2000
        deep.maxRecursion = 30

        return [
            ScanProfile(name: "Default", options: ScanOptions()),
            ScanProfile(name: "Quick", options: quick),
            ScanProfile(name: "Deep", options: deep),
        ]
    }

    func profile(id: UUID?) -> ScanProfile? {
        guard let id else { return nil }
        return profiles.first { $0.id == id }
    }

    func add(name: String, options: ScanOptions) -> ScanProfile {
        var uniqueName = name.trimmingCharacters(in: .whitespaces)
        if uniqueName.isEmpty { uniqueName = "Untitled" }
        // De-dupe names: "Quick" -> "Quick 2"
        var candidate = uniqueName
        var n = 2
        while profiles.contains(where: { $0.name == candidate }) {
            candidate = "\(uniqueName) \(n)"; n += 1
        }
        let profile = ScanProfile(name: candidate, options: options)
        profiles.append(profile)
        save()
        return profile
    }

    func update(_ profile: ScanProfile) {
        guard let idx = profiles.firstIndex(where: { $0.id == profile.id }) else { return }
        profiles[idx] = profile
        save()
    }

    func remove(_ profile: ScanProfile) {
        profiles.removeAll { $0.id == profile.id }
        save()
    }

    // MARK: Import / export

    func exportData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(profiles)
    }

    /// Imports profiles, regenerating IDs to avoid collisions; returns count imported.
    @discardableResult
    func importData(_ data: Data) throws -> Int {
        let imported = try JSONDecoder().decode([ScanProfile].self, from: data)
        for var profile in imported {
            profile.id = UUID()
            _ = add(name: profile.name, options: profile.options)
        }
        return imported.count
    }

    // MARK: Persistence

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        profiles = (try? JSONDecoder().decode([ScanProfile].self, from: data)) ?? []
    }

    private func save() {
        try? FileManager.default.createDirectory(
            at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(profiles) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}

// MARK: - Notifications

/// Thin wrapper over UNUserNotificationCenter. Authorization is requested
/// lazily on first notification; denial is silently respected thereafter.
enum NotificationManager {

    static var enabled: Bool {
        UserDefaults.standard.object(forKey: "notificationsEnabled") as? Bool ?? true
    }

    static func notify(title: String, body: String) {
        guard enabled else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                    if granted { post(title: title, body: body) }
                }
            case .authorized, .provisional:
                post(title: title, body: body)
            default:
                break // denied — respect it
            }
        }
    }

    private static func post(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
