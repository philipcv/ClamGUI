import Foundation
import CryptoKit
import Combine

enum QuarantineError: LocalizedError {
    case restoreCollision(String)
    case vaultBlobMissing(String)

    var errorDescription: String? {
        switch self {
        case .restoreCollision(let path):
            return "A file already exists at \(path). Move it aside before restoring."
        case .vaultBlobMissing(let name):
            return "Quarantined blob \(name) is missing from the vault. Index entry removed."
        }
    }
}

/// Quarantine = move into an app-private 0700 vault, stored 0400, with metadata
/// (original path, signature, size, SHA-256, timestamp) in a JSON index.
///
/// Layout: ~/Library/Application Support/ClamGUI/Quarantine/<uuid>.bin
///         ~/Library/Application Support/ClamGUI/quarantine-index.json
@MainActor
final class QuarantineManager: ObservableObject {

    @Published private(set) var entries: [QuarantineEntry] = []

    private let fm = FileManager.default

    private var baseDir: URL {
        let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return appSupport.appendingPathComponent("ClamGUI", isDirectory: true)
    }
    private var quarantineDir: URL { baseDir.appendingPathComponent("Quarantine", isDirectory: true) }
    private var indexURL: URL { baseDir.appendingPathComponent("quarantine-index.json") }

    init() {
        try? fm.createDirectory(at: quarantineDir, withIntermediateDirectories: true,
                                attributes: [.posixPermissions: 0o700])
        loadIndex()
        reconcile()
    }

    // MARK: - Operations

    @discardableResult
    func quarantine(threat: DetectedThreat) throws -> QuarantineEntry {
        let sourceURL = URL(fileURLWithPath: threat.path)
        // Streamed hash — never load multi-GB samples into memory.
        let digest = try Self.sha256OfFile(at: sourceURL)
        let size = (try? fm.attributesOfItem(atPath: threat.path)[.size] as? NSNumber)
            .flatMap { $0 }?.int64Value ?? 0

        let stored = UUID().uuidString + ".bin"
        let destURL = quarantineDir.appendingPathComponent(stored)

        // Atomic on same volume; copy+verify+unlink across volumes.
        do {
            try fm.moveItem(at: sourceURL, to: destURL)
        } catch {
            try fm.copyItem(at: sourceURL, to: destURL)
            // Verify the copy before destroying the only original.
            guard try Self.sha256OfFile(at: destURL) == digest else {
                try? fm.removeItem(at: destURL)
                throw CocoaError(.fileWriteUnknown, userInfo: [
                    NSLocalizedDescriptionKey: "Copy verification failed for \(threat.path); original left in place."
                ])
            }
            try fm.removeItem(at: sourceURL)
        }
        try? fm.setAttributes([.posixPermissions: 0o400], ofItemAtPath: destURL.path)

        let entry = QuarantineEntry(
            id: UUID(),
            originalPath: threat.path,
            storedFilename: stored,
            signature: threat.signature,
            quarantinedAt: .now,
            fileSize: size,
            sha256: digest
        )
        entries.append(entry)
        saveIndex()
        return entry
    }

    func restore(_ entry: QuarantineEntry) throws {
        let src = quarantineDir.appendingPathComponent(entry.storedFilename)
        guard fm.fileExists(atPath: src.path) else {
            entries.removeAll { $0.id == entry.id }
            saveIndex()
            throw QuarantineError.vaultBlobMissing(entry.storedFilename)
        }
        let dest = URL(fileURLWithPath: entry.originalPath)
        guard !fm.fileExists(atPath: dest.path) else {
            throw QuarantineError.restoreCollision(entry.originalPath)
        }
        try fm.createDirectory(at: dest.deletingLastPathComponent(),
                               withIntermediateDirectories: true)
        try fm.moveItem(at: src, to: dest)
        try? fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: dest.path)
        entries.removeAll { $0.id == entry.id }
        saveIndex()
    }

    func delete(_ entry: QuarantineEntry) throws {
        let src = quarantineDir.appendingPathComponent(entry.storedFilename)
        if fm.fileExists(atPath: src.path) {
            try fm.removeItem(at: src)
        }
        entries.removeAll { $0.id == entry.id }
        saveIndex()
    }

    func deleteAll() {
        for entry in entries { try? delete(entry) }
    }

    // MARK: - Integrity

    /// Drops index entries whose blob vanished (e.g. user nuked the vault dir manually),
    /// so the UI never shows phantom rows that fail on every action.
    private func reconcile() {
        let before = entries.count
        entries.removeAll {
            !fm.fileExists(atPath: quarantineDir.appendingPathComponent($0.storedFilename).path)
        }
        if entries.count != before { saveIndex() }
    }

    static func sha256OfFile(at url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try autoreleasepool {
                try handle.read(upToCount: 1 << 20) ?? Data()
            }
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Persistence

    private func loadIndex() {
        guard let data = try? Data(contentsOf: indexURL) else { return }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        entries = (try? decoder.decode([QuarantineEntry].self, from: data)) ?? []
    }

    private func saveIndex() {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(entries) else { return }
        try? data.write(to: indexURL, options: .atomic)
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: indexURL.path)
    }
}
