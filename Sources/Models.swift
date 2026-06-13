import Foundation

// MARK: - Scan results

enum ScanVerdict: String, Codable {
    case clean
    case infected
    case error
}

struct DetectedThreat: Identifiable, Hashable, Codable {
    let id: UUID
    let path: String
    let signature: String
    let detectedAt: Date

    init(path: String, signature: String, detectedAt: Date = .now) {
        self.id = UUID()
        self.path = path
        self.signature = signature
        self.detectedAt = detectedAt
    }
}

struct ScanSummary: Codable {
    var knownSignatures: Int?
    var scannedDirectories: Int?
    var scannedFiles: Int?
    var infectedFiles: Int?
    var dataScanned: String?
    var dataRead: String?
    var duration: String?
}

enum ScanState: Equatable {
    case idle
    case running(currentPath: String?)
    case finished(exitCode: Int32)
    case cancelled
    case failed(String)

    var isRunning: Bool {
        if case .running = self { return true }
        return false
    }
}

// MARK: - Scan options

struct ScanOptions: Codable, Equatable {
    var recursive: Bool = true
    var scanArchives: Bool = true
    var scanMail: Bool = true
    var scanPE: Bool = true
    var scanELF: Bool = true
    var scanOLE2: Bool = true
    var scanPDF: Bool = true
    var detectPUA: Bool = false
    var heuristicAlerts: Bool = true
    var alertEncrypted: Bool = false
    var crossFilesystems: Bool = true
    var followDirSymlinks: Bool = false
    var followFileSymlinks: Bool = false
    var maxFileSizeMB: Int = 100
    var maxScanSizeMB: Int = 400
    var maxRecursion: Int = 17
    var excludePatterns: [String] = []   // regex, passed via --exclude / --exclude-dir
    var useClamd: Bool = false           // clamdscan via local daemon (multiscan, fdpass)

    /// CLI arguments for clamscan. clamdscan ignores most of these (daemon-side config),
    /// so callers should branch on `useClamd`.
    func clamscanArguments() -> [String] {
        var args: [String] = [
            "--stdout",                 // summary prints by default; we parse it
        ]
        args.append(recursive ? "--recursive=yes" : "--recursive=no")
        args.append("--scan-archive=\(scanArchives ? "yes" : "no")")
        args.append("--scan-mail=\(scanMail ? "yes" : "no")")
        args.append("--scan-pe=\(scanPE ? "yes" : "no")")
        args.append("--scan-elf=\(scanELF ? "yes" : "no")")
        args.append("--scan-ole2=\(scanOLE2 ? "yes" : "no")")
        args.append("--scan-pdf=\(scanPDF ? "yes" : "no")")
        args.append("--heuristic-alerts=\(heuristicAlerts ? "yes" : "no")")
        args.append("--cross-fs=\(crossFilesystems ? "yes" : "no")")
        args.append("--follow-dir-symlinks=\(followDirSymlinks ? "1" : "0")")
        args.append("--follow-file-symlinks=\(followFileSymlinks ? "1" : "0")")
        if detectPUA { args.append("--detect-pua=yes") }
        if alertEncrypted { args.append("--alert-encrypted=yes") }
        args.append("--max-filesize=\(maxFileSizeMB)M")
        args.append("--max-scansize=\(maxScanSizeMB)M")
        args.append("--max-recursion=\(maxRecursion)")
        for pattern in excludePatterns where !pattern.isEmpty {
            args.append("--exclude=\(pattern)")
            args.append("--exclude-dir=\(pattern)")
        }
        return args
    }

    func clamdscanArguments() -> [String] {
        // fdpass avoids clamd needing read permission on the user's files;
        // multiscan parallelizes across the daemon's thread pool.
        ["--stdout", "--fdpass", "--multiscan"]
    }
}

// MARK: - Quarantine

struct QuarantineEntry: Identifiable, Codable, Hashable {
    let id: UUID
    let originalPath: String
    let storedFilename: String   // UUID-based name inside the quarantine dir
    let signature: String
    let quarantinedAt: Date
    let fileSize: Int64
    let sha256: String
}

// MARK: - Log

struct LogLine: Identifiable, Equatable {
    enum Kind { case info, hit, error, summary }
    let id = UUID()
    let kind: Kind
    let text: String
    let timestamp = Date()
}
