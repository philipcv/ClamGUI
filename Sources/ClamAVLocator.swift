import Foundation

/// Locates ClamAV binaries across common install prefixes.
/// Precedence: user-configured path > Homebrew (ARM) > Homebrew (Intel) > MacPorts > /usr/local.
struct ClamAVLocator {

    static let searchPrefixes = [
        "/opt/homebrew/bin",   // Homebrew, Apple Silicon
        "/usr/local/bin",      // Homebrew Intel / manual builds
        "/opt/local/bin",      // MacPorts
    ]

    struct Toolchain: Equatable {
        var clamscan: String
        var clamdscan: String?
        var freshclam: String
        var sigtool: String?
        var version: String?
    }

    static func locate(userOverridePrefix: String? = nil) -> Toolchain? {
        var prefixes = searchPrefixes
        if let override = userOverridePrefix, !override.isEmpty {
            prefixes.insert(override, at: 0)
        }
        let fm = FileManager.default
        for prefix in prefixes {
            let clamscan = "\(prefix)/clamscan"
            let freshclam = "\(prefix)/freshclam"
            guard fm.isExecutableFile(atPath: clamscan),
                  fm.isExecutableFile(atPath: freshclam) else { continue }

            let clamdscan = "\(prefix)/clamdscan"
            let sigtool = "\(prefix)/sigtool"
            return Toolchain(
                clamscan: clamscan,
                clamdscan: fm.isExecutableFile(atPath: clamdscan) ? clamdscan : nil,
                freshclam: freshclam,
                sigtool: fm.isExecutableFile(atPath: sigtool) ? sigtool : nil,
                version: nil
            )
        }
        return nil
    }

    /// Returns e.g. "ClamAV 1.4.1/27556/Wed Jun 10 09:21:13 2026"
    /// (engine version / daily.cvd version / daily.cvd build time)
    static func engineVersion(clamscanPath: String) async -> String? {
        await ProcessRunner.capture(executable: clamscanPath, arguments: ["--version"])?
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// True if clamd appears to be running (local socket or TCP per default brew config).
    static func clamdIsReachable(clamdscanPath: String?) async -> Bool {
        guard let clamdscanPath else { return false }
        // `clamdscan --ping 1` exits 0 if the daemon answers within 1s (ClamAV >= 0.105)
        let status = await ProcessRunner.exitCode(executable: clamdscanPath, arguments: ["--ping", "1"])
        return status == 0
    }
}

/// Minimal async one-shot process helpers (for short, non-streaming invocations).
enum ProcessRunner {
    static func capture(executable: String, arguments: [String]) async -> String? {
        await withCheckedContinuation { continuation in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: executable)
            p.arguments = arguments
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            // Safe transfer: the handle is read exactly once, after child exit.
            let reader = UncheckedSendable(pipe.fileHandleForReading)
            p.terminationHandler = { _ in
                let data = reader.value.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8))
            }
            do { try p.run() } catch { continuation.resume(returning: nil) }
        }
    }

    static func exitCode(executable: String, arguments: [String]) async -> Int32 {
        await withCheckedContinuation { continuation in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: executable)
            p.arguments = arguments
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            p.terminationHandler = { proc in
                continuation.resume(returning: proc.terminationStatus)
            }
            do { try p.run() } catch { continuation.resume(returning: -1) }
        }
    }
}
