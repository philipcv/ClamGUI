import Foundation
import Combine

/// Tracks every spawned child so they can be terminated synchronously at app exit.
/// NSApplication.willTerminate fires on an arbitrary point in teardown where
/// MainActor tasks are no longer guaranteed to run, so this is deliberately
/// lock-based and nonisolated.
final class ChildProcessRegistry: @unchecked Sendable {
    static let shared = ChildProcessRegistry()
    private let lock = NSLock()
    private var processes: [ObjectIdentifier: Process] = [:]

    func register(_ p: Process)   { lock.lock(); processes[ObjectIdentifier(p)] = p; lock.unlock() }
    func unregister(_ p: Process) { lock.lock(); processes[ObjectIdentifier(p)] = nil; lock.unlock() }

    func terminateAll() {
        lock.lock(); defer { lock.unlock() }
        for p in processes.values where p.isRunning { p.terminate() }
        processes.removeAll()
    }
}

/// Outcome handed to the host (AppState) when a scan finishes for history + notifications.
struct ScanOutcome {
    let startedAt: Date
    let duration: TimeInterval
    let targets: [String]
    let filesScanned: Int
    let threats: [DetectedThreat]
    let exitCode: Int32
    let cancelled: Bool
    let profileName: String?
}

/// Drives clamscan/clamdscan as a child process, streaming and parsing stdout line-by-line.
///
/// Exit codes (per clamscan(1)): 0 = clean, 1 = virus(es) found, 2 = error.
///
/// Reliability notes:
/// - The termination handler awaits both pipe readers reaching EOF before
///   finalizing, so the last detection lines are never dropped.
/// - UI-visible state (`log`, `filesScanned`, current path) is buffered and
///   flushed at ~8 Hz; per-line @Published mutations on a 100k-file tree would
///   otherwise saturate the main thread with SwiftUI invalidations.
@MainActor
final class ScanEngine: ObservableObject {

    @Published var state: ScanState = .idle
    @Published var log: [LogLine] = []
    @Published var threats: [DetectedThreat] = []
    @Published var summary = ScanSummary()
    @Published var filesScanned: Int = 0

    /// Set by AppState; called exactly once per scan that actually launched.
    var onScanFinished: ((ScanOutcome) -> Void)?

    private var process: Process?
    private var flushTask: Task<Void, Never>?
    private var wasCancelled = false
    private var startedAt = Date()
    private var targetPaths: [String] = []
    private var profileName: String?

    // Buffered pending UI state, flushed on a timer.
    private var pendingLines: [LogLine] = []
    private var pendingThreats: [DetectedThreat] = []
    private var internalFilesScanned = 0
    private var internalCurrentPath: String?

    // "path: Signature.Name FOUND" — path may itself contain ": ", so anchor on the suffix.
    private static let hitRegex = try! NSRegularExpression(pattern: #"^(.*): (\S+) FOUND$"#)

    func startScan(targets: [URL],
                   toolchain: ClamAVLocator.Toolchain,
                   options: ScanOptions,
                   profileName: String? = nil) {
        guard !state.isRunning else { return }

        // Reset
        log.removeAll(); threats.removeAll(); summary = ScanSummary()
        filesScanned = 0; internalFilesScanned = 0
        pendingLines.removeAll(); pendingThreats.removeAll()
        internalCurrentPath = nil; wasCancelled = false
        startedAt = Date()
        targetPaths = targets.map(\.path)
        self.profileName = profileName
        state = .running(currentPath: nil)

        let useDaemon = options.useClamd && toolchain.clamdscan != nil
        let executable = useDaemon ? toolchain.clamdscan! : toolchain.clamscan
        var args = useDaemon ? options.clamdscanArguments() : options.clamscanArguments()
        if !useDaemon { args.append("--verbose") } // emits per-file "Scanning <path>" for progress
        args.append(contentsOf: targetPaths)

        bufferLog(.info, "$ \(executable) \(args.joined(separator: " "))")

        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        p.qualityOfService = .utility
        let stdout = Pipe()
        let stderr = Pipe()
        p.standardOutput = stdout
        p.standardError = stderr
        process = p

        // Readers are captured locally so the termination handler can await
        // them without touching MainActor-isolated properties.
        // FileHandle is non-Sendable; each handle is transferred to exactly one
        // reader task and never touched from this context again, so the
        // UncheckedSendable transfer is safe.
        let outHandle = UncheckedSendable(stdout.fileHandleForReading)
        let errHandle = UncheckedSendable(stderr.fileHandleForReading)
        let outTask = Task.detached(priority: .utility) { [weak self] in
            await Self.consume(handle: outHandle.value) { line in
                await self?.ingest(line: line, isStderr: false)
            }
        }
        let errTask = Task.detached(priority: .utility) { [weak self] in
            await Self.consume(handle: errHandle.value) { line in
                await self?.ingest(line: line, isStderr: true)
            }
        }

        p.terminationHandler = { proc in
            let code = proc.terminationStatus
            let signalled = proc.terminationReason == .uncaughtSignal
            Task {
                // Drain to EOF before finalizing — guarantees no lost lines.
                _ = await outTask.value
                _ = await errTask.value
                await MainActor.run { [weak self] in
                    self?.finalize(exitCode: code, signalled: signalled)
                }
            }
        }

        do {
            try p.run()
        } catch {
            state = .failed("Failed to launch \(executable): \(error.localizedDescription)")
            process = nil
            return
        }
        ChildProcessRegistry.shared.register(p)

        // ~8 Hz UI flush while running.
        flushTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 120_000_000)
                self?.flushPending()
            }
        }
    }

    func cancelScan() {
        guard let p = process, p.isRunning else { return }
        wasCancelled = true
        p.terminate() // SIGTERM; clamscan exits promptly
    }

    // MARK: - Stream consumption

    // nonisolated: statics of a @MainActor class are MainActor-isolated by
    // default, which would pin the byte-stream loop to the main actor.
    private nonisolated static func consume(handle: FileHandle,
                                            onLine: @escaping (String) async -> Void) async {
        do {
            for try await line in handle.bytes.lines {
                await onLine(line)
            }
        } catch {
            // Pipe torn down on termination — expected.
        }
        try? handle.close()
    }

    private func ingest(line: String, isStderr: Bool) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }

        if isStderr {
            bufferLog(.error, trimmed)
            return
        }

        // Per-file progress (clamscan --verbose): "Scanning /path/to/file"
        if trimmed.hasPrefix("Scanning ") {
            internalFilesScanned += 1
            internalCurrentPath = String(trimmed.dropFirst("Scanning ".count))
            return // status-bar only; keeps the log signal-only on huge trees
        }

        // Detection line
        let range = NSRange(trimmed.startIndex..., in: trimmed)
        if let m = Self.hitRegex.firstMatch(in: trimmed, range: range),
           let pathRange = Range(m.range(at: 1), in: trimmed),
           let sigRange = Range(m.range(at: 2), in: trimmed) {
            pendingThreats.append(DetectedThreat(
                path: String(trimmed[pathRange]),
                signature: String(trimmed[sigRange])
            ))
            bufferLog(.hit, trimmed)
            return
        }

        if parseSummaryLine(trimmed) {
            bufferLog(.summary, trimmed)
            return
        }

        if trimmed.hasSuffix(": OK") {
            // clamdscan emits "path: OK" per file; surface it as live progress
            // without flooding the log.
            let path = String(trimmed.dropLast(": OK".count))
            if !path.isEmpty {
                internalFilesScanned += 1
                internalCurrentPath = path
            }
            return
        }
        bufferLog(.info, trimmed)
    }

    private func parseSummaryLine(_ line: String) -> Bool {
        func value(_ prefix: String) -> String? {
            line.hasPrefix(prefix) ? line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces) : nil
        }
        if let v = value("Known viruses:")       { summary.knownSignatures = Int(v); return true }
        if let v = value("Scanned directories:") { summary.scannedDirectories = Int(v); return true }
        if let v = value("Scanned files:")       { summary.scannedFiles = Int(v); return true }
        if let v = value("Infected files:")      { summary.infectedFiles = Int(v); return true }
        if let v = value("Data scanned:")        { summary.dataScanned = v; return true }
        if let v = value("Data read:")           { summary.dataRead = v; return true }
        if let v = value("Time:")                { summary.duration = v; return true }
        return line == "----------- SCAN SUMMARY -----------"
    }

    // MARK: - Buffered publishing

    private func bufferLog(_ kind: LogLine.Kind, _ text: String) {
        pendingLines.append(LogLine(kind: kind, text: text))
    }

    private func flushPending() {
        if !pendingLines.isEmpty {
            log.append(contentsOf: pendingLines)
            pendingLines.removeAll(keepingCapacity: true)
            if log.count > 5_000 { log.removeFirst(log.count - 5_000) } // bound memory
        }
        if !pendingThreats.isEmpty {
            threats.append(contentsOf: pendingThreats)
            pendingThreats.removeAll(keepingCapacity: true)
        }
        if filesScanned != internalFilesScanned { filesScanned = internalFilesScanned }
        if case .running = state {
            state = .running(currentPath: internalCurrentPath)
        }
    }

    // MARK: - Finalization

    private func finalize(exitCode: Int32, signalled: Bool) {
        // Idempotency: finalize is reached from the termination handler exactly
        // once per Process, but a `nil` process is the canonical "already finalized"
        // marker, so double-invocations (future refactors, replay, etc.) are no-ops.
        guard process != nil else { return }
        flushTask?.cancel()
        flushTask = nil
        if let p = process { ChildProcessRegistry.shared.unregister(p) }
        process = nil

        let cancelled = wasCancelled || signalled
        flushPending() // last partial batch

        if cancelled {
            bufferLog(.info, "Scan cancelled.")
            state = .cancelled
        } else {
            switch exitCode {
            case 0:  bufferLog(.info, "Scan complete — no threats found.")
            case 1:  bufferLog(.error, "Scan complete — \(threats.count) threat(s) detected.")
            default: bufferLog(.error, "Scanner exited with code \(exitCode) (engine error).")
            }
            state = .finished(exitCode: exitCode)
        }
        flushPending()

        let outcome = ScanOutcome(
            startedAt: startedAt,
            duration: Date().timeIntervalSince(startedAt),
            targets: targetPaths,
            filesScanned: summary.scannedFiles ?? internalFilesScanned,
            threats: threats,
            exitCode: exitCode,
            cancelled: cancelled,
            profileName: profileName
        )
        onScanFinished?(outcome)
    }
}
