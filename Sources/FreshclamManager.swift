import Foundation
import Combine

/// Runs freshclam and reports database state.
///
/// Note on Homebrew: freshclam requires $(brew --prefix)/etc/clamav/freshclam.conf
/// to exist with the `Example` line removed. We surface that error explicitly,
/// along with lock contention from a concurrently running scheduled update.
@MainActor
final class FreshclamManager: ObservableObject {

    @Published var isUpdating = false
    @Published var output: [LogLine] = []
    @Published var lastResult: String?
    @Published var engineVersionString: String?

    private var process: Process?

    func refreshVersion(toolchain: ClamAVLocator.Toolchain) async {
        engineVersionString = await ClamAVLocator.engineVersion(clamscanPath: toolchain.clamscan)
    }

    func runUpdate(toolchain: ClamAVLocator.Toolchain) {
        guard !isUpdating else { return }
        isUpdating = true
        output.removeAll()
        lastResult = nil

        let p = Process()
        p.executableURL = URL(fileURLWithPath: toolchain.freshclam)
        p.arguments = ["--stdout"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        process = p

        // Swift 6: extract everything non-Sendable synchronously in the
        // handler — `proc` must not cross into the MainActor task.
        p.terminationHandler = { [weak self] proc in
            ChildProcessRegistry.shared.unregister(proc)
            let status = proc.terminationStatus
            Task { @MainActor in
                guard let self else { return }
                self.isUpdating = false
                self.process = nil
                if status == 0 {
                    self.lastResult = "Signature databases are up to date."
                } else if self.output.contains(where: { $0.text.localizedCaseInsensitiveContains("locked") }) {
                    self.lastResult = "Another freshclam instance holds the database lock (likely a scheduled update). Try again shortly."
                } else if self.output.contains(where: { $0.text.contains("Example") }) {
                    self.lastResult = """
                    freshclam.conf is unconfigured. Edit the config and comment out the \
                    'Example' line (brew: $(brew --prefix)/etc/clamav/freshclam.conf).
                    """
                } else {
                    self.lastResult = "freshclam exited with code \(status). See log."
                }
                await self.refreshVersion(toolchain: toolchain)
            }
        }

        do {
            try p.run()
            ChildProcessRegistry.shared.register(p)
        } catch {
            isUpdating = false
            process = nil
            lastResult = "Failed to launch freshclam: \(error.localizedDescription)"
            return
        }

        // Safe transfer: handle is owned by exactly this one reader task.
        let reader = UncheckedSendable(pipe.fileHandleForReading)
        Task.detached(priority: .utility) { [weak self] in
            let handle = reader.value
            do {
                for try await line in handle.bytes.lines {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty else { continue }
                    let kind: LogLine.Kind = trimmed.localizedCaseInsensitiveContains("error") ? .error : .info
                    await MainActor.run {
                        self?.output.append(LogLine(kind: kind, text: trimmed))
                    }
                }
            } catch { /* pipe torn down on termination — expected */ }
            try? handle.close()
        }
    }

    func cancel() {
        process?.terminate()
    }
}
