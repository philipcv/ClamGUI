import Foundation
import SQLite3
import Combine

struct ScanRecord: Identifiable, Hashable {
    let id: UUID
    let startedAt: Date
    let duration: TimeInterval
    let targets: [String]
    let filesScanned: Int
    let threatsFound: Int
    let exitCode: Int32
    let cancelled: Bool
    let profile: String?
}

struct HistoryStats {
    var totalScans = 0
    var totalThreats = 0
    var totalFilesScanned = 0
    var lastScan: Date?
}

/// Scan history persisted to SQLite (WAL). libsqlite3 ships with macOS, so no
/// dependency is introduced. If the database can't be opened (corrupt file,
/// weird sandbox state), the store degrades to in-memory so the app keeps
/// working and surfaces `persistenceFailed` in the UI instead of crashing.
@MainActor
final class HistoryStore: ObservableObject {

    @Published private(set) var records: [ScanRecord] = []
    @Published private(set) var stats = HistoryStats()
    @Published private(set) var persistenceFailed = false

    private var db: OpaquePointer?
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    private let maxRecords = 1_000

    init() {
        open()
        reload()
    }

    // MARK: - Public API

    func insert(outcome: ScanOutcome) {
        let record = ScanRecord(
            id: UUID(),
            startedAt: outcome.startedAt,
            duration: outcome.duration,
            targets: outcome.targets,
            filesScanned: outcome.filesScanned,
            threatsFound: outcome.threats.count,
            exitCode: outcome.exitCode,
            cancelled: outcome.cancelled,
            profile: outcome.profileName
        )

        if let db {
            exec("BEGIN")
            var stmt: OpaquePointer?
            let sql = """
            INSERT INTO scans (id, started_at, duration_s, targets, files_scanned,
                               threats_found, exit_code, cancelled, profile)
            VALUES (?,?,?,?,?,?,?,?,?)
            """
            if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
                sqlite3_bind_text(stmt, 1, record.id.uuidString, -1, Self.transient)
                sqlite3_bind_double(stmt, 2, record.startedAt.timeIntervalSince1970)
                sqlite3_bind_double(stmt, 3, record.duration)
                sqlite3_bind_text(stmt, 4, record.targets.joined(separator: "\n"), -1, Self.transient)
                sqlite3_bind_int(stmt, 5, Int32(record.filesScanned))
                sqlite3_bind_int(stmt, 6, Int32(record.threatsFound))
                sqlite3_bind_int(stmt, 7, record.exitCode)
                sqlite3_bind_int(stmt, 8, record.cancelled ? 1 : 0)
                if let profile = record.profile {
                    sqlite3_bind_text(stmt, 9, profile, -1, Self.transient)
                } else {
                    sqlite3_bind_null(stmt, 9)
                }
                sqlite3_step(stmt)
            }
            sqlite3_finalize(stmt)

            for threat in outcome.threats {
                var tStmt: OpaquePointer?
                let tSQL = "INSERT INTO threats (id, scan_id, path, signature, detected_at) VALUES (?,?,?,?,?)"
                if sqlite3_prepare_v2(db, tSQL, -1, &tStmt, nil) == SQLITE_OK {
                    sqlite3_bind_text(tStmt, 1, threat.id.uuidString, -1, Self.transient)
                    sqlite3_bind_text(tStmt, 2, record.id.uuidString, -1, Self.transient)
                    sqlite3_bind_text(tStmt, 3, threat.path, -1, Self.transient)
                    sqlite3_bind_text(tStmt, 4, threat.signature, -1, Self.transient)
                    sqlite3_bind_double(tStmt, 5, threat.detectedAt.timeIntervalSince1970)
                    sqlite3_step(tStmt)
                }
                sqlite3_finalize(tStmt)
            }
            exec("COMMIT")
            // Retention: trim oldest beyond maxRecords (threats cascade).
            exec("""
            DELETE FROM scans WHERE id IN (
                SELECT id FROM scans ORDER BY started_at DESC LIMIT -1 OFFSET \(maxRecords)
            )
            """)
            reload()
        } else {
            records.insert(record, at: 0)
            recomputeStatsInMemory()
        }
    }

    func threats(for recordID: UUID) -> [DetectedThreat] {
        guard let db else { return [] }
        var out: [DetectedThreat] = []
        var stmt: OpaquePointer?
        let sql = "SELECT path, signature, detected_at FROM threats WHERE scan_id = ? ORDER BY detected_at"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, recordID.uuidString, -1, Self.transient)
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let pathC = sqlite3_column_text(stmt, 0),
                  let sigC = sqlite3_column_text(stmt, 1) else { continue }
            out.append(DetectedThreat(
                path: String(cString: pathC),
                signature: String(cString: sigC),
                detectedAt: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
            ))
        }
        return out
    }

    func delete(_ record: ScanRecord) {
        if let db {
            var stmt: OpaquePointer?
            if sqlite3_prepare_v2(db, "DELETE FROM scans WHERE id = ?", -1, &stmt, nil) == SQLITE_OK {
                sqlite3_bind_text(stmt, 1, record.id.uuidString, -1, Self.transient)
                sqlite3_step(stmt)
            }
            sqlite3_finalize(stmt)
            reload()
        } else {
            records.removeAll { $0.id == record.id }
            recomputeStatsInMemory()
        }
    }

    func clearAll() {
        if db != nil {
            exec("DELETE FROM threats")
            exec("DELETE FROM scans")
            reload()
        } else {
            records.removeAll()
            recomputeStatsInMemory()
        }
    }

    // MARK: - SQLite plumbing

    private func open() {
        let fm = FileManager.default
        let dir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ClamGUI", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("history.sqlite").path

        var handle: OpaquePointer?
        guard sqlite3_open_v2(path, &handle,
                              SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                              nil) == SQLITE_OK, let handle else {
            persistenceFailed = true
            if let h = handle { sqlite3_close_v2(h) }
            return
        }
        db = handle
        exec("PRAGMA journal_mode = WAL")
        exec("PRAGMA foreign_keys = ON")
        exec("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            started_at REAL NOT NULL,
            duration_s REAL NOT NULL,
            targets TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            threats_found INTEGER NOT NULL,
            exit_code INTEGER NOT NULL,
            cancelled INTEGER NOT NULL DEFAULT 0,
            profile TEXT
        )
        """)
        exec("""
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            path TEXT NOT NULL,
            signature TEXT NOT NULL,
            detected_at REAL NOT NULL
        )
        """)
        exec("CREATE INDEX IF NOT EXISTS idx_threats_scan ON threats(scan_id)")
        exec("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)")
    }

    private func exec(_ sql: String) {
        guard let db else { return }
        if sqlite3_exec(db, sql, nil, nil, nil) != SQLITE_OK {
            // Non-fatal: log to console; the app keeps running.
            let message = String(cString: sqlite3_errmsg(db))
            NSLog("ClamGUI history SQL error: %@ (%@)", message, sql)
        }
    }

    private func reload() {
        guard let db else { return }
        var out: [ScanRecord] = []
        var stmt: OpaquePointer?
        let sql = """
        SELECT id, started_at, duration_s, targets, files_scanned, threats_found,
               exit_code, cancelled, profile
        FROM scans ORDER BY started_at DESC LIMIT \(maxRecords)
        """
        if sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK {
            while sqlite3_step(stmt) == SQLITE_ROW {
                guard let idC = sqlite3_column_text(stmt, 0),
                      let uuid = UUID(uuidString: String(cString: idC)),
                      let targetsC = sqlite3_column_text(stmt, 3) else { continue }
                let profileC = sqlite3_column_text(stmt, 8)
                out.append(ScanRecord(
                    id: uuid,
                    startedAt: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
                    duration: sqlite3_column_double(stmt, 2),
                    targets: String(cString: targetsC).split(separator: "\n").map(String.init),
                    filesScanned: Int(sqlite3_column_int(stmt, 4)),
                    threatsFound: Int(sqlite3_column_int(stmt, 5)),
                    exitCode: sqlite3_column_int(stmt, 6),
                    cancelled: sqlite3_column_int(stmt, 7) == 1,
                    profile: profileC.map { String(cString: $0) }
                ))
            }
        }
        sqlite3_finalize(stmt)
        records = out

        var s = HistoryStats()
        var aggStmt: OpaquePointer?
        let aggSQL = """
        SELECT COUNT(*), COALESCE(SUM(threats_found), 0),
               COALESCE(SUM(files_scanned), 0), MAX(started_at)
        FROM scans
        """
        if sqlite3_prepare_v2(db, aggSQL, -1, &aggStmt, nil) == SQLITE_OK,
           sqlite3_step(aggStmt) == SQLITE_ROW {
            s.totalScans = Int(sqlite3_column_int(aggStmt, 0))
            s.totalThreats = Int(sqlite3_column_int(aggStmt, 1))
            s.totalFilesScanned = Int(sqlite3_column_int(aggStmt, 2))
            if sqlite3_column_type(aggStmt, 3) != SQLITE_NULL {
                s.lastScan = Date(timeIntervalSince1970: sqlite3_column_double(aggStmt, 3))
            }
        }
        sqlite3_finalize(aggStmt)
        stats = s
    }

    private func recomputeStatsInMemory() {
        stats = HistoryStats(
            totalScans: records.count,
            totalThreats: records.reduce(0) { $0 + $1.threatsFound },
            totalFilesScanned: records.reduce(0) { $0 + $1.filesScanned },
            lastScan: records.first?.startedAt
        )
    }
}
