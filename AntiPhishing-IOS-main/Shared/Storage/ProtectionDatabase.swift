//
//  ProtectionDatabase.swift
//  AntiPhishing (Shared)
//
//  SQLite-backed malicious-domain database. Chosen over an in-memory Set or a
//  Bloom filter because the feed data is 600k+ variable-length domains:
//
//    • lookups are exact B-tree probes (no false positives to re-confirm),
//    • nothing is loaded into memory at startup — the extension process only
//      touches the few pages a lookup needs,
//    • the file lives in the App Group container so the app (writer, during
//      updates) and the Safari extension (reader) share one copy,
//    • per-domain source/type metadata feeds the warning page.
//
//  Schema (see ProtectionDatabaseWriter.create):
//    domains(domain TEXT PRIMARY KEY, source TEXT, type TEXT) WITHOUT ROWID
//
//  Uses the raw SQLite3 C API bundled with iOS — no third-party dependency.
//

import Foundation
import SQLite3

// SQLite's "copy the bound string" sentinel; immutable C constant, safe to
// share across isolation domains.
private nonisolated(unsafe) let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// A confirmed hit in the malicious-domain database.
nonisolated struct DomainMatch: Equatable {
    /// The database entry that matched (may be a parent of the visited host).
    let matchedDomain: String
    /// Feed the entry came from (e.g. "Phishing_Army") — shown as the reason.
    let source: String
    /// Threat category from the feed definition ("blacklist"/"threat_intel").
    let threatType: String
}

// MARK: - Read side (app + extension)

/// Read-only handle on the active protection database.
/// Create per use-site; open() is cheap (no data is loaded eagerly).
nonisolated final class ProtectionDatabase {

    private var db: OpaquePointer?
    private var lookupStatement: OpaquePointer?

    let url: URL

    init(url: URL) {
        self.url = url
    }

    deinit { close() }

    /// Opens read-only. Fails (returns false) when the file is missing or not
    /// a valid database — callers surface that as "database unavailable".
    func open() -> Bool {
        guard db == nil else { return true }
        guard FileManager.default.fileExists(atPath: url.path) else { return false }
        // FULLMUTEX: serialized access, safe if the host process calls from
        // multiple queues.
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        guard sqlite3_open_v2(url.path, &db, flags, nil) == SQLITE_OK else {
            close()
            return false
        }
        sqlite3_busy_timeout(db, 2000)
        guard sqlite3_prepare_v2(db, "SELECT domain, source, type FROM domains WHERE domain = ?1 LIMIT 1", -1, &lookupStatement, nil) == SQLITE_OK else {
            close()
            return false
        }
        return true
    }

    func close() {
        if let stmt = lookupStatement { sqlite3_finalize(stmt); lookupStatement = nil }
        if let handle = db { sqlite3_close(handle); db = nil }
    }

    /// Checks a normalized host against the database, walking parent domains
    /// (a.b.evil.com → b.evil.com → evil.com) so entries for abused parent
    /// domains also match. Host MUST already be DomainNormalizer-normalized.
    func match(normalizedHost: String) -> DomainMatch? {
        guard open() else { return nil }
        for candidate in DomainNormalizer.lookupCandidates(for: normalizedHost) {
            if let hit = lookupExact(candidate) { return hit }
        }
        return nil
    }

    /// Exact single-domain probe (no parent walk).
    func lookupExact(_ domain: String) -> DomainMatch? {
        guard open(), let stmt = lookupStatement else { return nil }
        defer { sqlite3_reset(stmt); sqlite3_clear_bindings(stmt) }
        sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let matched = String(cString: sqlite3_column_text(stmt, 0))
        let source = sqlite3_column_text(stmt, 1).map { String(cString: $0) } ?? "threat feed"
        let type = sqlite3_column_text(stmt, 2).map { String(cString: $0) } ?? "malicious"
        return DomainMatch(matchedDomain: matched, source: source, threatType: type)
    }

    /// Total number of domains, or nil when the DB can't be read.
    func domainCount() -> Int? {
        guard open() else { return nil }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM domains", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Cheap structural sanity check used before activating a staged database.
    func passesIntegrityCheck() -> Bool {
        guard open() else { return false }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW,
              let result = sqlite3_column_text(stmt, 0) else { return false }
        return String(cString: result) == "ok"
    }
}

// MARK: - Write side (app only, during updates)

/// Builds a brand-new database file in the staging area. The active database
/// is replaced only after the staged file is complete and validated
/// (see ProtectionUpdater.activate).
nonisolated final class ProtectionDatabaseWriter {

    enum WriterError: Error {
        case cannotCreate(String)
        case insertFailed(String)
    }

    private var db: OpaquePointer?
    private var insertStatement: OpaquePointer?
    private var pendingInTransaction = 0
    private(set) var insertedCount = 0

    let url: URL

    /// Creates (or truncates) the staging database with the final schema.
    init(url: URL) throws {
        self.url = url
        try? FileManager.default.removeItem(at: url)
        var handle: OpaquePointer?
        guard sqlite3_open_v2(url.path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK else {
            throw WriterError.cannotCreate("sqlite3_open_v2 failed for \(url.lastPathComponent)")
        }
        db = handle

        // Journal not needed while building a throwaway staging file; keeps
        // the build fast and avoids leaving -wal/-shm files behind.
        exec("PRAGMA journal_mode = OFF")
        exec("PRAGMA synchronous = OFF")
        exec("""
            CREATE TABLE domains(
                domain TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                type   TEXT NOT NULL
            ) WITHOUT ROWID
            """)

        guard sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO domains(domain, source, type) VALUES(?1, ?2, ?3)", -1, &insertStatement, nil) == SQLITE_OK else {
            throw WriterError.cannotCreate("failed to prepare insert statement")
        }
        exec("BEGIN")
    }

    deinit {
        if let stmt = insertStatement { sqlite3_finalize(stmt) }
        if let handle = db { sqlite3_close(handle) }
    }

    /// Inserts one normalized domain. Duplicates across feeds are ignored
    /// (first feed wins). Batched into transactions of 20k rows.
    func insert(domain: String, source: String, type: String) throws {
        guard let stmt = insertStatement else {
            throw WriterError.insertFailed("writer already finished")
        }
        sqlite3_bind_text(stmt, 1, domain, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, source, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, type, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
        guard rc == SQLITE_DONE else {
            throw WriterError.insertFailed("sqlite step returned \(rc)")
        }
        if sqlite3_changes(db) > 0 { insertedCount += 1 }

        pendingInTransaction += 1
        if pendingInTransaction >= 20_000 {
            exec("COMMIT")
            exec("BEGIN")
            pendingInTransaction = 0
        }
    }

    /// Commits and closes. After this the file is a complete database ready
    /// for validation.
    func finish() {
        exec("COMMIT")
        if let stmt = insertStatement { sqlite3_finalize(stmt); insertStatement = nil }
        if let handle = db { sqlite3_close(handle); db = nil }
    }

    private func exec(_ sql: String) {
        sqlite3_exec(db, sql, nil, nil, nil)
    }
}
