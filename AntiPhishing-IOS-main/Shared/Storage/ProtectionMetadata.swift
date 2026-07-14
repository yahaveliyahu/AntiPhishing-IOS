//
//  ProtectionMetadata.swift
//  AntiPhishing (Shared)
//
//  Codable description of the currently active protection database, stored as
//  metadata.json next to protection.sqlite in the App Group container.
//
//  The `version` counter is the synchronization signal between the app and the
//  Safari extension: the extension tags its cached verdicts with the version it
//  used, and drops them when the app activates a database with a newer version.
//

import Foundation

nonisolated struct ProtectionMetadata: Codable, Equatable {

    /// Monotonically increasing local database version. Bumped every time a
    /// new database is activated. (The server has no version field of its own —
    /// see ThreatFeed.swift for how freshness is derived.)
    var version: Int

    /// When the active database finished downloading + validating.
    var updatedAt: Date

    /// Number of unique malicious domains in the active database.
    var domainCount: Int

    /// SHA-256 of the activated protection.sqlite, computed right after the
    /// build. Lets both processes detect on-disk corruption.
    var sha256: String

    /// Per-feed download state, keyed by feed name. ETag / Last-Modified are
    /// replayed as conditional-GET headers so unchanged feeds are not
    /// re-downloaded ("incremental" behavior the feed servers support).
    var feedStates: [String: FeedState]

    /// Snapshot of GET /api/stats counters taken when this database was built.
    /// A different malicious_domains count on a later check means the server's
    /// database changed since our snapshot → local data is outdated.
    var serverMaliciousDomains: Int?
    var serverMaliciousURLs: Int?

    /// Last time an update *check* completed against the server (whether or
    /// not new data was downloaded).
    var lastCheckedAt: Date?

    /// Debug detail of the most recent failed update, if any. The UI shows a
    /// friendly message; this raw string is for logs/diagnostics only.
    var lastUpdateError: String?

    /// Wall-clock duration of the update that produced this database —
    /// shown in the UI so "how long does it take" has a real answer.
    var lastUpdateDuration: TimeInterval?

    /// Feeds that contributed nothing to the last update (name → reason,
    /// e.g. "HTTP 502" / timeout). Non-fatal — the database still built from
    /// the remaining feeds — but surfaced in the UI for transparency.
    var lastFeedIssues: [String: String]?

    nonisolated struct FeedState: Codable, Equatable {
        var etag: String?
        var lastModified: String?
        var recordCount: Int
        var fetchedAt: Date
        /// Decompressed byte size of the last fresh download. Used as the
        /// expected size for the next download's progress bar (more accurate
        /// than Content-Length, which reports the gzip-compressed size).
        var byteSize: Int64?
    }

    // MARK: Serialization

    static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }

    static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
