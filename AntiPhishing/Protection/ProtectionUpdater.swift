//
//  ProtectionUpdater.swift
//  AntiPhishing
//
//  Downloads, validates and atomically activates the malicious-domain
//  database. App-side only — the Safari extension never writes protection
//  data, it only reads what this engine activates.
//
//  Update sequence (rollback-safe by construction):
//    1. GET /api/stats            → server counters (freshness + display)
//    2. Conditional GET per feed  → 304 reuses the cached copy, 200 stages a
//                                   fresh one (ETag / Last-Modified based)
//    3. Stream-parse feeds        → normalized domains into a *staging*
//                                   SQLite file (never the live one)
//    4. Validate                  → minimum domain count, SQLite integrity,
//                                   row count == inserted count, SHA-256
//    5. Activate                  → atomic file replacement of the live DB
//    6. Persist metadata          → version+1; the version bump is what
//                                   tells the extension to drop its caches
//
//  A failure at any step leaves the previous database untouched and active.
//

import Foundation
import CryptoKit

nonisolated enum ProtectionUpdateEngine {

    /// An update that would produce fewer domains than this is considered a
    /// corrupt/gutted download and is rejected (the healthy combined feed set
    /// is 600k+; see /api/stats malicious_domains ≈ 675k).
    static let minimumAcceptableDomainCount = 50_000

    enum Phase: Sendable {
        case contactingServer
        /// Overall progress of the (concurrent) feed downloads.
        /// `fraction` covers the whole download stage (0…1, byte-weighted);
        /// `detail` is a ready-made human line ("3/8 · 12.4 MB").
        case downloading(completed: Int, total: Int, fraction: Double, detail: String?)
        /// Staging-database build progress. `estimatedTotal` (server domain
        /// count or the previous build's count) may be nil → indeterminate.
        case building(inserted: Int, estimatedTotal: Int?)
        case validating
        case activating
    }

    enum Outcome: Sendable {
        case updated(ProtectionMetadata)
        /// Every feed replied 304 Not Modified and a database already exists.
        case alreadyUpToDate(ProtectionMetadata)
    }

    enum UpdateError: Error, Sendable {
        case storageUnavailable          // App Group container missing
        case noFeedData([String: String])// all feeds failed; name → reason
        case tooFewDomains(Int)          // downloaded data looks gutted
        case buildFailed(String)
        case validationFailed(String)
        case activationFailed(String)

        /// Raw technical detail for metadata/logging (UI uses L10n strings).
        var debugDescription: String {
            switch self {
            case .storageUnavailable: return "App Group container unavailable"
            case .noFeedData(let reasons):
                return "all feeds failed: " + reasons.map { "\($0.key): \($0.value)" }.joined(separator: "; ")
            case .tooFewDomains(let count):
                return "only \(count) domains parsed (minimum \(minimumAcceptableDomainCount))"
            case .buildFailed(let why): return "build failed: \(why)"
            case .validationFailed(let why): return "validation failed: \(why)"
            case .activationFailed(let why): return "activation failed: \(why)"
            }
        }
    }

    private struct FeedFetchResult: Sendable {
        var feed: ThreatFeed
        /// Local file to parse (fresh download or reused cache), nil = feed unusable.
        var dataURL: URL?
        var freshDownload: Bool
        var etag: String?
        var lastModified: String?
        /// Decompressed size of a fresh download (progress estimate next time).
        var byteCount: Int64?
        var failureReason: String?
    }

    // MARK: - Entry point

    /// Runs the full update. `force` skips conditional-GET short-circuiting
    /// (used by the manual "Update Protection Database" action so the user
    /// can always rebuild).
    static func performUpdate(force: Bool,
                              progress: @escaping @Sendable (Phase) -> Void) async throws -> Outcome {
        guard let stagingDir = SharedStore.stagingDirectoryURL,
              let cacheDir = SharedStore.feedCacheDirectoryURL,
              let liveDBURL = SharedStore.databaseURL else {
            throw UpdateError.storageUnavailable
        }

        let startedAt = Date()
        let previousMetadata = SharedStore.loadMetadata()

        // ── 1. Server counters (best effort — update works offline-tolerant
        //       as long as the feeds themselves are reachable). Fetched
        //       CONCURRENTLY with the downloads: the counters only feed the
        //       freshness display and a progress estimate, so a sleeping /
        //       502 server must never stall the update at the starting line
        //       (that stall was the "stuck on Update" symptom). ──────────────
        async let statsAsync = ApiClient.fetchStats(timeout: 8)

        // ── 2. Download feeds concurrently (conditional GETs). Parallelism
        //       bounds the wall time by the slowest feed instead of the sum
        //       of all of them; the board merges per-feed byte counts into
        //       one overall fraction for the progress bar. ───────────────────
        let total = ThreatFeed.all.count
        let board = DownloadProgressBoard(total: total)
        progress(.downloading(completed: 0, total: total, fraction: 0, detail: nil))

        var fetches: [FeedFetchResult] = []
        await withTaskGroup(of: FeedFetchResult.self) { group in
            for feed in ThreatFeed.all {
                let previous = previousMetadata?.feedStates[feed.name]
                group.addTask {
                    await fetch(feed: feed,
                                previousState: force ? nil : previous,
                                expectedBytes: previous?.byteSize,
                                stagingDir: stagingDir,
                                cacheDir: cacheDir) { received, expected in
                        if let snap = board.update(feed: feed.name, received: received, expected: expected) {
                            progress(.downloading(completed: snap.completed, total: total,
                                                  fraction: snap.fraction, detail: snap.detail))
                        }
                    }
                }
            }
            for await result in group {
                fetches.append(result)
                let snap = board.finish(feed: result.feed.name)
                progress(.downloading(completed: snap.completed, total: total,
                                      fraction: snap.fraction, detail: snap.detail))
            }
        }

        let anyFresh = fetches.contains { $0.freshDownload }
        let usable = fetches.filter { $0.dataURL != nil }

        // Collect the concurrent stats now. The downloads gave it a head
        // start, so on a real connection it has already finished (or timed
        // out) — no added wait — while the update never stalled waiting for it.
        let stats = await statsAsync

        // Non-fatal per-feed problems, surfaced in the UI for transparency.
        // A feed that fell back to its cached copy still counts: its data is
        // stale even though the update as a whole succeeded.
        var feedIssues: [String: String] = [:]
        for f in fetches {
            guard let reason = f.failureReason else { continue }
            feedIssues[f.feed.name] = f.dataURL != nil ? "\(reason) — using cached copy" : reason
        }

        if usable.isEmpty {
            var reasons: [String: String] = [:]
            for f in fetches { reasons[f.feed.name] = f.failureReason ?? "no data" }
            throw UpdateError.noFeedData(reasons)
        }

        // Nothing changed anywhere and we already have a working database →
        // record the successful check and keep the active data.
        if !anyFresh, !force, var metadata = previousMetadata, SharedStore.databaseExists {
            metadata.lastCheckedAt = Date()
            metadata.serverMaliciousDomains = stats?.maliciousDomains ?? metadata.serverMaliciousDomains
            metadata.serverMaliciousURLs = stats?.maliciousUrls ?? metadata.serverMaliciousURLs
            metadata.lastUpdateError = nil
            metadata.lastFeedIssues = feedIssues.isEmpty ? nil : feedIssues
            try? SharedStore.saveMetadata(metadata)
            return .alreadyUpToDate(metadata)
        }

        // ── 3. Build the staging database ────────────────────────────────────
        // Progress denominator: the previous build's count is the most
        // reliable, always-available estimate of the final size; the server
        // counter is the fallback for a first-ever build.
        let estimatedTotal = previousMetadata?.domainCount ?? stats?.maliciousDomains
        progress(.building(inserted: 0, estimatedTotal: estimatedTotal))
        let stagingDB = stagingDir.appendingPathComponent("protection-staging.sqlite")
        var feedStates: [String: ProtectionMetadata.FeedState] = [:]
        let insertedCount: Int
        do {
            let writer = try ProtectionDatabaseWriter(url: stagingDB)
            for fetch in usable {
                guard let fileURL = fetch.dataURL else { continue }
                let count = try await parse(feed: fetch.feed, fileURL: fileURL, into: writer) { inserted in
                    progress(.building(inserted: inserted, estimatedTotal: estimatedTotal))
                }
                // A 200-OK feed that parses to zero domains is corrupt output;
                // keep the update alive but don't record it as a good state.
                if count > 0 {
                    let previous = previousMetadata?.feedStates[fetch.feed.name]
                    feedStates[fetch.feed.name] = ProtectionMetadata.FeedState(
                        etag: fetch.freshDownload ? fetch.etag : previous?.etag,
                        lastModified: fetch.freshDownload ? fetch.lastModified : previous?.lastModified,
                        recordCount: count,
                        fetchedAt: fetch.freshDownload ? Date() : (previous?.fetchedAt ?? Date()),
                        byteSize: fetch.freshDownload ? fetch.byteCount : previous?.byteSize
                    )
                }
            }
            writer.finish()
            insertedCount = writer.insertedCount
        } catch let error as UpdateError {
            try? FileManager.default.removeItem(at: stagingDB)
            throw error
        } catch {
            try? FileManager.default.removeItem(at: stagingDB)
            throw UpdateError.buildFailed(String(describing: error))
        }

        // ── 4. Validate before touching the live database ────────────────────
        progress(.validating)
        guard insertedCount >= minimumAcceptableDomainCount else {
            try? FileManager.default.removeItem(at: stagingDB)
            throw UpdateError.tooFewDomains(insertedCount)
        }
        let verifier = ProtectionDatabase(url: stagingDB)
        guard verifier.passesIntegrityCheck(),
              let verifiedCount = verifier.domainCount(),
              verifiedCount == insertedCount else {
            verifier.close()
            try? FileManager.default.removeItem(at: stagingDB)
            throw UpdateError.validationFailed("staged database failed integrity/count verification")
        }
        verifier.close()

        let sha256: String
        do {
            sha256 = try FileHasher.sha256Hex(of: stagingDB)
        } catch {
            try? FileManager.default.removeItem(at: stagingDB)
            throw UpdateError.validationFailed("could not hash staged database")
        }

        // ── 5. Atomic activation ─────────────────────────────────────────────
        progress(.activating)
        do {
            if FileManager.default.fileExists(atPath: liveDBURL.path) {
                // replaceItemAt is atomic on APFS: readers either see the old
                // file (already-open handles keep the old inode) or the new one.
                _ = try FileManager.default.replaceItemAt(liveDBURL, withItemAt: stagingDB)
            } else {
                try FileManager.default.moveItem(at: stagingDB, to: liveDBURL)
            }
        } catch {
            try? FileManager.default.removeItem(at: stagingDB)
            throw UpdateError.activationFailed(String(describing: error))
        }

        // Promote fresh raw downloads into the feed cache for the next
        // incremental run (only after activation succeeded).
        for fetch in fetches where fetch.freshDownload {
            guard let staged = fetch.dataURL else { continue }
            let cached = cacheDir.appendingPathComponent(fetch.feed.name + ".txt")
            try? FileManager.default.removeItem(at: cached)
            try? FileManager.default.moveItem(at: staged, to: cached)
        }

        // ── 6. Persist metadata (version bump = extension sync signal) ──────
        let metadata = ProtectionMetadata(
            version: (previousMetadata?.version ?? 0) + 1,
            updatedAt: Date(),
            domainCount: insertedCount,
            sha256: sha256,
            feedStates: feedStates,
            serverMaliciousDomains: stats?.maliciousDomains ?? previousMetadata?.serverMaliciousDomains,
            serverMaliciousURLs: stats?.maliciousUrls ?? previousMetadata?.serverMaliciousURLs,
            lastCheckedAt: Date(),
            lastUpdateError: nil,
            lastUpdateDuration: Date().timeIntervalSince(startedAt),
            lastFeedIssues: feedIssues.isEmpty ? nil : feedIssues
        )
        try? SharedStore.saveMetadata(metadata)
        return .updated(metadata)
    }

    /// Records a failed update in metadata (previous database stays active)
    /// so the UI can show "last update failed" after relaunch too.
    static func recordFailure(_ error: UpdateError) {
        guard var metadata = SharedStore.loadMetadata() else { return }
        metadata.lastUpdateError = error.debugDescription
        metadata.lastCheckedAt = Date()
        try? SharedStore.saveMetadata(metadata)
    }

    // MARK: - Networking

    /// Downloads one feed, streaming to disk and reporting received bytes via
    /// `onBytes(received, expected)`. `expected` prefers the previous fresh
    /// download's decompressed size (`expectedBytes`) over Content-Length,
    /// which reports the gzip-compressed size and would skew the bar.
    private static func fetch(feed: ThreatFeed,
                              previousState: ProtectionMetadata.FeedState?,
                              expectedBytes: Int64?,
                              stagingDir: URL,
                              cacheDir: URL,
                              onBytes: @escaping @Sendable (Int64, Int64?) -> Void) async -> FeedFetchResult {
        var request = URLRequest(url: feed.url)
        request.timeoutInterval = 90 // idle timeout between packets, not total
        request.setValue("AntiPhishing-iOS/1.0", forHTTPHeaderField: "User-Agent")

        let cachedFile = cacheDir.appendingPathComponent(feed.name + ".txt")
        let hasCache = FileManager.default.fileExists(atPath: cachedFile.path)

        // Conditional GET — the feed hosts' own incremental-update mechanism.
        if hasCache, let previous = previousState {
            if let etag = previous.etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
            if let lm = previous.lastModified { request.setValue(lm, forHTTPHeaderField: "If-Modified-Since") }
        }

        do {
            let (bytes, response) = try await URLSession.shared.bytes(for: request)
            guard let http = response as? HTTPURLResponse else {
                return FeedFetchResult(feed: feed, dataURL: hasCache ? cachedFile : nil,
                                       freshDownload: false, etag: nil, lastModified: nil,
                                       byteCount: nil, failureReason: "no HTTP response")
            }
            switch http.statusCode {
            case 200:
                let headerLength = http.expectedContentLength > 0 ? http.expectedContentLength : nil
                let expected = expectedBytes ?? headerLength
                let staged = stagingDir.appendingPathComponent(feed.name + ".download")
                try? FileManager.default.removeItem(at: staged)
                FileManager.default.createFile(atPath: staged.path, contents: nil)
                let handle = try FileHandle(forWritingTo: staged)
                var received: Int64 = 0
                do {
                    var buffer = Data(capacity: 1 << 18)
                    for try await byte in bytes {
                        buffer.append(byte)
                        if buffer.count >= 1 << 18 { // flush + report every 256 KB
                            try handle.write(contentsOf: buffer)
                            received += Int64(buffer.count)
                            buffer.removeAll(keepingCapacity: true)
                            onBytes(received, expected)
                        }
                    }
                    if !buffer.isEmpty {
                        try handle.write(contentsOf: buffer)
                        received += Int64(buffer.count)
                    }
                    try handle.close()
                    onBytes(received, expected)
                } catch {
                    try? handle.close()
                    try? FileManager.default.removeItem(at: staged)
                    throw error
                }
                return FeedFetchResult(
                    feed: feed, dataURL: staged, freshDownload: true,
                    etag: http.value(forHTTPHeaderField: "ETag"),
                    lastModified: http.value(forHTTPHeaderField: "Last-Modified"),
                    byteCount: received,
                    failureReason: nil)
            case 304:
                // Unchanged since last download — reuse the cached copy.
                return FeedFetchResult(feed: feed, dataURL: hasCache ? cachedFile : nil,
                                       freshDownload: false, etag: nil, lastModified: nil,
                                       byteCount: nil,
                                       failureReason: hasCache ? nil : "304 without cache")
            default:
                return FeedFetchResult(feed: feed, dataURL: hasCache ? cachedFile : nil,
                                       freshDownload: false, etag: nil, lastModified: nil,
                                       byteCount: nil, failureReason: "HTTP \(http.statusCode)")
            }
        } catch {
            // Network failure: fall back to the cached copy (if any) so a
            // temporarily broken feed doesn't drop its domains from the DB.
            return FeedFetchResult(feed: feed, dataURL: hasCache ? cachedFile : nil,
                                   freshDownload: false, etag: nil, lastModified: nil,
                                   byteCount: nil, failureReason: error.localizedDescription)
        }
    }

    // MARK: - Parsing

    /// Streams one feed file line-by-line into the staging database,
    /// reporting the writer's total inserted count every 25k rows.
    /// Never loads the whole feed into memory (files can be 10–20MB).
    private static func parse(feed: ThreatFeed, fileURL: URL,
                              into writer: ProtectionDatabaseWriter,
                              onProgress: (Int) -> Void) async throws -> Int {
        var count = 0
        var isFirstLine = true
        do {
            for try await line in fileURL.lines {
                defer { isFirstLine = false }
                guard let candidate = feed.domainCandidate(fromLine: line, isFirstLine: isFirstLine),
                      let domain = DomainNormalizer.normalizeHost(from: candidate),
                      !ThreatFeed.excludedHosts.contains(domain) else { continue }
                try writer.insert(domain: domain, source: feed.name, type: feed.threatType)
                count += 1
                if writer.insertedCount % 25_000 == 0 { onProgress(writer.insertedCount) }
            }
        } catch let error as ProtectionDatabaseWriter.WriterError {
            throw UpdateError.buildFailed("\(feed.name): \(error)")
        } catch {
            // Unreadable/corrupt feed file — skip this feed, keep the update.
            return count
        }
        return count
    }
}

// MARK: - Download progress aggregation

/// Merges concurrent per-feed byte counts into one 0…1 fraction + detail line
/// for the UI, rate-limited so the MainActor isn't flooded with hops.
/// Thread-safe via an internal lock (updates arrive from parallel tasks).
private nonisolated final class DownloadProgressBoard: @unchecked Sendable {

    struct Snapshot {
        var completed: Int
        var fraction: Double
        var detail: String
    }

    private let lock = NSLock()
    private let total: Int
    private var fractions: [String: Double] = [:]
    private var bytes: [String: Int64] = [:]
    private var completedFeeds = 0
    private var lastEmit = Date.distantPast

    init(total: Int) { self.total = max(total, 1) }

    /// Byte-progress update from one feed. Returns nil when rate-limited.
    func update(feed: String, received: Int64, expected: Int64?) -> Snapshot? {
        lock.lock(); defer { lock.unlock() }
        if let expected, expected > 0 {
            // Cap below 1: only finish() marks a feed complete.
            fractions[feed] = min(Double(received) / Double(expected), 0.99)
        }
        bytes[feed] = received
        guard Date().timeIntervalSince(lastEmit) > 0.25 else { return nil }
        lastEmit = Date()
        return snapshotLocked()
    }

    /// A feed finished (successfully or not — either way it's done).
    func finish(feed: String) -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        fractions[feed] = 1
        completedFeeds += 1
        lastEmit = Date()
        return snapshotLocked()
    }

    private func snapshotLocked() -> Snapshot {
        let fraction = fractions.values.reduce(0, +) / Double(total)
        let totalBytes = bytes.values.reduce(0, +)
        let mb = ByteCountFormatter.string(fromByteCount: totalBytes, countStyle: .file)
        return Snapshot(completed: completedFeeds,
                        fraction: min(fraction, 1),
                        detail: "\(completedFeeds)/\(total) · \(mb)")
    }
}

// MARK: - File hashing

nonisolated enum FileHasher {
    /// Streaming SHA-256 (files are tens of MB; don't slurp them).
    static func sha256Hex(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
