//
//  AllowlistStore.swift
//  AntiPhishing (Shared)
//
//  User "Continue Anyway" decisions, shared between the app (management
//  screen) and the Safari extension (which writes new approvals and honors
//  them on later visits).
//
//  Kept as a separate JSON file — deliberately NOT inside protection.sqlite —
//  so replacing the malicious-domain database during an update can never wipe
//  the user's choices.
//
//  Approvals are temporary by default (24h): a phishing warning the user
//  clicked through once should not silence protection forever. Expired
//  entries are ignored by lookups and can be purged from the app.
//

import Foundation

nonisolated struct AllowlistEntry: Codable, Equatable, Identifiable {
    /// Normalized domain the approval applies to. This is the database entry
    /// that triggered the warning (possibly a parent of the visited host), so
    /// one approval covers the whole blocked site, matching user intent.
    var domain: String
    var approvedAt: Date
    var expiresAt: Date
    /// Why the entry exists — currently always a user action, but stored so
    /// the management UI can distinguish sources later.
    var reason: String
    /// True when the user explicitly tapped "Continue Anyway".
    var userApproved: Bool

    var id: String { domain }
    var isExpired: Bool { expiresAt < Date() }
}

nonisolated enum AllowlistStore {

    /// Default lifetime of a "Continue Anyway" approval. The prototype
    /// extension used a 10-minute per-URL bypass; for managed per-domain
    /// approvals with a management screen, 24h is the chosen policy.
    static let defaultApprovalTTL: TimeInterval = 24 * 60 * 60

    static let userApprovalReason = "continue_anyway"

    // MARK: Reading

    /// All entries currently on disk, newest first. Includes expired entries
    /// (the management screen shows and purges them); use activeEntry(for:)
    /// for protection decisions.
    static func allEntries() -> [AllowlistEntry] {
        guard let url = SharedStore.allowlistURL,
              let data = try? Data(contentsOf: url),
              let entries = try? ProtectionMetadata.decoder.decode([AllowlistEntry].self, from: data) else {
            return []
        }
        return entries.sorted { $0.approvedAt > $1.approvedAt }
    }

    /// The non-expired approval covering a normalized host, if any. Walks the
    /// same parent chain as the database lookup so an approval for "evil.com"
    /// also covers "login.evil.com".
    static func activeEntry(forNormalizedHost host: String) -> AllowlistEntry? {
        let entries = allEntries()
        guard !entries.isEmpty else { return nil }
        let candidates = Set(DomainNormalizer.lookupCandidates(for: host))
        return entries.first { !$0.isExpired && candidates.contains($0.domain) }
    }

    // MARK: Mutations

    /// Records a user approval for a domain (replacing any previous entry for
    /// the same domain). Returns the stored entry.
    @discardableResult
    static func approve(domain: String,
                        ttl: TimeInterval = defaultApprovalTTL,
                        reason: String = userApprovalReason) -> AllowlistEntry? {
        guard let normalized = DomainNormalizer.normalizeHost(from: domain) else { return nil }
        var entries = allEntries().filter { $0.domain != normalized }
        let entry = AllowlistEntry(
            domain: normalized,
            approvedAt: Date(),
            expiresAt: Date().addingTimeInterval(ttl),
            reason: reason,
            userApproved: true
        )
        entries.insert(entry, at: 0)
        persist(entries)
        return entry
    }

    static func remove(domain: String) {
        persist(allEntries().filter { $0.domain != domain })
    }

    static func clearExpired() {
        persist(allEntries().filter { !$0.isExpired })
    }

    static func clearAll() {
        persist([])
    }

    // MARK: Persistence

    private static func persist(_ entries: [AllowlistEntry]) {
        guard let url = SharedStore.allowlistURL,
              let data = try? ProtectionMetadata.encoder.encode(entries) else { return }
        // Atomic write; the extension and app both replace the whole file.
        // Concurrent writes are rare (a user can't tap "Continue Anyway" and
        // manage the list at the same instant) and last-writer-wins is safe.
        try? data.write(to: url, options: .atomic)
    }
}
