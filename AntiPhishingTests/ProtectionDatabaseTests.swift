//
//  ProtectionDatabaseTests.swift
//  AntiPhishingTests
//
//  Round-trips the SQLite protection database: build with the writer (as the
//  updater does), read with the same reader the app and Safari extension use.
//

import Foundation
import Testing
@testable import AntiPhishing

@MainActor
struct ProtectionDatabaseTests {

    /// Builds a small throwaway database in the temp dir.
    private func makeDatabase(domains: [(String, String, String)]) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("test-\(UUID().uuidString).sqlite")
        let writer = try ProtectionDatabaseWriter(url: url)
        for (domain, source, type) in domains {
            try writer.insert(domain: domain, source: source, type: type)
        }
        writer.finish()
        return url
    }

    @Test("Exact domain lookup hits and misses correctly")
    func exactLookup() throws {
        let url = try makeDatabase(domains: [
            ("evil.test", "Phishing_Army", "blacklist"),
            ("malware.example", "URLhaus_Domains", "threat_intel"),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let db = ProtectionDatabase(url: url)
        defer { db.close() }

        let hit = db.match(normalizedHost: "evil.test")
        #expect(hit?.matchedDomain == "evil.test")
        #expect(hit?.source == "Phishing_Army")
        #expect(hit?.threatType == "blacklist")
        #expect(db.match(normalizedHost: "good.test") == nil)
    }

    @Test("Subdomains of a listed domain are blocked via the parent walk")
    func parentWalk() throws {
        let url = try makeDatabase(domains: [("evil.test", "Phishing_Army", "blacklist")])
        defer { try? FileManager.default.removeItem(at: url) }

        let db = ProtectionDatabase(url: url)
        defer { db.close() }

        let hit = db.match(normalizedHost: "login.secure.evil.test")
        #expect(hit?.matchedDomain == "evil.test")
        // …but a sibling domain that merely contains the string is NOT hit.
        #expect(db.match(normalizedHost: "notevil.test") == nil)
    }

    @Test("Duplicate inserts are ignored and count stays exact")
    func duplicatesAndCount() throws {
        let url = try makeDatabase(domains: [
            ("dup.test", "A", "blacklist"),
            ("dup.test", "B", "blacklist"),
            ("other.test", "A", "blacklist"),
        ])
        defer { try? FileManager.default.removeItem(at: url) }

        let db = ProtectionDatabase(url: url)
        defer { db.close() }

        #expect(db.domainCount() == 2)
        #expect(db.passesIntegrityCheck())
        // First feed wins for duplicates (mirrors INSERT OR IGNORE).
        #expect(db.lookupExact("dup.test")?.source == "A")
    }

    @Test("Missing database file fails open() instead of crashing")
    func missingFile() {
        let db = ProtectionDatabase(url: FileManager.default.temporaryDirectory
            .appendingPathComponent("does-not-exist.sqlite"))
        #expect(db.open() == false)
        #expect(db.match(normalizedHost: "evil.test") == nil)
    }
}

@MainActor
struct AllowlistStoreTests {

    /// The allowlist lives in the App Group container; when the test host
    /// can't access one (e.g. missing entitlement on CI) the store degrades
    /// to empty results, which we tolerate by skipping.
    private var containerAvailable: Bool { SharedStore.allowlistURL != nil }

    @Test("Approve, look up (including subdomain), remove")
    func approveAndRemove() throws {
        guard containerAvailable else { return }
        AllowlistStore.clearAll()
        defer { AllowlistStore.clearAll() }

        let entry = AllowlistStore.approve(domain: "https://Evil.Test/login")
        #expect(entry?.domain == "evil.test")
        #expect(entry?.userApproved == true)

        // Active for the domain and its subdomains (same walk as the DB).
        #expect(AllowlistStore.activeEntry(forNormalizedHost: "evil.test") != nil)
        #expect(AllowlistStore.activeEntry(forNormalizedHost: "login.evil.test") != nil)
        #expect(AllowlistStore.activeEntry(forNormalizedHost: "other.test") == nil)

        AllowlistStore.remove(domain: "evil.test")
        #expect(AllowlistStore.activeEntry(forNormalizedHost: "evil.test") == nil)
    }

    @Test("Expired approvals are ignored by lookups and purged by clearExpired")
    func expiry() throws {
        guard containerAvailable else { return }
        AllowlistStore.clearAll()
        defer { AllowlistStore.clearAll() }

        AllowlistStore.approve(domain: "old.test", ttl: -60) // already expired
        AllowlistStore.approve(domain: "fresh.test")

        #expect(AllowlistStore.activeEntry(forNormalizedHost: "old.test") == nil)
        #expect(AllowlistStore.activeEntry(forNormalizedHost: "fresh.test") != nil)
        #expect(AllowlistStore.allEntries().count == 2) // both still stored

        AllowlistStore.clearExpired()
        #expect(AllowlistStore.allEntries().map(\.domain) == ["fresh.test"])
    }
}
