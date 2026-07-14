//
//  HistoryStoreTests.swift
//  AntiPhishingTests
//
//  Verifies the scan-history store mirrors the Android Room/LinkDao behaviour:
//  dedupe by URL, FIFO-trim safe links to the 5 most recent, keep suspicious
//  links indefinitely, and report the dashboard counts.
//
//  Serialized because it mutates the HistoryStore singleton.
//

import Foundation
import Testing
@testable import AntiPhishing

@Suite(.serialized)
@MainActor
struct HistoryStoreTests {

    private func freshStore() -> HistoryStore {
        let store = HistoryStore.shared
        store.clearHistory()
        return store
    }

    private func link(_ url: String, ts: Double, suspicious: Bool = false, risk: Int = 0) -> ScannedLink {
        ScannedLink(url: url, timestamp: ts, isSuspicious: suspicious, riskScore: risk)
    }

    @Test("Safe links are FIFO-trimmed to the 5 most recent")
    func fifoTrimsSafeLinks() {
        let store = freshStore()
        for i in 1...7 { store.insertAndTrim(link("https://s\(i).com", ts: Double(i))) }

        #expect(store.links.count == 5)
        #expect(store.links.contains { $0.url == "https://s7.com" })
        #expect(!store.links.contains { $0.url == "https://s1.com" })
        #expect(!store.links.contains { $0.url == "https://s2.com" })
        store.clearHistory()
    }

    @Test("Suspicious links are kept beyond the 5-safe limit")
    func suspiciousLinksRetained() {
        let store = freshStore()
        store.insertAndTrim(link("https://mal.com", ts: 1000, suspicious: true, risk: 95))
        for i in 1...6 { store.insertAndTrim(link("https://s\(i).com", ts: Double(i))) }

        #expect(store.blockedThreatsCount == 1)
        #expect(store.links.contains { $0.url == "https://mal.com" })   // kept
        #expect(store.links.count == 6)                                 // 5 safe + 1 suspicious
        #expect(!store.links.contains { $0.url == "https://s1.com" })   // oldest safe trimmed
        store.clearHistory()
    }

    @Test("Inserting the same URL twice keeps a single entry")
    func dedupeByUrl() {
        let store = freshStore()
        store.insertAndTrim(link("https://dup.com", ts: 1))
        store.insertAndTrim(link("https://dup.com", ts: 2))
        #expect(store.links.count == 1)
        store.clearHistory()
    }

    @Test("clearHistory empties the store")
    func clearHistory() {
        let store = freshStore()
        store.insertAndTrim(link("https://a.com", ts: 1))
        store.insertAndTrim(link("https://b.com", ts: 2))
        store.clearHistory()
        #expect(store.links.isEmpty)
    }

    @Test("todayScannedCount counts links scanned today")
    func todayCount() {
        let store = freshStore()
        let now = Date().timeIntervalSince1970 * 1000
        store.insertAndTrim(link("https://a.com", ts: now))
        store.insertAndTrim(link("https://b.com", ts: now))
        store.insertAndTrim(link("https://c.com", ts: now))
        #expect(store.todayScannedCount == 3)
        store.clearHistory()
    }
}
