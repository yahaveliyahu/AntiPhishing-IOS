//
//  HistoryStore.swift
//  AntiPhishing
//
//  Equivalent of the Android Room database (ScannedLink entity + LinkDao).
//  Stores scanned-link history in a shared App Group container so both the
//  main app and the Share Extension read/write the same data.
//
//  Mirrors LinkDao behaviour:
//   • insertAndTrim   — insert a link, dedupe by URL, FIFO-trim safe links to 5
//   • getRecentLinks  — latest 5 by timestamp
//   • todayScannedCount / blockedThreatsCount
//   • clearHistory / deleteLink(id:)
//

// 1. מגדיר איך נראית רשומת קישור שנבדק.
// 2. שומר את כל ההיסטוריה ב־App Group.
// 3. טוען את ההיסטוריה כשהאפליקציה נפתחת.
// 4. מחזיר את 5 הקישורים האחרונים.
// 5. סופר כמה קישורים נבדקו היום.
// 6. סופר כמה איומים נחסמו.
// 7. מוסיף קישור חדש ומונע כפילויות.
// 8. שומר רק 5 קישורים בטוחים אחרונים.
// 9. שומר קישורים מסוכנים בלי הגבלה.
// 10. מאפשר למחוק קישור בודד או לנקות את כל ההיסטוריה.


import Foundation
import Combine

// MARK: - Model (port of ScannedLink.kt)

struct ScannedLink: Identifiable, Codable, Equatable {
    var id: String = UUID().uuidString
    var url: String
    var timestamp: Double = Date().timeIntervalSince1970 * 1000  // millis, like Android
    var isSuspicious: Bool        // true = Red, false = Green
    var riskScore: Int            // 0-100
    var threatType: String? = nil
}

// MARK: - Store

final class HistoryStore: ObservableObject {

    static let shared = HistoryStore()

    /// App Group identifier — single source of truth lives in SharedStore
    /// (shared with the Safari Web Extension); this alias keeps existing
    /// call sites working.
    static let appGroup = SharedStore.appGroupID

    private let storageKey = "scanned_links"
    private let prefsKey = "AntiPhishingPrefs"

    @Published private(set) var links: [ScannedLink] = []

    private var defaults: UserDefaults {
        UserDefaults(suiteName: Self.appGroup) ?? .standard
    }

    private init() {
        reload()
    }

    // MARK: Reload from disk

    func reload() {
        guard let data = defaults.data(forKey: storageKey),
              let decoded = try? JSONDecoder().decode([ScannedLink].self, from: data) else {
            links = []
            return
        }
        links = decoded.sorted { $0.timestamp > $1.timestamp }
    }

    private func persist() {
        if let data = try? JSONEncoder().encode(links) {
            defaults.set(data, forKey: storageKey)
        }
    }

    // MARK: Queries (mirror LinkDao)

    /// Latest 5 scanned links for the dashboard.
    var recentLinks: [ScannedLink] {
        Array(links.sorted { $0.timestamp > $1.timestamp }.prefix(5))
    }

    /// Count of links scanned since the start of today.
    var todayScannedCount: Int {
        let startOfDay = Calendar.current.startOfDay(for: Date()).timeIntervalSince1970 * 1000
        return links.filter { $0.timestamp >= startOfDay }.count
    }

    /// Count of links marked suspicious.
    var blockedThreatsCount: Int {
        links.filter { $0.isSuspicious }.count
    }

    // MARK: Mutations (mirror LinkDao)

    /// Insert a new link, dedupe by URL, then FIFO-trim safe links to the 5 most recent.
    /// Suspicious links are kept indefinitely.
    func insertAndTrim(_ link: ScannedLink) {
        // deleteLinksByUrl
        links.removeAll { $0.url == link.url }
        // insertLink
        links.append(link)
        // enforceFifoOnSafeLinks: keep all suspicious; keep only the 5 newest safe links
        let sorted = links.sorted { $0.timestamp > $1.timestamp }
        let newestSafeIds = Set(sorted.filter { !$0.isSuspicious }.prefix(5).map { $0.id })
        links = links.filter { $0.isSuspicious || newestSafeIds.contains($0.id) }
        links.sort { $0.timestamp > $1.timestamp }
        persist()
        publish()
    }

    func deleteLink(id: String) {
        links.removeAll { $0.id == id }
        persist()
        publish()
    }

    func clearHistory() {
        links.removeAll()
        persist()
        publish()
    }

    private func publish() {
        // Ensure @Published change is delivered on the main thread for SwiftUI.
        if Thread.isMainThread {
            objectWillChange.send()
        } else {
            DispatchQueue.main.async { self.objectWillChange.send() }
        }
    }
}
