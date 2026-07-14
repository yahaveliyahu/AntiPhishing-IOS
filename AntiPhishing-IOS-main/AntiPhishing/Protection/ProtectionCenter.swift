//
//  ProtectionCenter.swift
//  AntiPhishing
//
//  Observable coordinator between the protection engine and the UI. Owns the
//  user-visible protection state machine and triggers launch checks and
//  manual updates. All the states required by the product spec map onto
//  `summary` below:
//
//    • extension not enabled            → extensionDetected == false
//    • extension on, no database        → .notReady
//    • database outdated                → .activeUpdateAvailable / stale flag
//    • active with current data         → .active
//    • active offline with old data     → .activeOffline
//    • update in progress               → .updating
//    • update failed, old DB active     → .updateFailedDatabaseActive
//    • no internet and no database      → .notReadyOffline
//    • shared storage / DB failure      → .storageError
//
// 1. טוען את מצב מסד הנתונים המקומי.
// 2. בודק אם Safari Extension נראה פעיל.
// 3. בודק אם השרת זמין.
// 4. בודק אם קיימת גרסת DB חדשה.
// 5. מחליט איזה סטטוס להציג למשתמש.
// 6. מפעיל עדכון DB כשהמשתמש לוחץ Update.
// 7. מעדכן progress בזמן ההורדה והבנייה.
// 8. שומר תוצאת הצלחה או שגיאה.
// 9. מעדכן את SwiftUI בכל שינוי.

// האפליקציה נפתחת.
// ProtectionCenter קורא metadata, DB ו-heartbeat.
// הוא שולח בקשת /api/stats קצרה.
// summary מחליט איזה מצב להציג.
// המשתמש לוחץ Update.
// ProtectionUpdateEngine מוריד ובונה DB.
// ProtectionCenter מעדכן progress.
// בסיום הוא טוען מחדש את ה־metadata וה־DB.
// SwiftUI מתעדכן אוטומטית.


import Foundation
import Combine

@MainActor
final class ProtectionCenter: ObservableObject {

    static let shared = ProtectionCenter()

    // MARK: State published to SwiftUI

    /// Metadata of the active database (nil until the first successful update).
    @Published private(set) var metadata: ProtectionMetadata?
    /// Live row count read from the database file itself.
    @Published private(set) var localDomainCount: Int?
    /// Latest /api/stats snapshot from this session; nil = server not reached.
    @Published private(set) var serverStats: ServerStats?
    /// False after a failed connectivity attempt, true after a success,
    /// nil before the first attempt finishes.
    @Published private(set) var serverReachable: Bool?
    /// Timestamp of the last Safari-extension native call (heartbeat).
    @Published private(set) var extensionLastSeen: Date?
    @Published private(set) var updateActivity: UpdateActivity = .idle
    /// Friendly outcome line for the last finished update ("1 minute ago…").
    @Published private(set) var lastUpdateOutcomeKey: String?
    /// When the running update started — drives the elapsed/remaining line.
    @Published private(set) var updateStartedAt: Date?
    /// A lightweight `/api/stats` freshness check is running in the background.
    /// Kept SEPARATE from `updateActivity` on purpose: a background check must
    /// never make the "Update Protection Database" button look busy or block a
    /// real update (that conflation made a slow/unreachable server look like a
    /// stuck download).
    @Published private(set) var isCheckingFreshness = false

    enum UpdateActivity: Equatable {
        case idle
        /// `progress` is the overall update fraction (0…1) for the bar,
        /// nil while a stage can't estimate (e.g. build with unknown total).
        case updating(phaseKey: String, detail: String?, progress: Double?)

        /// True only during a real database update (download/build/activate),
        /// so only that drives the button spinner — never a freshness check.
        var isBusy: Bool { self != .idle }
    }

    /// One coarse state for the status card.
    enum Summary: Equatable {
        case storageError
        case masterOff              // app's master protection switch is off
        case updating
        case notReady               // no DB, connectivity unknown/ok
        case notReadyOffline        // no DB and server+feeds unreachable
        case active                 // DB present, believed current
        case activeUpdateAvailable  // DB present, server counters moved on
        case activeStale            // DB present but old (no recent check)
        case activeOffline          // DB present, currently offline
        case updateFailedDatabaseActive
    }

    /// Database older than this without a successful check is shown as
    /// "using an older database" (the server reseeds feeds every 12h).
    static let staleAfter: TimeInterval = 7 * 24 * 60 * 60

    /// Heartbeat window in which we consider the extension "enabled".
    /// There is no iOS API to query Safari extension state directly, so a
    /// recent native-handler call is the only reliable evidence.
    static let extensionSeenWindow: TimeInterval = 14 * 24 * 60 * 60

    private var didRunLaunchCheck = false
    /// Identifies the current update run. Progress callbacks are delivered via
    /// detached MainActor tasks that can arrive out of order — including AFTER
    /// the run finished — which previously left the bar frozen at "98%". Each
    /// callback carries the token it was issued under and is dropped once the
    /// token moves on, so no late phase can revive a finished update.
    private var updateRunToken = 0

    private init() {
        refreshLocalState()
    }

    // MARK: Derived state

    var storageAvailable: Bool { SharedStore.containerURL != nil }
    var databaseExists: Bool { SharedStore.databaseExists }

    /// True when the Safari extension has called home recently enough.
    var extensionDetected: Bool {
        guard let seen = extensionLastSeen else { return false }
        return Date().timeIntervalSince(seen) < Self.extensionSeenWindow
    }

    /// Server counters moved since our snapshot → newer data is available.
    var updateAvailable: Bool {
        guard let stats = serverStats,
              let snapshot = metadata?.serverMaliciousDomains else { return false }
        return stats.maliciousDomains != snapshot
    }

    var summary: Summary {
        if !storageAvailable { return .storageError }
        if case .updating = updateActivity { return .updating }
        // The extension honors the app's master switch (verdict "off"), so
        // the status must say so instead of claiming active protection.
        if !AppSettings.shared.isProtectionActive { return .masterOff }

        guard databaseExists, metadata != nil else {
            return serverReachable == false ? .notReadyOffline : .notReady
        }
        // A database is active from here on.
        if metadata?.lastUpdateError != nil { return .updateFailedDatabaseActive }
        if serverReachable == false { return .activeOffline }
        if updateAvailable { return .activeUpdateAvailable }
        if let updated = metadata?.updatedAt,
           Date().timeIntervalSince(updated) > Self.staleAfter {
            return .activeStale
        }
        return .active
    }

    // MARK: Actions

    /// Re-reads everything shared from disk (called on appear/foreground —
    /// the extension may have stamped its heartbeat or added allowlist
    /// entries while the app was inactive).
    func refreshLocalState() {
        metadata = SharedStore.loadMetadata()
        extensionLastSeen = SharedStore.lastExtensionHeartbeat
        if let dbURL = SharedStore.databaseURL, SharedStore.databaseExists {
            let db = ProtectionDatabase(url: dbURL)
            localDomainCount = db.domainCount()
            db.close()
        } else {
            localDomainCount = nil
        }
    }

    /// App-open behavior: refresh local state and run the lightweight
    /// /api/stats freshness check (a few hundred bytes) so the status card
    /// can say "update available". Database downloads are NEVER started
    /// implicitly — they only run when the user presses the
    /// download/update button (startUpdate).
    func runLaunchCheckIfNeeded() async {
        guard !didRunLaunchCheck else { return }
        didRunLaunchCheck = true
        await refreshStatus()
    }

    /// Pull-to-refresh / launch check: re-reads shared state from disk
    /// (extension heartbeat, allowlist, metadata) and refreshes the server
    /// freshness snapshot. Cheap and side-effect free — never downloads, and
    /// never blocks or spins the update button (see `isCheckingFreshness`).
    /// A real update in progress takes priority — skip the check then.
    func refreshStatus() async {
        refreshLocalState()
        guard storageAvailable, !updateActivity.isBusy, !isCheckingFreshness else { return }

        isCheckingFreshness = true
        // Short timeout: this is a best-effort freshness ping. A sleeping or
        // broken server must resolve fast instead of hanging the indicator.
        let stats = await ApiClient.fetchStats(timeout: 8)
        serverStats = stats
        serverReachable = stats != nil
        if stats != nil, var m = metadata {
            m.lastCheckedAt = Date()
            try? SharedStore.saveMetadata(m)
            metadata = m
        }
        isCheckingFreshness = false
    }

    /// The "Update Protection Database" action (also used for the automatic
    /// first download). Runs the engine off the main actor and reflects
    /// progress into the UI.
    func startUpdate(force: Bool) async {
        guard !updateActivity.isBusy else { return }
        guard storageAvailable else { return }
        lastUpdateOutcomeKey = nil
        updateStartedAt = Date()
        updateRunToken &+= 1
        let token = updateRunToken
        updateActivity = .updating(phaseKey: "sp_phase_contacting", detail: nil, progress: 0)

        do {
            let outcome = try await ProtectionUpdateEngine.performUpdate(force: force) { phase in
                Task { @MainActor in
                    ProtectionCenter.shared.reflect(phase: phase, token: token)
                }
            }
            switch outcome {
            case .updated(let newMetadata):
                metadata = newMetadata
                lastUpdateOutcomeKey = "sp_update_success"
            case .alreadyUpToDate(let newMetadata):
                metadata = newMetadata
                lastUpdateOutcomeKey = "sp_update_already_current"
            }
            serverReachable = true
        } catch let error as ProtectionUpdateEngine.UpdateError {
            ProtectionUpdateEngine.recordFailure(error)
            lastUpdateOutcomeKey = friendlyErrorKey(for: error)
            if case .noFeedData = error { serverReachable = false }
        } catch {
            lastUpdateOutcomeKey = "err_update_generic"
        }

        // Invalidate the run BEFORE going idle so any late progress task is
        // dropped instead of reviving the bar.
        updateRunToken &+= 1
        updateActivity = .idle
        updateStartedAt = nil
        refreshLocalState()
        // Best-effort freshness counters; short timeout so a dead server
        // doesn't leave a trailing operation hanging for 20s.
        serverStats = await ApiClient.fetchStats(timeout: 8) ?? serverStats
        if serverStats != nil { serverReachable = true }
    }

    /// Maps engine phases onto one overall 0…1 progress scale. Weights are
    /// wall-time-based: downloads dominate (3–72%), building is CPU-bound
    /// (72–92%), the rest is bookkeeping. A callback whose `token` is no
    /// longer current belongs to a finished/superseded run and is ignored.
    // contacting server → 2%
    // downloading       → 3% עד 72%
    // building          → 72% עד 92%
    // validating        → 94%
    // activating        → 98%
    private func reflect(phase: ProtectionUpdateEngine.Phase, token: Int) {
        guard token == updateRunToken else { return }
        switch phase {
        case .contactingServer:
            updateActivity = .updating(phaseKey: "sp_phase_contacting", detail: nil, progress: 0.02)
        case .downloading(_, _, let fraction, let detail):
            updateActivity = .updating(phaseKey: "sp_phase_downloading", detail: detail,
                                       progress: 0.03 + fraction * 0.69)
        case .building(let inserted, let estimatedTotal):
            let fraction = estimatedTotal.map { min(Double(inserted) / Double(max($0, 1)), 1) }
            updateActivity = .updating(phaseKey: "sp_phase_building",
                                       detail: inserted > 0 ? inserted.formatted() : nil,
                                       progress: fraction.map { 0.72 + $0 * 0.20 })
        case .validating:
            updateActivity = .updating(phaseKey: "sp_phase_validating", detail: nil, progress: 0.94)
        case .activating:
            updateActivity = .updating(phaseKey: "sp_phase_activating", detail: nil, progress: 0.98)
        }
    }

    /// Maps engine errors to friendly, localized message keys. Raw details
    /// stay in metadata.lastUpdateError for debugging only.
    private func friendlyErrorKey(for error: ProtectionUpdateEngine.UpdateError) -> String {
        switch error {
        case .storageUnavailable: return "err_update_storage"
        case .noFeedData: return databaseExists ? "err_update_offline_db" : "err_update_offline_nodb"
        case .tooFewDomains, .validationFailed: return "err_update_invalid_data"
        case .buildFailed, .activationFailed: return "err_update_generic"
        }
    }
}
