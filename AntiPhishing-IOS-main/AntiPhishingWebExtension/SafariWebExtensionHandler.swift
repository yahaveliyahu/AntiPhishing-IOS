//
//  SafariWebExtensionHandler.swift
//  AntiPhishingWebExtension
//
//  Native side of the Safari Web Extension. The extension's JavaScript cannot
//  read App Group files, so every protection decision funnels through this
//  handler via browser.runtime.sendNativeMessage:
//
//    {action: "checkDomain", url}   → verdict, checked in order: allowlist →
//                                     SQLite malicious-domain database →
//                                     on-device lexical analysis → (only if
//                                     still undecided) the ML server, exactly
//                                     mirroring CheckPipeline.swift's 3-step
//                                     pipeline used by the app's own link
//                                     check. Only that last step, and only for
//                                     pages not already resolved locally,
//                                     sends the page's host to the server.
//    {action: "allowDomain", domain}→ "Continue Anyway": stores a temporary
//                                     approval in the shared allowlist.
//    {action: "getStatus"}          → database/protection status for the
//                                     popup UI.
//
//  Shared code: SharedStore / ProtectionDatabase / DomainNormalizer /
//  AllowlistStore / LexicalAnalyzer / ApiClient are the same source files the
//  app compiles — both sides normalize, look up and score domains identically
//  by construction.
//
//  Every request also stamps a heartbeat in the shared defaults; the app uses
//  it as the only available evidence that the user enabled the extension
//  (iOS offers no API to query Safari extension state).
//
//
// 1. מקבל את ההודעה מ־background.js.
// 2. מוציא ממנה את action.
// 3. רושם heartbeat כדי שהאפליקציה תדע שהתוסף היה פעיל.
// 4. אם action הוא checkDomain — מפעיל את בדיקת האתר.
// 5. אם action הוא allowDomain — שומר אישור זמני.
// 6. אם action הוא getStatus — מחזיר את מצב ההגנה.
// 7. אורז את התוצאה בתוך NSExtensionItem.
// 8. מחזיר את התשובה ל־JavaScript.


import SafariServices
import os.log

private let log = OSLog(subsystem: "com.rongo.AntiPhishing.WebExtension", category: "protection")

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {

    /// One read-only database handle per extension process. Reopened when the
    /// app activates a new database version (file replaced under us).
    private static var database: ProtectionDatabase?
    private static var databaseVersion: Int = -1

    func beginRequest(with context: NSExtensionContext) {
        let request = context.inputItems.first as? NSExtensionItem
        let message: Any?
        if #available(iOS 15.0, macOS 11.0, *) {
            message = request?.userInfo?[SFExtensionMessageKey]
        } else {
            message = request?.userInfo?["message"]
        }

        // Evidence for the app's "extension enabled" status row.
        SharedStore.recordExtensionHeartbeat()

        guard let dict = message as? [String: Any], let action = dict["action"] as? String else {
            Self.complete(context, with: ["ok": false, "error": "unknown action"])
            return
        }

        switch action {
        case "checkDomain":
            // The only action that may reach the ML server, so it's the only
            // one that needs to run off the (synchronous) beginRequest call —
            // completeRequest is fine to call later, from the Task.
            Task {
                Self.complete(context, with: await Self.handleCheckDomain(dict))
            }
        case "allowDomain":
            Self.complete(context, with: Self.handleAllowDomain(dict))
        case "getStatus":
            Self.complete(context, with: Self.handleGetStatus())
        default:
            os_log(.default, log: log, "unknown native action: %{public}@", action)
            Self.complete(context, with: ["ok": false, "error": "unknown action"])
        }
    }

    private static func complete(_ context: NSExtensionContext, with response: [String: Any]) {
        let item = NSExtensionItem()
        if #available(iOS 15.0, macOS 11.0, *) {
            item.userInfo = [SFExtensionMessageKey: response]
        } else {
            item.userInfo = ["message": response]
        }
        context.completeRequest(returningItems: [item], completionHandler: nil)
    }

    // MARK: - Actions

    /// Short timeout for the ML call made from here: this gates a live page
    /// load, unlike the app's own "check a link" screen where a 60s wait
    /// behind a spinner is acceptable. A slow/asleep server fails open
    /// (verdict "safe") rather than hold the page.
    private static let mlTimeout: TimeInterval = 6

    /// Verdict for one page URL. Response verdicts:
    ///   "off"          protection switch disabled in the app
    ///   "unprotected"  no database downloaded yet / storage failure
    ///   "allowlisted"  covered by a user "Continue Anyway" approval
    ///   "malicious"    matched the malicious-domain database, an obvious
    ///                  lexical signal, or the ML model
    ///   "safe"         not in the database, and lexical analysis + the ML
    ///                  model (or a timeout/error from it) found nothing
    ///
    /// Only the ML step (reached when the database has no match and lexical
    /// analysis found no obvious signal) sends the page's host to the server
    /// — see ext_guide_note in Localization.swift, which discloses this.

    //1. מנרמל ל־login.example.com.
    //2. בודק שההגנה פעילה.
    //3. בודק allowlist.
    //4. בודק SQLite.
    //5. בודק ניתוח לקסיקלי.
    //6. פונה ל־ML רק אם עדיין אין החלטה.
    private static func handleCheckDomain(_ dict: [String: Any]) async -> [String: Any] {
        guard let rawURL = dict["url"] as? String,
              let host = DomainNormalizer.normalizeHost(from: rawURL) else {
            return ["ok": false, "error": "invalid url"]
        }

        let metadata = SharedStore.loadMetadata()
        var response: [String: Any] = [
            "ok": true,
            "host": host,
            // The JS layer tags its verdict cache with this and drops entries
            // when the app activates a newer database.
            "dbVersion": metadata?.version ?? 0,
            // "Show check confirmation" toggle from the app: content.js shows
            // a status toast on every page load while this is on.
            "toast": SharedStore.isCheckToastEnabled,
        ]
        defer {
            if let verdict = response["verdict"] as? String {
                SharedStore.recordRecentVisit(host: host, verdict: verdict)
            }
        }

        guard SharedStore.isProtectionActive else {
            response["verdict"] = "off"
            return response
        }

        // User-approved domain (walks the same parent chain as the DB lookup).
        if let approval = AllowlistStore.activeEntry(forNormalizedHost: host) {
            response["verdict"] = "allowlisted"
            response["allowlistExpiresAt"] = approval.expiresAt.timeIntervalSince1970 * 1000
            return response
        }

        guard let db = openDatabase(currentVersion: metadata?.version ?? 0) else {
            response["verdict"] = "unprotected"
            return response
        }

        if let match = db.match(normalizedHost: host) {
            response["verdict"] = "malicious"
            response["matchedDomain"] = match.matchedDomain
            response["source"] = match.source
            response["threatType"] = match.threatType
            return response
        }

        // Not in the local database — fall through exactly like
        // CheckPipeline.swift: obvious lexical signals block without a
        // network call; anything still undecided goes to the ML model.
        let lexical = LexicalAnalyzer.analyze(rawURL)
        if lexical.isObviouslyMalicious {
            response["verdict"] = "malicious"
            response["matchedDomain"] = host
            response["source"] = "Lexical Analysis"
            response["threatType"] = "lexical"
            response["explanation"] = lexical.flags.prefix(3).joined(separator: "\n")
            return response
        }

        switch await ApiClient.scoreLexical(rawURL, features: lexical.features, timeout: mlTimeout) {
        case .malicious(let explanation, let source, let confidence, let matchType):
            response["verdict"] = "malicious"
            response["matchedDomain"] = host
            response["source"] = source ?? "ML Model"
            response["threatType"] = matchType
            response["explanation"] = explanation
            response["confidence"] = confidence
        case .unknown, .whitelisted, .error:
            // Server said safe, or was unreachable/slow — fail open, never
            // hold the page hostage to a cold-starting free-tier server.
            response["verdict"] = "safe"
        }
        return response
    }

    /// Stores the user's "Continue Anyway" decision. `domain` is the matched
    /// (blocking) database entry so the approval covers the whole blocked
    /// site; expiry uses the shared default TTL (24h).
    private static func handleAllowDomain(_ dict: [String: Any]) -> [String: Any] {
        guard let domain = dict["domain"] as? String,
              let entry = AllowlistStore.approve(domain: domain) else {
            return ["ok": false, "error": "invalid domain"]
        }
        os_log(.info, log: log, "user approved domain until %{public}@", "\(entry.expiresAt)")
        return [
            "ok": true,
            "domain": entry.domain,
            "expiresAt": entry.expiresAt.timeIntervalSince1970 * 1000,
        ]
    }

    /// Status snapshot for the popup: does a database exist, how fresh is it,
    /// how many domains, is the master switch on.
    private static func handleGetStatus() -> [String: Any] {
        let metadata = SharedStore.loadMetadata()
        var response: [String: Any] = [
            "ok": true,
            "protectionActive": SharedStore.isProtectionActive,
            "databaseExists": SharedStore.databaseExists,
            "dbVersion": metadata?.version ?? 0,
            // background.js re-syncs its stored copy of the toast toggle from
            // this on every wake-up of its (ephemeral) background page.
            "toast": SharedStore.isCheckToastEnabled,
        ]
        if let metadata {
            response["domainCount"] = metadata.domainCount
            response["updatedAt"] = metadata.updatedAt.timeIntervalSince1970 * 1000
        }
        return response
    }

    // MARK: - Database handle

    /// Returns an open handle on the active database, reopening after the
    /// app swapped the file for a newer version (the version lives in
    /// metadata.json, so comparing it is cheap and cross-process safe).
    private static func openDatabase(currentVersion: Int) -> ProtectionDatabase? {
        if let db = database, databaseVersion == currentVersion {
            return db
        }
        database?.close()
        database = nil
        guard let url = SharedStore.databaseURL, SharedStore.databaseExists else { return nil }
        let db = ProtectionDatabase(url: url)
        guard db.open() else { return nil }
        database = db
        databaseVersion = currentVersion
        return db
    }
}
