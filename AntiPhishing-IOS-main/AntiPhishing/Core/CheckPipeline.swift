//
//  CheckPipeline.swift
//  AntiPhishing
//
//  The shared check pipeline used by the dashboard, QR scanner, and
//  Share Extension — equivalent to the logic inside LinkInterceptorActivity
//  and QrScannerActivity on Android.
//
//  Step 1: Check URL against local lists (IS_LOCAL) or the Flask server.
//  Step 2: For Unknown results, run on-device LexicalAnalyzer.
//          - isObviouslyMalicious  → block immediately (Malicious)
//          - otherwise             → Step 3: ApiClient.scoreLexical (ML server)
//


// 1. בודק SQLite מקומי.
// 2. אם נמצאה התאמה — malicious ומסיים.
// 3. אם מצב פיתוח מקומי פעיל — בודק LocalUrlLists.
// 4. אחרת — פונה ל־Flask דרך checkUrl או checkQrUrl.
// 5. אם התוצאה אינה Unknown — מחזיר אותה.
// 6. אם Unknown — מריץ LexicalAnalyzer.
// 7. אם ברור שה־URL זדוני — מחזיר malicious בביטחון 95.
// 8. אחרת — שולח את ה־URL וה־features לשרת ML.
// 9. מחזיר את תוצאת ה־ML.

import Foundation

/// When false, the pipeline checks URLs against the live Flask backend via
/// `ApiClient` — exactly like the Android app. Set to true only for offline
/// development, which uses the bundled `LocalUrlLists` instead of the server.
let IS_LOCAL = false

enum CheckPipeline {

    /// Runs the full pipeline for a URL and returns a CheckResult.
    /// `useQrEndpoint` selects the /api/qr/check endpoint when running against the server.
    static func check(_ url: String, useQrEndpoint: Bool = false) async -> CheckResult {

        // Step 0: local protection database (same data the Safari extension
        // uses, shared via the App Group). Instant, private, and works
        // offline — a hit here skips the server round-trip entirely.
        if let localHit = checkProtectionDatabase(url) {
            return localHit
        }

        // Step 1
        let serverResult: CheckResult
        if IS_LOCAL {
            serverResult = checkLocalLists(url)
        } else {
            serverResult = useQrEndpoint
                ? await ApiClient.checkQrUrl(url)
                : await ApiClient.checkUrl(url)
        }

        // Step 2: lexical analysis for Unknown links
        guard case .unknown = serverResult else {
            return serverResult
        }

        let lexical = LexicalAnalyzer.analyze(url)

        if lexical.isObviouslyMalicious {
            // Unambiguous signal — block immediately, no ML server call needed.
            return .malicious(
                explanation: lexical.flags.prefix(3).joined(separator: "\n"),
                source: "Lexical Analysis",
                confidence: 95,
                matchType: "lexical"
            )
        } else {
            // Step 3: forward the URL and lexical feature vector to the ML model.
            return await ApiClient.scoreLexical(url, features: lexical.features)
        }
    }

    /// Checks the downloaded malicious-domain database (if one has been
    /// activated). Returns nil when the URL's domain is not listed or no
    /// database exists yet.
    static func checkProtectionDatabase(_ url: String) -> CheckResult? {
        guard let host = DomainNormalizer.normalizeHost(from: url),
              let dbURL = SharedStore.databaseURL,
              SharedStore.databaseExists else { return nil }
        let db = ProtectionDatabase(url: dbURL)
        defer { db.close() }
        guard let match = db.match(normalizedHost: host) else { return nil }
        return .malicious(
            explanation: "The domain \(match.matchedDomain) is listed as \(match.threatType) in the \(match.source) threat feed (on-device protection database).",
            source: match.source,
            confidence: 100,
            matchType: "local_db"
        )
    }

    /// Used in dev/local mode instead of hitting the Flask server.
    static func checkLocalLists(_ url: String) -> CheckResult {
        switch LocalUrlLists.check(url) {
        case .whitelisted(let domain, _):
            _ = domain
            return .whitelisted(description: "Local whitelist match", category: "local_whitelist")
        case .blacklisted(let domain, let explanation):
            return .malicious(
                explanation: explanation,
                source: "Local blacklist: \(domain)",
                confidence: 100,
                matchType: "local_domain"
            )
        case .unknown:
            return .unknown(explanation: "No match in local whitelist or blacklist.")
        }
    }

    /// Builds a ScannedLink history entry from a result (mirrors saveToLocalDb).
    static func makeHistoryEntry(url: String, result: CheckResult) -> ScannedLink {
        let isSuspicious: Bool
        let riskScore: Int
        let threatType: String?

        switch result {
        case .whitelisted:
            isSuspicious = false; riskScore = 0; threatType = nil
        case .malicious(_, let source, let confidence, _):
            isSuspicious = true; riskScore = confidence; threatType = source
        case .unknown:
            isSuspicious = false; riskScore = 50; threatType = nil
        case .error:
            isSuspicious = false; riskScore = 50; threatType = nil
        }

        return ScannedLink(url: url, isSuspicious: isSuspicious, riskScore: riskScore, threatType: threatType)
    }

    // MARK: URL extraction (port of extractUrlFromText)

    static func extractUrlFromText(_ text: String) -> String? {
        if text.hasPrefix("http://") || text.hasPrefix("https://") {
            return text.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let pattern = #"https?://\S+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/\S*)?"#
        guard let range = text.range(of: pattern, options: .regularExpression) else { return nil }
        var raw = String(text[range])
        while let last = raw.last, ".,;)]}".contains(last) { raw.removeLast() }
        if raw.hasPrefix("http://") || raw.hasPrefix("https://") {
            return raw
        }
        return "https://\(raw)"
    }
}
