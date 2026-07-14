//
//  ApiClient.swift
//  AntiPhishing
//
//  Port of the Kotlin ApiClient. Handles HTTP communication with the Flask
//  backend. Only used when IS_LOCAL == false.
//
//  Endpoints:
//    POST /api/check      → Check a URL from link interception
//    POST /api/qr/check   → Check a URL decoded from a QR code
//    POST /api/qr/report  → Save a QR scan result
//    POST /api/score      → ML scoring from lexical feature vector (Step 3)
//    GET  /api/stats      → DB counters (used as the protection-database
//                           update-check signal; the server has no bulk
//                           download or version endpoint)
//
//  Compiled into BOTH the app target and the AntiPhishingWebExtension target
//  (lives in Shared) — the extension calls scoreLexical with a short timeout
//  when its local database has no match for a page Safari is loading.
//

import Foundation

/// Response of GET /api/stats — the server's database counters.
/// `maliciousDomains` doubles as the freshness signal for the local
/// protection database: when it differs from the snapshot stored at the last
/// sync, the server's threat data has changed since we last downloaded.
struct ServerStats: Equatable, Sendable {
    let maliciousUrls: Int
    let maliciousDomains: Int
    let whitelistedDomains: Int
    let cachedChecks: Int
}

enum ApiClient {

    // Live Flask backend (same server the Android app uses).
    // For a local Flask server use e.g. "http://10.100.102.6:5000" — but note
    // iOS App Transport Security blocks plain http:// unless you add an ATS
    // exception, so prefer the https:// production URL.
    private static let baseURL = "https://antiphishing-backend.onrender.com"

    // Long timeout on purpose: Render's free tier sleeps after ~15 min idle and
    // takes ~50s to wake on the first request — mirrors the Android client's
    // 60s read timeout so cold starts don't spuriously fail. Callers gating a
    // page load in real time (the Safari extension) pass a much shorter
    // timeout instead — see scoreLexical.
    private static let defaultTimeout: TimeInterval = 60

    // MARK: Public API

    static func checkUrl(_ url: String) async -> CheckResult {
        await post(path: "/api/check", body: ["url": url], serverLabel: "server")
    }

    static func checkQrUrl(_ url: String) async -> CheckResult {
        await post(path: "/api/qr/check", body: ["url": url], serverLabel: "server")
    }

    /// Fire-and-forget QR report.
    static func reportQrScan(url: String, result: CheckResult) async {
        var confidence = 0
        var source = ""
        var matchType = "error"
        var isMalicious = false

        switch result {
        case .malicious(_, let s, let c, let m):
            isMalicious = true; confidence = c; source = s ?? ""; matchType = m
        case .whitelisted:
            confidence = 100; matchType = "whitelist"
        case .unknown:
            matchType = "unknown"
        case .error:
            matchType = "error"
        }

        let body: [String: Any] = [
            "url": url,
            "is_malicious": isMalicious,
            "confidence": confidence,
            "source": source,
            "match_type": matchType
        ]
        _ = await rawPost(path: "/api/qr/report", body: body)
    }

    /// GET /api/stats. Returns nil when the server is unreachable — callers
    /// treat that as "offline" and keep using local data. The short timeout is
    /// deliberate: this runs at launch and must not hang the UI on Render
    /// cold starts (a manual update retries with the same call anyway).
    static func fetchStats(timeout: TimeInterval = 20) async -> ServerStats? {
        guard let url = URL(string: baseURL + "/api/stats") else { return nil }
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return ServerStats(
            maliciousUrls: obj["malicious_urls"] as? Int ?? 0,
            maliciousDomains: obj["malicious_domains"] as? Int ?? 0,
            whitelistedDomains: obj["whitelisted_domains"] as? Int ?? 0,
            cachedChecks: obj["cached_checks"] as? Int ?? 0
        )
    }

    /// Step 3 — send the URL and its lexical feature vector to the ML model.
    /// `timeout` defaults to the generous 60s used by the app's own check
    /// flow; the Safari extension passes a short timeout instead since this
    /// call gates a live page load.
    static func scoreLexical(_ url: String, features: [String: Double], timeout: TimeInterval = defaultTimeout) async -> CheckResult {
        let body: [String: Any] = ["url": url, "features": features]
        return await post(path: "/api/score", body: body, serverLabel: "ML server", timeout: timeout)
    }

    // MARK: Helpers

    private static func post(path: String, body: [String: Any], serverLabel: String, timeout: TimeInterval = defaultTimeout) async -> CheckResult {
        guard let (data, code) = await rawPost(path: path, body: body, timeout: timeout) else {
            return .error(message: "Could not reach \(serverLabel)")
        }
        guard code == 200 else {
            return .error(message: "\(serverLabel) returned HTTP \(code)")
        }
        return parseResponse(data)
    }

    private static func rawPost(path: String, body: [String: Any], timeout: TimeInterval = defaultTimeout) async -> (Data, Int)? {
        guard let url = URL(string: baseURL + path) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            return (data, code)
        } catch {
            return nil
        }
    }

    private static func parseResponse(_ data: Data) -> CheckResult {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .error(message: "Invalid server response")
        }
        let isMalicious = obj["is_malicious"] as? Bool ?? false
        let confidence = obj["confidence"] as? Int ?? 0
        let matchType = obj["match_type"] as? String ?? ""
        let sourceRaw = obj["source"] as? String
        let source = (sourceRaw?.isEmpty == false && sourceRaw != "null") ? sourceRaw : nil
        let explanation = obj["explanation"] as? String ?? ""
        let category = obj["category"] as? String ?? ""
        let description = obj["description"] as? String ?? ""

        if matchType == "whitelist" {
            return .whitelisted(description: description, category: category)
        } else if isMalicious {
            return .malicious(explanation: explanation, source: source, confidence: confidence, matchType: matchType)
        } else {
            return .unknown(explanation: explanation)
        }
    }
}
