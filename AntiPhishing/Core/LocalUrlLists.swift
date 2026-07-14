//
//  LocalUrlLists.swift
//  AntiPhishing
//
//  1:1 port of the Kotlin LocalUrlLists object.
//  Local whitelist / blacklist used in IS_LOCAL development mode
//  instead of hitting the Flask server.
//

import Foundation

enum LocalUrlResult {
    case whitelisted(domain: String, description: String)
    case blacklisted(domain: String, explanation: String)
    case unknown
}

enum LocalUrlLists {

    private static let whitelistDomains: Set<String> = [
        "google.com",
        "facebook.com",
        "youtube.com",
        "gmail.com",
        "wikipedia.org",
        "github.com"
    ]

    private static let blacklistDomains: Set<String> = [
        "bad.test",
        "safe-test-phishing.local",
        "fake-login-test.com",
        "malicious-demo.invalid",
        "bank-security-check.example",
        "verify-account-now.test",
        "phishing-simulation-only.invalid"
    ]

    static func check(_ url: String) -> LocalUrlResult {
        let host = extractHost(url)

        if let matchedWhitelist = whitelistDomains.first(where: { host.matchesDomain($0) }) {
            return .whitelisted(domain: matchedWhitelist, description: "Local whitelist match")
        }

        if let matchedBlacklist = blacklistDomains.first(where: { host.matchesDomain($0) }) {
            return .blacklisted(
                domain: matchedBlacklist,
                explanation: "Local blacklist match. This is a safe test domain for checking the warning screen."
            )
        }

        return .unknown
    }

    private static func extractHost(_ url: String) -> String {
        let normalizedUrl = url.contains("://") ? url : "https://\(url)"
        guard let host = URLComponents(string: normalizedUrl)?.host else { return "" }
        var h = host.lowercased()
        if h.hasPrefix("www.") { h.removeFirst(4) }
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }
}

private extension String {
    func matchesDomain(_ domain: String) -> Bool {
        self == domain || hasSuffix(".\(domain)")
    }
}
