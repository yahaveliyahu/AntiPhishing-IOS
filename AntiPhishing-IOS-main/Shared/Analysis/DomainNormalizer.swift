//
//  DomainNormalizer.swift
//  AntiPhishing (Shared)
//
//  One normalization used EVERYWHERE a domain is stored, compared, cached,
//  blocked or allowlisted — by the database builder in the app, the manual
//  check pipeline, and the Safari extension's native handler.
//
//  The rules intentionally mirror the server's extract_domain() in
//  seed_db.py / lookup.py (hostname → lowercase → strip leading "www."), so a
//  domain normalized on-device matches the same feed entry the server stores.
//  On top of that we add the pieces a browser context needs: scheme/port/path
//  stripping, trailing dots, IPv6 brackets, and IDN → punycode so a Unicode
//  hostname compares equal to the ASCII (ACE) form used by threat feeds.
//
//  The extension's JavaScript uses `new URL(...)` for the same job — WebKit
//  already lowercases and punycode-encodes `url.hostname`, so both sides
//  produce identical strings. Keep this file and background.js in sync if the
//  rules ever change.
//

import Foundation

nonisolated enum DomainNormalizer {

    /// Normalizes a URL string or bare hostname into the canonical lookup key.
    /// Returns nil for input that has no usable host (invalid URLs, empty
    /// strings, unsupported schemes like javascript:).
    ///
    /// "HTTPS://WWW.ExAmple.com:8443/a?b=1" → "example.com"
    /// "münchen.de."                        → "xn--mnchen-3ya.de"
    /// "http://192.168.7.1/login"           → "192.168.7.1"
    static func normalizeHost(from input: String) -> String? {
        var raw = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return nil }

        // Explicitly reject non-web schemes; they have no host to check.
        let lowered = raw.lowercased()
        for scheme in ["javascript:", "data:", "mailto:", "tel:", "about:", "file:"] {
            if lowered.hasPrefix(scheme) { return nil }
        }

        // Ensure something URL-shaped so host extraction is uniform.
        if !raw.contains("://") { raw = "http://" + raw }

        guard var host = extractRawHost(from: raw) else { return nil }

        // Trailing dots ("example.com.") are equivalent in DNS.
        while host.hasSuffix(".") { host.removeLast() }
        guard !host.isEmpty else { return nil }

        // IPv6 literal — keep the bare address, no www/punycode handling.
        if host.hasPrefix("[") && host.hasSuffix("]") {
            return String(host.dropFirst().dropLast()).lowercased()
        }

        // IDN labels → punycode (ACE) so Unicode spoofs compare against the
        // ASCII form stored in the feeds. ASCII labels are just lowercased.
        let labels = host.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        var aceLabels: [String] = []
        for label in labels {
            if label.isEmpty { return nil } // "a..b" is not a valid host
            if label.allSatisfy({ $0.isASCII }) {
                aceLabels.append(String(label))
            } else if let encoded = Punycode.encodeLabel(String(label)) {
                aceLabels.append("xn--" + encoded)
            } else {
                return nil
            }
        }
        var normalized = aceLabels.joined(separator: ".")

        // The server strips a leading "www." when it seeds domains, so we
        // must do the same for lookups (see seed_db.extract_domain).
        if normalized.hasPrefix("www.") && normalized.count > 4 {
            normalized = String(normalized.dropFirst(4))
        }

        guard isPlausibleHost(normalized) else { return nil }
        return normalized
    }

    /// The chain of domains to test against the database for one host,
    /// most-specific first: "a.b.example.com" → ["a.b.example.com",
    /// "b.example.com", "example.com"]. Feeds list both exact phishing hosts
    /// and abused parent domains, so a hit on any suffix blocks the page.
    /// The bare TLD is never tested, and IP addresses only match exactly.
    static func lookupCandidates(for host: String) -> [String] {
        if isIPAddress(host) { return [host] }
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return [host] }
        var candidates: [String] = []
        for start in 0...(labels.count - 2) {
            candidates.append(labels[start...].joined(separator: "."))
        }
        return candidates
    }

    static func isIPAddress(_ host: String) -> Bool {
        // IPv6 (has colons) or dotted-quad IPv4.
        if host.contains(":") { return true }
        let parts = host.split(separator: ".")
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let n = UInt8(part) else { return false }
            return String(n) == part // rejects leading zeros like "01"
        }
    }

    // MARK: - Internals

    /// Extracts the raw host from a URL-shaped string. Tries Foundation first
    /// and falls back to manual parsing for inputs Foundation rejects
    /// (e.g. raw Unicode hosts on some OS versions).
    private static func extractRawHost(from urlString: String) -> String? {
        if let components = URLComponents(string: urlString), let host = components.host, !host.isEmpty {
            return host
        }

        // Manual fallback: scheme://[userinfo@]host[:port][/path...]
        guard let schemeRange = urlString.range(of: "://") else { return nil }
        var rest = String(urlString[schemeRange.upperBound...])
        if let end = rest.firstIndex(where: { "/?#".contains($0) }) {
            rest = String(rest[..<end])
        }
        // Strip userinfo (also covers the "@" phishing trick — the real host
        // is what follows the last "@").
        if let at = rest.lastIndex(of: "@") {
            rest = String(rest[rest.index(after: at)...])
        }
        // Strip port, careful with IPv6 "[::1]:8080".
        if rest.hasPrefix("[") {
            if let close = rest.firstIndex(of: "]") {
                rest = String(rest[...close])
            }
        } else if let colon = rest.lastIndex(of: ":") {
            rest = String(rest[..<colon])
        }
        return rest.isEmpty ? nil : rest
    }

    private static func isPlausibleHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 253 else { return false }
        if host.contains(":") { return true } // IPv6, already unbracketed
        // Letters, digits, hyphens and dots only after punycode conversion.
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-._")
        return host.unicodeScalars.allSatisfy { allowed.contains($0) }
    }
}

// MARK: - Punycode (RFC 3492, encode-only)

/// Minimal punycode encoder used to convert internationalized labels to their
/// ASCII (ACE) form. Only encoding is needed: the database itself contains
/// ASCII, we just need Unicode input to map onto it deterministically.
nonisolated enum Punycode {

    private static let base = 36, tmin = 1, tmax = 26
    private static let skew = 38, damp = 700
    private static let initialBias = 72, initialN = 128

    /// Encodes one already-lowercased Unicode label (without the "xn--"
    /// prefix). Returns nil on overflow / invalid input.
    static func encodeLabel(_ label: String) -> String? {
        let input = Array(label.unicodeScalars).map { Int($0.value) }
        var output = input.filter { $0 < 128 }.map { Character(UnicodeScalar($0)!) }

        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }

        var n = initialN
        var delta = 0
        var bias = initialBias

        while handled < input.count {
            guard let m = input.filter({ $0 >= n }).min() else { return nil }
            let increment = (m - n) * (handled + 1)
            guard delta <= Int.max - increment else { return nil }
            delta += increment
            n = m

            for c in input {
                if c < n {
                    delta += 1
                    if delta == Int.max { return nil }
                }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta: delta, numPoints: handled + 1, firstTime: handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return String(output)
    }

    private static func adapt(delta: Int, numPoints: Int, firstTime: Bool) -> Int {
        var delta = firstTime ? delta / damp : delta / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= base - tmin
            k += base
        }
        return k + ((base - tmin + 1) * delta) / (delta + skew)
    }

    private static func digit(_ d: Int) -> Character {
        d < 26 ? Character(UnicodeScalar(UInt8(97 + d))) // a-z
               : Character(UnicodeScalar(UInt8(48 + d - 26))) // 0-9
    }
}
