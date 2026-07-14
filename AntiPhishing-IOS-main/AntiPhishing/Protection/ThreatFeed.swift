//
//  ThreatFeed.swift
//  AntiPhishing
//
//  The protection database is the client-side mirror of the server's MongoDB
//  `malicious_domains` collection. The server has no bulk-download endpoint —
//  its collection is seeded from public threat feeds (see FEEDS in the
//  server's scripts/seed_db.py, re-run every 12h by scheduler.py) — so the
//  app downloads the same feeds the server seeds from and applies the same
//  parsing rules. GET /api/stats supplies the server-side counters used to
//  detect that the server's data moved on since our last sync.
//
//  Feed list = the `enabled: True` server feeds, minus three that can't be
//  used on-device:
//    • PhishTank JSON mirror  — 30–60MB JSON blob; its URLs are already
//      folded into Phishing Army / Phishing.Database, which we do download.
//    • URLhaus URL text feed  — URL-level; the URLhaus hostfile below is the
//      domain-level view of the same data.
//    • AlienVault OTX         — requires a private API key the client
//      doesn't have (server-side env var).
//

import Foundation

nonisolated struct ThreatFeed: Sendable {

    /// Line format, mirroring the matching parser in the server's seed_db.py.
    enum Format: Sendable {
        /// One domain per line; tolerates hosts-style "0.0.0.0 domain" rows
        /// (server: parse_plain_domains).
        case plainDomains
        /// Hosts file "0.0.0.0 domain" rows (server: parse_hosts_file).
        case hostsFile
        /// One URL per line; the domain is extracted (server: parse_plain_urls).
        case plainURLs
        /// CSV with the domain in the first column, header row skipped
        /// (server: parse_c2intel_domains).
        case csvFirstColumnDomain
    }

    let name: String
    let url: URL
    let format: Format
    /// Threat category stored per domain ("blacklist" / "threat_intel"),
    /// same values the server stores — shown on the warning page.
    let threatType: String

    /// Same set of feeds the server enables in seed_db.py (see header note).
    static let all: [ThreatFeed] = [
        ThreatFeed(name: "Phishing_Army",
                   url: URL(string: "https://phishing.army/download/phishing_army_blocklist_extended.txt")!,
                   format: .plainDomains, threatType: "blacklist"),
        ThreatFeed(name: "Phishing_Database",
                   url: URL(string: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt")!,
                   format: .plainDomains, threatType: "blacklist"),
        ThreatFeed(name: "URLhaus_Domains",
                   url: URL(string: "https://urlhaus.abuse.ch/downloads/hostfile/")!,
                   format: .hostsFile, threatType: "blacklist"),
        ThreatFeed(name: "OpenPhish",
                   url: URL(string: "https://openphish.com/feed.txt")!,
                   format: .plainURLs, threatType: "blacklist"),
        ThreatFeed(name: "DisconnectMe_Malware",
                   url: URL(string: "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt")!,
                   format: .plainDomains, threatType: "threat_intel"),
        ThreatFeed(name: "Ultimate_Hosts_Blacklist",
                   url: URL(string: "https://raw.githubusercontent.com/mitchellkrogza/Ultimate.Hosts.Blacklist/master/hosts/hosts0")!,
                   format: .hostsFile, threatType: "threat_intel"),
        ThreatFeed(name: "C2IntelFeeds_Domains",
                   url: URL(string: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv")!,
                   format: .csvFirstColumnDomain, threatType: "threat_intel"),
        ThreatFeed(name: "Botvrij_URLs",
                   url: URL(string: "https://www.botvrij.eu/data/ioclist.url.raw")!,
                   format: .plainURLs, threatType: "threat_intel"),
    ]

    /// Values the server's parsers explicitly refuse to store as domains.
    static let excludedHosts: Set<String> = [
        "localhost", "local", "broadcasthost", "0.0.0.0", "127.0.0.1",
    ]

    /// Extracts the domain candidate from one raw feed line, or nil for
    /// comments/garbage. The caller runs the result through DomainNormalizer
    /// (the equivalent of the server's extract_domain) and the exclusion set.
    func domainCandidate(fromLine rawLine: String, isFirstLine: Bool) -> String? {
        var line = rawLine.trimmingCharacters(in: .whitespaces)
        guard !line.isEmpty else { return nil }

        switch format {
        case .plainDomains:
            let lowered = line.lowercased()
            if lowered.hasPrefix("#") || lowered.hasPrefix(";") || lowered.hasPrefix("//") { return nil }
            let parts = lowered.split(separator: " ").map(String.init)
            // Hosts-style row inside a plain list: take the mapped domain.
            if parts.count >= 2 {
                guard parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" else { return nil }
                return parts[1]
            }
            return parts.first

        case .hostsFile:
            if line.hasPrefix("#") { return nil }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard parts.count >= 2 else { return nil }
            return String(parts[1]).lowercased()

        case .plainURLs:
            if line.hasPrefix("#") || line.hasPrefix(";") { return nil }
            return line // full URL — normalizer extracts the host

        case .csvFirstColumnDomain:
            if isFirstLine { return nil } // header row
            if line.hasPrefix("#") { return nil }
            guard let first = line.split(separator: ",").first else { return nil }
            line = first.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            return line.isEmpty ? nil : line.lowercased()
        }
    }
}
