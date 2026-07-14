//
//  DomainNormalizerTests.swift
//  AntiPhishingTests
//
//  The normalizer is the contract between the app, the Safari extension and
//  the feed-built database — every storage/lookup/allowlist path depends on
//  these rules being stable.
//

import Testing
@testable import AntiPhishing

@MainActor
struct DomainNormalizerTests {

    @Test("Scheme, case, port, path and query are stripped")
    func fullURLNormalization() {
        #expect(DomainNormalizer.normalizeHost(from: "HTTPS://WWW.ExAmple.com:8443/a/b?c=1#f") == "example.com")
    }

    @Test("Bare hostname works without a scheme")
    func bareHost() {
        #expect(DomainNormalizer.normalizeHost(from: "  Example.COM  ") == "example.com")
    }

    @Test("Leading www. is stripped (matches the server's extract_domain)")
    func wwwStripping() {
        #expect(DomainNormalizer.normalizeHost(from: "http://www.evil.test/login") == "evil.test")
        // "www" alone is not stripped into emptiness
        #expect(DomainNormalizer.normalizeHost(from: "http://www.com") == "com")
    }

    @Test("Trailing dots are removed")
    func trailingDots() {
        #expect(DomainNormalizer.normalizeHost(from: "example.com.") == "example.com")
    }

    @Test("Unicode hosts become punycode (ACE) form")
    func punycode() {
        #expect(DomainNormalizer.normalizeHost(from: "https://münchen.de/x") == "xn--mnchen-3ya.de")
        #expect(DomainNormalizer.normalizeHost(from: "пример.рф") == "xn--e1afmkfd.xn--p1ai")
    }

    @Test("IPv4 hosts are kept as-is")
    func ipv4Host() {
        #expect(DomainNormalizer.normalizeHost(from: "http://192.168.7.1/login") == "192.168.7.1")
        #expect(DomainNormalizer.isIPAddress("192.168.7.1"))
        #expect(!DomainNormalizer.isIPAddress("192.168.7.com"))
    }

    @Test("Userinfo @-trick resolves to the real host")
    func userinfoTrick() {
        #expect(DomainNormalizer.normalizeHost(from: "http://paypal.com@evil.test/login") == "evil.test")
    }

    @Test("Non-web schemes and garbage return nil")
    func invalidInput() {
        #expect(DomainNormalizer.normalizeHost(from: "javascript:alert(1)") == nil)
        #expect(DomainNormalizer.normalizeHost(from: "") == nil)
        #expect(DomainNormalizer.normalizeHost(from: "   ") == nil)
        #expect(DomainNormalizer.normalizeHost(from: "http://a..b") == nil)
    }

    @Test("Lookup candidates walk parents but never the bare TLD")
    func lookupCandidates() {
        #expect(DomainNormalizer.lookupCandidates(for: "a.b.example.com")
                == ["a.b.example.com", "b.example.com", "example.com"])
        #expect(DomainNormalizer.lookupCandidates(for: "example.com") == ["example.com"])
        // IPs only ever match exactly.
        #expect(DomainNormalizer.lookupCandidates(for: "192.168.7.1") == ["192.168.7.1"])
    }
}

@MainActor
struct ThreatFeedParsingTests {

    private let plainFeed = ThreatFeed.all.first { $0.format == .plainDomains }!
    private let hostsFeed = ThreatFeed.all.first { $0.format == .hostsFile }!
    private let urlFeed = ThreatFeed.all.first { $0.format == .plainURLs }!
    private let csvFeed = ThreatFeed.all.first { $0.format == .csvFirstColumnDomain }!

    @Test("Plain-domain lines parse; comments are skipped")
    func plainDomains() {
        #expect(plainFeed.domainCandidate(fromLine: "evil.test", isFirstLine: false) == "evil.test")
        #expect(plainFeed.domainCandidate(fromLine: "# comment", isFirstLine: false) == nil)
        #expect(plainFeed.domainCandidate(fromLine: "0.0.0.0 evil.test", isFirstLine: false) == "evil.test")
    }

    @Test("Hosts-file lines yield the mapped domain")
    func hostsFile() {
        #expect(hostsFeed.domainCandidate(fromLine: "0.0.0.0\tbad.example", isFirstLine: false) == "bad.example")
        #expect(hostsFeed.domainCandidate(fromLine: "just-one-column", isFirstLine: false) == nil)
    }

    @Test("URL lines pass through for host extraction")
    func urlLines() {
        let candidate = urlFeed.domainCandidate(fromLine: "https://phish.example/login?x=1", isFirstLine: false)
        #expect(candidate != nil)
        #expect(DomainNormalizer.normalizeHost(from: candidate!) == "phish.example")
    }

    @Test("CSV first column parses; header row is skipped")
    func csvLines() {
        #expect(csvFeed.domainCandidate(fromLine: "domain,ip,url", isFirstLine: true) == nil)
        #expect(csvFeed.domainCandidate(fromLine: "\"c2.example\",1.2.3.4", isFirstLine: false) == "c2.example")
    }
}
