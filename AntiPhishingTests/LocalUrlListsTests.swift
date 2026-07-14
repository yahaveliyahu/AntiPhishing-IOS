//
//  LocalUrlListsTests.swift
//  AntiPhishingTests
//
//  Verifies the offline whitelist/blacklist matching (used when IS_LOCAL).
//

import Testing
@testable import AntiPhishing

@MainActor
struct LocalUrlListsTests {

    @Test("Whitelisted domain is recognised")
    func whitelistMatch() {
        if case .whitelisted(let domain, _) = LocalUrlLists.check("https://www.google.com/search?q=x") {
            #expect(domain == "google.com")
        } else {
            Issue.record("Expected google.com to be whitelisted")
        }
    }

    @Test("Subdomain of a whitelisted domain still matches")
    func whitelistSubdomain() {
        if case .whitelisted = LocalUrlLists.check("https://mail.google.com") {
            // ok
        } else {
            Issue.record("Expected mail.google.com to match the google.com whitelist")
        }
    }

    @Test("Blacklisted domain is recognised")
    func blacklistMatch() {
        if case .blacklisted(let domain, _) = LocalUrlLists.check("http://bad.test/login") {
            #expect(domain == "bad.test")
        } else {
            Issue.record("Expected bad.test to be blacklisted")
        }
    }

    @Test("Unknown domain returns .unknown")
    func unknownDomain() {
        if case .unknown = LocalUrlLists.check("https://totally-unknown-domain-9j2k.com") {
            // ok
        } else {
            Issue.record("Expected an unlisted domain to be unknown")
        }
    }

    @Test("Bare domain (no scheme) is normalised and matched")
    func bareDomainNormalised() {
        if case .whitelisted = LocalUrlLists.check("github.com/apple") {
            // ok
        } else {
            Issue.record("Expected a scheme-less github.com to be whitelisted")
        }
    }
}
