//
//  CheckPipelineTests.swift
//  AntiPhishingTests
//
//  Verifies the pieces of the shared pipeline that are deterministic and
//  offline: local-list classification, the lexical "obvious killer" decision,
//  history-entry mapping, and URL extraction from free text.
//

import Testing
@testable import AntiPhishing

@MainActor
struct CheckPipelineTests {

    // MARK: checkLocalLists

    @Test("Local check classifies a whitelisted URL as whitelisted")
    func localWhitelist() {
        if case .whitelisted = CheckPipeline.checkLocalLists("https://www.google.com") {
            // ok
        } else {
            Issue.record("Expected whitelisted result")
        }
    }

    @Test("Local check classifies a blacklisted URL as malicious")
    func localBlacklist() {
        if case .malicious(_, let source, let confidence, _) = CheckPipeline.checkLocalLists("http://bad.test") {
            #expect(confidence == 100)
            #expect(source?.contains("bad.test") == true)
        } else {
            Issue.record("Expected malicious result")
        }
    }

    @Test("Local check classifies an unlisted URL as unknown")
    func localUnknown() {
        if case .unknown = CheckPipeline.checkLocalLists("https://totally-unknown-domain-9j2k.com") {
            // ok
        } else {
            Issue.record("Expected unknown result")
        }
    }

    // MARK: Lexical decision used by step 2 of the pipeline

    @Test("An obviously-malicious unknown URL becomes malicious after lexical analysis")
    func lexicalEscalatesToMalicious() {
        let lexical = LexicalAnalyzer.analyze("http://user:pass@evil.com/account")
        #expect(lexical.isObviouslyMalicious == true)
    }

    // MARK: makeHistoryEntry mapping (mirrors Android saveToLocalDb)

    @Test("Malicious result maps to a suspicious history entry with its confidence")
    func historyMalicious() {
        let entry = CheckPipeline.makeHistoryEntry(
            url: "http://evil.com",
            result: .malicious(explanation: "x", source: "PhishTank", confidence: 95, matchType: "url")
        )
        #expect(entry.isSuspicious == true)
        #expect(entry.riskScore == 95)
        #expect(entry.threatType == "PhishTank")
    }

    @Test("Whitelisted result maps to a safe, zero-risk entry")
    func historyWhitelisted() {
        let entry = CheckPipeline.makeHistoryEntry(
            url: "https://google.com",
            result: .whitelisted(description: "Google", category: "search")
        )
        #expect(entry.isSuspicious == false)
        #expect(entry.riskScore == 0)
    }

    @Test("Unknown and error results map to risk score 50")
    func historyUnknownAndError() {
        let unknown = CheckPipeline.makeHistoryEntry(url: "u", result: .unknown(explanation: "x"))
        let error = CheckPipeline.makeHistoryEntry(url: "e", result: .error(message: "x"))
        #expect(unknown.riskScore == 50 && unknown.isSuspicious == false)
        #expect(error.riskScore == 50 && error.isSuspicious == false)
    }

    // MARK: extractUrlFromText (mirrors Android extractUrlFromText)

    @Test("A full https URL is returned unchanged")
    func extractFullUrl() {
        #expect(CheckPipeline.extractUrlFromText("https://example.com/path") == "https://example.com/path")
    }

    @Test("A URL embedded in text is extracted")
    func extractFromText() {
        #expect(CheckPipeline.extractUrlFromText("Click here: https://example.com/win now!") == "https://example.com/win")
    }

    @Test("A bare domain gets an https:// prefix")
    func extractBareDomain() {
        #expect(CheckPipeline.extractUrlFromText("go to example.com today") == "https://example.com")
    }

    @Test("Trailing punctuation is trimmed")
    func extractTrimsPunctuation() {
        #expect(CheckPipeline.extractUrlFromText("see https://example.com/page.") == "https://example.com/page")
    }

    @Test("Text without a link returns nil")
    func extractNoLink() {
        #expect(CheckPipeline.extractUrlFromText("there is no link in this sentence") == nil)
    }
}
