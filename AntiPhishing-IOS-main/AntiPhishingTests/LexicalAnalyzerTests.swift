//
//  LexicalAnalyzerTests.swift
//  AntiPhishingTests
//
//  Verifies the on-device URL risk engine behaves like the Android
//  LexicalAnalyzer.kt: "obvious killer" signals block immediately, benign
//  URLs stay clean, and the numeric feature vector matches expectations.
//

import Testing
@testable import AntiPhishing

@MainActor
struct LexicalAnalyzerTests {

    // MARK: Obvious killers — must be flagged isObviouslyMalicious

    @Test("@ symbol in URL is an obvious killer")
    func atSymbolIsKiller() {
        let r = LexicalAnalyzer.analyze("http://evil.com/@real-bank.com/login")
        #expect(r.isObviouslyMalicious == true)
        #expect(r.features["has_at_symbol"] == 1)
    }

    @Test("javascript: scheme is an obvious killer")
    func javascriptSchemeIsKiller() {
        let r = LexicalAnalyzer.analyze("javascript:alert(document.cookie)")
        #expect(r.isObviouslyMalicious == true)
    }

    @Test("data: scheme is an obvious killer")
    func dataSchemeIsKiller() {
        let r = LexicalAnalyzer.analyze("data:text/html;base64,PHNjcmlwdD4=")
        #expect(r.isObviouslyMalicious == true)
    }

    @Test("Null byte is an obvious killer")
    func nullByteIsKiller() {
        let r = LexicalAnalyzer.analyze("http://evil.com/login%00.php")
        #expect(r.isObviouslyMalicious == true)
        #expect(r.features["has_null_byte"] == 1)
    }

    @Test("Double file extension is an obvious killer")
    func doubleExtensionIsKiller() {
        let r = LexicalAnalyzer.analyze("http://files.example.com/invoice.pdf.exe")
        #expect(r.isObviouslyMalicious == true)
        #expect(r.features["has_double_extension"] == 1)
    }

    @Test("Double URL encoding is an obvious killer")
    func doubleEncodingIsKiller() {
        let r = LexicalAnalyzer.analyze("http://evil.com/%252e%252e/secret")
        #expect(r.isObviouslyMalicious == true)
        #expect(r.features["has_double_encoding"] == 1)
    }

    @Test("Credentials pattern user:pass@host is an obvious killer")
    func credentialsPatternIsKiller() {
        let r = LexicalAnalyzer.analyze("http://user:password@evil.com/account")
        #expect(r.isObviouslyMalicious == true)
        #expect(r.features["has_credentials_pattern"] == 1)
    }

    @Test("Hidden zero-width Unicode is an obvious killer")
    func hiddenUnicodeIsKiller() {
        // Zero-width space (U+200B) hidden inside the host.
        let r = LexicalAnalyzer.analyze("http://goog\u{200B}le.com/login")
        #expect(r.isObviouslyMalicious == true)
        #expect((r.features["hidden_char_count"] ?? 0) >= 1)
    }

    // MARK: Benign URLs — must NOT be flagged

    @Test("Plain https site is not obviously malicious", arguments: [
        "https://www.google.com",
        "https://github.com/apple/swift",
        "https://en.wikipedia.org/wiki/Phishing"
    ])
    func benignUrlsAreClean(_ url: String) {
        let r = LexicalAnalyzer.analyze(url)
        #expect(r.isObviouslyMalicious == false)
    }

    @Test("HTTPS sets the is_https feature")
    func httpsFeature() {
        #expect(LexicalAnalyzer.analyze("https://www.google.com").features["is_https"] == 1)
        #expect(LexicalAnalyzer.analyze("http://www.google.com").features["is_https"] == 0)
    }

    // MARK: Feature-vector spot checks (parity with Android)

    @Test("Raw IP address is detected")
    func ipAddressFeature() {
        let r = LexicalAnalyzer.analyze("http://192.168.10.5/login")
        #expect(r.features["is_ip_address"] == 1)
    }

    @Test("Subdomain count is computed")
    func subdomainCount() {
        let r = LexicalAnalyzer.analyze("https://a.b.c.example.com")
        // a.b.c = 3 subdomains over registrable example.com
        #expect(r.features["subdomain_count"] == 3)
    }

    @Test("URL shortener is detected")
    func shortenerFeature() {
        #expect(LexicalAnalyzer.analyze("http://bit.ly/3xyzAbc").features["is_shortener"] == 1)
        #expect(LexicalAnalyzer.analyze("https://www.google.com").features["is_shortener"] == 0)
    }

    @Test("Punycode/IDN domain is detected")
    func punycodeFeature() {
        #expect(LexicalAnalyzer.analyze("https://xn--pypal-4ve.com").features["is_punycode"] == 1)
    }

    @Test("Suspicious TLD is detected")
    func suspiciousTldFeature() {
        #expect(LexicalAnalyzer.analyze("http://free-prize.tk/claim").features["is_suspicious_tld"] == 1)
    }

    @Test("Typosquatting via digit substitution is detected (paypa1 -> paypal)")
    func visualSpoofFeature() {
        #expect(LexicalAnalyzer.analyze("http://paypa1.com/login").features["visual_spoof_detected"] == 1)
    }

    @Test("Brand only in subdomain is detected")
    func brandInSubdomainFeature() {
        let r = LexicalAnalyzer.analyze("http://paypal.login.secure.evil.com/verify")
        #expect(r.features["brand_in_subdomain"] == 1)
    }

    @Test("url_length feature matches the input length")
    func urlLengthFeature() {
        let url = "https://www.example.com/path"
        #expect(LexicalAnalyzer.analyze(url).features["url_length"] == Double(url.count))
    }

    @Test("Risk score is clamped to 0...100")
    func riskScoreClamped() {
        // A deliberately nasty URL piling on many penalties.
        let r = LexicalAnalyzer.analyze(
            "http://paypal-login.secure.verify.account.update.evil-bank-phishing.tk/login/verify/confirm/secure?redirect=https://paypal.com&token=abc"
        )
        let score = r.features["lexical_risk_score"] ?? -1
        #expect(score >= 0 && score <= 100)
    }
}
