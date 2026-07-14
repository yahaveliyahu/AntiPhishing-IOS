//
//  ApiClientLiveTests.swift
//  AntiPhishingTests
//
//  Live connectivity tests against the production Flask backend
//  (https://antiphishing-backend.onrender.com) — the same server the Android
//  app uses. These hit the real network. The backend runs on Render's free
//  tier, which sleeps when idle and can take ~50s to wake, so each call is
//  retried a few times before giving up.
//
//  Tagged `.network` so they can be excluded from offline runs with:
//      xcodebuild test ... -skip-testing:AntiPhishingTests/ApiClientLiveTests
//

import Testing
@testable import AntiPhishing

extension Tag {
    @Tag static var network: Self
}

@MainActor
@Suite(.tags(.network))
struct ApiClientLiveTests {

    /// Retries while the server is waking from cold start.
    private func check(_ url: String, attempts: Int = 3) async -> CheckResult {
        var last: CheckResult = .error(message: "no attempt made")
        for attempt in 0..<attempts {
            last = await ApiClient.checkUrl(url)
            if case .error = last {
                if attempt < attempts - 1 {
                    try? await Task.sleep(nanoseconds: 3_000_000_000)  // 3s back-off
                }
                continue
            }
            return last
        }
        return last
    }

    @Test("Backend classifies a known-safe site as whitelisted")
    func knownSafeIsWhitelisted() async {
        let result = await check("https://www.google.com")
        if case .error(let message) = result {
            Issue.record("Backend unreachable: \(message)")
            return
        }
        guard case .whitelisted = result else {
            Issue.record("Expected google.com to be whitelisted, got \(result)")
            return
        }
    }

    @Test("Backend returns a non-error verdict for an arbitrary URL")
    func arbitraryUrlReturnsVerdict() async {
        let result = await check("http://some-random-site-for-testing-1234.com/page")
        if case .error(let message) = result {
            Issue.record("Backend unreachable: \(message)")
            return
        }
        // The server returns match_type "safe"/"unknown" here, which the client
        // maps to .unknown (triggering on-device lexical analysis) — never a crash.
        switch result {
        case .whitelisted, .malicious, .unknown:
            break   // any concrete verdict is acceptable
        case .error(let message):
            Issue.record("Unexpected error verdict: \(message)")
        }
    }
}
