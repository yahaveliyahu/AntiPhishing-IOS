//
//  CheckResult.swift
//  AntiPhishing
//
//  Port of the Kotlin ApiClient.CheckResult sealed class.
//  The result of checking a URL through the pipeline.
//

import Foundation

enum CheckResult: Equatable {

    /// Domain is in the whitelist — known safe site (Facebook, Google, etc.)
    case whitelisted(description: String, category: String)

    /// URL or domain found in malicious blacklist OR flagged by lexical analysis.
    case malicious(explanation: String, source: String?, confidence: Int, matchType: String)

    /// Not found in lists — triggers lexical analysis.
    case unknown(explanation: String)

    /// Server unreachable or network error.
    case error(message: String)
}
