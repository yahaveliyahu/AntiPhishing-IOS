//
//  LexicalAnalyzer.swift
//  AntiPhishing
//
//  A fully self-contained, offline URL risk-scoring engine.
//  1:1 port of the Android LexicalAnalyzer.kt.
//
//  It operates exclusively on the lexical (textual) properties of a URL —
//  no DNS lookups, no network calls — so it works instantly and offline.
//
//  This analyzer does NOT classify URLs as safe or malicious by itself
//  (that is the ML server's job). The ONE exception is `isObviouslyMalicious`:
//  a small set of signals so unambiguous that no legitimate URL ever uses them,
//  which are blocked immediately without waiting for the server.
//

import Foundation

enum LexicalAnalyzer {

    // MARK: - Public data types

    struct LexicalResult {
        let isObviouslyMalicious: Bool   // True ONLY for unambiguous signals — blocks without ML
        let flags: [String]              // Human-readable explanations for the user
        let features: [String: Double]   // Numeric feature vector for the ML server
    }

    // MARK: - Entry point

    static func analyze(_ rawUrl: String) -> LexicalResult {
        let url = rawUrl.trimmingCharacters(in: .whitespacesAndNewlines)

        // Parse URL components; fall back gracefully on malformed input
        let comps = URLComponents(string: url)
        let scheme = (comps?.scheme?.lowercased()) ?? extractSchemeFallback(url)
        let host = (comps?.host?.lowercased()).map { trimTrailingDots($0) } ?? extractHostFallback(url)
        let path = comps?.path ?? ""
        let query = comps?.query ?? ""
        let fragment = comps?.fragment ?? ""
        let fullUrl = url.lowercased()

        var flags = [String]()
        var score = 0          // Raw score — used only as a feature sent to the ML model
        var obviousKillers = 0 // Counts signals so unambiguous that no legitimate URL uses them

        // MARK: 1. URL STRUCTURE & LENGTH

        let urlLength = url.count
        if urlLength > 200 {
            score += 15; flags.append("⚠️ Extremely long URL (\(urlLength) chars) — phishing links often hide destination behind excessive length")
        } else if urlLength > 100 {
            score += 8; flags.append("⚠️ Unusually long URL (\(urlLength) chars)")
        } else if urlLength > 75 {
            score += 3
        }

        // Deep directory paths are uncommon on legitimate sites
        let pathDepth = path.split(separator: "/").filter { !$0.isEmpty }.count
        if pathDepth >= 6 {
            score += 10; flags.append("⚠️ Very deep URL path (\(pathDepth) levels) — legitimate sites rarely use such deep paths")
        } else if pathDepth >= 4 {
            score += 5
        }

        // Many query parameters are a classic obfuscation trick
        let queryParamCount = query.isEmpty ? 0 : query.split(separator: "&").count
        if queryParamCount >= 10 {
            score += 10; flags.append("⚠️ Excessive query parameters (\(queryParamCount)) — often used to confuse security scanners")
        } else if queryParamCount >= 5 {
            score += 5
        }

        // Presence of URL fragment used for redirection tricks
        if !fragment.isEmpty && fragment.count > 20 {
            score += 5; flags.append("⚠️ Unusually long URL fragment — may be used for redirect manipulation")
        }

        // MARK: 2. DOMAIN & HOST ANALYSIS

        // Raw IP address instead of domain name
        let isIpAddress = matches(host, #"^\d{1,3}(\.\d{1,3}){3}$"#)
        if isIpAddress {
            score += 20; flags.append("🚨 IP address used instead of domain name — phishing sites frequently avoid registering a domain")
        }

        let domainParts = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let tld = domainParts.last ?? ""
        let registrable: String = domainParts.count >= 2
            ? "\(domainParts[domainParts.count - 2]).\(domainParts.last!)"
            : host

        // Excessive subdomains (e.g. secure.login.paypal.verify.evil.com)
        let subdomainCount = max(domainParts.count - 2, 0)
        if subdomainCount >= 4 {
            score += 20; flags.append("🚨 Very many subdomains (\(subdomainCount)) — classic phishing trick to make URL appear legitimate")
        } else if subdomainCount >= 3 {
            score += 12; flags.append("⚠️ Multiple subdomains (\(subdomainCount)) — e.g. 'secure.login.bank.evil.com'")
        } else if subdomainCount == 2 {
            score += 5
        }

        // Typosquatting: well-known brand in subdomain but not in registrable domain
        let knownBrands = [
            "paypal", "google", "facebook", "apple", "amazon", "microsoft",
            "netflix", "instagram", "whatsapp", "twitter", "linkedin",
            "ebay", "bank", "bankhapoalim", "bankleumi", "poalim", "leumi",
            "yahoo", "dropbox", "icloud", "wellsfargo", "chase", "barclays"
        ]
        let brandInSubdomain = knownBrands.contains { brand in
            host.hasPrefix("\(brand).") || host.contains(".\(brand).")
        }
        let brandInRegistrable = knownBrands.contains { brand in registrable.hasPrefix("\(brand).") }

        if brandInSubdomain && !brandInRegistrable {
            score += 25
            flags.append("🚨 Brand name appears in subdomain only — this is the #1 typosquatting technique (e.g. 'paypal.login.evil.com')")
        }

        // Typosquatting via character substitution (0→o, 1→l, rn→m, etc.)
        let visualSpoofed = checkVisualSpoofing(host, knownBrands)
        if let spoof = visualSpoofed {
            score += 20; flags.append("🚨 Domain looks like '\(spoof)' but differs by 1–2 characters — typosquatting detected")
        }

        // Unusually long registrable domain name
        let domainName = domainParts.count >= 2 ? domainParts[domainParts.count - 2] : ""
        if domainName.count > 30 {
            score += 12; flags.append("⚠️ Very long domain name (\(domainName.count) chars) — legitimate sites have short, memorable names")
        } else if domainName.count > 20 {
            score += 6
        }

        // Hyphens in domain (e.g. secure-paypal-login.com)
        let hyphenCount = host.filter { $0 == "-" }.count
        if hyphenCount >= 4 {
            score += 15; flags.append("🚨 Many hyphens in domain (\(hyphenCount)) — phishing sites often join multiple words with hyphens")
        } else if hyphenCount >= 2 {
            score += 8; flags.append("⚠️ Multiple hyphens in domain (\(hyphenCount))")
        } else if hyphenCount == 1 {
            score += 3
        }

        // Digits in domain name (not counting TLD)
        let digitCountInDomain = domainName.filter { $0.isNumber }.count
        if digitCountInDomain >= 3 {
            score += 8; flags.append("⚠️ Many digits in domain name — random-looking domains are often auto-generated by attackers")
        }

        // MARK: 3. SUSPICIOUS KEYWORDS

        // High-risk action words — almost always phishing when in a URL
        let highRiskKeywords = [
            "login", "log-in", "signin", "sign-in", "logon", "log-on",
            "verify", "verification", "validate", "account-verify",
            "secure", "security", "update", "confirm", "confirmation",
            "suspend", "suspended", "unlock", "reactivate", "reactivation",
            "billing", "invoice", "payment", "checkout", "reset-password",
            "password-reset", "credential", "webscr", "cmd=", "dispatch="
        ]
        let foundHighRisk = highRiskKeywords.filter { fullUrl.contains($0) }
        if foundHighRisk.count >= 3 {
            score += 20
            flags.append("🚨 Multiple high-risk keywords found: \(foundHighRisk.prefix(4).joined(separator: ", ")) — strongly associated with credential harvesting")
        } else if foundHighRisk.count == 2 {
            score += 12
            flags.append("⚠️ Suspicious keywords found: \(foundHighRisk.joined(separator: ", "))")
        } else if foundHighRisk.count == 1 {
            score += 6
            flags.append("⚠️ Suspicious keyword found: '\(foundHighRisk[0])'")
        }

        // Urgency/social-engineering words
        let urgencyKeywords = [
            "urgent", "immediately", "alert", "warning", "attention",
            "limited", "expire", "expired", "action-required", "act-now",
            "free", "winner", "won", "prize", "gift", "reward",
            "bonus", "congratulations", "claim", "lucky", "selected"
        ]
        let foundUrgency = urgencyKeywords.filter { fullUrl.contains($0) }
        if foundUrgency.count >= 2 {
            score += 12
            flags.append("⚠️ Social engineering language in URL: \(foundUrgency.prefix(3).joined(separator: ", ")) — used to pressure users into clicking")
        } else if foundUrgency.count == 1 {
            score += 5
        }

        // Brand names appearing in the path/query (not domain) — classic phishing
        let brandInPathOrQuery = knownBrands.filter { brand in
            (path.lowercased() + query.lowercased()).contains(brand)
        }
        if !brandInPathOrQuery.isEmpty && !brandInRegistrable {
            score += 15
            flags.append("⚠️ Brand name '\(brandInPathOrQuery[0])' appears in URL path but not in domain — deceptive structure")
        }

        // Fake file extensions in path (e.g. /index.html/secure/login)
        let pathLowerForExt = path.lowercased()
        let fakeExtensions = [".php", ".html", ".aspx", ".jsp"].filter { ext in
            if let idx = pathLowerForExt.range(of: ext)?.lowerBound {
                let pos = pathLowerForExt.distance(from: pathLowerForExt.startIndex, to: idx)
                return pos < pathLowerForExt.count - ext.count
            }
            return false
        }.count
        if fakeExtensions > 0 {
            score += 8; flags.append("⚠️ File extension appears in the middle of the path — often used to spoof file type")
        }

        // MARK: 4. CHARACTER-LEVEL ANALYSIS

        // @ symbol — OBVIOUS KILLER
        if url.contains("@") {
            score += 25; obviousKillers += 1; flags.append("🚨 '@' symbol in URL — browsers ignore everything before it, redirecting to a completely different site")
        }

        // Hidden Unicode characters — OBVIOUS KILLER
        let dangerousUnicodeScalars: [ClosedRange<UInt32>] = [
            0x200B...0x200D,  // Zero-width space, non-joiner, joiner
            0x202A...0x202E,  // Direction control chars
            0x2060...0x2064,  // Word joiners
            0xFEFF...0xFEFF,  // BOM / zero-width no-break space
            0x00AD...0x00AD   // Soft hyphen
        ]
        let hiddenCharCount = url.unicodeScalars.filter { sc in
            dangerousUnicodeScalars.contains { $0.contains(sc.value) }
        }.count
        let hasHiddenChars = hiddenCharCount > 0
        if hasHiddenChars {
            score += 50; obviousKillers += 1
            flags.append("🚨 Hidden Unicode characters detected (\(hiddenCharCount) found) — invisible characters used to disguise the real URL destination")
        }

        // Double slash in path (not scheme) — redirect trick
        if path.contains("//") {
            score += 10; flags.append("⚠️ Double slash in URL path — often used to confuse parsers or create open redirect")
        }

        // Percent-encoding overuse
        let percentEncodedCount = url.components(separatedBy: "%").count - 1
        if percentEncodedCount >= 15 {
            score += 20; flags.append("🚨 Heavy URL encoding (\(percentEncodedCount) encoded chars) — attackers encode URLs to evade keyword filters")
        } else if percentEncodedCount >= 6 {
            score += 10; flags.append("⚠️ Significant URL encoding (\(percentEncodedCount) encoded chars)")
        } else if percentEncodedCount >= 3 {
            score += 5
        }

        // Alpha-numeric ratio
        let alphaCount = host.filter { $0.isLetter }.count
        let digitCount = host.filter { $0.isNumber }.count
        let alphaRatio = host.isEmpty ? 1.0 : Double(alphaCount) / Double(host.count)
        if alphaRatio < 0.5 && host.count > 5 {
            score += 12; flags.append("⚠️ Low letter ratio in domain (\(Int(alphaRatio * 100))%) — random-looking domains suggest auto-generation")
        }

        // Abnormal special characters in host
        let specialCharsInHost = host.filter { !$0.isLetter && !$0.isNumber && $0 != "." && $0 != "-" }.count
        if specialCharsInHost > 0 {
            score += 15; flags.append("⚠️ Unusual special characters in domain — not allowed in normal domain names")
        }

        // High Shannon entropy in domain name = random-looking = DGA
        let entropy = shannonEntropy(domainName)
        if entropy > 4.0 {
            score += 15; flags.append("🚨 Domain name appears random/auto-generated (entropy: \(String(format: "%.1f", entropy))) — consistent with malware DGA domains")
        } else if entropy > 3.5 {
            score += 8
        }

        // Consecutive consonants
        let maxConsecutiveConsonants = longestConsonantRun(domainName)
        if maxConsecutiveConsonants >= 5 {
            score += 10; flags.append("⚠️ Domain contains long consonant sequence ('\(domainName)') — looks auto-generated")
        }

        // Consecutive vowels
        let maxConsecutiveVowels = longestVowelRun(domainName)
        if maxConsecutiveVowels >= 4 {
            score += 10; flags.append("⚠️ Domain contains long vowel sequence ('\(domainName)') — looks like a made-up or auto-generated word")
        } else if maxConsecutiveVowels >= 3 {
            score += 5
        }

        // Misleading dots/dashes that fragment brand names (e.g. pay-pal.com)
        let brandFragmented = knownBrands.contains { brand in
            let fragmented = brand.map { String($0) }.joined(separator: "[.\\-]")
            return matches(host, fragmented)
        }
        if brandFragmented && !brandInRegistrable {
            score += 18; flags.append("⚠️ Brand name split with dots or hyphens in domain — a typosquatting trick to evade detection")
        }

        // MARK: 5. TLD & PROTOCOL

        let suspiciousTlds: Set<String> = [
            "xyz", "top", "club", "online", "site", "fun", "icu",
            "gq", "ml", "cf", "tk", "ga",
            "buzz", "rest", "work", "link", "click", "download",
            "zip", "mov",
            "pw", "cc", "su", "to", "ws"
        ]
        if suspiciousTlds.contains(tld) {
            score += 12; flags.append("⚠️ Suspicious TLD '.\(tld)' — this domain extension is frequently used in phishing campaigns")
        }

        // Numeric TLD
        if !tld.isEmpty && tld.allSatisfy({ $0.isNumber }) {
            score += 20; flags.append("🚨 Numeric TLD — extremely unusual, nearly always malicious")
        }

        // No HTTPS
        if scheme == "http" {
            score += 8; flags.append("⚠️ Unencrypted HTTP connection — legitimate modern sites use HTTPS")
        }
        // OBVIOUS KILLERS: data: and javascript:
        if scheme == "data" {
            score += 40; obviousKillers += 1; flags.append("🚨 data: URI — can embed malicious content directly in the link")
        }
        if scheme == "javascript" {
            score += 50; obviousKillers += 1; flags.append("🚨 javascript: URI — executes code directly, never from a link")
        }
        if !["http", "https", "ftp", "ftps", ""].contains(scheme) {
            score += 20; flags.append("⚠️ Unusual URL scheme '\(scheme)'")
        }

        // Multiple dots in TLD
        if tld.contains(".") {
            score += 10; flags.append("⚠️ Compound TLD structure — can be used to disguise the true registrable domain")
        }

        // Port number in URL
        let port = comps?.port ?? -1
        if port > 0 && ![80, 443, 8080, 8443].contains(port) {
            score += 10; flags.append("⚠️ Non-standard port \(port) — legitimate websites almost never use unusual ports")
        }

        // MARK: 6. ADVANCED PHISHING PATTERNS

        // Punycode / Internationalized domain.
        // Apple's URLComponents decodes an `xn--` host into its Unicode form,
        // so — unlike Android's java.net.URI — the parsed `host` may not contain
        // "xn--". Check the raw host string too, to keep parity with Android.
        let isPunycode = host.contains("xn--") || extractHostFallback(url).contains("xn--")
        if isPunycode {
            score += 22; flags.append("🚨 Punycode/internationalized domain detected — attackers use non-Latin characters that look identical to real brand names")
        }

        // Known redirector services
        let knownRedirectors = [
            "google.com/url", "google.co", "googleweblight.com",
            "t.co/", "bit.ly/", "tinyurl.com/", "t.ly/", "ow.ly/",
            "rb.gy/", "cutt.ly/", "shorturl.at/", "tiny.cc/",
            "is.gd/", "buff.ly/", "soo.gd/", "bc.vc/"
        ]
        let isRedirector = knownRedirectors.contains { fullUrl.contains($0) }
        if isRedirector {
            score += 15; flags.append("⚠️ Known URL redirector service detected — the real destination is hidden behind a redirect")
        }

        // URL shortener
        let knownShorteners = [
            "bit.ly", "tinyurl.com", "t.ly", "ow.ly", "rb.gy",
            "cutt.ly", "shorturl.at", "tiny.cc", "is.gd", "buff.ly",
            "soo.gd", "bc.vc", "t.co", "goo.gl", "youtu.be",
            "bl.ink", "snip.ly", "clck.ru", "qr.ae", "po.st"
        ]
        let isShortener = knownShorteners.contains { host == $0 || host.hasSuffix(".\($0)") }
        if isShortener {
            score += 18; flags.append("⚠️ URL shortener detected — the real destination is completely hidden, a common phishing technique")
        }

        // Repeated brand name in the URL
        let brandRepeatCount = knownBrands.map { brand in
            fullUrl.components(separatedBy: brand).count - 1
        }.max() ?? 0
        if brandRepeatCount >= 3 {
            score += 18; flags.append("🚨 Brand name repeated \(brandRepeatCount) times in URL — used to appear convincing while hiding the real domain")
        } else if brandRepeatCount == 2 {
            score += 8
        }

        // Excessive dots in the full URL
        let dotCount = url.filter { $0 == "." }.count
        if dotCount >= 8 {
            score += 15; flags.append("🚨 Excessive dots in URL (\(dotCount)) — deep subdomain nesting used to hide the real domain")
        } else if dotCount >= 5 {
            score += 8; flags.append("⚠️ Many dots in URL (\(dotCount)) — suggests suspicious subdomain structure")
        }

        // Sensitive words used as TLD
        let sensitiveTlds: Set<String> = [
            "secure", "security", "login", "signin", "verify", "account",
            "support", "help", "update", "confirm", "banking", "payment",
            "deals", "offer", "free", "win", "gift", "bonus"
        ]
        if sensitiveTlds.contains(tld) {
            score += 20; flags.append("🚨 Sensitive word used as TLD ('.\(tld)') — designed to make the URL appear trustworthy")
        }

        // Full domain name embedded inside the path
        let domainInPath = matches(path, #"(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}"#)
        if domainInPath {
            score += 20; flags.append("🚨 A full domain/URL appears inside the URL path — classic redirect attack disguising the real destination")
        }

        // Excessively long subdomain string
        let subdomainPart = domainParts.count > 2 ? domainParts.dropLast(2).joined(separator: ".") : ""
        if subdomainPart.count > 40 {
            score += 12; flags.append("⚠️ Very long subdomain string (\(subdomainPart.count) chars) — used to push the real domain out of the visible URL bar")
        } else if subdomainPart.count > 20 {
            score += 5
        }

        // Mixed character scripts — homograph attack
        let hasNonAsciiInHost = host.unicodeScalars.contains { $0.value > 127 }
        if hasNonAsciiInHost {
            score += 25; flags.append("🚨 Non-ASCII characters detected in domain — homograph attack: foreign letters that look identical to Latin ones")
        }

        // Full URL embedded inside a query parameter
        let urlInQuery = matches(query, #"(https?://|www\.)[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}"#)
        if urlInQuery {
            score += 20; flags.append("🚨 A full URL is embedded inside a query parameter — used to disguise the real destination as a redirect")
        }

        // MARK: 7. ENCODING, INJECTION & OBFUSCATION ATTACKS

        // Double extension
        let dangerousExtensions = [".exe", ".apk", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".jar", ".msi", ".dmg"]
        let safeExtensions = [".pdf", ".docx", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip"]
        let pathLower = path.lowercased()
        let hasDoubleExtension = dangerousExtensions.contains { danger in
            safeExtensions.contains { safe in
                pathLower.contains("\(safe)\(danger)") ||
                (pathLower.contains("\(safe).") &&
                 (pathLower.components(separatedBy: "\(safe).").last ?? "").contains(String(danger.dropFirst())))
            }
        }
        if hasDoubleExtension {
            score += 30; obviousKillers += 1; flags.append("🚨 Double file extension detected — a safe-looking extension (e.g. .pdf) hides a dangerous one (e.g. .apk) to trick the user")
        }

        // OBVIOUS KILLER: Null byte injection
        let hasNullByte = url.contains("%00") || url.contains("\u{0000}")
        if hasNullByte {
            score += 35; obviousKillers += 1; flags.append("🚨 Null byte detected in URL — used to truncate the URL in some systems and bypass security filters")
        }

        // OBVIOUS KILLER: Tab / newline / carriage-return injected into URL
        let hasControlChars = url.contains("%09") || url.contains("%0A") || url.contains("%0D") ||
            url.contains("\t") || url.contains("\n") || url.contains("\r")
        if hasControlChars {
            score += 30; obviousKillers += 1; flags.append("🚨 Tab or newline character in URL — injected to confuse security scanners while browsers silently ignore them")
        }

        // OBVIOUS KILLER: Double URL encoding
        let hasDoubleEncoding = matches(url, "%25[0-9A-Fa-f]{2}")
        if hasDoubleEncoding {
            score += 25; obviousKillers += 1; flags.append("🚨 Double URL encoding detected — attackers encode characters twice to bypass security filters that only decode once")
        }

        // Backslash in URL
        let hasBackslash = url.contains("\\")
        if hasBackslash {
            score += 20; flags.append("🚨 Backslash in URL — some browsers treat it as a forward slash, silently navigating to a completely different domain")
        }

        // OBVIOUS KILLER: Credentials pattern user:password@host
        let hasCredentialsPattern = matches(url, #"https?://[^@\s]+:[^@\s]+@"#)
        if hasCredentialsPattern {
            score += 30; obviousKillers += 1; flags.append("🚨 Credentials pattern in URL (user:password@host) — the displayed host is fake; browser navigates to the host after the '@'")
        }

        // URL self-repetition
        let selfRepeatCount = host.count > 4 ? (path + query).components(separatedBy: host).count - 1 : 0
        if selfRepeatCount >= 2 {
            score += 15; flags.append("⚠️ URL contains its own domain repeated \(selfRepeatCount) times in the path — used to overflow length filters")
        }

        // OBVIOUS KILLER: Unicode normalization attack
        let normalizationMap: [Character: Character] = [
            "ⓐ": "a", "ⓑ": "b", "ⓒ": "c", "ⓓ": "d", "ⓔ": "e",
            "ⓕ": "f", "ⓖ": "g", "ⓗ": "h", "ⓘ": "i", "ⓙ": "j",
            "ⓚ": "k", "ⓛ": "l", "ⓜ": "m", "ⓝ": "n", "ⓞ": "o",
            "ⓟ": "p", "ⓠ": "q", "ⓡ": "r", "ⓢ": "s", "ⓣ": "t",
            "ⓤ": "u", "ⓥ": "v", "ⓦ": "w", "ⓧ": "x", "ⓨ": "y", "ⓩ": "z",
            "\u{212B}": "a", "\u{0392}": "b", "\u{03F2}": "c", "\u{0395}": "e",
            "\u{0397}": "h", "\u{0399}": "i", "\u{039A}": "k", "\u{039C}": "m",
            "\u{039D}": "n", "\u{039F}": "o", "\u{03A1}": "p", "\u{03A4}": "t",
            "\u{03A5}": "y", "\u{03A7}": "x"
        ]
        let normalizedHost = String(host.map { normalizationMap[$0] ?? $0 })
        let hasNormalizationSpoof = normalizedHost != host && knownBrands.contains { normalizedHost.contains($0) }
        if hasNormalizationSpoof {
            score += 28; obviousKillers += 1; flags.append("🚨 Unicode normalization attack detected — circled or Greek letters that convert to ASCII brand names")
        }

        // Path traversal sequences
        let hasPathTraversal = path.contains("../") || path.contains("..\\") ||
            url.contains("%2E%2E%2F") || url.contains("%2E%2E/")
        if hasPathTraversal {
            score += 18; flags.append("⚠️ Path traversal sequence (../) detected — used to navigate outside the intended directory and access restricted resources")
        }

        // Credential or full URL in fragment
        let sensitiveFragmentKeywords = ["http://", "https://", "www.", "access_token=", "id_token=", "token=", "password=", "passwd=", "pwd="]
        let hasSensitiveFragment = sensitiveFragmentKeywords.contains { fragment.lowercased().contains($0) }
        if hasSensitiveFragment {
            score += 20; flags.append("🚨 Sensitive content in URL fragment — credentials or a redirect URL hidden after the # symbol")
        }

        // Mixed case in domain
        let originalHost = comps?.host ?? extractHostFallback(url)
        let hasMixedCaseHost = originalHost.contains { $0.isUppercase } && originalHost.contains { $0.isLowercase }
        if hasMixedCaseHost {
            score += 8; flags.append("⚠️ Mixed uppercase/lowercase in domain — used to evade case-sensitive keyword filters")
        }

        // OBVIOUS KILLER: Non-ASCII characters in TLD
        let hasNonAsciiTld = tld.unicodeScalars.contains { $0.value > 127 }
        if hasNonAsciiTld {
            score += 25; obviousKillers += 1; flags.append("🚨 Non-ASCII characters in TLD — homograph attack targeting the domain extension itself (e.g. Cyrillic о in .cоm)")
        }

        // MARK: Clamp raw score
        let finalScore = min(max(score, 0), 100)

        // MARK: Build feature vector for ML server
        func b(_ v: Bool) -> Double { v ? 1 : 0 }
        let features: [String: Double] = [
            "url_length": Double(urlLength),
            "path_depth": Double(pathDepth),
            "query_param_count": Double(queryParamCount),
            "is_ip_address": b(isIpAddress),
            "subdomain_count": Double(subdomainCount),
            "domain_length": Double(domainName.count),
            "hyphen_count": Double(hyphenCount),
            "digit_count_in_domain": Double(digitCountInDomain),
            "has_at_symbol": b(url.contains("@")),
            "hidden_char_count": Double(hiddenCharCount),
            "has_double_slash": b(path.contains("//")),
            "percent_encoded_count": Double(percentEncodedCount),
            "alpha_ratio": alphaRatio,
            "special_chars_in_host": Double(specialCharsInHost),
            "domain_entropy": entropy,
            "max_consonant_run": Double(maxConsecutiveConsonants),
            "max_vowel_run": Double(maxConsecutiveVowels),
            "high_risk_keyword_count": Double(foundHighRisk.count),
            "urgency_keyword_count": Double(foundUrgency.count),
            "brand_in_subdomain": b(brandInSubdomain && !brandInRegistrable),
            "brand_in_path": b(!brandInPathOrQuery.isEmpty && !brandInRegistrable),
            "is_suspicious_tld": b(suspiciousTlds.contains(tld)),
            "is_https": b(scheme == "https"),
            "has_non_standard_port": b(port > 0 && ![80, 443, 8080, 8443].contains(port)),
            "digit_count_in_host": Double(digitCount),
            "visual_spoof_detected": b(visualSpoofed != nil),
            "lexical_risk_score": Double(finalScore),
            "obvious_killer_count": Double(obviousKillers),
            "is_punycode": b(isPunycode),
            "is_redirector": b(isRedirector),
            "is_shortener": b(isShortener),
            "brand_repeat_count": Double(brandRepeatCount),
            "dot_count": Double(dotCount),
            "sensitive_tld": b(sensitiveTlds.contains(tld)),
            "domain_in_path": b(domainInPath),
            "subdomain_string_length": Double(subdomainPart.count),
            "has_non_ascii_host": b(hasNonAsciiInHost),
            "url_in_query": b(urlInQuery),
            "has_double_extension": b(hasDoubleExtension),
            "has_null_byte": b(hasNullByte),
            "has_control_chars": b(hasControlChars),
            "has_double_encoding": b(hasDoubleEncoding),
            "has_backslash": b(hasBackslash),
            "has_credentials_pattern": b(hasCredentialsPattern),
            "self_repeat_count": Double(selfRepeatCount),
            "has_normalization_spoof": b(hasNormalizationSpoof),
            "has_path_traversal": b(hasPathTraversal),
            "has_sensitive_fragment": b(hasSensitiveFragment),
            "has_mixed_case_host": b(hasMixedCaseHost),
            "has_non_ascii_tld": b(hasNonAsciiTld),
            "fake_extension_in_path": Double(fakeExtensions),
            "brand_fragmented": b(brandFragmented && !brandInRegistrable)
        ]

        return LexicalResult(
            isObviouslyMalicious: obviousKillers > 0,
            flags: flags,
            features: features
        )
    }

    // MARK: - Private helpers

    private static func trimTrailingDots(_ s: String) -> String {
        var r = s
        while r.hasSuffix(".") { r.removeLast() }
        return r
    }

    /// Fallback scheme extraction (everything before the first ':') for URLs
    /// that URLComponents fails to parse.
    private static func extractSchemeFallback(_ url: String) -> String {
        guard let colon = url.firstIndex(of: ":") else { return "" }
        let candidate = String(url[url.startIndex..<colon]).lowercased()
        // A scheme is letters/digits/+/-/. only; reject anything else.
        let valid = candidate.allSatisfy { $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." }
        return (valid && !candidate.isEmpty) ? candidate : ""
    }

    /// Fallback host extraction for malformed URLs.
    private static func extractHostFallback(_ url: String) -> String {
        let afterScheme = url.components(separatedBy: "://").count > 1
            ? url.components(separatedBy: "://")[1]
            : url
        return afterScheme
            .components(separatedBy: "/")[0]
            .components(separatedBy: "?")[0]
            .components(separatedBy: "#")[0]
            .lowercased()
    }

    /// Shannon entropy of a string — higher entropy = more random-looking.
    private static func shannonEntropy(_ s: String) -> Double {
        if s.isEmpty { return 0.0 }
        var freq = [Character: Int]()
        for c in s { freq[c, default: 0] += 1 }
        let len = Double(s.count)
        return freq.values.reduce(0.0) { acc, count in
            let p = Double(count) / len
            return acc - p * (log(p) / log(2.0))
        }
    }

    /// Longest uninterrupted consonant run. Digits/hyphens are skipped silently.
    private static func longestConsonantRun(_ s: String) -> Int {
        let vowels: Set<Character> = ["a", "e", "i", "o", "u"]
        var maxRun = 0, cur = 0
        for ch in s.lowercased() {
            if ch.isLetter && !vowels.contains(ch) {
                cur += 1; if cur > maxRun { maxRun = cur }
            } else if ch.isLetter {
                cur = 0
            }
        }
        return maxRun
    }

    /// Longest uninterrupted vowel run. Digits/hyphens are skipped silently.
    private static func longestVowelRun(_ s: String) -> Int {
        let vowels: Set<Character> = ["a", "e", "i", "o", "u"]
        var maxRun = 0, cur = 0
        for ch in s.lowercased() {
            if ch.isLetter && vowels.contains(ch) {
                cur += 1; if cur > maxRun { maxRun = cur }
            } else if ch.isLetter {
                cur = 0
            }
        }
        return maxRun
    }

    /// Checks if a domain looks like a known brand but with 1–2 character substitutions.
    private static func checkVisualSpoofing(_ host: String, _ brands: [String]) -> String? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let domainBase = parts.count >= 2 ? parts[parts.count - 2] : host

        let normalized = domainBase
            .replacingOccurrences(of: "0", with: "o")
            .replacingOccurrences(of: "1", with: "l")
            .replacingOccurrences(of: "1", with: "i")
            .replacingOccurrences(of: "3", with: "e")
            .replacingOccurrences(of: "4", with: "a")
            .replacingOccurrences(of: "5", with: "s")
            .replacingOccurrences(of: "6", with: "b")
            .replacingOccurrences(of: "7", with: "t")
            .replacingOccurrences(of: "9", with: "g")
            .replacingOccurrences(of: "$", with: "s")
            .replacingOccurrences(of: "I", with: "l")
            .replacingOccurrences(of: "O", with: "o")
            .replacingOccurrences(of: "rn", with: "m")
            .replacingOccurrences(of: "cl", with: "d")
            .replacingOccurrences(of: "vv", with: "w")
            .replacingOccurrences(of: "ii", with: "n")

        for brand in brands {
            if normalized == brand { return brand }
            if levenshtein(domainBase, brand) == 1 { return brand }
            if levenshtein(normalized, brand) <= 1 { return brand }
        }
        return nil
    }

    /// Classic iterative Levenshtein distance.
    private static func levenshtein(_ a: String, _ b: String) -> Int {
        if abs(a.count - b.count) > 3 { return 99 }
        let aChars = Array(a), bChars = Array(b)
        var dp = Array(repeating: Array(repeating: 0, count: bChars.count + 1), count: aChars.count + 1)
        for i in 0...aChars.count { dp[i][0] = i }
        for j in 0...bChars.count { dp[0][j] = j }
        if aChars.count > 0 && bChars.count > 0 {
            for i in 1...aChars.count {
                for j in 1...bChars.count {
                    dp[i][j] = aChars[i - 1] == bChars[j - 1]
                        ? dp[i - 1][j - 1]
                        : 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
                }
            }
        }
        return dp[aChars.count][bChars.count]
    }

    /// Regex helper — returns true if the pattern is found anywhere in the string.
    private static func matches(_ string: String, _ pattern: String) -> Bool {
        guard !string.isEmpty else { return false }
        return string.range(of: pattern, options: .regularExpression) != nil
    }
}
