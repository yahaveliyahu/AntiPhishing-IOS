# AntiPhishing — iOS

AntiPhishing is a mobile information-security project that aims to **identify phishing links before the user opens them** — from Safari, the share sheet of any app (Messages / WhatsApp / Mail…), or a physical **QR code** — and to show **a risk verdict with a clear, human-readable explanation** instead of a silent block.

Authors: **Yahav Eliyahu, Ron Golan**

---

## Problem Statement

Phishing attacks are one of the most common and dangerous security problems today. Thousands of users fall every day for an attack that begins with a single tap on a link — and that link can appear anywhere: in WhatsApp, an SMS, an email, a social network, or even on a physical QR code printed on a flyer or poster.

The core danger of phishing is that it rarely *looks* dangerous. Attackers are extremely good at crafting links that closely mimic legitimate ones. A domain can look almost identical to the original, differing by a single character — replacing the `l` in `paypal` with a `1`, for example.

Techniques such as **QR-code phishing** are especially deceptive because they hide the destination URL from the user entirely — you cannot proofread a link you never see.

When attackers misuse the names of trusted banks, well-known corporations, or familiar services, the visual cues of a scam disappear. This makes the threat highly sophisticated and dangerous — especially for older adults and people who are less technologically experienced.

Most existing solutions rely on known blacklists and Threat-Intelligence databases, which leaves users exposed to **zero-day** attacks and to malicious QR codes in the physical world.

---

## Project Goal

Build a system that provides **proactive protection** — a verdict *before* the damage, not after:

- Show whether a link is **Safe** or **Dangerous**.
- When it is dangerous, show **why**, in plain language (new/typosquatted domain, suspicious keyword, unusual URL structure, hidden characters…).
- Do it **fast and privately**, working even when the device is offline.

---

## The iOS reality (an honest, central design note)

On **Android**, an app can register as the system's default browser and silently intercept *every* link tapped in *every* app. **iOS does not allow this** — Apple does not let a third-party, non-browser app become the system-wide link handler, and there is no App-Store-compliant way around it.

So the iOS version delivers the same protection through the four mechanisms Apple **does** allow, which together cover almost the same ground:

| Entry point | How it triggers | What it covers |
|---|---|---|
| **Safari Web Extension** | Automatic on every page load in Safari | Links tapped in Messages/WhatsApp/Mail that open in Safari |
| **Share Extension** | In any app: **Share → AntiPhishing** on a link | Cross-app link checking |
| **QR scanner** | Tap *Scan QR Code* in the app | Physical / on-screen QR codes |
| **Manual check** | Paste or type a link on the home screen | Anything the user wants to vet |

Every entry point runs the **same** check pipeline and shows the **same** warning screen.

---

## Key Features

- **Safari protection (Web Extension).** A Manifest-V3 Safari Web Extension checks every page Safari opens against an on-device malicious-domain database. It declares **no host permissions and makes no network requests** — lookups go to the app's native handler, so **no page URL ever leaves the device**.
- **Cross-app protection (Share Extension).** Intercept and analyze a link shared from any iOS app before it is opened.
- **QR-code scanning.** A built-in **AVFoundation** camera scanner extracts the encoded URL and runs the risk assessment *before* any navigation occurs.
- **On-device lexical analysis.** A self-contained engine runs **50+ signals** over a URL's text (length, subdomains, typosquatting, homograph/punycode, encoding attacks, suspicious TLDs/keywords, entropy…) with no network calls — instant and offline.
- **On-device threat database.** 600k+ malicious domains from public threat feeds are stored in **SQLite** in a shared App Group container for exact, offline, private lookups.
- **Server-side ML scoring.** For links that are unknown but not obviously malicious, the lexical **feature vector** is sent to a **Flask** backend (`/api/score`) for an additional probability/risk score.
- **Explainable security.** Every verdict comes with user-readable reasons — not just a percentage.
- **History & statistics.** Checked links are saved locally (shared across app + extensions) with counters shown to the user.
- **Bilingual UI.** Full **English / Hebrew** with a runtime language toggle.

---

## Architecture (flow)

<!-- Drop an image at ./IOS-diagram.jpg and uncomment to embed it:
<p align="center"><img src="IOS-diagram.jpg" alt="AntiPhishing architecture" width="650" /></p>
-->

```
        ┌───────────────────────── URL captured ─────────────────────────┐
        │  Safari extension  ·  Share sheet  ·  QR scanner  ·  Manual box │
        └────────────────────────────────┬───────────────────────────────┘
                                          ▼
                             Normalize host (lowercase,
                             strip params, punycode → host)
                                          ▼
                     ┌──── On-device SQLite threat DB (600k+) ────┐
                     └───────────────────┬────────────────────────┘
                             hit ◄────────┴────────► miss
                              │                        │
                          MALICIOUS            Flask /api/check
                                                        │ Unknown
                                                        ▼
                                        On-device LexicalAnalyzer
                                          (50+ signals, offline)
                                                        │
                    obvious killer ◄────────────────────┴──────► needs review
                          │                                          │
                      MALICIOUS                            Flask /api/score (ML)
                                                        │
                                                        ▼
                       Verdict + explanation  →  warning screen / open safe link
```

---

## Algorithm

The system classifies URLs in real time using a multi-layered pipeline (`CheckPipeline.swift`). QR codes add an interception step at the very top.

1. **URL interception.** Triggered when Safari loads a page, a user shares a link, a user scans a QR code (AVFoundation extracts the encoded URL *before* navigation), or a user pastes a link manually.

2. **Normalization.** `DomainNormalizer` lowercases the URL, strips tracking noise, decodes punycode, and extracts the registrable host so every layer compares the same canonical value.

3. **On-device database lookup.** The normalized host is checked against the local SQLite threat database (the same data the Safari extension uses, shared via the App Group). A hit is **instant, private, and offline**, and short-circuits the rest of the pipeline as **Malicious**.

4. **Server / offline check.** On a miss, the URL goes to the Flask backend (`/api/check` or `/api/qr/check`). For offline development, `IS_LOCAL = true` swaps in the bundled `LocalUrlLists` whitelist/blacklist instead of the network.

5. **Feature extraction (zero-day path).** If the result is still *Unknown*, the on-device `LexicalAnalyzer` computes 50+ signals and packages them into a numeric feature vector, including:
   - URL length and path depth.
   - Number of subdomains and hyphens/digits in the domain.
   - Suspicious keywords (`login`, `verify`, `secure`…) and urgency words.
   - Alpha-numeric ratio and Shannon entropy (DGA-style random domains).
   - Special/hidden characters (`@`, `%00`, zero-width Unicode), punycode/homograph, typosquatting distance to known brands, shorteners/redirectors, and more.

6. **Classification & decision.**
   - **Obvious killers** — signals no legitimate URL ever uses (`@` in the authority, `javascript:`/`data:` URIs, hidden Unicode, null bytes, credential `user:pass@host`, double file extensions…) → **blocked immediately** without any server call.
   - **Otherwise** → the feature vector is sent to the ML endpoint (`/api/score`), which returns an `is_malicious` classification with a confidence score.

7. **Enforcement & explanation.**
   - **Malicious** (DB hit, obvious killer, or server verdict) → a full-screen AntiPhishing warning shows the domain, the reason, and the risk level. *Go Back* is the primary action; *Continue Anyway* stores a **24-hour approval** in the shared allowlist.
   - **Safe** → the link opens in the user's chosen browser.
   - Either way the result is written to the shared scan history and the statistics counters.

---

## System Architecture

**iOS app (SwiftUI)**
- Dashboard with live statistics, recent activity, and language toggle.
- Manual link check, AVFoundation QR scanner, and result/warning screens.
- `LexicalAnalyzer` risk engine + `DomainNormalizer` (shared with the extensions).
- Protection center: downloads threat feeds, builds/validates the SQLite DB, and swaps it in atomically.
- History, settings, and the "Approved Domains" (allowlist) manager.

**Safari Web Extension**
- MV3 background/content/popup scripts — **no host permissions, no network**.
- A native `SafariWebExtensionHandler` performs the on-device DB lookups and allowlist writes; safe verdicts are cached (and invalidated when the DB updates).

**Share Extension**
- Receives a shared URL/text, runs the same pipeline, and shows the same warning UI.

**Shared layer (compiled into app + extensions)**
- App Group storage, `ProtectionDatabase` (SQLite reader/writer), `ProtectionMetadata`, one `DomainNormalizer`, and the shared `AllowlistStore` (24h TTL).

**Backend (Flask, hosted on Render)**
- `POST /api/check`, `POST /api/qr/check`, `POST /api/qr/report`, `POST /api/score` (ML), `GET /api/stats`.
- **MongoDB** for the malicious-domain collection, whitelist, and cached checks, seeded from public threat feeds on a schedule.
- A 60-second client timeout accommodates Render free-tier cold starts.

---

## Tech Stack

- **iOS:** Swift, SwiftUI, AVFoundation (QR scanning), Share Extension, **Safari Web Extension (Manifest V3, JS)**, App Groups, SafariServices.
- **On-device storage:** SQLite (threat database) + App Group shared container (history, settings, allowlist).
- **Backend:** Flask (REST API on Render).
- **Server storage:** MongoDB (malicious domains, whitelist, cache).
- **ML:** URL phishing scoring from an engineered lexical feature vector (`/api/score`).
- **Threat intelligence:** public feeds (Phishing Army, Phishing.Database, URLhaus, OpenPhish, Disconnect.me, C2IntelFeeds, Botvrij…).

---

## Privacy

- Safari-extension lookups are **100% on-device**; page URLs never leave the phone.
- The threat database is downloaded **only** when the user taps *Download/Update* — nothing heavy runs implicitly.
- Because lookups are local, protection keeps working **offline** with the last downloaded database.

---

## Tests

A unit-test target (`AntiPhishingTests`) covers the ported logic: the `LexicalAnalyzer` risk engine and its feature vector, `DomainNormalizer`, the local whitelist/blacklist, the pipeline's history mapping and URL extraction, the `HistoryStore` behaviour, the `ProtectionDatabase`, and live backend connectivity.

```sh
xcodebuild test -scheme AntiPhishing \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
```

The live-network tests live in `ApiClientLiveTests`; skip them for a purely offline run with `-skip-testing:AntiPhishingTests/ApiClientLiveTests`.

---

## Research / References

The project builds on a review of **blacklist, heuristic, and machine-learning** approaches to phishing-URL detection, including host-based signals and the combination of lexical features that feed the on-device engine and the ML scorer.

---

## Credits

Project by:

- **Yahav Eliyahu**
- **Ron Golan**
</content>
</invoke>
