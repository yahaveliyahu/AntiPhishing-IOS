/**
 * AntiPhishing — content script.
 *
 * Runs at document_start on every top-frame http(s) page, asks the
 * background script for a verdict from the LOCAL protection database, and:
 *
 *   • malicious → stops the load and replaces the page with the AntiPhishing
 *     warning. "Go Back" is the primary action; "Continue Anyway" stores a
 *     temporary approval in the shared allowlist and reloads.
 *   • any other verdict with `toast: true` (the app's "Show check
 *     confirmation in Safari" toggle) → shows a small self-dismissing status
 *     toast on every page load: green "checked — safe", or an explicit
 *     problem state — no database downloaded, protection switched off, app
 *     unreachable — so the user can SEE why protection isn't active.
 *   • toggle off → does nothing at all; normal browsing stays untouched.
 *
 * Running at document_start on the committed document URL means redirect
 * chains are covered too: whatever URL the navigation actually lands on is
 * the one that gets checked.
 */

// 1. בודק שהקוד רץ רק בחלון הראשי ולא בתוך iframe.
// 2. בודק שהכתובת היא HTTP או HTTPS.
// 3. שולח את הכתובת ל־background.js לבדיקה.
// 4. אם התוצאה בטוחה או אחרת שאינה malicious — מציג toast אם צריך.
// 5. אם התוצאה malicious — עוצר את טעינת האתר.
// 6. מוחק את תוכן העמוד ומציג מסך אזהרה.
// 7. מאפשר למשתמש לחזור אחורה.
// 8. אם המשתמש בוחר Continue Anyway — שולח בקשה לאשר את הדומיין זמנית.
// 9. טוען את האתר מחדש אחרי שהאישור נשמר.



(async () => {
    if (window.top !== window) return; // top frame only
    const pageUrl = location.href;
    if (!/^https?:/i.test(pageUrl)) return;

    let result;
    try {
        result = await browser.runtime.sendMessage({ type: "checkUrl", url: pageUrl });
    } catch (_) {
        return; // background not reachable — never break the page
    }
    if (!result) return;

    if (result.verdict !== "malicious") {
        if (result.toast === true) {
            showCheckToast(result.host, result.verdict);
        }
        return;
    }

    showWarningPage(pageUrl, result);

    // ── Check-confirmation toast ─────────────────────────────────────────────
    // Purely cosmetic and fully defensive: any failure here must never
    // affect the page. Runs at document_start, so it waits for a <body>.

    function showCheckToast(host, verdict) {
        try {
            const h = host || location.hostname;
            let text, bg;
            switch (verdict) {
                case "safe":
                    text = h + " checked — safe";
                    bg = "rgba(27,94,32,.92)";       // green
                    break;
                case "allowlisted":
                    text = h + " — approved by you";
                    bg = "rgba(230,126,0,.95)";      // orange: user overrode a block
                    break;
                case "unprotected":
                    text = "No protection database — download it in the AntiPhishing app";
                    bg = "rgba(230,126,0,.95)";      // orange
                    break;
                case "off":
                    text = "AntiPhishing protection is turned off";
                    bg = "rgba(97,97,97,.95)";       // gray
                    break;
                case "unavailable":
                    text = "AntiPhishing can’t reach the app";
                    bg = "rgba(198,40,40,.95)";      // red
                    break;
                default:
                    return;
            }

            const render = () => {
                try {
                    if (!document.body) return;
                    const toast = document.createElement("div");
                    toast.textContent = "\u{1F6E1}️ " + text;
                    toast.setAttribute("role", "status");
                    toast.style.cssText =
                        "position:fixed;top:12px;left:50%;transform:translateX(-50%) translateY(-8px);" +
                        "max-width:88vw;box-sizing:border-box;padding:8px 14px;border-radius:16px;" +
                        "background:" + bg + ";color:#fff;font:600 12px/1.4 -apple-system,system-ui,sans-serif;" +
                        "white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" +
                        "box-shadow:0 4px 14px rgba(0,0,0,.25);z-index:2147483647;opacity:0;" +
                        "transition:opacity .25s ease,transform .25s ease;pointer-events:none;";
                    document.body.appendChild(toast);
                    requestAnimationFrame(() => {
                        toast.style.opacity = "1";
                        toast.style.transform = "translateX(-50%) translateY(0)";
                    });
                    setTimeout(() => {
                        toast.style.opacity = "0";
                        toast.style.transform = "translateX(-50%) translateY(-8px)";
                        setTimeout(() => toast.remove(), 300);
                    }, 2500);
                } catch (_) {}
            };
            if (document.body) render();
            else document.addEventListener("DOMContentLoaded", render, { once: true });
        } catch (_) {}
    }

    // ── AntiPhishing warning page ────────────────────────────────────────────
    // Built with DOM APIs (no innerHTML with page data) and deliberately
    // weighted so leaving the site is the obvious, primary choice.

    function showWarningPage(url, res) {
        try { window.stop(); } catch (_) {}

        const doc = document;
        doc.documentElement.innerHTML = "";

        const head = doc.createElement("head");
        const meta = doc.createElement("meta");
        meta.name = "viewport";
        meta.content = "width=device-width, initial-scale=1";
        head.appendChild(meta);
        const titleEl = doc.createElement("title");
        titleEl.textContent = "Blocked — AntiPhishing";
        head.appendChild(titleEl);

        const body = doc.createElement("body");
        body.style.cssText =
            "margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;" +
            "background:#FFF7F7;font-family:-apple-system,system-ui,sans-serif;color:#1a1a1a;";

        const wrap = doc.createElement("div");
        wrap.style.cssText = "max-width:420px;width:100%;padding:24px;box-sizing:border-box;text-align:center;";

        const shield = doc.createElement("div");
        shield.textContent = "🚨";
        shield.style.cssText = "font-size:64px;line-height:1;";
        wrap.appendChild(shield);

        const h1 = doc.createElement("h1");
        h1.textContent = "Dangerous Website Blocked";
        h1.style.cssText = "font-size:22px;font-weight:700;color:#C62828;margin:16px 0 8px;";
        wrap.appendChild(h1);

        // Local-database matches are a confirmed listing; lexical/ML verdicts
        // are this device's own risk analysis — worded differently so the
        // page never overclaims certainty it doesn't have.
        const isAnalysisVerdict = res.threatType === "lexical" || res.threatType === "ml_model";

        const subtitle = doc.createElement("p");
        subtitle.textContent = isAnalysisVerdict
            ? "AntiPhishing's on-device risk analysis flagged this site. It may try to steal " +
              "passwords, payment details or personal information."
            : "This site is listed in the AntiPhishing threat database. It may try to steal " +
              "passwords, payment details or personal information.";
        subtitle.style.cssText = "font-size:14px;line-height:20px;color:#6B4B4B;margin:0 0 16px;";
        wrap.appendChild(subtitle);

        // Details card: blocked domain + reason/category from the database.
        const card = doc.createElement("div");
        card.style.cssText = "background:#FFEBEE;border-radius:12px;padding:16px;text-align:left;";

        card.appendChild(detailRow("Blocked domain", res.matchedDomain, true));
        if (res.host && res.host !== res.matchedDomain) {
            card.appendChild(detailRow("Full address", res.host, true));
        }
        if (res.threatType) {
            card.appendChild(detailRow("Threat category", humanThreatType(res.threatType), false));
        }
        if (res.source) {
            card.appendChild(detailRow("Listed by", humanSource(res.source), false));
        }
        if (typeof res.confidence === "number") {
            card.appendChild(detailRow("Risk score", res.confidence + "%", false));
        }
        if (res.explanation) {
            const reasonWrap = doc.createElement("div");
            reasonWrap.style.cssText = "margin-top:10px;padding-top:10px;border-top:1px solid rgba(198,40,40,.15);";
            res.explanation.split("\n").forEach((line) => {
                if (!line.trim()) return;
                const p = doc.createElement("div");
                p.textContent = line;
                p.style.cssText = "font-size:13px;line-height:19px;color:#7F1D1D;";
                reasonWrap.appendChild(p);
            });
            card.appendChild(reasonWrap);
        }
        wrap.appendChild(card);

        // Primary action — leave (visually dominant on purpose).
        const backBtn = doc.createElement("button");
        backBtn.textContent = "← Go Back (Recommended)";
        backBtn.style.cssText =
            "display:block;width:100%;height:52px;margin-top:24px;border:none;border-radius:26px;" +
            "background:#1976D2;color:#fff;font-size:16px;font-weight:600;cursor:pointer;";
        backBtn.addEventListener("click", () => {
            if (history.length > 1) {
                history.back();
                // Nothing to go back to → close the tab instead.
                setTimeout(() => { browser.runtime.sendMessage({ type: "closeTab" }).catch(() => {}); }, 600);
            } else {
                browser.runtime.sendMessage({ type: "closeTab" }).catch(() => {});
            }
        });
        wrap.appendChild(backBtn);

        // Secondary action — small, plain, and behind an extra confirm.
        const proceedBtn = doc.createElement("button");
        proceedBtn.textContent = "Continue Anyway (At Your Own Risk)";
        proceedBtn.style.cssText =
            "display:block;width:100%;height:40px;margin-top:14px;border:none;border-radius:20px;" +
            "background:transparent;color:#9E5A5A;font-size:13px;cursor:pointer;text-decoration:underline;";
        proceedBtn.addEventListener("click", async () => {
            const sure = window.confirm(
                "This site was flagged as dangerous. If you continue it will be allowed for 24 hours. Continue?");
            if (!sure) return;
            try {
                const res2 = await browser.runtime.sendMessage({ type: "allowDomain", domain: res.matchedDomain });
                if (res2 && res2.ok) { location.reload(); return; }
            } catch (_) {}
            proceedBtn.textContent = "Could not store the approval — try again";
        });
        wrap.appendChild(proceedBtn);

        const brand = doc.createElement("div");
        brand.textContent = res.threatType === "ml_model"
            ? "🛡️ Protected by AntiPhishing · risk model on the server"
            : "🛡️ Protected by AntiPhishing · checked on this device";
        brand.style.cssText = "font-size:12px;color:#9E9E9E;margin-top:24px;";
        wrap.appendChild(brand);

        body.appendChild(wrap);
        doc.documentElement.appendChild(head);
        doc.documentElement.appendChild(body);
    }

    function detailRow(label, value, mono) {
        const row = document.createElement("div");
        row.style.cssText = "margin-bottom:10px;";
        const labelEl = document.createElement("div");
        labelEl.textContent = label;
        labelEl.style.cssText = "font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#9E5A5A;";
        const valueEl = document.createElement("div");
        valueEl.textContent = value;
        valueEl.style.cssText =
            (mono ? "font-family:ui-monospace,Menlo,monospace;" : "") +
            "font-size:14px;font-weight:600;color:#7F1D1D;word-break:break-all;margin-top:2px;";
        row.appendChild(labelEl);
        row.appendChild(valueEl);
        return row;
    }

    function humanThreatType(type) {
        switch (type) {
            case "blacklist": return "Phishing / malicious site";
            case "threat_intel": return "Malware / threat-intelligence listing";
            case "lexical": return "Suspicious URL structure";
            case "ml_model": return "Flagged by risk-scoring model";
            default: return type;
        }
    }

    function humanSource(source) {
        // Feed identifiers → readable names (same names the server stores).
        return String(source).replace(/_/g, " ");
    }
})();
