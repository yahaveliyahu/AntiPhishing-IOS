/**
 * AntiPhishing popup — renders the protection status reported by the native
 * handler (via the background script). Read-only by design: database
 * updates and allowlist management belong to the AntiPhishing app.
 */

function el(id) { return document.getElementById(id); }

function setStatus(text, tone) {
    const status = el("status-text");
    status.textContent = text;
    status.className = "status" + (tone ? " " + tone : "");
}

async function render() {
    let res;
    try {
        res = await browser.runtime.sendMessage({ type: "getPopupStatus" });
    } catch (_) {
        res = null;
    }

    if (!res || !res.ok) {
        setStatus("Status unavailable — open the AntiPhishing app", "warn");
        return;
    }

    const hasDb = !!res.databaseExists;
    el("db-state").textContent = hasDb ? "Downloaded" : "Not downloaded";
    el("db-count").textContent = typeof res.domainCount === "number"
        ? res.domainCount.toLocaleString() : "–";
    el("db-version").textContent = res.dbVersion ? String(res.dbVersion) : "–";
    el("db-updated").textContent = res.updatedAt
        ? new Date(res.updatedAt).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })
        : "–";

    if (!res.protectionActive) {
        setStatus("Protection is turned off in the app", "warn");
    } else if (!hasDb) {
        setStatus("Not ready — download the database in the app", "bad");
    } else {
        setStatus("Protection active on this device", "ok");
    }
}

render();
