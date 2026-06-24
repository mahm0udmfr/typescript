;(function(){if(globalThis.__dtgContentLoaded){if(globalThis.__dtgRescan)globalThis.__dtgRescan();return;}globalThis.__dtgContentLoaded=true;
"use strict";
/**
 * Download Trap Guard — content script.
 * Runs after analysis.js sets globalThis.DTGAnalysis.
 */
const DTG = () => globalThis.DTGAnalysis;
const MIN_TRAP_IMAGE_PX = 16;
const DISMISS_STORAGE_KEY = "dtg_dismissed_banners";
const MAX_BANNER_ITEMS = 10;
const BUTTON_CLASS_RE = /\b(btn|button|cta|action|primary|submit)\b/i;
// ── Left sidebar / ticket list — never scan these ──────────────────────────
const LIST_EXCLUDE = '[class*="lhsPanel"], [class*="ticketList"], [class*="listView"], ' +
    '[class*="navPanel"], [class*="leftPanel"]';
let lastBannerKey = "";
let scanTimer = null;
let watching = false;
let startAttempts = 0;
let lastWatchUrl = "";
let lastEmailFingerprint = "";
// Track timers/observers so we can tear everything down if the extension context
// is invalidated (e.g. the extension was reloaded while this tab stayed open).
let stopped = false;
const intervals = [];
const observers = [];
/**
 * Returns true while the extension's runtime context is still valid.
 * After the extension is reloaded/updated, old content scripts linger in the page
 * but every chrome.* call throws "Extension context invalidated". We detect that
 * here and stop all work so no further errors are logged.
 */
function extensionAlive() {
    if (stopped)
        return false;
    try {
        // Accessing chrome.runtime.id throws once the context is invalidated.
        return Boolean(chrome.runtime?.id);
    }
    catch {
        return false;
    }
}
/** Disconnect every timer/observer and remove UI. Called once on context loss. */
function teardown() {
    if (stopped)
        return;
    stopped = true;
    for (const id of intervals) {
        try {
            clearInterval(id);
        }
        catch { /* ignore */ }
    }
    for (const ob of observers) {
        try {
            ob.disconnect();
        }
        catch { /* ignore */ }
    }
    if (scanTimer) {
        try {
            clearTimeout(scanTimer);
        }
        catch { /* ignore */ }
    }
    try {
        clearWarnings();
    }
    catch { /* ignore */ }
}
let activeHighlights = [];
const flaggedElements = new WeakSet();
if (!globalThis.DTGAnalysis) {
    console.error("[DTG] analysis.js not loaded — disabled.");
}
// ── URL helpers ────────────────────────────────────────────────────────────
function isTicketDetailsUrl(url) {
    try {
        const p = new URL(url).pathname.toLowerCase();
        return /\/agent\/[^/]+\/[^/]+\/tickets\/details\//.test(p) || p.includes("/tickets/details/");
    }
    catch {
        return false;
    }
}
function isOnTicketPage() {
    if (isTicketDetailsUrl(window.location.href))
        return true;
    // inside cross-origin iframe whose parent is a ticket page
    try {
        if (window.parent !== window) {
            const ph = window.parent.location.href;
            if (isTicketDetailsUrl(ph))
                return true;
        }
    }
    catch {
        /* cross-origin */
    }
    // last resort: referrer
    return Boolean(document.referrer && isTicketDetailsUrl(document.referrer));
}
function isZohoDeskFrame() {
    const h = window.location.hostname.toLowerCase();
    return (h.includes("zohopublic") ||
        h.includes("zappsusercontent") ||
        h.includes("zohostratus") ||
        h.includes("zohocdn") ||
        h.includes("zoho.eu"));
}
function shouldActivate() {
    if (isOnTicketPage() || isZohoDeskFrame())
        return true;
    // Activate in any subframe — Zoho renders email bodies in iframes (about:blank,
    // about:srcdoc, or cross-origin Zoho URLs) whose href doesn't match ticket patterns.
    // The analysis confidence threshold + sidebar exclusion prevent false positives.
    if (window !== window.top)
        return true;
    return false;
}
function pageHost() {
    try {
        if (window.parent !== window) {
            const ph = window.parent.location.href;
            if (ph)
                return new URL(ph).hostname;
        }
    }
    catch {
        /* cross-origin */
    }
    return window.location.hostname;
}
// ── Ticket context (sender, subject) ───────────────────────────────────────
let ctxCache = null;
let ctxTs = 0;
function extractEmail(t) {
    return t.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i)?.[0]?.toLowerCase();
}
function extractDisplayName(t) {
    const email = extractEmail(t);
    if (!email)
        return undefined;
    const beforeEmail = t.split(email)[0] ?? "";
    const cleaned = beforeEmail
        .replace(/\bfrom\b/i, "")
        .replace(/[<>"“”]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    return cleaned.length > 1 && cleaned.length < 80 ? cleaned : undefined;
}
function getTicketContext() {
    const now = Date.now();
    if (ctxCache && now - ctxTs < 4000)
        return ctxCache;
    const ctx = {};
    const subjSel = '[class*="ticketSubject"],[class*="subjTitle"],[class*="subjectLine"],[class*="zd_v2-subject"]';
    for (const el of Array.from(document.querySelectorAll(subjSel))) {
        const t = el.textContent?.trim();
        if (t && t.length > 4 && t.length < 400) {
            ctx.subject = t.replace(/\s+/g, " ").slice(0, 300);
            break;
        }
    }
    if (!ctx.subject && document.title) {
        const t = document.title.replace(/^Ticket\s*#?\d+\s*[-–:|]\s*/i, "").replace(/\s*[-–|]\s*(Zoho|Desk).*$/i, "").trim();
        if (t.length > 4)
            ctx.subject = t.slice(0, 300);
    }
    const mailSel = '[class*="requesterMail"],[class*="fromMail"],[class*="senderEmail"],[class*="fromEmail"]';
    for (const el of Array.from(document.querySelectorAll(mailSel))) {
        const text = el.textContent ?? "";
        const e = extractEmail(text);
        if (e) {
            ctx.senderEmail = e;
            ctx.senderDisplayName = extractDisplayName(text);
            break;
        }
    }
    if (!ctx.senderEmail) {
        for (const el of Array.from(document.querySelectorAll('a[href^="mailto:"]'))) {
            const e = extractEmail(el.getAttribute("href")?.replace(/^mailto:/i, "").split("?")[0] ?? "");
            if (e) {
                ctx.senderEmail = e;
                break;
            }
        }
    }
    // Zoho often renders the From line as plain text, e.g.
    // From "Booking.com"<attacker@gmail.com>. Capture the visible display name
    // so brand-impersonation rules work even when there is no mailto: element.
    if (!ctx.senderDisplayName && ctx.senderEmail) {
        const bodyText = document.body?.textContent ?? "";
        const idx = bodyText.toLowerCase().indexOf(ctx.senderEmail);
        if (idx >= 0) {
            const windowText = bodyText.slice(Math.max(0, idx - 90), idx + ctx.senderEmail.length);
            ctx.senderDisplayName = extractDisplayName(windowText);
        }
    }
    ctxCache = ctx;
    ctxTs = now;
    return ctx;
}
function ctx(partial) {
    return { ...partial, ticket: getTicketContext() };
}
// ── Element helpers ────────────────────────────────────────────────────────
/**
 * Extract the real destination URL from a redirect/tracking wrapper.
 * Handles Google (google.com/url?q=...) and Zoho link-protect wrappers,
 * which are common when Gmail-sent phishing emails are rendered in Zoho Desk.
 */
function unwrapRedirectUrl(url) {
    if (!url)
        return null;
    try {
        const u = new URL(url);
        // Google redirect: https://www.google.com/url?q=<encoded-real-url>&...
        if ((u.hostname === "www.google.com" || u.hostname === "google.com") &&
            u.pathname === "/url") {
            const q = u.searchParams.get("q") || u.searchParams.get("url");
            if (q && /^https?:\/\//i.test(q))
                return q;
        }
        // Zoho link-protect: https://mail.zoho.com/link-protect?url=<encoded-real-url>&...
        if (u.hostname.endsWith(".zoho.com") && u.pathname.includes("link-protect")) {
            const q = u.searchParams.get("url");
            if (q && /^https?:\/\//i.test(q))
                return q;
        }
    }
    catch { /* ignore */ }
    return null;
}
function getLinkUrl(a) {
    const raw = a.getAttribute("href")?.trim() || a.href;
    if (!raw || raw === "#")
        return "";
    // Try to unwrap Google / Zoho redirect wrappers.
    // Also check data-saferedirecturl (Gmail's safe-redirect attribute preserves the real URL).
    return (unwrapRedirectUrl(raw) ??
        unwrapRedirectUrl(a.getAttribute("data-saferedirecturl") ?? "") ??
        raw);
}
function isIgnorableHref(h) {
    if (!h || h === "#")
        return true;
    const l = h.toLowerCase();
    return l.startsWith("javascript:") || l.startsWith("mailto:") || l.startsWith("tel:");
}
function getLabel(el) {
    const inner = el.querySelector("button, input[type='button'], input[type='submit']");
    if (inner instanceof HTMLElement) {
        const t = inner.getAttribute("aria-label")?.trim() || inner.textContent?.trim();
        if (t)
            return t.replace(/\s+/g, " ").slice(0, 120);
    }
    const aria = el.getAttribute("aria-label")?.trim();
    if (aria)
        return aria;
    return (el.textContent?.trim().replace(/\s+/g, " ") ?? "").slice(0, 120);
}
function isButtonStyled(a) {
    if (a.querySelector("button, input[type='button'], input[type='submit']"))
        return true;
    if (BUTTON_CLASS_RE.test(a.className?.toString() ?? ""))
        return true;
    if (a.getAttribute("role") === "button")
        return true;
    const s = a.getAttribute("style") ?? "";
    if (/background(-color)?\s*:/i.test(s) && (/padding/i.test(s) || /border-radius/i.test(s)))
        return true;
    try {
        const bg = getComputedStyle(a).backgroundColor;
        const pad = parseFloat(getComputedStyle(a).paddingLeft);
        if (bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent" && pad >= 4)
            return true;
    }
    catch { /* ignore */ }
    return false;
}
function getImgSize(img) {
    const rect = img.getBoundingClientRect();
    return {
        w: img.width || img.naturalWidth || img.offsetWidth || Math.round(rect.width) || 0,
        h: img.height || img.naturalHeight || img.offsetHeight || Math.round(rect.height) || 0
    };
}
function isTrackingPixel(img) {
    const { w, h } = getImgSize(img);
    return w > 0 && h > 0 && w < MIN_TRAP_IMAGE_PX && h < MIN_TRAP_IMAGE_PX;
}
function resolveButtonUrls(el) {
    const urls = [];
    if ((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.formAction)
        urls.push(el.formAction);
    const pa = el.closest("a[href]");
    if (pa instanceof HTMLAnchorElement)
        urls.push(getLinkUrl(pa));
    const oc = el.getAttribute("onclick");
    if (oc)
        urls.push(...DTG().extractUrlsFromOnclick(oc));
    const dh = el.getAttribute("data-href") || el.getAttribute("data-url") || el.getAttribute("data-saferedirecturl");
    if (dh)
        urls.push(dh);
    return [...new Set(urls.filter(Boolean))];
}
// ── In-list-panel guard (only thing we skip) ──────────────────────────────
function inListPanel(el) {
    return Boolean(el.closest(LIST_EXCLUDE));
}
// ── DOM walkers ────────────────────────────────────────────────────────────
function allAnchorsIn(root) {
    const out = [];
    const seen = new Set();
    function walk(n) {
        if (n instanceof HTMLAnchorElement) {
            const h = n.getAttribute("href") ?? n.href;
            if (h && !isIgnorableHref(h) && !seen.has(n)) {
                seen.add(n);
                out.push(n);
            }
        }
        if (n instanceof HTMLIFrameElement) {
            try {
                const d = n.contentDocument;
                if (d?.body)
                    walk(d.body);
            }
            catch { /* cross-origin */ }
        }
        if (n instanceof Element && n.shadowRoot)
            walk(n.shadowRoot);
        n.childNodes.forEach(walk);
    }
    walk(root);
    return out;
}
function allButtonsIn(root) {
    const out = [];
    const seen = new Set();
    function walk(n) {
        if (n instanceof HTMLElement) {
            const isBtn = n instanceof HTMLButtonElement ||
                (n instanceof HTMLInputElement && (n.type === "button" || n.type === "submit"));
            if (isBtn && !seen.has(n)) {
                seen.add(n);
                out.push(n);
            }
            if (n instanceof HTMLIFrameElement) {
                try {
                    const d = n.contentDocument;
                    if (d?.body)
                        walk(d.body);
                }
                catch { /* cross-origin */ }
            }
            if (n.shadowRoot)
                walk(n.shadowRoot);
        }
        n.childNodes.forEach(walk);
    }
    walk(root);
    return out;
}
// ── Risk analysis ──────────────────────────────────────────────────────────
function pushRisk(seen, risks, el, url, analysis, kind) {
    if (!analysis.dangerous || analysis.confidence < DTG().MIN_CONFIDENCE)
        return;
    if (inListPanel(el))
        return;
    const label = getLabel(el);
    const key = `${kind}|${url}|${el.tagName}|${label}`;
    if (seen.has(key))
        return;
    seen.add(key);
    risks.push({ element: el, targetUrl: url, displayLabel: label, reason: analysis.reason, confidence: analysis.confidence, kind });
}
function analyzeAnchor(a, host, seen, risks) {
    const url = getLinkUrl(a);
    if (isIgnorableHref(url))
        return;
    const label = getLabel(a);
    const btnStyled = isButtonStyled(a);
    const imgs = Array.from(a.querySelectorAll("img")).filter((i) => i instanceof HTMLImageElement);
    if (imgs.length > 0) {
        let analyzed = false;
        for (const img of imgs) {
            if (isTrackingPixel(img))
                continue;
            analyzed = true;
            const { w, h } = getImgSize(img);
            const r = DTG().analyzeNavigationTarget(url, host, window.location.href, ctx({ kind: "image-link", imgSrc: img.src, imgWidth: w, imgHeight: h, label, buttonStyled: btnStyled }));
            pushRisk(seen, risks, a, url, r, "image-link");
        }
        if (analyzed)
            return;
    }
    const kind = btnStyled ? "button-link" : "text-link";
    const r = DTG().analyzeNavigationTarget(url, host, window.location.href, ctx({ kind, label, buttonStyled: btnStyled }));
    pushRisk(seen, risks, a, url, r, kind);
}
function analyzeButton(el, host, seen, risks) {
    const label = getLabel(el);
    for (const url of resolveButtonUrls(el)) {
        const r = DTG().analyzeNavigationTarget(url, host, window.location.href, ctx({ kind: "button-element", label, buttonStyled: true }));
        pushRisk(seen, risks, el, url, r, "button-element");
    }
}
function scanRoot(root, host, seen, risks) {
    const anchorsSeen = new Set();
    const btnSeen = new Set();
    for (const a of allAnchorsIn(root)) {
        if (anchorsSeen.has(a))
            continue;
        anchorsSeen.add(a);
        analyzeAnchor(a, host, seen, risks);
    }
    for (const btn of allButtonsIn(root)) {
        if (btnSeen.has(btn))
            continue;
        btnSeen.add(btn);
        if (btn.closest("a[href]") instanceof HTMLAnchorElement)
            continue;
        analyzeButton(btn, host, seen, risks);
    }
    // Fast path: directly query known trap URLs
    for (const sel of ['a[href*="share.google"]', 'a[href*="share-google"]', '[data-href*="share.google"]']) {
        root.querySelectorAll(sel).forEach((node) => {
            if (!(node instanceof HTMLAnchorElement) || anchorsSeen.has(node))
                return;
            if (inListPanel(node))
                return;
            anchorsSeen.add(node);
            analyzeAnchor(node, host, seen, risks);
        });
    }
    // Clickable images not inside <a>
    root.querySelectorAll("img").forEach((node) => {
        if (!(node instanceof HTMLImageElement))
            return;
        if (isTrackingPixel(node))
            return;
        if (node.closest("a[href]"))
            return;
        let el = node;
        for (let d = 0; el && d < 6; d++, el = el.parentElement) {
            const dh = el.getAttribute("data-href") || el.getAttribute("data-url") || el.getAttribute("onclick");
            if (!dh)
                continue;
            const urls = dh.startsWith("http") ? [dh] : DTG().extractUrlsFromOnclick(dh);
            for (const url of urls) {
                const { w, h } = getImgSize(node);
                const r = DTG().analyzeNavigationTarget(url, host, window.location.href, ctx({ kind: "image-link", imgSrc: node.src, imgWidth: w, imgHeight: h, label: getLabel(el) }));
                if (r.dangerous) {
                    pushRisk(seen, risks, el, url, r, "image-link");
                    return;
                }
            }
        }
    });
}
function findRiskyTargets() {
    if (!shouldActivate())
        return [];
    if (!DTG())
        return [];
    const seen = new Set();
    const risks = [];
    const host = pageHost();
    scanRoot(document.body, host, seen, risks);
    return risks.sort((a, b) => b.confidence - a.confidence);
}
// ── CBS Hunter Panel ────────────────────────────────────────────────────────
const PANEL_ID = "cbs-hunter-panel";
function escapeHtml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function panelKey(risks) {
    return risks.map((r) => `${r.kind}|${r.targetUrl}|${r.displayLabel}`).sort().join("||");
}
async function isPanelDismissed(key) {
    if (!extensionAlive())
        return false;
    try {
        const d = await chrome.storage.session.get(DISMISS_STORAGE_KEY);
        return Boolean(d[DISMISS_STORAGE_KEY]?.[key]);
    }
    catch {
        return false;
    }
}
async function rememberDismissed(key) {
    if (!extensionAlive())
        return;
    try {
        const d = await chrome.storage.session.get(DISMISS_STORAGE_KEY);
        const map = d[DISMISS_STORAGE_KEY] ?? {};
        map[key] = Date.now();
        await chrome.storage.session.set({ [DISMISS_STORAGE_KEY]: map });
    }
    catch { /* ignore */ }
}
function applyHighlights(risks) {
    if (!extensionAlive())
        return;
    const uniq = new Map();
    for (const r of risks)
        uniq.set(r.element, r.targetUrl);
    activeHighlights = Array.from(uniq.entries()).map(([element, targetUrl]) => ({ element, targetUrl }));
    activeHighlights.forEach(({ element: el, targetUrl }) => {
        if (!targetUrl)
            return;
        // Guard the entire per-element body: flagged elements can live inside
        // same-origin iframes or framework-managed DOM that may reject mutations.
        try {
            if (el instanceof HTMLAnchorElement || el.tagName === "A")
                el.classList.add("dtg-highlight-link");
            else
                el.classList.add("dtg-highlight-button");
            el.querySelectorAll("img").forEach((img) => img.classList.add("dtg-highlight"));
            flaggedElements.add(el);
            // Set tooltip directly on the link so hovering anywhere on it shows the warning.
            el.setAttribute("data-cbs-tooltip", "CBS Hunter: Phishing trap \u2014 do not click");
            // Inject a pulsing red badge immediately after the element (only once per element).
            // Create the badge in the element's OWN document so insertion never crosses
            // documents (the scanner descends into same-origin iframes).
            if (el.parentNode && !el.nextElementSibling?.hasAttribute("data-cbs-badge")) {
                const doc = el.ownerDocument ?? document;
                const badge = doc.createElement("span");
                badge.className = "cbs-threat-badge";
                badge.setAttribute("data-cbs-badge", "1");
                badge.setAttribute("aria-label", "Phishing trap detected");
                const icon = doc.createElement("span");
                icon.className = "cbs-badge-icon";
                icon.textContent = "\u26A0"; // ⚠
                const text = doc.createElement("span");
                text.className = "cbs-badge-text";
                text.textContent = "TRAP";
                badge.appendChild(icon);
                badge.appendChild(text);
                el.insertAdjacentElement("afterend", badge);
            }
        }
        catch { /* element in a managed/cross-doc context — skip safely */ }
    });
}
function clearWarnings(opts) {
    document.getElementById(PANEL_ID)?.remove();
    document.querySelectorAll("[data-cbs-badge]").forEach((b) => b.remove());
    if (opts?.removeHighlights === false)
        return;
    clearHighlights();
}
function clearHighlights() {
    for (const { element: el } of activeHighlights) {
        try {
            el.classList.remove("dtg-highlight-link", "dtg-highlight-button");
            el.removeAttribute("data-cbs-tooltip");
            el.querySelectorAll("img").forEach((img) => img.classList.remove("dtg-highlight"));
            // Remove the badge sibling (covers badges inside same-origin iframes too).
            const sib = el.nextElementSibling;
            if (sib?.hasAttribute("data-cbs-badge"))
                sib.remove();
            flaggedElements.delete(el);
        }
        catch { /* ignore */ }
    }
    activeHighlights = [];
}
/**
 * Serialize RiskyTarget[] → SerializedRisk[] for cross-frame postMessage.
 */
function serializeRisks(risks) {
    return risks.map(({ targetUrl, displayLabel, reason, confidence, kind }) => ({ targetUrl, displayLabel, reason, confidence, kind }));
}
/**
 * Build and display the CBS Hunter side panel in the MAIN frame document.
 * Called only when window === window.top.
 */
async function showPanel(risks) {
    const key = panelKey(risks);
    if (key === lastBannerKey)
        return;
    if (await isPanelDismissed(key))
        return;
    lastBannerKey = key;
    const existingPanel = document.getElementById(PANEL_ID);
    let logoUrl = "";
    try {
        if (extensionAlive() && chrome.runtime?.getURL) {
            logoUrl = chrome.runtime.getURL("cbs-hunter-logo.png");
        }
    }
    catch { /* context invalidated — render without logo */ }
    function riskItem(r, idx) {
        const realUrl = escapeHtml(r.targetUrl);
        const labelText = r.displayLabel.trim();
        const labelIsUrl = /^https?:\/\//i.test(labelText);
        const labelDiffers = labelText.length > 0 &&
            !r.targetUrl.toLowerCase().includes(labelText.toLowerCase().slice(0, 20));
        const fakeRow = labelIsUrl && labelDiffers
            ? `<span class="cbs-item-row">
           <span class="cbs-item-row-label">Shown as&nbsp;</span>
           <span class="cbs-item-code cbs-fake">${escapeHtml(labelText.slice(0, 80))}</span>
         </span>`
            : "";
        return `<div class="cbs-item">
      <span class="cbs-item-reason">
        <span class="cbs-item-num">${idx + 1}</span>${escapeHtml(r.reason)}
      </span>
      ${fakeRow}
      <span class="cbs-item-row">
        <span class="cbs-item-row-label">Real link&nbsp;</span>
        <span class="cbs-item-code">${realUrl}</span>
      </span>
    </div>`;
    }
    const extra = risks.length > MAX_BANNER_ITEMS ? risks.length - MAX_BANNER_ITEMS : 0;
    const shown = risks.slice(0, MAX_BANNER_ITEMS);
    const panel = document.createElement("div");
    panel.id = PANEL_ID;
    panel.setAttribute("role", "alert");
    panel.innerHTML = `
    <div class="cbs-header">
      ${logoUrl ? `<img class="cbs-logo" src="${logoUrl}" alt="CBS Hunter">` : ""}
      <div class="cbs-brand">
        <span class="cbs-brand-top">Crown Business Solutions</span>
        <span class="cbs-brand-hunter">Hunter</span>
      </div>
    </div>
    <div class="cbs-alert-strip">
      <span class="cbs-alert-icon">⚠</span>
      <span class="cbs-alert-title">Phishing detected</span>
      <span class="cbs-alert-count">${risks.length} item${risks.length === 1 ? "" : "s"}</span>
    </div>
    <div class="cbs-body">
      ${shown.map(riskItem).join("")}
      ${extra > 0 ? `<div class="cbs-item" style="text-align:center;color:#806a30;font-size:11px;">…and ${extra} more</div>` : ""}
    </div>
    <div class="cbs-footer">
      <button type="button" class="cbs-btn cbs-btn-dismiss">✕&nbsp; Dismiss</button>
    </div>`;
    const bindDismiss = (target) => {
        target.querySelector(".cbs-btn-dismiss")?.addEventListener("click", () => {
            void rememberDismissed(key);
            target.classList.remove("cbs-visible");
            setTimeout(() => target.remove(), 350);
        });
    };
    if (existingPanel) {
        // Risk results can arrive twice: once from the main-frame scan and once from
        // the email iframe postMessage. Keep the SAME root element visible and only
        // update its content; replacing the root can look like a second animation.
        existingPanel.innerHTML = panel.innerHTML;
        existingPanel.classList.add("cbs-visible");
        bindDismiss(existingPanel);
    }
    else {
        document.body.appendChild(panel);
        bindDismiss(panel);
        // Trigger slide-in animation only for the first render.
        requestAnimationFrame(() => requestAnimationFrame(() => panel.classList.add("cbs-visible")));
    }
}
// ── Main scan loop ─────────────────────────────────────────────────────────
/**
 * Build a short fingerprint of the visible email body so we can detect when
 * Zoho silently loads a different conversation without changing the tab URL
 * (common in the multi-conversation ticket view).
 */
function emailFingerprint() {
    // Prefer the dedicated email content container; fall back to the ticket-detail RHS panel.
    const EMAIL_SELECTORS = [
        '[class*="mailContent"]', '[class*="mailWrapper"]', '[class*="thrdPlain"]',
        '[class*="msgContent"]', '[class*="emailContent"]', '[class*="threadBody"]',
        '[class*="richtext"]', '[class*="threadDetail"]', '[class*="conversation"]'
    ];
    const visibleTextWithoutHunterUi = (el) => {
        const clone = el.cloneNode(true);
        if (!(clone instanceof Element))
            return "";
        // Ignore our injected badges/panel; otherwise the second scan sees "TRAP"
        // as new email text, clears the panel, and replays the warning animation.
        clone.querySelectorAll("[data-cbs-badge], #cbs-hunter-panel").forEach((n) => n.remove());
        return clone.textContent?.replace(/\s+/g, " ").trim().slice(0, 200) ?? "";
    };
    for (const sel of EMAIL_SELECTORS) {
        const el = document.querySelector(sel);
        if (el && !el.closest(LIST_EXCLUDE)) {
            const t = visibleTextWithoutHunterUi(el);
            if (t.length > 20)
                return t;
        }
    }
    return "";
}
async function scanAndWarn() {
    // Wrap the ENTIRE body so the scan loop can never produce an uncaught promise
    // rejection — e.g. "Extension context invalidated" after the extension reloads.
    try {
        // Stop entirely if the extension was reloaded/updated under us.
        if (!extensionAlive()) {
            teardown();
            return;
        }
        if (!shouldActivate())
            return;
        // Detect when Zoho switches to a different conversation (same URL, different content).
        // Do NOT clear the panel yet: Zoho can mutate the same email during load.
        // We scan first, then clear only if the new content has no risks.
        const fp = emailFingerprint();
        const contentChanged = Boolean(fp && fp !== lastEmailFingerprint);
        if (fp && fp !== lastEmailFingerprint) {
            lastEmailFingerprint = fp;
            ctxCache = null;
            ctxTs = 0;
        }
        const risks = findRiskyTargets();
        if (risks.length === 0) {
            if (contentChanged) {
                clearWarnings();
                lastBannerKey = "";
            }
            return;
        }
        // If the content changed but phishing is still present, refresh highlights
        // without removing the already-visible panel (prevents double animation).
        if (contentChanged)
            clearHighlights();
        // Always apply element highlights in the current frame.
        applyHighlights(risks);
        const serialized = serializeRisks(risks);
        if (window === window.top) {
            // Main frame: show the CBS Hunter panel directly.
            await showPanel(serialized);
        }
        else {
            // Sub-frame (email iframe): send risks up to the main frame.
            try {
                window.parent.postMessage({ type: "CBS_HUNTER_IFRAME_RISKS", risks: serialized }, "*");
            }
            catch { /* cross-origin parent blocked postMessage */ }
        }
        if (extensionAlive()) {
            try {
                chrome.runtime.sendMessage({
                    type: "DOWNLOAD_TRAP_DETECTED",
                    count: risks.length,
                    url: window.location.href,
                    frame: window !== window.top
                });
            }
            catch { /* ignore */ }
        }
    }
    catch {
        // Any failure (context loss, DOM rejection) — stop the orphaned script quietly.
        teardown();
    }
}
function scheduleScan() {
    if (stopped)
        return;
    if (scanTimer)
        clearTimeout(scanTimer);
    scanTimer = setTimeout(() => void scanAndWarn(), 350);
}
function onRouteChange() {
    const url = location.href;
    if (url === lastWatchUrl)
        return;
    lastWatchUrl = url;
    ctxCache = null;
    ctxTs = 0;
    clearWarnings();
    lastBannerKey = "";
    if (!watching) {
        startAttempts = 0;
        startWatching();
    }
    else
        void scanAndWarn();
}
function startWatching() {
    if (watching)
        return;
    if (!DTG())
        return;
    if (!shouldActivate()) {
        if (startAttempts++ < 60)
            setTimeout(startWatching, 800);
        return;
    }
    watching = true;
    lastWatchUrl = location.href;
    console.info("[DTG] watching:", location.href);
    void scanAndWarn();
    const domObserver = new MutationObserver(scheduleScan);
    domObserver.observe(document.documentElement, {
        childList: true, subtree: true, attributes: true,
        attributeFilter: ["href", "src", "onclick", "formaction", "data-href", "data-url"]
    });
    observers.push(domObserver);
    intervals.push(setInterval(() => void scanAndWarn(), 5000));
    intervals.push(setInterval(onRouteChange, 1500));
    // Watchdog: if the extension is reloaded, stop everything quietly.
    intervals.push(setInterval(() => { if (!extensionAlive())
        teardown(); }, 2000));
    // Delayed scans — email content in Zoho often loads 1-5s after document_idle
    for (const ms of [300, 800, 1500, 2500, 4000, 7000, 12000, 20000]) {
        setTimeout(() => void scanAndWarn(), ms);
    }
    // Attach to iframes when they load
    const attachFrame = (frame) => {
        frame.addEventListener("load", () => { setTimeout(() => void scanAndWarn(), 300); });
        setTimeout(() => void scanAndWarn(), 800);
    };
    document.querySelectorAll("iframe").forEach((f) => attachFrame(f));
    const iframeObserver = new MutationObserver((muts) => {
        for (const m of muts)
            m.addedNodes.forEach((n) => {
                if (n instanceof HTMLIFrameElement)
                    attachFrame(n);
                if (n instanceof Element)
                    n.querySelectorAll("iframe").forEach((f) => attachFrame(f));
            });
    });
    iframeObserver.observe(document.documentElement, { childList: true, subtree: true });
    observers.push(iframeObserver);
}
// Expose rescan hook so the IIFE guard can call it on re-injection
globalThis.__dtgRescan = () => {
    ctxCache = null;
    ctxTs = 0;
    lastBannerKey = "";
    lastEmailFingerprint = "";
    void scanAndWarn();
};
// Boot
{
    const g = globalThis;
    if (!g.__dtgInit) {
        g.__dtgInit = true;
        if (document.readyState === "loading")
            document.addEventListener("DOMContentLoaded", startWatching);
        else
            startWatching();
    }
}
try {
    chrome.runtime.onMessage.addListener((message) => {
        if (message?.type === "DTG_CLEAR_BANNER") {
            clearWarnings();
            lastBannerKey = "";
        }
    });
}
catch { /* context invalidated at load time */ }
// Main frame: receive serialized risks from cross-origin email iframes and show the panel.
if (window === window.top) {
    window.addEventListener("message", (e) => {
        if (!e.data || e.data.type !== "CBS_HUNTER_IFRAME_RISKS")
            return;
        const risks = e.data.risks;
        if (!Array.isArray(risks) || risks.length === 0)
            return;
        showPanel(risks).catch(() => { });
    });
}
// ── Click / keyboard blocking ──────────────────────────────────────────────
function getFlagged(target) {
    if (!target)
        return null;
    const flagged = target.closest("a.dtg-highlight-link, .dtg-highlight-button, img.dtg-highlight");
    if (!flagged)
        return null;
    const el = flagged instanceof HTMLAnchorElement ? flagged :
        flagged.closest("a.dtg-highlight-link") ??
            flagged.closest(".dtg-highlight-button") ??
            (flagged instanceof HTMLElement ? flagged : null);
    if (!el)
        return null;
    const ref = activeHighlights.find((h) => h.element === el);
    const url = ref?.targetUrl ?? (el instanceof HTMLAnchorElement ? getLinkUrl(el) : resolveButtonUrls(el)[0] ?? "");
    return { el, url };
}
function block(e, dest) {
    if (window.confirm("DOWNLOAD TRAP WARNING\n\nThis may download malware when clicked.\n\n" +
        (dest ? `Destination: ${dest}\n\n` : "") +
        "Continue anyway?"))
        return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
}
document.addEventListener("click", (e) => { const h = getFlagged(e.target); if (h)
    block(e, h.url); }, true);
document.addEventListener("auxclick", (e) => { const h = getFlagged(e.target); if (h)
    block(e, h.url); }, true);
document.addEventListener("contextmenu", (e) => {
    const h = getFlagged(e.target);
    if (!h)
        return;
    e.preventDefault();
    window.alert(`Download trap: do not open this link.\nDestination: ${h.url}`);
}, true);
document.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ")
        return;
    const h = getFlagged(e.target);
    if (h)
        block(e, h.url);
}, true);

})();
