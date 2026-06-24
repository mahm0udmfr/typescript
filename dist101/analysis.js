;(function(){if(globalThis.__dtgAnalysisLoaded)return;globalThis.__dtgAnalysisLoaded=true;
/** Pure URL / navigation analysis (no DOM). Phase A: unified risk scoring. */
const MIN_CONFIDENCE = 70;
const LARGE_IMAGE_MIN_PX = 120;
const EXECUTABLE_EXTENSIONS = new Set([
    ".exe", ".msi", ".msp", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".dll", ".sys",
    ".docm", ".xlsm", ".pptm", ".jar", ".appimage"
]);
const ARCHIVE_EXTENSIONS = new Set([
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".iso", ".dmg", ".pkg", ".apk", ".deb", ".rpm"
]);
const IMAGE_EXTENSIONS = new Set([
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"
]);
const TRUSTED_LINK_HOSTS = [
    "zoho.com", "zohocdn.com", "zohostatic.com", "zohopublic.com",
    "zappsusercontent.com", "zohostratus.com", "zohocorpcloud.com",
    "imgur.com", "i.imgur.com", "eviivo.com",
    "booking.com", "airbnb.com", "expedia.com",
    // CBS partner links. Keep this specific: do not trust all *.go.link.
    "perk.go.link"
];
const DOWNLOAD_TRAP_HOST_EXACT = new Set([
    "share.google",
    "search.app", // Google link-redirect that hides the true destination
    "publick-gstx.com" // confirmed phishing domain seen in multiple Booking.com lures
]);
const DOWNLOAD_TRAP_HOST_CONTAINS = [
    "share-google", "sharegoogle", "drive-google"
];
const IMAGE_LURE_HOSTS = [
    "imgur.com", "i.imgur.com", "ibb.co", "i.ibb.co", "postimg.cc", "postimages.org"
];
const CTA_KEYWORDS = [
    // Reply / messaging
    "send reply", "reply now", "click here", "respond", "reply",
    // View / open documents
    "download", "view invoice", "view document", "open attachment", "view details",
    "view feedback", "view complaint", "view report", "view case", "view claim",
    "view dispute", "view summary", "view message", "view photo", "view photos",
    "view documentation", "photo documentation", "supporting evidence",
    "supporting document", "read message", "see details", "check details",
    "open report", "review", "take action", "open report",
    // Auth
    "confirm", "verify", "update payment", "sign in", "log in", "reset password",
    // Action verbs commonly used in phishing buttons
    "process", "proceed", "continue", "accept", "approve", "authorize", "activate",
    "validate", "cancel", "cancellation", "process cancellation", "manage booking",
    "update details", "confirm booking", "make payment", "pay now", "pay",
    "complete", "resolve", "submit", "respond now", "act now", "get started"
];
const URGENCY_SUBJECT_KEYWORDS = [
    "urgent", "payment", "invoice", "verify", "suspended", "action required",
    "booking", "reservation", "password", "security alert", "overdue", "refund",
    "complaint", "compensation", "dispute", "chargeback", "penalty", "deadline"
];
const BRAND_IMPERSONATION_KEYWORDS = [
    "hotel", "marriott", "hilton", "booking", "airbnb", "expedia", "paypal",
    "microsoft", "google", "apple", "bank", "reservation", "stay"
];
const FREE_WEBMAIL_DOMAINS = [
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "protonmail.com", "mail.com", "aol.com",
    "libero.it", "virgilio.it", "gmx.com", "yandex.com", "mail.ru"
];
function extensionFromPath(pathname) {
    const segment = pathname.split("/").pop()?.split("?")[0] ?? "";
    const lower = segment.toLowerCase();
    if (lower.endsWith(".tar.gz"))
        return ".tar.gz";
    if (lower.endsWith(".tar.bz2"))
        return ".tar.bz2";
    const dot = segment.lastIndexOf(".");
    if (dot <= 0)
        return null;
    return segment.slice(dot).toLowerCase();
}
function extensionFromUrlParts(pathname, search, hash) {
    const fromPath = extensionFromPath(pathname);
    if (fromPath && isDownloadExtension(fromPath))
        return fromPath;
    const queryMatch = search.match(/\.(exe|msi|zip|7z|rar|dmg|pkg|apk|bat|cmd|js|docm|xlsm|pptm)(?:[&=]|$)/i);
    if (queryMatch)
        return queryMatch[0].replace(/[&=]$/, "").toLowerCase();
    const hashMatch = hash.match(/\.(exe|msi|zip|7z|rar|dmg|pkg|apk|bat|cmd|js|docm|xlsm|pptm)$/i);
    if (hashMatch)
        return hashMatch[0].toLowerCase();
    return fromPath;
}
function isDownloadExtension(ext) {
    return EXECUTABLE_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext);
}
function isImagePreviewUrl(parsed) {
    const ext = extensionFromPath(parsed.pathname);
    if (ext && IMAGE_EXTENSIONS.has(ext))
        return true;
    return /\.(jpe?g|png|gif|webp|svg|bmp|ico)(\?|$)/i.test(parsed.pathname);
}
function normalizeHostname(hostname) {
    try {
        return hostname.toLowerCase().replace(/^www\./, "");
    }
    catch {
        return hostname.toLowerCase();
    }
}
function hostsAreRelated(a, b) {
    const left = normalizeHostname(a);
    const right = normalizeHostname(b);
    if (left === right)
        return true;
    return left.endsWith("." + right) || right.endsWith("." + left);
}
function isShareGoogleVariant(hostname) {
    const host = normalizeHostname(hostname);
    if (host === "share.google" || host.endsWith(".share.google"))
        return true;
    if (host.includes("share-google") || host.includes("sharegoogle"))
        return true;
    try {
        const decoded = new URL(`http://${host}`).hostname.toLowerCase();
        return decoded === "share.google" || decoded.endsWith(".share.google");
    }
    catch {
        return false;
    }
}
function isPortalInternalHost(hostname, pageHost) {
    const h = normalizeHostname(hostname);
    const page = normalizeHostname(pageHost);
    if (h === page)
        return true;
    return h.endsWith("." + page);
}
function isTrustedHost(hostname, pageHost) {
    if (isPortalInternalHost(hostname, pageHost))
        return true;
    const h = normalizeHostname(hostname);
    return TRUSTED_LINK_HOSTS.some((t) => h === t || h.endsWith("." + t));
}
function isImageLureHost(hostname) {
    const h = normalizeHostname(hostname);
    return IMAGE_LURE_HOSTS.some((t) => h === t || h.endsWith("." + t) || h.includes(t));
}
function isSuspiciousCtaLabel(label) {
    const text = label.trim().toLowerCase().replace(/\s+/g, " ");
    if (!text || text.length > 80)
        return false;
    return CTA_KEYWORDS.some((kw) => text.includes(kw));
}
function isFreeWebmailHost(emailOrDomain) {
    const raw = emailOrDomain.trim().toLowerCase();
    const domain = raw.includes("@") ? raw.split("@").pop() ?? "" : raw;
    if (!domain)
        return false;
    return FREE_WEBMAIL_DOMAINS.some((d) => domain === d || domain.endsWith("." + d));
}
function hasUrgencyLanguage(text) {
    const lower = text.trim().toLowerCase();
    if (!lower)
        return false;
    return URGENCY_SUBJECT_KEYWORDS.some((kw) => lower.includes(kw));
}
function hasBrandImpersonationLanguage(text) {
    const lower = text.trim().toLowerCase();
    if (!lower)
        return false;
    return BRAND_IMPERSONATION_KEYWORDS.some((kw) => lower.includes(kw));
}
/** Pull a domain explicitly shown as a URL in link text (not brand names like "Booking.com"). */
function extractDomainFromText(text) {
    const trimmed = text.trim();
    if (!trimmed)
        return null;
    const urlMatch = trimmed.match(/https?:\/\/([^\s/]+)/i);
    if (urlMatch?.[1])
        return normalizeHostname(urlMatch[1]);
    const wwwMatch = trimmed.match(/\bwww\.([a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)+)\b/i);
    if (wwwMatch?.[1])
        return normalizeHostname(wwwMatch[1]);
    const pathMatch = trimmed.match(/\b([a-z0-9][-a-z0-9]*\.[a-z]{2,})\/[^\s]/i);
    if (pathMatch?.[1])
        return normalizeHostname(pathMatch[1]);
    return null;
}
function checkHrefTextMismatch(label, linkHost, pageHost) {
    const mentioned = extractDomainFromText(label);
    if (!mentioned)
        return null;
    const actual = normalizeHostname(linkHost);
    if (hostsAreRelated(mentioned, actual))
        return null;
    if (isPortalInternalHost(actual, pageHost))
        return null;
    if (isTrustedHost(actual, pageHost))
        return null;
    // Only fire when the label mentions a domain we recognise as trustworthy —
    // that's the deliberate deception: making the link *look* like a trusted site.
    if (!isTrustedHost(mentioned, pageHost))
        return null;
    // Higher score when the label contains a full URL (e.g. https://booking.com/complaint?...)
    // because the attacker explicitly forged a trusted-looking URL as the visible text.
    const hasFullUrl = /https?:\/\//i.test(label);
    const score = hasFullUrl ? 88 : 75;
    return {
        score,
        reason: `Link appears to go to "${mentioned}" but actually goes to ${actual}`
    };
}
function checkDownloadTrapHost(hostname) {
    const host = normalizeHostname(hostname);
    if (DOWNLOAD_TRAP_HOST_EXACT.has(host) || isShareGoogleVariant(host)) {
        return {
            dangerous: true,
            reason: `Links to "${host}" — known to download a file when clicked`,
            confidence: 98
        };
    }
    for (const fragment of DOWNLOAD_TRAP_HOST_CONTAINS) {
        if (host.includes(fragment)) {
            return {
                dangerous: true,
                reason: `Links to "${host}" — may download a file when clicked`,
                confidence: 92
            };
        }
    }
    return { dangerous: false, reason: "", confidence: 0 };
}
function extractUrlsFromOnclick(onclick) {
    const urls = [];
    const patterns = [
        /location(?:\.href)?\s*=\s*['"]([^'"]+)['"]/gi,
        /window\.open\s*\(\s*['"]([^'"]+)['"]/gi,
        /document\.location\s*=\s*['"]([^'"]+)['"]/gi
    ];
    for (const re of patterns) {
        let m;
        while ((m = re.exec(onclick)) !== null) {
            if (m[1]?.startsWith("http"))
                urls.push(m[1]);
        }
    }
    return urls;
}
function finalizeRiskScore(signals) {
    if (signals.length === 0)
        return { dangerous: false, reason: "", confidence: 0 };
    const sorted = [...signals].sort((a, b) => b.score - a.score);
    const total = Math.min(100, sorted.reduce((sum, s) => sum + s.score, 0));
    if (total < MIN_CONFIDENCE)
        return { dangerous: false, reason: "", confidence: total };
    const reason = sorted
        .slice(0, 2)
        .map((s) => s.reason)
        .join("; ");
    return { dangerous: true, reason, confidence: total };
}
function isLargeImage(width, height) {
    if (!width || !height)
        return false;
    return Math.max(width, height) >= LARGE_IMAGE_MIN_PX;
}
function collectImageSignals(host, pageHost, parsed, context, imgHost) {
    if (context.kind !== "image-link")
        return [];
    const signals = [];
    const untrusted = !isTrustedHost(host, pageHost);
    const notImageDest = !isImagePreviewUrl(parsed);
    if (!untrusted || !notImageDest)
        return signals;
    // Baseline: any clickable image going to an untrusted host is suspicious.
    // Even if image dimensions are unavailable (0), ticket context can push this
    // over the threshold (e.g. gmail sender + brand impersonation = +36).
    signals.push({
        score: 32,
        reason: `Clickable image links to untrusted host ${host}`
    });
    // Large image is a stronger signal — adds on top of the baseline.
    if (isLargeImage(context.imgWidth, context.imgHeight)) {
        signals.push({
            score: 42,
            reason: `Large clickable image (${context.imgWidth}×${context.imgHeight}px) links to ${host}`
        });
    }
    const imgOnLureCdn = isImageLureHost(imgHost);
    const linkIsImgur = imgHost.includes("imgur.com") && host.includes("imgur.com");
    if (imgOnLureCdn && !linkIsImgur) {
        signals.push({
            score: 28,
            reason: `Image hosted on lure CDN (${imgHost}) links to ${host}`
        });
    }
    return signals;
}
function collectButtonSignals(host, pageHost, context) {
    const isButtonish = context.kind === "button-element" ||
        context.kind === "button-link" ||
        context.buttonStyled === true;
    if (!isButtonish || isTrustedHost(host, pageHost))
        return [];
    const signals = [];
    const label = context.label ?? "";
    if (isSuspiciousCtaLabel(label)) {
        signals.push({
            score: 72,
            reason: `Suspicious "${label.trim()}" button links to ${host}`
        });
    }
    else if (context.buttonStyled && context.kind === "button-link") {
        signals.push({
            score: 24,
            reason: `Styled button in ticket links to untrusted host ${host}`
        });
    }
    return signals;
}
function collectTextCtaSignals(host, pageHost, context) {
    if (context.kind !== "text-link" || isTrustedHost(host, pageHost))
        return [];
    const label = context.label ?? "";
    if (!isSuspiciousCtaLabel(label))
        return [];
    return [{
            score: 58,
            reason: `Suspicious "${label.trim()}" link points to unrelated host ${host}`
        }];
}
function collectTicketContextSignals(host, pageHost, context) {
    const ticket = context.ticket;
    if (!ticket || isTrustedHost(host, pageHost))
        return [];
    const signals = [];
    const senderEmail = ticket.senderEmail?.trim() ?? "";
    const senderName = ticket.senderDisplayName?.trim() ?? "";
    const subject = ticket.subject?.trim() ?? "";
    const fromFreeWebmail = senderEmail ? isFreeWebmailHost(senderEmail) : false;
    if (fromFreeWebmail) {
        signals.push({
            score: 14,
            reason: `External link from free webmail sender (${senderEmail.split("@")[1]})`
        });
    }
    if (subject && hasUrgencyLanguage(subject)) {
        signals.push({
            score: 12,
            reason: "Ticket subject uses urgent/payment language with external link"
        });
    }
    const impersonationText = `${senderName} ${subject}`.trim();
    if (impersonationText && hasBrandImpersonationLanguage(impersonationText)) {
        if (fromFreeWebmail) {
            signals.push({
                score: 22,
                reason: "Sender appears to impersonate a known brand (free email + business language)"
            });
        }
        else {
            // Non-free-webmail sender whose domain does not match the brand being impersonated.
            // e.g. "wordpress@berkemeier-recht.de" impersonating Booking.com — classic compromised
            // third-party domain used as a phishing launch pad.
            const senderDomain = senderEmail ? (senderEmail.split("@").pop() ?? "") : "";
            const senderMatchesBrand = BRAND_IMPERSONATION_KEYWORDS.some((b) => senderDomain.includes(b));
            if (!senderMatchesBrand && senderDomain) {
                signals.push({
                    score: 18,
                    reason: `Sender domain (${senderDomain}) does not match the brand being impersonated`
                });
            }
        }
    }
    return signals;
}
/** Is this an external (untrusted) clickable call-to-action? */
function isExternalActionable(host, pageHost, context) {
    if (isTrustedHost(host, pageHost))
        return false;
    return (context.kind === "button-element" ||
        context.kind === "button-link" ||
        context.buttonStyled === true ||
        isSuspiciousCtaLabel(context.label ?? ""));
}
/**
 * Generalizing signal: the email impersonates a known brand, but its action
 * button/link points to a domain that is neither the brand's official domain
 * nor the support portal. This is the universal phishing signature — it catches
 * NEW, never-before-seen malicious domains without any hardcoded list, because a
 * genuine "Booking.com" email always links back to booking.com (a trusted host),
 * while a fake one links somewhere else.
 */
function collectBrandCtaComboSignals(host, pageHost, context) {
    const ticket = context.ticket;
    if (!ticket || isTrustedHost(host, pageHost))
        return [];
    if (!isExternalActionable(host, pageHost, context))
        return [];
    const senderName = ticket.senderDisplayName?.trim() ?? "";
    const subject = ticket.subject?.trim() ?? "";
    const senderEmail = ticket.senderEmail?.trim() ?? "";
    const impersonationText = `${senderName} ${subject}`.trim();
    if (!impersonationText || !hasBrandImpersonationLanguage(impersonationText))
        return [];
    // Don't fire if the sender's own domain legitimately matches the brand
    // (e.g. a real hotel whose domain contains its brand name).
    const senderDomain = senderEmail ? (senderEmail.split("@").pop() ?? "") : "";
    const senderMatchesBrand = BRAND_IMPERSONATION_KEYWORDS.some((b) => senderDomain.includes(b));
    if (senderMatchesBrand)
        return [];
    return [{
            score: 45,
            reason: `Email impersonates a known brand but its action button links to an unrelated site (${host})`
        }];
}
function analyzeNavigationTarget(url, pageHost, baseUrl, context) {
    if (!url || url.startsWith("javascript:") || url.startsWith("data:") || url.startsWith("mailto:")) {
        return { dangerous: false, reason: "", confidence: 0 };
    }
    try {
        const parsed = new URL(url, baseUrl);
        const host = parsed.hostname.toLowerCase();
        const trapHost = checkDownloadTrapHost(host);
        if (trapHost.dangerous) {
            if (context.kind === "button-link" || context.kind === "button-element") {
                return {
                    ...trapHost,
                    reason: trapHost.reason.replace("Links to", "Button links to")
                };
            }
            return trapHost;
        }
        const ext = extensionFromUrlParts(parsed.pathname, parsed.search, parsed.hash);
        if (ext && isDownloadExtension(ext)) {
            const label = context.kind === "button-link" || context.kind === "button-element" ? "Button" : "Link";
            return {
                dangerous: true,
                reason: `${label} click downloads a ${ext} file`,
                confidence: 96
            };
        }
        const signals = [];
        const mismatch = checkHrefTextMismatch(context.label ?? "", host, pageHost);
        if (mismatch)
            signals.push(mismatch);
        let imgHost = "";
        if (context.imgSrc) {
            try {
                imgHost = new URL(context.imgSrc, baseUrl).hostname.toLowerCase();
            }
            catch {
                /* ignore */
            }
        }
        signals.push(...collectImageSignals(host, pageHost, parsed, context, imgHost));
        signals.push(...collectButtonSignals(host, pageHost, context));
        signals.push(...collectTextCtaSignals(host, pageHost, context));
        signals.push(...collectTicketContextSignals(host, pageHost, context));
        signals.push(...collectBrandCtaComboSignals(host, pageHost, context));
        return finalizeRiskScore(signals);
    }
    catch {
        return { dangerous: false, reason: "", confidence: 0 };
    }
}
/** @deprecated Use analyzeNavigationTarget — kept for tests. */
function analyzeImageLink(url, imgSrc, pageHost, baseUrl, extra) {
    return analyzeNavigationTarget(url, pageHost, baseUrl, {
        kind: "image-link",
        imgSrc,
        imgWidth: extra?.imgWidth,
        imgHeight: extra?.imgHeight,
        ticket: extra?.ticket
    });
}
if (typeof globalThis !== "undefined") {
    globalThis.DTGAnalysis = {
        analyzeNavigationTarget,
        analyzeImageLink,
        extractUrlsFromOnclick,
        isSuspiciousCtaLabel,
        MIN_CONFIDENCE,
        extensionFromPath,
        extensionFromUrlParts,
        isShareGoogleVariant,
        checkDownloadTrapHost,
        extractDomainFromText,
        finalizeRiskScore
    };
}

})();
