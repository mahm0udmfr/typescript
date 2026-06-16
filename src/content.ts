/**
 * Download Trap Guard v2.0 — clickable images that trigger downloads
 * Zoho Desk tickets only: share.google traps, imgur lures, .zip/.exe links
 */

const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".msi", ".msp", ".bat", ".cmd", ".com", ".scr", ".pif",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".dll", ".sys",
  ".docm", ".xlsm", ".pptm", ".jar", ".appimage"
]);

const ARCHIVE_EXTENSIONS = new Set([
  ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".dmg", ".pkg", ".apk", ".deb", ".rpm"
]);

const IMAGE_EXTENSIONS = new Set([
  ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"
]);

const ZOHO_HOST_PATTERNS = ["desk.zoho.", "mail.zoho.", "support.zoho.", ".zohodesk.com"];

const TRUSTED_LINK_HOSTS = [
  "zoho.com", "zohocdn.com", "zohostatic.com", "zohopublic.com",
  "zappsusercontent.com", "zohostratus.com", "zohocorpcloud.com",
  "imgur.com", "i.imgur.com", "eviivo.com", "stayzltd.com"
];

const DOWNLOAD_TRAP_HOST_EXACT = new Set(["share.google"]);

const DOWNLOAD_TRAP_HOST_CONTAINS = [
  "share-google", "sharegoogle", "googledrive", "drive-google"
];

const SKIP_SCAN_HOSTS = [
  "google.com", "googleusercontent.com", "gstatic.com", "ggpht.com",
  "bing.com", "yahoo.com", "duckduckgo.com", "facebook.com", "instagram.com",
  "twitter.com", "x.com", "youtube.com", "ytimg.com", "reddit.com",
  "wikipedia.org", "linkedin.com", "pinterest.com", "amazon.com", "ebay.com"
];

const BANNER_ID = "dtg-warning-banner";
const STYLE_ID = "dtg-injected-styles";
const MIN_CONFIDENCE = 70;
const MIN_TRAP_IMAGE_PX = 16;

let lastWarnedKey = "";
let scanTimer: ReturnType<typeof setTimeout> | null = null;

interface RiskyImage {
  link: HTMLAnchorElement;
  image: HTMLImageElement;
  targetUrl: string;
  reason: string;
  confidence: number;
}

function isTicketDetailsUrl(url: string): boolean {
  try {
    const path = new URL(url).pathname.toLowerCase();
    return (
      /\/agent\/[^/]+\/[^/]+\/tickets\/details\//.test(path) ||
      path.includes("/tickets/details/")
    );
  } catch {
    return false;
  }
}

function getParentUrl(): string | null {
  try {
    if (window.parent !== window) return window.parent.location.href;
  } catch {
    /* cross-origin */
  }
  return null;
}

function queryAllDeep(selector: string): Element[] {
  const results: Element[] = [];

  function walk(node: Node): void {
    if (node instanceof Element) {
      if (node.matches(selector) && !results.includes(node)) results.push(node);
      node.querySelectorAll(selector).forEach((el) => {
        if (!results.includes(el)) results.push(el);
      });
      if (node.shadowRoot) walk(node.shadowRoot);
    }
    node.childNodes.forEach(walk);
  }

  walk(document.documentElement);
  return results;
}

function queryAllAnchorsDeep(): HTMLAnchorElement[] {
  const anchors: HTMLAnchorElement[] = [];

  function walk(node: Node): void {
    if (node instanceof HTMLAnchorElement && node.hasAttribute("href")) {
      anchors.push(node);
    }
    if (node instanceof Element && node.shadowRoot) walk(node.shadowRoot);
    node.childNodes.forEach(walk);
  }

  walk(document.documentElement);
  return anchors;
}

function hasZohoDeskDom(): boolean {
  return queryAllDeep('[class*="zd_v2-richtextcontent"], [class*="thrdPlain"]').length > 0;
}

function isZohoDeskContext(): boolean {
  if (isTicketDetailsUrl(window.location.href)) return true;
  const parent = getParentUrl();
  if (parent && isTicketDetailsUrl(parent)) return true;
  if (hasZohoDeskDom()) return true;
  return ZOHO_HOST_PATTERNS.some((p) => window.location.hostname.toLowerCase().includes(p));
}

function isInsideTicketContent(el: Element): boolean {
  if (el.closest('[class*="richtextcontent"]')) return true;
  if (el.closest('[class*="thrdPlain"]')) return true;
  if (el.closest('[class*="contentwrapper"]')) return true;
  if (el.closest('[class*="threadContent"]')) return true;
  if (el.closest('[class*="CommentContent"]')) return true;
  return false;
}

function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  if (pattern.endsWith(".")) return h.includes(pattern);
  return h === pattern || h.endsWith("." + pattern);
}

function shouldSkipPage(): boolean {
  if (isZohoDeskContext()) return false;
  const host = window.location.hostname.toLowerCase();
  if (SKIP_SCAN_HOSTS.some((p) => hostMatches(host, p))) return true;
  return false;
}

function getBannerDocument(): Document {
  try {
    if (window.top?.document?.documentElement) return window.top.document;
  } catch {
    /* cross-origin */
  }
  return document;
}

function isPortalInternalHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  const pageHost = window.location.hostname.toLowerCase();
  if (h === pageHost) return true;
  if (h.endsWith("." + pageHost)) return true;
  const pageBase = pageHost.split(".").slice(-2).join(".");
  if (pageBase.length > 3 && h.endsWith("." + pageBase)) return true;
  return false;
}

function isTrustedHost(hostname: string): boolean {
  if (isPortalInternalHost(hostname)) return true;
  return TRUSTED_LINK_HOSTS.some((t) => {
    const h = hostname.toLowerCase();
    return h === t || h.endsWith("." + t);
  });
}

function extensionFromPath(pathname: string): string | null {
  const segment = pathname.split("/").pop()?.split("?")[0] ?? "";
  const dot = segment.lastIndexOf(".");
  if (dot <= 0) return null;
  return segment.slice(dot).toLowerCase();
}

function isDownloadExtension(ext: string): boolean {
  return EXECUTABLE_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext);
}

function isImagePreviewUrl(parsed: URL): boolean {
  const ext = extensionFromPath(parsed.pathname);
  if (ext && IMAGE_EXTENSIONS.has(ext)) return true;
  return /\.(jpe?g|png|gif|webp|svg)(\?|$)/i.test(parsed.pathname);
}

function checkDownloadTrapHost(hostname: string): { dangerous: boolean; reason: string; confidence: number } {
  const host = hostname.toLowerCase();

  if (DOWNLOAD_TRAP_HOST_EXACT.has(host)) {
    return {
      dangerous: true,
      reason: `Image links to "${host}" — known to download a file when clicked`,
      confidence: 98
    };
  }

  for (const fragment of DOWNLOAD_TRAP_HOST_CONTAINS) {
    if (host.includes(fragment)) {
      return {
        dangerous: true,
        reason: `Image links to "${host}" — may download a file when clicked`,
        confidence: 92
      };
    }
  }

  return { dangerous: false, reason: "", confidence: 0 };
}

function getLinkUrl(anchor: HTMLAnchorElement): string {
  return anchor.getAttribute("href")?.trim() || anchor.href;
}

function getImageSize(img: HTMLImageElement): { w: number; h: number } {
  return {
    w: img.width || img.naturalWidth || img.offsetWidth || 0,
    h: img.height || img.naturalHeight || img.offsetHeight || 0
  };
}

function isTrackingPixel(img: HTMLImageElement): boolean {
  const { w, h } = getImageSize(img);
  return w > 0 && h > 0 && w < MIN_TRAP_IMAGE_PX && h < MIN_TRAP_IMAGE_PX;
}

function analyzeImageLink(
  url: string,
  img: HTMLImageElement
): { dangerous: boolean; reason: string; confidence: number } {
  if (!url || url.startsWith("javascript:") || url.startsWith("data:") || url.startsWith("mailto:")) {
    return { dangerous: false, reason: "", confidence: 0 };
  }

  try {
    const parsed = new URL(url, window.location.href);
    const host = parsed.hostname.toLowerCase();

    const trapHost = checkDownloadTrapHost(host);
    if (trapHost.dangerous) return trapHost;

    const pathExt = extensionFromPath(parsed.pathname);
    if (pathExt && isDownloadExtension(pathExt)) {
      return {
        dangerous: true,
        reason: `Image click downloads a ${pathExt} file`,
        confidence: 96
      };
    }

    let imgHost = "";
    try {
      imgHost = new URL(img.src).hostname.toLowerCase();
    } catch {
      /* ignore */
    }

    // Imgur preview image wrapping a non-image download link
    if (
      imgHost.includes("imgur.com") &&
      !isTrustedHost(host) &&
      !isImagePreviewUrl(parsed)
    ) {
      return {
        dangerous: true,
        reason: `Imgur image click goes to ${host} — may download malware`,
        confidence: 95
      };
    }

    return { dangerous: false, reason: "", confidence: 0 };
  } catch {
    return { dangerous: false, reason: "", confidence: 0 };
  }
}

function findRiskyImages(): RiskyImage[] {
  const risks: RiskyImage[] = [];
  const seen = new Set<string>();

  if (!isZohoDeskContext()) return [];

  for (const anchor of queryAllAnchorsDeep()) {
    if (!isInsideTicketContent(anchor)) continue;

    const img = anchor.querySelector("img");
    if (!(img instanceof HTMLImageElement)) continue;
    if (isTrackingPixel(img)) continue;

    const targetUrl = getLinkUrl(anchor);
    const analysis = analyzeImageLink(targetUrl, img);
    if (!analysis.dangerous || analysis.confidence < MIN_CONFIDENCE) continue;

    const key = targetUrl + "|" + img.src;
    if (seen.has(key)) continue;
    seen.add(key);

    risks.push({
      link: anchor,
      image: img,
      targetUrl,
      reason: analysis.reason,
      confidence: analysis.confidence
    });
  }

  return risks.sort((a, b) => b.confidence - a.confidence);
}

function injectBannerStyles(doc: Document): void {
  if (doc.getElementById(STYLE_ID)) return;
  const style = doc.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    #${BANNER_ID}{position:fixed;top:0;left:0;right:0;z-index:2147483647;font-family:system-ui,sans-serif;font-size:14px;box-shadow:0 4px 24px rgba(0,0,0,.3)}
    #${BANNER_ID} .dtg-inner{display:flex;gap:12px;background:linear-gradient(135deg,#7f1d1d,#991b1b);color:#fff;padding:14px 18px;border-bottom:3px solid #fca5a5}
    #${BANNER_ID} .dtg-text strong{display:block;font-size:15px;margin-bottom:4px}
    #${BANNER_ID} .dtg-text p{margin:0 0 8px;line-height:1.4}
    #${BANNER_ID} .dtg-list{margin:0;padding-left:18px;font-size:13px}
    #${BANNER_ID} .dtg-list code{background:rgba(0,0,0,.25);padding:1px 4px;border-radius:3px;font-size:12px}
    #${BANNER_ID} .dtg-dismiss{margin-left:auto;background:rgba(255,255,255,.15);border:none;color:#fff;width:32px;height:32px;border-radius:6px;cursor:pointer;font-size:16px}
    img.dtg-highlight{outline:3px solid #ef4444!important;outline-offset:2px;box-shadow:0 0 0 6px rgba(239,68,68,.4)!important}
    a.dtg-highlight-link{outline:3px solid #ef4444!important;outline-offset:3px;box-shadow:0 0 12px rgba(239,68,68,.6)!important;background:rgba(239,68,68,.15)!important}
  `;
  doc.head.appendChild(style);
}

function clearWarnings(): void {
  try {
    getBannerDocument().getElementById(BANNER_ID)?.remove();
  } catch {
    /* ignore */
  }
  document.getElementById(BANNER_ID)?.remove();

  queryAllAnchorsDeep().forEach((a) => a.classList.remove("dtg-highlight-link"));
  queryAllDeep("img.dtg-highlight").forEach((img) => img.classList.remove("dtg-highlight"));
}

function showBanner(risks: RiskyImage[]): void {
  clearWarnings();

  const bannerDoc = getBannerDocument();
  injectBannerStyles(bannerDoc);

  const banner = bannerDoc.createElement("div");
  banner.id = BANNER_ID;
  banner.setAttribute("role", "alert");
  banner.innerHTML = `
    <div class="dtg-inner">
      <div style="font-size:28px">⚠️</div>
      <div class="dtg-text">
        <strong>Download trap — do not click this image</strong>
        <p>This ticket has a clickable image that may download malware (.zip or similar). Do not click.</p>
        <ul class="dtg-list">
          ${risks
            .slice(0, 3)
            .map(
              (r) =>
                `<li>${escapeHtml(r.reason)} → <code>${escapeHtml(shortUrl(r.targetUrl))}</code></li>`
            )
            .join("")}
        </ul>
      </div>
      <button type="button" class="dtg-dismiss" aria-label="Dismiss">✕</button>
    </div>
  `;

  banner.querySelector(".dtg-dismiss")?.addEventListener("click", () => clearWarnings());
  bannerDoc.documentElement.prepend(banner);

  risks.forEach((r) => {
    r.image.classList.add("dtg-highlight");
    r.link.classList.add("dtg-highlight-link");
  });
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    const q = u.search ? u.search.slice(0, 30) + (u.search.length > 30 ? "…" : "") : "";
    return u.hostname + u.pathname + q;
  } catch {
    return url.slice(0, 60);
  }
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function scanAndWarn(): void {
  if (shouldSkipPage()) {
    clearWarnings();
    return;
  }

  const risks = findRiskyImages();
  if (risks.length === 0) {
    clearWarnings();
    return;
  }

  showBanner(risks);

  const key = risks.map((r) => r.targetUrl).join("|");
  if (key === lastWarnedKey) return;
  lastWarnedKey = key;
}

function scheduleScan(): void {
  if (scanTimer) clearTimeout(scanTimer);
  scanTimer = setTimeout(scanAndWarn, 300);
}

function startWatching(): void {
  scheduleScan();
  new MutationObserver(scheduleScan).observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  if (isZohoDeskContext()) {
    let ticks = 0;
    const interval = setInterval(() => {
      scanAndWarn();
      if (++ticks >= 30) clearInterval(interval);
    }, 2000);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", startWatching);
} else {
  startWatching();
}

function blockClick(e: Event): void {
  const target = e.target as Element | null;
  const flagged = target?.closest("a.dtg-highlight-link, img.dtg-highlight");
  if (!flagged) return;

  const link = (flagged.closest("a") ?? flagged) as HTMLAnchorElement;
  const dest = link.href ? getLinkUrl(link) : "";

  const ok = window.confirm(
    "⚠️ DOWNLOAD TRAP WARNING\n\n" +
      "This image may download malware (.zip or similar) when clicked.\n\n" +
      (dest ? `Link: ${dest}\n\n` : "") +
      "Do NOT click unless you verified the sender.\n\nContinue anyway?"
  );

  if (!ok) {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
  }
}

document.addEventListener("click", blockClick, true);
document.addEventListener("auxclick", blockClick, true);
